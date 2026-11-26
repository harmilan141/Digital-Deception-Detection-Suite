// url-checker.js — content script
// Checks links inside incoming chat messages via background.js.
// Instead of underlining links, it reports URL verdicts (harmful, suspicious, or safe)
// to messaging-text-capture.js so the text message itself is labeled using priority:
//   harmful: 1, suspicious: 2, safe: 3   (lesser number wins)

(() => {
  const SCAN_DEBOUNCE_MS = 500;
  const BATCH_MS = 400;
  const RETRY_BACKOFF_MS = 30000;
  const MAX_URLS_PER_FLUSH = 100;

  // Map URL checker verdicts to internal classification labels and priorities.
  const VERDICT_TO_FLAG = {
    unsafe: { label: 'harmful', score: 0.95 },
    caution: { label: 'suspicious', score: 0.65 },
    safe: { label: 'safe', score: 0.05 },
  };
  const PRIORITY = { harmful: 1, suspicious: 2, safe: 3 };

  // Chat apps often wrap outgoing links in a redirector; unwrap to the real target.
  const REDIRECTORS = {
    'l.facebook.com': ['u'],
    'lm.facebook.com': ['u'],
    'l.messenger.com': ['u'],
    'slack-redir.net': ['url'],
    'www.google.com': ['q'], // only for /url
  };

  let enabled = true;
  let observer = null;
  let scanTimer = null;
  let flushTimer = null;
  let retryAfter = 0;

  const verdicts = new Map();  // target URL -> { verdict, reasons }
  const pending = new Set();   // URLs waiting to be sent
  const inFlight = new Set();  // URLs sent, awaiting a reply

  // ------------------------------------------------------------ URL helpers

  function resolveTarget(href) {
    let u;
    try { u = new URL(href, location.href); } catch { return null; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;

    const params = REDIRECTORS[u.hostname];
    if (params && (u.hostname !== 'www.google.com' || u.pathname === '/url')) {
      for (const p of params) {
        const v = u.searchParams.get(p);
        if (!v) continue;
        try {
          const t = new URL(v);
          if (t.protocol === 'http:' || t.protocol === 'https:') return t.href;
        } catch { /* not a URL, ignore */ }
      }
    }
    return u.href;
  }

  const hostOf = (url) => new URL(url).hostname.toLowerCase();

  // True when the link text shows one site but the href goes to another.
  function textHostMismatch(a, targetHost) {
    const text = (a.textContent || '').trim();
    const m = text.match(/^(?:https?:\/\/)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:[/?#:]|$)/i);
    if (!m) return false;
    const shown = m[1].toLowerCase().replace(/^www\./, '');
    const real = targetHost.replace(/^www\./, '');
    return shown !== real && !real.endsWith('.' + shown) && !shown.endsWith('.' + real);
  }

  // ------------------------------------------------ message association

  function buildContainerIndex(nodes, containerSel) {
    const map = new Map();
    if (!containerSel) return map;
    for (const node of nodes) {
      const container = node.el.closest(containerSel);
      if (!container) continue;
      if (!map.has(container)) map.set(container, node);
      else map.set(container, null); // ambiguous container with multiple message nodes
    }
    return map;
  }

  function findOwningMessage(a, nodes, containerSel, containerIndex) {
    // 1. Direct descendant of a captured message text element (most common).
    let match = null;
    for (const node of nodes) {
      if (node.el.contains(a)) {
        if (!match || match.el.contains(node.el)) match = node;
      }
    }
    if (match) return match;

    // 2. Fallback: link preview card inside the same message bubble container.
    if (containerSel) {
      const container = a.closest(containerSel);
      if (container) return containerIndex.get(container) || null;
    }
    return null;
  }

  function evaluateLink(a, target) {
    const cached = verdicts.get(target);
    const mismatch = textHostMismatch(a, hostOf(target));

    if (!cached && !mismatch) return { state: 'pending' };

    let verdict = cached?.verdict || 'unknown';
    let reasons = cached?.reasons ? [...cached.reasons] : [];

    if (mismatch) {
      verdict = 'unsafe';
      reasons.unshift('Link text shows a different site than where it really goes');
    }

    const mapped = VERDICT_TO_FLAG[verdict];
    if (!mapped) {
      return { state: 'unknown', reasons };
    }

    return {
      state: 'classified',
      label: mapped.label,
      score: mapped.score,
      reasons,
    };
  }

  // ----------------------------------------------------------------- scanning

  function queue(url) {
    if (verdicts.has(url) || inFlight.has(url) || Date.now() < retryAfter) return;
    pending.add(url);
    scheduleFlush(BATCH_MS);
  }

  function scheduleFlush(delay) {
    if (flushTimer) return;
    flushTimer = setTimeout(flush, delay);
  }

  function scan() {
    if (!enabled) return;

    const bridge = globalThis.__DDD__;
    const nodes = bridge?.getMessageNodes?.() || [];
    if (nodes.length === 0) return;

    const containerSel = bridge?.getMessageContainerSelector?.() || null;
    const containerIndex = buildContainerIndex(nodes, containerSel);
    const perMessage = new Map(); // id -> { bestLabel, bestScore, reasons, hasPending, hasUnknown, unknownReasons }

    for (const a of document.querySelectorAll('a[href]')) {
      if (a.closest('[contenteditable="true"]')) continue;       // the compose box

      const target = resolveTarget(a.getAttribute('href'));
      if (!target) continue;
      if (hostOf(target) === location.hostname) continue;        // in-app navigation

      const owner = findOwningMessage(a, nodes, containerSel, containerIndex);
      if (!owner) continue;

      if (!verdicts.has(target)) queue(target);

      let entry = perMessage.get(owner.id);
      if (!entry) {
        entry = {
          bestLabel: null,
          bestScore: 0,
          reasons: [],
          hasPending: false,
          hasUnknown: false,
          unknownReasons: [],
        };
        perMessage.set(owner.id, entry);
      }

      const res = evaluateLink(a, target);
      if (res.state === 'pending') {
        entry.hasPending = true;
        continue;
      }
      if (res.state === 'unknown') {
        entry.hasUnknown = true;
        for (const r of res.reasons) {
          if (!entry.unknownReasons.includes(r)) entry.unknownReasons.push(r);
        }
        continue;
      }

      if (!entry.bestLabel || PRIORITY[res.label] < PRIORITY[entry.bestLabel]) {
        entry.bestLabel = res.label;
      }
      entry.bestScore = Math.max(entry.bestScore, res.score);
      if (res.label !== 'safe') {
        for (const r of res.reasons) {
          if (!entry.reasons.includes(r)) entry.reasons.push(r);
        }
      } else if (entry.reasons.length === 0) {
        for (const r of res.reasons) {
          if (!entry.reasons.includes(r)) entry.reasons.push(r);
        }
      }
    }

    const flagsById = new Map();
    for (const [id, entry] of perMessage.entries()) {
      if (entry.bestLabel === 'harmful' || entry.bestLabel === 'suspicious') {
        flagsById.set(id, {
          label: entry.bestLabel,
          score: entry.bestScore,
          reasons: entry.reasons,
        });
      } else if (!entry.hasPending && entry.bestLabel === 'safe' && !entry.hasUnknown) {
        flagsById.set(id, {
          label: 'safe',
          score: entry.bestScore,
          reasons: entry.reasons,
        });
      } else if (!entry.hasPending && entry.hasUnknown && !entry.bestLabel) {
        flagsById.set(id, {
          label: 'unknown',
          reasons: entry.unknownReasons,
        });
      }
    }

    if (flagsById.size > 0) {
      bridge?.setUrlFlags?.(flagsById);
    }
  }

  function scheduleScan() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scan, SCAN_DEBOUNCE_MS);
  }

  async function flush() {
    flushTimer = null;
    if (!enabled || pending.size === 0) return;

    if (!chrome.runtime?.id) { stop(); return; } // extension was reloaded; this script is orphaned

    const allPending = [...pending];
    const urls = allPending.slice(0, MAX_URLS_PER_FLUSH);
    for (const u of urls) {
      pending.delete(u);
      inFlight.add(u);
    }

    let resp = null;
    try {
      resp = await chrome.runtime.sendMessage({ type: 'CHECK_URLS', urls });
    } catch (e) {
      console.warn('[DDD] URL check failed:', e);
    }
    urls.forEach((u) => inFlight.delete(u));

    if (resp?.ok) {
      for (const [url, r] of Object.entries(resp.results)) verdicts.set(url, r);
      if (pending.size > 0) scheduleFlush(BATCH_MS);
    } else {
      retryAfter = Date.now() + RETRY_BACKOFF_MS; // a later scan retries
    }
    scan();
  }

  // ---------------------------------------------------------------- lifecycle

  function start() {
    if (observer) return;
    observer = new MutationObserver(scheduleScan);
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['href'],
    });
    scan();
  }

  function stop() {
    if (observer) { observer.disconnect(); observer = null; }
    clearTimeout(scanTimer);
    clearTimeout(flushTimer);
    flushTimer = null;
    pending.clear();
  }

  globalThis.__DDD__ = Object.assign(globalThis.__DDD__ || {}, {
    onMessagesUpdated: scheduleScan,
  });

  // Respect the same on/off toggle as the rest of the extension, and invalidate
  // in-memory verdicts if the user updates their Safe Browsing API key.
  chrome.storage.local.get(['enabled'], (res) => {
    enabled = res.enabled !== false;
    if (enabled) start();
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;

    if (changes.safeBrowsingKey) {
      verdicts.clear();
      pending.clear();
      retryAfter = 0;
      if (enabled) scan();
    }

    if (changes.enabled) {
      enabled = changes.enabled.newValue !== false;
      if (enabled) start(); else stop();
    }
  });
})();
