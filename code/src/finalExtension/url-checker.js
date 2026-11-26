// url-checker.js — content script
// Checks every link in incoming messages via background.js (Safe Browsing + local heuristics).
// Results are reported to messaging-text-capture.js via __DDD__.setUrlFlags so the message
// element itself is labelled — no link underlining.

(() => {
  const SCAN_DEBOUNCE_MS  = 500;
  const BATCH_MS          = 400;
  const RETRY_BACKOFF_MS  = 30000;
  const MAX_URLS_PER_FLUSH = 100;

  const VERDICT_TO_FLAG = {
    unsafe:  { label: 'harmful',    score: 0.95 },
    caution: { label: 'suspicious', score: 0.65 },
    safe:    { label: 'safe',       score: 0.05 },
  };
  const PRIORITY = { harmful: 1, suspicious: 2, safe: 3 };

  const REDIRECTORS = {
    'l.facebook.com':  ['u'], 'lm.facebook.com': ['u'], 'l.messenger.com': ['u'],
    'slack-redir.net': ['url'], 'www.google.com': ['q'],
  };

  let enabled    = true;
  let observer   = null;
  let scanTimer  = null;
  let flushTimer = null;
  let retryAfter = 0;

  const verdicts = new Map();
  const pending  = new Set();
  const inFlight = new Set();

  function resolveTarget(href) {
    let u; try { u = new URL(href, location.href); } catch { return null; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const params = REDIRECTORS[u.hostname];
    if (params && (u.hostname !== 'www.google.com' || u.pathname === '/url')) {
      for (const p of params) {
        const v = u.searchParams.get(p); if (!v) continue;
        try { const t = new URL(v); if (t.protocol === 'http:' || t.protocol === 'https:') return t.href; } catch { }
      }
    }
    return u.href;
  }
  const hostOf = url => new URL(url).hostname.toLowerCase();

  function textHostMismatch(a, targetHost) {
    const text = (a.textContent || '').trim();
    const m = text.match(/^(?:https?:\/\/)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:[/?#:]|$)/i);
    if (!m) return false;
    const shown = m[1].toLowerCase().replace(/^www\./, '');
    const real  = targetHost.replace(/^www\./, '');
    return shown !== real && !real.endsWith('.' + shown) && !shown.endsWith('.' + real);
  }

  function buildContainerIndex(nodes, sel) {
    const map = new Map(); if (!sel) return map;
    for (const node of nodes) {
      const c = node.el.closest(sel); if (!c) continue;
      map.set(c, map.has(c) ? null : node);
    }
    return map;
  }
  function findOwner(a, nodes, containerSel, containerIndex) {
    let match = null;
    for (const node of nodes) { if (node.el.contains(a)) { if (!match || match.el.contains(node.el)) match = node; } }
    if (match) return match;
    if (containerSel) { const c = a.closest(containerSel); if (c) return containerIndex.get(c) || null; }
    return null;
  }

  function evaluateLink(a, target) {
    const cached   = verdicts.get(target);
    const mismatch = textHostMismatch(a, hostOf(target));
    if (!cached && !mismatch) return { state: 'pending' };
    let verdict = cached?.verdict || 'unknown';
    let reasons = cached?.reasons ? [...cached.reasons] : [];
    if (mismatch) { verdict = 'unsafe'; reasons.unshift('Link text shows a different site than where it really goes'); }
    const mapped = VERDICT_TO_FLAG[verdict];
    if (!mapped) return { state: 'unknown', reasons };
    return { state: 'classified', label: mapped.label, score: mapped.score, reasons };
  }

  function scan() {
    if (!enabled) return;
    const bridge = globalThis.__DDD__;
    const nodes  = bridge?.getMessageNodes?.() || [];
    if (!nodes.length) return;
    const contSel = bridge?.getMessageContainerSelector?.() || null;
    const contIdx = buildContainerIndex(nodes, contSel);
    const perMsg  = new Map();

    for (const a of document.querySelectorAll('a[href]')) {
      if (a.closest('[contenteditable="true"]')) continue;
      const target = resolveTarget(a.getAttribute('href')); if (!target) continue;
      if (hostOf(target) === location.hostname) continue;
      const owner = findOwner(a, nodes, contSel, contIdx); if (!owner) continue;
      if (!verdicts.has(target)) queue(target);
      let entry = perMsg.get(owner.id);
      if (!entry) { entry = { bestLabel: null, bestScore: 0, reasons: [], hasPending: false, hasUnknown: false, unknownReasons: [] }; perMsg.set(owner.id, entry); }
      const res = evaluateLink(a, target);
      if (res.state === 'pending') { entry.hasPending = true; continue; }
      if (res.state === 'unknown') { entry.hasUnknown = true; res.reasons.forEach(r => { if (!entry.unknownReasons.includes(r)) entry.unknownReasons.push(r); }); continue; }
      if (!entry.bestLabel || PRIORITY[res.label] < PRIORITY[entry.bestLabel]) entry.bestLabel = res.label;
      entry.bestScore = Math.max(entry.bestScore, res.score);
      if (res.label !== 'safe') res.reasons.forEach(r => { if (!entry.reasons.includes(r)) entry.reasons.push(r); });
      else if (!entry.reasons.length) res.reasons.forEach(r => { if (!entry.reasons.includes(r)) entry.reasons.push(r); });
    }

    const flagsById = new Map();
    for (const [id, e] of perMsg) {
      if (e.bestLabel === 'harmful' || e.bestLabel === 'suspicious') {
        flagsById.set(id, { label: e.bestLabel, score: e.bestScore, reasons: e.reasons });
      } else if (!e.hasPending && e.bestLabel === 'safe' && !e.hasUnknown) {
        flagsById.set(id, { label: 'safe', score: e.bestScore, reasons: e.reasons });
      } else if (!e.hasPending && e.hasUnknown && !e.bestLabel) {
        flagsById.set(id, { label: 'unknown', reasons: e.unknownReasons });
      }
    }
    if (flagsById.size) bridge?.setUrlFlags?.(flagsById);
  }

  const scheduleScan = () => { clearTimeout(scanTimer); scanTimer = setTimeout(scan, SCAN_DEBOUNCE_MS); };

  function queue(url) { if (verdicts.has(url) || inFlight.has(url) || Date.now() < retryAfter) return; pending.add(url); scheduleFlush(BATCH_MS); }
  const scheduleFlush = delay => { if (flushTimer) return; flushTimer = setTimeout(flush, delay); };

  async function flush() {
    flushTimer = null;
    if (!enabled || !pending.size) return;
    if (!chrome.runtime?.id) { stop(); return; }
    const urls = [...pending].slice(0, MAX_URLS_PER_FLUSH);
    urls.forEach(u => { pending.delete(u); inFlight.add(u); });
    let resp = null;
    try { resp = await chrome.runtime.sendMessage({ type: 'CHECK_URLS', urls }); } catch (e) { console.warn('[DDD] URL check failed:', e); }
    urls.forEach(u => inFlight.delete(u));
    if (resp?.ok) { for (const [url, r] of Object.entries(resp.results)) verdicts.set(url, r); if (pending.size) scheduleFlush(BATCH_MS); }
    else retryAfter = Date.now() + RETRY_BACKOFF_MS;
    scan();
  }

  function start() {
    if (observer) return;
    observer = new MutationObserver(scheduleScan);
    observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['href'] });
    scan();
  }
  function stop() {
    observer?.disconnect(); observer = null;
    clearTimeout(scanTimer); clearTimeout(flushTimer); flushTimer = null; pending.clear();
  }

  globalThis.__DDD__ = Object.assign(globalThis.__DDD__ || {}, { onMessagesUpdated: scheduleScan });

  chrome.storage.local.get(['enabled'], res => { enabled = res.enabled !== false; if (enabled) start(); });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes.enabled) { enabled = changes.enabled.newValue !== false; if (enabled) start(); else stop(); }
  });
})();
