// Injected on the messaging domains declared in manifest.json.
//
// 1. Finds the real message elements on the page (per-site selectors below). It no longer
//    falls back to "all page text", so times, contact names and menus are never captured.
// 2. Separates URL-only messages from text / URL+text messages:
//      - URL-only messages are NEVER passed to the ML model; only the URL tester checks them.
//      - Mixed (URL+text) messages strip URLs before sending the text portion to ML, while
//        the URL tester checks the URLs.
// 3. Compares text & URL labels using internal priorities:
//      harmful: 1, suspicious: 2, safe: 3   (lower number = higher priority wins)
//    Note: "low_risk" is dropped and treated as "safe".
// 4. Shows the resulting label on the message itself in the chat, as a small badge.
//
// Badges are drawn with a CSS ::after rule driven by a data attribute, so no nodes are
// inserted into the chat app's DOM (safer with React re-renders) and the message text
// the app reports is unchanged.

(() => {
  const SITE = location.hostname;
  const STORAGE_KEY = `messagingCapture:${SITE}`;
  const MAX_STORED = 500;         // cap so storage doesn't grow unbounded
  const MIN_LEN = 2;              // ignore near-empty text
  const MAX_LEN = 2000;           // ignore giant blobs (e.g. a pasted document)
  const SCAN_DEBOUNCE_MS = 800;   // wait for the DOM to settle before capturing
  const PAINT_THROTTLE_MS = 200;  // how quickly badges are (re)applied after the DOM changes
  const CLASSIFY_BATCH = 50;      // messages per request to the ML server
  const RETRY_BACKOFF_MS = 30000; // wait this long after the ML server fails

  const VALID_LABELS = new Set(['safe', 'suspicious', 'harmful']);
  // Internal classification priority: lower number = higher priority.
  const PRIORITY = { harmful: 1, suspicious: 2, safe: 3 };
  const LABEL_NAMES = { safe: 'Safe', suspicious: 'Suspicious', harmful: 'Harmful' };

  const URL_PATTERN = /\b(?:https?:\/\/|www\.)[^\s<>"{}|\\^`\[\]]+/gi;
  const DOMAIN_TEXT_RE = /^(?:https?:\/\/)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:[/?#:]\S*)?$/i;

  // ---- settings you may want to change -------------------------------------------------
  // Labels listed here are classified but not shown in the chat,
  // e.g. new Set(['safe']) to only display warnings.
  const HIDDEN_LABELS = new Set();

  // true = only analyse INCOMING messages; messages you sent are ignored (not stored, not
  // sent to the model, no badge). Only works on sites listed in OWN_MESSAGE_SELECTORS or
  // OWN_BY_POSITION. Other sites still check everything.
  // NOTE: in WhatsApp's "message yourself" chat every message counts as sent by you.
  const SKIP_OWN_MESSAGES = true;
  const OWN_MESSAGE_SELECTORS = {
    // .message-out = WhatsApp's class for sent bubbles; data-id="true_..." is its sent-message id.
    // Either one matching is enough, so a markup change to one doesn't break the filter.
    'web.whatsapp.com': '.message-out, [data-id^="true_"]',
    // Telegram Web K marks sent bubbles .is-out; Web A marks them .own
    'web.telegram.org': '.bubble.is-out, .Message.own',
  };

  // Backup that does not depend on any class names: on these sites a bubble that sits on the
  // RIGHT side of the chat pane is one you sent, on the LEFT is one you received.
  const OWN_BY_POSITION = new Set([
    'web.whatsapp.com',
    'web.telegram.org',
    'messenger.com',
    'www.messenger.com',
  ]);
  const PANE_SELECTORS = {
    'web.whatsapp.com': '#main',
    'web.telegram.org': '#column-center, #MiddleColumn',
    'messenger.com': '[role="main"]',
    'www.messenger.com': '[role="main"]',
  };

  // Quoted/replied-to text shown inside a bubble is not a separate message.
  const SKIP_INSIDE_SELECTORS = {
    'web.whatsapp.com': '[aria-label^="Quoted"], [data-testid="quoted-message"]',
    'messenger.com': '[aria-label^="Replying to"], [data-testid="reply_to_message"]',
    'www.messenger.com': '[aria-label^="Replying to"], [data-testid="reply_to_message"]',
  };

  // Selectors for the element holding the TEXT of a message. Tried in order; the first one
  // that matches any message wins. These depend on each site's markup and can break when
  // the site updates, so keep them here. A site with no entry captures nothing.
  const SITE_SELECTORS = {
    'web.whatsapp.com': ['[data-pre-plain-text] span.selectable-text', 'span.selectable-text.copyable-text'],
    'discord.com': ['[id^="message-content-"]'],
    'app.slack.com': ['.p-rich_text_section'],
    // Telegram Web A (/a/) first, then Web K (/k/).
    'web.telegram.org': [
      '.Message .text-content',          // Web A
      '.bubble-content .message',        // Web K
      '.bubble .message',
      '.message.spoilers-container',
      '.text-content',
    ],
    'messenger.com': [
      '[data-testid="message-container"] [dir="auto"]',
      '[role="main"] [role="row"] div[dir="auto"]',
    ],
    'www.messenger.com': [
      '[data-testid="message-container"] [dir="auto"]',
      '[role="main"] [role="row"] div[dir="auto"]',
    ],
  };

  // Outer bubble/container per message, used by url-checker.js to associate preview-card
  // links in the same bubble with this message when the <a> is outside the text span.
  const MESSAGE_CONTAINER_SELECTORS = {
    'web.whatsapp.com': '[data-pre-plain-text], [data-id]',
    'discord.com': '[id^="chat-messages-"], li[class*="messageListItem"]',
    'app.slack.com': '[data-qa="message_container"], .c-message_kit__background',
    'web.telegram.org': '.bubble, .Message',
    'messenger.com': '[data-testid="message-container"], [role="row"]',
    'www.messenger.com': '[data-testid="message-container"], [role="row"]',
  };

  // Parts INSIDE a message element that are not message text (time, ticks, reactions).
  // They are removed from a copy of the element before its text is read.
  const TEXT_IGNORE_SELECTORS = {
    'web.telegram.org': '.MessageMeta, .time, .reactions, .Reactions',
  };

  // A message that is only a clock time is never a real message.
  const NOISE_PATTERNS = [/^\d{1,2}:\d{2}(\s?[ap]\.?m\.?)?$/i];
  // --------------------------------------------------------------------------------------

  const STYLE_ID = '__ddd_msg_style__';

  let enabled = true;
  let observer = null;
  let debounceTimer = null;
  let paintTimer = null;
  let classifying = false;
  let retryAfter = 0;
  let warnedNoSelector = false;
  let matchedEver = false;

  const seenThisSession = new Set();
  const labels = new Map();     // message id -> effective { label, score, explanation, signals, source }
  const mlResults = new Map();  // message id -> ml verdict object
  const urlFlags = new Map();   // message id -> { label, score, reasons }
  const urlOnlyIds = new Set(); // message ids that contain only URL(s) and must skip ML

  // All storage read-modify-write operations run one at a time, so appending new
  // messages and writing back labels can never overwrite each other.
  let writeChain = Promise.resolve();
  function enqueue(fn) {
    const p = writeChain.then(fn);
    writeChain = p.catch(() => {});
    return p;
  }

  // Small non-cryptographic hash, used only to give each message text an id.
  function hashText(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) {
      h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
    }
    return h.toString(36);
  }

  function normalizeLabel(label) {
    return label === 'low_risk' ? 'safe' : label;
  }

  // ------------------------------------------------------------ extraction

  function nodeText(el) {
    const ignore = TEXT_IGNORE_SELECTORS[SITE];
    if (ignore) {
      const copy = el.cloneNode(true);
      copy.querySelectorAll(ignore).forEach((n) => n.remove());
      return (copy.textContent || '').trim();
    }
    return (el.innerText || el.textContent || '').trim();
  }

  function isCandidate(text) {
    return text.length >= MIN_LEN
      && text.length <= MAX_LEN
      && !NOISE_PATTERNS.some((re) => re.test(text));
  }

  function analyzeMessageContent(el, rawText) {
    let hasUrl = URL_PATTERN.test(rawText);
    URL_PATTERN.lastIndex = 0;

    let stripped = rawText.replace(URL_PATTERN, ' ');
    for (const a of el.querySelectorAll('a[href]')) {
      const href = a.getAttribute('href') || '';
      if (!/^https?:\/\//i.test(href)) continue;
      hasUrl = true;
      const linkText = (a.textContent || '').trim();
      if (linkText && DOMAIN_TEXT_RE.test(linkText)) {
        stripped = stripped.split(linkText).join(' ');
      }
    }

    const textForMl = stripped.replace(/\s+/g, ' ').trim();
    const alphaNum = textForMl.replace(/[\s.,!?;:()\[\]{}'"<>|/\\-]+/g, '');
    const hasText = alphaNum.length >= 2;
    const urlOnly = hasUrl && !hasText;

    return {
      hasUrl,
      urlOnly,
      mlText: hasText ? textForMl : '',
    };
  }

  function isOnRightSide(el) {
    const bubble = el.closest('[data-pre-plain-text], .bubble-content, .message-content, [data-testid="message-container"]') || el;
    const r = bubble.getBoundingClientRect();
    if (!r.width) return false; // not laid out yet
    const paneSel = PANE_SELECTORS[SITE];
    const pane = paneSel ? document.querySelector(paneSel) : null;
    let left = 0;
    let right = document.documentElement.clientWidth;
    if (pane) {
      const p = pane.getBoundingClientRect();
      if (p.width) { left = p.left; right = p.right; }
    }
    return (right - r.right) < (r.left - left);
  }

  function isOwnMessage(el) {
    const sel = OWN_MESSAGE_SELECTORS[SITE];
    if (sel && el.closest(sel)) return true;
    return OWN_BY_POSITION.has(SITE) && isOnRightSide(el);
  }

  // Returns [{ el, text, hasUrl, urlOnly, mlText }] for every real message currently in the page.
  function collectMessageNodes() {
    const selectors = SITE_SELECTORS[SITE];
    if (!selectors) {
      if (!warnedNoSelector) {
        warnedNoSelector = true;
        console.info(`[DDD] No message selector configured for ${SITE}; nothing will be captured. Add one to SITE_SELECTORS.`);
      }
      return [];
    }

    const skipInside = SKIP_INSIDE_SELECTORS[SITE];

    for (const selector of selectors) {
      const nodes = [];
      for (const el of document.querySelectorAll(selector)) {
        if (el.closest('[contenteditable="true"]')) continue; // the compose box
        if (skipInside && el.closest(skipInside)) continue;   // quoted text
        if (SKIP_OWN_MESSAGES && isOwnMessage(el)) continue;  // messages you sent
        const text = nodeText(el);
        if (!isCandidate(text)) continue;
        nodes.push({ el, text, ...analyzeMessageContent(el, text) });
      }
      if (nodes.length) { matchedEver = true; return nodes; }
    }
    return [];
  }

  // ------------------------------------------------------- verdict merging

  function mergeVerdicts(ml, urlFlag, isUrlOnly = false) {
    const mlLabel = ml ? normalizeLabel(ml.label) : null;
    const urlLabel = urlFlag ? normalizeLabel(urlFlag.label) : null;
    const hasMl = !isUrlOnly && Boolean(mlLabel && VALID_LABELS.has(mlLabel));
    const hasUrl = Boolean(urlLabel && VALID_LABELS.has(urlLabel));

    // URL-only messages never use ML; only the URL tester labels them.
    if (isUrlOnly) {
      if (hasUrl) {
        const reasons = Array.isArray(urlFlag.reasons) ? urlFlag.reasons : [];
        return {
          label: urlLabel,
          score: urlFlag.score,
          source: 'url',
          explanation: reasons.length ? `URL check: ${reasons.join('; ')}` : '',
          signals: urlLabel === 'safe' ? [] : [LABEL_NAMES[urlLabel] + ' link'],
        };
      }
      if (urlFlag?.label === 'unknown') {
        const reasons = Array.isArray(urlFlag.reasons) ? urlFlag.reasons : [];
        return {
          label: 'unclassified',
          score: undefined,
          source: 'url',
          explanation: reasons.length ? `URL check: ${reasons.join('; ')}` : 'URL not verified',
          signals: [],
        };
      }
      return null;
    }

    // Both URL and text exist (or text-only): compare priorities (lower number wins).
    if (hasMl && hasUrl) {
      const urlWins = PRIORITY[urlLabel] < PRIORITY[mlLabel];
      const label = urlWins ? urlLabel : mlLabel;

      const scores = [];
      if (typeof ml.score === 'number') scores.push(ml.score);
      if (typeof urlFlag.score === 'number') scores.push(urlFlag.score);
      const score = scores.length ? Math.max(...scores) : undefined;

      const expParts = [];
      if (ml.explanation) expParts.push(ml.explanation);
      if (Array.isArray(urlFlag.reasons) && urlFlag.reasons.length) {
        expParts.push(`URL check (${urlLabel}): ${urlFlag.reasons.join('; ')}`);
      }

      const signals = [];
      const seenSig = new Set();
      for (const s of (Array.isArray(ml.signals) ? ml.signals : [])) {
        if (!seenSig.has(s)) { seenSig.add(s); signals.push(s); }
      }
      if (urlLabel !== 'safe') {
        const linkSig = `${LABEL_NAMES[urlLabel]} link`;
        if (!seenSig.has(linkSig)) { seenSig.add(linkSig); signals.push(linkSig); }
      }

      return {
        label,
        score,
        source: `${ml.source || 'ml'}+url`,
        explanation: expParts.join(' | '),
        signals,
      };
    }

    if (hasMl) {
      return {
        label: mlLabel,
        score: ml.score,
        source: ml.source || 'ml',
        explanation: ml.explanation || '',
        signals: Array.isArray(ml.signals) ? ml.signals : [],
      };
    }

    // URL flagged harmful/suspicious before ML responded (or while ML server is offline).
    if (hasUrl && (urlLabel === 'harmful' || urlLabel === 'suspicious')) {
      const reasons = Array.isArray(urlFlag.reasons) ? urlFlag.reasons : [];
      return {
        label: urlLabel,
        score: urlFlag.score,
        source: 'url',
        explanation: reasons.length ? `URL check: ${reasons.join('; ')}` : '',
        signals: [`${LABEL_NAMES[urlLabel]} link`],
      };
    }

    // Note: if urlLabel === 'safe' on a mixed message while ML is still pending,
    // wait for ML so the text label determines the outcome (priority 1/2/3).
    return null;
  }

  function applyEffectiveFields(m) {
    const merged = mergeVerdicts(m.ml, m.urlFlag, Boolean(m.urlOnly));
    if (merged) {
      m.status = merged.label;
      m.score = merged.score;
      m.source = merged.source;
      m.explanation = merged.explanation;
      m.signals = merged.signals;
      return;
    }
    if (!m.urlOnly && m.ml && m.ml.label === 'unclassified') {
      m.status = 'unclassified';
    }
  }

  function refreshInMemoryLabels(id) {
    const merged = mergeVerdicts(mlResults.get(id), urlFlags.get(id), urlOnlyIds.has(id));
    if (merged && VALID_LABELS.has(merged.label)) labels.set(id, merged);
    else labels.delete(id);
  }

  // --------------------------------------------------------------- storage

  function appendMessages(nodes) {
    if (nodes.length === 0) return Promise.resolve();

    return enqueue(async () => {
      const stored = await chrome.storage.local.get(STORAGE_KEY);
      const existing = stored[STORAGE_KEY] || [];
      const existingIds = new Set(existing.map((m) => m.id));

      const additions = [];
      for (const node of nodes) {
        const id = hashText(node.text);
        if (node.urlOnly) urlOnlyIds.add(id);
        if (seenThisSession.has(id) || existingIds.has(id)) continue;
        seenThisSession.add(id);
        const entry = {
          id,
          site: SITE,
          url: location.href,
          text: node.text,
          mlText: node.mlText,
          hasUrl: node.hasUrl,
          urlOnly: node.urlOnly,
          capturedAt: new Date().toISOString(),
          status: 'pending', // replaced by the ML and/or URL label
        };
        if (urlFlags.has(id)) {
          entry.urlFlag = urlFlags.get(id);
          applyEffectiveFields(entry);
        }
        additions.push(entry);
      }
      if (additions.length === 0) return;

      const merged = existing.concat(additions);
      const trimmed = merged.length > MAX_STORED
        ? merged.slice(merged.length - MAX_STORED)
        : merged;

      await chrome.storage.local.set({ [STORAGE_KEY]: trimmed });
    });
  }

  // Newest pending non-URL-only messages first; URL-only messages are NEVER sent to ML.
  function pickPending() {
    return enqueue(async () => {
      const stored = await chrome.storage.local.get(STORAGE_KEY);
      return (stored[STORAGE_KEY] || [])
        .filter((m) => !m.urlOnly && (m.status === 'pending' || (Boolean(m.urlFlag) && !m.ml)))
        .slice(-CLASSIFY_BATCH)
        .map((m) => ({ id: m.id, text: m.mlText || m.text }));
    });
  }

  function applyResults(batch, results) {
    return enqueue(async () => {
      const byId = new Map(results.map((r) => [r.id, r]));
      const batchIds = new Set(batch.map((b) => b.id));

      const stored = await chrome.storage.local.get(STORAGE_KEY);
      const list = stored[STORAGE_KEY] || [];

      for (const m of list) {
        if (!batchIds.has(m.id)) continue;
        const r = byId.get(m.id);
        const normLabel = r ? normalizeLabel(r.label) : null;
        if (r && VALID_LABELS.has(normLabel)) {
          m.ml = {
            label: normLabel,
            score: r.score,
            source: r.source || 'ml',
            explanation: r.explanation || '',
            signals: r.signals || [],
          };
          m.classifiedAt = new Date().toISOString();
          mlResults.set(m.id, m.ml);
        } else {
          m.ml = { label: 'unclassified' }; // server skipped it; don't retry forever
        }
        if (!m.urlFlag && urlFlags.has(m.id)) m.urlFlag = urlFlags.get(m.id);
        applyEffectiveFields(m);
      }
      await chrome.storage.local.set({ [STORAGE_KEY]: list });

      rebuildLabels(list);
      schedulePaint();
    });
  }

  function persistUrlFlags(flaggedEntries) {
    if (flaggedEntries.size === 0) return Promise.resolve();

    return enqueue(async () => {
      const stored = await chrome.storage.local.get(STORAGE_KEY);
      const list = stored[STORAGE_KEY] || [];
      let changed = false;

      for (const m of list) {
        const flag = flaggedEntries.get(m.id);
        if (!flag) continue;
        // Preserve legacy ML verdict if this message was classified before m.ml existed.
        if (!m.ml && !m.urlOnly && VALID_LABELS.has(normalizeLabel(m.status)) && m.source !== 'url') {
          m.ml = {
            label: normalizeLabel(m.status),
            score: m.score,
            source: m.source || 'ml',
            explanation: m.explanation || '',
            signals: m.signals || [],
          };
          mlResults.set(m.id, m.ml);
        }
        const prev = JSON.stringify(m.urlFlag || null);
        const next = JSON.stringify(flag);
        if (prev !== next) {
          m.urlFlag = flag;
          applyEffectiveFields(m);
          changed = true;
        }
      }

      if (changed) {
        await chrome.storage.local.set({ [STORAGE_KEY]: list });
        rebuildLabels(list);
        schedulePaint();
      }
    });
  }

  function setUrlFlags(flagsById) {
    if (!flagsById || flagsById.size === 0) return;
    let changed = false;
    const toPersist = new Map();
    for (const [id, flag] of flagsById.entries()) {
      if (!flag || (!VALID_LABELS.has(flag.label) && flag.label !== 'unknown')) continue;
      const prev = JSON.stringify(urlFlags.get(id) || null);
      const next = JSON.stringify(flag);
      if (prev !== next) {
        urlFlags.set(id, flag);
        refreshInMemoryLabels(id);
        changed = true;
      }
      toPersist.set(id, flag);
    }
    if (changed) schedulePaint();
    persistUrlFlags(toPersist);
  }

  // -------------------------------------------------------- classification

  async function requestClassification(batch) {
    try {
      return await chrome.runtime.sendMessage({ type: 'CLASSIFY', items: batch });
    } catch (e) {
      console.warn('[DDD] classify request failed:', e);
      return null;
    }
  }

  async function classifyPending() {
    if (classifying || Date.now() < retryAfter) return;
    classifying = true;
    try {
      while (enabled && chrome.runtime?.id) {
        const batch = await pickPending();
        if (batch.length === 0) break;

        const resp = await requestClassification(batch);
        if (!resp?.ok) {
          retryAfter = Date.now() + RETRY_BACKOFF_MS; // messages stay 'pending'; retried later
          break;
        }
        await applyResults(batch, resp.results);
      }
    } finally {
      classifying = false;
    }
  }

  // --------------------------------------------------- badges in the chat

  function injectStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const s = document.createElement('style');
    s.id = STYLE_ID;
    s.textContent = `
      [data-ddd-msg]::after {
        display: inline-block;
        margin-left: 6px;
        padding: 2px 7px;
        border-radius: 9px;
        font: 600 10px/1.3 system-ui, -apple-system, sans-serif;
        letter-spacing: 0.2px;
        white-space: nowrap;
        vertical-align: middle;
        user-select: none;
      }
      [data-ddd-msg="safe"]::after       { content: "\\2713  Safe";        background: #dcfce7; color: #15803d; }
      [data-ddd-msg="suspicious"]::after { content: "\\26A0  Suspicious";  background: #ffedd5; color: #c2410c; }
      [data-ddd-msg="harmful"]::after    { content: "\\26D4  Harmful";     background: #fee2e2; color: #b91c1c; }
      [data-ddd-msg="suspicious"] {
        background: rgba(249, 115, 22, 0.22);
        border-radius: 4px;
        box-decoration-break: clone;
        -webkit-box-decoration-break: clone;
      }
      [data-ddd-msg="harmful"] {
        background: rgba(220, 38, 38, 0.28);
        border-radius: 4px;
        box-decoration-break: clone;
        -webkit-box-decoration-break: clone;
      }
    `;
    document.documentElement.appendChild(s);
  }

  function rebuildLabels(list) {
    labels.clear();
    mlResults.clear();
    for (const m of list || []) {
      if (m.urlOnly) urlOnlyIds.add(m.id);
      const mlNorm = m.ml ? normalizeLabel(m.ml.label) : null;
      const statusNorm = normalizeLabel(m.status);
      const ml = m.ml && VALID_LABELS.has(mlNorm)
        ? { ...m.ml, label: mlNorm }
        : (!m.urlOnly && VALID_LABELS.has(statusNorm) && m.source !== 'url'
          ? {
              label: statusNorm,
              score: m.score,
              source: m.source || 'ml',
              explanation: m.explanation,
              signals: m.signals,
            }
          : null);
      if (ml) mlResults.set(m.id, ml);
      if (m.urlFlag && (VALID_LABELS.has(normalizeLabel(m.urlFlag.label)) || m.urlFlag.label === 'unknown')) {
        urlFlags.set(m.id, m.urlFlag);
      }
      const merged = mergeVerdicts(ml, urlFlags.get(m.id), Boolean(m.urlOnly));
      if (merged && VALID_LABELS.has(merged.label)) labels.set(m.id, merged);
    }
    // Also keep any in-memory urlFlags for messages not yet persisted to storage.
    for (const id of urlFlags.keys()) {
      if (!labels.has(id)) refreshInMemoryLabels(id);
    }
  }

  function tooltipFor(info) {
    const lines = [`[DDD] ${LABEL_NAMES[info.label]}`
      + (typeof info.score === 'number' ? ` (risk ${Math.round(info.score * 100)}%)` : '')];
    if (info.explanation) lines.push(info.explanation);
    if (Array.isArray(info.signals) && info.signals.length) lines.push(`Signals: ${info.signals.join(', ')}`);
    return lines.join('\n');
  }

  function paintMessage(el, info) {
    if (!info) {
      if (el.dataset.dddMsg) {
        delete el.dataset.dddMsg;
        if ((el.title || '').startsWith('[DDD]')) el.removeAttribute('title');
      }
      return;
    }
    if (el.dataset.dddMsg !== info.label) el.dataset.dddMsg = info.label;
    if (!el.title || el.title.startsWith('[DDD]')) {
      const tip = tooltipFor(info);
      if (el.title !== tip) el.title = tip;
    }
  }

  function paintAll() {
    paintTimer = null;
    if (!enabled) return;
    const nodes = collectMessageNodes(); // all layout reads happen here, before any writes
    const current = new Set(nodes.map((n) => n.el));
    for (const { el, text } of nodes) {
      const info = labels.get(hashText(text));
      paintMessage(el, info && !HIDDEN_LABELS.has(info.label) ? info : null);
    }
    document.querySelectorAll('[data-ddd-msg]').forEach((el) => {
      if (!current.has(el)) paintMessage(el, null); // e.g. a sent message that was badged earlier
    });
  }

  // Throttled (not debounced) so badges keep up even while the chat is constantly updating.
  function schedulePaint() {
    if (paintTimer) return;
    paintTimer = setTimeout(paintAll, PAINT_THROTTLE_MS);
  }

  function clearMarks() {
    document.querySelectorAll('[data-ddd-msg]').forEach((el) => {
      delete el.dataset.dddMsg;
      if ((el.title || '').startsWith('[DDD]')) el.removeAttribute('title');
    });
  }

  // ------------------------------------------------------------- scanning

  async function scan() {
    if (!enabled) return;
    if (!chrome.runtime?.id) { stopObserving(); return; } // extension reloaded; this script is orphaned
    await appendMessages(collectMessageNodes());
    schedulePaint();
    classifyPending();
    globalThis.__DDD__?.onMessagesUpdated?.();
  }

  function scheduleScan() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(scan, SCAN_DEBOUNCE_MS);
  }

  function onDomChange() {
    scheduleScan();
    schedulePaint(); // chat apps recreate nodes while scrolling; re-apply badges quickly
  }

  // If nothing was ever recognised, say so in the console so the selectors can be fixed.
  function noMatchHint() {
    if (matchedEver || !SITE_SELECTORS[SITE]) return;
    console.info(
      `[DDD] No incoming messages recognised on ${SITE} yet. If a chat with received messages is open, `
      + 'the selectors for this site need updating (SITE_SELECTORS in messaging-text-capture.js).'
    );
  }

  async function startObserving() {
    if (observer) return;
    injectStyle();
    setTimeout(noMatchHint, 8000);
    observer = new MutationObserver(onDomChange);
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
    });
    try {
      const stored = await chrome.storage.local.get(STORAGE_KEY);
      rebuildLabels(stored[STORAGE_KEY]); // labels from earlier visits
    } catch { /* storage unavailable; labels will arrive with new results */ }
    schedulePaint();
    scan(); // capture whatever is already on screen
  }

  function stopObserving() {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    clearTimeout(debounceTimer);
    clearTimeout(paintTimer);
    paintTimer = null;
    try { clearMarks(); } catch { /* page may be unloading */ }
  }

  // Shared bridge used by url-checker.js in the same extension content-script world.
  globalThis.__DDD__ = Object.assign(globalThis.__DDD__ || {}, {
    getMessageNodes: () => collectMessageNodes().map(({ el, text, hasUrl, urlOnly }) => ({
      el,
      text,
      hasUrl,
      urlOnly,
      id: hashText(text),
    })),
    getMessageContainerSelector: () => MESSAGE_CONTAINER_SELECTORS[SITE] || null,
    setUrlFlags,
  });

  chrome.storage.local.get(['enabled'], (res) => {
    enabled = res.enabled !== false;
    if (enabled) startObserving();
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;

    if (changes[STORAGE_KEY]) {
      const list = changes[STORAGE_KEY].newValue;
      if (!list || list.length === 0) {
        seenThisSession.clear(); // data was cleared; allow re-capture
        urlFlags.clear();
        urlOnlyIds.clear();
      }
      rebuildLabels(list);
      schedulePaint();
    }

    if (changes.enabled) {
      enabled = changes.enabled.newValue !== false;
      if (enabled) startObserving();
      else stopObserving();
    }
  });
})();
