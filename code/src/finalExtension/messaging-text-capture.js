// messaging-text-capture.js — injected into supported messaging sites.
//
// Logic:
//  1. Scrapes incoming message text via site-specific selectors.
//  2. Analyses each message:
//       URL-only  → skipped by ML; only the URL checker labels it.
//       URL+text  → URL stripped before sending text to ML; both verdicts merged by priority.
//       Text-only → sent to ML.
//  3. Priority: harmful=1 < suspicious=2 < safe=3  (lower wins).
//     "low_risk" from ML is normalised to "safe".
//  4. Renders a coloured badge on the message element itself — no link underlining.

(() => {
  const SITE        = location.hostname;
  const STORAGE_KEY = `ddd:messages:${SITE}`;
  const MAX_STORED  = 500;
  const MIN_LEN     = 2;
  const MAX_LEN     = 2000;
  const SCAN_DEBOUNCE_MS  = 800;
  const PAINT_THROTTLE_MS = 200;
  const CLASSIFY_BATCH    = 50;
  const RETRY_BACKOFF_MS  = 30000;

  const VALID_LABELS = new Set(['safe', 'suspicious', 'harmful']);
  const PRIORITY     = { harmful: 1, suspicious: 2, safe: 3 };
  const LABEL_NAMES  = { safe: 'Safe', suspicious: 'Suspicious', harmful: 'Harmful' };

  const URL_PATTERN   = /\b(?:https?:\/\/|www\.)[^\s<>"{}|\\^`[\]]+/gi;
  const DOMAIN_TEXT_RE = /^(?:https?:\/\/)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:[/?#:]\S*)?$/i;

  const HIDDEN_LABELS = new Set();     // set e.g. new Set(['safe']) to hide safe badges
  const SKIP_OWN_MESSAGES = true;

  const OWN_MSG_SEL = {
    'web.whatsapp.com':   '.message-out, [data-id^="true_"]',
    'web.telegram.org':   '.bubble.is-out, .Message.own',
  };
  const OWN_BY_POSITION = new Set([
    'web.whatsapp.com', 'web.telegram.org', 'messenger.com', 'www.messenger.com',
  ]);
  const PANE_SEL = {
    'web.whatsapp.com':   '#main',
    'web.telegram.org':   '#column-center, #MiddleColumn',
    'messenger.com':      '[role="main"]',
    'www.messenger.com':  '[role="main"]',
  };
  const SKIP_INSIDE_SEL = {
    'web.whatsapp.com':   '[aria-label^="Quoted"], [data-testid="quoted-message"]',
    'messenger.com':      '[aria-label^="Replying to"], [data-testid="reply_to_message"]',
    'www.messenger.com':  '[aria-label^="Replying to"], [data-testid="reply_to_message"]',
  };
  const SITE_SEL = {
    'web.whatsapp.com':  ['[data-pre-plain-text] span.selectable-text', 'span.selectable-text.copyable-text'],
    'discord.com':       ['[id^="message-content-"]'],
    'app.slack.com':     ['.p-rich_text_section'],
    'web.telegram.org':  ['.Message .text-content', '.bubble-content .message', '.bubble .message', '.message.spoilers-container', '.text-content'],
    'messenger.com':     ['[data-testid="message-container"] [dir="auto"]', '[role="main"] [role="row"] div[dir="auto"]'],
    'www.messenger.com': ['[data-testid="message-container"] [dir="auto"]', '[role="main"] [role="row"] div[dir="auto"]'],
  };
  const CONTAINER_SEL = {
    'web.whatsapp.com':  '[data-pre-plain-text], [data-id]',
    'discord.com':       '[id^="chat-messages-"], li[class*="messageListItem"]',
    'app.slack.com':     '[data-qa="message_container"], .c-message_kit__background',
    'web.telegram.org':  '.bubble, .Message',
    'messenger.com':     '[data-testid="message-container"], [role="row"]',
    'www.messenger.com': '[data-testid="message-container"], [role="row"]',
  };
  const TEXT_IGNORE_SEL = {
    'web.telegram.org':  '.MessageMeta, .time, .reactions, .Reactions',
  };
  const NOISE_RE = [/^\d{1,2}:\d{2}(\s?[ap]\.?m\.?)?$/i];

  const STYLE_ID = '__ddd_msg_style__';

  let enabled       = true;
  let observer      = null;
  let debounceTimer = null;
  let paintTimer    = null;
  let classifying   = false;
  let retryAfter    = 0;
  let warnedNoSel   = false;
  let matchedEver   = false;

  const seenThisSession = new Set();
  const labels    = new Map();   // id → effective verdict object
  const mlResults = new Map();   // id → ml verdict
  const urlFlags  = new Map();   // id → url verdict
  const urlOnlyIds = new Set();  // ids that contain only URL(s) — skip ML

  let writeChain = Promise.resolve();
  const enqueue = fn => { const p = writeChain.then(fn); writeChain = p.catch(() => {}); return p; };

  function hashText(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
    return h.toString(36);
  }
  const normLabel = l => (l === 'low_risk' ? 'safe' : l);

  // ── extraction ──────────────────────────────────────────────────────────

  function nodeText(el) {
    const ign = TEXT_IGNORE_SEL[SITE];
    if (ign) { const c = el.cloneNode(true); c.querySelectorAll(ign).forEach(n => n.remove()); return (c.textContent || '').trim(); }
    return (el.innerText || el.textContent || '').trim();
  }
  const isCandidate = t => t.length >= MIN_LEN && t.length <= MAX_LEN && !NOISE_RE.some(r => r.test(t));

  function analyzeContent(el, raw) {
    let hasUrl = URL_PATTERN.test(raw); URL_PATTERN.lastIndex = 0;
    let stripped = raw.replace(URL_PATTERN, ' '); URL_PATTERN.lastIndex = 0;
    for (const a of el.querySelectorAll('a[href]')) {
      const href = a.getAttribute('href') || '';
      if (!/^https?:\/\//i.test(href)) continue;
      hasUrl = true;
      const lt = (a.textContent || '').trim();
      if (lt && DOMAIN_TEXT_RE.test(lt)) stripped = stripped.split(lt).join(' ');
    }
    const textForMl = stripped.replace(/\s+/g, ' ').trim();
    const alpha = textForMl.replace(/[\s.,!?;:()\[\]{}'"<>|/\\-]+/g, '');
    return { hasUrl, urlOnly: hasUrl && alpha.length < 2, mlText: alpha.length >= 2 ? textForMl : '' };
  }

  function isOnRightSide(el) {
    const bbl = el.closest('[data-pre-plain-text], .bubble-content, .message-content, [data-testid="message-container"]') || el;
    const r = bbl.getBoundingClientRect();
    if (!r.width) return false;
    const paneSel = PANE_SEL[SITE];
    const pane = paneSel ? document.querySelector(paneSel) : null;
    let left = 0, right = document.documentElement.clientWidth;
    if (pane) { const p = pane.getBoundingClientRect(); if (p.width) { left = p.left; right = p.right; } }
    return (right - r.right) < (r.left - left);
  }
  function isOwnMessage(el) {
    const sel = OWN_MSG_SEL[SITE];
    if (sel && el.closest(sel)) return true;
    return OWN_BY_POSITION.has(SITE) && isOnRightSide(el);
  }

  function collectNodes() {
    const sels = SITE_SEL[SITE];
    if (!sels) {
      if (!warnedNoSel) { warnedNoSel = true; console.info(`[DDD] No selector for ${SITE}`); }
      return [];
    }
    const skip = SKIP_INSIDE_SEL[SITE];
    for (const sel of sels) {
      const nodes = [];
      for (const el of document.querySelectorAll(sel)) {
        if (el.closest('[contenteditable="true"]')) continue;
        if (skip && el.closest(skip)) continue;
        if (SKIP_OWN_MESSAGES && isOwnMessage(el)) continue;
        const text = nodeText(el);
        if (!isCandidate(text)) continue;
        nodes.push({ el, text, ...analyzeContent(el, text) });
      }
      if (nodes.length) { matchedEver = true; return nodes; }
    }
    return [];
  }

  // ── verdict merging ──────────────────────────────────────────────────────

  function mergeVerdicts(ml, urlFlag, urlOnly = false) {
    const mlLabel  = ml ? normLabel(ml.label) : null;
    const urlLabel = urlFlag ? normLabel(urlFlag.label) : null;
    const hasMl    = !urlOnly && Boolean(mlLabel && VALID_LABELS.has(mlLabel));
    const hasUrl   = Boolean(urlLabel && VALID_LABELS.has(urlLabel));

    if (urlOnly) {
      if (hasUrl) {
        const reasons = Array.isArray(urlFlag.reasons) ? urlFlag.reasons : [];
        return { label: urlLabel, score: urlFlag.score, source: 'url', explanation: reasons.length ? `URL check: ${reasons.join('; ')}` : '', signals: urlLabel === 'safe' ? [] : [LABEL_NAMES[urlLabel] + ' link'] };
      }
      if (urlFlag?.label === 'unknown') return { label: 'unclassified', source: 'url', explanation: 'URL not verified', signals: [] };
      return null;
    }

    if (hasMl && hasUrl) {
      const label   = PRIORITY[urlLabel] < PRIORITY[mlLabel] ? urlLabel : mlLabel;
      const scores  = [ml.score, urlFlag.score].filter(s => typeof s === 'number');
      const expParts = [];
      if (ml.explanation) expParts.push(ml.explanation);
      if (Array.isArray(urlFlag.reasons) && urlFlag.reasons.length) expParts.push(`URL (${urlLabel}): ${urlFlag.reasons.join('; ')}`);
      const signals = [...(Array.isArray(ml.signals) ? ml.signals : [])];
      if (urlLabel !== 'safe' && !signals.includes(`${LABEL_NAMES[urlLabel]} link`)) signals.push(`${LABEL_NAMES[urlLabel]} link`);
      return { label, score: scores.length ? Math.max(...scores) : undefined, source: `${ml.source || 'ml'}+url`, explanation: expParts.join(' | '), signals };
    }

    if (hasMl) return { label: mlLabel, score: ml.score, source: ml.source || 'ml', explanation: ml.explanation || '', signals: Array.isArray(ml.signals) ? ml.signals : [] };

    if (hasUrl && (urlLabel === 'harmful' || urlLabel === 'suspicious')) {
      const reasons = Array.isArray(urlFlag.reasons) ? urlFlag.reasons : [];
      return { label: urlLabel, score: urlFlag.score, source: 'url', explanation: reasons.join('; '), signals: [`${LABEL_NAMES[urlLabel]} link`] };
    }
    return null;
  }

  function applyEffectiveFields(m) {
    const merged = mergeVerdicts(m.ml, m.urlFlag, Boolean(m.urlOnly));
    if (merged) { Object.assign(m, { status: merged.label, score: merged.score, source: merged.source, explanation: merged.explanation, signals: merged.signals }); }
    else if (!m.urlOnly && m.ml?.label === 'unclassified') m.status = 'unclassified';
  }

  function refreshInMemoryLabel(id) {
    const merged = mergeVerdicts(mlResults.get(id), urlFlags.get(id), urlOnlyIds.has(id));
    if (merged && VALID_LABELS.has(merged.label)) labels.set(id, merged); else labels.delete(id);
  }

  // ── storage ──────────────────────────────────────────────────────────────

  function appendMessages(nodes) {
    if (!nodes.length) return Promise.resolve();
    return enqueue(async () => {
      const stored = await chrome.storage.local.get(STORAGE_KEY);
      const existing = stored[STORAGE_KEY] || [];
      const existingIds = new Set(existing.map(m => m.id));
      const additions = [];
      for (const node of nodes) {
        const id = hashText(node.text);
        if (node.urlOnly) urlOnlyIds.add(id);
        if (seenThisSession.has(id) || existingIds.has(id)) continue;
        seenThisSession.add(id);
        const entry = { id, site: SITE, url: location.href, text: node.text, mlText: node.mlText, hasUrl: node.hasUrl, urlOnly: node.urlOnly, capturedAt: new Date().toISOString(), status: 'pending' };
        if (urlFlags.has(id)) { entry.urlFlag = urlFlags.get(id); applyEffectiveFields(entry); }
        additions.push(entry);
      }
      if (!additions.length) return;
      const merged = existing.concat(additions);
      await chrome.storage.local.set({ [STORAGE_KEY]: merged.length > MAX_STORED ? merged.slice(merged.length - MAX_STORED) : merged });
    });
  }

  function pickPending() {
    return enqueue(async () => {
      const stored = await chrome.storage.local.get(STORAGE_KEY);
      return (stored[STORAGE_KEY] || [])
        .filter(m => !m.urlOnly && (m.status === 'pending' || (m.urlFlag && !m.ml)))
        .slice(-CLASSIFY_BATCH)
        .map(m => ({ id: m.id, text: m.mlText || m.text }));
    });
  }

  function applyResults(batch, results) {
    return enqueue(async () => {
      const byId   = new Map(results.map(r => [r.id, r]));
      const batchIds = new Set(batch.map(b => b.id));
      const stored = await chrome.storage.local.get(STORAGE_KEY);
      const list   = stored[STORAGE_KEY] || [];
      for (const m of list) {
        if (!batchIds.has(m.id)) continue;
        const r  = byId.get(m.id);
        const nl = r ? normLabel(r.label) : null;
        if (r && VALID_LABELS.has(nl)) {
          m.ml = { label: nl, score: r.score, source: r.source || 'ml', explanation: r.explanation || '', signals: r.signals || [] };
          m.classifiedAt = new Date().toISOString();
          mlResults.set(m.id, m.ml);
        } else {
          m.ml = { label: 'unclassified' };
        }
        if (!m.urlFlag && urlFlags.has(m.id)) m.urlFlag = urlFlags.get(m.id);
        applyEffectiveFields(m);
      }
      await chrome.storage.local.set({ [STORAGE_KEY]: list });
      rebuildLabels(list); schedulePaint();
    });
  }

  function persistUrlFlags(flagged) {
    if (!flagged.size) return Promise.resolve();
    return enqueue(async () => {
      const stored = await chrome.storage.local.get(STORAGE_KEY);
      const list   = stored[STORAGE_KEY] || [];
      let changed  = false;
      for (const m of list) {
        const flag = flagged.get(m.id); if (!flag) continue;
        if (!m.ml && !m.urlOnly && VALID_LABELS.has(normLabel(m.status)) && m.source !== 'url') {
          m.ml = { label: normLabel(m.status), score: m.score, source: m.source || 'ml', explanation: m.explanation || '', signals: m.signals || [] };
          mlResults.set(m.id, m.ml);
        }
        if (JSON.stringify(m.urlFlag || null) !== JSON.stringify(flag)) { m.urlFlag = flag; applyEffectiveFields(m); changed = true; }
      }
      if (changed) { await chrome.storage.local.set({ [STORAGE_KEY]: list }); rebuildLabels(list); schedulePaint(); }
    });
  }

  function setUrlFlags(flagsById) {
    if (!flagsById?.size) return;
    let changed = false;
    const toPersist = new Map();
    for (const [id, flag] of flagsById) {
      if (!flag || (!VALID_LABELS.has(flag.label) && flag.label !== 'unknown')) continue;
      if (JSON.stringify(urlFlags.get(id) || null) !== JSON.stringify(flag)) { urlFlags.set(id, flag); refreshInMemoryLabel(id); changed = true; }
      toPersist.set(id, flag);
    }
    if (changed) schedulePaint();
    persistUrlFlags(toPersist);
  }

  // ── classification ───────────────────────────────────────────────────────

  async function classifyPending() {
    if (classifying || Date.now() < retryAfter) return;
    classifying = true;
    try {
      while (enabled && chrome.runtime?.id) {
        const batch = await pickPending();
        if (!batch.length) break;
        let resp = null;
        try { resp = await chrome.runtime.sendMessage({ type: 'CLASSIFY', items: batch }); } catch { }
        if (!resp?.ok) { retryAfter = Date.now() + RETRY_BACKOFF_MS; break; }
        await applyResults(batch, resp.results);
      }
    } finally { classifying = false; }
  }

  // ── badges ───────────────────────────────────────────────────────────────

  function injectStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const s = document.createElement('style'); s.id = STYLE_ID;
    s.textContent = `
      [data-ddd-msg]::after {
        display:inline-block; margin-left:6px; padding:2px 7px;
        border-radius:9px; font:600 10px/1.3 system-ui,sans-serif;
        letter-spacing:.2px; white-space:nowrap; vertical-align:middle; user-select:none;
      }
      [data-ddd-msg="safe"]::after       { content:"\\2713\\00A0Safe";       background:#dcfce7;color:#15803d; }
      [data-ddd-msg="suspicious"]::after { content:"\\26A0\\00A0Suspicious"; background:#ffedd5;color:#c2410c; }
      [data-ddd-msg="harmful"]::after    { content:"\\26D4\\00A0Harmful";    background:#fee2e2;color:#b91c1c; }
      [data-ddd-msg="suspicious"] { background:rgba(249,115,22,.22);border-radius:4px;box-decoration-break:clone;-webkit-box-decoration-break:clone; }
      [data-ddd-msg="harmful"]    { background:rgba(220,38,38,.28); border-radius:4px;box-decoration-break:clone;-webkit-box-decoration-break:clone; }
    `;
    document.documentElement.appendChild(s);
  }

  function rebuildLabels(list) {
    labels.clear(); mlResults.clear();
    for (const m of list || []) {
      if (m.urlOnly) urlOnlyIds.add(m.id);
      const mlN = m.ml ? normLabel(m.ml.label) : null;
      const stN = normLabel(m.status);
      const ml  = (m.ml && VALID_LABELS.has(mlN)) ? { ...m.ml, label: mlN }
        : (!m.urlOnly && VALID_LABELS.has(stN) && m.source !== 'url')
          ? { label: stN, score: m.score, source: m.source || 'ml', explanation: m.explanation, signals: m.signals } : null;
      if (ml) mlResults.set(m.id, ml);
      if (m.urlFlag && (VALID_LABELS.has(normLabel(m.urlFlag.label)) || m.urlFlag.label === 'unknown')) urlFlags.set(m.id, m.urlFlag);
      const merged = mergeVerdicts(ml, urlFlags.get(m.id), Boolean(m.urlOnly));
      if (merged && VALID_LABELS.has(merged.label)) labels.set(m.id, merged);
    }
    for (const id of urlFlags.keys()) if (!labels.has(id)) refreshInMemoryLabel(id);
  }

  function tooltipFor(info) {
    const lines = [`[DDD] ${LABEL_NAMES[info.label]}` + (typeof info.score === 'number' ? ` (risk ${Math.round(info.score * 100)}%)` : '')];
    if (info.explanation) lines.push(info.explanation);
    if (info.signals?.length) lines.push(`Signals: ${info.signals.join(', ')}`);
    return lines.join('\n');
  }
  function paintMessage(el, info) {
    if (!info) { if (el.dataset.dddMsg) { delete el.dataset.dddMsg; if ((el.title || '').startsWith('[DDD]')) el.removeAttribute('title'); } return; }
    if (el.dataset.dddMsg !== info.label) el.dataset.dddMsg = info.label;
    if (!el.title || el.title.startsWith('[DDD]')) { const t = tooltipFor(info); if (el.title !== t) el.title = t; }
  }
  function paintAll() {
    paintTimer = null; if (!enabled) return;
    const nodes   = collectNodes();
    const current = new Set(nodes.map(n => n.el));
    for (const { el, text } of nodes) { const info = labels.get(hashText(text)); paintMessage(el, info && !HIDDEN_LABELS.has(info.label) ? info : null); }
    document.querySelectorAll('[data-ddd-msg]').forEach(el => { if (!current.has(el)) paintMessage(el, null); });
  }
  const schedulePaint = () => { if (paintTimer) return; paintTimer = setTimeout(paintAll, PAINT_THROTTLE_MS); };

  // ── scanning ─────────────────────────────────────────────────────────────

  async function scan() {
    if (!enabled) return;
    if (!chrome.runtime?.id) { stopObserving(); return; }
    await appendMessages(collectNodes());
    schedulePaint(); classifyPending();
    globalThis.__DDD__?.onMessagesUpdated?.();
  }
  const scheduleScan = () => { clearTimeout(debounceTimer); debounceTimer = setTimeout(scan, SCAN_DEBOUNCE_MS); };
  const onDomChange  = () => { scheduleScan(); schedulePaint(); };

  function noMatchHint() {
    if (matchedEver || !SITE_SEL[SITE]) return;
    console.info(`[DDD] No messages recognised on ${SITE} yet — selectors may need updating.`);
  }

  async function startObserving() {
    if (observer) return;
    injectStyle();
    setTimeout(noMatchHint, 8000);
    observer = new MutationObserver(onDomChange);
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    try { const s = await chrome.storage.local.get(STORAGE_KEY); rebuildLabels(s[STORAGE_KEY]); } catch { }
    schedulePaint(); scan();
  }
  function stopObserving() {
    observer?.disconnect(); observer = null;
    clearTimeout(debounceTimer); clearTimeout(paintTimer); paintTimer = null;
    try { document.querySelectorAll('[data-ddd-msg]').forEach(el => { delete el.dataset.dddMsg; if ((el.title || '').startsWith('[DDD]')) el.removeAttribute('title'); }); } catch { }
  }

  // ── shared bridge for url-checker.js ────────────────────────────────────

  globalThis.__DDD__ = Object.assign(globalThis.__DDD__ || {}, {
    getMessageNodes:            () => collectNodes().map(({ el, text, hasUrl, urlOnly }) => ({ el, text, hasUrl, urlOnly, id: hashText(text) })),
    getMessageContainerSelector: () => CONTAINER_SEL[SITE] || null,
    setUrlFlags,
  });

  // ── boot ─────────────────────────────────────────────────────────────────

  chrome.storage.local.get(['enabled'], res => { enabled = res.enabled !== false; if (enabled) startObserving(); });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes[STORAGE_KEY]) { const list = changes[STORAGE_KEY].newValue; if (!list?.length) { seenThisSession.clear(); urlFlags.clear(); urlOnlyIds.clear(); } rebuildLabels(list); schedulePaint(); }
    if (changes.enabled) { enabled = changes.enabled.newValue !== false; if (enabled) startObserving(); else stopObserving(); }
  });
})();
