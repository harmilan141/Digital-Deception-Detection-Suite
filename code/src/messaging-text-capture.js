// Injected on the messaging domains declared in manifest.json.
// While the extension is enabled, this watches the page for new message-like
// text and appends each distinct message as its own entry in a growing array
// in chrome.storage.local, so a classifier can later walk the array and tag
// each entry as spam / not-spam / phishing / suspicious-link.

(() => {
  const SITE = location.hostname;
  const STORAGE_KEY = `messagingCapture:${SITE}`;
  const MAX_STORED = 500;        // cap so storage doesn't grow unbounded
  const MIN_LEN = 2;             // ignore near-empty lines
  const MAX_LEN = 2000;          // ignore giant blobs (e.g. a pasted document)
  const SCAN_DEBOUNCE_MS = 800;  // wait for the DOM to settle before scanning

  let enabled = true;
  let observer = null;
  let debounceTimer = null;
  const seenThisSession = new Set(); // avoid re-checking storage for lines we already added

  // Small non-cryptographic hash, used only to de-dupe message text.
  function hashText(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) {
      h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
    }
    return h.toString(36);
  }

  function extractCandidateMessages() {
    const raw = document.body?.innerText || '';
    return raw
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length >= MIN_LEN && line.length <= MAX_LEN);
  }

  async function appendMessages(lines) {
    if (lines.length === 0) return;

    const stored = await chrome.storage.local.get(STORAGE_KEY);
    const existing = stored[STORAGE_KEY] || [];
    const existingIds = new Set(existing.map((m) => m.id));

    const additions = [];
    for (const text of lines) {
      const id = hashText(text);
      if (seenThisSession.has(id) || existingIds.has(id)) continue;
      seenThisSession.add(id);
      additions.push({
        id,
        site: SITE,
        url: location.href,
        text,
        capturedAt: new Date().toISOString(),
        status: 'pending', // set by the classifier later: spam | not-spam | phishing | suspicious-link
      });
    }

    if (additions.length === 0) return;

    const merged = existing.concat(additions);
    const trimmed = merged.length > MAX_STORED
      ? merged.slice(merged.length - MAX_STORED)
      : merged;

    await chrome.storage.local.set({ [STORAGE_KEY]: trimmed });
  }

  function scan() {
    if (!enabled) return;
    appendMessages(extractCandidateMessages());
  }

  function scheduleScan() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(scan, SCAN_DEBOUNCE_MS);
  }

  function startObserving() {
    if (observer) return;
    observer = new MutationObserver(scheduleScan);
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
    });
    scan(); // capture whatever is already on screen
  }

  function stopObserving() {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    clearTimeout(debounceTimer);
  }

  chrome.storage.local.get(['enabled'], (res) => {
    enabled = res.enabled !== false;
    if (enabled) startObserving();
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !changes.enabled) return;
    enabled = changes.enabled.newValue !== false;
    if (enabled) startObserving();
    else stopObserving();
  });
})();