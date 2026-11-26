// background.js — MV3 service worker. Two jobs:
//
//  1. CHECK_URLS : { type:'CHECK_URLS', urls:[...] }        -> { ok, results:{ [url]:{verdict,reasons} } }
//  2. CLASSIFY   : { type:'CLASSIFY',   items:[{id,text}] } -> { ok, results:[{id,label,score,...}] }
//
// Settings kept in chrome.storage.local (all optional):
//   safeBrowsingKey : Google Safe Browsing API key (set from the popup)
//   mlApiUrl        : override the ML server URL (default below)
//   mlApiToken      : sent as X-API-Key if the server has API_TOKEN set
// To change mlApiUrl/mlApiToken, run in THIS service worker's DevTools console:
//   chrome.storage.local.set({ mlApiUrl: 'https://your-host/classify', mlApiToken: '...' })
// and add that host to "host_permissions" in manifest.json.

// =========================================================================
// 1. ML MESSAGE CLASSIFICATION
// =========================================================================

const ML_DEFAULT_URL = 'http://127.0.0.1:8000/classify';
const ML_TIMEOUT_MS = 30000;      // Gemini can be slow on a cold request
const ML_MAX_ITEMS = 100;

async function classifyMessages(items) {
  const { mlApiUrl, mlApiToken } = await chrome.storage.local.get(['mlApiUrl', 'mlApiToken']);

  const headers = { 'Content-Type': 'application/json' };
  if (mlApiToken) headers['X-API-Key'] = mlApiToken;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ML_TIMEOUT_MS);
  try {
    const res = await fetch(mlApiUrl || ML_DEFAULT_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify({ messages: items }),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`Model API HTTP ${res.status}`);
    const data = await res.json();
    return Array.isArray(data.results) ? data.results : [];
  } finally {
    clearTimeout(timer);
  }
}

// =========================================================================
// 2. URL REPUTATION (Google Safe Browsing + local heuristics)
// =========================================================================

const SB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const SB_BATCH = 500;
const CACHE_KEY = 'urlVerdictCache';
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const CACHE_MAX = 1000;
const MAX_URLS_PER_REQUEST = 100;

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'cutt.ly',
  'rb.gy', 'shorturl.at', 'tiny.cc', 'buff.ly', 'rebrand.ly',
]);

const RISKY_TLDS = new Set([
  'zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'click',
  'rest', 'loan', 'icu', 'cyou', 'buzz',
]);

const BRANDS = {
  paypal: ['paypal.com'],
  google: ['google.com', 'googleusercontent.com', 'googleapis.com', 'gstatic.com', 'google.co.in'],
  microsoft: ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com'],
  apple: ['apple.com', 'icloud.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazonaws.com'],
  facebook: ['facebook.com', 'fb.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com', 'whatsapp.net'],
  netflix: ['netflix.com'],
  binance: ['binance.com'],
  coinbase: ['coinbase.com'],
  metamask: ['metamask.io'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  hdfc: ['hdfcbank.com'],
  icici: ['icicibank.com'],
};

const THREAT_LABELS = {
  MALWARE: 'malware',
  SOCIAL_ENGINEERING: 'phishing / social engineering',
  UNWANTED_SOFTWARE: 'unwanted software',
  POTENTIALLY_HARMFUL_APPLICATION: 'harmful application',
};

const isOrSub = (host, domain) => host === domain || host.endsWith('.' + domain);

function analyze(urlStr) {
  const reasons = [];
  let score = 0;
  const add = (points, why) => { score += points; reasons.push(why); };

  let u;
  try { u = new URL(urlStr); } catch { return { score: 3, reasons: ['Malformed URL'] }; }

  const host = u.hostname.toLowerCase();
  const labels = host.split('.');
  const tokens = host.split(/[.\-]/);

  if (u.protocol === 'http:') add(1, 'Does not use HTTPS');
  if (u.username || u.password) add(3, 'Has credentials in the URL (the "@" trick)');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) add(3, 'Uses a raw IP address instead of a domain');
  if (labels.some((l) => l.startsWith('xn--'))) add(2, 'Punycode domain (may use lookalike characters)');
  if (SHORTENERS.has(host)) add(1, 'Link shortener hides the real destination');
  if (RISKY_TLDS.has(labels[labels.length - 1])) add(1, `Uncommon top-level domain (.${labels[labels.length - 1]})`);
  if (labels.length > 5) add(1, 'Unusually many subdomains');

  const lure = '(login|signin|verify|secure|update|account|wallet|claim|airdrop|support)';
  if (new RegExp(`-${lure}|${lure}-`).test(host)) add(1, 'Hyphenated "login/verify/secure"-style domain');

  for (const [brand, legit] of Object.entries(BRANDS)) {
    const mentions = tokens.includes(brand) || (brand.length >= 6 && host.includes(brand));
    if (mentions && !legit.some((d) => isOrSub(host, d))) {
      add(2, `Mentions "${brand}" but is not a ${brand} domain`);
      break;
    }
  }

  return { score, reasons };
}

async function lookupSafeBrowsing(urls, apiKey) {
  const flagged = new Map();

  for (let i = 0; i < urls.length; i += SB_BATCH) {
    const chunk = urls.slice(i, i + SB_BATCH);
    const res = await fetch(`${SB_ENDPOINT}?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'digital-deception-detection-suite', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: Object.keys(THREAT_LABELS),
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: chunk.map((url) => ({ url })),
        },
      }),
    });
    if (!res.ok) throw new Error(`Safe Browsing HTTP ${res.status}`);

    const data = await res.json();
    for (const m of data.matches || []) {
      const set = flagged.get(m.threat.url) || new Set();
      set.add(THREAT_LABELS[m.threatType] || m.threatType);
      flagged.set(m.threat.url, set);
    }
  }
  return flagged;
}

let cacheWrite = Promise.resolve();

async function loadCache() {
  return (await chrome.storage.local.get(CACHE_KEY))[CACHE_KEY] || {};
}

function saveCache(fresh) {
  cacheWrite = cacheWrite
    .then(async () => {
      const cache = await loadCache();
      Object.assign(cache, fresh);
      const keys = Object.keys(cache);
      if (keys.length > CACHE_MAX) {
        keys
          .sort((a, b) => cache[a].t - cache[b].t)
          .slice(0, keys.length - CACHE_MAX)
          .forEach((k) => delete cache[k]);
      }
      await chrome.storage.local.set({ [CACHE_KEY]: cache });
    })
    .catch((e) => console.warn('[DDD] cache write failed', e));
  return cacheWrite;
}

// Changing the API key invalidates earlier verdicts (e.g. cached "unknown"s).
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.safeBrowsingKey) {
    chrome.storage.local.remove(CACHE_KEY);
  }
});

async function checkUrls(urls) {
  const now = Date.now();
  const cache = await loadCache();
  const results = {};
  const toCheck = [];

  for (const url of new Set(urls)) {
    const hit = cache[url];
    if (hit && now - hit.t < CACHE_TTL_MS) results[url] = hit;
    else toCheck.push(url);
  }
  if (toCheck.length === 0) return results;

  const { safeBrowsingKey } = await chrome.storage.local.get('safeBrowsingKey');
  let flagged = null;
  let lookupFailed = false;
  if (safeBrowsingKey) {
    try {
      flagged = await lookupSafeBrowsing(toCheck, safeBrowsingKey);
    } catch (e) {
      console.warn('[DDD] Safe Browsing lookup failed:', e);
      lookupFailed = true;
    }
  }

  const fresh = {};
  for (const url of toCheck) {
    const { score, reasons } = analyze(url);
    const threats = flagged?.get(url);
    let verdict;

    if (threats) {
      verdict = 'unsafe';
      reasons.unshift(`Flagged by Google Safe Browsing: ${[...threats].join(', ')}`);
    } else if (score >= 3) {
      verdict = 'unsafe';
    } else if (score >= 1) {
      verdict = 'caution';
    } else if (flagged) {
      verdict = 'safe';
      reasons.push('Not on Google Safe Browsing lists (this is not a guarantee)');
    } else {
      verdict = 'unknown';
      reasons.push(lookupFailed
        ? 'Reputation lookup failed; only local checks ran'
        : 'No Safe Browsing API key set; only local checks ran');
    }

    const entry = { verdict, reasons, t: now };
    results[url] = entry;
    if (!lookupFailed) fresh[url] = entry;
  }

  if (Object.keys(fresh).length) await saveCache(fresh);
  return results;
}

// =========================================================================
// MESSAGE ROUTER
// =========================================================================

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'CHECK_URLS') {
    const urls = (Array.isArray(msg.urls) ? msg.urls : [])
      .filter((u) => typeof u === 'string' && /^https?:\/\//i.test(u))
      .slice(0, MAX_URLS_PER_REQUEST);

    checkUrls(urls)
      .then((results) => sendResponse({ ok: true, results }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (msg?.type === 'CLASSIFY') {
    const items = (Array.isArray(msg.items) ? msg.items : [])
      .filter((m) => m && typeof m.id === 'string' && typeof m.text === 'string')
      .slice(0, ML_MAX_ITEMS)
      .map(({ id, text }) => ({ id, text }));

    classifyMessages(items)
      .then((results) => sendResponse({ ok: true, results }))
      .catch((err) => {
        console.warn('[DDD] ML classify failed:', err);
        sendResponse({ ok: false, error: String(err) });
      });
    return true;
  }
});
