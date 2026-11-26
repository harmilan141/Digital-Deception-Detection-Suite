// background.js — MV3 service worker (fully in-browser, no external ML server)
//
// Two jobs:
//  1. CLASSIFY  : { type:'CLASSIFY', items:[{id,text}] }
//                 -> { ok, results:[{id,label,score,source,explanation,signals}] }
//     Classification uses a TF-IDF + Logistic Regression model loaded from
//     model/model_data.json (bundled with the extension).
//
//  2. CHECK_URLS: { type:'CHECK_URLS', urls:[...] }
//                 -> { ok, results:{ [url]:{verdict,reasons} } }
//     Combines local heuristics with Google Safe Browsing v4 (API key is
//     embedded below — replace SAFE_BROWSING_API_KEY with your key if needed).

// =========================================================================
// CONFIG
// =========================================================================

// Replace with a real Google Safe Browsing v4 API key.
// Get one at https://developers.google.com/safe-browsing/v4/get-started
const SAFE_BROWSING_API_KEY = 'AIzaSyBZQVMOOqpWFyeW2zuyS6ec7fvmJ61wPqI';

// Labels & priorities (lower = higher priority, wins in merge)
const LEVELS   = ['safe', 'suspicious', 'harmful'];
const PRIORITY = { harmful: 1, suspicious: 2, safe: 3 };

// =========================================================================
// IN-BROWSER ML — TF-IDF + Logistic Regression
// =========================================================================

let _model = null;   // loaded lazily on first CLASSIFY request

async function loadModel() {
  if (_model) return _model;
  const url = chrome.runtime.getURL('model/model_data.json');
  const res  = await fetch(url);
  if (!res.ok) throw new Error(`Failed to load model_data.json: HTTP ${res.status}`);
  _model = await res.json();
  return _model;
}

// Tokeniser matching sklearn's default: r"(?u)\b\w\w+\b"
const TOKEN_RE = /\b\w\w+\b/gu;

function tfidfVector(text, vocab, idf, sublinearTf) {
  const tf = {};
  const tokens = text.toLowerCase().match(TOKEN_RE) || [];
  for (const t of tokens) {
    if (t in vocab) tf[t] = (tf[t] || 0) + 1;
  }

  // Build sparse result as [index, value] pairs
  const sparse = [];
  for (const [term, cnt] of Object.entries(tf)) {
    const idx = vocab[term];
    if (idx === undefined) continue;
    const freq = sublinearTf ? (1 + Math.log(cnt)) : cnt;
    sparse.push([idx, freq * idf[idx]]);
  }

  // L2 normalise
  let norm = 0;
  for (const [, v] of sparse) norm += v * v;
  norm = Math.sqrt(norm);
  if (norm === 0) return sparse;
  return sparse.map(([i, v]) => [i, v / norm]);
}

function softmax(scores) {
  const max = Math.max(...scores);
  const exps = scores.map(s => Math.exp(s - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map(e => e / sum);
}

function inferOne(text, model) {
  const { vocabulary, idf, coef, intercept, classes, sublinear_tf } = model;
  const vec = tfidfVector(text, vocabulary, idf, Boolean(sublinear_tf));

  // scores[c] = dot(coef[c], x) + intercept[c]
  const scores = intercept.map((b, c) => {
    let s = b;
    for (const [i, v] of vec) s += coef[c][i] * v;
    return s;
  });

  const proba = softmax(scores);
  const probMap = {};
  classes.forEach((cls, i) => { probMap[cls] = proba[i]; });

  const hamP = probMap['ham'] || 0;
  const smishP = probMap['smishing'] || 0;
  const spamP = probMap['spam'] || 0;

  let label, score;
  if (smishP >= spamP && smishP >= hamP) {
    label = 'harmful'; score = round4(smishP);
  } else if (spamP >= smishP && spamP >= hamP) {
    label = 'suspicious'; score = round4(spamP);
  } else {
    label = 'safe'; score = round4(1 - hamP);
  }

  return {
    label,
    score,
    source: 'ml',
    explanation: '',
    signals: [],
    ml: { prediction: label === 'harmful' ? 'smishing' : (label === 'suspicious' ? 'spam' : 'ham'), probabilities: probMap },
  };
}

function round4(x) { return Math.round(x * 10000) / 10000; }

async function classifyMessages(items) {
  const model = await loadModel();
  return items.map(({ id, text }) => ({ id, ...inferOne(text, model) }));
}

// =========================================================================
// URL REPUTATION — Google Safe Browsing v4 + local heuristics
// =========================================================================

const SB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const SB_BATCH    = 500;
const CACHE_KEY   = 'urlVerdictCache';
const CACHE_TTL_MS  = 6 * 60 * 60 * 1000;
const CACHE_MAX   = 1000;
const MAX_URLS_PER_REQUEST = 100;

const SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','is.gd','ow.ly','cutt.ly',
  'rb.gy','shorturl.at','tiny.cc','buff.ly','rebrand.ly',
]);
const RISKY_TLDS = new Set([
  'zip','mov','tk','ml','ga','cf','gq','top','xyz','click',
  'rest','loan','icu','cyou','buzz',
]);
const BRANDS = {
  paypal:    ['paypal.com'],
  google:    ['google.com','googleusercontent.com','googleapis.com','gstatic.com','google.co.in'],
  microsoft: ['microsoft.com','microsoftonline.com','live.com','office.com'],
  apple:     ['apple.com','icloud.com'],
  amazon:    ['amazon.com','amazon.in','amazonaws.com'],
  facebook:  ['facebook.com','fb.com'],
  instagram: ['instagram.com'],
  whatsapp:  ['whatsapp.com','whatsapp.net'],
  netflix:   ['netflix.com'],
  binance:   ['binance.com'],
  coinbase:  ['coinbase.com'],
  metamask:  ['metamask.io'],
  paytm:     ['paytm.com'],
  phonepe:   ['phonepe.com'],
  hdfc:      ['hdfcbank.com'],
  icici:     ['icicibank.com'],
};
const THREAT_LABELS = {
  MALWARE: 'malware',
  SOCIAL_ENGINEERING: 'phishing / social engineering',
  UNWANTED_SOFTWARE: 'unwanted software',
  POTENTIALLY_HARMFUL_APPLICATION: 'harmful application',
};
const isOrSub = (host, domain) => host === domain || host.endsWith('.' + domain);

function analyzeUrl(urlStr) {
  const reasons = [];
  let score = 0;
  const add = (pts, why) => { score += pts; reasons.push(why); };

  let u;
  try { u = new URL(urlStr); } catch { return { score: 3, reasons: ['Malformed URL'] }; }

  const host   = u.hostname.toLowerCase();
  const labels = host.split('.');
  const tokens = host.split(/[.\-]/);

  if (u.protocol === 'http:') add(1, 'Does not use HTTPS');
  if (u.username || u.password) add(3, 'Has credentials in the URL (the "@" trick)');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) add(3, 'Uses a raw IP address instead of a domain');
  if (labels.some(l => l.startsWith('xn--'))) add(2, 'Punycode domain (may use lookalike characters)');
  if (SHORTENERS.has(host)) add(1, 'Link shortener hides the real destination');
  if (RISKY_TLDS.has(labels[labels.length - 1])) add(1, `Uncommon top-level domain (.${labels[labels.length - 1]})`);
  if (labels.length > 5) add(1, 'Unusually many subdomains');

  const lure = '(login|signin|verify|secure|update|account|wallet|claim|airdrop|support)';
  if (new RegExp(`-${lure}|${lure}-`).test(host)) add(1, 'Hyphenated "login/verify/secure"-style domain');

  for (const [brand, legit] of Object.entries(BRANDS)) {
    const mentions = tokens.includes(brand) || (brand.length >= 6 && host.includes(brand));
    if (mentions && !legit.some(d => isOrSub(host, d))) {
      add(2, `Mentions "${brand}" but is not a ${brand} domain`);
      break;
    }
  }
  return { score, reasons };
}

async function lookupSafeBrowsing(urls) {
  const flagged = new Map();
  for (let i = 0; i < urls.length; i += SB_BATCH) {
    const chunk = urls.slice(i, i + SB_BATCH);
    const res = await fetch(`${SB_ENDPOINT}?key=${encodeURIComponent(SAFE_BROWSING_API_KEY)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'digital-deception-detection-suite', clientVersion: '2.0' },
        threatInfo: {
          threatTypes: Object.keys(THREAT_LABELS),
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: chunk.map(url => ({ url })),
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
        keys.sort((a, b) => cache[a].t - cache[b].t)
          .slice(0, keys.length - CACHE_MAX)
          .forEach(k => delete cache[k]);
      }
      await chrome.storage.local.set({ [CACHE_KEY]: cache });
    })
    .catch(e => console.warn('[DDD] cache write failed', e));
  return cacheWrite;
}

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

  let flagged = null;
  let lookupFailed = false;
  try {
    flagged = await lookupSafeBrowsing(toCheck);
  } catch (e) {
    console.warn('[DDD] Safe Browsing lookup failed:', e);
    lookupFailed = true;
  }

  const fresh = {};
  for (const url of toCheck) {
    const { score, reasons } = analyzeUrl(url);
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
        : 'Only local heuristics ran');
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
  if (msg?.type === 'CLASSIFY') {
    const items = (Array.isArray(msg.items) ? msg.items : [])
      .filter(m => m && typeof m.id === 'string' && typeof m.text === 'string')
      .slice(0, 100)
      .map(({ id, text }) => ({ id, text }));

    classifyMessages(items)
      .then(results => sendResponse({ ok: true, results }))
      .catch(err => {
        console.warn('[DDD] classify failed:', err);
        sendResponse({ ok: false, error: String(err) });
      });
    return true;
  }

  if (msg?.type === 'CHECK_URLS') {
    const urls = (Array.isArray(msg.urls) ? msg.urls : [])
      .filter(u => typeof u === 'string' && /^https?:\/\//i.test(u))
      .slice(0, MAX_URLS_PER_REQUEST);

    checkUrls(urls)
      .then(results => sendResponse({ ok: true, results }))
      .catch(err => sendResponse({ ok: false, error: String(err) }));
    return true;
  }
});
