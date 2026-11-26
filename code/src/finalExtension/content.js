// content.js — shows a brief on-page banner when the user enables/disables the extension.

const BANNER_ID  = '__ddd_banner__';
const DISPLAY_MS = 2000;
const ANIM_MS    = 300;

let hideTimer = null;
let removeTimer = null;

function clearBannerTimers() {
  clearTimeout(hideTimer);
  clearTimeout(removeTimer);
  hideTimer = removeTimer = null;
}
function removeBannerNow() {
  clearBannerTimers();
  document.getElementById(BANNER_ID)?.remove();
}
function showBanner(enabled) {
  removeBannerNow();
  const banner = document.createElement('div');
  banner.id = BANNER_ID;
  banner.textContent = enabled ? 'DDD: Detection ON — You are protected!' : 'DDD: Detection OFF!';
  Object.assign(banner.style, {
    position: 'fixed', top: '0', left: '0', right: '0', zIndex: '2147483647',
    background: enabled ? '#16a34a' : '#dc2626',
    color: 'white', fontFamily: 'sans-serif', fontSize: '14px',
    padding: '8px', textAlign: 'center',
    transform: 'translateY(0)', opacity: '1',
    transition: `transform ${ANIM_MS}ms ease-in, opacity ${ANIM_MS}ms ease-in`,
  });
  document.documentElement.appendChild(banner);
  hideTimer = setTimeout(() => {
    banner.style.transform = 'translateY(-100%)';
    banner.style.opacity = '0';
    removeTimer = setTimeout(() => banner.remove(), ANIM_MS);
  }, DISPLAY_MS);
}

chrome.storage.local.get(['enabled'], res => showBanner(res.enabled !== false));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.enabled) showBanner(changes.enabled.newValue);
});
