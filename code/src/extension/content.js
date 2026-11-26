const BANNER_ID = '__toggle_demo_banner__';
const DISPLAY_MS = 2000; // how long the banner stays fully visible
const ANIM_MS = 300;     // duration of the slide-up/fade-out

let hideTimer = null;
let removeTimer = null;

function clearBannerTimers() {
  clearTimeout(hideTimer);
  clearTimeout(removeTimer);
  hideTimer = null;
  removeTimer = null;
}

function removeBannerNow() {
  clearBannerTimers();
  const existing = document.getElementById(BANNER_ID);
  if (existing) existing.remove();
}

function showBanner(enabled) {
  // Restart cleanly if a banner (or its timers) is already active.
  removeBannerNow();

  const banner = document.createElement('div');
  banner.id = BANNER_ID;
  banner.textContent = enabled
    ? 'Detection ON, You are safe!'
    : 'Detection OFF!';

  Object.assign(banner.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    right: '0',
    zIndex: '2147483647',
    background: enabled ? '#16a34a' : '#dc2626', // green when ON, red when OFF
    color: 'white',
    fontFamily: 'sans-serif',
    fontSize: '14px',
    padding: '8px',
    textAlign: 'center',
    transform: 'translateY(0)',
    opacity: '1',
    transition: `transform ${ANIM_MS}ms ease-in, opacity ${ANIM_MS}ms ease-in`,
  });

  document.documentElement.appendChild(banner);

  // After DISPLAY_MS, slide it up and fade it out, then remove it from the DOM.
  hideTimer = setTimeout(() => {
    banner.style.transform = 'translateY(-100%)';
    banner.style.opacity = '0';

    removeTimer = setTimeout(() => {
      banner.remove();
    }, ANIM_MS);
  }, DISPLAY_MS);
}

function applyState(enabled) {
  showBanner(enabled);
}

// Show the current state briefly as soon as the page loads.
chrome.storage.local.get(['enabled'], (res) => {
  applyState(res.enabled !== false);
});

// React instantly whenever the toggle is flipped in the popup.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.enabled) {
    applyState(changes.enabled.newValue);
  }
});