const BANNER_ID = '__toggle_demo_banner__';

function showBanner() {
  if (document.getElementById(BANNER_ID)) return;
  const banner = document.createElement('div');
  banner.id = BANNER_ID;
  banner.textContent = 'Toggle Demo Extension is ON';
  Object.assign(banner.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    right: '0',
    zIndex: '2147483647',
    background: '#7c3aed',
    color: 'white',
    fontFamily: 'sans-serif',
    fontSize: '14px',
    padding: '8px',
    textAlign: 'center',
  });
  document.documentElement.appendChild(banner);
}

function hideBanner() {
  const banner = document.getElementById(BANNER_ID);
  if (banner) banner.remove();
}

function applyState(enabled) {
  if (enabled) showBanner();
  else hideBanner();
}

// Apply the saved state as soon as the page loads
chrome.storage.local.get(['enabled'], (res) => {
  applyState(res.enabled !== false);
});

// React instantly when the toggle is flipped in the popup - no page reload needed
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.enabled) {
    applyState(changes.enabled.newValue);
  }
});
