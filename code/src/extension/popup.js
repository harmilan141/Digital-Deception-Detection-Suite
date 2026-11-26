const toggle = document.getElementById('toggle');
const status = document.getElementById('status');

function render(enabled) {
  toggle.checked = enabled;
  status.textContent = enabled ? 'Enabled' : 'Disabled';
}

// Load current state when popup opens (default: enabled).
chrome.storage.local.get(['enabled'], (res) => {
  render(res.enabled !== false);
});

// Save state whenever the user flips the switch.
// content.js listens for this change and shows the on-page banner itself.
toggle.addEventListener('change', () => {
  const enabled = toggle.checked;
  chrome.storage.local.set({ enabled });
  render(enabled);
});

// ---- Safe Browsing API key (used by background.js for link checking) ----
const keyInput = document.getElementById('sbkey');
const keyStatus = document.getElementById('keystatus');

function renderKeyStatus(hasKey) {
  keyStatus.textContent = hasKey
    ? 'Key saved. Full link checking is on.'
    : 'No key: only local link checks run.';
}

chrome.storage.local.get(['safeBrowsingKey'], (res) => {
  renderKeyStatus(Boolean(res.safeBrowsingKey));
});

document.getElementById('savekey').addEventListener('click', () => {
  const key = keyInput.value.trim();
  if (key) {
    chrome.storage.local.set({ safeBrowsingKey: key }, () => renderKeyStatus(true));
  } else {
    chrome.storage.local.remove('safeBrowsingKey', () => renderKeyStatus(false));
  }
  keyInput.value = '';
});
