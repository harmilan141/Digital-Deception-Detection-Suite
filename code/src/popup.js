const toggle = document.getElementById('toggle');
const status = document.getElementById('status');

function render(enabled) {
  toggle.checked = enabled;
  status.textContent = enabled ? 'Enabled' : 'Disabled';
}

// Load current state when popup opens (default: enabled)
chrome.storage.local.get(['enabled'], (res) => {
  render(res.enabled !== false);
});

// Save state whenever the user flips the switch
toggle.addEventListener('change', () => {
  const enabled = toggle.checked;
  chrome.storage.local.set({ enabled });
  render(enabled);
});
