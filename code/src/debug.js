const PREFIX = 'messagingCapture:';
const content = document.getElementById('content');

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function statusClass(status) {
  return `status status-${(status || 'pending').replace(/[^a-z-]/g, '')}`;
}

async function render() {
  const all = await chrome.storage.local.get(null);
  const siteKeys = Object.keys(all)
    .filter((k) => k.startsWith(PREFIX))
    .sort();

  if (siteKeys.length === 0) {
    content.innerHTML = '<div class="empty">No messages captured yet. Enable the extension and visit a supported messaging site.</div>';
    return;
  }

  content.innerHTML = siteKeys.map((key) => {
    const site = key.slice(PREFIX.length);
    const messages = (all[key] || []).slice().reverse(); // newest first

    const rows = messages.map((m) => `
      <tr>
        <td class="timestamp">${escapeHtml(new Date(m.capturedAt).toLocaleString())}</td>
        <td class="text-cell">${escapeHtml(m.text)}</td>
        <td><span class="${statusClass(m.status)}">${escapeHtml(m.status || 'pending')}</span></td>
      </tr>
    `).join('');

    return `
      <div class="site-block">
        <div class="site-header">
          <h2>${escapeHtml(site)}</h2>
          <span class="count">${messages.length} message${messages.length === 1 ? '' : 's'}</span>
        </div>
        <table>
          <thead>
            <tr><th style="width:160px">Captured</th><th>Text</th><th style="width:120px">Status</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `;
  }).join('');
}

document.getElementById('refresh').addEventListener('click', render);

document.getElementById('clear').addEventListener('click', async () => {
  const all = await chrome.storage.local.get(null);
  const keysToRemove = Object.keys(all).filter((k) => k.startsWith(PREFIX));
  if (keysToRemove.length === 0) return;
  if (!confirm(`Remove captured messages for ${keysToRemove.length} site(s)?`)) return;
  await chrome.storage.local.remove(keysToRemove);
  render();
});

// Re-render automatically whenever storage changes (e.g. new message captured).
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (Object.keys(changes).some((k) => k.startsWith(PREFIX))) {
    render();
  }
});

render();