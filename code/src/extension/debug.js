const PREFIX = 'messagingCapture:';
const content = document.getElementById('content');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// low_risk -> status-low-risk (underscores become hyphens so it matches the CSS)
function statusClass(status) {
  const safe = String(status || 'pending').toLowerCase().replace(/_/g, '-').replace(/[^a-z-]/g, '');
  return `status status-${safe}`;
}

function statusLabel(status) {
  return String(status || 'pending').replace(/_/g, ' ');
}

function detailsFor(m) {
  const parts = [];
  if (typeof m.score === 'number') parts.push(`Risk score: ${Math.round(m.score * 100)}%`);
  if (m.explanation) parts.push(m.explanation);
  if (Array.isArray(m.signals) && m.signals.length) parts.push(`Signals: ${m.signals.join(', ')}`);
  if (m.source) parts.push(`(${m.source})`);
  return parts.join('\n');
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
        <td><span class="${statusClass(m.status)}">${escapeHtml(statusLabel(m.status))}</span></td>
        <td class="text-cell details">${escapeHtml(detailsFor(m))}</td>
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
            <tr>
              <th style="width:150px">Captured</th>
              <th>Text</th>
              <th style="width:110px">Status</th>
              <th style="width:260px">Details</th>
            </tr>
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

// Re-render automatically whenever storage changes (new message captured or labelled).
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (Object.keys(changes).some((k) => k.startsWith(PREFIX))) {
    render();
  }
});

render();
