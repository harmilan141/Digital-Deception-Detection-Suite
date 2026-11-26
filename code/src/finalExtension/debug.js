const PREFIX  = 'ddd:messages:';
const content = document.getElementById('content');

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c =>
    ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
function statusClass(s) {
  return 'status status-' + String(s || 'pending').toLowerCase().replace(/_/g,'-').replace(/[^a-z-]/g,'');
}
function statusLabel(s) { return String(s || 'pending').replace(/_/g,' '); }

function detailsFor(m) {
  const parts = [];
  if (typeof m.score === 'number') parts.push(`Risk: ${Math.round(m.score * 100)}%`);
  if (m.explanation) parts.push(m.explanation);
  if (Array.isArray(m.signals) && m.signals.length) parts.push(`Signals: ${m.signals.join(', ')}`);
  if (m.source) parts.push(`Source: ${m.source}`);
  return parts.join('\n');
}

async function render() {
  const all  = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter(k => k.startsWith(PREFIX)).sort();

  if (!keys.length) {
    content.innerHTML = '<div class="empty">No messages captured yet. Enable the extension and visit a supported messaging site.</div>';
    return;
  }

  content.innerHTML = keys.map(key => {
    const site     = key.slice(PREFIX.length);
    const messages = (all[key] || []).slice().reverse();
    const rows = messages.map(m => `
      <tr>
        <td class="timestamp">${esc(new Date(m.capturedAt).toLocaleString())}</td>
        <td class="text-cell">${esc(m.text)}${m.urlOnly ? '<span class="tag-url-only">URL-only</span>' : ''}</td>
        <td><span class="${statusClass(m.status)}">${esc(statusLabel(m.status))}</span></td>
        <td class="text-cell details">${esc(detailsFor(m))}</td>
      </tr>`).join('');

    return `
      <div class="site-block">
        <div class="site-header">
          <h2>${esc(site)}</h2>
          <span class="count">${messages.length} message${messages.length === 1 ? '' : 's'}</span>
        </div>
        <table>
          <thead><tr><th style="width:150px">Captured</th><th>Text</th><th style="width:110px">Status</th><th style="width:260px">Details</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }).join('');
}

document.getElementById('refresh').addEventListener('click', render);
document.getElementById('clear').addEventListener('click', async () => {
  const all  = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter(k => k.startsWith(PREFIX));
  if (!keys.length) return;
  if (!confirm(`Remove captured messages for ${keys.length} site(s)?`)) return;
  await chrome.storage.local.remove(keys);
  render();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && Object.keys(changes).some(k => k.startsWith(PREFIX))) render();
});

render();
