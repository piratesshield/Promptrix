// Popup Logic — Promptrix v2.0

document.addEventListener('DOMContentLoaded', () => {

  const safeSend = (msg, cb) => {
    try {
      chrome.runtime.sendMessage(msg, (r) => {
        if (chrome.runtime.lastError) { console.error(chrome.runtime.lastError); return; }
        cb(r);
      });
    } catch (e) { console.error(e); }
  };

  // Load Stats
  safeSend({ action: 'get_stats' }, (stats) => {
    if (stats) {
      document.getElementById('count-total').textContent = stats.total || 0;
      document.getElementById('count-tokens').textContent = (stats.tokens || 0).toLocaleString();
      document.getElementById('count-starred').textContent = stats.starred || 0;
    }
  });

  // Load Recent
  safeSend({ action: 'get_all_captures' }, (data) => {
    const list = document.getElementById('recent-list');
    list.innerHTML = '';

    if (!data || data.length === 0) {
      list.innerHTML = '<div style="text-align:center;color:#555;font-size:11px;padding:30px;">No captures yet.<br>Start chatting with an AI tool!</div>';
      return;
    }

    data.slice(0, 5).forEach(item => {
      const el = document.createElement('div');
      el.className = 'item';
      const time = new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const tags = (item.tags || [item.category || 'General']).map(t => `<span class="pill">${escapeHtml(t)}</span>`).join('');
      const star = item.starred ? '⭐ ' : '';

      el.innerHTML = `
        <div class="item-meta">
          <span class="tag ${item.type}">${star}${item.type.toUpperCase()}</span>
          <span>${item.aiTool} • ${time}</span>
        </div>
        <div class="item-content">${escapeHtml(item.content)}</div>
        <div class="item-tags">${tags}</div>
      `;
      list.appendChild(el);
    });
  });

  // Navigation
  document.getElementById('open-dash').addEventListener('click', () => {
    chrome.tabs.create({ url: 'dashboard.html' });
  });

  document.getElementById('view-all').addEventListener('click', () => {
    chrome.tabs.create({ url: 'dashboard.html' });
  });

  // Cloud Sync
  document.getElementById('sync-cloud').addEventListener('click', () => {
    const btn = document.getElementById('sync-cloud');
    btn.textContent = '⏳ Syncing...';
    btn.disabled = true;

    safeSend({ action: 'force_sync' }, (resp) => {
      if (resp && resp.success) {
        btn.textContent = '✓ Synced!';
        btn.style.color = '#4ade80';
      } else {
        btn.textContent = '✕ Failed';
        btn.style.color = '#ff4444';
      }
      setTimeout(() => {
        btn.textContent = '☁ Sync';
        btn.style.color = '';
        btn.disabled = false;
      }, 2000);
    });
  });
});

function escapeHtml(text) {
  if (!text) return '';
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}