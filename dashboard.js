// Dashboard Logic — Promptrix v2.0
// Features: Thread View, Memory Graph, Tags, Starred, Cloud Sync, AI Digest

let allCaptures = [];
let currentTimeFrame = 'Week';
let activeFilterNode = null;
let activeSidebarTab = 'threads';
let activeThreadUrl = null;

const TOOL_COLORS = {
    'chatgpt': '#10a37f',
    'gemini': '#4285f4',
    'claude': '#d97706',
    'perplexity': '#14b8a6',
    'copilot': '#7c3aed',
    'default': '#666666'
};

// ─────────────────────────────────────
// INIT
// ─────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    loadData();
    renderLegend();
    loadSyncConfig();

    // Header buttons
    document.getElementById('refresh-btn').addEventListener('click', loadData);
    document.getElementById('export-btn').addEventListener('click', exportData);
    document.getElementById('clear-btn').addEventListener('click', clearHistory);
    // Global navigation — one handler for the whole group.
    document.querySelectorAll('.topnav-item').forEach(b =>
        b.addEventListener('click', () => navigate(b.dataset.view)));

    // Every sub-page's back control, delegated so new pages get it for free.
    document.querySelectorAll('[data-back]').forEach(b =>
        b.addEventListener('click', () => navigate('dashboard')));

    // Escape returns to the dashboard from any sub-page — a keyboard route out
    // that does not depend on finding the button.
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        if (document.querySelector('.dlp-drawer[aria-hidden="false"]')) return; // drawer owns Esc
        if (currentView() !== 'dashboard') navigate('dashboard');
    });

    // Render whatever the URL asks for, so a deep link opens the right section.
    renderView(currentView());

    // Sync buttons
    document.getElementById('sync-btn').addEventListener('click', forceSync);
    document.getElementById('force-sync-btn').addEventListener('click', forceSync);
    document.getElementById('save-sync-config').addEventListener('click', saveSyncConfig);

    // ── Settings auto-save ────────────────────────────────────────────
    // Toggles persist immediately; text fields persist on blur and on a pause
    // in typing. Saving on every keystroke would write a half-typed Worker URL
    // or token and make the connection look broken mid-edit.
    function autosave(fn, wait) {
        let t = null;
        return () => { clearTimeout(t); t = setTimeout(fn, wait); };
    }
    const autoSync = autosave(() => saveSyncConfig({ auto: true }), 600);
    const autoGist = autosave(() => saveGistConfig({ auto: true }), 600);

    ['sync-toggle'].forEach(id => { const el = document.getElementById(id);
        if (el) el.addEventListener('click', () => setTimeout(autoSync, 0)); });
    ['gist-toggle'].forEach(id => { const el = document.getElementById(id);
        if (el) el.addEventListener('click', () => setTimeout(autoGist, 0)); });

    ['worker-url', 'sync-token-input'].forEach(id => { const el = document.getElementById(id);
        if (!el) return;
        el.addEventListener('input', autoSync);
        el.addEventListener('change', () => saveSyncConfig({ auto: true }));   // blur
    });
    ['github-pat', 'github-gist-id'].forEach(id => { const el = document.getElementById(id);
        if (!el) return;
        el.addEventListener('input', autoGist);
        el.addEventListener('change', () => saveGistConfig({ auto: true }));
    });
    document.getElementById('backup-gist-btn').addEventListener('click', backupToGist);
    
    // Gist & Test Buttons
    document.getElementById('save-gist-config-btn').addEventListener('click', saveGistConfig);
    document.getElementById('test-cf-btn').addEventListener('click', testCloudflare);
    document.getElementById('test-gist-btn').addEventListener('click', testGistPat);

    // Sync toggles
    document.getElementById('sync-toggle').addEventListener('click', function() {
        this.classList.toggle('on');
    });
    document.getElementById('gist-toggle').addEventListener('click', function() {
        this.classList.toggle('on');
    });

    // ── DLP (Data-Loss Prevention) ──
    initDlp();

    // Filters
    document.getElementById('search-input').addEventListener('input', () => { activeFilterNode = null; renderTable(); });
    document.getElementById('tool-filter').addEventListener('change', () => { activeFilterNode = null; renderTable(); });
    document.getElementById('type-filter').addEventListener('change', () => { activeFilterNode = null; renderTable(); });

    // Time controls
    document.querySelectorAll('.time-controls button').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.time-controls button').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            currentTimeFrame = e.target.dataset.period;
            renderChart();
        });
    });

    // Sidebar tabs
    document.querySelectorAll('.sidebar-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            activeSidebarTab = tab.dataset.tab;
            renderSidebar();
        });
    });
});

// ─────────────────────────────────────
// VIEW MANAGEMENT
// ─────────────────────────────────────
// ── Router ────────────────────────────────────────────────────────────
// Views are addressed by hash so the browser Back button, forward, and deep
// links all work. Previously showView() only toggled a CSS class: there was no
// history entry, so Back left the extension page entirely instead of returning
// to the dashboard, and a section could not be linked to or reopened.
const VIEWS = ['dashboard', 'thread', 'settings', 'dlp'];
const VIEW_TITLE = { dashboard: 'Promptrix', thread: 'Thread', settings: 'Settings', dlp: 'Data Protection' };

function currentView() {
    const h = (location.hash || '').replace(/^#\/?/, '');
    return VIEWS.indexOf(h) !== -1 ? h : 'dashboard';
}

// Navigate: pushes history so Back returns here.
function navigate(viewName) {
    if (VIEWS.indexOf(viewName) === -1) viewName = 'dashboard';
    if (currentView() === viewName) { renderView(viewName); return; }
    location.hash = '#' + viewName;   // hashchange drives renderView
}

function renderView(viewName) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const el = document.getElementById('view-' + viewName);
    if (el) el.classList.add('active');

    // Current-section state. aria-current is the accessible signal; the styling
    // hangs off the same attribute so the two can never disagree.
    document.querySelectorAll('.topnav-item').forEach(b => {
        if (b.dataset.view === viewName) b.setAttribute('aria-current', 'page');
        else b.removeAttribute('aria-current');
    });

    // Capture-scoped actions are meaningless on a policy page — hide rather
    // than leave them inert.
    const tools = document.getElementById('header-tools');
    if (tools) tools.hidden = (viewName !== 'dashboard');

    document.title = VIEW_TITLE[viewName] || 'Promptrix';

    // Entry work per view.
    if (viewName === 'settings') {
        if (typeof loadFwdProfiles === 'function' && window.PromptrixSIEM) loadFwdProfiles();
        if (typeof renderClearCount === 'function') renderClearCount();
    }
    if (viewName === 'dlp' && typeof loadDlpLogs === 'function') loadDlpLogs();

    // Returning to the top of a switched page — a new page should not inherit
    // the previous one's scroll position.
    const main = document.querySelector('.main-content');
    if (main) main.scrollTop = 0;
}

// Back-compat: existing call sites keep working.
function showView(viewName) { navigate(viewName); }

window.addEventListener('hashchange', () => renderView(currentView()));

// ─────────────────────────────────────
// DATA LOADING
// ─────────────────────────────────────
function loadData() {
    try {
        chrome.runtime.sendMessage({ action: 'get_all_captures' }, (data) => {
            if (chrome.runtime.lastError) { console.error(chrome.runtime.lastError); return; }
            allCaptures = data || [];
            updateStats();
            renderTable();
            renderChart();
            renderMemoryGraph();
            renderSidebar();
            renderDigest();
            renderClearCount();
        });
    } catch (e) {
        console.error("Connection failed", e);
    }
}

// ─────────────────────────────────────
// STATS
// ─────────────────────────────────────
function updateStats() {
    const total = allCaptures.length;
    const tokens = allCaptures.reduce((acc, c) => acc + (c.tokens || 0), 0);
    const prompts = allCaptures.filter(c => c.type === 'prompt').length;
    const responses = allCaptures.filter(c => c.type === 'response').length;
    const starred = allCaptures.filter(c => c.starred).length;

    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-tokens').textContent = tokens.toLocaleString();
    document.getElementById('stat-prompts').textContent = prompts;
    document.getElementById('stat-responses').textContent = responses;
    document.getElementById('stat-starred').textContent = starred;
}

// ─────────────────────────────────────
// AI DIGEST
// ─────────────────────────────────────
function renderDigest() {
    const content = document.getElementById('digest-content');
    const cloud = document.getElementById('topic-cloud');
    if (allCaptures.length === 0) {
        content.innerHTML = '<div class="digest-item" style="color:var(--muted);">Start chatting with AI tools to see your digest here.</div>';
        cloud.innerHTML = '';
        return;
    }

    const now = new Date();
    const weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
    const thisWeek = allCaptures.filter(c => new Date(c.timestamp) > weekAgo);
    const prevWeek = allCaptures.filter(c => {
        const d = new Date(c.timestamp);
        return d > new Date(now - 14 * 24 * 60 * 60 * 1000) && d <= weekAgo;
    });

    const pctChange = prevWeek.length > 0
        ? Math.round(((thisWeek.length - prevWeek.length) / prevWeek.length) * 100)
        : 100;
    const arrow = pctChange >= 0 ? '↑' : '↓';

    // Tool breakdown this week
    const toolCounts = {};
    thisWeek.forEach(c => {
        const t = getToolClass(c.aiTool);
        toolCounts[t] = (toolCounts[t] || 0) + 1;
    });
    const topTool = Object.entries(toolCounts).sort((a, b) => b[1] - a[1])[0];

    // Active streak
    const uniqueDays = new Set(allCaptures.map(c => new Date(c.timestamp).toDateString()));
    let streak = 0;
    const today = new Date();
    for (let i = 0; i < 365; i++) {
        const d = new Date(today - i * 24 * 60 * 60 * 1000);
        if (uniqueDays.has(d.toDateString())) streak++;
        else break;
    }

    content.innerHTML = `
        <div class="digest-item">
            <strong>${thisWeek.length}</strong> captures this week
            <span class="highlight">${arrow}${Math.abs(pctChange)}%</span> vs last week
        </div>
        <div class="digest-item">
            Top tool: <strong>${topTool ? topTool[0].toUpperCase() : 'N/A'}</strong>
            ${topTool ? `(${topTool[1]} captures)` : ''}
        </div>
        <div class="digest-item">
            🔥 <strong>${streak}-day</strong> active streak
        </div>
        <div class="digest-item">
            ⭐ <strong>${allCaptures.filter(c => c.starred).length}</strong> starred prompts
        </div>
    `;

    // Topic cloud
    const tagCounts = {};
    allCaptures.forEach(c => {
        (c.tags || [c.category || 'General']).forEach(tag => {
            tagCounts[tag] = (tagCounts[tag] || 0) + 1;
        });
    });
    const maxCount = Math.max(...Object.values(tagCounts), 1);
    const sorted = Object.entries(tagCounts).sort((a, b) => b[1] - a[1]).slice(0, 15);

    cloud.innerHTML = sorted.map(([tag, count]) => {
        const size = 10 + (count / maxCount) * 6;
        const opacity = 0.5 + (count / maxCount) * 0.5;
        return `<span class="topic-pill" style="font-size:${size}px;opacity:${opacity}">${tag} (${count})</span>`;
    }).join('');
}

// ─────────────────────────────────────
// SIDEBAR: Threads / Starred / Tags
// ─────────────────────────────────────
function renderSidebar() {
    const list = document.getElementById('sidebar-list');
    list.innerHTML = '';

    if (activeSidebarTab === 'threads') renderThreadsSidebar(list);
    else if (activeSidebarTab === 'starred') renderStarredSidebar(list);
    else if (activeSidebarTab === 'tags') renderTagsSidebar(list);
}

function processThreads() {
    const threadMap = {};
    allCaptures.forEach(item => {
        const url = item.sessionUrl || 'unknown';
        if (!threadMap[url]) threadMap[url] = [];
        threadMap[url].push(item);
    });

    return Object.entries(threadMap)
        .map(([url, items]) => {
            items.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            const lastPrompt = [...items].reverse().find(i => i.type === 'prompt');
            const preview = lastPrompt ? lastPrompt.content : items[0].content;
            const tool = items[0].aiTool;
            const lastTime = items[items.length - 1].timestamp;
            const hasStarred = items.some(i => i.starred);

            // Find most common tag
            const tagCounts = {};
            items.forEach(i => {
                (i.tags || [i.category || 'General']).forEach(t => {
                    tagCounts[t] = (tagCounts[t] || 0) + 1;
                });
            });
            const topTag = Object.entries(tagCounts).sort((a, b) => b[1] - a[1])[0];

            return { url, items, preview, tool, lastTime, topTag: topTag ? topTag[0] : 'General', hasStarred, count: items.length };
        })
        .sort((a, b) => new Date(b.lastTime) - new Date(a.lastTime));
}

function renderThreadsSidebar(list) {
    const threads = processThreads();
    if (threads.length === 0) {
        list.innerHTML = '<div style="text-align:center;padding:40px 16px;color:var(--muted);font-size:12px;">No conversations yet</div>';
        return;
    }

    threads.forEach(thread => {
        const el = document.createElement('div');
        el.className = 'thread-item' + (activeThreadUrl === thread.url ? ' active' : '');
        const toolClass = getToolClass(thread.tool);
        const color = TOOL_COLORS[toolClass] || '#666';
        const time = formatRelativeTime(thread.lastTime);

        el.innerHTML = `
            <span class="thread-tool" style="background:${color}22;color:${color};border:1px solid ${color}44;">${thread.tool}</span>
            <div class="thread-preview">${escapeHtml(thread.preview.substring(0, 80))}</div>
            <div class="thread-meta">
                <span>${time} • ${thread.count} msgs</span>
                <span>
                    ${thread.hasStarred ? '<span class="star-indicator">⭐</span>' : ''}
                    <span class="thread-tag">${thread.topTag}</span>
                </span>
            </div>
        `;
        el.addEventListener('click', () => openThread(thread));
        list.appendChild(el);
    });
}

function renderStarredSidebar(list) {
    const starred = allCaptures.filter(c => c.starred);
    if (starred.length === 0) {
        list.innerHTML = '<div style="text-align:center;padding:40px 16px;color:var(--muted);font-size:12px;">No starred items yet.<br>Click ⭐ on a capture to star it.</div>';
        return;
    }

    starred.forEach(item => {
        const el = document.createElement('div');
        el.className = 'thread-item';
        const toolClass = getToolClass(item.aiTool);
        const color = TOOL_COLORS[toolClass] || '#666';

        el.innerHTML = `
            <span class="thread-tool" style="background:${color}22;color:${color};border:1px solid ${color}44;">⭐ ${item.aiTool}</span>
            <div class="thread-preview">${escapeHtml(item.content.substring(0, 80))}</div>
            <div class="thread-meta">
                <span>${formatRelativeTime(item.timestamp)}</span>
                <span class="thread-tag">${item.type}</span>
            </div>
        `;
        el.addEventListener('click', () => {
            if (item.sessionUrl) openThread({ url: item.sessionUrl, items: allCaptures.filter(c => c.sessionUrl === item.sessionUrl).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)), tool: item.aiTool });
        });
        list.appendChild(el);
    });
}

function renderTagsSidebar(list) {
    const tagCounts = {};
    allCaptures.forEach(c => {
        (c.tags || [c.category || 'General']).forEach(tag => {
            tagCounts[tag] = (tagCounts[tag] || 0) + 1;
        });
    });
    const sorted = Object.entries(tagCounts).sort((a, b) => b[1] - a[1]);

    if (sorted.length === 0) {
        list.innerHTML = '<div style="text-align:center;padding:40px 16px;color:var(--muted);font-size:12px;">No tags yet</div>';
        return;
    }

    sorted.forEach(([tag, count]) => {
        const el = document.createElement('div');
        el.className = 'thread-item';
        el.innerHTML = `
            <div class="thread-preview" style="font-weight:600;">${tag}</div>
            <div class="thread-meta"><span>${count} captures</span></div>
        `;
        el.addEventListener('click', () => {
            showView('dashboard');
            document.getElementById('search-input').value = '';
            activeFilterNode = { type: 'tag', id: tag };
            renderTable();
        });
        list.appendChild(el);
    });
}

// ─────────────────────────────────────
// THREAD VIEW
// ─────────────────────────────────────
function openThread(thread) {
    activeThreadUrl = thread.url;
    showView('thread');
    renderSidebar();

    document.getElementById('thread-title').textContent = thread.tool + ' Conversation';
    document.getElementById('thread-info').textContent = thread.items.length + ' messages';

    const container = document.getElementById('thread-messages');
    container.innerHTML = '';

    // Sort by timestamp ascending
    const sorted = thread.items.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    sorted.forEach(item => {
        const div = document.createElement('div');
        div.className = 'thread-msg ' + (item.type === 'prompt' ? 'prompt-msg' : 'response-msg');

        const time = new Date(item.timestamp).toLocaleString();
        const tags = (item.tags || [item.category || 'General']).map(t => `<span class="tag-pill">${t}</span>`).join('');
        const starClass = item.starred ? 'starred' : '';

        div.innerHTML = `
            <div class="msg-meta">
                <span class="tag ${item.type}">${item.type}</span>
                <span style="color:var(--muted)">${time}</span>
                ${tags}
                <button class="star-btn ${starClass}" data-id="${item.id}">${item.starred ? '⭐' : '☆'}</button>
            </div>
            <div class="msg-content">${parseMarkdown(escapeHtml(item.content))}</div>
        `;
        container.appendChild(div);
    });

    // Star button listeners
    container.querySelectorAll('.star-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleStar(btn.dataset.id);
        });
    });

    // Scroll link
    if (thread.url && thread.url !== 'unknown') {
        document.getElementById('thread-info').innerHTML = `${thread.items.length} messages • <a href="${thread.url}" target="_blank" class="link-btn" style="font-size:10px;">Open Original</a>`;
    }
}

// ─────────────────────────────────────
// MARKDOWN PARSING (Simple)
// ─────────────────────────────────────
function parseMarkdown(text) {
    if (!text) return '';
    // Code blocks
    const codeBlocks = [];
    text = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) => {
        const idx = codeBlocks.length;
        codeBlocks.push(`<pre style="background:var(--bg);padding:12px;border-radius:6px;border:1px solid var(--border);overflow-x:auto;margin:8px 0;"><code>${code.trim()}</code></pre>`);
        return `__CODE_${idx}__`;
    });
    // Inline code
    text = text.replace(/`([^`]+)`/g, '<code style="background:var(--bg);padding:1px 4px;border-radius:3px;font-size:12px;">$1</code>');
    // Bold
    text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    // Italic
    text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');
    // Re-inject code blocks
    codeBlocks.forEach((block, i) => {
        text = text.replace(`__CODE_${i}__`, block);
    });
    return text;
}

// ─────────────────────────────────────
// TABLE RENDERING
// ─────────────────────────────────────
function renderTable() {
    const tbody = document.getElementById('table-body');
    const search = document.getElementById('search-input').value.toLowerCase();
    const toolFilter = document.getElementById('tool-filter').value;
    const typeFilter = document.getElementById('type-filter').value;

    let filtered = allCaptures.filter(item => {
        const matchSearch = item.content.toLowerCase().includes(search);
        const matchTool = toolFilter === 'ALL' || item.aiTool === toolFilter;
        const matchType = typeFilter === 'ALL' || item.type === typeFilter;
        return matchSearch && matchTool && matchType;
    });

    // Graph / tag filter
    if (activeFilterNode) {
        if (activeFilterNode.type === 'tool') {
            filtered = filtered.filter(item => item.aiTool === activeFilterNode.id);
        } else if (activeFilterNode.type === 'item') {
            filtered = filtered.filter(item => item.content === activeFilterNode.label);
        } else if (activeFilterNode.type === 'tag') {
            filtered = filtered.filter(item => {
                const tags = item.tags || [item.category || 'General'];
                return tags.includes(activeFilterNode.id);
            });
        }
    }

    tbody.innerHTML = '';

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--muted);padding:30px;">No captures found.</td></tr>';
        return;
    }

    filtered.slice(0, 100).forEach(item => {
        const tr = document.createElement('tr');
        const date = new Date(item.timestamp).toLocaleString();
        const toolClass = getToolClass(item.aiTool);
        const tags = (item.tags || [item.category || 'General']).map(t => `<span class="tag-pill">${t}</span>`).join(' ');
        const starClass = item.starred ? 'starred' : '';

        tr.innerHTML = `
            <td><button class="star-btn ${starClass}" data-id="${item.id}">${item.starred ? '⭐' : '☆'}</button></td>
            <td><span class="tag ${item.type}">${item.type}</span></td>
            <td><span class="tag ${toolClass}">${item.aiTool}</span></td>
            <td>${tags}</td>
            <td class="content-cell">${escapeHtml(item.content)}</td>
            <td style="font-family:monospace;color:var(--muted);font-size:11px;">${(item.tokens || 0).toLocaleString()}</td>
            <td style="color:var(--muted);font-size:11px;">${date}</td>
            <td><button class="copy-btn" data-content="${escapeHtmlAttr(item.content)}">Copy</button></td>
            <td>${item.sessionUrl ? `<a href="${item.sessionUrl}" target="_blank" class="link-btn">↗</a>` : '-'}</td>
        `;
        tbody.appendChild(tr);
    });

    // Copy listeners
    tbody.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            navigator.clipboard.writeText(e.target.getAttribute('data-content')).then(() => {
                e.target.textContent = '✓';
                e.target.style.color = '#4ade80';
                setTimeout(() => { e.target.textContent = 'Copy'; e.target.style.color = ''; }, 1500);
            });
        });
    });

    // Star listeners
    tbody.querySelectorAll('.star-btn').forEach(btn => {
        btn.addEventListener('click', () => toggleStar(btn.dataset.id));
    });
}

// ─────────────────────────────────────
// STAR TOGGLE
// ─────────────────────────────────────
function toggleStar(captureId) {
    chrome.runtime.sendMessage({ action: 'toggle_star', captureId }, () => {
        loadData();
    });
}

// ─────────────────────────────────────
// CHART
// ─────────────────────────────────────
function renderLegend() {
    const el = document.getElementById('chart-legend');
    el.innerHTML = '';
    Object.keys(TOOL_COLORS).forEach(tool => {
        if (tool === 'default') return;
        const item = document.createElement('div');
        item.className = 'legend-item';
        item.innerHTML = `<div class="legend-dot" style="background:${TOOL_COLORS[tool]}"></div>${tool.charAt(0).toUpperCase() + tool.slice(1)}`;
        el.appendChild(item);
    });
}

function renderChart() {
    const container = document.getElementById('chart-container');
    container.innerHTML = '';

    if (allCaptures.length === 0) {
        container.innerHTML = '<div style="position:absolute;width:100%;text-align:center;color:var(--muted);top:45%;">No data available</div>';
        return;
    }

    const groups = {};
    const now = new Date();
    let limitTime = 0, getKey = () => {}, getSortTime = () => {};

    if (currentTimeFrame === 'Day') {
        limitTime = 24 * 60 * 60 * 1000;
        getKey = (d) => d.getHours() + ':00';
        getSortTime = (d) => d.setMinutes(0, 0, 0);
    } else if (currentTimeFrame === 'Week') {
        limitTime = 7 * 24 * 60 * 60 * 1000;
        getKey = (d) => (d.getMonth() + 1) + '/' + d.getDate();
        getSortTime = (d) => d.setHours(0, 0, 0, 0);
    } else if (currentTimeFrame === 'Month') {
        limitTime = 30 * 24 * 60 * 60 * 1000;
        getKey = (d) => (d.getMonth() + 1) + '/' + d.getDate();
        getSortTime = (d) => d.setHours(0, 0, 0, 0);
    } else if (currentTimeFrame === 'Year') {
        limitTime = 365 * 24 * 60 * 60 * 1000;
        getKey = (d) => (d.getMonth() + 1) + '/' + d.getFullYear();
        getSortTime = (d) => d.setDate(1);
    } else {
        limitTime = 5 * 365 * 24 * 60 * 60 * 1000;
        getKey = (d) => d.getFullYear();
        getSortTime = (d) => d.setMonth(0, 1);
    }

    allCaptures.forEach(item => {
        const d = new Date(item.timestamp);
        if (now - d > limitTime) return;
        const key = getKey(d);
        const sortTime = getSortTime(d);
        if (!groups[sortTime]) groups[sortTime] = { label: key, total: 0, tools: {} };
        const baseTool = getToolClass(item.aiTool);
        if (!groups[sortTime].tools[baseTool]) groups[sortTime].tools[baseTool] = 0;
        groups[sortTime].tools[baseTool]++;
        groups[sortTime].total++;
    });

    const data = Object.keys(groups).sort((a, b) => a - b).map(k => groups[k]);
    if (data.length === 0) {
        container.innerHTML = '<div style="position:absolute;width:100%;text-align:center;color:var(--muted);top:45%;">No activity in this period</div>';
        return;
    }

    const maxVal = Math.max(...data.map(d => d.total));

    data.forEach(d => {
        const groupEl = document.createElement('div');
        groupEl.className = 'bar-group';
        const stackEl = document.createElement('div');
        stackEl.className = 'bar-stack';
        stackEl.style.height = `${Math.max((d.total / maxVal) * 100, 2)}%`;

        let tooltipText = `${d.label}\nTotal: ${d.total}`;
        Object.keys(d.tools).forEach(tool => {
            const count = d.tools[tool];
            if (count > 0) {
                const seg = document.createElement('div');
                seg.className = 'bar-segment';
                seg.style.height = `${(count / d.total) * 100}%`;
                seg.style.backgroundColor = TOOL_COLORS[tool] || TOOL_COLORS['default'];
                stackEl.appendChild(seg);
                tooltipText += `\n${tool.toUpperCase()}: ${count}`;
            }
        });

        const tooltip = document.createElement('div');
        tooltip.className = 'bar-tooltip';
        tooltip.innerText = tooltipText;
        const label = document.createElement('div');
        label.className = 'bar-label';
        label.innerText = d.label;

        groupEl.appendChild(tooltip);
        groupEl.appendChild(stackEl);
        groupEl.appendChild(label);
        container.appendChild(groupEl);
    });
}

// ─────────────────────────────────────
// MEMORY GRAPH (Fixed — Proper Layout)
// ─────────────────────────────────────
function renderMemoryGraph() {
    const container = document.getElementById('memory-graph-container');
    container.innerHTML = '';

    const items = allCaptures.filter(i => i.type === 'prompt').slice(0, 150);

    if (items.length === 0) {
        container.innerHTML = '<div style="text-align:center;padding-top:180px;color:var(--muted);font-size:13px;">No prompt history for graph</div>';
        return;
    }

    container.onmouseleave = () => { activeFilterNode = null; renderTable(); };

    const nodes = [];
    const links = [];
    const nodeMap = {};
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 400;

    const addNode = (id, type, label, color, r) => {
        if (!nodeMap[id]) {
            nodeMap[id] = { id, type, label, color, r, x: width / 2 + (Math.random() - 0.5) * 200, y: height / 2 + (Math.random() - 0.5) * 200, vx: 0, vy: 0 };
            nodes.push(nodeMap[id]);
        }
        return nodeMap[id];
    };

    // Create category nodes (clusters)
    const categoryColors = {
        'Code': '#ff6b6b', 'Security': '#f59e0b', 'Cloud': '#3b82f6', 'AI/ML': '#8b5cf6',
        'Database': '#06b6d4', 'General': '#6b7280', 'Python': '#3776ab', 'JavaScript': '#f7df1e',
        'React': '#61dafb', 'DevOps': '#ff9800', 'API': '#4caf50', 'Git': '#f05032',
        'Testing': '#9c27b0', 'Debugging': '#ef4444', 'Writing': '#ec4899', 'Question': '#14b8a6',
        'Explanation': '#a78bfa', 'Node.js': '#68a063', 'CSS': '#2965f1', 'HTML': '#e34c26',
        'TypeScript': '#3178c6', 'Math': '#fbbf24',
    };

    // Create tool nodes
    const activeTools = new Set(items.map(i => i.aiTool));
    activeTools.forEach(toolName => {
        const toolColor = TOOL_COLORS[getToolClass(toolName)] || '#666';
        addNode('tool:' + toolName, 'tool', toolName, toolColor, 22);
    });

    // Create category nodes based on actual usage
    const usedCategories = new Set();
    items.forEach(item => {
        const tags = item.tags || [item.category || 'General'];
        tags.forEach(t => usedCategories.add(t));
    });
    usedCategories.forEach(cat => {
        addNode('cat:' + cat, 'category', cat, categoryColors[cat] || '#666', 16);
    });

    // Create prompt nodes and link them
    const contentMap = {};
    items.forEach(item => {
        if (!contentMap[item.content]) contentMap[item.content] = { tools: new Set(), tags: new Set() };
        contentMap[item.content].tools.add(item.aiTool);
        (item.tags || [item.category || 'General']).forEach(t => contentMap[item.content].tags.add(t));
    });

    Object.keys(contentMap).forEach((content, idx) => {
        const { tools, tags } = contentMap[content];
        const nodeId = 'prompt:' + idx;
        addNode(nodeId, 'item', content, '#c41e3a', 5);

        // Link to tools
        tools.forEach(tool => links.push({ source: 'tool:' + tool, target: nodeId }));
        // Link to categories
        tags.forEach(tag => links.push({ source: 'cat:' + tag, target: nodeId }));
    });

    // SVG setup with zoom/pan
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    container.appendChild(svg);

    let transform = { x: 0, y: 0, k: 1 };
    const g = document.createElementNS(svgNS, "g");
    svg.appendChild(g);

    // Zoom
    svg.addEventListener('wheel', (e) => {
        e.preventDefault();
        const factor = e.deltaY > 0 ? 0.9 : 1.1;
        transform.k = Math.max(0.3, Math.min(3, transform.k * factor));
        updateTransform();
    });

    // Pan
    let isPanning = false, panStart = { x: 0, y: 0 };
    svg.addEventListener('mousedown', (e) => {
        if (e.target === svg || e.target === g) {
            isPanning = true;
            panStart = { x: e.clientX - transform.x, y: e.clientY - transform.y };
        }
    });
    svg.addEventListener('mousemove', (e) => {
        if (isPanning) {
            transform.x = e.clientX - panStart.x;
            transform.y = e.clientY - panStart.y;
            updateTransform();
        }
    });
    svg.addEventListener('mouseup', () => isPanning = false);
    svg.addEventListener('mouseleave', () => isPanning = false);

    function updateTransform() {
        g.setAttribute('transform', `translate(${transform.x},${transform.y}) scale(${transform.k})`);
    }

    // Force simulation
    const render = () => {
        while (g.firstChild) g.removeChild(g.firstChild);

        // Draw edges
        links.forEach(l => {
            const s = nodeMap[l.source];
            const t = nodeMap[l.target];
            if (s && t) {
                const line = document.createElementNS(svgNS, "line");
                line.setAttribute("x1", s.x); line.setAttribute("y1", s.y);
                line.setAttribute("x2", t.x); line.setAttribute("y2", t.y);
                line.setAttribute("stroke", "#333"); line.setAttribute("stroke-width", "0.5");
                line.setAttribute("opacity", "0.4");
                g.appendChild(line);
            }
        });

        // Draw nodes
        nodes.forEach(n => {
            const circle = document.createElementNS(svgNS, "circle");
            circle.setAttribute("cx", n.x); circle.setAttribute("cy", n.y);
            circle.setAttribute("r", n.r);
            circle.setAttribute("fill", n.color);
            circle.setAttribute("stroke", n.type === 'tool' ? '#fff' : 'none');
            circle.setAttribute("stroke-width", n.type === 'tool' ? '2' : '0');
            circle.style.cursor = 'pointer';
            circle.setAttribute("opacity", n.type === 'item' ? '0.7' : '1');

            circle.onmouseenter = () => {
                circle.setAttribute("r", n.r * 1.5);
                circle.setAttribute("stroke", "#fff");
                circle.setAttribute("stroke-width", "2");
                activeFilterNode = n.type === 'tool'
                    ? { type: 'tool', id: n.label }
                    : n.type === 'category'
                    ? { type: 'tag', id: n.label }
                    : { type: 'item', label: n.label };
                renderTable();
            };
            circle.onmouseleave = () => {
                circle.setAttribute("r", n.r);
                circle.setAttribute("stroke", n.type === 'tool' ? '#fff' : 'none');
                circle.setAttribute("stroke-width", n.type === 'tool' ? '2' : '0');
            };

            const title = document.createElementNS(svgNS, "title");
            title.textContent = n.label ? (n.label.length > 100 ? n.label.substring(0, 100) + '...' : n.label) : '';
            circle.appendChild(title);
            g.appendChild(circle);

            // Labels for tools and categories
            if (n.type === 'tool' || n.type === 'category') {
                const text = document.createElementNS(svgNS, "text");
                text.setAttribute("x", n.x); text.setAttribute("y", n.y - n.r - 4);
                text.setAttribute("text-anchor", "middle");
                text.setAttribute("fill", n.type === 'tool' ? '#eee' : '#999');
                text.setAttribute("font-size", n.type === 'tool' ? '11' : '9');
                text.setAttribute("font-weight", "600");
                text.setAttribute("font-family", "Inter, sans-serif");
                text.style.pointerEvents = "none";
                text.textContent = n.label;
                g.appendChild(text);
            }
        });
    };

    // Physics simulation
    const step = () => {
        // Repulsion
        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const a = nodes[i], b = nodes[j];
                const dx = a.x - b.x, dy = a.y - b.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                const minDist = (a.r + b.r) * 3;
                const force = Math.min(800, (minDist * minDist) / (dist * dist));
                const fx = (dx / dist) * force, fy = (dy / dist) * force;
                a.vx += fx; a.vy += fy;
                b.vx -= fx; b.vy -= fy;
            }
        }

        // Spring attraction (links)
        links.forEach(l => {
            const s = nodeMap[l.source], t = nodeMap[l.target];
            if (s && t) {
                const dx = t.x - s.x, dy = t.y - s.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                const idealLen = s.type === 'category' || t.type === 'category' ? 60 : 100;
                const force = (dist - idealLen) * 0.03;
                const fx = (dx / dist) * force, fy = (dy / dist) * force;
                s.vx += fx; s.vy += fy;
                t.vx -= fx; t.vy -= fy;
            }
        });

        // Center gravity
        nodes.forEach(n => {
            n.vx += (width / 2 - n.x) * 0.015;
            n.vy += (height / 2 - n.y) * 0.015;
            n.vx *= 0.82; n.vy *= 0.82;
            n.x += n.vx; n.y += n.vy;
            n.x = Math.max(n.r + 5, Math.min(width - n.r - 5, n.x));
            n.y = Math.max(n.r + 15, Math.min(height - n.r - 5, n.y));
        });

        render();
    };

    let ticks = 0;
    const interval = setInterval(() => {
        step();
        if (++ticks > 250) clearInterval(interval);
    }, 16);
}

// ─────────────────────────────────────
// SYNC SETTINGS
// ─────────────────────────────────────
function loadSyncConfig() {
    try {
        chrome.runtime.sendMessage({ action: 'get_sync_config' }, (config) => {
            if (chrome.runtime.lastError) return;
            if (config) {
                document.getElementById('worker-url').value = config.workerUrl || '';
                document.getElementById('sync-token-input').value = config.syncToken || '';
                if (config.enabled) document.getElementById('sync-toggle').classList.add('on');
            }
        });
        chrome.runtime.sendMessage({ action: 'get_gist_config' }, (config) => {
            if (chrome.runtime.lastError) return;
            if (config) {
                document.getElementById('github-pat').value = config.pat || '';
                document.getElementById('github-gist-id').value = config.gistId || '';
                if (config.autoSync) document.getElementById('gist-toggle').classList.add('on');
            }
        });
    } catch (e) {}
}

function saveSyncConfig() {
    const config = {
        enabled: document.getElementById('sync-toggle').classList.contains('on'),
        workerUrl: document.getElementById('worker-url').value.replace(/\/$/, ''),
        syncToken: document.getElementById('sync-token-input').value,
    };

    chrome.runtime.sendMessage({ action: 'save_sync_config', config }, () => {
        const status = document.getElementById('sync-status');
        if (!status) return;
        status.style.display = 'block';
        // Report the actual outcome. Auto-save happens without the operator
        // pressing anything, so a silent failure would leave them believing
        // their Worker URL or token had been stored when it had not.
        if (chrome.runtime.lastError) {
            status.innerHTML = '<span class="dot red"></span> Not saved: ' + chrome.runtime.lastError.message;
            setTimeout(() => { status.style.display = 'none'; }, 8000);
            return;
        }
        status.innerHTML = '<span class="dot green"></span> Saved.';
        setTimeout(() => { status.style.display = 'none'; }, 2200);
    });
}

function forceSync() {
    const status = document.getElementById('sync-status');
    status.style.display = 'block';
    status.innerHTML = '<span class="dot yellow"></span> Syncing...';

    // Route through service worker — extension pages CANNOT fetch cross-origin directly in MV3
    chrome.runtime.sendMessage({ action: 'force_sync' }, (resp) => {
        if (chrome.runtime.lastError) {
            status.innerHTML = '<span class="dot red"></span> Service worker error: ' + chrome.runtime.lastError.message;
        } else if (resp && resp.success) {
            status.innerHTML = `<span class="dot green"></span> ✓ Synced ${resp.count} captures! ${resp.message || ''}`;
        } else {
            status.innerHTML = '<span class="dot red"></span> Sync failed: ' + ((resp && resp.error) || 'No response from service worker. Reload extension at chrome://extensions');
        }
        setTimeout(() => { status.style.display = 'none'; }, 6000);
    });
}

function saveGistConfig() {
    const config = {
        autoSync: document.getElementById('gist-toggle').classList.contains('on'),
        pat: document.getElementById('github-pat').value,
        gistId: document.getElementById('github-gist-id').value
    };
    chrome.runtime.sendMessage({ action: 'save_gist_config', config }, () => {
        const status = document.getElementById('gist-status');
        if (!status) return;
        status.style.display = 'block';
        if (chrome.runtime.lastError) {
            status.innerHTML = '<span class="dot red"></span> Not saved: ' + chrome.runtime.lastError.message;
            setTimeout(() => { status.style.display = 'none'; }, 8000);
            return;
        }
        status.innerHTML = '<span class="dot green"></span> Saved.';
        setTimeout(() => { status.style.display = 'none'; }, 2200);
    });
}

async function testCloudflare() {
    const btn = document.getElementById('test-cf-btn');
    const url = document.getElementById('worker-url').value.replace(/\/$/, '');
    const token = document.getElementById('sync-token-input').value;
    const status = document.getElementById('sync-status');

    if (!url) { alert('Enter Worker URL first'); return; }
    if (!token) { alert('Enter Sync Token'); return; }

    btn.textContent = '⏳ Testing...';
    btn.disabled = true;
    status.style.display = 'block';
    status.innerHTML = '<span class="dot yellow"></span> Testing connection to ' + url + '...';

    // Route through service worker — extension pages CANNOT fetch cross-origin directly in MV3
    chrome.runtime.sendMessage({ action: 'test_cloudflare', url, token }, (resp) => {
        if (chrome.runtime.lastError) {
            btn.textContent = '✕ Failed';
            btn.style.color = '#ff4444';
            btn.style.borderColor = 'rgba(255,68,68,0.3)';
            status.innerHTML = '<span class="dot red"></span> Service worker error: ' + chrome.runtime.lastError.message + '. Reload extension at chrome://extensions';
        } else if (resp && resp.success) {
            const info = resp.data || {};
            btn.textContent = '✓ Connected!';
            btn.style.color = '#4ade80';
            btn.style.borderColor = 'rgba(74,222,128,0.3)';
            status.innerHTML = `<span class="dot green"></span> Connected! Captures: ${info.count || 0} • Last sync: ${info.lastSync ? new Date(info.lastSync).toLocaleString() : 'Never'}`;
        } else if (resp && resp.error) {
            btn.textContent = '✕ Failed';
            btn.style.color = '#ff4444';
            btn.style.borderColor = 'rgba(255,68,68,0.3)';
            status.innerHTML = '<span class="dot red"></span> ' + resp.error;
        } else {
            btn.textContent = '✕ No Response';
            btn.style.color = '#ff4444';
            btn.style.borderColor = 'rgba(255,68,68,0.3)';
            status.innerHTML = '<span class="dot red"></span> No response from service worker. Go to chrome://extensions and RELOAD the extension, then reopen this dashboard.';
        }

        setTimeout(() => {
            btn.textContent = '🧪 Test Connection';
            btn.style.color = ''; btn.style.borderColor = ''; btn.disabled = false;
        }, 6000);
    });
}

async function testGistPat() {
    const btn = document.getElementById('test-gist-btn');
    const pat = document.getElementById('github-pat').value;
    if (!pat) { alert('Enter GitHub PAT'); return; }

    btn.textContent = '⏳ Testing...';
    btn.disabled = true;

    try {
        const res = await fetch('https://api.github.com/user', {
            headers: { 'Authorization': `token ${pat}` }
        });
        if (res.ok) {
            btn.textContent = '✓ Auth Success!';
            btn.style.color = '#4ade80';
            btn.style.borderColor = 'rgba(74,222,128,0.3)';
        } else {
            throw new Error('Status ' + res.status);
        }
    } catch (e) {
        btn.textContent = '✕ Failed: ' + e.message;
        btn.style.color = '#ff4444';
        btn.style.borderColor = 'rgba(255,68,68,0.3)';
    }

    setTimeout(() => {
        btn.textContent = '🧪 Test PAT';
        btn.style.color = ''; btn.style.borderColor = ''; btn.disabled = false;
    }, 4000);
}

function backupToGist() {
    const pat = document.getElementById('github-pat').value;
    const gistId = document.getElementById('github-gist-id').value;
    if (!pat) { alert('Please enter a GitHub PAT'); return; }

    const data = JSON.stringify(allCaptures, null, 2);
    const method = gistId ? 'PATCH' : 'POST';
    const url = gistId ? `https://api.github.com/gists/${gistId}` : 'https://api.github.com/gists';

    document.getElementById('backup-gist-btn').textContent = '⏳ Backing up...';

    fetch(url, {
        method,
        headers: {
            'Authorization': `token ${pat}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            description: `Promptrix Backup — ${new Date().toISOString().slice(0, 10)}`,
            public: false,
            files: {
                'prompt_bin_backup.json': { content: data }
            }
        }),
    })
    .then(r => r.json())
    .then(result => {
        if (result.html_url) {
            if (!gistId) {
                document.getElementById('github-gist-id').value = result.id;
                saveGistConfig();
            }
            document.getElementById('backup-gist-btn').textContent = '✓ Success!';
        } else {
            alert('Backup failed: ' + JSON.stringify(result));
            document.getElementById('backup-gist-btn').textContent = '⬆ Manual Backup';
        }
        setTimeout(() => document.getElementById('backup-gist-btn').textContent = '⬆ Manual Backup', 3000);
    })
    .catch(err => {
        alert('Error: ' + err.message);
        document.getElementById('backup-gist-btn').textContent = '⬆ Manual Backup';
    });
}

// ─────────────────────────────────────
// EXPORT / CLEAR
// ─────────────────────────────────────
function exportData() {
    if (allCaptures.length === 0) { alert("No data to export."); return; }
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(allCaptures, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = "prompt_bin_export_" + new Date().toISOString().slice(0, 10) + ".json";
    document.body.appendChild(a);
    a.click();
    a.remove();
}

function clearHistory() {
    const n = allCaptures.length;
    if (!n) { alert('There is no capture history to clear.'); return; }
    const starred = allCaptures.filter(c => c.starred).length;
    // Name what is actually being destroyed. "Delete all history?" gave the
    // operator no way to judge the blast radius before agreeing to it.
    const msg = 'Permanently delete ' + n + ' captured item' + (n === 1 ? '' : 's') +
        (starred ? ' (including ' + starred + ' starred)' : '') + '?\n\n' +
        'DLP policy, DLP audit logs and your sync/forwarding settings are kept.\n' +
        'Copies already sent to Cloud Sync, Gist or a SIEM are not removed.\n\n' +
        'This cannot be undone.';
    if (!confirm(msg)) return;
    chrome.runtime.sendMessage({ action: 'clear_all' }, () => {
        loadData();
        renderClearCount();
    });
}

// Show the operator how much this button would destroy, before they press it.
function renderClearCount() {
    const el = document.getElementById('clear-count');
    if (!el) return;
    const n = allCaptures.length;
    const btn = document.getElementById('clear-btn');
    if (btn) btn.disabled = !n;
    if (!n) { el.textContent = 'Nothing stored — there is no history to clear.'; return; }
    const starred = allCaptures.filter(c => c.starred).length;
    el.textContent = n.toLocaleString() + ' item' + (n === 1 ? '' : 's') + ' stored' +
        (starred ? ' · ' + starred + ' starred' : '');
}

// ─────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────
function getToolClass(toolName) {
    const t = (toolName || '').toLowerCase();
    if (t.includes('chatgpt')) return 'chatgpt';
    if (t.includes('gemini')) return 'gemini';
    if (t.includes('claude')) return 'claude';
    if (t.includes('perplexity')) return 'perplexity';
    if (t.includes('copilot')) return 'copilot';
    return 'default';
}

function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function escapeHtmlAttr(text) {
    if (!text) return '';
    return text.replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function formatRelativeTime(timestamp) {
    const now = new Date();
    const then = new Date(timestamp);
    const diff = now - then;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return mins + 'm ago';
    const hours = Math.floor(mins / 60);
    if (hours < 24) return hours + 'h ago';
    const days = Math.floor(hours / 24);
    if (days < 7) return days + 'd ago';
    return then.toLocaleDateString();
}

// ═════════════════════════════════════════════════════════════════════════
// DLP — DATA-LOSS PREVENTION (policy, pattern toggles, audit log)
// ═════════════════════════════════════════════════════════════════════════

const DLP = window.PromptrixDLP || null;
const CIE = window.PromptrixInspector || null;

const DLP_CLASS_ORDER = [
    'AUTHENTICATION_SECRET',
    'HIGH_RISK_IDENTIFIER',
    'SPECIAL_HANDLING_DATA',
    'PERSONAL_DATA',
    'CONFIDENTIAL',
];
const DLP_CLASS_ICON = {
    AUTHENTICATION_SECRET: '🔑',
    HIGH_RISK_IDENTIFIER: '🆔',
    SPECIAL_HANDLING_DATA: '🧬',
    PERSONAL_DATA: '👤',
    CONFIDENTIAL: '🏢',
};
const DLP_SEV_COLOR = { CRITICAL: '#ef4444', HIGH: '#f59e0b', MEDIUM: '#60a5fa', LOW: '#8888a0' };

let dlpCurrentPolicy = null;
let dlpLastLogs = [];
const DLP_COLS = ['enabled', 'mask', 'block', 'warn']; // Detect / Mask / Block / Warn
const DLP_COL_CLASS = { enabled: '', mask: '', block: 'blk', warn: 'wrn' };

function initDlp() {
    if (!DLP) {
        console.warn('[Promptrix] DLP engine not loaded in dashboard.');
        return;
    }
    const on = (id, ev, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(ev, fn); };

    // Global labeling switch (append classification banner to masked prompts).
    on('dlp-labeling-toggle', 'click', function () { this.classList.toggle('on'); });

    // On-page warning bulk switch — turns Warn on/off for every enabled detector.
    on('dlp-warn-all', 'click', function () {
        const turnOn = !this.classList.contains('on');
        this.classList.toggle('on', turnOn);
        document.querySelectorAll('#dlp-table-groups .dlp-mini[data-col="warn"]').forEach(t => t.classList.toggle('on', turnOn));
        document.querySelectorAll('#dlp-table-groups .dlp-group').forEach(g => syncGroupHeader(g, groupRules(g)));
    });

    // Bulk enforcement segmented (Monitor / Mask / Block).
    document.querySelectorAll('#dlp-enf button').forEach(b => {
        b.addEventListener('click', () => applyEnforcement(b.getAttribute('data-enf')));
    });

    // ── Content Inspection controls ──
    ['cie-archives', 'cie-documents', 'cie-masquerade', 'cie-fingerprint']
        .forEach(id => on(id, 'click', function () { this.classList.toggle('on'); }));
    document.querySelectorAll('#cie-depth button').forEach(b => {
        b.addEventListener('click', () => setInspectionDepth(b.getAttribute('data-depth')));
    });
    document.querySelectorAll('#cie-actions .dlp-seg[data-bandseg]').forEach(seg => {
        seg.querySelectorAll('button').forEach(b => {
            b.addEventListener('click', () => {
                seg.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
            });
        });
    });
    on('save-dlp-file', 'click', () => saveDlpPolicy('dlp-file-status'));

    // Header + page actions.
    // (nav + back are bound above; renderView() handles the DLP log refresh)
    on('dlp-reset-defaults', 'click', resetDlpDefaults);

    // ── Auto-save ─────────────────────────────────────────────────────
    // Every policy edit persists on its own. Debounced so dragging across a
    // column writes once, not once per toggle, and so a rapid series of edits
    // collapses into a single storage write.
    let dlpSaveTimer = null;
    function autosaveDlpPolicy() {
        clearTimeout(dlpSaveTimer);
        dlpSaveTimer = setTimeout(() => saveDlpPolicy(null, { auto: true }), 350);
    }

    const dlpView = document.getElementById('view-dlp');
    if (dlpView) {
        // Delegated so detector rows rendered later are covered without rebinding.
        dlpView.addEventListener('click', (e) => {
            if (e.target.closest('.dlp-tab, .dlp-panelbar, #dlp-logs-clear, #dlp-reset-defaults, .dlp-logbar, .dlp-log-chips, .dlp-log-pager, .dlp-drawer')) return;
            if (e.target.closest('.dlp-mini, .toggle, .dlp-seg, .dlp-group, [data-bandseg], [data-depth]')) autosaveDlpPolicy();
        });
        dlpView.addEventListener('change', (e) => {
            if (e.target.closest('.dlp-logbar')) return;   // log filters are view state, not policy
            autosaveDlpPolicy();
        });
    }

    on('dlp-expand-all', 'click', () => setAllGroups(false));
    on('dlp-collapse-all', 'click', () => setAllGroups(true));
    on('dlp-density', 'click', function () {
        const g = document.getElementById('dlp-table-groups');
        const compact = g.classList.toggle('compact');
        this.textContent = compact ? 'Comfortable' : 'Compact';
    });
    on('dlp-search', 'input', function () { filterDetectors(this.value); });
    on('dlp-tierfilter', 'click', function () {
        const modes = ['all', 'on', 'candidate'];
        const next = modes[(modes.indexOf(this.dataset.mode || 'all') + 1) % modes.length];
        this.dataset.mode = next;
        this.textContent = { all: 'All detectors', on: 'Enabled only', candidate: 'Candidates only' }[next];
        applyTierFilter(next);
    });

    on('dlp-logs-refresh', 'click', loadDlpLogs);
    on('dlp-logs-clear', 'click', clearDlpLogs);

    // ── Activity-log filters ──────────────────────────────────────────
    let logSearchTimer = null;
    on('dlp-log-search', 'input', function () {
        clearTimeout(logSearchTimer);
        const v = this.value;
        logSearchTimer = setTimeout(() => {
            dlpLogFilter.q = v.trim();
            dlpLogPage = 0;
            renderDlpLogs(dlpLastLogs);
        }, 220);   // debounce so typing does not re-render per keystroke
    });
    [['dlp-log-action', 'action'], ['dlp-log-sev', 'severity'], ['dlp-log-tool', 'tool']]
        .forEach(([id, key]) => on(id, 'change', function () {
            dlpLogFilter[key] = this.value;
            dlpLogPage = 0;
            renderDlpLogs(dlpLastLogs);
        }));

    // In-page tabs.
    document.querySelectorAll('.dlp-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const name = tab.getAttribute('data-dtab');
            document.querySelectorAll('.dlp-tab').forEach(t => t.classList.toggle('active', t === tab));
            document.querySelectorAll('.dlp-dpanel').forEach(p => p.classList.toggle('active', p.id === 'dlp-panel-' + name));
            if (name === 'log') loadDlpLogs();
        });
    });

    // Detail drawer close.
    on('dlp-drawer-scrim', 'click', closeDlpDrawer);

    loadDlpPolicy();
    initFwd();
}

// Rules array for a group element (from its rendered rows).
function groupRules(group) {
    return [...group.querySelectorAll('.dlp-gbody [data-pattern]')]
        .map(t => t.getAttribute('data-pattern'))
        .filter((v, i, a) => a.indexOf(v) === i)
        .map(id => ({ id }));
}

// Bulk enforcement: set mask/block for every ENABLED detector.
function applyEnforcement(mode) {
    document.querySelectorAll('#dlp-enf button').forEach(b => b.classList.toggle('on', b.getAttribute('data-enf') === mode));
    document.querySelectorAll('#dlp-table-groups .dlp-prow').forEach(row => {
        const det = row.querySelector('.dlp-mini[data-col="enabled"]');
        if (!det || !det.classList.contains('on')) return;
        const mask = row.querySelector('.dlp-mini[data-col="mask"]');
        const block = row.querySelector('.dlp-mini[data-col="block"]');
        if (mode === 'monitor') { mask && mask.classList.remove('on'); block && block.classList.remove('on'); }
        else if (mode === 'mask') { mask && mask.classList.add('on'); block && block.classList.remove('on'); }
        else if (mode === 'block') { block && block.classList.add('on'); }
    });
    document.querySelectorAll('#dlp-table-groups .dlp-group').forEach(g => { refreshRowDisabling(g); syncGroupHeader(g, groupRules(g)); });
    renderDlpStatband();
}

// Search filter across the matrix (label + rule id); auto-expands matching groups.
function filterDetectors(q) {
    const query = (q || '').trim().toLowerCase();
    let anyVisible = false;
    document.querySelectorAll('#dlp-table-groups .dlp-group').forEach(group => {
        let groupHit = false;
        group.querySelectorAll('.dlp-prow').forEach(row => {
            const id = (row.getAttribute('data-row') || '').toLowerCase();
            const name = (row.querySelector('.n') ? row.querySelector('.n').textContent : '').toLowerCase();
            const hit = !query || id.includes(query) || name.includes(query);
            row.style.display = hit ? '' : 'none';
            if (hit) { groupHit = true; anyVisible = true; }
        });
        group.style.display = groupHit ? '' : 'none';
        if (query) group.classList.remove('collapsed'); // expand to reveal matches
    });
    const nr = document.getElementById('dlp-noresults');
    if (nr) nr.style.display = anyVisible ? 'none' : 'block';
}

// Status band — live posture from the current UI state + audit log.
function renderDlpStatband(logs) {
    const el = document.getElementById('dlp-statband');
    if (!el) return;
    const minis = [...document.querySelectorAll('#dlp-table-groups .dlp-prow .dlp-mini[data-col="enabled"]')];
    const det = minis.filter(m => m.classList.contains('on')).length || DLP.RULES.length;
    const total = DLP.RULES.length;
    const blocking = [...document.querySelectorAll('#dlp-table-groups .dlp-prow .dlp-mini[data-col="block"].on')].length;
    const masking = [...document.querySelectorAll('#dlp-table-groups .dlp-prow .dlp-mini[data-col="mask"].on')].length;
    const posture = document.querySelector('#dlp-enf button.on');
    const postureLbl = posture ? posture.getAttribute('data-enf') : 'mask';

    const L = logs || dlpLastLogs || [];
    const dayAgo = Date.now() - 864e5, wkAgo = Date.now() - 7 * 864e5;
    const recent = L.filter(l => new Date(l.ts).getTime() > dayAgo);
    const masked = recent.filter(l => l.action === 'mask').length;
    const blocked = recent.filter(l => l.action === 'block').length;
    const files = L.filter(l => l.source === 'file' && new Date(l.ts).getTime() > wkAgo).length;
    const items = L.filter(l => new Date(l.ts).getTime() > wkAgo).reduce((a, l) => a + (l.totalFindings || 0), 0);

    // Coverage is the one number that answers "am I protected?", so it leads.
    // Everything else is supporting detail and is rendered at lower weight —
    // previously all six tiles were peers, which made configuration state and
    // activity counts look equally important.
    const pct = total ? Math.round(det / total * 100) : 0;
    const band = pct >= 70 ? 'good' : pct >= 40 ? 'warn' : 'bad';
    const POSTURE_COPY = {
        mask:  'Sensitive values are redacted, then the prompt is sent.',
        block: 'Prompts containing sensitive values are stopped outright.',
        warn:  'You are warned, but the original prompt is still sent.',
        off:   'No enforcement — detections are recorded only.',
    };

    const R = 30, C = 2 * Math.PI * R;
    el.innerHTML = `
      <div class="dlp-posture ${band}">
        <div class="dlp-ring" role="img" aria-label="${det} of ${total} detectors enabled, ${pct} percent coverage">
          <svg viewBox="0 0 72 72" aria-hidden="true">
            <circle cx="36" cy="36" r="${R}" class="trk"/>
            <circle cx="36" cy="36" r="${R}" class="val"
              stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${(C * (1 - pct / 100)).toFixed(1)}"/>
          </svg>
          <div class="dlp-ringnum">${pct}<span>%</span></div>
        </div>
        <div class="dlp-posturetext">
          <div class="dlp-posturelbl">Enforcement</div>
          <div class="dlp-posturev">${postureLbl.charAt(0).toUpperCase() + postureLbl.slice(1)}</div>
          <div class="dlp-posturesub">${POSTURE_COPY[postureLbl] || ''}</div>
          <div class="dlp-posturemeta">
            <b>${det.toLocaleString()}</b> of ${total.toLocaleString()} detectors on
            <span class="sep">·</span> <b>${masking.toLocaleString()}</b> masking
            <span class="sep">·</span> <b>${blocking.toLocaleString()}</b> blocking
          </div>
        </div>
      </div>
      <div class="dlp-kpis">
        ${[['Masked', masked, 'last 24h'], ['Blocked', blocked, 'last 24h'],
           ['Files flagged', files, 'last 7d'], ['Items redacted', items, 'last 7d']]
          .map(([l, v, s]) => `<div class="dlp-kpi"><div class="v">${Number(v).toLocaleString()}</div>
             <div class="l">${l}</div><div class="s">${s}</div></div>`).join('')}
      </div>`;
}

// ── Per-detector detail drawer ──
function openDlpDrawer(ruleId) {
    const rule = DLP.RULES.find(r => r.id === ruleId);
    if (!rule) return;
    const drawer = document.getElementById('dlp-drawer');
    const scrim = document.getElementById('dlp-drawer-scrim');
    const cls = DLP.CLASSIFICATION_SHORT[rule.classification] || rule.classification;
    const src = rule.regex ? rule.regex.source : '(unavailable)';
    const flags = rule.regex ? rule.regex.flags : '';
    const ctlMeta = { enabled: ['Detect', 'Run this detector'], mask: ['Mask', 'Redact matches'], block: ['Block', 'Stop the prompt'], warn: ['Warn', 'On-page banner'] };
    const rowMinis = {};
    document.querySelectorAll(`#dlp-table-groups .dlp-prow[data-row="${ruleId}"] .dlp-mini`).forEach(m => { rowMinis[m.getAttribute('data-col')] = m; });

    drawer.innerHTML =
        `<div class="dlp-dr-head">
            <div class="dlp-dr-close" id="dlp-dr-close">✕</div>
            <div class="dlp-dr-title">${escapeHtml(rule.label.replace(/_/g, ' '))}</div>
            <div class="dlp-dr-badges">
                <span class="dlp-sev-badge dlp-sev-${rule.severity}">${rule.severity}</span>
                ${rule.secret ? '<span class="dlp-sev-badge dlp-sev-CRITICAL">SECRET</span>' : ''}
                ${rule.lowConfidence ? '<span class="dlp-sev-badge dlp-sev-LOW">CANDIDATE</span>' : ''}
                <span class="dlp-class-chip">${escapeHtml(cls)}</span>
            </div>
        </div>
        <div class="dlp-dr-body">
            <div class="dlp-dr-sect">Controls</div>
            <div class="dlp-dr-controls" id="dlp-dr-controls">
                ${DLP_COLS.map(col => {
                    const on = rowMinis[col] && rowMinis[col].classList.contains('on');
                    const kls = col === 'block' ? ' blk' : col === 'warn' ? ' wrn' : '';
                    return `<div class="dlp-dr-ctl"><div><div class="cl">${ctlMeta[col][0]}</div><div class="cd">${ctlMeta[col][1]}</div></div><div class="dlp-mini${kls}${on ? ' on' : ''}" data-drcol="${col}"></div></div>`;
                }).join('')}
            </div>
            <div class="dlp-dr-sect" style="margin-top:22px;">Detector</div>
            <div class="dlp-dr-row"><span class="k">Rule ID</span><span class="v mono" style="font-family:'SF Mono',monospace;">${escapeHtml(rule.id)}</span></div>
            <div class="dlp-dr-row"><span class="k">Classification</span><span class="v">${escapeHtml(cls)}</span></div>
            <div class="dlp-dr-row"><span class="k">Category</span><span class="v">${escapeHtml(rule.category)}</span></div>
            <div class="dlp-dr-row"><span class="k">Deterministic validator</span><span class="v">${rule.validator || rule.validate ? 'Yes' : '—'}</span></div>
            <div class="dlp-dr-row"><span class="k">Literal pre-gate</span><span class="v mono" style="font-family:'SF Mono',monospace;">${rule.lit ? escapeHtml(rule.lit) : '—'}</span></div>
            <div class="dlp-dr-row"><span class="k">Confidence tier</span><span class="v">${escapeHtml(rule.tier || 'precise')}${rule.defaultOn === false ? ' (off by default)' : ''}</span></div>
            ${rule.family ? `<div class="dlp-dr-row"><span class="k">Category</span><span class="v">${escapeHtml(rule.family)}</span></div>` : ''}
            ${rule.sample ? `<div class="dlp-dr-row"><span class="k">Example</span><span class="v mono" style="font-family:'SF Mono',monospace;font-size:11px;">${escapeHtml(rule.sample.slice(0, 34))}</span></div>` : ''}
            <div class="dlp-dr-sect" style="margin-top:22px;">Pattern</div>
            <div class="dlp-dr-regex">/${escapeHtml(src)}/${escapeHtml(flags)}</div>
            <p style="font-size:11px;color:var(--muted);margin-top:12px;line-height:1.5;">Matches are masked to <b>XXXX</b> of the same width. The audit log stores redacted evidence only — never the raw value.</p>
        </div>`;

    // Sync drawer controls back to the matrix row (single source of truth).
    drawer.querySelectorAll('.dlp-mini[data-drcol]').forEach(dm => {
        dm.addEventListener('click', () => {
            const col = dm.getAttribute('data-drcol');
            const rowMini = rowMinis[col];
            if (!rowMini) return;
            rowMini.click(); // reuse the row toggle's full logic (disabling, group sync, statband)
            dm.classList.toggle('on', rowMini.classList.contains('on'));
        });
    });
    drawer.querySelector('#dlp-dr-close').addEventListener('click', closeDlpDrawer);
    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
    scrim.classList.add('open');
}

function closeDlpDrawer() {
    const drawer = document.getElementById('dlp-drawer');
    const scrim = document.getElementById('dlp-drawer-scrim');
    if (drawer) { drawer.classList.remove('open'); drawer.setAttribute('aria-hidden', 'true'); }
    if (scrim) scrim.classList.remove('open');
}

function loadDlpPolicy() {
    chrome.runtime.sendMessage({ action: 'get_dlp_policy' }, (policy) => {
        if (chrome.runtime.lastError) { console.warn(chrome.runtime.lastError); return; }
        dlpCurrentPolicy = DLP.normalizePolicy(policy);
        applyPolicyToUi(dlpCurrentPolicy);
        renderDlpMatrix(dlpCurrentPolicy);
        // Reflect the saved policy in the enforcement segmented + warning switch.
        syncEnforcementUi();
        const tc = document.getElementById('dlp-tc-policy');
        if (tc) tc.textContent = DLP.RULES.length;
        renderDlpStatband();
        loadDlpLogs();
    });
}

// Infer the enforcement segmented + global warn switch from the matrix state.
function syncEnforcementUi() {
    const rows = [...document.querySelectorAll('#dlp-table-groups .dlp-prow')];
    const enabled = rows.filter(r => { const d = r.querySelector('.dlp-mini[data-col="enabled"]'); return d && d.classList.contains('on'); });
    const anyBlock = enabled.some(r => { const b = r.querySelector('.dlp-mini[data-col="block"]'); return b && b.classList.contains('on'); });
    const anyMask = enabled.some(r => { const m = r.querySelector('.dlp-mini[data-col="mask"]'); return m && m.classList.contains('on'); });
    const mode = anyBlock ? 'block' : anyMask ? 'mask' : 'monitor';
    document.querySelectorAll('#dlp-enf button').forEach(b => b.classList.toggle('on', b.getAttribute('data-enf') === mode));
    const allWarn = enabled.length && enabled.every(r => { const w = r.querySelector('.dlp-mini[data-col="warn"]'); return w && w.classList.contains('on'); });
    const wa = document.getElementById('dlp-warn-all');
    if (wa) wa.classList.toggle('on', !!allWarn);
}

function applyPolicyToUi(policy) {
    const lbl = document.getElementById('dlp-labeling-toggle');
    if (lbl) lbl.classList.toggle('on', !!policy.labeling);
    // Content-inspection settings
    const f = policy.file || (CIE ? CIE.defaultInspectionPolicy() : null);
    if (!f) return;
    const set = (id, on) => { const el = document.getElementById(id); if (el) el.classList.toggle('on', !!on); };
    const val = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
    set('cie-archives', f.inspectArchives);
    set('cie-documents', f.inspectDocuments);
    set('cie-masquerade', f.flagMasquerade);
    set('cie-fingerprint', f.fingerprint);
    val('cie-maxsize', f.maxSizeKB);
    val('cie-maxms', f.maxMs);
    val('cie-maxdepth', f.maxDepth);
    val('cie-maxentries', f.maxEntries);
    setInspectionDepth(f.enabled === false ? 'off' : f.depth, true);
    // Response matrix
    Object.keys(f.actions || {}).forEach(band => {
        const seg = document.querySelector(`#cie-actions .dlp-seg[data-bandseg="${band}"]`);
        if (!seg) return;
        seg.querySelectorAll('button').forEach(b => b.classList.toggle('on', b.getAttribute('data-act') === f.actions[band]));
    });
}

// Inspection depth segmented control + its explanatory hint.
const CIE_DEPTH_HINT = {
    off: 'Attachments are not inspected. Prompt-text protection is unaffected.',
    shallow: 'Plain-text files only. Archives, Office documents and PDFs are passed through uninspected.',
    deep: 'Opens archives and Office documents, following nested containers to the configured depth.',
};
function setInspectionDepth(depth, silent) {
    document.querySelectorAll('#cie-depth button').forEach(b =>
        b.classList.toggle('on', b.getAttribute('data-depth') === depth));
    const hint = document.getElementById('cie-depth-hint');
    if (hint) hint.textContent = CIE_DEPTH_HINT[depth] || CIE_DEPTH_HINT.deep;
    // Coverage toggles are meaningless unless deep inspection is running.
    const deep = depth === 'deep';
    ['cie-archives', 'cie-documents'].forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.style.opacity = deep ? '1' : '.35'; el.style.pointerEvents = deep ? 'auto' : 'none'; }
    });
    if (!silent) renderDlpStatband();
}

// Build one mini toggle cell for a given rule + column.
function dlpMiniToggle(ruleId, col, on) {
    const cell = document.createElement('div');
    cell.className = 'dlp-cell';
    const t = document.createElement('div');
    t.className = 'dlp-mini' + (DLP_COL_CLASS[col] ? ' ' + DLP_COL_CLASS[col] : '');
    t.setAttribute('data-pattern', ruleId);
    t.setAttribute('data-col', col);
    if (on) t.classList.add('on');
    t.title = col === 'enabled' ? 'Detect' : col.charAt(0).toUpperCase() + col.slice(1);
    cell.appendChild(t);
    return cell;
}

// Render the collapsible classification → data-type matrix.

// ══ Detector efficacy ═════════════════════════════════════════════════
// With 224 detectors an admin cannot tune the policy blind. Real DLP consoles
// surface per-rule hit counts so operators can find the two things that matter:
// detectors that never fire (dead weight, candidates for disabling) and
// detectors that fire constantly (noise, candidates for tightening).
let dlpHitIndex = { counts: {}, total: 0, windowDays: 30, since: null };

function buildDlpHitIndex(logs) {
    const counts = {};
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    let total = 0, oldest = null;
    (logs || []).forEach(entry => {
        const t = Date.parse(entry.ts || '') || 0;
        if (t && t < cutoff) return;
        if (t && (oldest === null || t < oldest)) oldest = t;
        (entry.items || []).forEach(it => {
            const key = it.label || it.id;
            if (!key) return;
            counts[key] = (counts[key] || 0) + (it.count || 1);
            total += (it.count || 1);
        });
    });
    dlpHitIndex = { counts, total, windowDays: 30, since: oldest };
    return dlpHitIndex;
}

// Matrix rows carry a hits cell; repaint it without a full re-render.
function paintDlpHits() {
    const { counts } = dlpHitIndex;
    // Group totals first, so a collapsed classification still reports activity.
    document.querySelectorAll('#dlp-table-groups .dlp-group').forEach(g => {
        const cell = g.querySelector('[data-role="ghits"]');
        if (!cell) return;
        let sum = 0;
        g.querySelectorAll('.dlp-prow').forEach(r => {
            const rule = DLP.RULES.find(x => x.id === r.getAttribute('data-row'));
            sum += counts[rule ? (rule.label || rule.id) : ''] || 0;
        });
        cell.className = 'dlp-hits ' + (sum ? 'has' : 'off');
        cell.textContent = sum ? sum.toLocaleString() : '\u00B7';
        if (sum) cell.title = `${sum.toLocaleString()} matches in this classification (30d)`;
    });
    document.querySelectorAll('#dlp-table-groups .dlp-prow').forEach(row => {
        const el = row.querySelector('[data-role="hits"]');
        if (!el) return;
        const id = row.getAttribute('data-row');
        const rule = DLP.RULES.find(r => r.id === id);
        const key = rule ? (rule.label || rule.id) : id;
        const n = counts[key] || 0;
        const enabled = row.querySelector('.dlp-mini[data-col="enabled"].on');
        if (n > 0) {
            el.className = 'dlp-hits has';
            el.textContent = n.toLocaleString();
            el.title = `${n.toLocaleString()} match${n === 1 ? '' : 'es'} in the last 30 days`;
        } else if (enabled) {
            // Flag dead detectors subtly — admins hunt these.
            el.className = 'dlp-hits none';
            el.textContent = '\u2014';
            el.title = 'No matches in the last 30 days — review whether this detector earns its place';
        } else {
            el.className = 'dlp-hits off';
            el.textContent = '\u00B7';
            el.title = 'Detector disabled';
        }
    });
}

function renderDlpMatrix(policy) {
    const container = document.getElementById('dlp-table-groups');
    if (!container) return;
    container.innerHTML = '';
    setTimeout(paintDlpHits, 0);   // rows exist by the time this runs

    const byClass = {};
    DLP.RULES.forEach(r => { (byClass[r.classification] = byClass[r.classification] || []).push(r); });

    DLP_CLASS_ORDER.forEach((cls, gi) => {
        const rules = byClass[cls];
        if (!rules || !rules.length) return;

        const group = document.createElement('div');
        // Open the first group by default so the expand/collapse behaviour is
        // obvious at a glance; the rest start collapsed for density.
        group.className = 'dlp-group' + (gi === 0 ? '' : ' collapsed');
        group.setAttribute('data-class', cls);

        // ── Classification header row (also the accordion control) ──
        const head = document.createElement('div');
        head.className = 'dlp-ghead dlp-row';
        head.title = 'Click to expand / collapse';

        const name = document.createElement('div');
        name.className = 'dlp-gname dlp-c-name';
        name.innerHTML = `<span class="dlp-disc"><svg class="dlp-chevron" viewBox="0 0 24 24" fill="none"><path d="m9 6 6 6-6 6" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg></span>` +
            `<span>${DLP_CLASS_ICON[cls] || '🛡️'}</span>` +
            `<span>${DLP.CLASSIFICATION_SHORT[cls] || cls}</span>` +
            `<span class="dlp-gcount">(${rules.length})</span>` +
            `<span class="dlp-gsummary" data-role="summary"></span>`;
        head.appendChild(name);

        // Placeholder so the group header's bulk toggles stay aligned with the
        // detector rows now that an efficacy column sits between them.
        const ghits = document.createElement('div');
        ghits.className = 'dlp-hits off';
        ghits.setAttribute('data-role', 'ghits');
        head.appendChild(ghits);

        // Group-level bulk toggle per column (sets every type in the group).
        DLP_COLS.forEach(col => {
            const allOn = rules.every(r => policy.patterns[r.id][col]);
            const cell = dlpMiniToggle('__group__', col, allOn);
            const t = cell.querySelector('.dlp-mini');
            t.setAttribute('data-group-col', col);
            t.addEventListener('click', (e) => {
                e.stopPropagation();
                const turnOn = !t.classList.contains('on');
                t.classList.remove('mixed');
                t.classList.toggle('on', turnOn);
                group.querySelectorAll(`.dlp-gbody .dlp-mini[data-col="${col}"]`).forEach(ch => {
                    ch.classList.toggle('on', turnOn);
                });
                if (col === 'enabled') refreshRowDisabling(group);
                syncGroupHeader(group, rules); // refresh header states + summary
            });
            head.appendChild(cell);
        });

        // Accordion expand/collapse on header click (ignore clicks on toggles).
        head.addEventListener('click', (e) => {
            if (e.target.closest('.dlp-mini')) return;
            group.classList.toggle('collapsed');
        });
        group.appendChild(head);

        // ── Data-type rows ──
        const body = document.createElement('div');
        body.className = 'dlp-gbody';
        rules.forEach(r => {
            const row = document.createElement('div');
            row.className = 'dlp-prow dlp-row';
            row.setAttribute('data-row', r.id);
            row.setAttribute('data-tier', r.tier || 'precise');

            const meta = document.createElement('div');
            meta.className = 'dlp-c-name';
            meta.style.cursor = 'pointer';
            meta.title = 'View detector details';
            meta.innerHTML =
                `<div class="dlp-pname"><span class="n">${r.label.replace(/_/g, ' ')}</span>` +
                `<span class="dlp-sev-badge dlp-sev-${r.severity}">${r.severity}</span>` +
                (r.secret ? '<span class="dlp-sev-badge dlp-sev-CRITICAL">SECRET</span>' : '') +
                (r.tier === 'candidate' ? '<span class="dlp-sev-badge dlp-sev-LOW" title="Matches bare digit/letter runs — off by default">CANDIDATE</span>'
                  : r.lowConfidence ? '<span class="dlp-sev-badge dlp-sev-LOW">CANDIDATE</span>' : '') +
                (r.family ? `<span class="dlp-sev-badge dlp-sev-MEDIUM" style="opacity:.75;">${escapeHtml(r.family)}</span>` : '') +
                `</div><div class="dlp-pid">${r.id}</div>`;
            meta.addEventListener('click', () => openDlpDrawer(r.id));
            row.appendChild(meta);

            // Efficacy column: matches in the last 30 days.
            const hits = document.createElement('div');
            hits.className = 'dlp-hits off';
            hits.setAttribute('data-role', 'hits');
            hits.textContent = '\u00B7';
            row.appendChild(hits);

            DLP_COLS.forEach(col => {
                const cell = dlpMiniToggle(r.id, col, policy.patterns[r.id][col]);
                const t = cell.querySelector('.dlp-mini');
                t.addEventListener('click', function () {
                    this.classList.toggle('on');
                    if (col === 'enabled') refreshRowDisabling(group);
                    syncGroupHeader(group, rules);
                    renderDlpStatband();
                });
                row.appendChild(cell);
            });
            body.appendChild(row);
        });
        group.appendChild(body);
        container.appendChild(group);

        refreshRowDisabling(group);
        syncGroupHeader(group, rules);
    });
}

// When a type's Detect is OFF, its Mask/Block/Warn are irrelevant — dim them.
function refreshRowDisabling(group) {
    group.querySelectorAll('.dlp-gbody .dlp-prow').forEach(row => {
        const detect = row.querySelector('.dlp-mini[data-col="enabled"]');
        const on = detect && detect.classList.contains('on');
        row.querySelectorAll('.dlp-mini[data-col="mask"],.dlp-mini[data-col="block"],.dlp-mini[data-col="warn"]')
            .forEach(t => t.classList.toggle('disabled', !on));
    });
}

// Recompute each group-header toggle (on / off / mixed) + the summary text.
function syncGroupHeader(group, rules) {
    DLP_COLS.forEach(col => {
        const gt = group.querySelector(`.dlp-mini[data-group-col="${col}"]`);
        if (!gt) return;
        const states = rules.map(r => {
            const t = group.querySelector(`.dlp-gbody .dlp-mini[data-pattern="${r.id}"][data-col="${col}"]`);
            return t && t.classList.contains('on');
        });
        const allOn = states.every(Boolean);
        const noneOn = states.every(s => !s);
        gt.classList.toggle('on', allOn);
        gt.classList.toggle('mixed', !allOn && !noneOn);
    });
    // Summary: how many detected / masked / blocked
    const cnt = c => rules.filter(r => {
        const t = group.querySelector(`.dlp-gbody .dlp-mini[data-pattern="${r.id}"][data-col="${c}"]`);
        return t && t.classList.contains('on');
    }).length;
    const sum = group.querySelector('[data-role="summary"]');
    if (sum) sum.textContent = `· ${cnt('enabled')} on · ${cnt('mask')} mask · ${cnt('block')} block`;
}

// Toolbar filter across the matrix: all / enabled-only / candidate-only.
function applyTierFilter(mode) {
    document.querySelectorAll('#dlp-table-groups .dlp-group').forEach(group => {
        let anyVisible = false;
        group.querySelectorAll('.dlp-prow').forEach(row => {
            const det = row.querySelector('.dlp-mini[data-col="enabled"]');
            const isOn = det && det.classList.contains('on');
            const isCand = row.getAttribute('data-tier') === 'candidate';
            const show = mode === 'all' || (mode === 'on' && isOn) || (mode === 'candidate' && isCand);
            row.style.display = show ? '' : 'none';
            if (show) anyVisible = true;
        });
        group.style.display = anyVisible ? '' : 'none';
        if (mode !== 'all') group.classList.remove('collapsed');
    });
}

function setAllGroups(collapsed) {
    document.querySelectorAll('#dlp-table-groups .dlp-group').forEach(g => g.classList.toggle('collapsed', collapsed));
}

function collectDlpPolicy() {
    const patterns = {};
    DLP.RULES.forEach(r => { patterns[r.id] = { enabled: false, mask: false, block: false, warn: false }; });
    document.querySelectorAll('#dlp-table-groups .dlp-gbody .dlp-mini[data-pattern]').forEach(t => {
        const id = t.getAttribute('data-pattern');
        const col = t.getAttribute('data-col');
        if (patterns[id] && col) patterns[id][col] = t.classList.contains('on');
    });
    const has = id => document.getElementById(id);
    const isOn = id => !!(has(id) && has(id).classList.contains('on'));
    const num = (id, d) => Number(has(id) && has(id).value) || d;
    const depthBtn = document.querySelector('#cie-depth button.on');
    const depth = depthBtn ? depthBtn.getAttribute('data-depth') : 'deep';
    const actions = {};
    document.querySelectorAll('#cie-actions .dlp-seg[data-bandseg]').forEach(seg => {
        const chosen = seg.querySelector('button.on');
        actions[seg.getAttribute('data-bandseg')] = chosen ? chosen.getAttribute('data-act') : 'notify';
    });
    const file = {
        enabled: depth !== 'off',
        depth: depth,
        inspectArchives: isOn('cie-archives'),
        inspectDocuments: isOn('cie-documents'),
        flagMasquerade: isOn('cie-masquerade'),
        fingerprint: isOn('cie-fingerprint'),
        maxSizeKB: num('cie-maxsize', 4096),
        maxMs: num('cie-maxms', 4000),
        maxDepth: num('cie-maxdepth', 3),
        maxEntries: num('cie-maxentries', 400),
        actions: actions,
    };
    return {
        labeling: document.getElementById('dlp-labeling-toggle').classList.contains('on'),
        patterns,
        file,
    };
}


function saveDlpPolicy(statusId, opts) {
    const auto = !!(opts && opts.auto);
    const policy = collectDlpPolicy();
    chrome.runtime.sendMessage({ action: 'save_dlp_policy', policy }, () => {
        const status = document.getElementById(typeof statusId === 'string' ? statusId : 'dlp-status');
        if (!status) return;
        status.style.display = 'block';
        if (chrome.runtime.lastError) {
            // A failed auto-save must be loud — the operator did not press
            // anything, so silence would leave them believing it applied.
            status.innerHTML = '<span class="dot red"></span> Not saved: ' +
                chrome.runtime.lastError.message + ' — your change is not in effect.';
            setTimeout(() => { status.style.display = 'none'; }, 9000);
            return;
        }
        dlpCurrentPolicy = DLP.normalizePolicy(policy);
        const det = Object.values(policy.patterns).filter(p => p.enabled).length;
        const msk = Object.values(policy.patterns).filter(p => p.enabled && p.mask).length;
        const blk = Object.values(policy.patterns).filter(p => p.enabled && p.block).length;
        status.innerHTML = auto
            ? `<span class="dot green"></span> Saved — ${det}/${DLP.RULES.length} detecting · ${msk} masking · ${blk} blocking.`
            : `<span class="dot green"></span> Policy saved — ${det}/${DLP.RULES.length} detecting · ${msk} masking · ${blk} blocking.`;
        renderDlpStatband();
        setTimeout(() => { status.style.display = 'none'; }, auto ? 2200 : 4500);
    });
}

function resetDlpDefaults() {
    const def = DLP.defaultPolicy();
    applyPolicyToUi(def);
    renderDlpMatrix(def);
    syncEnforcementUi();
    renderDlpStatband();
    const status = document.getElementById('dlp-status');
    status.style.display = 'block';
    status.innerHTML = '<span class="dot yellow"></span> Defaults restored — click <b>Save Policy</b> to apply.';
    setTimeout(() => { status.style.display = 'none'; }, 5000);
}

// ── Audit log ──
function loadDlpLogs() {
    chrome.runtime.sendMessage({ action: 'get_dlp_logs' }, (logs) => {
        if (chrome.runtime.lastError) { console.warn(chrome.runtime.lastError); return; }
        dlpLastLogs = logs || [];
        const tc = document.getElementById('dlp-tc-log');
        if (tc) tc.textContent = dlpLastLogs.length;
        renderDlpLogs(dlpLastLogs);
        renderDlpStatband(dlpLastLogs);
        // The audit log is the only source of detector efficacy — rebuild the
        // hit index whenever it reloads, then repaint the matrix cells.
        buildDlpHitIndex(dlpLastLogs);
        paintDlpHits();
        // Facets reflect what is actually in the log — offering a filter value
        // that matches nothing is a dead end.
        const { tools, sevs } = dlpLogFacets();
        const fill = (id, map, cur) => {
            const el = document.getElementById(id);
            if (!el) return;
            const keys = Object.keys(map).sort((a, b) => map[b] - map[a]);
            el.innerHTML = '<option value="all">All</option>' + keys.map(k =>
                `<option value="${escapeHtml(k)}">${escapeHtml(k)} (${map[k]})</option>`).join('');
            el.value = cur;
        };
        fill('dlp-log-tool', tools, dlpLogFilter.tool);
        fill('dlp-log-sev', sevs, dlpLogFilter.severity);
    });
}


// ══ Activity log: filter-first, paginated ═════════════════════════════
// The log previously rendered every retained event into the DOM in one pass.
// At the 1,000-entry cap that is a large synchronous render with no way to
// narrow the set — and a security log is only useful if you can answer "show me
// blocks on Copilot involving credentials" without scrolling.
const DLP_LOG_PAGE = 50;
let dlpLogFilter = { action: 'all', tool: 'all', severity: 'all', q: '' };
let dlpLogPage = 0;

function filteredDlpLogs() {
    const f = dlpLogFilter;
    const q = (f.q || '').toLowerCase();
    return (dlpLastLogs || []).filter(l => {
        if (f.action !== 'all') {
            const a = l.action || '';
            const isFile = a.indexOf('file') === 0;
            if (f.action === 'file' ? !isFile : a !== f.action) return false;
        }
        if (f.tool !== 'all' && (l.aiTool || '') !== f.tool) return false;
        if (f.severity !== 'all' && (l.maxSeverity || '') !== f.severity) return false;
        if (q) {
            const hay = [
                l.aiTool, l.fileName, l.url,
                (l.classifications || []).join(' '),
                (l.items || []).map(i => i.label).join(' '),
            ].join(' ').toLowerCase();
            if (hay.indexOf(q) === -1) return false;
        }
        return true;
    });
}

function dlpLogFacets() {
    const tools = {}, sevs = {};
    (dlpLastLogs || []).forEach(l => {
        if (l.aiTool) tools[l.aiTool] = (tools[l.aiTool] || 0) + 1;
        if (l.maxSeverity) sevs[l.maxSeverity] = (sevs[l.maxSeverity] || 0) + 1;
    });
    return { tools, sevs };
}

// Chips for what is currently narrowing the view, so an empty result is never
// mysterious — the operator can see exactly which filter caused it.
function renderDlpLogChips() {
    const wrap = document.getElementById('dlp-log-chips');
    if (!wrap) return;
    const f = dlpLogFilter, chips = [];
    if (f.action !== 'all') chips.push(['action', 'Action: ' + f.action]);
    if (f.tool !== 'all') chips.push(['tool', 'Tool: ' + f.tool]);
    if (f.severity !== 'all') chips.push(['severity', 'Severity: ' + f.severity]);
    if (f.q) chips.push(['q', 'Search: "' + f.q + '"']);
    wrap.innerHTML = chips.length
        ? chips.map(([k, label]) =>
            `<button class="dlp-chip" data-clear="${k}">${escapeHtml(label)}
             <span aria-hidden="true">\u2715</span></button>`).join('') +
          '<button class="dlp-chip clear" data-clear="all">Clear all</button>'
        : '';
    wrap.querySelectorAll('[data-clear]').forEach(b => b.addEventListener('click', () => {
        const k = b.getAttribute('data-clear');
        if (k === 'all') dlpLogFilter = { action: 'all', tool: 'all', severity: 'all', q: '' };
        else dlpLogFilter[k] = (k === 'q') ? '' : 'all';
        const si = document.getElementById('dlp-log-search');
        if (si && k !== 'q' ? false : si) si.value = dlpLogFilter.q;
        dlpLogPage = 0;
        renderDlpLogs(dlpLastLogs);
    }));
}

function renderDlpLogPager(total, shown) {
    const el = document.getElementById('dlp-log-pager');
    if (!el) return;
    if (total <= DLP_LOG_PAGE) { el.innerHTML = total ? `<span class="dlp-pginfo">${total.toLocaleString()} event${total === 1 ? '' : 's'}</span>` : ''; return; }
    const pages = Math.ceil(total / DLP_LOG_PAGE);
    const from = dlpLogPage * DLP_LOG_PAGE + 1;
    const to = Math.min(total, from + shown - 1);
    el.innerHTML =
        `<span class="dlp-pginfo">${from.toLocaleString()}\u2013${to.toLocaleString()} of ${total.toLocaleString()}</span>` +
        `<button class="btn sm" id="dlp-pg-prev" ${dlpLogPage === 0 ? 'disabled' : ''}>Previous</button>` +
        `<button class="btn sm" id="dlp-pg-next" ${dlpLogPage >= pages - 1 ? 'disabled' : ''}>Next</button>`;
    const prev = document.getElementById('dlp-pg-prev'), next = document.getElementById('dlp-pg-next');
    if (prev) prev.addEventListener('click', () => { dlpLogPage--; renderDlpLogs(dlpLastLogs); });
    if (next) next.addEventListener('click', () => { dlpLogPage++; renderDlpLogs(dlpLastLogs); });
}

function renderDlpLogs(logs) {
    // Stats
    const statsEl = document.getElementById('dlp-log-stats');
    const masked = logs.filter(l => l.action === 'mask').length;
    const blocked = logs.filter(l => l.action === 'block').length;
    const warned = logs.filter(l => l.action === 'warn').length;
    const files = logs.filter(l => l.source === 'file').length;
    const findings = logs.reduce((a, l) => a + (l.totalFindings || 0), 0);
    statsEl.innerHTML = [
        ['Total Events', logs.length],
        ['🎭 Masked', masked],
        ['⛔ Blocked', blocked],
        ['⚠️ Warned', warned],
        ['📎 Files', files],
        ['Items Redacted', findings],
    ].map(([l, v]) => `<div class="dlp-stat-pill"><div class="v">${v}</div><div class="l">${l}</div></div>`).join('');

    const body = document.getElementById('dlp-logs-body');

    // Filter, then page. Both states are reflected in the UI so an empty table
    // always explains itself.
    renderDlpLogChips();
    const matched = filteredDlpLogs();
    const pages = Math.max(1, Math.ceil(matched.length / DLP_LOG_PAGE));
    if (dlpLogPage > pages - 1) dlpLogPage = pages - 1;
    if (dlpLogPage < 0) dlpLogPage = 0;
    const page = matched.slice(dlpLogPage * DLP_LOG_PAGE, dlpLogPage * DLP_LOG_PAGE + DLP_LOG_PAGE);
    renderDlpLogPager(matched.length, page.length);

    if (!logs.length) {
        body.innerHTML = '<tr><td colspan="5" class="dlp-logempty">No DLP events yet. Sensitive data caught in prompts will appear here.</td></tr>';
        return;
    }
    if (!matched.length) {
        // Distinct from "no events": the data exists, the filter excluded it.
        body.innerHTML = '<tr><td colspan="5" class="dlp-logempty">' +
            'No events match the current filters. <b>' + logs.length.toLocaleString() +
            '</b> event' + (logs.length === 1 ? '' : 's') + ' are retained — clear a filter to widen the view.</td></tr>';
        return;
    }
    logs = page;

    const actionClass = a => (a === 'mask' || a === 'block' || a === 'warn') ? a : (a && a.indexOf('file') === 0 ? 'file' : 'warn');
    body.innerHTML = logs.map(l => {
        const when = new Date(l.ts).toLocaleString();
        const toolColor = TOOL_COLORS[(l.aiTool || '').toLowerCase()] || TOOL_COLORS.default;
        const classes = (l.classifications || []).map(c =>
            `<span class="dlp-class-chip">${(DLP && DLP.CLASSIFICATION_SHORT[c]) || c}</span>`).join('');
        const items = (l.items || []).map(it =>
            `<div style="margin:2px 0;">
                <span class="dlp-sev-badge dlp-sev-${it.severity}">${it.severity}</span>
                <b style="font-size:11.5px;">${escapeHtml((it.label || '').replace(/_/g, ' '))}</b>
                ${it.count > 1 ? `<span style="color:var(--muted);">×${it.count}</span>` : ''}
                <span class="dlp-evi">${escapeHtml(it.evidence || '')}</span>
            </div>`).join('');
        // File events carry the inspection verdict: true type, parts, evasion.
        let fileTag = '';
        if (l.source === 'file') {
            const meta = [];
            if (l.trueType) meta.push(l.trueType);
            if (l.segments > 1) meta.push(l.segments + ' parts');
            if (l.sizeBytes) meta.push(Math.max(1, Math.round(l.sizeBytes / 1024)) + ' KB');
            if (l.truncated) meta.push('partial');
            if (l.sha) meta.push('sha:' + l.sha.slice(0, 8));
            fileTag =
                `<div style="font-size:11px;color:var(--text);font-weight:600;margin-bottom:2px;">📎 ${escapeHtml(l.fileName || 'file')}</div>` +
                (meta.length ? `<div class="dlp-filemeta">${escapeHtml(meta.join(' · '))}</div>` : '') +
                (l.masquerade ? `<div class="dlp-masq">⚠ declared .${escapeHtml(l.declaredExt || '?')} · content is ${escapeHtml(l.trueType || '?')}</div>` : '');
        }
        const riskTag = (typeof l.riskScore === 'number' && l.riskBand)
            ? `<div style="margin-top:4px;"><span class="dlp-risk dlp-risk-${l.riskBand}">RISK ${l.riskScore} · ${l.riskBand}</span></div>` : '';
        const actLabel = (l.action || '').replace('file-', '').toUpperCase();
        return `<tr>
            <td style="font-size:11px;color:var(--muted);white-space:nowrap;">${when}</td>
            <td><span style="color:${toolColor};font-weight:600;font-size:11px;">${escapeHtml(l.aiTool || '')}</span></td>
            <td><span class="dlp-action-badge dlp-action-${actionClass(l.action)}">${actLabel}</span></td>
            <td>${classes}</td>
            <td>${fileTag}${riskTag}${items}</td>
        </tr>`;
    }).join('');
}

function clearDlpLogs() {
    if (!confirm('Clear all DLP audit logs? This cannot be undone.')) return;
    chrome.runtime.sendMessage({ action: 'clear_dlp_logs' }, () => loadDlpLogs());
}

// ═════════════════════════════════════════════════════════════════════════
// LOG FORWARDING — SIEM webhook profiles
// ═════════════════════════════════════════════════════════════════════════

const SIEM = window.PromptrixSIEM || null;
let fwdProfiles = [];
let fwdEditing = null;          // working copy of the profile being edited

function initFwd() {
    if (!SIEM) return;
    const on = (id, ev, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(ev, fn); };

    // Populate the static selects once.
    fillSelect('fwd-format', SIEM.FORMATS.map(f => [f.id, f.label]));
    fillSelect('fwd-auth-type', SIEM.AUTH_TYPES.map(a => [a.id, a.label]));
    fillSelect('fwd-minsev', SIEM.SEVERITIES.map(s => [s, s.charAt(0) + s.slice(1).toLowerCase() + ' and above']));
    fillSelect('fwd-content', SIEM.CONTENT_MODES.map(c => [c.id, c.label]));
    renderFwdEvents();
    renderFwdTemplateTokens();

    on('fwd-add', 'click', () => openFwdEditor(SIEM.defaultProfile(), true));
    on('fwd-back', 'click', () => showFwdList());
    on('fwd-save', 'click', saveFwdProfile);
    on('fwd-delete', 'click', deleteFwdProfile);
    on('fwd-test', 'click', testFwdProfile);
    on('fwd-preview', 'click', previewFwdPayload);
    on('fwd-flush', 'click', flushFwdQueue);
    on('fwd-add-header', 'click', () => { collectFwdEditor(); fwdEditing.headers.push({ name: '', value: '' }); renderFwdHeaders(); });
    on('fwd-enabled', 'click', function () { this.classList.toggle('on'); });
    on('fwd-format', 'change', function () {
        const f = SIEM.FORMATS.find(x => x.id === this.value);
        setText('fwd-format-hint', f ? f.hint : '');
        const show = (id, on, disp) => { const el = document.getElementById(id); if (el) el.style.display = on ? (disp || 'grid') : 'none'; };
        show('fwd-splunk-fields', this.value === 'splunk');
        show('fwd-coralogix-fields', this.value === 'coralogix');
        show('fwd-template-fields', this.value === 'template', 'block');
    });
    on('fwd-auth-type', 'change', function () {
        const a = SIEM.AUTH_TYPES.find(x => x.id === this.value);
        setText('fwd-auth-hint', a ? a.hint : '');
        renderFwdAuthFields(this.value);
    });
    on('fwd-content', 'change', function () {
        const c = SIEM.CONTENT_MODES.find(x => x.id === this.value);
        setText('fwd-content-hint', c ? c.hint : '');
    });

    loadFwdProfiles();
}

function fillSelect(id, pairs) {
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = pairs.map(([v, l]) => `<option value="${v}">${escapeHtml(l)}</option>`).join('');
}
function setText(id, t) { const el = document.getElementById(id); if (el) el.textContent = t; }

// ── List view ──
function loadFwdProfiles() {
    chrome.runtime.sendMessage({ action: 'get_siem_profiles' }, (resp) => {
        if (chrome.runtime.lastError) return;
        fwdProfiles = (resp && resp.profiles) || [];
        renderFwdCards();
    });
}

function renderFwdCards() {
    const wrap = document.getElementById('fwd-cards');
    if (!wrap) return;
    const badge = document.getElementById('dlp-tc-fwd');
    if (badge) badge.textContent = fwdProfiles.filter(p => p.enabled && p.url).length;

    const queued = fwdProfiles.reduce((a, p) => a + (p._queued || 0), 0);
    setText('fwd-summary', fwdProfiles.length
        ? `${fwdProfiles.length} forwarder${fwdProfiles.length > 1 ? 's' : ''} · ${queued} event${queued === 1 ? '' : 's'} queued`
        : '');

    if (!fwdProfiles.length) {
        wrap.innerHTML = '<div class="fwd-empty">No forwarders configured. Add one to stream DLP events to your SIEM.</div>';
        return;
    }
    wrap.innerHTML = fwdProfiles.map((p, i) => {
        const fmt = (SIEM.FORMATS.find(f => f.id === p.format) || {}).label || p.format;
        const auth = (SIEM.AUTH_TYPES.find(a => a.id === p.auth.type) || {}).label || p.auth.type;
        const evOn = Object.keys(p.events).filter(k => p.events[k]).length;
        const h = p._health;
        let hs = '<span class="hs fwd-idle"><span class="fwd-dot" style="background:#8888a0"></span> Not yet delivered</span>';
        let sub = 'No delivery attempted';
        if (h && h.lastSuccess && !h.consecutiveFailures) {
            hs = '<span class="hs fwd-ok"><span class="fwd-dot" style="background:#4ade80"></span> Healthy</span>';
            sub = `${h.ok || 0} sent · last ${fwdAgo(h.lastSuccess)}`;
        } else if (h && h.consecutiveFailures) {
            hs = `<span class="hs fwd-bad"><span class="fwd-dot" style="background:#f87171"></span> Failing (${h.consecutiveFailures})</span>`;
            sub = escapeHtml(String(h.lastError || '').slice(0, 60));
        }
        return `<div class="fwd-card${p.enabled ? '' : ' off'}" data-idx="${i}">
            <div>
                <div class="fwd-cname">
                    <span class="fwd-dot" style="background:${p.enabled ? '#4ade80' : '#8888a0'}"></span>
                    ${escapeHtml(p.name)}
                </div>
                <div class="fwd-curl">${escapeHtml(p.url || '(no endpoint set)')}</div>
                <div class="fwd-cmeta">
                    <span class="fwd-pill fmt">${escapeHtml(fmt)}</span>
                    <span class="fwd-pill ${p.auth.type === 'none' ? 'noauth' : 'auth'}">${escapeHtml(auth)}</span>
                    <span class="fwd-pill">${evOn} event type${evOn === 1 ? '' : 's'}</span>
                    <span class="fwd-pill">≥ ${escapeHtml(p.minSeverity)}</span>
                    ${p.content === 'full' ? '<span class="fwd-pill full">FULL CONTENT</span>' : ''}
                    ${p._queued ? `<span class="fwd-pill">${p._queued} queued</span>` : ''}
                </div>
            </div>
            <div class="fwd-health">${hs}<div>${sub}</div></div>
        </div>`;
    }).join('');
    wrap.querySelectorAll('.fwd-card').forEach(c => {
        c.addEventListener('click', () => openFwdEditor(fwdProfiles[Number(c.dataset.idx)], false));
    });
}

function showFwdList() {
    const l = document.getElementById('fwd-list-view'), e = document.getElementById('fwd-edit-view');
    if (!l || !e) return;
    l.style.display = '';
    e.style.display = 'none';
    fwdEditing = null;
    loadFwdProfiles();
}

// ── Editor ──
function openFwdEditor(profile, isNew) {
    fwdEditing = SIEM.normalizeProfile(JSON.parse(JSON.stringify(profile)));
    fwdEditing._isNew = !!isNew;
    document.getElementById('fwd-list-view').style.display = 'none';
    document.getElementById('fwd-edit-view').style.display = '';
    setText('fwd-edit-title', isNew ? 'New forwarder' : fwdEditing.name);
    document.getElementById('fwd-delete').style.display = isNew ? 'none' : '';
    document.getElementById('fwd-preview-box').style.display = 'none';

    const v = (id, val) => { const el = document.getElementById(id); if (el) el.value = val; };
    v('fwd-name', fwdEditing.name);
    v('fwd-url', fwdEditing.url);
    v('fwd-method', fwdEditing.method);
    v('fwd-format', fwdEditing.format);
    v('fwd-auth-type', fwdEditing.auth.type);
    v('fwd-minsev', fwdEditing.minSeverity);
    v('fwd-content', fwdEditing.content);
    v('fwd-batch', fwdEditing.batchSize);
    v('fwd-flushsec', fwdEditing.flushSeconds);
    v('fwd-retries', fwdEditing.maxRetries);
    v('fwd-timeout', fwdEditing.timeoutMs);
    v('fwd-splunk-index', fwdEditing.splunk.index);
    v('fwd-splunk-sourcetype', fwdEditing.splunk.sourcetype);
    v('fwd-splunk-source', fwdEditing.splunk.source);
    v('fwd-cx-app', fwdEditing.coralogix.applicationName);
    v('fwd-cx-sub', fwdEditing.coralogix.subsystemName);
    v('fwd-cx-host', fwdEditing.coralogix.computerName);
    v('fwd-tpl-ct', fwdEditing.templateContentType);
    v('fwd-tpl-body', fwdEditing.bodyTemplate);
    document.getElementById('fwd-enabled').classList.toggle('on', fwdEditing.enabled);
    document.getElementById('fwd-format').dispatchEvent(new Event('change'));
    document.getElementById('fwd-auth-type').dispatchEvent(new Event('change'));
    document.getElementById('fwd-content').dispatchEvent(new Event('change'));
    renderFwdHeaders();
    syncFwdEventBoxes();
}

// Auth fields vary by method — render only what the chosen method needs.
const FWD_AUTH_FIELDS = {
    none: [],
    bearer: [['token', 'Token', 'password', 'span 2']],
    header: [['headerName', 'Header name', 'text', ''], ['headerValue', 'Header value', 'password', 'span 2']],
    basic: [['username', 'Username', 'text', ''], ['password', 'Password', 'password', '']],
    hmac: [['secret', 'Shared secret', 'password', 'span 2'], ['signatureHeader', 'Signature header', 'text', '']],
    query: [['paramName', 'Parameter name', 'text', ''], ['paramValue', 'Parameter value', 'password', 'span 2']],
};
function renderFwdAuthFields(type) {
    const wrap = document.getElementById('fwd-auth-fields');
    if (!wrap) return;
    const fields = FWD_AUTH_FIELDS[type] || [];
    wrap.innerHTML = fields.map(([key, label, kind, span]) =>
        `<div class="form-group"${span ? ` style="grid-column:${span};"` : ''}>
            <label>${escapeHtml(label)}</label>
            <input type="${kind}" data-auth="${key}" value="${escapeHtmlAttr(String((fwdEditing && fwdEditing.auth[key]) || ''))}" autocomplete="off">
         </div>`).join('');
    wrap.style.display = fields.length ? 'grid' : 'none';
}

function renderFwdHeaders() {
    const wrap = document.getElementById('fwd-headers');
    if (!wrap || !fwdEditing) return;
    if (!fwdEditing.headers.length) {
        wrap.innerHTML = '<div class="dlp-hint" style="margin:0;">No custom headers.</div>';
        return;
    }
    wrap.innerHTML = fwdEditing.headers.map((h, i) =>
        `<div class="fwd-hdrrow">
            <input type="text" data-hdr="name" data-i="${i}" placeholder="X-Header-Name" value="${escapeHtmlAttr(h.name || '')}">
            <input type="text" data-hdr="value" data-i="${i}" placeholder="value" value="${escapeHtmlAttr(h.value || '')}">
            <button class="fwd-hdrdel" data-del="${i}">Remove</button>
         </div>`).join('');
    wrap.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', () => {
        collectFwdEditor();
        fwdEditing.headers.splice(Number(b.dataset.del), 1);
        renderFwdHeaders();
    }));
}

// Clickable placeholder palette for the FortiGate-style body template.
const FWD_TOKENS = ['type','ts','severity','outcome','aiTool','url','findingCount','detections',
    'classifications','risk.score','risk.band','file.name','file.trueType','file.sha256','content','json'];
function renderFwdTemplateTokens() {
    const wrap = document.getElementById('fwd-tpl-tokens');
    if (!wrap) return;
    wrap.innerHTML = FWD_TOKENS.map(t => `<span class="fwd-token" data-tok="${t}">%%${t}%%</span>`).join('');
    wrap.querySelectorAll('[data-tok]').forEach(el => {
        el.title = 'Insert at the cursor';
        el.addEventListener('click', () => {
            const ta = document.getElementById('fwd-tpl-body');
            if (!ta) return;
            const tok = `%%${el.dataset.tok}%%`;
            const a = ta.selectionStart ?? ta.value.length, b = ta.selectionEnd ?? a;
            ta.value = ta.value.slice(0, a) + tok + ta.value.slice(b);
            ta.focus();
            ta.selectionStart = ta.selectionEnd = a + tok.length;
        });
    });
}

function renderFwdEvents() {
    const wrap = document.getElementById('fwd-events');
    if (!wrap) return;
    const groups = {};
    SIEM.EVENT_TYPES.forEach(t => (groups[t.group] = groups[t.group] || []).push(t));
    wrap.innerHTML = Object.keys(groups).map(g =>
        `<div class="fwd-evgroup"><h5>${escapeHtml(g)}</h5>` +
        groups[g].map(t =>
            `<div class="fwd-ev" data-ev="${t.id}">
                <div class="fwd-cb" data-cb="${t.id}">✓</div>
                <div><div class="el">${escapeHtml(t.label)}</div><div class="ed">${escapeHtml(t.desc)}</div></div>
             </div>`).join('') + '</div>').join('');
    wrap.querySelectorAll('.fwd-ev').forEach(row => {
        row.addEventListener('click', () => {
            const cb = row.querySelector('.fwd-cb');
            cb.classList.toggle('on');
        });
    });
}
function syncFwdEventBoxes() {
    document.querySelectorAll('#fwd-events .fwd-cb').forEach(cb => {
        cb.classList.toggle('on', !!(fwdEditing && fwdEditing.events[cb.dataset.cb]));
    });
}

// Read the DOM back into the working profile.
function collectFwdEditor() {
    if (!fwdEditing) return null;
    const g = id => (document.getElementById(id) || {}).value;
    fwdEditing.name = g('fwd-name') || 'Unnamed forwarder';
    fwdEditing.url = (g('fwd-url') || '').trim();
    fwdEditing.method = g('fwd-method');
    fwdEditing.format = g('fwd-format');
    fwdEditing.enabled = document.getElementById('fwd-enabled').classList.contains('on');
    fwdEditing.minSeverity = g('fwd-minsev');
    fwdEditing.content = g('fwd-content');
    fwdEditing.batchSize = Number(g('fwd-batch')) || 20;
    fwdEditing.flushSeconds = Number(g('fwd-flushsec')) || 60;
    fwdEditing.maxRetries = Number(g('fwd-retries'));
    fwdEditing.timeoutMs = Number(g('fwd-timeout')) || 10000;
    fwdEditing.splunk = { index: g('fwd-splunk-index') || '', sourcetype: g('fwd-splunk-sourcetype') || 'promptrix:dlp', source: g('fwd-splunk-source') || 'promptrix' };
    fwdEditing.coralogix = { applicationName: g('fwd-cx-app') || 'promptrix', subsystemName: g('fwd-cx-sub') || 'dlp', computerName: g('fwd-cx-host') || 'browser-extension' };
    fwdEditing.templateContentType = g('fwd-tpl-ct') || 'application/json';
    fwdEditing.bodyTemplate = g('fwd-tpl-body') || '';
    fwdEditing.auth.type = g('fwd-auth-type');
    document.querySelectorAll('#fwd-auth-fields [data-auth]').forEach(i => { fwdEditing.auth[i.dataset.auth] = i.value; });
    const hdrs = [];
    document.querySelectorAll('#fwd-headers [data-hdr="name"]').forEach(n => {
        const i = n.dataset.i;
        const val = document.querySelector(`#fwd-headers [data-hdr="value"][data-i="${i}"]`);
        hdrs.push({ name: n.value, value: val ? val.value : '' });
    });
    fwdEditing.headers = hdrs.filter(h => h.name.trim());
    document.querySelectorAll('#fwd-events .fwd-cb').forEach(cb => {
        fwdEditing.events[cb.dataset.cb] = cb.classList.contains('on');
    });
    return fwdEditing;
}

function fwdStatus(html, ms) {
    const el = document.getElementById('fwd-status');
    if (!el) return;
    el.style.display = 'block';
    el.innerHTML = html;
    if (ms) setTimeout(() => { el.style.display = 'none'; }, ms);
}

// Arbitrary endpoints need a host grant. Ask on the user gesture (save/test).
// ── Host access ───────────────────────────────────────────────────────
// Chrome match patterns are <scheme>://<host>/<path> and the host may NOT
// carry a port: new URL(u).origin returns "http://localhost:8787", so the
// pattern "http://localhost:8787/*" was rejected outright as invalid. Every
// collector on a non-443 port (Splunk HEC :8088, any self-hosted receiver)
// could therefore never be granted.
function hostPattern(url) {
    let u;
    try { u = new URL(url); } catch (e) { return null; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.protocol + '//' + u.hostname + '/*';   // hostname, not host: no port
}

// Resolves { ok, reason, detail, pattern } — never rejects, never hangs.
//
// chrome.permissions.request() must be invoked synchronously inside the user
// gesture that triggered it. The previous version called permissions.contains()
// first, and that async callback ended the gesture, so request() threw
// "This function must be called during a user gesture" from inside a callback
// — where nothing caught it. The promise then never settled and the UI sat on
// "Sending test event…" forever with no error. request() is idempotent and
// resolves without prompting when the permission is already held, so calling it
// first is both correct and simpler.
function ensureHostAccess(url) {
    return new Promise(resolve => {
        const pattern = hostPattern(url);
        if (!pattern) { resolve({ ok: false, reason: 'bad-url' }); return; }
        if (!chrome.permissions) { resolve({ ok: true }); return; }
        try {
            chrome.permissions.request({ origins: [pattern] }, granted => {
                const err = chrome.runtime.lastError;
                if (err) { resolve({ ok: false, reason: 'error', detail: err.message, pattern }); return; }
                resolve(granted ? { ok: true, pattern } : { ok: false, reason: 'denied', pattern });
            });
        } catch (e) {
            // Synchronous throw: the gesture was already spent (or the pattern
            // was rejected). Fall back to contains() — if the permission is
            // already held we need no prompt at all, and reporting "click again"
            // when access actually works would be a false negative.
            try {
                chrome.permissions.contains({ origins: [pattern] }, has => {
                    if (chrome.runtime.lastError) { resolve({ ok: false, reason: 'error', detail: chrome.runtime.lastError.message, pattern }); return; }
                    resolve(has ? { ok: true, pattern }
                                : { ok: false, reason: 'gesture', detail: e && e.message, pattern });
                });
            } catch (e2) {
                resolve({ ok: false, reason: 'error', detail: (e2 && e2.message) || (e && e.message), pattern });
            }
        }
    });
}

// Human-readable, actionable explanation for a failed grant.
function hostAccessError(r) {
    if (r.reason === 'bad-url') return 'That endpoint is not a valid http(s) URL.';
    if (r.reason === 'denied') return 'Permission for <b>' + escapeHtml(r.pattern) + '</b> was declined. Chrome must allow the extension to reach that host before it can deliver.';
    if (r.reason === 'gesture') return 'Chrome refused the permission prompt: ' + escapeHtml(r.detail || '') + ' — click the button again.';
    return 'Could not obtain host permission: ' + escapeHtml(r.detail || 'unknown error');
}

async function saveFwdProfile() {
    const p = collectFwdEditor();
    if (!p) return;
    if (!p.url) { fwdStatus('<span class="dot red"></span> Enter an endpoint URL.', 4000); return; }
    if (p.enabled) {
        const grant = await ensureHostAccess(p.url);
        if (!grant.ok) {
            fwdStatus('<span class="dot red"></span> Saved, but it cannot deliver yet. ' + hostAccessError(grant), 9000);
        }
    }
    const idx = fwdProfiles.findIndex(x => x.id === p.id);
    const list = fwdProfiles.slice();
    if (idx === -1) list.push(p); else list[idx] = p;
    chrome.runtime.sendMessage({ action: 'save_siem_profiles', profiles: list.map(stripRuntime) }, () => {
        fwdStatus('<span class="dot green"></span> Forwarder saved.', 3000);
        fwdProfiles = list;
        setText('fwd-edit-title', p.name);
        fwdEditing._isNew = false;
        renderFwdCards();
    });
}
// Compact relative time for forwarder health lines.
function fwdAgo(ms) {
    if (!ms) return 'never';
    const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
}

function stripRuntime(p) { const c = Object.assign({}, p); delete c._health; delete c._queued; delete c._isNew; return c; }

function deleteFwdProfile() {
    if (!fwdEditing) return;
    if (!confirm(`Delete forwarder "${fwdEditing.name}"? Queued events for it are discarded.`)) return;
    const list = fwdProfiles.filter(x => x.id !== fwdEditing.id).map(stripRuntime);
    chrome.runtime.sendMessage({ action: 'save_siem_profiles', profiles: list }, () => {
        fwdProfiles = list;
        showFwdList();
    });
}

async function testFwdProfile() {
    const p = collectFwdEditor();
    if (!p || !p.url) { fwdStatus('<span class="dot red"></span> Enter an endpoint URL first.', 4000); return; }
    const grant = await ensureHostAccess(p.url);
    if (!grant.ok) { fwdStatus('<span class="dot red"></span> ' + hostAccessError(grant), 9000); return; }
    fwdStatus('<span class="dot yellow"></span> Sending test event…');
    chrome.runtime.sendMessage({ action: 'test_siem_profile', profile: stripRuntime(p) }, (r) => {
        if (chrome.runtime.lastError) { fwdStatus('<span class="dot red"></span> ' + chrome.runtime.lastError.message, 8000); return; }
        fwdStatus(r && r.success
            ? `<span class="dot green"></span> Delivered — HTTP ${r.status} in ${r.ms} ms. Check your collector for a <b>dlp.block</b> test event.`
            : `<span class="dot red"></span> Failed: ${escapeHtml((r && r.error) || 'no response')}`, 9000);
    });
}

function previewFwdPayload() {
    const p = collectFwdEditor();
    if (!p) return;
    chrome.runtime.sendMessage({ action: 'preview_siem_payload', profile: stripRuntime(p) }, (r) => {
        if (chrome.runtime.lastError || !r || r.error) return;
        const box = document.getElementById('fwd-preview-box');
        const out = document.getElementById('fwd-preview-out');
        const hdrs = Object.keys(r.headers).map(k => `${k}: ${r.headers[k]}`).join('\n');
        out.textContent = `${r.method} ${r.url}\n${hdrs}\n\n${r.body}`;
        box.style.display = 'block';
        box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
}

function flushFwdQueue() {
    chrome.runtime.sendMessage({ action: 'flush_siem' }, (r) => {
        if (chrome.runtime.lastError) return;
        loadFwdProfiles();
    });
}
