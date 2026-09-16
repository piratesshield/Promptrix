
// Content Script - Promptrix v7.1
// Features: WebNav URL Tracking, Robust Paste, Auto-Capture (Prompts + Responses)

console.log('[Promptrix] Content Script Active');

// --- STATE ---
let inputBuffer = '';
let pendingPrompt = null; 
let isComposing = false;
let suggestionBox = null;
let safetyTimer = null;
let currentUrl = window.location.href;

// Response tracking
let lastCapturedResponseId = '';
let responseCheckTimer = null;
let lastKnownResponseCount = 0;

const getToolName = () => {
    const host = window.location.hostname;
    if (host.includes('openai') || host.includes('chatgpt')) return 'ChatGPT';
    if (host.includes('google') || host.includes('gemini')) return 'Gemini';
    if (host.includes('claude') || host.includes('anthropic')) return 'Claude';
    if (host.includes('perplexity')) return 'Perplexity';
    if (host.includes('microsoft') || host.includes('copilot') || host.includes('bing')) return 'Copilot';
    return 'Unknown AI';
};

const TOOL_NAME = getToolName();

// --- TOOL-SPECIFIC RESPONSE SELECTORS ---
// Each AI tool renders responses in different DOM structures.
// These selectors target the actual response message containers.

const RESPONSE_SELECTORS = {
    'ChatGPT': {
        // ChatGPT wraps each assistant message in a div with data-message-author-role="assistant"
        messageContainer: '[data-message-author-role="assistant"]',
        contentSelector: '.markdown, .whitespace-pre-wrap',
        // The chat turn list
        turnList: '[class*="react-scroll"]',
        // Streaming indicator
        streamingIndicator: '.result-streaming, [class*="streaming"]',
    },
    'Gemini': {
        // Gemini uses message-content inside model-response
        messageContainer: 'model-response, .model-response-text, .response-container-content',
        contentSelector: '.markdown, .model-response-text, message-content',
        turnList: '.conversation-container',
        streamingIndicator: '.loading, .generating',
    },
    'Claude': {
        // Claude uses data-is-streaming and font-claude-message
        messageContainer: '[data-is-streaming], .font-claude-message, [class*="AssistantMessage"]',
        contentSelector: '.font-claude-message, [class*="markdown"], [class*="AssistantMessage"]',
        turnList: '.flex.flex-col',
        streamingIndicator: '[data-is-streaming="true"]',
    },
    'Perplexity': {
        // Perplexity wraps answers in specific containers
        messageContainer: '[class*="AnswerContainer"], [class*="prose"], .break-words',
        contentSelector: '[class*="prose"], .break-words, .markdown-body',
        turnList: '.flex.flex-col',
        streamingIndicator: '[class*="animate"]',
    },
    'Copilot': {
        // Copilot / Bing Chat
        messageContainer: '[class*="response-message"], cib-message[type="bot"], .ac-container',
        contentSelector: '.ac-textBlock, [class*="response-text"]',
        turnList: '.scroller',
        streamingIndicator: '[class*="typing"]',
    }
};

// Fallback generic selectors for unknown AI tools
const GENERIC_SELECTORS = {
    messageContainer: '[class*="response"], [class*="answer"], [class*="assistant"], [class*="message"][class*="bot"]',
    contentSelector: '.markdown, .prose, [class*="markdown"]',
    streamingIndicator: '[class*="streaming"], [class*="loading"], [class*="typing"], [class*="generating"]',
};


// --- 1. URL TRACKING (Secure Method) ---

// Listen for updates from Background script (WebNavigation API)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'url_changed') {
        currentUrl = request.url;
        // Update pending prompt if waiting
        if (pendingPrompt) {
            pendingPrompt.sessionUrl = currentUrl;
        }
    }
});

// Fallback: Poll for URL changes (handles cases where WebNav might miss internal state)
setInterval(() => {
    if (document.hidden) return;
    if (window.location.href !== currentUrl) {
        currentUrl = window.location.href;
        if (pendingPrompt) pendingPrompt.sessionUrl = currentUrl;
    }
}, 2000);


// --- 1b. DLP GATE (Data-Loss Prevention) ---
// Scans the prompt before it leaves the page. Depending on policy it masks
// PII/secrets in place, blocks the send, and/or shows a warning banner.
// The engine (window.PromptrixDLP) is injected by the manifest before this file.

let DLP = (typeof window !== 'undefined' && window.PromptrixDLP) ? window.PromptrixDLP : null;
let dlpPolicy = DLP ? DLP.defaultPolicy() : null;
let dlpEngineWarned = false;

// The detection engine is injected by a SIBLING content script. If that script
// had not finished evaluating when this one ran — or threw — DLP was captured as
// null and stayed null for the entire life of the page: the submit gate's first
// line short-circuited, no banner appeared, and the prompt went to the provider
// completely unprotected. A reload "fixed" it, which is exactly the intermittent
// behaviour reported. Re-resolve on every use so it recovers as soon as the
// engine is present.
function dlpEngine() {
    if (!DLP && typeof window !== 'undefined' && window.PromptrixDLP) {
        DLP = window.PromptrixDLP;
        if (!dlpPolicy) { dlpPolicy = DLP.defaultPolicy(); loadDlpPolicy(); }
    }
    return DLP;
}

// Protection is off and we could not scan. Say so loudly — silently allowing a
// prompt through is the one outcome a DLP tool must never produce.
function warnEngineUnavailable() {
    if (dlpEngineWarned) return;
    dlpEngineWarned = true;
    try {
        pbxInjectStyles();
        const box = document.createElement('div');
        box.id = 'promptrix-dlp-banner';
        box.style.cssText = 'position:fixed;z-index:2147483647;box-sizing:border-box;background:#2a1215;' +
            'border:1px solid #ef4444;border-left:4px solid #ef4444;border-radius:12px;' +
            'box-shadow:0 14px 44px rgba(0,0,0,.6);color:#f3f4f6;padding:13px 15px;' +
            'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;';
        box.appendChild(pbxBrandHeader('#ef4444', '\u26A0\uFE0F', 'DLP protection is NOT active'));
        const m = document.createElement('div');
        m.style.cssText = 'font-size:12.5px;line-height:1.55;color:#e5e7eb;';
        m.innerHTML = 'The detection engine did not load on this page, so nothing was scanned. ' +
            '<b>Reload the tab</b> before sending sensitive data.';
        box.appendChild(m);
        document.body.appendChild(box);
        dlpBanner = box;
        pbxTrackAnchor(box, findEditableElement(null));
        const c = box.querySelector('#pbx-dlp-close');
        if (c) c.onclick = removeDlpBanner;
    } catch (e) {}
}

function loadDlpPolicy() {
    if (!DLP) return;
    try {
        chrome.storage.local.get([DLP.STORAGE_KEYS.policy], (res) => {
            if (chrome.runtime.lastError) return;
            const saved = res[DLP.STORAGE_KEYS.policy];
            if (!saved) {
                // First run: persist the default-ON policy so the dashboard shows it.
                dlpPolicy = DLP.defaultPolicy();
                chrome.storage.local.set({ [DLP.STORAGE_KEYS.policy]: dlpPolicy });
            } else {
                dlpPolicy = DLP.normalizePolicy(saved);
            }
        });
    } catch (e) {}
}
loadDlpPolicy();

// Keep in sync with changes made in the dashboard settings.
try {
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && DLP && changes[DLP.STORAGE_KEYS.policy]) {
            dlpPolicy = DLP.normalizePolicy(changes[DLP.STORAGE_KEYS.policy].newValue);
        }
    });
} catch (e) {}

// ── Identifying the composer's SEND control ───────────────────────────
// This must be exact. Treating any icon button as "send" made us veto the
// paperclip, the model picker and the sidebar toggle — a stopImmediatePropagation
// in the capture phase cancels the host app's own handler, so the file dialog
// never opened. Never classify by "contains an <svg>".
const SEND_SELECTORS = [
    '[data-testid="send-button"]',
    '[data-testid="fruitjuice-send-button"]',
    'button[aria-label="Send message"]',
    'button[aria-label="Send Message"]',
    'button[aria-label*="send message" i]',
    'button[aria-label*="send prompt" i]',
    'button[type="submit"]',
];
// Controls that must NEVER be mistaken for send, whatever else matches.
const NOT_SEND = /attach|upload|file|image|photo|picture|camera|screenshot|mic|voice|audio|record|dictate|model|menu|setting|option|profile|account|sidebar|new chat|history|copy|edit|delete|remove|close|dismiss|cancel|stop|regenerate|retry|share|export|thumb|like|feedback|scroll|expand|collapse|search|tool|plugin|canvas|artifact/i;

function isSendControl(btn) {
    if (!btn || btn.disabled) return false;
    const label = (btn.getAttribute('aria-label') || btn.getAttribute('title') ||
                   btn.getAttribute('data-testid') || '').toLowerCase();
    // An excluded control is never send, even if it also says "submit".
    if (NOT_SEND.test(label)) return false;
    for (const sel of SEND_SELECTORS) {
        try { if (btn.matches(sel)) return true; } catch (e) {}
    }
    if (/\bsend\b|\bsubmit\b/.test(label)) return true;
    // Bare arrow glyph composers (textContent, not innerText — no layout).
    const t = (btn.textContent || '').trim();
    return t === '\u2191' || t === '\u27a4' || t === '\u2192';
}

function getEditableText(el) {
    if (!el) return '';
    return el.value || el.innerText || el.textContent || '';
}

// Controls that look editable but are not the prompt composer. Writing masked
// text into one of these silently clobbered the user's sidebar search box.
// Fields that are definitely NOT the prompt composer. These must be SPECIFIC
// phrases: a bare /search/ rejected Perplexity's own composer ("Search or ask
// anything") — it is a search product — so the gate could not find the input,
// could not mask it, and fell through to a misleading block banner.
const NOT_COMPOSER = /search\s+(your\s+|the\s+|all\s+)?(chats?|history|conversations?|threads?|messages?|files?|spaces?|prompts?|library|docs?|documents?)|filter|rename|sign ?in|log ?in|e-?mail address|your name|card number|coupon|promo code/i;

function isComposer(el, trusted) {
    if (!el) return false;
    const tag = el.tagName;
    if (tag !== 'TEXTAREA' && tag !== 'INPUT' && !el.isContentEditable) return false;
    if (tag === 'INPUT' && !/^(text|search|)$/i.test(el.type || '')) return false;
    // A password field is never a prompt composer, however it is labelled.
    if (tag === 'INPUT' && /^password$/i.test(el.type || '')) return false;
    // `trusted` means this is the focused element — the user is literally typing
    // into it, which outranks any label heuristic. Only guesses get screened.
    if (!trusted) {
        const hint = ((el.getAttribute('aria-label') || '') + ' ' + (el.getAttribute('placeholder') || '') +
                      ' ' + (el.getAttribute('name') || '') + ' ' + (el.id || '')).toLowerCase();
        if (NOT_COMPOSER.test(hint)) return false;
    }
    if (el.offsetParent === null && tag !== 'TEXTAREA' && !el.isContentEditable) return false;
    return true;
}

function findEditableElement(fallbackTarget) {
    // Focused element first, then the event target's editable ancestor.
    const active = document.activeElement;
    if (isComposer(active, true)) return active;          // focused => trusted
    if (fallbackTarget && fallbackTarget.closest) {
        const near = fallbackTarget.closest('textarea, input, [contenteditable="true"]');
        if (isComposer(near, true)) return near;           // event target => trusted
    }
    // Known composer for THIS site. Not a blind page-wide guess — these are
    // selectors specific to the app we are on, which is what makes it safe.
    const a = adapter();
    if (a && a.composer) {
        for (let i = 0; i < a.composer.length; i++) {
            let el;
            try { el = document.querySelector(a.composer[i]); } catch (e) { continue; }
            if (el && isComposer(el, true)) return el;
        }
    }
    // Still nothing: refuse to guess. Writing into an unidentified field is how
    // masked text once landed in a sidebar search box.
    return null;
}

// Returns true if the submission may proceed, false if the DLP gate intercepted it.
function dlpGate(text, editableElement) {
    const eng = dlpEngine();
    if (!eng || !dlpPolicy) { warnEngineUnavailable(); return false; }  // fail CLOSED

    const res = eng.sanitize(text, dlpPolicy);
    if (res.action === 'allow' || res.findings.length === 0) return true;

    // Audit every intervention (redacted evidence only).
    logDlpEvent(res);

    if (res.action === 'block') {
        showDlpBanner('block', res, editableElement); // block banner always shows (explains the stop)
        return false; // hard stop — user must remove the sensitive data
    }

    if (res.action === 'warn') {
        // Detected type(s) with warn ON but mask/block OFF: warn, send original.
        showDlpBanner('warn', res, editableElement);
        return true;
    }

    // action === 'mask': rewrite the composer with the sanitized (X-masked)
    // text, stop the original submit, then auto-send the sanitized prompt.
    if (!editableElement) {
        // We could not identify the composer, so we cannot rewrite it. Fail
        // closed and say so plainly — silently stopping the send with no
        // explanation and no edit would strand the user.
        showDlpBanner('holdback', res, null);
        return false;
    }
    try { simulateReplacement(editableElement, res.sanitized); } catch (e) {}
    inputBuffer = res.sanitized;
    suppressedText = res.sanitized;
    autoSendMaskedPrompt(editableElement);
    if (res.warn) showDlpBanner('mask', res, editableElement); // only the per-type warn switch gates this
    return false;
}

function logDlpEvent(res) {
    try {
        const entry = dlpEngine().buildLogEntry(res, { aiTool: TOOL_NAME, url: currentUrl });
        chrome.runtime.sendMessage({ action: 'dlp_log', entry }, () => { void chrome.runtime.lastError; });
    } catch (e) {}
}

// Locate the composer's send button so a masked prompt can be submitted
// automatically. Tool-specific selectors first, then generic fallbacks.
function findSendButton(el) {
    // Prefer a send control inside the composer's own form/container so we can
    // never activate a lookalike elsewhere on the page.
    const scopes = [];
    if (el && el.closest) { const f = el.closest('form'); if (f) scopes.push(f); }
    scopes.push(document);
    const a = adapter();
    const selectors = (a && a.send) ? a.send.concat(SEND_SELECTORS) : SEND_SELECTORS;
    for (const scope of scopes) {
        for (const sel of selectors) {
            let list;
            try { list = scope.querySelectorAll(sel); } catch (e) { continue; }
            for (const b of list) {
                if (b && !b.disabled && b.offsetParent !== null && isSendControl(b)) return b;
            }
        }
    }
    return null;
}

// After masking, let the site's framework register the new value (and enable
// its send button), then click it. The masked text scans clean, so the DLP
// gate lets this programmatic submit through. Fail-safe: if no send button is
// found, the masked text simply stays in the composer for the user to send.
// Auto-send after masking. The composer is RE-READ AND RE-SCANNED immediately
// before the click, because a write can silently fail or be reverted: React
// controlled inputs re-render from state, ProseMirror/Lexical reject foreign DOM
// mutations, and simulateReplacement() reported nothing either way while the
// caller swallowed errors in an empty catch. The result was that we pressed Send
// on a composer still holding the raw secret — the prompt reached the provider
// unmasked. Verify at the moment of sending, which is the only instant that
// actually matters.
function autoSendMaskedPrompt(el) {
    setTimeout(() => {
        try {
            const eng = dlpEngine();
            const now = getEditableText(el);
            if (eng && dlpPolicy) {
                const check = eng.sanitize(now, dlpPolicy);
                if (check.findings.length > 0 && check.action !== 'allow') {
                    // The mask did not stick. Do NOT send. Tell the user why.
                    showDlpBanner('holdback', check, el);
                    return;
                }
            } else if (!eng) {
                warnEngineUnavailable();
                return;   // cannot verify => do not send
            }
            const btn = findSendButton(el);
            if (btn) btn.click();
        } catch (e) {
            // Any failure here means we could not confirm the prompt is safe.
            try { warnEngineUnavailable(); } catch (e2) {}
        }
    }, 150);
}

// --- DLP WARNING BANNER ---
let dlpBanner = null;
let dlpBannerTimer = null;

function humanizeLabel(label) {
    return (label || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ── DLP notification placement ────────────────────────────────────────
// The notification is anchored to the LEFT of the composer rather than pinned
// to the top of the viewport. While typing, the user's eyes are on the input
// box at the bottom of the page; a top-centre toast sits outside that focus and
// was easy to miss entirely. Anchoring it beside the input puts the alert in
// the same place the user is already looking, and it slides in from the left so
// the motion is picked up by peripheral vision.
const PBX_GAP = 14;          // breathing room from the composer / viewport edge
const PBX_SIDE_MIN = 300;    // below this, there is no usable room to the left
let dlpAnchorEl = null, dlpAnchorRaf = 0, dlpReflow = null;

function pbxInjectStyles() {
    if (document.getElementById('promptrix-dlp-styles')) return;
    const st = document.createElement('style');
    st.id = 'promptrix-dlp-styles';
    st.textContent =
        '@keyframes pbx-in-left { from { opacity:0; transform:translateX(-26px) scale(.97); }' +
        ' to { opacity:1; transform:translateX(0) scale(1); } }' +
        '@keyframes pbx-in-up { from { opacity:0; transform:translateY(16px) scale(.97); }' +
        ' to { opacity:1; transform:translateY(0) scale(1); } }' +
        '@keyframes pbx-logo-pop { 0% { transform:scale(.4) rotate(-18deg); opacity:0; }' +
        ' 60% { transform:scale(1.18) rotate(4deg); opacity:1; } 100% { transform:scale(1) rotate(0); opacity:1; } }';
    document.head.appendChild(st);
}

// Where can the notification physically go, given the composer's position?
function pbxPlaceBanner(box, inputEl) {
    const vw = window.innerWidth, vh = window.innerHeight;
    let rect = null;
    try {
        const a = inputEl && inputEl.getBoundingClientRect ? inputEl : null;
        if (a) { const r = a.getBoundingClientRect(); if (r.width || r.height) rect = r; }
    } catch (e) {}

    box.style.right = 'auto';
    if (!rect) {
        // Composer not on screen: stay low-left, still near where input lives.
        const w = Math.min(380, vw - PBX_GAP * 2);
        box.style.width = w + 'px';
        box.style.left = PBX_GAP + 'px';
        box.style.top = 'auto';
        box.style.bottom = (PBX_GAP + 10) + 'px';
        box.style.animation = 'pbx-in-left .24s cubic-bezier(.22,1.2,.36,1)';
        return;
    }

    box.style.bottom = 'auto';
    const roomLeft = rect.left - PBX_GAP * 2;
    const h = box.offsetHeight || 150;

    if (roomLeft >= PBX_SIDE_MIN) {
        // Preferred: beside the input box, bottom edges aligned.
        const w = Math.min(400, roomLeft);
        box.style.width = w + 'px';
        box.style.left = Math.max(PBX_GAP, rect.left - PBX_GAP - w) + 'px';
        box.style.top = Math.max(PBX_GAP, Math.min(rect.bottom - h, vh - h - PBX_GAP)) + 'px';
        box.style.animation = 'pbx-in-left .24s cubic-bezier(.22,1.2,.36,1)';
    } else {
        // Narrow window: sit directly above the composer, left-aligned to it.
        const w = Math.min(520, vw - PBX_GAP * 2);
        box.style.width = w + 'px';
        box.style.left = Math.max(PBX_GAP, Math.min(rect.left, vw - w - PBX_GAP)) + 'px';
        box.style.top = Math.max(PBX_GAP, rect.top - h - PBX_GAP) + 'px';
        box.style.animation = 'pbx-in-up .24s cubic-bezier(.22,1.2,.36,1)';
    }
}

// The composer moves as the thread grows or the window resizes, so keep the
// notification pinned to it. rAF-throttled: one placement per frame at most.
function pbxTrackAnchor(box, inputEl) {
    dlpAnchorEl = inputEl || null;
    pbxPlaceBanner(box, dlpAnchorEl);
    dlpReflow = function () {
        if (!dlpBanner || dlpAnchorRaf) return;
        dlpAnchorRaf = requestAnimationFrame(function () {
            dlpAnchorRaf = 0;
            if (dlpBanner) pbxPlaceBanner(dlpBanner, dlpAnchorEl);
        });
    };
    window.addEventListener('resize', dlpReflow, true);
    window.addEventListener('scroll', dlpReflow, true);
}

function pbxUntrackAnchor() {
    if (dlpReflow) {
        window.removeEventListener('resize', dlpReflow, true);
        window.removeEventListener('scroll', dlpReflow, true);
        dlpReflow = null;
    }
    if (dlpAnchorRaf) { cancelAnimationFrame(dlpAnchorRaf); dlpAnchorRaf = 0; }
    dlpAnchorEl = null;
}

// Branded header: the Promptrix mark makes the source of the alert unmistakable.
function pbxBrandHeader(accent, icon, title) {
    const head = document.createElement('div');
    head.style.cssText = 'display:flex; align-items:flex-start; gap:10px; margin-bottom:9px;';
    head.innerHTML =
        '<span style="display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;' +
        'flex:0 0 26px;border-radius:8px;background:' + accent + '22;border:1px solid ' + accent + '66;' +
        'font-size:14px;animation:pbx-logo-pop .34s cubic-bezier(.22,1.4,.36,1);">\u26A1</span>' +
        '<span style="flex:1;min-width:0;">' +
          '<span style="display:block;font-size:9.5px;font-weight:700;letter-spacing:.11em;' +
          'text-transform:uppercase;color:' + accent + ';margin-bottom:2px;">Promptrix DLP</span>' +
          '<span style="display:block;font-weight:700;font-size:13px;color:#fff;line-height:1.3;">' +
          icon + ' ' + title + '</span>' +
        '</span>' +
        '<span id="pbx-dlp-close" title="Dismiss" style="cursor:pointer;opacity:.55;font-size:13px;' +
        'padding:2px 5px;border-radius:5px;flex:0 0 auto;">\u2715</span>';
    return head;
}

function showDlpBanner(kind, res, inputEl) {
    removeDlpBanner();

    const typeList = Object.keys(res.counts).map(humanizeLabel);
    const typesText = typeList.slice(0, 6).join(', ') + (typeList.length > 6 ? ` +${typeList.length - 6} more` : '');
    const classText = (res.classifications || [])
        .map(c => ((DLP && DLP.CLASSIFICATION_SHORT && DLP.CLASSIFICATION_SHORT[c]) || c)).join(', ');

    const theme = {
        block:    { accent: '#ef4444', bg: '#2a1215', icon: '⛔', title: 'Prompt blocked by Promptrix DLP' },
        mask:     { accent: '#f59e0b', bg: '#2a2110', icon: '🛡️', title: 'Sensitive data masked' },
        warn:     { accent: '#f59e0b', bg: '#2a2110', icon: '⚠️', title: 'Sensitive data detected' },
        // Not a policy block: masking was requested but could not be applied to
        // this site's editor, so the send was held back rather than leaked.
        holdback: { accent: '#ef4444', bg: '#2a1215', icon: '✋', title: 'Send held back — masking could not be applied' },
    }[kind] || { accent: '#f59e0b', bg: '#2a2110', icon: '⚠️', title: 'Sensitive data detected' };

    const detail = kind === 'holdback'
        ? 'Promptrix could not rewrite this site\'s input box, so the prompt was NOT sent — your data did not leave the page. Edit or delete the flagged values manually, then send again.'
        : kind === 'block'
        ? 'This prompt was not sent. Remove or edit the flagged data, then try again.'
        : kind === 'mask'
            ? 'The flagged data was masked with X and the sanitized prompt was sent. If it did not send, press Enter / Send again.'
            : 'Masking is turned off, so the original text was sent. Enable masking in Promptrix → Settings to redact automatically.';

    pbxInjectStyles();

    const box = document.createElement('div');
    box.id = 'promptrix-dlp-banner';
    // Left edge carries the accent bar: it points at the input box it came from.
    box.style.cssText = `
        position: fixed; z-index: 2147483647; box-sizing: border-box;
        background: ${theme.bg}; border: 1px solid ${theme.accent};
        border-left: 4px solid ${theme.accent};
        border-radius: 12px; box-shadow: 0 14px 44px rgba(0,0,0,0.6);
        color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        padding: 13px 15px;
    `;

    const head = pbxBrandHeader(theme.accent, theme.icon, theme.title);

    const msg = document.createElement('div');
    msg.style.cssText = 'font-size:12.5px; line-height:1.5; color:#e5e7eb;';
    msg.innerHTML = `You tried to post <b style="color:${theme.accent}">${escapeForHtml(typesText || 'sensitive')}</b> info ` +
        `<span style="color:#9ca3af;">(Data Classified — ${escapeForHtml(classText || 'Sensitive')})</span>.` +
        `<div style="margin-top:6px; color:#c7cbd1;">${detail}</div>`;

    const chips = document.createElement('div');
    chips.style.cssText = 'display:flex; flex-wrap:wrap; gap:6px; margin-top:10px;';
    Object.keys(res.counts).slice(0, 8).forEach(label => {
        const chip = document.createElement('span');
        chip.textContent = `${humanizeLabel(label)}${res.counts[label] > 1 ? ' ×' + res.counts[label] : ''}`;
        chip.style.cssText = `font-size:10px; font-weight:600; letter-spacing:0.3px; color:${theme.accent};` +
            `background:${theme.accent}1a; border:1px solid ${theme.accent}55; padding:2px 8px; border-radius:20px;`;
        chips.appendChild(chip);
    });

    box.appendChild(head);
    box.appendChild(msg);
    box.appendChild(chips);

    // A hold-back means we could not rewrite this site's editor. Do not leave
    // the user stuck: hand them the masked text so they can paste it manually.
    if (kind === 'holdback' && res && res.sanitized) {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;align-items:center;gap:10px;margin-top:12px;flex-wrap:wrap;';
        const btn = document.createElement('button');
        btn.textContent = '\u2398 Copy masked prompt';
        btn.style.cssText = 'cursor:pointer;font-size:11.5px;font-weight:600;color:#fff;' +
            'background:' + theme.accent + '33;border:1px solid ' + theme.accent + ';' +
            'padding:6px 12px;border-radius:7px;font-family:inherit;';
        const note = document.createElement('span');
        note.style.cssText = 'font-size:11px;color:#9ca3af;';
        btn.onclick = () => {
            try {
                navigator.clipboard.writeText(res.sanitized).then(
                    () => { note.textContent = 'Copied — select all in the box and paste over it.'; },
                    () => { note.textContent = 'Clipboard blocked by this site.'; });
            } catch (e) { note.textContent = 'Clipboard blocked by this site.'; }
        };
        row.appendChild(btn); row.appendChild(note);
        box.appendChild(row);
    }

    document.body.appendChild(box);
    dlpBanner = box;
    // Anchor AFTER insertion — placement needs the rendered height.
    pbxTrackAnchor(box, inputEl || findEditableElement(null));

    const closeEl = box.querySelector('#pbx-dlp-close');
    if (closeEl) closeEl.onclick = removeDlpBanner;

    // Block banners persist until dismissed; mask/warn auto-hide.
    if (kind !== 'block' && kind !== 'holdback') {
        dlpBannerTimer = setTimeout(removeDlpBanner, 7000);
    }
}

function removeDlpBanner() {
    if (dlpBannerTimer) { clearTimeout(dlpBannerTimer); dlpBannerTimer = null; }
    if (dlpBanner) { dlpBanner.remove(); dlpBanner = null; }
    pbxUntrackAnchor();   // stop repositioning once the banner is gone
}

// Registered HERE, before the input/keydown/click listeners in section 3, so
// the gate runs first in the capture phase and can stop the page's own send
// handler via stopImmediatePropagation when it blocks or masks a prompt.
document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || e.shiftKey || isComposing) return;
    if (!dlpEngine() || !dlpPolicy) {
        // Could not scan. Warn instead of silently letting the prompt through.
        const el0 = findEditableElement(e.target);
        const t0 = el0 ? getEditableText(el0) : inputBuffer;
        if (t0 && t0.trim().length > 1) warnEngineUnavailable();
        return;
    }
    // Let autocomplete keyboard-selection win.
    if (suggestionBox && selectedSuggestionIndex >= 0) return;

    const el = findEditableElement(e.target);
    const text = el ? getEditableText(el) : inputBuffer;
    if (!text || text.trim().length < 2) return;

    if (!dlpGate(text, el)) {
        e.preventDefault();
        e.stopImmediatePropagation();
    }
}, true);

document.addEventListener('click', (e) => {
    const btn0 = e.target.closest && e.target.closest('button, [role="button"]');
    if (!dlpEngine() || !dlpPolicy) {
        if (btn0 && isSendControl(btn0)) warnEngineUnavailable();
        return;
    }
    const btn = btn0;
    if (!btn || !isSendControl(btn)) return;

    const el = findEditableElement(e.target);
    const text = (el ? getEditableText(el) : '') || inputBuffer;
    if (!text || text.trim().length < 2) return;

    if (!dlpGate(text, el)) {
        e.preventDefault();
        e.stopImmediatePropagation();
    }
}, true);


// --- 1c. CONTENT INSPECTION (attachments) ---
// Files attached to an AI chat are inspected in-page by the Content
// Inspection Engine before they can be transmitted: true file type is
// resolved from content, containers (Office documents, archives, PDFs) are
// opened, the detection catalogue runs over every extracted part, and a risk
// score selects the response action. Bytes never leave the browser.

const CIE = (typeof window !== 'undefined' && window.PromptrixInspector) ? window.PromptrixInspector : null;
const inspectedFiles = new WeakSet();

function inspectionPolicy() {
    if (dlpPolicy && dlpPolicy.file) return dlpPolicy.file;
    return CIE ? CIE.defaultInspectionPolicy() : null;
}
function inspectionActive() {
    const ip = inspectionPolicy();
    return !!(CIE && DLP && ip && ip.enabled && ip.depth !== 'off');
}

// Adapter: the inspector asks us to run the detection catalogue over a string.
function makeTextScanner() {
    return (text) => dlpEngine().scan(text, dlpPolicy);
}

async function onAttachments(fileList, sourceInput) {
    if (!inspectionActive() || !fileList || !fileList.length) return;
    const ip = inspectionPolicy();
    const scanText = makeTextScanner();
    const flagged = [];

    for (const file of fileList) {
        if (!file || inspectedFiles.has(file)) continue;
        inspectedFiles.add(file);
        let report;
        try {
            report = await CIE.inspect(file, scanText, ip);
        } catch (e) {
            console.warn('[Promptrix CIE] inspection failed for', file.name, e && e.message);
            continue;
        }
        if (!report.inspected) {
            console.info(`[Promptrix CIE] ${file.name}: not inspected — ${report.skipReason}`);
            continue;
        }
        console.info(`[Promptrix CIE] ${file.name}: type=${report.trueType} parts=${report.segments} ` +
                     `findings=${report.findings.length} risk=${report.risk.score}/${report.risk.band} → ${report.action}`);
        if (report.action === 'allow') continue;

        flagged.push({ file, report });
        try {
            const entry = CIE.buildInspectionLog(report, { aiTool: TOOL_NAME, url: currentUrl });
            chrome.runtime.sendMessage({ action: 'dlp_log', entry }, () => { void chrome.runtime.lastError; });
        } catch (e) {}
    }
    if (!flagged.length) return;

    // Enforce the strongest action requested across the batch.
    const rank = { allow: 0, notify: 1, quarantine: 2, block: 3 };
    const strongest = flagged.reduce((a, f) => rank[f.report.action] > rank[a] ? f.report.action : a, 'notify');
    if (strongest === 'quarantine' || strongest === 'block') {
        await Promise.all(flagged
            .filter(f => rank[f.report.action] >= 2)
            .map(f => detachAttachment(f.file.name, sourceInput)));
    }
    showInspectionBanner(flagged, sourceInput, strongest);
}

// ── Detaching a quarantined attachment ──────────────────────────────────
// Chat SPAs copy the FileList into component state on selection, so clearing
// the <input> is a no-op once the app has read it. The reliable path is to
// drive the app's own per-attachment dismiss control. We locate the card by
// matching its rendered filename, then activate the control the way a user
// would (pointer sequence, since some frameworks ignore a bare .click()).
const DISMISS_CANDIDATES = [
    '[aria-label*="remove" i]', '[aria-label*="delete" i]', '[aria-label*="dismiss" i]',
    '[aria-label*="close" i]', '[title*="remove" i]', '[data-testid*="remove" i]',
];

function attachmentCardsFor(name) {
    const needle = String(name).toLowerCase();
    const sel = DISMISS_CANDIDATES.join(',');
    const cards = [];
    let controls = [];
    try { controls = [...document.querySelectorAll(sel)]; } catch (e) { return cards; }
    for (const ctl of controls) {
        // Walk up until an ancestor renders this filename — that box is the card.
        let node = ctl.parentElement;
        for (let hop = 0; hop < 6 && node; hop++, node = node.parentElement) {
            const txt = (node.textContent || '').toLowerCase();
            if (txt.includes(needle)) { cards.push({ card: node, control: ctl }); break; }
            if (txt.length > 4000) break;   // walked out of the attachment strip
        }
    }
    return cards;
}

function activate(el) {
    const opts = { bubbles: true, cancelable: true, composed: true, view: window };
    for (const type of ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click']) {
        try {
            const Ctor = type.startsWith('pointer') && typeof PointerEvent === 'function' ? PointerEvent : MouseEvent;
            el.dispatchEvent(new Ctor(type, opts));
        } catch (e) {}
    }
}

async function detachAttachment(name, sourceInput) {
    const hits = attachmentCardsFor(name);
    if (hits.length) {
        activate(hits[0].control);
        await new Promise(r => setTimeout(r, 220));
        if (!attachmentCardsFor(name).length) return true;
    }
    // Non-framework uploader: resetting the input is sufficient.
    if (sourceInput instanceof HTMLInputElement) {
        try {
            sourceInput.value = '';
            sourceInput.dispatchEvent(new Event('input', { bubbles: true }));
            sourceInput.dispatchEvent(new Event('change', { bubbles: true }));
            return true;
        } catch (e) {}
    }
    console.warn(`[Promptrix CIE] could not detach "${name}" — remove it manually before sending.`);
    return false;
}

// ── Inspection verdict banner ───────────────────────────────────────────
const BAND_THEME = {
    CRITICAL: { accent: '#ef4444', bg: '#2a1215' },
    HIGH:     { accent: '#f59e0b', bg: '#2a2110' },
    MODERATE: { accent: '#60a5fa', bg: '#111a2a' },
    LOW:      { accent: '#8888a0', bg: '#16161f' },
};

function showInspectionBanner(flagged, sourceInput, action) {
    removeDlpBanner();
    const worst = flagged.reduce((a, f) =>
        (f.report.risk.score > (a ? a.report.risk.score : -1)) ? f : a, null);
    const theme = BAND_THEME[worst.report.risk.band] || BAND_THEME.HIGH;
    const verb = { notify: 'Sensitive content detected in attachment',
                   quarantine: 'Attachment quarantined',
                   block: 'Attachment blocked' }[action] || 'Attachment flagged';

    pbxInjectStyles();

    const box = document.createElement('div');
    box.id = 'promptrix-dlp-banner';
    box.style.cssText = `position:fixed; z-index:2147483647; box-sizing:border-box;
        background:${theme.bg}; border:1px solid ${theme.accent};
        border-left:4px solid ${theme.accent}; border-radius:12px; box-shadow:0 14px 44px rgba(0,0,0,.6);
        color:#f3f4f6; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
        padding:13px 15px;`;

    const head = pbxBrandHeader(theme.accent, '\u{1F6E1}\u{FE0F}', verb);
    // Keep the risk score in the header, slotted in before the close control.
    const risk = document.createElement('span');
    risk.textContent = `RISK ${worst.report.risk.score} \u00B7 ${worst.report.risk.band}`;
    risk.style.cssText = `font-size:9.5px;font-weight:700;letter-spacing:.06em;color:${theme.accent};` +
        `background:${theme.accent}22;border:1px solid ${theme.accent}55;padding:3px 8px;` +
        `border-radius:20px;flex:0 0 auto;white-space:nowrap;align-self:center;`;
    const closeSlot = head.querySelector('#pbx-dlp-close');
    if (closeSlot) head.insertBefore(risk, closeSlot); else head.appendChild(risk);
    box.appendChild(head);

    const body = document.createElement('div');
    body.style.cssText = 'font-size:12.5px; line-height:1.55; color:#e5e7eb;';
    body.innerHTML = flagged.map(f => {
        const r = f.report;
        const types = Object.keys(r.counts).map(l => l.replace(/_/g, ' ')).slice(0, 5).join(', ');
        const where = r.segments > 1 ? ` · ${r.segments} parts inspected` : '';
        const masq = r.masquerade
            ? `<div style="color:${theme.accent};font-size:11px;margin-top:3px;">⚠ Declared .${r.declaredExt} but content is ${r.trueType} — possible evasion</div>` : '';
        return `<div style="margin:5px 0;">
            <b style="color:${theme.accent}">${escapeForHtml(r.fileName)}</b>
            <span style="color:#9ca3af;font-size:11px;"> ${r.trueType}${where}${r.truncated ? ' · partial' : ''}</span>
            <div style="color:#c7cbd1;font-size:11.5px;">${r.findings.length} item(s): ${escapeForHtml(types || '—')}</div>
            ${masq}</div>`;
    }).join('');
    const note = action === 'notify'
        ? 'Review before sending — nothing was removed.'
        : 'Removed from the composer. Verify it is gone before you send.';
    body.innerHTML += `<div style="margin-top:8px;color:#c7cbd1;font-size:11.5px;">${note}</div>`;
    box.appendChild(body);

    if (action === 'notify') {
        const actions = document.createElement('div');
        actions.style.cssText = 'display:flex; gap:8px; margin-top:11px;';
        const rm = document.createElement('button');
        rm.textContent = 'Remove attachment' + (flagged.length > 1 ? 's' : '');
        rm.style.cssText = `background:${theme.accent};color:#fff;border:none;border-radius:7px;padding:6px 12px;font-size:12px;font-weight:600;cursor:pointer;`;
        rm.onclick = async () => {
            await Promise.all(flagged.map(f => detachAttachment(f.file.name, sourceInput)));
            flagged.forEach(f => {
                try {
                    f.report.action = 'quarantine';
                    const entry = CIE.buildInspectionLog(f.report, { aiTool: TOOL_NAME, url: currentUrl });
                    chrome.runtime.sendMessage({ action: 'dlp_log', entry }, () => { void chrome.runtime.lastError; });
                } catch (e) {}
            });
            removeDlpBanner();
        };
        const keep = document.createElement('button');
        keep.textContent = 'Keep';
        keep.style.cssText = 'background:rgba(255,255,255,.08);color:#e5e7eb;border:1px solid rgba(255,255,255,.15);border-radius:7px;padding:6px 12px;font-size:12px;cursor:pointer;';
        keep.onclick = removeDlpBanner;
        actions.appendChild(rm); actions.appendChild(keep);
        box.appendChild(actions);
    }

    document.body.appendChild(box);
    dlpBanner = box;
    // sourceInput is the file <input>, which is usually hidden and has no useful
    // rect — anchor to the composer the attachment was destined for instead.
    pbxTrackAnchor(box, findEditableElement(null));
    const closeEl = box.querySelector('#pbx-dlp-close');
    if (closeEl) closeEl.onclick = removeDlpBanner;
    if (action === 'notify') dlpBannerTimer = setTimeout(removeDlpBanner, 12000);
}

// Attachment entry points: picker, drag-drop and clipboard.
document.addEventListener('change', (e) => {
    const t = e.target;
    if (t instanceof HTMLInputElement && t.type === 'file' && t.files && t.files.length) {
        onAttachments(t.files, t);
    }
}, true);
window.addEventListener('drop', (e) => {
    const f = e.dataTransfer && e.dataTransfer.files;
    if (f && f.length) onAttachments(f, null);
}, true);
window.addEventListener('paste', (e) => {
    if (!e.isTrusted) return;
    const f = e.clipboardData && e.clipboardData.files;
    if (f && f.length) onAttachments(f, null);
}, true);


// --- 2. CAPTURE LOGIC ---

const sendToBackground = (type, content, specificUrl = null) => {
    if (!content || content.trim().length < 2) return;
    
    const finalUrl = specificUrl || currentUrl;

    try {
        chrome.runtime.sendMessage({
            action: 'capture',
            data: {
                type: type,
                content: content.trim(),
                aiTool: TOOL_NAME,
                timestamp: new Date().toISOString(),
                sessionUrl: finalUrl
            }
        });
        console.log(`[Promptrix] Saved ${type} (${content.trim().length} chars)`);
    } catch (e) {
        // Context invalidated
    }
};

const queuePrompt = (content) => {
    if (!content || content.trim().length < 2) return;
    
    // Store prompt and current URL
    pendingPrompt = {
        content: content,
        timestamp: Date.now(),
        sessionUrl: currentUrl 
    };
    
    console.log('[Promptrix] Prompt Queued. Waiting for response...');
    
    if (safetyTimer) clearTimeout(safetyTimer);
    safetyTimer = setTimeout(() => {
        if (pendingPrompt) {
            finalizePrompt();
        }
    }, 15000);
};

const finalizePrompt = () => {
    if (!pendingPrompt) return;
    
    // Send with the latest URL we have
    sendToBackground('prompt', pendingPrompt.content, pendingPrompt.sessionUrl);
    
    pendingPrompt = null;
    if (safetyTimer) clearTimeout(safetyTimer);
};


// --- 3. INPUT MONITORING ---

document.addEventListener('compositionstart', () => isComposing = true, true);
document.addEventListener('compositionend', () => isComposing = false, true);

document.addEventListener('input', (e) => {
    if (isComposing) return;
    
    let target = e.target;
    // Find the relevant editable element
    let editableElement = target.closest('textarea, input, [contenteditable="true"]');

    if (editableElement) {
        // textContent, NOT innerText: this runs on every keystroke and innerText
        // forces a layout each time, which is what made typing stutter. The
        // accurate (layout-aware) read happens once, at submit time.
        const val = editableElement.value || editableElement.textContent || '';
        inputBuffer = val;
        
        // Prompt recall is a TYPING aid. Firing it for a large buffer made every
        // paste ask the worker to deserialize the whole capture store (~75 ms at
        // volume) and search it with a multi-kilobyte needle — work that can
        // never produce a useful autocomplete. Pastes are not typing sessions.
        if (inputBuffer.length > 3 && inputBuffer.length <= RECALL_MAX_BUFFER) {
            fetchSuggestions(inputBuffer, editableElement);
        } else {
            removeSuggestionBox();
        }
    }
}, true);

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        removeSuggestionBox();
        suppressedText = inputBuffer; // Suppress until user changes text
    }
    
    if (e.key === 'Enter' && !e.shiftKey) {
        // Only capture prompt if no suggestion is selected (otherwise keyboard nav handles it)
        if (suggestionBox && selectedSuggestionIndex >= 0) return; // Handled by keyboard nav listener
        
        const textToSave = inputBuffer;
        if (textToSave && textToSave.trim().length > 1) {
            removeSuggestionBox();
            suppressedText = textToSave; // Suppress after sending
            queuePrompt(textToSave);
            setTimeout(() => { inputBuffer = ''; suppressedText = ''; }, 500);
        }
    }
}, true);

// Google Search-style: popup does NOT close on click outside.
// It only closes on: Esc, Enter (send), Send button click, or no matches.
// This keeps suggestions visible while user thinks/clicks elsewhere briefly.
document.addEventListener('click', (e) => {
    const btn = e.target.closest('button, [role="button"]');
    if (btn) {
        if (isSendControl(btn)) {
             if (inputBuffer && inputBuffer.trim().length > 1) {
                removeSuggestionBox();
                suppressedText = inputBuffer;
                queuePrompt(inputBuffer);
                setTimeout(() => { inputBuffer = ''; suppressedText = ''; }, 500);
             }
        }
    }
}, true);


// --- 4. RESPONSE CAPTURE (Tool-Specific + Generic Fallback) ---

// Get the right selectors for the current AI tool
function getSelectors() {
    return RESPONSE_SELECTORS[TOOL_NAME] || GENERIC_SELECTORS;
}

// Check if the AI is still streaming/generating
function isStreaming() {
    const a = adapter();
    if (a && a.streaming) {
        for (let i = 0; i < a.streaming.length; i++) {
            try { if (document.querySelector(a.streaming[i])) return true; } catch (e) {}
        }
    }
    const selectors = getSelectors();
    const indicator = selectors.streamingIndicator;
    if (!indicator) return false;
    
    // Try each selector (comma-separated)
    const parts = indicator.split(',').map(s => s.trim());
    for (const sel of parts) {
        try {
            if (document.querySelector(sel)) return true;
        } catch(e) {}
    }
    return false;
}

// Extract all response messages from the page using tool-specific selectors
function getAllResponseTexts() {
    const selectors = getSelectors();
    const responses = [];
    
    // Try tool-specific message containers first
    const containerSelector = selectors.messageContainer;
    if (containerSelector) {
        const parts = containerSelector.split(',').map(s => s.trim());
        for (const sel of parts) {
            try {
                const all = document.querySelectorAll(sel);
                // Only the newest turns can be an uncaptured response. Reading
                // every message in a long thread meant one forced layout per
                // message on every poll.
                const elements = all.length > 3 ? Array.prototype.slice.call(all, -3) : all;
                elements.forEach(el => {
                    // Try content selector within the container
                    let text = '';
                    if (selectors.contentSelector) {
                        const contentParts = selectors.contentSelector.split(',').map(s => s.trim());
                        for (const cSel of contentParts) {
                            try {
                                const content = el.querySelector(cSel);
                                if (content) {
                                    text = content.innerText || content.textContent || '';
                                    break;
                                }
                            } catch(e) {}
                        }
                    }
                    // Fallback to container's own text
                    if (!text) {
                        text = el.innerText || el.textContent || '';
                    }
                    
                    text = text.trim();
                    if (text.length > 20) {
                        responses.push(text);
                    }
                });
            } catch(e) {}
        }
    }
    
    return responses;
}

// Get the latest (last) response that we haven't captured yet
function getLatestNewResponse() {
    const responses = getAllResponseTexts();
    if (responses.length === 0) return null;
    
    // Get the last response
    const lastResponse = responses[responses.length - 1];
    
    // Create a fingerprint to avoid duplicate captures
    const fingerprint = hashText(lastResponse);
    
    if (fingerprint !== lastCapturedResponseId && lastResponse.length > 20) {
        return { text: lastResponse, fingerprint, index: responses.length - 1 };
    }
    
    return null;
}

// Simple string hash for dedup
function hashText(text) {
    if (!text) return '';
    // Use first 100 + last 100 chars + length as a fingerprint
    const sample = text.substring(0, 100) + '|' + text.substring(Math.max(0, text.length - 100)) + '|' + text.length;
    let hash = 0;
    for (let i = 0; i < sample.length; i++) {
        hash = ((hash << 5) - hash) + sample.charCodeAt(i);
        hash |= 0;
    }
    return hash.toString(36);
}

// Attempt to capture the latest response
function captureLatestResponse() {
    // Don't capture while streaming
    if (isStreaming()) {
        console.log('[Promptrix] AI still streaming, waiting...');
        return false;
    }
    
    const newResp = getLatestNewResponse();
    if (newResp) {
        console.log(`[Promptrix] New response detected (${newResp.text.length} chars)`);
        sendToBackground('response', newResp.text);
        lastCapturedResponseId = newResp.fingerprint;
        lastKnownResponseCount = getAllResponseTexts().length;
        return true;
    }
    return false;
}


// --- 4b. MUTATION OBSERVER (watches for new DOM content) ---

let responseDebounceTimer = null;

// Coalesce bursts: while a model streams, mutations arrive continuously. We
// only need to know THAT something changed, so do the cheap check and bail.
let mutationGate = 0;

const observer = new MutationObserver((mutations) => {
    // Rate-limit the callback itself. Streaming can deliver thousands of
    // records per second and the old code did work on every single one.
    const now = Date.now();
    if (now - mutationGate < 250) return;

    let hasSignificantChange = false;
    // Only inspect a bounded slice — one qualifying node is enough.
    const limit = Math.min(mutations.length, 30);
    for (let i = 0; i < limit && !hasSignificantChange; i++) {
        const added = mutations[i].addedNodes;
        for (let j = 0; j < added.length; j++) {
            const node = added[j];
            if (node.nodeType !== 1) continue;
            // textContent is a plain tree walk. innerText is layout-dependent
            // and forced a full reflow here on every streamed token, which is
            // what locked the tab up.
            if ((node.textContent || '').length > 30) { hasSignificantChange = true; break; }
        }
    }
    if (!hasSignificantChange) return;
    mutationGate = now;

    // When new content appears, finalize pending prompt
    if (hasSignificantChange && pendingPrompt) {
        setTimeout(() => {
            finalizePrompt();
        }, 500);
    }

    // Debounce response capture — wait for streaming to finish
    if (hasSignificantChange) {
        clearTimeout(responseDebounceTimer);
        responseDebounceTimer = setTimeout(() => {
            // Double-check streaming stopped, then try to capture
            if (!isStreaming()) {
                captureLatestResponse();
            } else {
                // Still streaming — retry in 3 more seconds
                console.log('[Promptrix] Still streaming, retrying in 3s...');
                clearTimeout(responseDebounceTimer);
                responseDebounceTimer = setTimeout(() => {
                    if (!isStreaming()) {
                        captureLatestResponse();
                    } else {
                        // Final retry after 5 more seconds
                        setTimeout(() => captureLatestResponse(), 5000);
                    }
                }, 3000);
            }
        }, 4000); // Wait 4 seconds after last DOM change
    }
});

// characterData is deliberately OFF. With subtree:true on <body> it fires for
// every streamed character; childList alone tells us a message arrived.
function startResponseObserver() {
    const root = document.body;
    if (!root) return;
    observer.observe(root, { childList: true, subtree: true });
}
if (document.body) startResponseObserver();
else document.addEventListener('DOMContentLoaded', startResponseObserver, { once: true });


// --- 4c. PERIODIC RESPONSE CHECKER (backup for streaming tools) ---
// Some tools don't trigger clear MutationObserver events when streaming finishes.
// This polls every 8 seconds to catch any missed responses.

// Runs only while the tab is visible: a background tab cannot be producing new
// responses, and polling DOM reads there burned CPU on every open chat tab.
setInterval(() => {
    if (document.hidden) return;
    const currentCount = getAllResponseTexts().length;
    if (currentCount > lastKnownResponseCount && !isStreaming()) {
        captureLatestResponse();
    }
}, 8000);


// --- 5. ROBUST INSERTION (AUTOCOMPLETE) ---

// ── Per-site composer adapters ────────────────────────────────────────
// Every GenAI web app builds its input differently, and a single generic write
// strategy cannot satisfy all of them:
//   ChatGPT / Claude  ProseMirror contenteditable — rejects foreign DOM writes,
//                     but handles a native paste event correctly.
//   Gemini            Quill contenteditable — same story.
//   Copilot / Perplexity  React CONTROLLED <textarea>. Setting .value fires an
//                     input event, but React's ChangeEventPlugin dedupes via an
//                     internal _valueTracker: if the tracker's cached value did
//                     not change, React ignores the event and re-renders from
//                     state, REVERTING the mask. This is why masking appeared to
//                     work and then silently undid itself on Copilot.
// Strategies are ordered per site and each one is verified by reading the value
// back, so we never assume a write landed.
const SITE_ADAPTERS = {
    ChatGPT: {
        composer: ['#prompt-textarea', 'div.ProseMirror[contenteditable="true"]',
                   'textarea[data-id]', 'div[contenteditable="true"]'],
        send: ['[data-testid="send-button"]', '[data-testid="fruitjuice-send-button"]',
               'button[aria-label*="Send prompt" i]', 'button[aria-label*="Send message" i]'],
        write: ['paste', 'exec', 'native'],
        streaming: ['[data-testid="stop-button"]', 'button[aria-label*="Stop" i]'],
    },
    Claude: {
        composer: ['div.ProseMirror[contenteditable="true"]', 'fieldset div[contenteditable="true"]',
                   'div[contenteditable="true"]'],
        send: ['button[aria-label="Send message"]', 'button[aria-label*="Send" i]'],
        write: ['paste', 'exec', 'native'],
        streaming: ['[data-is-streaming="true"]', 'button[aria-label*="Stop" i]'],
    },
    Gemini: {
        composer: ['div.ql-editor[contenteditable="true"]', 'rich-textarea div[contenteditable="true"]',
                   'div[contenteditable="true"]'],
        send: ['button[aria-label*="Send message" i]', 'button.send-button',
               'button[aria-label*="Submit" i]'],
        write: ['paste', 'exec', 'native'],
        streaming: ['button[aria-label*="Stop" i]', '.loading'],
    },
    Perplexity: {
        composer: ['textarea[placeholder*="Ask" i]', 'textarea[placeholder*="ask" i]',
                   'div[contenteditable="true"]', 'textarea'],
        send: ['button[aria-label="Submit"]', 'button[data-testid="submit-button"]',
               'button[aria-label*="Submit" i]', 'button[type="submit"]'],
        write: ['react', 'paste', 'exec', 'native'],
        streaming: ['button[aria-label*="Stop" i]'],
    },
    Copilot: {
        composer: ['#userInput', 'textarea#userInput', 'textarea[placeholder*="Message" i]',
                   'textarea[aria-label*="Ask" i]', 'div[contenteditable="true"]', 'textarea'],
        send: ['button[title*="Submit" i]', 'button[aria-label*="Submit" i]',
               'button[data-testid="submit-button"]', 'button[aria-label*="Send" i]'],
        write: ['react', 'paste', 'exec', 'native'],
        streaming: ['button[title*="Stop" i]', 'button[aria-label*="Stop" i]'],
    },
};

function adapter() { return SITE_ADAPTERS[TOOL_NAME] || null; }

function readComposer(el) {
    if (!el) return '';
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') return el.value || '';
    return el.textContent || '';
}

// ── write strategies ──────────────────────────────────────────────────
// React controlled input: reset the value tracker so React's synthetic change
// detection sees a real transition, otherwise it reverts our write.
function writeReact(el, text) {
    if (el.tagName !== 'TEXTAREA' && el.tagName !== 'INPUT') return false;
    try {
        const proto = Object.getPrototypeOf(el);
        const setter = Object.getOwnPropertyDescriptor(proto, 'value') &&
                       Object.getOwnPropertyDescriptor(proto, 'value').set;
        if (el._valueTracker && typeof el._valueTracker.setValue === 'function') {
            el._valueTracker.setValue('\u0000never');   // force a perceived change
        }
        if (setter) setter.call(el, text); else el.value = text;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
    } catch (e) { return false; }
}

// Rich editors (ProseMirror, Quill, Lexical) own their DOM but implement paste
// properly, so a synthetic paste is the most reliable way in.
function writePaste(el, text) {
    try {
        el.focus();
        const sel = window.getSelection();
        if (el.isContentEditable) {
            const range = document.createRange();
            range.selectNodeContents(el);
            sel.removeAllRanges(); sel.addRange(range);
        } else if (el.setSelectionRange) {
            el.setSelectionRange(0, (el.value || '').length);
        }
        const dt = new DataTransfer();
        dt.setData('text/plain', text);
        const ev = new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true });
        el.dispatchEvent(ev);
        return true;
    } catch (e) { return false; }
}

function writeExec(el, text) {
    try {
        el.focus();
        if (el.isContentEditable) {
            const range = document.createRange();
            range.selectNodeContents(el);
            const sel = window.getSelection();
            sel.removeAllRanges(); sel.addRange(range);
        } else if (el.setSelectionRange) {
            el.setSelectionRange(0, (el.value || '').length);
        }
        if (!document.execCommand('insertText', false, text)) return false;
        el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
        return true;
    } catch (e) { return false; }
}

function writeNative(el, text) {
    try {
        if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {
            const proto = Object.getPrototypeOf(el);
            const setter = Object.getOwnPropertyDescriptor(proto, 'value') &&
                           Object.getOwnPropertyDescriptor(proto, 'value').set;
            if (setter) setter.call(el, text); else el.value = text;
        } else {
            el.textContent = text;
        }
        el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
        return true;
    } catch (e) { return false; }
}

const WRITE_STRATEGIES = { react: writeReact, paste: writePaste, exec: writeExec, native: writeNative };

// Try this site's strategies in order, VERIFYING after each. Returns true only
// when the composer actually holds the requested text.
function setComposerText(el, text) {
    if (!el) return false;
    const a = adapter();
    const order = (a && a.write) || ['react', 'paste', 'exec', 'native'];
    for (let i = 0; i < order.length; i++) {
        const fn = WRITE_STRATEGIES[order[i]];
        if (!fn) continue;
        let attempted = false;
        try { attempted = fn(el, text); } catch (e) { attempted = false; }
        if (!attempted) continue;
        const now = readComposer(el);
        if (now === text || now.indexOf(text) !== -1) return true;
    }
    return false;
}

function simulateReplacement(element, text) {
    if (!element) return false;

    if (element.tagName !== 'INPUT' && element.tagName !== 'TEXTAREA') {
        const contentEditable = element.closest('[contenteditable="true"]');
        if (contentEditable) element = contentEditable;
    }

    // Per-site strategy chain, verified after each attempt.
    if (setComposerText(element, text)) return true;

    element.focus();

    // Strategy 1: the framework's own value setter. Doing this FIRST avoids
    // execCommand entirely for textarea/input composers.
    if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
        const proto = Object.getPrototypeOf(element);
        const nativeSetter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
        
        if (nativeSetter) {
            nativeSetter.call(element, text);
            element.dispatchEvent(new Event('input', { bubbles: true }));
        } else {
            element.value = text;
            element.dispatchEvent(new Event('input', { bubbles: true }));
        }
        return element.value === text;
    }

    // Strategy 2: contenteditable. Select ONLY this element's contents before
    // inserting — document.execCommand('selectAll') selected the whole page,
    // which escaped ProseMirror/Lexical composers (Claude, ChatGPT) and left
    // their internal model out of sync with the DOM, freezing the input.
    try {
        const range = document.createRange();
        range.selectNodeContents(element);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        if (document.execCommand('insertText', false, text)) {
            element.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
            return true;
        }
    } catch (e) {}

    // Strategy 3: last resort — replace the text node directly.
    try {
        element.textContent = text;
        element.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
        return true;
    } catch (e) {}
    return false;
}


// --- 6. AUTOCOMPLETE UI (Premium Prompt Recall) ---

let selectedSuggestionIndex = -1;
let currentSuggestionItems = [];
let currentTargetInput = null;
let suggestionDebounceTimer = null;
let suppressedText = '';        // Text inserted by "Use" — suppress popup until user types differently
let lastRenderedFingerprint = ''; // Avoid re-rendering identical results (keeps popup stable)

// Recall limits. A query longer than a phrase cannot autocomplete anything, and
// a buffer this large means the user pasted rather than typed.
const RECALL_MAX_BUFFER = 2000;   // skip recall entirely beyond this
const RECALL_MAX_QUERY = 120;     // longest needle worth sending to the worker

function fetchSuggestions(query, target) {
    // Match on the tail: that is where the caret is and what the user just typed.
    if (query.length > RECALL_MAX_QUERY) query = query.slice(-RECALL_MAX_QUERY);

    // If user just used a suggestion and text hasn't changed, suppress popup
    if (suppressedText && query.trim() === suppressedText.trim()) {
        return;
    }
    // If user typed beyond the suppressed text, clear suppression
    if (suppressedText && query.trim() !== suppressedText.trim()) {
        suppressedText = '';
    }

    // Fast debounce for Google Search-like responsiveness
    clearTimeout(suggestionDebounceTimer);
    suggestionDebounceTimer = setTimeout(() => {
        try {
            chrome.runtime.sendMessage({ action: 'search_history', query }, (response) => {
                if (chrome.runtime.lastError) return;
                if (response && response.matches && response.matches.length > 0) {
                    // Check if results actually changed — if same, keep popup stable (no flicker)
                    const fingerprint = response.matches.map(m => m.id).join(',');
                    if (suggestionBox && fingerprint === lastRenderedFingerprint) {
                        // Same results, popup already showing — do nothing (stable)
                        return;
                    }
                    currentTargetInput = target;
                    renderSuggestionBox(response.matches, target, query);
                    lastRenderedFingerprint = fingerprint;
                } else {
                    lastRenderedFingerprint = '';
                    removeSuggestionBox();
                }
            });
        } catch(e) {}
    }, 350); // typing-speed debounce: 150ms fired mid-word on every keystroke
}

function removeSuggestionBox() {
    if (suggestionBox) {
        suggestionBox.style.opacity = '0';
        suggestionBox.style.transform = 'translateY(8px)';
        setTimeout(() => {
            if (suggestionBox) {
                suggestionBox.remove();
                suggestionBox = null;
            }
        }, 150);
    }
    selectedSuggestionIndex = -1;
    currentSuggestionItems = [];
    currentTargetInput = null;
    lastRenderedFingerprint = '';
}

function getToolColor(tool) {
    const t = (tool || '').toLowerCase();
    if (t.includes('chatgpt')) return '#10a37f';
    if (t.includes('gemini')) return '#4285f4';
    if (t.includes('claude')) return '#d97706';
    if (t.includes('perplexity')) return '#14b8a6';
    if (t.includes('copilot')) return '#7c3aed';
    return '#6b7280';
}

function getToolIcon(tool) {
    const t = (tool || '').toLowerCase();
    if (t.includes('chatgpt')) return '◉';
    if (t.includes('gemini')) return '✦';
    if (t.includes('claude')) return '◈';
    if (t.includes('perplexity')) return '◎';
    if (t.includes('copilot')) return '◆';
    return '●';
}

function formatRelTime(timestamp) {
    if (!timestamp) return '';
    const now = new Date();
    const then = new Date(timestamp);
    const diff = now - then;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    const hours = Math.floor(mins / 60);
    if (hours < 24) return hours + 'h ago';
    const days = Math.floor(hours / 24);
    if (days < 7) return days + 'd ago';
    if (days < 30) return Math.floor(days / 7) + 'w ago';
    return then.toLocaleDateString();
}

function highlightMatch(text, query, maxLen) {
    if (!text) return '';
    const truncated = text.length > maxLen ? text.substring(0, maxLen) + '…' : text;
    if (!query || query.length < 2) return escapeForHtml(truncated);
    
    const lowerText = truncated.toLowerCase();
    const lowerQuery = query.toLowerCase();
    const idx = lowerText.indexOf(lowerQuery);
    
    if (idx === -1) return escapeForHtml(truncated);
    
    const before = truncated.substring(0, idx);
    const match = truncated.substring(idx, idx + query.length);
    const after = truncated.substring(idx + query.length);
    
    return escapeForHtml(before) + 
           '<span style="background:rgba(196,30,58,0.35);color:#ff8fa3;font-weight:600;border-radius:2px;padding:0 1px;">' + 
           escapeForHtml(match) + '</span>' + 
           escapeForHtml(after);
}

function escapeForHtml(text) {
    if (!text) return '';
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Keyboard navigation for suggestions
document.addEventListener('keydown', (e) => {
    if (!suggestionBox || currentSuggestionItems.length === 0) return;
    
    if (e.key === 'ArrowDown') {
        e.preventDefault();
        e.stopPropagation();
        selectedSuggestionIndex = Math.min(selectedSuggestionIndex + 1, currentSuggestionItems.length - 1);
        updateSuggestionHighlight();
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        e.stopPropagation();
        selectedSuggestionIndex = Math.max(selectedSuggestionIndex - 1, -1);
        updateSuggestionHighlight();
    } else if ((e.key === 'Tab' || e.key === 'Enter') && selectedSuggestionIndex >= 0 && suggestionBox) {
        e.preventDefault();
        e.stopPropagation();
        applySuggestion(currentSuggestionItems[selectedSuggestionIndex]);
    }
}, true);

function updateSuggestionHighlight() {
    if (!suggestionBox) return;
    const rows = suggestionBox.querySelectorAll('[data-suggestion-row]');
    rows.forEach((row, i) => {
        if (i === selectedSuggestionIndex) {
            row.style.backgroundColor = '#2a2a3a';
            row.style.borderLeft = '3px solid #c41e3a';
            row.scrollIntoView({ block: 'nearest' });
        } else {
            row.style.backgroundColor = 'transparent';
            row.style.borderLeft = '3px solid transparent';
        }
    });
}

function applySuggestion(item) {
    if (!item || !currentTargetInput) return;
    simulateReplacement(currentTargetInput, item.content);
    inputBuffer = item.content;
    // Suppress popup from re-appearing with the same inserted text
    suppressedText = item.content;
    removeSuggestionBox();
}

function renderSuggestionBox(items, targetInput, query) {
    removeSuggestionBox();
    selectedSuggestionIndex = -1;
    currentSuggestionItems = items;
    currentTargetInput = targetInput;
    
    const rect = targetInput.getBoundingClientRect();
    const itemHeight = 88; // approx height per suggestion row
    const headerHeight = 42;
    const boxHeight = Math.min(items.length * itemHeight + headerHeight, 400);
    
    const box = document.createElement('div');
    box.id = 'prompt-bin-autocomplete';
    
    // Inject animation keyframes if not already present
    if (!document.getElementById('prompt-bin-styles')) {
        const styleTag = document.createElement('style');
        styleTag.id = 'prompt-bin-styles';
        styleTag.textContent = `
            @keyframes pb-slide-in { 
                from { opacity: 0; transform: translateY(8px); } 
                to { opacity: 1; transform: translateY(0); } 
            }
            @keyframes pb-pulse { 
                0%, 100% { box-shadow: 0 0 0 0 rgba(196,30,58,0.2); }
                50% { box-shadow: 0 0 0 4px rgba(196,30,58,0.1); }
            }
            #prompt-bin-autocomplete * { box-sizing: border-box; }
        `;
        document.head.appendChild(styleTag);
    }
    
    box.style.cssText = `
        position: fixed;
        bottom: ${window.innerHeight - rect.top + 8}px;
        left: ${Math.max(8, rect.left)}px;
        width: ${Math.min(Math.max(rect.width, 380), 560)}px;
        max-height: ${boxHeight}px;
        background: #18181b;
        border: 1px solid rgba(196,30,58,0.4);
        border-radius: 12px;
        box-shadow: 0 -8px 40px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.04);
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        animation: pb-slide-in 0.2s ease-out;
        transition: opacity 0.15s, transform 0.15s;
    `;
    
    // --- Header ---
    const header = document.createElement('div');
    header.style.cssText = `
        background: linear-gradient(135deg, #c41e3a 0%, #9b1830 100%);
        color: white;
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 8px 14px;
        flex-shrink: 0;
    `;
    
    const titleWrap = document.createElement('div');
    titleWrap.style.cssText = 'display:flex; align-items:center; gap:8px;';
    
    const logoSpan = document.createElement('span');
    logoSpan.innerText = '⚡';
    logoSpan.style.cssText = 'font-size:13px;';
    
    const titleText = document.createElement('span');
    titleText.innerText = 'PROMPT RECALL';
    titleText.style.cssText = 'font-size:10px; font-weight:700; letter-spacing:1.5px; opacity:0.95;';
    
    const countBadge = document.createElement('span');
    countBadge.innerText = items.length + ' match' + (items.length > 1 ? 'es' : '');
    countBadge.style.cssText = 'font-size:9px; background:rgba(255,255,255,0.2); padding:2px 7px; border-radius:10px; font-weight:500;';
    
    titleWrap.appendChild(logoSpan);
    titleWrap.appendChild(titleText);
    titleWrap.appendChild(countBadge);
    
    const closeBtn = document.createElement('span');
    closeBtn.innerText = '✕';
    closeBtn.style.cssText = 'cursor:pointer; font-size:13px; opacity:0.7; padding:2px 4px; border-radius:4px; transition:all 0.15s;';
    closeBtn.onmouseenter = () => { closeBtn.style.opacity = '1'; closeBtn.style.background = 'rgba(255,255,255,0.15)'; };
    closeBtn.onmouseleave = () => { closeBtn.style.opacity = '0.7'; closeBtn.style.background = 'none'; };
    closeBtn.onclick = (e) => { e.stopPropagation(); removeSuggestionBox(); };
    
    header.appendChild(titleWrap);
    header.appendChild(closeBtn);
    box.appendChild(header);
    
    // --- Suggestion List ---
    const listContainer = document.createElement('div');
    listContainer.style.cssText = 'overflow-y:auto; flex:1; scrollbar-width:thin; scrollbar-color:#333 transparent;';
    
    items.forEach((item, index) => {
        const row = document.createElement('div');
        row.setAttribute('data-suggestion-row', index);
        row.style.cssText = `
            padding: 10px 14px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            cursor: pointer;
            display: flex;
            flex-direction: column;
            gap: 6px;
            transition: background 0.15s, border-left 0.15s;
            border-left: 3px solid transparent;
        `;
        
        // --- Top row: Tool badge + Time + Chat link ---
        const metaRow = document.createElement('div');
        metaRow.style.cssText = 'display:flex; align-items:center; justify-content:space-between; width:100%;';
        
        const leftMeta = document.createElement('div');
        leftMeta.style.cssText = 'display:flex; align-items:center; gap:8px;';
        
        const toolColor = getToolColor(item.aiTool);
        const badge = document.createElement('span');
        badge.innerHTML = getToolIcon(item.aiTool) + ' ' + escapeForHtml((item.aiTool || 'AI').toUpperCase());
        badge.style.cssText = `
            background: ${toolColor}18;
            color: ${toolColor};
            border: 1px solid ${toolColor}40;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 9px;
            letter-spacing: 0.5px;
        `;
        
        const timeSpan = document.createElement('span');
        timeSpan.innerText = formatRelTime(item.timestamp);
        timeSpan.style.cssText = 'color:#6b7280; font-size:10px;';
        
        leftMeta.appendChild(badge);
        leftMeta.appendChild(timeSpan);
        
        const rightMeta = document.createElement('div');
        rightMeta.style.cssText = 'display:flex; align-items:center; gap:6px;';
        
        // Chat link button (if sessionUrl exists)
        if (item.sessionUrl && item.sessionUrl !== 'unknown') {
            const linkBtn = document.createElement('a');
            linkBtn.href = item.sessionUrl;
            linkBtn.target = '_blank';
            linkBtn.rel = 'noopener';
            linkBtn.title = 'View original chat';
            linkBtn.innerHTML = '↗ Chat';
            linkBtn.style.cssText = `
                color: #60a5fa;
                font-size: 10px;
                font-weight: 600;
                text-decoration: none;
                background: rgba(96,165,250,0.1);
                border: 1px solid rgba(96,165,250,0.25);
                padding: 2px 8px;
                border-radius: 4px;
                transition: all 0.15s;
                display: inline-flex;
                align-items: center;
                gap: 3px;
            `;
            linkBtn.onmouseenter = () => {
                linkBtn.style.background = 'rgba(96,165,250,0.2)';
                linkBtn.style.borderColor = 'rgba(96,165,250,0.5)';
                linkBtn.style.color = '#93bbfc';
            };
            linkBtn.onmouseleave = () => {
                linkBtn.style.background = 'rgba(96,165,250,0.1)';
                linkBtn.style.borderColor = 'rgba(96,165,250,0.25)';
                linkBtn.style.color = '#60a5fa';
            };
            linkBtn.onmousedown = (e) => e.stopPropagation(); // Don't trigger row click
            rightMeta.appendChild(linkBtn);
        }
        
        // Use prompt button
        const useBtn = document.createElement('span');
        useBtn.innerHTML = '⏎ Use';
        useBtn.title = 'Insert this prompt';
        useBtn.style.cssText = `
            color: #4ade80;
            font-size: 10px;
            font-weight: 600;
            background: rgba(74,222,128,0.1);
            border: 1px solid rgba(74,222,128,0.25);
            padding: 2px 8px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.15s;
        `;
        useBtn.onmouseenter = () => {
            useBtn.style.background = 'rgba(74,222,128,0.25)';
            useBtn.style.borderColor = 'rgba(74,222,128,0.5)';
        };
        useBtn.onmouseleave = () => {
            useBtn.style.background = 'rgba(74,222,128,0.1)';
            useBtn.style.borderColor = 'rgba(74,222,128,0.25)';
        };
        useBtn.onmousedown = (e) => {
            e.preventDefault();
            e.stopPropagation();
            applySuggestion(item);
        };
        rightMeta.appendChild(useBtn);
        
        metaRow.appendChild(leftMeta);
        metaRow.appendChild(rightMeta);
        
        // --- Prompt preview with highlighted match ---
        const contentDiv = document.createElement('div');
        contentDiv.innerHTML = highlightMatch(item.content, query, 160);
        contentDiv.style.cssText = `
            color: #d1d5db;
            font-size: 12px;
            line-height: 1.5;
            font-family: "SF Mono", "Fira Code", "JetBrains Mono", monospace;
            overflow: hidden;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            word-break: break-word;
        `;
        
        // --- Tags ---
        if (item.tags && item.tags.length > 0) {
            const tagsRow = document.createElement('div');
            tagsRow.style.cssText = 'display:flex; gap:4px; flex-wrap:wrap;';
            item.tags.slice(0, 3).forEach(tag => {
                const tagEl = document.createElement('span');
                tagEl.innerText = tag;
                tagEl.style.cssText = 'font-size:9px; color:#9ca3af; background:rgba(255,255,255,0.05); padding:1px 6px; border-radius:3px; border:1px solid rgba(255,255,255,0.08);';
                tagsRow.appendChild(tagEl);
            });
            row.appendChild(metaRow);
            row.appendChild(contentDiv);
            row.appendChild(tagsRow);
        } else {
            row.appendChild(metaRow);
            row.appendChild(contentDiv);
        }
        
        // Hover effects
        row.onmouseenter = () => {
            if (selectedSuggestionIndex !== index) {
                row.style.backgroundColor = '#1f1f2e';
                row.style.borderLeft = '3px solid rgba(196,30,58,0.4)';
            }
        };
        row.onmouseleave = () => {
            if (selectedSuggestionIndex !== index) {
                row.style.backgroundColor = 'transparent';
                row.style.borderLeft = '3px solid transparent';
            }
        };
        
        // Click the row body to insert
        row.onmousedown = (e) => {
            // Don't trigger if clicking the chat link
            if (e.target.tagName === 'A' || e.target.closest('a')) return;
            e.preventDefault();
            e.stopPropagation();
            applySuggestion(item);
        };
        
        listContainer.appendChild(row);
    });
    
    box.appendChild(listContainer);
    
    // --- Footer hint ---
    const footer = document.createElement('div');
    footer.style.cssText = `
        padding: 5px 14px;
        background: rgba(0,0,0,0.3);
        border-top: 1px solid rgba(255,255,255,0.06);
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-shrink: 0;
    `;
    
    const hintLeft = document.createElement('span');
    hintLeft.innerHTML = '<span style="color:#6b7280;font-size:9px;">↑↓ Navigate</span> <span style="color:#4b5563;font-size:9px;">•</span> <span style="color:#6b7280;font-size:9px;">Tab/Enter Select</span> <span style="color:#4b5563;font-size:9px;">•</span> <span style="color:#6b7280;font-size:9px;">Esc Close</span>';
    
    const hintRight = document.createElement('span');
    hintRight.style.cssText = 'font-size:9px; color:#4b5563;';
    hintRight.innerText = 'Promptrix';
    
    footer.appendChild(hintLeft);
    footer.appendChild(hintRight);
    box.appendChild(footer);
    
    document.body.appendChild(box);
    suggestionBox = box;
}