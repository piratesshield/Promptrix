// Background Service Worker — Promptrix v7.1
// Features: Capture, Cloud Sync (MV3 safe), Multi-Tag, Star, Sync Config, DLP

// Load the shared DLP engine so the worker knows the default policy, storage
// keys and log cap. Wrapped in try/catch so a load failure never bricks capture.
try {
  importScripts('pattern-library.js');
  importScripts('content-inspector.js');
  importScripts('dlp-engine.js');
  importScripts('siem-forwarder.js');
} catch (e) {
  warn('[Promptrix] DLP engine failed to load in worker:', e && e.message);
}
const DLP = self.PromptrixDLP || null;
const DLP_POLICY_KEY = (DLP && DLP.STORAGE_KEYS.policy) || 'prompt_bin_dlp_policy';
const DLP_LOGS_KEY = (DLP && DLP.STORAGE_KEYS.logs) || 'prompt_bin_dlp_logs';
const DLP_LOG_LIMIT = (DLP && DLP.LOG_LIMIT) || 1000;

// Debug-gated logging — set prompt_bin_debug=true in storage to enable
let _debugEnabled = false;
try { chrome.storage.local.get(['prompt_bin_debug'], r => { _debugEnabled = !!(r && r.prompt_bin_debug); }); } catch (e) {}
const log = (...args) => { if (_debugEnabled) console.log(...args); };
const warn = (...args) => { if (_debugEnabled) console.warn(...args); };

// ── Credential encryption (AES-256-GCM) ─────────────────────────────────
const CRED_SALT_KEY = 'prompt_bin_cred_salt';
let _credKey = null;

async function getCredKey() {
  if (_credKey) return _credKey;
  const r = await chrome.storage.local.get([CRED_SALT_KEY]);
  let salt = r[CRED_SALT_KEY];
  if (!salt) {
    salt = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    await chrome.storage.local.set({ [CRED_SALT_KEY]: salt });
  }
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(chrome.runtime.id + salt), 'PBKDF2', false, ['deriveKey']);
  _credKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('promptrix-cred-v1'), iterations: 100000, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
  return _credKey;
}

async function encryptValue(plaintext) {
  if (!plaintext) return plaintext;
  try {
    const key = await getCredKey();
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
    return { _enc: 1, iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
  } catch (e) { return plaintext; }
}

async function decryptValue(stored) {
  if (!stored || typeof stored !== 'object' || !stored._enc) return stored;
  try {
    const key = await getCredKey();
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(stored.iv) },
      key, new Uint8Array(stored.ct)
    );
    return new TextDecoder().decode(pt);
  } catch (e) { return ''; }
}

async function encryptProfileAuth(profile) {
  if (!profile || !profile.auth) return profile;
  const a = { ...profile.auth };
  if (a.token) a.token = await encryptValue(a.token);
  if (a.password) a.password = await encryptValue(a.password);
  if (a.headerValue) a.headerValue = await encryptValue(a.headerValue);
  if (a.secret) a.secret = await encryptValue(a.secret);
  if (a.paramValue) a.paramValue = await encryptValue(a.paramValue);
  return { ...profile, auth: a };
}

async function decryptProfileAuth(profile) {
  if (!profile || !profile.auth) return profile;
  const a = { ...profile.auth };
  a.token = await decryptValue(a.token);
  a.password = await decryptValue(a.password);
  a.headerValue = await decryptValue(a.headerValue);
  a.secret = await decryptValue(a.secret);
  a.paramValue = await decryptValue(a.paramValue);
  return { ...profile, auth: a };
}

// ── DLP Policy Integrity (HMAC-SHA256) ───────────────────────────────────
const DLP_HMAC_KEY = 'prompt_bin_dlp_policy_hmac';
let _hmacKey = null;

async function getHmacKey() {
  if (_hmacKey) return _hmacKey;
  const r = await chrome.storage.local.get([CRED_SALT_KEY]);
  const salt = r[CRED_SALT_KEY] || 'default';
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(chrome.runtime.id + salt), 'PBKDF2', false, ['deriveKey']);
  _hmacKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('promptrix-policy-hmac-v1'), iterations: 100000, hash: 'SHA-256' },
    km, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']
  );
  return _hmacKey;
}

async function signPolicy(policy) {
  try {
    const key = await getHmacKey();
    const enc = new TextEncoder();
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(JSON.stringify(policy)));
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) { return null; }
}

async function verifyPolicy(policy, hmac) {
  if (!hmac) return false;
  try {
    const computed = await signPolicy(policy);
    return computed === hmac;
  } catch (e) { return false; }
}

// --- UTILITIES ---

// chrome.storage is async IPC, so a read-modify-write on a shared array races
// whenever two events land in the same tick — every in-flight handler reads the
// same snapshot and the last write wins, silently discarding the others. This
// was observed losing 17 of 20 audit-log entries under load. Every mutation of
// a shared collection goes through this queue.
let storageLock = Promise.resolve();
function storageSerial(fn) {
  const run = storageLock.then(fn, fn);
  storageLock = run.then(() => {}, () => {});
  return run;
}

// Prepend `entry` to the array at `key`, capped at `limit`. Returns the new length.
function prependCapped(key, entry, limit) {
  return storageSerial(async () => {
    const r = await chrome.storage.local.get([key]);
    const list = r[key] || [];
    const updated = [entry, ...list].slice(0, limit);
    await chrome.storage.local.set({ [key]: updated });
    return updated.length;
  });
}

function prependCappedTiered(key, entry, limit) {
  return storageSerial(async () => {
    const r = await chrome.storage.local.get([key]);
    let list = [entry, ...(r[key] || [])];
    if (list.length <= limit) {
      await chrome.storage.local.set({ [key]: list });
      return list.length;
    }
    const isHP = e => { const s = (e.maxSeverity || '').toUpperCase(); return s === 'HIGH' || s === 'CRITICAL'; };
    const excess = list.length - limit;
    let toRemove = excess;
    const keep = new Array(list.length).fill(true);
    for (let i = list.length - 1; i >= 0 && toRemove > 0; i--) {
      if (!isHP(list[i])) { keep[i] = false; toRemove--; }
    }
    for (let i = list.length - 1; i >= 0 && toRemove > 0; i--) {
      if (keep[i]) { keep[i] = false; toRemove--; }
    }
    list = list.filter((_, i) => keep[i]);
    await chrome.storage.local.set({ [key]: list });
    return list.length;
  });
}

// ── Capture store budget ──────────────────────────────────────────────
// The store used to be capped at 5000 ITEMS with no regard for their size. A
// single pasted prompt can be 7 KB, so 5000 items reached ~33 MB — far past the
// 10 MB chrome.storage.local quota, at which point every write throws. Worse,
// each capture rewrote the entire array (~100 ms of JSON work at that volume)
// inside the worker, so every message the page sent queued behind it. That is
// what made the tab hang and eventually crash. Budget by BYTES instead.
const CAPTURE_MAX_ITEMS = 5000;
const CAPTURE_MAX_BYTES = 4 * 1024 * 1024;   // well inside the quota
const CAPTURE_MAX_CONTENT = 20000;           // per item; recall never needs more

// Keep a bounded prefix of very long content. The full text has already been
// forwarded to Cloud Sync / Gist / SIEM if those are configured; the local copy
// exists for recall and search, which only need the beginning.
function clampContent(text) {
  const t = String(text || '');
  if (t.length <= CAPTURE_MAX_CONTENT) return t;
  return t.slice(0, CAPTURE_MAX_CONTENT) +
    '\n\n[… truncated by Promptrix: ' + (t.length - CAPTURE_MAX_CONTENT) + ' more characters]';
}

// Rough byte cost of one entry WITHOUT serialising it. Calling
// JSON.stringify() on the whole array per capture would reintroduce exactly the
// multi-hundred-millisecond stall this budget exists to prevent (measured: the
// first draft of this function took >2 minutes for 600 captures). Content is
// the only field that varies materially, so estimate from it.
const CAPTURE_META_BYTES = 320;          // id, timestamps, tags, url, flags
const CAPTURE_STARRED_RESERVE = 512 * 1024;

function itemCost(it) {
  if (!it) return 0;
  return (it.content ? it.content.length : 0) + CAPTURE_META_BYTES;
}

// Single pass, newest first, integer math only. Starred items that fall outside
// the main budget get a small reserve — the user explicitly marked them.
function fitCaptureBudget(list) {
  const kept = [], overflowStarred = [];
  let bytes = 0;
  for (let i = 0; i < list.length; i++) {
    const it = list[i];
    if (!it) continue;
    const cost = itemCost(it);
    if (kept.length < CAPTURE_MAX_ITEMS && bytes + cost <= CAPTURE_MAX_BYTES) {
      kept.push(it); bytes += cost;
    } else if (it.starred && bytes + cost <= CAPTURE_MAX_BYTES + CAPTURE_STARRED_RESERVE) {
      overflowStarred.push(it); bytes += cost;
    }
  }
  return overflowStarred.length ? kept.concat(overflowStarred) : kept;
}

const estimateTokens = (text) => {
  if (!text) return 0;
  const chars = text.length;
  const words = text.trim().split(/\s+/).length;
  const hasCode = /```|def |function |class |import |const |var |\{|\}/.test(text);
  let tokenCount = hasCode ? Math.ceil(chars / 3.5) : Math.ceil(chars / 4);
  return Math.max(tokenCount, Math.ceil(words * 1.33));
};

// --- MULTI-TAG EXTRACTION ---

const KEYWORD_MAP = {
  'react': 'React', 'hooks': 'React', 'jsx': 'React', 'component': 'React', 'useState': 'React', 'useEffect': 'React', 'nextjs': 'React', 'next.js': 'React',
  'python': 'Python', 'pip': 'Python', 'django': 'Python', 'flask': 'Python', 'pandas': 'Python', 'numpy': 'Python',
  'javascript': 'JavaScript', 'typescript': 'TypeScript', 'node': 'Node.js', 'express': 'Node.js', 'npm': 'Node.js',
  'css': 'CSS', 'html': 'HTML', 'tailwind': 'CSS',
  'sql': 'Database', 'database': 'Database', 'mongodb': 'Database', 'postgres': 'Database', 'mysql': 'Database', 'redis': 'Database',
  'api': 'API', 'rest': 'API', 'graphql': 'API', 'endpoint': 'API', 'fetch': 'API',
  'docker': 'DevOps', 'kubernetes': 'DevOps', 'k8s': 'DevOps', 'ci/cd': 'DevOps', 'deploy': 'DevOps', 'nginx': 'DevOps',
  'aws': 'Cloud', 'azure': 'Cloud', 'gcp': 'Cloud', 'cloud': 'Cloud', 's3': 'Cloud', 'lambda': 'Cloud',
  'security': 'Security', 'xss': 'Security', 'csrf': 'Security', 'auth': 'Security', 'oauth': 'Security', 'jwt': 'Security', 'vulnerability': 'Security', 'encryption': 'Security',
  'ai': 'AI/ML', 'machine learning': 'AI/ML', 'model': 'AI/ML', 'neural': 'AI/ML', 'llm': 'AI/ML', 'gpt': 'AI/ML', 'transformer': 'AI/ML',
  'git': 'Git', 'github': 'Git', 'merge': 'Git', 'branch': 'Git', 'commit': 'Git',
  'test': 'Testing', 'jest': 'Testing', 'unittest': 'Testing', 'pytest': 'Testing', 'testing': 'Testing',
  'debug': 'Debugging', 'error': 'Debugging', 'fix': 'Debugging', 'bug': 'Debugging', 'crash': 'Debugging', 'traceback': 'Debugging',
  'write': 'Writing', 'essay': 'Writing', 'blog': 'Writing', 'email': 'Writing', 'letter': 'Writing',
  'math': 'Math', 'calculate': 'Math', 'equation': 'Math', 'formula': 'Math',
};

function extractTags(text) {
  if (!text) return ['General'];
  const lower = text.toLowerCase();
  const tags = new Set();

  for (const [keyword, tag] of Object.entries(KEYWORD_MAP)) {
    if (lower.includes(keyword)) tags.add(tag);
  }

  if (/```|function\s|const\s|let\s|var\s|=>\s|class\s|import\s|def\s|return\s/.test(text)) tags.add('Code');
  if (/^(how|what|why|when|where|can|could|should|is|are|do|does)\s/i.test(text.trim())) tags.add('Question');
  if (/explain|describe|summarize|break down|walk me through/i.test(lower)) tags.add('Explanation');

  if (tags.size === 0) tags.add('General');
  return Array.from(tags).slice(0, 4);
}

// --- CLOUD SYNC (MV3 compatible — no setTimeout reliance) ---

// Push captures to Cloudflare Worker. Returns { success, error/message }.
async function syncToCloud(captures) {
  const logTag = '[Promptrix Sync]';
  try {
    const result = await chrome.storage.local.get(['prompt_bin_sync_config']);
    const config = result['prompt_bin_sync_config'];
    if (config && config.syncToken) config.syncToken = await decryptValue(config.syncToken);

    if (!config) {
      console.warn(logTag, 'No sync config found');
      return { success: false, error: 'No sync config found. Go to Settings and save your Worker URL + token.' };
    }
    if (!config.workerUrl) {
      console.warn(logTag, 'Worker URL is empty');
      return { success: false, error: 'Worker URL is empty' };
    }
    if (!config.syncToken) {
      console.warn(logTag, 'Sync token is empty');
      return { success: false, error: 'Sync token is empty' };
    }
    if (!config.enabled) {
      console.warn(logTag, 'Sync is disabled');
      return { success: false, error: 'Cloud sync is disabled. Toggle it ON in Settings.' };
    }

    const workerUrl = config.workerUrl.replace(/\/$/, '');
    console.log(logTag, `Pushing ${captures.length} captures to ${workerUrl}/api/push`);

    const response = await fetch(workerUrl + '/api/push', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Sync-Token': config.syncToken,
      },
      body: JSON.stringify({ captures }),
    });

    if (response.ok) {
      const data = await response.json();
      console.log(logTag, 'SUCCESS:', data.message);
      return { success: true, message: data.message };
    } else {
      let errText = 'HTTP ' + response.status;
      if (response.status === 401) errText = 'Invalid sync token (401 Unauthorized)';
      else if (response.status === 404) errText = 'Worker endpoint not found (404). Check your Worker URL.';
      try { const body = await response.text(); errText += ' — ' + body; } catch(e) {}
      console.warn(logTag, 'FAILED:', errText);
      return { success: false, error: errText };
    }
  } catch (e) {
    console.error(logTag, 'NETWORK ERROR:', e);
    return { success: false, error: 'Network error: ' + e.message };
  }
}

async function syncToGist() {
  try {
    const res = await chrome.storage.local.get(['prompt_bin_gist_config', 'prompt_bin_captures']);
    const config = res['prompt_bin_gist_config'];
    if (config && config.pat) config.pat = await decryptValue(config.pat);
    const captures = res['prompt_bin_captures'] || [];

    if (!config || !config.autoSync || !config.pat) return;

    const method = config.gistId ? 'PATCH' : 'POST';
    const url = config.gistId ? `https://api.github.com/gists/${config.gistId}` : 'https://api.github.com/gists';

    const response = await fetch(url, {
      method,
      headers: {
        'Authorization': `token ${config.pat}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        description: `Promptrix Backup — ${new Date().toISOString().slice(0, 10)}`,
        public: false,
        files: {
          'prompt_bin_backup.json': { content: JSON.stringify(captures, null, 2) }
        }
      }),
    });

    if (response.ok) {
      const data = await response.json();
      if (!config.gistId) {
         chrome.storage.local.set({ 'prompt_bin_gist_config': { ...config, gistId: data.id } });
      }
      log('[Promptrix] Gist auto-sync success');
    } else {
      warn('[Promptrix] Gist auto-sync failed:', response.status);
    }
  } catch (e) {
    warn('[Promptrix] Gist auto-sync error:', e.message);
  }
}

// MV3-safe: Sync immediately on capture instead of using unreliable setTimeout.
// In MV3, the service worker can be killed at any time, so debounce timers are broken.
async function immediateCloudSync(newItem) {
  try {
    const result = await chrome.storage.local.get(['prompt_bin_sync_config']);
    const config = result['prompt_bin_sync_config'];
    if (config && config.syncToken) config.syncToken = await decryptValue(config.syncToken);
    if (!config || !config.enabled || !config.workerUrl || !config.syncToken) return;

    log('[Promptrix] Immediate sync for new capture...');
    const workerUrl = config.workerUrl.replace(/\/$/, '');
    const response = await fetch(workerUrl + '/api/push', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Sync-Token': config.syncToken,
      },
      body: JSON.stringify({ captures: [newItem] }),
    });

    if (response.ok) {
      const data = await response.json();
      log('[Promptrix] Auto-sync success:', data.message);
    } else {
      warn('[Promptrix] Auto-sync failed:', response.status);
    }
  } catch (e) {
    warn('[Promptrix] Auto-sync error:', e.message);
  }
}

// ─── LOG FORWARDING (SIEM webhooks) ────────────────────────────────────────
// Events are spooled to storage and flushed on a batch/interval trigger rather
// than sent one-per-event: MV3 service workers are killed at will, and HTTP log
// forwarding is explicitly a lossy transport at volume (Palo Alto documents
// this for their own HTTP profiles), so durability lives on disk, not in RAM.

const SIEM = self.PromptrixSIEM || null;
const SIEM_PROFILES_KEY = (SIEM && SIEM.STORAGE_KEYS.profiles) || 'prompt_bin_siem_profiles';
const SIEM_SPOOL_KEY = (SIEM && SIEM.STORAGE_KEYS.spool) || 'prompt_bin_siem_spool';
const SIEM_HEALTH_KEY = (SIEM && SIEM.STORAGE_KEYS.health) || 'prompt_bin_siem_health';
const SIEM_ALARM = 'promptrix-siem-flush';

// Storage is read-modify-write, and capture events arrive concurrently (a page
// can fire several in the same tick). Without serialisation every in-flight
// emit reads the same spool and the last write wins — silently discarding
// every other event. All spool/health mutations run through this queue.
let siemLock = Promise.resolve();
function siemSerial(fn) {
  const run = siemLock.then(fn, fn);
  siemLock = run.then(() => {}, () => {});
  return run;
}

async function siemProfiles() {
  if (!SIEM) return [];
  const r = await chrome.storage.local.get([SIEM_PROFILES_KEY]);
  return (r[SIEM_PROFILES_KEY] || []).map(SIEM.normalizeProfile);
}

// Fan an event out to every profile that subscribes to it. Each profile gets
// its OWN projection, because content-inclusion is a per-profile decision.
async function siemEmit(kind, payload, meta) {
  if (!SIEM) return;
  try {
    const evt = SIEM.toEvent(kind, payload, meta || {});
    // Profiles are read INSIDE the lock: reading them first let an event queue
    // itself against a profile the operator deleted a moment earlier, which
    // recreated that profile's spool entry after it had been pruned.
    const ready = await siemSerial(async () => {
      const r = await chrome.storage.local.get([SIEM_SPOOL_KEY, SIEM_PROFILES_KEY]);
      const profiles = (r[SIEM_PROFILES_KEY] || []).map(SIEM.normalizeProfile).filter(p => p.enabled && p.url);
      if (!profiles.length) return false;
      const spool = r[SIEM_SPOOL_KEY] || {};
      let queued = false;
      for (const p of profiles) {
        if (!SIEM.passesFilter(evt, p)) continue;
        const projected = SIEM.projectForProfile(evt, p);
        (spool[p.id] = spool[p.id] || []).push(projected);
        if (spool[p.id].length > SIEM.SPOOL_CAP) spool[p.id] = spool[p.id].slice(-SIEM.SPOOL_CAP);
        queued = true;
      }
      if (!queued) return false;
      await chrome.storage.local.set({ [SIEM_SPOOL_KEY]: spool });
      return profiles.some(p => (spool[p.id] || []).length >= p.batchSize);
    });
    // Flush now if any profile reached its batch size; else let the alarm do it.
    if (ready) siemFlush();
    else siemEnsureAlarm();
  } catch (e) {
    warn('[Promptrix SIEM] emit failed:', e && e.message);
  }
}

function siemEnsureAlarm() {
  try {
    if (!chrome.alarms) return;
    chrome.alarms.get(SIEM_ALARM, (a) => { if (!a) chrome.alarms.create(SIEM_ALARM, { periodInMinutes: 1 }); });
  } catch (e) {}
}

// Drain each profile's spool. On failure the batch is put BACK at the head so
// nothing is dropped until the spool cap forces it.
async function siemFlush(force) {
  if (!SIEM) return { flushed: 0 };
  // Claim the batches under the lock, deliver OUTSIDE it (network latency must
  // not block incoming events), then re-merge the results under the lock again.
  // The profile list is read INSIDE the lock: reading it beforehand let a
  // concurrent delete slip through, and the claim phase would then rewrite the
  // spool for a profile that no longer existed.
  let profiles = [];
  const claimed = await siemSerial(async () => {
    const pr = await chrome.storage.local.get([SIEM_PROFILES_KEY]);
    const rawProfiles = (pr[SIEM_PROFILES_KEY] || []).map(SIEM.normalizeProfile).filter(p => p.enabled && p.url);
    profiles = await Promise.all(rawProfiles.map(p => decryptProfileAuth(p)));
    if (!profiles.length) return {};
    const r = await chrome.storage.local.get([SIEM_SPOOL_KEY, SIEM_HEALTH_KEY]);
    const spool = r[SIEM_SPOOL_KEY] || {};
    const health = r[SIEM_HEALTH_KEY] || {};
    const take = {};
    for (const p of profiles) {
      const q = spool[p.id] || [];
      if (!q.length) continue;
      // Age the batch from the OLDEST QUEUED EVENT, not from the last delivery
      // attempt. Keying off lastAttempt meant a never-flushed profile had
      // lastAttempt 0, so it read as perpetually due and any other profile's
      // flush dragged it along — a profile set to batch 50 was being shipped in
      // ones and twos, which matters when the SIEM bills per request.
      const oldest = Date.parse((q[0] && q[0].ts) || '') || 0;
      const waited = oldest ? (Date.now() - oldest) : Infinity;
      const due = force || q.length >= p.batchSize || waited >= p.flushSeconds * 1000;
      if (!due) continue;
      take[p.id] = q.slice(0, p.batchSize);
      spool[p.id] = q.slice(take[p.id].length);      // remove now; restore on failure
    }
    if (Object.keys(take).length) await chrome.storage.local.set({ [SIEM_SPOOL_KEY]: spool });
    return take;
  });
  if (!Object.keys(claimed).length) return { flushed: 0 };

  const results = {};
  for (const p of profiles) {
    if (!claimed[p.id]) continue;
    // A missing host permission surfaces from fetch() as a bare "Failed to
    // fetch", indistinguishable from DNS/TLS failure. Check first so the
    // forwarder's health card names the real problem, and mark it retryable so
    // the batch is retained rather than burned against a wall.
    const access = await siemHostAccess(p.url);
    results[p.id] = access.ok
      ? await SIEM.deliverWithRetry(p, claimed[p.id])
      : { ok: false, status: 0, error: access.error, ms: 0, retryable: true };
  }

  return await siemSerial(async () => {
  const r = await chrome.storage.local.get([SIEM_SPOOL_KEY, SIEM_HEALTH_KEY, SIEM_PROFILES_KEY]);
  const spool = r[SIEM_SPOOL_KEY] || {};
  const health = r[SIEM_HEALTH_KEY] || {};
  // The profile list is re-read here because a delete can land between the
  // claim and the merge. Restoring a failed batch for a profile the operator
  // has since removed would resurrect its queue and leak it back into storage.
  const stillConfigured = new Set((r[SIEM_PROFILES_KEY] || []).map(x => x && x.id));
  let flushed = 0;

  for (const p of profiles) {
    const batch = claimed[p.id];
    if (!batch) continue;
    if (!stillConfigured.has(p.id)) {            // deleted mid-flight — drop it
      delete spool[p.id]; delete health[p.id];
      continue;
    }
    const res = results[p.id];
    const h = health[p.id] || { ok: 0, fail: 0, consecutiveFailures: 0 };
    h.lastAttempt = Date.now();
    h.lastStatus = res.status;
    h.lastMs = res.ms;
    if (res.ok) {
      h.ok = (h.ok || 0) + batch.length;
      h.consecutiveFailures = 0;
      h.lastSuccess = Date.now();
      h.lastError = null;
      flushed += batch.length;
    } else {
      h.fail = (h.fail || 0) + 1;
      h.consecutiveFailures = (h.consecutiveFailures || 0) + 1;
      h.lastError = res.error;
      // Delivery failed — put the claimed batch BACK at the head of the queue
      // so nothing is lost, capped so a permanently-dead endpoint cannot grow
      // the spool without bound.
      spool[p.id] = batch.concat(spool[p.id] || []).slice(0, SIEM.SPOOL_CAP);
    }
    h.queued = (spool[p.id] || []).length;
    health[p.id] = h;
  }
  await chrome.storage.local.set({ [SIEM_SPOOL_KEY]: spool, [SIEM_HEALTH_KEY]: health });
  return { flushed };
  });
}

if (chrome.alarms && chrome.alarms.onAlarm) {
  chrome.alarms.onAlarm.addListener((a) => { if (a.name === SIEM_ALARM) siemFlush(); });
}

// --- DLP: seed the default-ON policy on install so it is active immediately ---
if (chrome.runtime && chrome.runtime.onInstalled) {
  chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.get([DLP_POLICY_KEY], (res) => {
      if (!res[DLP_POLICY_KEY]) {
        const policy = DLP ? DLP.defaultPolicy() : { masking: true, blocking: false, warning: true, labeling: true, patterns: {} };
        chrome.storage.local.set({ [DLP_POLICY_KEY]: policy });
        log('[Promptrix DLP] Seeded default policy (masking ON, blocking OFF).');
      }
    });
  });
}

// --- URL TRACKING ---

if (chrome.webNavigation && chrome.webNavigation.onHistoryStateUpdated) {
  chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
    if (details.frameId === 0) {
      chrome.tabs.sendMessage(details.tabId, {
        action: 'url_changed',
        url: details.url
      }).catch(() => {});
    }
  });
}

// --- STORAGE LOGIC ---

// Does the extension actually hold host permission for this endpoint? The
// pattern must use hostname (no port) — a port makes it an invalid match
// pattern and permissions.contains() then throws instead of returning false.
function siemHostAccess(url) {
  return new Promise(resolve => {
    let u;
    try { u = new URL(url); } catch (e) {
      resolve({ ok: false, error: 'Invalid endpoint URL: ' + url }); return;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      resolve({ ok: false, error: 'Endpoint must be http:// or https:// (got ' + u.protocol + ')' }); return;
    }
    if (!chrome.permissions) { resolve({ ok: true }); return; }
    const pattern = u.protocol + '//' + u.hostname + '/*';
    try {
      chrome.permissions.contains({ origins: [pattern] }, has => {
        if (chrome.runtime.lastError) { resolve({ ok: true }); return; }  // can't tell — let the fetch decide
        resolve(has ? { ok: true } : {
          ok: false,
          error: 'No host permission for ' + pattern +
                 '. Open the forwarder and press Save (or Send test event) and accept Chrome\'s permission prompt.',
        });
      });
    } catch (e) { resolve({ ok: true }); }
  });
}

const SENSITIVE_ACTIONS = new Set([
  'clear_all', 'save_sync_config', 'force_sync', 'test_sync_connection',
  'save_gist_config', 'save_dlp_policy', 'clear_dlp_logs',
  'save_siem_profiles', 'test_siem_profile',
]);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  if (SENSITIVE_ACTIONS.has(request.action) && sender.id !== chrome.runtime.id) {
    sendResponse({ success: false, error: 'Unauthorized sender' });
    return true;
  }

  // 1. CAPTURE & SAVE
  if (request.action === 'capture') {
    const { type, aiTool, sessionUrl } = request.data;
    let content = request.data.content;
    if (!content || content.length < 2) return true;
    const MAX_CAPTURE_LEN = 20480;
    if (content.length > MAX_CAPTURE_LEN) content = content.slice(0, MAX_CAPTURE_LEN) + '\n[…truncated at 20KB]';

    // Serialized: two captures landing in the same tick would otherwise both
    // read the same snapshot and one would be silently overwritten.
    storageSerial(async () => {
      const r = await chrome.storage.local.get(['prompt_bin_captures']);
      const captures = r['prompt_bin_captures'] || [];

      if (captures.length > 0) {
        const last = captures[0];
        if (last.content === content && last.aiTool === aiTool && last.type === type) {
          log('[Promptrix] Duplicate, skipping.');
          return null;
        }
      }

      const tags = extractTags(content);
      const newItem = {
        id: crypto.randomUUID(),
        type, content: clampContent(content), aiTool,
        timestamp: new Date().toISOString(),
        sessionUrl,
        tokens: estimateTokens(content),
        category: tags[0],
        tags: tags,
        starred: false,
      };

      await chrome.storage.local.set({ 'prompt_bin_captures': fitCaptureBudget([newItem, ...captures]) });
      return newItem;
    }).then((newItem) => {
      if (!newItem) return;
      log('[Promptrix] Saved:', newItem.type, newItem.tags);
      // Sync immediately (MV3 safe — no setTimeout)
      immediateCloudSync(newItem);
      // Forward to SIEM if a profile subscribes to activity events.
      siemEmit(newItem.type === 'response' ? 'response.captured' : 'prompt.captured', newItem);
    });
    return true;
  }

  // 2. AUTOCOMPLETE SEARCH
  if (request.action === 'search_history') {
    const query = (request.query || '').toLowerCase();
    // 2-char queries match almost every stored prompt, so the popup fired on
    // the first keystrokes of every message and re-rendered constantly.
    if (query.length < 4) { sendResponse({ matches: [] }); return true; }
    // Autocomplete cannot use a needle longer than a phrase, and searching with
    // one costs a full deserialize of the store. The content script already
    // trims, but a stale script or another caller must not be able to ask for it.
    if (query.length > 160) { sendResponse({ matches: [] }); return true; }

    chrome.storage.local.get(['prompt_bin_captures'], (result) => {
      const data = result['prompt_bin_captures'] || [];
      const matches = [], seen = new Set();
      // Bound the scan. This runs per keystroke; a full 5000-item linear scan
      // on every character is what made typing feel laggy.
      const scanned = data.length > 800 ? data.slice(0, 800) : data;
      for (const item of scanned) {
        if (!item || item.type !== 'prompt' || !item.content) continue;
        // Compare against a bounded prefix. toLowerCase() on full content
        // allocated a fresh copy of every stored prompt on every search.
        const hay = item.content.length > 4000 ? item.content.slice(0, 4000) : item.content;
        if (hay.toLowerCase().indexOf(query) !== -1 && !seen.has(item.content)) {
          // Return a trimmed projection: the popup shows ~160 chars, so sending
          // whole multi-kilobyte prompts across the message boundary is waste.
          matches.push({
            id: item.id, type: item.type, aiTool: item.aiTool, timestamp: item.timestamp,
            tags: item.tags, starred: item.starred,
            content: item.content.length > 600 ? item.content.slice(0, 600) : item.content,
            fullLength: item.content.length,
          });
          seen.add(item.content);
        }
        if (matches.length >= 5) break;
      }
      sendResponse({ matches });
    });
    return true;
  }

  // 3. CLEAR ALL
  if (request.action === 'clear_all') {
    chrome.storage.local.remove('prompt_bin_captures', () => sendResponse({ success: true }));
    return true;
  }

  // 4. GET ALL
  if (request.action === 'get_all_captures') {
    chrome.storage.local.get(['prompt_bin_captures'], (result) => {
      sendResponse(result['prompt_bin_captures'] || []);
    });
    return true;
  }

  // 5. GET STATS
  if (request.action === 'get_stats') {
    chrome.storage.local.get(['prompt_bin_captures'], (result) => {
      const data = result['prompt_bin_captures'] || [];
      sendResponse({
        total: data.length,
        tokens: data.reduce((acc, c) => acc + (c.tokens || 0), 0),
        starred: data.filter(c => c.starred).length,
      });
    });
    return true;
  }

  // 6. TOGGLE STAR
  if (request.action === 'toggle_star') {
    storageSerial(async () => {
      const r = await chrome.storage.local.get(['prompt_bin_captures']);
      const captures = r['prompt_bin_captures'] || [];
      for (let i = 0; i < captures.length; i++) {
        if (captures[i].id === request.captureId) { captures[i].starred = !captures[i].starred; break; }
      }
      await chrome.storage.local.set({ 'prompt_bin_captures': captures });
    }).then(() => sendResponse({ success: true }));
    return true;
  }

  // 7. SAVE SYNC CONFIG
  if (request.action === 'save_sync_config') {
    (async () => {
      const config = { ...request.config };
      if (config.syncToken) config.syncToken = await encryptValue(config.syncToken);
      await chrome.storage.local.set({ 'prompt_bin_sync_config': config });
      log('[Promptrix] Sync config saved');
      sendResponse({ success: true });
    })();
    return true;
  }

  // 8. GET SYNC CONFIG
  if (request.action === 'get_sync_config') {
    (async () => {
      const r = await chrome.storage.local.get(['prompt_bin_sync_config']);
      const config = r['prompt_bin_sync_config'] || { enabled: false, workerUrl: '', syncToken: '' };
      if (config.syncToken) config.syncToken = await decryptValue(config.syncToken);
      sendResponse(config);
    })();
    return true;
  }

  // 9. FORCE FULL SYNC — pushes ALL local captures to cloud (bypasses enabled check)
  if (request.action === 'force_sync') {
    (async () => {
      try {
        const storageResult = await chrome.storage.local.get(['prompt_bin_captures', 'prompt_bin_sync_config']);
        const captures = storageResult['prompt_bin_captures'] || [];
        const config = storageResult['prompt_bin_sync_config'];
        if (config && config.syncToken) config.syncToken = await decryptValue(config.syncToken);

        if (!config || !config.workerUrl || !config.syncToken) {
          sendResponse({ success: false, error: 'Missing Worker URL or Sync Token. Save your config first.' });
          return;
        }

        log('[Promptrix] Force sync: pushing', captures.length, 'captures to', config.workerUrl);

        const workerUrl = config.workerUrl.replace(/\/$/, '');
        const response = await fetch(workerUrl + '/api/push', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Sync-Token': config.syncToken,
          },
          body: JSON.stringify({ captures }),
        });

        if (response.ok) {
          const data = await response.json();
          log('[Promptrix] Force sync SUCCESS:', data);
          await syncToGist();
          sendResponse({ success: true, count: captures.length, message: data.message });
        } else {
          let errText = 'HTTP ' + response.status;
          if (response.status === 401) errText = 'Invalid sync token';
          try { const body = await response.text(); errText += ': ' + body; } catch(e) {}
          warn('[Promptrix] Force sync FAILED:', errText);
          sendResponse({ success: false, error: errText });
        }
      } catch (e) {
        console.error('[Promptrix] Force sync ERROR:', e);
        sendResponse({ success: false, error: 'Network error: ' + e.message });
      }
    })();
    return true;
  }

  // 10. TEST CLOUDFLARE CONNECTION
  if (request.action === 'test_cloudflare') {
    (async () => {
      const url = (request.url || '').replace(/\/$/, '');
      const token = request.token || '';
      if (!url) {
        sendResponse({ success: false, error: 'No Worker URL provided' });
        return;
      }

      log('[Promptrix] Testing connection to:', url + '/api/status');

      try {
        const res = await fetch(url + '/api/status', {
          headers: { 'X-Sync-Token': token }
        });

        log('[Promptrix] Test response status:', res.status);

        if (res.ok) {
          const data = await res.json();
          log('[Promptrix] Test SUCCESS:', data);
          sendResponse({ success: true, data });
        } else {
          let errText = 'HTTP ' + res.status;
          if (res.status === 401) errText = 'Invalid sync token (401)';
          try { const body = await res.text(); errText += ' — ' + body; } catch(e) {}
          sendResponse({ success: false, error: errText });
        }
      } catch (e) {
        console.error('[Promptrix] Test NETWORK ERROR:', e);
        sendResponse({ success: false, error: 'Network error: ' + e.message });
      }
    })();
    return true;
  }

  // 11. SAVE GIST CONFIG
  if (request.action === 'save_gist_config') {
    (async () => {
      const config = { ...request.config };
      if (config.pat) config.pat = await encryptValue(config.pat);
      await chrome.storage.local.set({ 'prompt_bin_gist_config': config });
      sendResponse({ success: true });
    })();
    return true;
  }

  // 12. GET GIST CONFIG
  if (request.action === 'get_gist_config') {
    (async () => {
      const r = await chrome.storage.local.get(['prompt_bin_gist_config']);
      const config = r['prompt_bin_gist_config'] || { autoSync: false, pat: '', gistId: '' };
      if (config.pat) config.pat = await decryptValue(config.pat);
      sendResponse(config);
    })();
    return true;
  }

  // ─── DLP: DATA-LOSS PREVENTION ─────────────────────────────────────────

  // 13. GET DLP POLICY (returns saved policy or the default-ON policy)
  if (request.action === 'get_dlp_policy') {
    (async () => {
      const r = await chrome.storage.local.get([DLP_POLICY_KEY, DLP_HMAC_KEY]);
      const saved = r[DLP_POLICY_KEY];
      if (saved && r[DLP_HMAC_KEY]) {
        const valid = await verifyPolicy(saved, r[DLP_HMAC_KEY]);
        if (!valid) {
          warn('[Promptrix DLP] Policy integrity check failed — falling back to defaults');
          const fallback = DLP ? DLP.defaultPolicy() : { masking: true, blocking: false, warning: true, labeling: true, patterns: {} };
          sendResponse(fallback);
          return;
        }
      }
      const policy = DLP ? DLP.normalizePolicy(saved) : (saved || { masking: true, blocking: false, warning: true, labeling: true, patterns: {} });
      sendResponse(policy);
    })();
    return true;
  }

  // 14. SAVE DLP POLICY
  if (request.action === 'save_dlp_policy') {
    (async () => {
      const policy = DLP ? DLP.normalizePolicy(request.policy) : request.policy;
      const hmac = await signPolicy(policy);
      await chrome.storage.local.set({ [DLP_POLICY_KEY]: policy, [DLP_HMAC_KEY]: hmac });
      const det = Object.values(policy.patterns || {}).filter(x => x && x.enabled).length;
      const blk = Object.values(policy.patterns || {}).filter(x => x && x.block).length;
      log('[Promptrix DLP] Policy saved:', det + ' detectors, ' + blk + ' blocking');
      siemEmit('policy.changed', {
        ts: new Date().toISOString(),
        summary: { detectorsEnabled: det, detectorsBlocking: blk, labeling: !!policy.labeling,
                   inspectionDepth: (policy.file && policy.file.depth) || 'deep' },
      });
      sendResponse({ success: true });
    })();
    return true;
  }

  // 15. APPEND A DLP LOG ENTRY (redacted evidence only — never raw secrets)
  if (request.action === 'dlp_log' && request.entry) {
    prependCappedTiered(DLP_LOGS_KEY, request.entry, DLP_LOG_LIMIT).then((total) => {
      // Forward to any subscribed SIEM profile. 'file-*' verdicts map to the
      // dlp.file event; prompt actions map to dlp.mask/block/warn.
      const a = request.entry.action || '';
      const kind = request.entry.source === 'file' ? 'dlp.file'
        : (a === 'block' ? 'dlp.block' : a === 'warn' ? 'dlp.warn' : 'dlp.mask');
      siemEmit(kind, request.entry);
      sendResponse({ success: true, total });
    });
    return true;
  }

  // 16. GET DLP LOGS
  if (request.action === 'get_dlp_logs') {
    chrome.storage.local.get([DLP_LOGS_KEY], (result) => {
      sendResponse(result[DLP_LOGS_KEY] || []);
    });
    return true;
  }

  // 17. CLEAR DLP LOGS
  if (request.action === 'clear_dlp_logs') {
    chrome.storage.local.remove(DLP_LOGS_KEY, () => sendResponse({ success: true }));
    return true;
  }

  // ─── LOG FORWARDING ────────────────────────────────────────────────────

  // 18. GET FORWARDING PROFILES (+ health/queue depth for each)
  if (request.action === 'get_siem_profiles') {
    (async () => {
      const r = await chrome.storage.local.get([SIEM_PROFILES_KEY, SIEM_HEALTH_KEY, SIEM_SPOOL_KEY]);
      let profiles = (r[SIEM_PROFILES_KEY] || []).map(p => SIEM ? SIEM.normalizeProfile(p) : p);
      profiles = await Promise.all(profiles.map(p => decryptProfileAuth(p)));
      const health = r[SIEM_HEALTH_KEY] || {};
      const spool = r[SIEM_SPOOL_KEY] || {};
      profiles.forEach(p => { p._health = health[p.id] || null; p._queued = (spool[p.id] || []).length; });
      sendResponse({ profiles });
    })();
    return true;
  }

  // 19. SAVE FORWARDING PROFILES (full replace)
  if (request.action === 'save_siem_profiles') {
    const list = (request.profiles || []).map(p => SIEM ? SIEM.normalizeProfile(p) : p)
      .map(p => (p.content === 'full' && !p.contentConfirmed) ? { ...p, content: 'redacted' } : p);
    // Deleting a profile must also drop its queue and health record, otherwise
    // an unreachable endpoint leaves up to SPOOL_CAP events (and a stale error
    // state) in storage forever.
    storageSerial(async () => {
      const live = new Set(list.map(p => p.id));
      const r = await chrome.storage.local.get([SIEM_SPOOL_KEY, SIEM_HEALTH_KEY]);
      const spool = r[SIEM_SPOOL_KEY] || {};
      const health = r[SIEM_HEALTH_KEY] || {};
      let pruned = 0;
      Object.keys(spool).forEach(id => { if (!live.has(id)) { pruned += (spool[id] || []).length; delete spool[id]; } });
      Object.keys(health).forEach(id => { if (!live.has(id)) delete health[id]; });
      const encList = await Promise.all(list.map(p => encryptProfileAuth(p)));
      await chrome.storage.local.set({
        [SIEM_PROFILES_KEY]: encList, [SIEM_SPOOL_KEY]: spool, [SIEM_HEALTH_KEY]: health,
      });
      if (pruned) log('[Promptrix SIEM] discarded', pruned, 'queued event(s) for removed profile(s)');
      return list.length;
    }).then((count) => {
      if (list.some(p => p.enabled && p.url)) siemEnsureAlarm();
      sendResponse({ success: true, count });
    });
    return true;
  }

  // 20. TEST A PROFILE — sends one synthetic event, no spooling
  if (request.action === 'test_siem_profile') {
    (async () => {
      if (!SIEM) { sendResponse({ success: false, error: 'Forwarder not loaded' }); return; }
      const p = SIEM.normalizeProfile(request.profile);
      if (!p.url) { sendResponse({ success: false, error: 'Enter an endpoint URL first' }); return; }
      // Verify host access BEFORE the fetch. Without it Chrome fails the
      // request with a bare "Failed to fetch" that looks identical to DNS and
      // TLS errors, which made a permission problem undiagnosable.
      const access = await siemHostAccess(p.url);
      if (!access.ok) { sendResponse({ success: false, error: access.error }); return; }
      const evt = SIEM.projectForProfile(SIEM.sampleEvent(), p);
      const res = await SIEM.deliver(p, [evt]);
      sendResponse(res.ok
        ? { success: true, status: res.status, ms: res.ms }
        : { success: false, error: res.error, status: res.status });
    })();
    return true;
  }

  // 21. PREVIEW the wire payload for a profile (no network)
  if (request.action === 'preview_siem_payload') {
    (async () => {
      if (!SIEM) { sendResponse({ error: 'Forwarder not loaded' }); return; }
      const p = SIEM.normalizeProfile(request.profile);
      const evt = SIEM.projectForProfile(SIEM.sampleEvent(), p);
      const ser = SIEM.serialize([evt], p);
      const auth = await SIEM.applyAuth(p, ser.body);
      const shown = {};
      Object.keys(auth.headers).forEach(k => {
        shown[k] = /authorization|api-?key|token|signature/i.test(k)
          ? String(auth.headers[k]).slice(0, 12) + '…(redacted)'
          : auth.headers[k];
      });
      sendResponse({
        url: auth.url, method: p.method,
        headers: Object.assign({ 'Content-Type': ser.type }, shown),
        body: ser.body.slice(0, 4000),
      });
    })();
    return true;
  }

  // 22. FLUSH THE SPOOL NOW
  if (request.action === 'flush_siem') {
    siemFlush(true).then(r => sendResponse({ success: true, flushed: r.flushed }));
    return true;
  }

  return true;
});