// ─────────────────────────────────────────────────────────────────────────
// Promptrix Log Forwarding — SIEM webhook delivery
//
// Modelled on how network-security products actually ship logs off-box:
//   • FortiGate Security Fabric automation stitches — a webhook action is
//     URI + method + custom headers + templated body, bound to event triggers.
//   • Palo Alto HTTP log-forwarding profiles — the payload is chosen PER LOG
//     TYPE, and the vendor explicitly warns HTTP forwarding can lose logs at
//     volume. That warning is the reason this module batches, retries with
//     backoff, and spools to disk instead of firing one request per event.
//
// Wire formats are the ones SIEMs actually parse: Splunk HEC, ArcSight CEF,
// QRadar LEEF 2.0, Elastic ECS/NDJSON, and plain JSON for everything else.
// Auth covers the real spread — including NONE, because collectors like Sumo
// Logic treat the unique endpoint URL itself as the credential.
//
// Egress safety: this module is itself a data-egress path. A DLP product must
// not become the leak, so event CONTENT is excluded by default; sending
// prompt text is an explicit, per-profile opt-in.
// ─────────────────────────────────────────────────────────────────────────

(function (root) {
  'use strict';

  var VENDOR = 'Promptrix';
  var PRODUCT = 'AI-DLP';
  var VERSION = '7.1';

  // ── Event catalogue — the "what to send" checkboxes ────────────────────
  var EVENT_TYPES = [
    { id: 'dlp.mask',        label: 'Prompt masked',        group: 'Data Protection', desc: 'Sensitive data redacted before send' },
    { id: 'dlp.block',       label: 'Prompt blocked',       group: 'Data Protection', desc: 'Submission stopped by policy' },
    { id: 'dlp.warn',        label: 'Warning raised',       group: 'Data Protection', desc: 'Detected but allowed through' },
    { id: 'dlp.file',        label: 'File inspection verdict', group: 'Data Protection', desc: 'Attachment quarantined / notified / blocked' },
    { id: 'policy.changed',  label: 'Policy changed',       group: 'Audit',           desc: 'Detection or inspection policy edited' },
    { id: 'prompt.captured', label: 'Prompt captured',      group: 'Activity',        desc: 'Every user prompt (high volume)' },
    { id: 'response.captured', label: 'Response captured',  group: 'Activity',        desc: 'Every AI response (high volume)' },
  ];

  var FORMATS = [
    { id: 'json',   label: 'JSON',            hint: 'Generic webhook. One object, or {events:[…]} when batching.' },
    { id: 'ndjson', label: 'NDJSON (bulk)',   hint: 'Newline-delimited — Elastic bulk, Loki, Vector.' },
    { id: 'splunk', label: 'Splunk HEC',      hint: 'Concatenated HEC envelopes with time/host/sourcetype/index.' },
    { id: 'cef',    label: 'ArcSight CEF',    hint: 'CEF:0|…| header plus key=value extension.' },
    { id: 'leef',   label: 'QRadar LEEF 2.0', hint: 'LEEF:2.0|…| header with tab-delimited attributes.' },
    { id: 'ecs',    label: 'Elastic ECS',     hint: 'ECS field names (event.*, file.*, user_agent.*).' },
    { id: 'coralogix', label: 'Coralogix',    hint: 'Coralogix /logs/v1/singles array — applicationName, subsystemName, severity 1-6, text.' },
    { id: 'template',  label: 'Custom template', hint: 'Write the body yourself with %%field%% placeholders, the way a FortiGate automation stitch does.' },
  ];

  // Coralogix severity scale: 1 debug, 2 verbose, 3 info, 4 warning, 5 error, 6 critical.
  var CORALOGIX_SEV = { LOW: 3, MEDIUM: 4, HIGH: 5, CRITICAL: 6 };

  var AUTH_TYPES = [
    { id: 'none',   label: 'None',            hint: 'Unauthenticated POST. Correct for collectors where the endpoint URL is itself the secret (Sumo Logic HTTP source).' },
    { id: 'bearer', label: 'Bearer token',    hint: 'Authorization: Bearer <token>' },
    { id: 'header', label: 'Custom header',   hint: 'Any header name/value — Splunk HEC (Authorization: Splunk …), Datadog (DD-API-KEY), Elastic (ApiKey …).' },
    { id: 'basic',  label: 'HTTP Basic',      hint: 'Authorization: Basic base64(user:pass)' },
    { id: 'hmac',   label: 'HMAC signature',  hint: 'Signs the request body with a shared secret (GitHub/Stripe style).' },
    { id: 'query',  label: 'Query parameter', hint: 'Appends ?<name>=<value> to the URL.' },
  ];

  // Content inclusion — the egress-safety control.
  var CONTENT_MODES = [
    { id: 'none',     label: 'Metadata only',     hint: 'Detector labels, counts, severity, risk. No prompt or file text. Safe default.' },
    { id: 'redacted', label: 'Redacted evidence', hint: 'Adds the masked sample already stored in the audit log (e.g. A••••F).' },
    { id: 'full',     label: 'Full content',      hint: 'Includes raw prompt/response text. This forwards the very data the policy protects — enable only for a controlled, in-scope collector.' },
  ];

  var SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  var SEV_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  // CEF/LEEF use 0-10 severity scales.
  var SEV_NUM = { LOW: 2, MEDIUM: 5, HIGH: 7, CRITICAL: 10 };

  var STORAGE_KEYS = { profiles: 'prompt_bin_siem_profiles', spool: 'prompt_bin_siem_spool', health: 'prompt_bin_siem_health' };
  var SPOOL_CAP = 500;

  // ── Profile ────────────────────────────────────────────────────────────
  function defaultProfile(seed) {
    return {
      id: 'wh_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      name: (seed && seed.name) || 'New forwarder',
      enabled: true,
      url: '',
      method: 'POST',
      format: 'json',
      auth: { type: 'none', token: '', headerName: '', headerValue: '', username: '', password: '', secret: '', signatureHeader: 'X-Promptrix-Signature', paramName: 'token', paramValue: '' },
      headers: [],                       // [{name, value}] — FortiGate-style custom headers
      events: { 'dlp.mask': true, 'dlp.block': true, 'dlp.warn': true, 'dlp.file': true, 'policy.changed': true, 'prompt.captured': false, 'response.captured': false },
      minSeverity: 'LOW',
      content: 'none',
      batchSize: 20,
      flushSeconds: 60,
      maxRetries: 4,
      timeoutMs: 10000,
      // Splunk-specific envelope fields (ignored by other formats)
      splunk: { index: '', sourcetype: 'promptrix:dlp', source: 'promptrix' },
      // Coralogix envelope fields
      coralogix: { applicationName: 'promptrix', subsystemName: 'dlp', computerName: 'browser-extension' },
      // Custom-template body. Placeholders are %%field%% with dotted paths,
      // e.g. %%risk.score%%, %%file.name%%. %%json%% inserts the whole event.
      bodyTemplate: '{\n  "event": "%%type%%",\n  "time": "%%ts%%",\n  "severity": "%%severity%%",\n  "action": "%%outcome%%",\n  "tool": "%%aiTool%%",\n  "detections": "%%detections%%",\n  "count": %%findingCount%%\n}',
      templateContentType: 'application/json',
      verifyTls: true,
    };
  }

  function normalizeProfile(p) {
    var d = defaultProfile();
    if (!p || typeof p !== 'object') return d;
    // Event subscriptions. A profile that HAS an events object is already
    // configured, so any key it does not mention is OFF — filling gaps from the
    // shipped defaults would silently widen egress (a profile subscribing to
    // dlp.block alone also received mask/warn/file/policy), and any event type
    // added in a future release would start flowing without operator consent.
    // Only a profile with no events object at all inherits the defaults.
    var configured = p.events && typeof p.events === 'object';
    var ev = {};
    EVENT_TYPES.forEach(function (t) {
      ev[t.id] = configured
        ? !!p.events[t.id]
        : d.events[t.id];
    });
    var a = p.auth || {};
    return {
      id: p.id || d.id,
      name: String(p.name || d.name).slice(0, 60),
      enabled: p.enabled !== undefined ? !!p.enabled : true,
      url: String(p.url || ''),
      method: ['POST', 'PUT', 'PATCH'].indexOf(p.method) !== -1 ? p.method : 'POST',
      format: FORMATS.some(function (f) { return f.id === p.format; }) ? p.format : 'json',
      auth: {
        type: AUTH_TYPES.some(function (x) { return x.id === a.type; }) ? a.type : 'none',
        token: String(a.token || ''), headerName: String(a.headerName || ''), headerValue: String(a.headerValue || ''),
        username: String(a.username || ''), password: String(a.password || ''),
        secret: String(a.secret || ''), signatureHeader: String(a.signatureHeader || 'X-Promptrix-Signature'),
        paramName: String(a.paramName || 'token'), paramValue: String(a.paramValue || ''),
      },
      headers: Array.isArray(p.headers) ? p.headers.filter(function (h) { return h && h.name; })
        .map(function (h) { return { name: String(h.name).slice(0, 80), value: String(h.value == null ? '' : h.value).slice(0, 500) }; }).slice(0, 20) : [],
      events: ev,
      minSeverity: SEVERITIES.indexOf(p.minSeverity) !== -1 ? p.minSeverity : 'LOW',
      content: CONTENT_MODES.some(function (c) { return c.id === p.content; }) ? p.content : 'none',
      contentConfirmed: !!p.contentConfirmed,
      batchSize: clamp(p.batchSize, 1, 200, 20),
      flushSeconds: clamp(p.flushSeconds, 10, 3600, 60),
      maxRetries: clamp(p.maxRetries, 0, 8, 4),
      timeoutMs: clamp(p.timeoutMs, 1000, 60000, 10000),
      splunk: {
        index: String((p.splunk && p.splunk.index) || ''),
        sourcetype: String((p.splunk && p.splunk.sourcetype) || 'promptrix:dlp'),
        source: String((p.splunk && p.splunk.source) || 'promptrix'),
      },
      coralogix: {
        applicationName: String((p.coralogix && p.coralogix.applicationName) || 'promptrix'),
        subsystemName: String((p.coralogix && p.coralogix.subsystemName) || 'dlp'),
        computerName: String((p.coralogix && p.coralogix.computerName) || 'browser-extension'),
      },
      bodyTemplate: typeof p.bodyTemplate === 'string' ? p.bodyTemplate.slice(0, 8000) : d.bodyTemplate,
      templateContentType: String(p.templateContentType || 'application/json').slice(0, 80),
      verifyTls: p.verifyTls !== undefined ? !!p.verifyTls : true,
    };
  }
  function clamp(v, lo, hi, dflt) {
    var n = Number(v);
    if (!isFinite(n)) return dflt;
    return Math.max(lo, Math.min(hi, Math.round(n)));
  }

  // ── Normalised event ───────────────────────────────────────────────────
  // Every source (DLP log entry, capture, policy change) is flattened into one
  // shape so the formatters never need to know where an event came from.
  function toEvent(kind, payload, meta) {
    var now = new Date().toISOString();
    var e = {
      type: kind,
      ts: (payload && payload.ts) || now,
      vendor: VENDOR, product: PRODUCT, version: VERSION,
      severity: 'LOW',
      outcome: 'observed',
      aiTool: (payload && payload.aiTool) || (meta && meta.aiTool) || 'Unknown',
      url: (payload && payload.url) || (payload && payload.sessionUrl) || '',
      id: (payload && payload.id) || (Date.now().toString(36) + Math.random().toString(36).slice(2, 6)),
      detections: [], classifications: [], findingCount: 0,
      file: null, risk: null, content: null, actor: null, detail: {},
    };
    if (!payload) return e;

    if (kind.indexOf('dlp.') === 0) {
      e.severity = payload.maxSeverity || 'LOW';
      e.outcome = payload.responseAction || (payload.action || '').replace('file-', '') || 'observed';
      e.classifications = payload.classifications || [];
      e.findingCount = payload.totalFindings || 0;
      e.detections = (payload.items || []).map(function (i) {
        return { label: i.label, classification: i.classification, severity: i.severity, count: i.count, evidence: i.evidence, segment: i.segment || null };
      });
      if (payload.source === 'file') {
        e.file = {
          name: payload.fileName, trueType: payload.trueType, declaredExt: payload.declaredExt,
          masquerade: !!payload.masquerade, sizeBytes: payload.sizeBytes || 0,
          parts: payload.segments || 0, truncated: !!payload.truncated, sha256: payload.sha || null,
        };
      }
      if (typeof payload.riskScore === 'number') {
        e.risk = { score: payload.riskScore, band: payload.riskBand, factors: payload.riskFactors || [] };
      }
    } else if (kind === 'prompt.captured' || kind === 'response.captured') {
      e.severity = 'LOW';
      e.outcome = 'captured';
      e.detail = { tokens: payload.tokens || 0, tags: payload.tags || [], category: payload.category || '' };
      e.content = payload.content || '';
    } else if (kind === 'policy.changed') {
      e.severity = 'MEDIUM';
      e.outcome = 'changed';
      e.detail = payload.summary || {};
    }
    return e;
  }

  // Apply the profile's content-inclusion rule. Never mutates the source.
  function projectForProfile(evt, profile) {
    var o = JSON.parse(JSON.stringify(evt));
    if (profile.content === 'none') {
      o.content = null;
      (o.detections || []).forEach(function (d) { delete d.evidence; });
    } else if (profile.content === 'redacted') {
      // Evidence in the audit log is already redacted; drop raw content.
      o.content = null;
    }
    // 'full' keeps everything as-is.
    return o;
  }

  function passesFilter(evt, profile) {
    if (!profile.events[evt.type]) return false;
    if (evt.type.indexOf('dlp.') === 0) {
      var need = SEV_RANK[profile.minSeverity] || 1;
      var got = SEV_RANK[evt.severity] || 1;
      if (got < need) return false;
    }
    return true;
  }

  // ── Formatters ─────────────────────────────────────────────────────────
  function esc(v) { return String(v == null ? '' : v); }

  // CEF escaping: \ | = and newlines in extension values.
  function cefEsc(v) { return esc(v).replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r?\n/g, '\\n'); }
  function cefHeaderEsc(v) { return esc(v).replace(/\\/g, '\\\\').replace(/\|/g, '\\|'); }

  function toCEF(e) {
    var name = e.type + ' ' + (e.outcome || '');
    var ext = {
      rt: Date.parse(e.ts) || Date.now(),
      act: e.outcome,
      outcome: e.outcome,
      cat: (e.classifications || []).join(','),
      cnt: e.findingCount,
      request: e.url,
      cs1Label: 'aiTool', cs1: e.aiTool,
      cs2Label: 'detectors', cs2: (e.detections || []).map(function (d) { return d.label + (d.count > 1 ? 'x' + d.count : ''); }).join(','),
    };
    if (e.file) {
      ext.fname = e.file.name; ext.fsize = e.file.sizeBytes; ext.fileType = e.file.trueType;
      if (e.file.sha256) ext.fileHash = e.file.sha256;
      ext.cs3Label = 'masquerade'; ext.cs3 = e.file.masquerade ? 'true' : 'false';
    }
    if (e.risk) { ext.cn1Label = 'riskScore'; ext.cn1 = e.risk.score; ext.cs4Label = 'riskBand'; ext.cs4 = e.risk.band; }
    if (e.content) ext.msg = e.content.slice(0, 1000);
    var pairs = Object.keys(ext).filter(function (k) { return ext[k] !== '' && ext[k] != null; })
      .map(function (k) { return k + '=' + cefEsc(ext[k]); }).join(' ');
    return 'CEF:0|' + cefHeaderEsc(VENDOR) + '|' + cefHeaderEsc(PRODUCT) + '|' + cefHeaderEsc(VERSION) + '|' +
      cefHeaderEsc(e.type) + '|' + cefHeaderEsc(name) + '|' + (SEV_NUM[e.severity] || 2) + '|' + pairs;
  }

  function toLEEF(e) {
    var attrs = {
      devTime: e.ts, devTimeFormat: 'yyyy-MM-dd\'T\'HH:mm:ss.SSSXXX',
      cat: (e.classifications || []).join(','),
      sev: SEV_NUM[e.severity] || 2,
      action: e.outcome, aiTool: e.aiTool, url: e.url,
      findingCount: e.findingCount,
      detectors: (e.detections || []).map(function (d) { return d.label; }).join(','),
    };
    if (e.file) { attrs.fileName = e.file.name; attrs.fileType = e.file.trueType; attrs.fileSize = e.file.sizeBytes; attrs.fileHash = e.file.sha256 || ''; attrs.masquerade = e.file.masquerade; }
    if (e.risk) { attrs.riskScore = e.risk.score; attrs.riskBand = e.risk.band; }
    if (e.content) attrs.msg = e.content.slice(0, 1000).replace(/\r?\n/g, ' ');
    var body = Object.keys(attrs).filter(function (k) { return attrs[k] !== '' && attrs[k] != null; })
      .map(function (k) { return k + '=' + esc(attrs[k]).replace(/\t/g, ' '); }).join('\t');
    // LEEF 2.0: the 5th pipe field declares the delimiter (tab = x09).
    return 'LEEF:2.0|' + VENDOR + '|' + PRODUCT + '|' + VERSION + '|' + e.type + '|x09|' + body;
  }

  function toECS(e) {
    var o = {
      '@timestamp': e.ts,
      event: { kind: e.type.indexOf('dlp.') === 0 ? 'alert' : 'event', category: ['intrusion_detection'], action: e.outcome, severity: SEV_NUM[e.severity] || 2, dataset: 'promptrix.dlp', module: 'promptrix', provider: VENDOR },
      observer: { vendor: VENDOR, product: PRODUCT, version: VERSION },
      rule: { name: e.type },
      labels: { ai_tool: e.aiTool, classifications: (e.classifications || []).join(','), outcome: e.outcome },
      promptrix: { detections: e.detections, findingCount: e.findingCount, detail: e.detail },
    };
    if (e.url) o.url = { full: e.url };
    if (e.file) {
      o.file = { name: e.file.name, size: e.file.sizeBytes, extension: e.file.declaredExt, mime_type: e.file.trueType };
      if (e.file.sha256) o.file.hash = { sha256: e.file.sha256 };
      o.promptrix.masquerade = e.file.masquerade;
    }
    if (e.risk) o.event.risk_score = e.risk.score;
    if (e.content) o.message = e.content;
    return o;
  }

  function toSplunk(e, profile) {
    var env = {
      time: Math.floor((Date.parse(e.ts) || Date.now()) / 1000),
      host: 'promptrix-extension',
      source: profile.splunk.source || 'promptrix',
      sourcetype: profile.splunk.sourcetype || 'promptrix:dlp',
      event: e,
    };
    if (profile.splunk.index) env.index = profile.splunk.index;
    return env;
  }

  // ── Coralogix /logs/v1/singles ────────────────────────────────────────
  // A JSON ARRAY of entries. `text` may be a string or a nested object; we send
  // the whole normalised event so Coralogix can index the fields.
  function toCoralogix(e, profile) {
    var c = profile.coralogix || {};
    return {
      applicationName: c.applicationName || 'promptrix',
      subsystemName: c.subsystemName || 'dlp',
      computerName: c.computerName || 'browser-extension',
      severity: CORALOGIX_SEV[e.severity] || 3,
      timestamp: Date.parse(e.ts) || Date.now(),
      category: e.type,
      className: e.aiTool,
      methodName: e.outcome,
      text: e,
    };
  }

  // ── FortiGate-style body templating ───────────────────────────────────
  // A Security Fabric automation stitch lets the operator write the HTTP body
  // and interpolate log fields. Same idea here: %%field%% with dotted paths.
  //   %%type%% %%ts%% %%severity%% %%outcome%% %%aiTool%% %%url%%
  //   %%findingCount%% %%detections%% %%classifications%%
  //   %%risk.score%% %%risk.band%% %%file.name%% %%file.sha256%% %%content%%
  //   %%json%%  → the entire event as JSON
  function resolveField(e, path) {
    if (path === 'json') return JSON.stringify(e);
    if (path === 'detections') {
      return (e.detections || []).map(function (d) {
        return d.label + (d.count > 1 ? 'x' + d.count : '');
      }).join(',');
    }
    if (path === 'classifications') return (e.classifications || []).join(',');
    var cur = e;
    var parts = path.split('.');
    for (var i = 0; i < parts.length; i++) {
      if (cur === null || cur === undefined) return '';
      cur = cur[parts[i]];
    }
    if (cur === null || cur === undefined) return '';
    if (typeof cur === 'object') return JSON.stringify(cur);
    return String(cur);
  }

  // JSON-escape when the placeholder sits inside a quoted JSON string so a
  // value containing a quote or newline cannot break the operator's template.
  function renderTemplate(tpl, e, jsonSafe) {
    return String(tpl).replace(/%%([A-Za-z0-9_.]+)%%/g, function (_, path) {
      var v = resolveField(e, path);
      if (!jsonSafe) return v;
      return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"')
                      .replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t');
    });
  }

  // Serialise a batch into the wire body + content type.
  function serialize(events, profile) {
    switch (profile.format) {
      case 'ndjson':
        return { body: events.map(function (e) { return JSON.stringify(e); }).join('\n') + '\n', type: 'application/x-ndjson' };
      case 'splunk':
        // HEC accepts concatenated JSON objects, not a JSON array.
        return { body: events.map(function (e) { return JSON.stringify(toSplunk(e, profile)); }).join('\n'), type: 'application/json' };
      case 'cef':
        return { body: events.map(toCEF).join('\n'), type: 'text/plain' };
      case 'leef':
        return { body: events.map(toLEEF).join('\n'), type: 'text/plain' };
      case 'ecs':
        return { body: events.map(function (e) { return JSON.stringify(toECS(e)); }).join('\n') + '\n', type: 'application/x-ndjson' };
      case 'coralogix':
        return { body: JSON.stringify(events.map(function (e) { return toCoralogix(e, profile); })), type: 'application/json' };
      case 'template': {
        var ct = profile.templateContentType || 'application/json';
        var jsonSafe = /json/i.test(ct);
        var parts = events.map(function (e) { return renderTemplate(profile.bodyTemplate, e, jsonSafe); });
        // One event per request reproduces FortiGate's per-trigger webhook; set
        // batch size 1 for that. A larger batch emits a JSON array when the
        // content type is JSON, otherwise newline-joined records.
        if (parts.length === 1) return { body: parts[0], type: ct };
        return { body: jsonSafe ? '[' + parts.join(',') + ']' : parts.join('\n'), type: ct };
      }
      case 'json':
      default:
        return {
          body: JSON.stringify(events.length === 1 ? events[0]
            : { vendor: VENDOR, product: PRODUCT, version: VERSION, count: events.length, events: events }),
          type: 'application/json',
        };
    }
  }

  // ── Auth ───────────────────────────────────────────────────────────────
  function b64(s) {
    if (typeof btoa === 'function') return btoa(unescape(encodeURIComponent(s)));
    return Buffer.from(s, 'utf8').toString('base64');
  }

  async function hmacSha256Hex(secret, body) {
    try {
      var enc = new TextEncoder();
      var key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      var sig = await crypto.subtle.sign('HMAC', key, enc.encode(body));
      var b = new Uint8Array(sig), out = '';
      for (var i = 0; i < b.length; i++) out += b[i].toString(16).padStart(2, '0');
      return out;
    } catch (e) { return null; }
  }

  // Returns {url, headers}. Auth type 'none' is fully supported and is the
  // correct configuration for URL-as-secret collectors.
  async function applyAuth(profile, body) {
    var url = profile.url;
    var headers = {};
    (profile.headers || []).forEach(function (h) { if (h.name) headers[h.name] = h.value; });
    var a = profile.auth || { type: 'none' };
    switch (a.type) {
      case 'bearer':
        if (a.token) headers['Authorization'] = 'Bearer ' + a.token;
        break;
      case 'header':
        if (a.headerName) headers[a.headerName] = a.headerValue;
        break;
      case 'basic':
        headers['Authorization'] = 'Basic ' + b64((a.username || '') + ':' + (a.password || ''));
        break;
      case 'hmac':
        if (a.secret) {
          var sig = await hmacSha256Hex(a.secret, body);
          if (sig) headers[a.signatureHeader || 'X-Promptrix-Signature'] = 'sha256=' + sig;
        }
        break;
      case 'query':
        if (a.paramName) {
          url += (url.indexOf('?') === -1 ? '?' : '&') +
                 encodeURIComponent(a.paramName) + '=' + encodeURIComponent(a.paramValue || '');
        }
        break;
      case 'none':
      default:
        break;   // unauthenticated — supported by design
    }
    return { url: url, headers: headers };
  }

  // Block requests to private/internal IP ranges (SSRF prevention)
  var PRIVATE_HOST_RE = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|localhost|\[::1\]|\[fc|\[fd|\[fe80)/i;
  function isPrivateUrl(urlStr) {
    try {
      var u = new URL(urlStr);
      return PRIVATE_HOST_RE.test(u.hostname) || u.hostname === '[::1]' || u.protocol === 'file:';
    } catch (e) { return true; }
  }

  // ── Delivery ───────────────────────────────────────────────────────────
  // One attempt. Returns {ok, status, error, ms}.
  async function deliver(profile, events) {
    var t0 = Date.now();
    if (!profile.url) return { ok: false, status: 0, error: 'No endpoint URL configured', ms: 0 };
    if (isPrivateUrl(profile.url)) return { ok: false, status: 0, error: 'Blocked: endpoint resolves to a private/internal address', ms: 0 };
    var ser = serialize(events, profile);
    var auth = await applyAuth(profile, ser.body);
    var headers = Object.assign({
      'Content-Type': ser.type,
      'User-Agent': VENDOR + '/' + VERSION,
      'X-Promptrix-Event-Count': String(events.length),
      'X-Promptrix-Format': profile.format,
    }, auth.headers);

    var ctl = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = ctl ? setTimeout(function () { ctl.abort(); }, profile.timeoutMs) : null;
    try {
      var res = await fetch(auth.url, {
        method: profile.method, headers: headers, body: ser.body,
        signal: ctl ? ctl.signal : undefined,
      });
      if (timer) clearTimeout(timer);
      var ms = Date.now() - t0;
      if (res.ok) return { ok: true, status: res.status, ms: ms };
      var txt = '';
      try { txt = (await res.text()).slice(0, 300); } catch (e) {}
      return { ok: false, status: res.status, error: 'HTTP ' + res.status + (txt ? ' — ' + txt : ''), ms: ms, retryable: res.status >= 500 || res.status === 429 };
    } catch (e) {
      if (timer) clearTimeout(timer);
      var msg = (e && e.name === 'AbortError') ? 'Timed out after ' + profile.timeoutMs + ' ms' : ('Network error: ' + (e && e.message));
      return { ok: false, status: 0, error: msg, ms: Date.now() - t0, retryable: true };
    }
  }

  // Deliver with bounded exponential backoff. Non-retryable failures (4xx
  // other than 429) fail fast — a bad token will not be fixed by waiting.
  async function deliverWithRetry(profile, events) {
    var attempt = 0, last = null;
    while (attempt <= profile.maxRetries) {
      last = await deliver(profile, events);
      if (last.ok) { last.attempts = attempt + 1; return last; }
      if (!last.retryable) break;
      attempt++;
      if (attempt > profile.maxRetries) break;
      await new Promise(function (r) { setTimeout(r, Math.min(30000, 500 * Math.pow(2, attempt))); });
    }
    last.attempts = attempt + 1;
    return last;
  }

  // A single synthetic event for the Test button, so an operator can validate
  // the endpoint, auth and parser without waiting for a real detection.
  function sampleEvent() {
    return toEvent('dlp.block', {
      id: 'test-' + Date.now().toString(36),
      ts: new Date().toISOString(),
      action: 'block', aiTool: 'ChatGPT', url: 'https://chatgpt.com/',
      maxSeverity: 'CRITICAL', classifications: ['AUTHENTICATION_SECRET'],
      totalFindings: 1,
      items: [{ label: 'AWS_KEY', classification: 'AUTHENTICATION_SECRET', severity: 'CRITICAL', count: 1, evidence: '••••••' }],
    }, {});
  }

  root.PromptrixSIEM = {
    VENDOR: VENDOR, PRODUCT: PRODUCT, VERSION: VERSION,
    EVENT_TYPES: EVENT_TYPES, FORMATS: FORMATS, AUTH_TYPES: AUTH_TYPES,
    CONTENT_MODES: CONTENT_MODES, SEVERITIES: SEVERITIES, STORAGE_KEYS: STORAGE_KEYS, SPOOL_CAP: SPOOL_CAP,
    defaultProfile: defaultProfile, normalizeProfile: normalizeProfile,
    toEvent: toEvent, projectForProfile: projectForProfile, passesFilter: passesFilter,
    serialize: serialize, applyAuth: applyAuth,
    toCEF: toCEF, toLEEF: toLEEF, toECS: toECS, toSplunk: toSplunk,
    toCoralogix: toCoralogix, renderTemplate: renderTemplate, resolveField: resolveField,
    CORALOGIX_SEV: CORALOGIX_SEV,
    deliver: deliver, deliverWithRetry: deliverWithRetry, sampleEvent: sampleEvent,
    hmacSha256Hex: hmacSha256Hex,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = root.PromptrixSIEM;

})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : globalThis));
