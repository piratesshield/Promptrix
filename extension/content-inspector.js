// ─────────────────────────────────────────────────────────────────────────
// Promptrix Content Inspection Engine (CIE)
//
// Deep content inspection for files attached to an external GenAI endpoint.
// Architected from GenAI_DLP_Data_Classification_and_Regex_Spec (India/DPDP):
//   §5 Detection Architecture — normalize → detect → validate → correlate →
//                               risk score → destination-aware policy action
//   §4 Compound Identity      — co-occurring attributes escalate risk
//
// Design stance (why this is not a "scan the file" checkbox):
//   1. TRUE FILE TYPE decides inspection, never the filename extension.
//      An extension allow-list is defeated by `mv secrets.env holiday.png`.
//   2. CONTAINERS ARE OPENED. Office documents and archives are the dominant
//      GenAI upload format; treating them as opaque "binary" is the single
//      largest blind spot in prompt-side DLP.
//   3. RISK IS SCORED, not flagged. One address in a config is noise; a
//      thousand in an export is a reportable event. Severity, density,
//      validation and identity correlation all feed one score.
//   4. EVERY TRAVERSAL IS BUDGETED. Bytes, wall-clock and recursion depth are
//      capped so a zip bomb degrades to a partial verdict, never a hung tab.
//
// Runs entirely in the page's isolated world. File bytes never leave the
// browser; only redacted evidence and a content fingerprint are retained.
// ─────────────────────────────────────────────────────────────────────────

(function (root) {
  'use strict';

  // ── 1. TRUE FILE TYPE ──────────────────────────────────────────────────
  // Signature table: [offset, bytes, type, family]. Ordered most-specific
  // first. `family` drives which extractor runs.
  var SIGNATURES = [
    { off: 0, sig: [0x25, 0x50, 0x44, 0x46], type: 'pdf',    family: 'pdf'       }, // %PDF
    { off: 0, sig: [0x50, 0x4B, 0x03, 0x04], type: 'zip',    family: 'zip'       }, // PK.. (also OOXML/ODF)
    { off: 0, sig: [0x50, 0x4B, 0x05, 0x06], type: 'zip',    family: 'zip'       }, // empty archive
    { off: 0, sig: [0x1F, 0x8B],             type: 'gzip',   family: 'gzip'      },
    { off: 0, sig: [0xD0, 0xCF, 0x11, 0xE0], type: 'ole',    family: 'opaque'    }, // legacy .doc/.xls
    { off: 0, sig: [0x89, 0x50, 0x4E, 0x47], type: 'png',    family: 'image'     },
    { off: 0, sig: [0xFF, 0xD8, 0xFF],       type: 'jpeg',   family: 'image'     },
    { off: 0, sig: [0x47, 0x49, 0x46, 0x38], type: 'gif',    family: 'image'     },
    { off: 0, sig: [0x52, 0x49, 0x46, 0x46], type: 'riff',   family: 'media'     },
    { off: 0, sig: [0x7F, 0x45, 0x4C, 0x46], type: 'elf',    family: 'binary'    },
    { off: 0, sig: [0x4D, 0x5A],             type: 'pe',     family: 'binary'    },
    { off: 0, sig: [0x53, 0x51, 0x4C, 0x69], type: 'sqlite', family: 'binary'    },
    { off: 0, sig: [0x37, 0x7A, 0xBC, 0xAF], type: '7z',     family: 'opaque'    },
    { off: 0, sig: [0x52, 0x61, 0x72, 0x21], type: 'rar',    family: 'opaque'    },
  ];

  // Extensions a user would EXPECT to be inert. If the true type contradicts
  // the name we raise an evasion signal (see §masquerade).
  var INERT_EXT = /\.(png|jpe?g|gif|bmp|webp|ico|svg|mp4|mp3|wav|mov|avi)$/i;

  function bytesMatch(u8, off, sig) {
    if (u8.length < off + sig.length) return false;
    for (var i = 0; i < sig.length; i++) if (u8[off + i] !== sig[i]) return false;
    return true;
  }

  // Heuristic text detection: valid-ish UTF-8 with a low control-character
  // ratio. Replaces "count NUL bytes" — UTF-16 and binary blobs with sparse
  // NULs both fooled that test.
  function looksLikeText(u8) {
    var n = Math.min(u8.length, 4096);
    if (n === 0) return false;
    // BOM fast paths
    if (u8[0] === 0xEF && u8[1] === 0xBB && u8[2] === 0xBF) return true;   // UTF-8
    if ((u8[0] === 0xFF && u8[1] === 0xFE) || (u8[0] === 0xFE && u8[1] === 0xFF)) return true; // UTF-16
    var ctrl = 0, high = 0;
    for (var i = 0; i < n; i++) {
      var b = u8[i];
      if (b === 0) return false;                                   // NUL ⇒ not text
      if (b < 0x09 || (b > 0x0D && b < 0x20)) ctrl++;              // C0 controls
      if (b >= 0x80) high++;
    }
    if (ctrl / n > 0.02) return false;      // >2% control chars ⇒ binary
    if (high / n > 0.45) return false;      // mostly high bytes ⇒ likely binary
    return true;
  }

  // Resolve what a file ACTUALLY is. Returns:
  //   { type, family, byName, masquerade }
  function resolveTrueType(u8, filename) {
    var name = String(filename || '').toLowerCase();
    var resolved = null;
    for (var i = 0; i < SIGNATURES.length; i++) {
      if (bytesMatch(u8, SIGNATURES[i].off, SIGNATURES[i].sig)) { resolved = SIGNATURES[i]; break; }
    }
    var type, family;
    if (resolved) {
      type = resolved.type; family = resolved.family;
      // A ZIP may be an Office document — refine once entries are known.
    } else if (looksLikeText(u8)) {
      type = 'text'; family = 'text';
    } else {
      type = 'unknown'; family = 'binary';
    }
    // Masquerade: content is a container/text but the name claims media.
    var masquerade = INERT_EXT.test(name) &&
                     (family === 'zip' || family === 'pdf' || family === 'text' || family === 'gzip');
    return { type: type, family: family, byName: name.slice(name.lastIndexOf('.') + 1), masquerade: masquerade };
  }

  // ── 2. SCAN BUDGET ─────────────────────────────────────────────────────
  // Every traversal is bounded. A budget that runs out yields a PARTIAL
  // verdict — findings so far are kept and the report says it was truncated.
  function Budget(limits) {
    this.maxBytes = limits.maxBytes;
    this.maxMs = limits.maxMs;
    this.maxDepth = limits.maxDepth;
    this.maxEntries = limits.maxEntries;
    this.bytes = 0; this.entries = 0;
    this.started = Date.now();
    this.truncated = false;
  }
  Budget.prototype.spend = function (n) {
    this.bytes += n;
    if (this.bytes > this.maxBytes) { this.truncated = true; return false; }
    return true;
  };
  Budget.prototype.expired = function () {
    if (Date.now() - this.started > this.maxMs) { this.truncated = true; return true; }
    return false;
  };
  Budget.prototype.entry = function () {
    if (++this.entries > this.maxEntries) { this.truncated = true; return false; }
    return true;
  };

  // ── 3. EXTRACTORS ──────────────────────────────────────────────────────
  var td = new TextDecoder('utf-8', { fatal: false });

  function decodeText(u8) { try { return td.decode(u8); } catch (e) { return ''; } }

  async function inflateRaw(u8, format) {
    if (typeof DecompressionStream !== 'function') return null;
    try {
      var ds = new DecompressionStream(format);
      var stream = new Blob([u8]).stream().pipeThrough(ds);
      var buf = await new Response(stream).arrayBuffer();
      return new Uint8Array(buf);
    } catch (e) { return null; }
  }

  // --- ZIP central-directory walk ---------------------------------------
  // Reads the End of Central Directory record, then each central entry, then
  // the local header to locate the compressed payload. Only STORE (0) and
  // DEFLATE (8) are handled; anything else is reported as an opaque entry.
  function u16(dv, p) { return dv.getUint16(p, true); }
  function u32(dv, p) { return dv.getUint32(p, true); }

  async function extractZip(u8, budget, depth, onSegment) {
    var dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    // Locate EOCD (0x06054b50), scanning back over the max comment length.
    var eocd = -1, scanFrom = Math.max(0, u8.length - 66000);
    for (var p = u8.length - 22; p >= scanFrom; p--) {
      if (u32(dv, p) === 0x06054b50) { eocd = p; break; }
    }
    if (eocd < 0) return;
    var count = u16(dv, eocd + 10);
    var cdOff = u32(dv, eocd + 16);
    var names = [];
    var ptr = cdOff;
    for (var i = 0; i < count && ptr + 46 <= u8.length; i++) {
      if (u32(dv, ptr) !== 0x02014b50) break;
      var method = u16(dv, ptr + 10);
      var compSize = u32(dv, ptr + 20);
      var nameLen = u16(dv, ptr + 28);
      var extraLen = u16(dv, ptr + 30);
      var cmtLen = u16(dv, ptr + 32);
      var localOff = u32(dv, ptr + 42);
      var name = decodeText(u8.subarray(ptr + 46, ptr + 46 + nameLen));
      names.push({ name: name, method: method, compSize: compSize, localOff: localOff });
      ptr += 46 + nameLen + extraLen + cmtLen;
    }
    // Identify Office/ODF payloads so we can prefer document parts.
    var isOoxml = names.some(function (e) { return e.name === '[Content_Types].xml'; });
    var ordered = isOoxml ? names.slice().sort(ooxmlPriority) : names;

    for (var k = 0; k < ordered.length; k++) {
      if (budget.expired()) return;
      if (!budget.entry()) return;
      var e = ordered[k];
      if (/\/$/.test(e.name)) continue;                       // directory
      if (isOoxml && !isInterestingOoxmlPart(e.name)) continue;
      if (e.localOff + 30 > u8.length) continue;
      var lnLen = u16(dv, e.localOff + 26), leLen = u16(dv, e.localOff + 28);
      var dataStart = e.localOff + 30 + lnLen + leLen;
      var payload = u8.subarray(dataStart, dataStart + e.compSize);
      if (!budget.spend(e.compSize)) return;
      var raw = null;
      if (e.method === 0) raw = payload;
      else if (e.method === 8) raw = await inflateRaw(payload, 'deflate-raw');
      if (!raw) continue;
      await routeEntry(raw, e.name, budget, depth + 1, onSegment);
    }
  }

  // Office parts that actually carry user text, in reading priority.
  function isInterestingOoxmlPart(n) {
    return /^word\/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$/.test(n) ||
           /^xl\/(sharedStrings|comments\d*)\.xml$/.test(n) ||
           /^xl\/worksheets\/sheet\d+\.xml$/.test(n) ||
           /^ppt\/(slides|notesSlides)\/[a-z]+\d+\.xml$/.test(n) ||
           /^docProps\/(core|app)\.xml$/.test(n) ||
           n === 'content.xml' || n === 'meta.xml';            // ODF
  }
  function ooxmlPriority(a, b) {
    var score = function (n) {
      if (/^word\/document\.xml$/.test(n)) return 0;
      if (/^xl\/sharedStrings\.xml$/.test(n)) return 0;
      if (/^ppt\/slides\//.test(n)) return 0;
      if (/^xl\/worksheets\//.test(n)) return 1;
      return 2;
    };
    return score(a.name) - score(b.name);
  }

  // XML → readable text. Paragraph/row/cell boundaries become newlines so
  // line-anchored detectors (ENV_VALUE) and context rules still work.
  function xmlToText(xml) {
    return xml
      .replace(/<\/(w:p|w:tr|a:p|text:p|row|Row)>/g, '\n')
      .replace(/<w:br\s*\/?>/g, '\n')
      .replace(/<\/(w:tc|a:tc|text:span|c)>/g, '\t')
      .replace(/<[^>]+>/g, '')
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&apos;/g, "'")
      .replace(/&amp;/g, '&')
      .replace(/[ \t]{2,}/g, ' ');
  }

  // --- PDF text extraction ----------------------------------------------
  // Pulls text-showing operators out of content streams. Handles the common
  // FlateDecode case; anything exotic simply yields less text (never throws).
  async function extractPdf(u8, budget, onSegment) {
    var latin = '';
    try { latin = new TextDecoder('latin1').decode(u8); } catch (e) { latin = decodeText(u8); }
    var out = [];
    var re = /stream\r?\n?([\s\S]*?)endstream/g, m, guard = 0;
    while ((m = re.exec(latin)) !== null && guard++ < 400) {
      if (budget.expired()) break;
      var chunk = m[1];
      var bytes = new Uint8Array(chunk.length);
      for (var i = 0; i < chunk.length; i++) bytes[i] = chunk.charCodeAt(i) & 0xFF;
      if (!budget.spend(bytes.length)) break;
      var text = null;
      if (bytes[0] === 0x78) {                                  // zlib header
        var inf = await inflateRaw(bytes, 'deflate');
        if (inf) text = decodeText(inf);
      }
      if (text === null) text = chunk;                          // uncompressed stream
      var pulled = pdfOperatorsToText(text);
      if (pulled) out.push(pulled);
    }
    // Also sweep the raw file for plaintext metadata / unencoded strings.
    var meta = latin.match(/\/(?:Title|Author|Subject|Keywords)\s*\(([^)]{0,300})\)/g);
    if (meta) out.push(meta.join('\n'));
    if (out.length) onSegment('(pdf:text)', out.join('\n'));
  }

  function pdfOperatorsToText(s) {
    var out = [];
    // (literal) Tj   and   [ (a) -2 (b) ] TJ
    var re = /\(((?:\\.|[^\\()])*)\)\s*(?:Tj|TJ|'|")/g, m, guard = 0;
    while ((m = re.exec(s)) !== null && guard++ < 5000) out.push(unescapePdf(m[1]));
    var arr = /\[((?:[^\[\]]|\\.){0,4000}?)\]\s*TJ/g, a, g2 = 0;
    while ((a = arr.exec(s)) !== null && g2++ < 2000) {
      var inner = a[1], im, ire = /\(((?:\\.|[^\\()])*)\)/g, g3 = 0;
      while ((im = ire.exec(inner)) !== null && g3++ < 2000) out.push(unescapePdf(im[1]));
    }
    return out.join('').replace(/\s{2,}/g, ' ').trim();
  }
  function unescapePdf(s) {
    return s.replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
            .replace(/\\([()\\])/g, '$1')
            .replace(/\\([0-7]{1,3})/g, function (_, o) { return String.fromCharCode(parseInt(o, 8)); });
  }

  // --- Dispatch one extracted entry to the right handler -----------------
  async function routeEntry(u8, path, budget, depth, onSegment) {
    if (depth > budget.maxDepth) { budget.truncated = true; return; }
    if (budget.expired()) return;
    var t = resolveTrueType(u8, path);
    if (t.family === 'zip')  return extractZip(u8, budget, depth, onSegment);
    if (t.family === 'pdf')  return extractPdf(u8, budget, onSegment);
    if (t.family === 'gzip') {
      var inf = await inflateRaw(u8, 'gzip');
      if (inf && budget.spend(inf.length)) return routeEntry(inf, path.replace(/\.gz$/i, ''), budget, depth + 1, onSegment);
      return;
    }
    if (t.family === 'text' || /\.(xml|rels)$/i.test(path)) {
      var text = decodeText(u8);
      if (/^\s*<\?xml|^\s*<[a-zA-Z]/.test(text)) text = xmlToText(text);
      if (text.trim()) onSegment(path, text);
      return;
    }
    // image / media / binary / opaque → nothing safely extractable
  }

  // ── 4. RISK SCORING (spec §4 + §5) ─────────────────────────────────────
  // risk = severity_base + validator_bonus + secret_bonus
  //        + identity_correlation + exposure_density + evasion
  var SEV_WEIGHT = { CRITICAL: 40, HIGH: 25, MEDIUM: 10, LOW: 3 };

  // Attributes that, co-occurring, materially increase identifiability.
  var IDENTITY_ATTRS = {
    EMAIL: 1, PHONE: 1, DOB: 1, DATE: 0, PAN: 1, AADHAAR: 1, PASSPORT: 1,
    VOTER_ID: 1, DL: 1, PINCODE: 1, BANK_ACCOUNT: 1, UPI_ID: 1, US_SSN: 1,
    UK_NINO: 1, IBAN: 1, PAYMENT_CARD: 1, VEHICLE_REG: 1, HEALTH: 1,
    BIOMETRIC: 1, GEO_COORDS: 1,
  };

  var BANDS = [
    { min: 80, band: 'CRITICAL' },
    { min: 50, band: 'HIGH' },
    { min: 25, band: 'MODERATE' },
    { min: 0,  band: 'LOW' },
  ];

  function scoreFindings(findings, inspectedBytes, masquerade) {
    if (!findings.length) {
      return { score: 0, band: 'LOW', factors: [], distinctIdentity: 0, density: 0 };
    }
    var factors = [];
    var floor = 0;                    // certain conditions mandate a minimum band
    // 1. Severity base — the single most severe finding sets the floor.
    var base = 0, topSev = 'LOW';
    findings.forEach(function (f) {
      var w = SEV_WEIGHT[f.severity] || 0;
      if (w > base) { base = w; topSev = f.severity; }
    });
    factors.push({ k: 'Severity (' + topSev + ')', v: base });
    var score = base;

    // 2. Deterministic validation passed (Verhoeff/Luhn/MOD-97) ⇒ confidence.
    if (findings.some(function (f) { return f.validated; })) {
      score += 10; factors.push({ k: 'Checksum-validated', v: 10 });
    }

    // 3. Credential material present. The spec is unambiguous here — an API
    //    key, password or private key is CRITICAL on its own — so a
    //    high-confidence credential sets a BAND FLOOR rather than merely
    //    adding points. Low-confidence heuristics (bare 40-char blobs) only
    //    contribute weight; they must not force a quarantine by themselves.
    var creds = findings.filter(function (f) { return f.classification === 'AUTHENTICATION_SECRET'; });
    var firmCreds = creds.filter(function (f) { return !f.lowConfidence; }).length;
    if (creds.length) {
      var sb = Math.min(30, 20 + creds.length * 2);
      score += sb; factors.push({ k: 'Credential material x' + creds.length, v: sb });
    }
    if (firmCreds) floor = Math.max(floor, 80);   // ⇒ CRITICAL band

    // 4. Compound identity (spec §4): distinct identity attributes together.
    var seen = {};
    findings.forEach(function (f) { if (IDENTITY_ATTRS[f.label]) seen[f.label] = 1; });
    var distinct = Object.keys(seen).length;
    if (distinct >= 3) {
      var cb = Math.min(30, 15 + (distinct - 3) * 5);
      score += cb; factors.push({ k: 'Compound identity (' + distinct + ' attributes)', v: cb });
    } else if (distinct === 2) {
      score += 6; factors.push({ k: 'Correlated attributes (2)', v: 6 });
    }

    // 5. Exposure density — bulk records, not an incidental mention.
    var kb = Math.max(1, inspectedBytes / 1024);
    var density = findings.length / kb;
    if (findings.length >= 25) {
      var db = Math.min(25, Math.round(Math.log2(findings.length) * 4));
      score += db; factors.push({ k: 'Bulk exposure (' + findings.length + ' items)', v: db });
    }

    // 6. Evasion — content type contradicts the filename.
    if (masquerade) { score += 15; factors.push({ k: 'Type masquerade', v: 15 }); }

    // Bulk personal data at reporting scale is a notifiable event in its own
    // right, independent of how severe any single record is.
    if (findings.length >= 100 && distinct >= 2) {
      floor = Math.max(floor, 80);
      factors.push({ k: 'Bulk personal data (reportable scale)', v: 'floor' });
    }

    score = Math.max(0, Math.min(100, Math.round(score)));
    if (floor > score) {
      factors.push({ k: 'Policy floor applied', v: floor - score });
      score = floor;
    }
    var band = 'LOW';
    for (var i = 0; i < BANDS.length; i++) if (score >= BANDS[i].min) { band = BANDS[i].band; break; }
    return { score: score, band: band, factors: factors, distinctIdentity: distinct, density: Math.round(density * 100) / 100 };
  }

  // ── 5. RESPONSE ACTIONS ────────────────────────────────────────────────
  var ACTIONS = ['allow', 'notify', 'quarantine', 'block'];
  var ACTION_LABEL = {
    allow: 'Allow', notify: 'Notify', quarantine: 'Quarantine', block: 'Block',
  };

  function defaultInspectionPolicy() {
    return {
      enabled: true,
      depth: 'deep',            // off | shallow (text only) | deep (containers)
      maxSizeKB: 4096,
      maxMs: 4000,
      maxDepth: 3,
      maxEntries: 400,
      inspectArchives: true,
      inspectDocuments: true,
      flagMasquerade: true,
      fingerprint: true,
      // Graduated response per risk band. Default posture is non-blocking:
      // every band warns (notify) or allows, so nothing is removed from the
      // composer out of the box. Block/Quarantine remain selectable in the
      // dashboard for operators who want hard enforcement.
      actions: { CRITICAL: 'notify', HIGH: 'notify', MODERATE: 'notify', LOW: 'allow' },
    };
  }

  function normalizeInspectionPolicy(p) {
    var d = defaultInspectionPolicy();
    if (!p || typeof p !== 'object') return d;
    var a = (p.actions && typeof p.actions === 'object') ? p.actions : {};
    var acts = {};
    ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].forEach(function (b) {
      acts[b] = ACTIONS.indexOf(a[b]) !== -1 ? a[b] : d.actions[b];
    });
    return {
      enabled: p.enabled !== undefined ? !!p.enabled : d.enabled,
      depth: ['off', 'shallow', 'deep'].indexOf(p.depth) !== -1 ? p.depth : d.depth,
      maxSizeKB: Number(p.maxSizeKB) > 0 ? Number(p.maxSizeKB) : d.maxSizeKB,
      maxMs: Number(p.maxMs) > 0 ? Number(p.maxMs) : d.maxMs,
      maxDepth: Number(p.maxDepth) > 0 ? Number(p.maxDepth) : d.maxDepth,
      maxEntries: Number(p.maxEntries) > 0 ? Number(p.maxEntries) : d.maxEntries,
      inspectArchives: p.inspectArchives !== undefined ? !!p.inspectArchives : d.inspectArchives,
      inspectDocuments: p.inspectDocuments !== undefined ? !!p.inspectDocuments : d.inspectDocuments,
      flagMasquerade: p.flagMasquerade !== undefined ? !!p.flagMasquerade : d.flagMasquerade,
      fingerprint: p.fingerprint !== undefined ? !!p.fingerprint : d.fingerprint,
      actions: acts,
    };
  }

  // ── 6. FINGERPRINT ─────────────────────────────────────────────────────
  // Content hash for audit correlation — proves "this same file was seen"
  // without ever retaining the content.
  async function fingerprint(u8) {
    try {
      var d = await crypto.subtle.digest('SHA-256', u8);
      var b = new Uint8Array(d), s = '';
      for (var i = 0; i < 8; i++) s += b[i].toString(16).padStart(2, '0');
      return s;                                                 // 64-bit prefix
    } catch (e) { return null; }
  }

  // ── 7. INSPECT ─────────────────────────────────────────────────────────
  // The public entry point. Returns an InspectionReport:
  //   { inspected, fileName, trueType, declaredExt, masquerade, sizeBytes,
  //     segments, inspectedBytes, truncated, findings, counts, labels,
  //     classifications, risk:{score,band,factors}, action, sha, skipReason }
  async function inspect(file, scanText, inspectionPolicy) {
    var ip = normalizeInspectionPolicy(inspectionPolicy);
    var report = {
      inspected: false, fileName: file && file.name || '(unnamed)',
      sizeBytes: file ? file.size : 0, trueType: null, declaredExt: null,
      masquerade: false, segments: 0, inspectedBytes: 0, truncated: false,
      findings: [], counts: {}, labels: [], classifications: [],
      risk: { score: 0, band: 'LOW', factors: [] },
      action: 'allow', sha: null, skipReason: null,
    };
    if (!ip.enabled || ip.depth === 'off') { report.skipReason = 'inspection disabled'; return report; }
    if (!file) { report.skipReason = 'no file'; return report; }
    if (file.size > ip.maxSizeKB * 1024) {
      report.skipReason = 'exceeds ' + ip.maxSizeKB + ' KB inspection limit';
      return report;
    }

    var u8;
    try { u8 = new Uint8Array(await file.arrayBuffer()); }
    catch (e) { report.skipReason = 'unreadable'; return report; }

    var t = resolveTrueType(u8, file.name);
    report.trueType = t.type;
    report.declaredExt = t.byName;
    report.masquerade = ip.flagMasquerade && t.masquerade;
    if (ip.fingerprint) report.sha = await fingerprint(u8);

    // Families we cannot extract text from carry no inspectable content.
    if (t.family === 'image' || t.family === 'media' || t.family === 'binary' || t.family === 'opaque') {
      report.skipReason = 'no extractable text (' + t.type + ')';
      // A masquerading binary is still worth reporting.
      if (report.masquerade) {
        report.inspected = true;
        report.risk = scoreFindings([], 0, true);
        report.action = ip.actions[report.risk.band] || 'notify';
      }
      return report;
    }
    if (ip.depth === 'shallow' && t.family !== 'text') {
      report.skipReason = 'container skipped (shallow inspection)';
      return report;
    }
    if (t.family === 'zip' && !ip.inspectArchives && !ip.inspectDocuments) {
      report.skipReason = 'container inspection disabled';
      return report;
    }

    var budget = new Budget({
      maxBytes: ip.maxSizeKB * 1024 * 4,   // decompressed allowance
      maxMs: ip.maxMs, maxDepth: ip.maxDepth, maxEntries: ip.maxEntries,
    });

    var collected = [];
    var onSegment = function (path, text) {
      if (!text) return;
      collected.push({ path: path, text: text });
      report.segments++;
      report.inspectedBytes += text.length;
    };

    await routeEntry(u8, file.name, budget, 0, onSegment);
    report.truncated = budget.truncated;
    report.inspected = true;

    // Run the detection catalogue over every extracted segment, keeping the
    // container path so evidence points at the right part of the document.
    var all = [];
    for (var i = 0; i < collected.length; i++) {
      var seg = collected[i];
      var res = scanText(seg.text);
      for (var j = 0; j < res.findings.length; j++) {
        var f = res.findings[j];
        f.segment = seg.path;
        f.validated = !!(f.validator || f.validate);
        all.push(f);
      }
    }
    report.findings = all;

    var counts = {}, labels = [], classes = {};
    all.forEach(function (f) {
      counts[f.label] = (counts[f.label] || 0) + 1;
      if (labels.indexOf(f.label) === -1) labels.push(f.label);
      classes[f.classification] = 1;
    });
    report.counts = counts;
    report.labels = labels;
    report.classifications = Object.keys(classes);
    report.risk = scoreFindings(all, report.inspectedBytes || u8.length, report.masquerade);
    report.action = all.length || report.masquerade
      ? (ip.actions[report.risk.band] || 'notify')
      : 'allow';
    return report;
  }

  // Compact, safe audit record. Content never leaves the browser; the record
  // carries redacted evidence, the risk math, and a content fingerprint.
  function buildInspectionLog(report, meta) {
    var byLabel = {};
    report.findings.forEach(function (f) {
      if (!byLabel[f.label]) {
        byLabel[f.label] = {
          label: f.label, classification: f.classification, severity: f.severity,
          count: 0, evidence: f.evidence, segment: f.segment || null,
        };
      }
      byLabel[f.label].count++;
    });
    return {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      ts: new Date().toISOString(),
      source: 'file',
      action: 'file-' + report.action,
      responseAction: report.action,
      fileName: report.fileName,
      trueType: report.trueType,
      declaredExt: report.declaredExt,
      masquerade: report.masquerade,
      sizeBytes: report.sizeBytes,
      segments: report.segments,
      truncated: report.truncated,
      sha: report.sha,
      riskScore: report.risk.score,
      riskBand: report.risk.band,
      riskFactors: report.risk.factors,
      aiTool: (meta && meta.aiTool) || 'Unknown AI',
      url: (meta && meta.url) || '',
      maxSeverity: report.findings.reduce(function (a, f) {
        return (SEV_WEIGHT[f.severity] || 0) > (SEV_WEIGHT[a] || 0) ? f.severity : a;
      }, null),
      classifications: report.classifications,
      totalFindings: report.findings.length,
      items: Object.keys(byLabel).map(function (k) { return byLabel[k]; }),
    };
  }

  root.PromptrixInspector = {
    SIGNATURES: SIGNATURES,
    ACTIONS: ACTIONS,
    ACTION_LABEL: ACTION_LABEL,
    BANDS: BANDS,
    SEV_WEIGHT: SEV_WEIGHT,
    resolveTrueType: resolveTrueType,
    looksLikeText: looksLikeText,
    scoreFindings: scoreFindings,
    defaultInspectionPolicy: defaultInspectionPolicy,
    normalizeInspectionPolicy: normalizeInspectionPolicy,
    inspect: inspect,
    buildInspectionLog: buildInspectionLog,
    fingerprint: fingerprint,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = root.PromptrixInspector;

})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : globalThis));
