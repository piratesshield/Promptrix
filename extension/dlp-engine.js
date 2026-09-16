// ─────────────────────────────────────────────────────────────────────────
// Promptrix DLP Engine — India / DPDP-aligned Data Classification & Masking
// Source: GenAI_DLP_Data_Classification_and_Regex_Spec_India_DPDP.docx
//
// Shared, dependency-free module. Loads in three contexts:
//   • content script  (added to manifest content_scripts before content.js)
//   • dashboard page   (<script src="extension/dlp-engine.js">)
//   • service worker   (importScripts, if needed)
//
// Design principle (from spec §Core): regex is a *candidate* detector. High-risk
// rules run a deterministic validator (Verhoeff / Luhn / IBAN MOD-97) before the
// engine treats a candidate as a finding, to keep false positives low.
// The engine NEVER persists the raw secret/identifier — only redacted evidence.
// ─────────────────────────────────────────────────────────────────────────

(function (root) {
  'use strict';

  // ── Classification taxonomy (spec §3) ──────────────────────────────────
  // DLP risk labels (operational), not DPDP statutory categories.
  const CLASSIFICATION = {
    PERSONAL_DATA: 'PERSONAL_DATA',
    HIGH_RISK_IDENTIFIER: 'HIGH_RISK_IDENTIFIER',
    AUTHENTICATION_SECRET: 'AUTHENTICATION_SECRET',
    SPECIAL_HANDLING_DATA: 'SPECIAL_HANDLING_DATA',
    CONFIDENTIAL: 'CONFIDENTIAL',
  };

  // Short human label used inside the in-prompt classification banner.
  const CLASSIFICATION_SHORT = {
    PERSONAL_DATA: 'Personal Data',
    HIGH_RISK_IDENTIFIER: 'High-Risk Identifier',
    AUTHENTICATION_SECRET: 'Authentication Secret',
    SPECIAL_HANDLING_DATA: 'Special-Handling Data',
    CONFIDENTIAL: 'Confidential',
  };

  // Map a rule "category" (spec column) → DLP classification (spec §3 taxonomy).
  function classificationFor(category) {
    switch (category) {
      case 'GOVERNMENT_IDENTIFIER':
      case 'GOVERNMENT_IDENTIFIER_GLOBAL':
      case 'DRIVING_IDENTIFIER':
      case 'FINANCIAL_IDENTIFIER':
      case 'FINANCIAL_IDENTIFIER_GLOBAL':
        return CLASSIFICATION.HIGH_RISK_IDENTIFIER;
      case 'CREDENTIAL_SECRET':
      case 'AUTHENTICATION_SECRET':
        return CLASSIFICATION.AUTHENTICATION_SECRET;
      case 'HEALTH_DATA':
      case 'BIOMETRIC_DATA':
      case 'LOCATION_DATA':
        return CLASSIFICATION.SPECIAL_HANDLING_DATA;
      case 'BUSINESS_IDENTIFIER':
        return CLASSIFICATION.CONFIDENTIAL;
      case 'CONTACT_PII':
      case 'IDENTITY_ATTRIBUTE':
      case 'ONLINE_IDENTIFIER':
      case 'VEHICLE_IDENTIFIER':
      default:
        return CLASSIFICATION.PERSONAL_DATA;
    }
  }

  // ── Deterministic validators (spec §5) ─────────────────────────────────

  // Verhoeff checksum — used for Aadhaar client-side validation (UIDAI).
  const VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
  ];
  const VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
  ];

  function verhoeffValid(numStr) {
    let c = 0;
    const digits = numStr.replace(/\D/g, '').split('').reverse();
    for (let i = 0; i < digits.length; i++) {
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][parseInt(digits[i], 10)]];
    }
    return c === 0;
  }

  // Aadhaar: 12 digits, cannot start with 0 or 1, Verhoeff-valid (spec rule 1).
  function aadhaarValid(raw) {
    const d = raw.replace(/\D/g, '');
    if (d.length !== 12) return false;
    if (d[0] === '0' || d[0] === '1') return false;
    return verhoeffValid(d);
  }

  // Luhn — payment card validation (spec rule 10).
  function luhnValid(raw) {
    const d = raw.replace(/\D/g, '');
    if (d.length < 12 || d.length > 19) return false;
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = parseInt(d[i], 10);
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
      alt = !alt;
    }
    return sum % 10 === 0;
  }

  // IBAN MOD-97 (spec rule 27).
  function ibanValid(raw) {
    const s = raw.replace(/[\s-]/g, '').toUpperCase();
    if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(s)) return false;
    const rearranged = s.slice(4) + s.slice(0, 4);
    let remainder = 0;
    for (let i = 0; i < rearranged.length; i++) {
      const ch = rearranged[i];
      const val = ch >= 'A' && ch <= 'Z' ? ch.charCodeAt(0) - 55 : ch;
      remainder = (remainder * (val.toString().length === 2 ? 100 : 10) + Number(val)) % 97;
    }
    return remainder === 1;
  }

  const VALIDATORS = {
    aadhaar: aadhaarValid,
    luhn: luhnValid,
    iban: ibanValid,
  };

  // ISO 3166-1 alpha-2 country codes — used to validate the country segment of
  // BIC/SWIFT and IBAN candidates so ordinary uppercase words cannot match.
  var ISO3166_A2 = ('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ ' +
    'CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR ' +
    'GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT ' +
    'JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ ' +
    'NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW ' +
    'SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ ' +
    'UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW').split(' ');

  // ── Rule catalogue (spec §6 — 40 production-oriented starter rules) ─────
  // Fields:
  //   id, category, severity, source (regex string), flags, group (capture
  //   index to mask; 0/undefined = whole match), validator (key in VALIDATORS),
  //   label (short token name shown when masked).
  const RULE_DEFS = [
    { id: 'IN_AADHAAR_CANDIDATE', category: 'GOVERNMENT_IDENTIFIER', severity: 'CRITICAL', label: 'AADHAAR',
      source: '(?<!\\d)[2-9](?:[ -]?\\d){11}(?!\\d)', flags: '', validator: 'aadhaar' },
    { id: 'IN_PAN', category: 'GOVERNMENT_IDENTIFIER', severity: 'HIGH', label: 'PAN',
      source: '(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])', flags: 'i' },
    { id: 'IN_DRIVING_LICENSE_CONTEXT', category: 'DRIVING_IDENTIFIER', severity: 'HIGH', label: 'DL',
      source: '\\b(?:driving\\s+licen[cs]e|dl\\s*(?:no|number|#)?)\\s*[:#\\-]?\\s*([A-Z]{2}\\s*[-/]?\\s*\\d{2}\\s*[-/]?\\s*\\d{4,11})\\b', flags: 'i', group: 1 },
    { id: 'IN_PASSPORT_CONTEXT', category: 'GOVERNMENT_IDENTIFIER', severity: 'HIGH', label: 'PASSPORT',
      source: '\\bpassport\\s*(?:no|number|#)?\\s*[:#\\-]?\\s*([A-Z][0-9]{7})\\b', flags: 'i', group: 1 },
    { id: 'IN_VOTER_EPIC_CONTEXT', category: 'GOVERNMENT_IDENTIFIER', severity: 'HIGH', label: 'VOTER_ID',
      source: '\\b(?:voter\\s*(?:id|number)?|epic)\\s*[:#\\-]?\\s*([A-Z]{3}[0-9]{7})\\b', flags: 'i', group: 1 },
    { id: 'IN_PASSPORT_BARE_CANDIDATE', category: 'GOVERNMENT_IDENTIFIER', severity: 'MEDIUM', label: 'PASSPORT', lowConfidence: true,
      source: '(?<![A-Z0-9])[A-Z][0-9]{7}(?![A-Z0-9])', flags: '' },
    { id: 'IN_BANK_ACCOUNT_CONTEXT', category: 'FINANCIAL_IDENTIFIER', severity: 'CRITICAL', label: 'BANK_ACCOUNT',
      source: '\\b(?:bank\\s*)?(?:account|a/c|acct)\\s*(?:no|number|#)?\\s*[:\\-]?\\s*([0-9]{9,18})\\b', flags: 'i', group: 1 },
    { id: 'IN_IFSC', category: 'FINANCIAL_IDENTIFIER', severity: 'HIGH', label: 'IFSC',
      source: '(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])', flags: 'i' },
    { id: 'IN_MICR', category: 'FINANCIAL_IDENTIFIER', severity: 'MEDIUM', label: 'MICR',
      source: '\\b(?:micr|micr\\s*code|cheque\\s*(?:no|number|code)?)\\s*[:#-]?\\s*([0-9]{9})\\b', flags: 'i', group: 1 },
    { id: 'PAYMENT_CARD_CANDIDATE', category: 'FINANCIAL_IDENTIFIER', severity: 'CRITICAL', label: 'PAYMENT_CARD',
      source: '(?<!\\d)(?:\\d[ -]?){12,18}\\d(?!\\d)', flags: '', validator: 'luhn' },
    { id: 'PAYMENT_CVV_CONTEXT', category: 'AUTHENTICATION_SECRET', severity: 'CRITICAL', label: 'CVV', secret: true,
      source: '\\b(?:cvv|cvc|security\\s*code)\\s*[:#-]?\\s*(\\d{3,4})\\b', flags: 'i', group: 1 },
    // EMAIL is defined before IN_UPI_ID so a dotted-TLD address is labelled
    // EMAIL on span ties; pure UPI handles (e.g. name@oksbi) still fall to UPI.
    { id: 'EMAIL', category: 'CONTACT_PII', severity: 'HIGH', label: 'EMAIL',
      source: "\\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+\\b", flags: 'i' },
    { id: 'IN_UPI_ID', category: 'FINANCIAL_IDENTIFIER', severity: 'HIGH', label: 'UPI_ID',
      source: '\\b[a-zA-Z0-9][a-zA-Z0-9._-]{1,255}@[a-zA-Z][a-zA-Z0-9.-]{1,63}\\b', flags: '' },
    { id: 'IN_GSTIN', category: 'BUSINESS_IDENTIFIER', severity: 'MEDIUM', label: 'GSTIN',
      source: '(?<![A-Z0-9])[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][A-Z0-9]Z[A-Z0-9](?![A-Z0-9])', flags: 'i' },
    { id: 'IN_CIN', category: 'BUSINESS_IDENTIFIER', severity: 'MEDIUM', label: 'CIN',
      source: '(?<![A-Z0-9])[LU][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}(?![A-Z0-9])', flags: 'i' },
    { id: 'IN_VEHICLE_REGISTRATION', category: 'VEHICLE_IDENTIFIER', severity: 'MEDIUM', label: 'VEHICLE_REG',
      source: '(?<![A-Z0-9])[A-Z]{2}[ -]?[0-9]{1,2}[ -]?[A-Z]{1,3}[ -]?[0-9]{4}(?![A-Z0-9])', flags: 'i' },
    { id: 'IN_PINCODE_CONTEXT', category: 'CONTACT_PII', severity: 'LOW', label: 'PINCODE',
      source: '\\b(?:pin(?:code)?|postal\\s*code)\\s*[:#-]?\\s*([1-9][0-9]{5})\\b', flags: 'i', group: 1 },
    { id: 'IN_PHONE', category: 'CONTACT_PII', severity: 'HIGH', label: 'PHONE',
      source: '(?<!\\d)(?:\\+91[ -]?)?[6-9][0-9]{4}[ -]?[0-9]{5}(?!\\d)', flags: '' },
    { id: 'IPV4', category: 'ONLINE_IDENTIFIER', severity: 'MEDIUM', label: 'IPV4',
      source: '(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?![0-9.])', flags: '' },
    // MAC precedes IPV6 so a 6-octet colon MAC is labelled MAC (not IPv6) on ties.
    { id: 'MAC_ADDRESS', category: 'ONLINE_IDENTIFIER', severity: 'MEDIUM', label: 'MAC',
      source: '(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])', flags: 'i' },
    // The spec's bare form also matches every CLOCK TIME ("10:30:45" is hex
    // groups separated by colons). A real address has >=4 groups, a "::" run,
    // or a hex letter; a time has none of those.
    { id: 'IPV6_CANDIDATE', category: 'ONLINE_IDENTIFIER', severity: 'MEDIUM', label: 'IPV6', lowConfidence: true,
      source: '(?<![0-9A-Za-z:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])', flags: 'i',
      validate: function (v) {
        if (v.length < 6) return false;
        var parts = v.split(':');
        var filled = parts.filter(function (x) { return x !== ''; });
        if (!filled.length) return false;
        if (v.indexOf('::') !== -1) return true;   // compressed form
        if (/[a-f]/i.test(v)) return true;         // hex digits ⇒ not a clock
        return filled.length >= 4;                 // times have at most 3 parts
      } },
    // Spec §6: "Date alone is often low confidence; raise risk when combined
    // with name/phone/address." It fires on every dd/mm/yyyy, so it ships off.
    { id: 'DATE_OF_BIRTH_DDMMYYYY', category: 'IDENTITY_ATTRIBUTE', severity: 'MEDIUM', label: 'DOB', lowConfidence: true, defaultOn: false,
      source: '(?<!\\d)(?:0?[1-9]|[12][0-9]|3[01])[./-](?:0?[1-9]|1[0-2])[./-](?:19|20)[0-9]{2}(?!\\d)', flags: '' },
    // Spec §6 rates this LOW and notes "ISO dates are common non-personal data
    // too" — a bare release/commit date is not an identity attribute, so it
    // ships disabled and is enabled per-deployment when dates matter.
    { id: 'DATE_ISO', category: 'IDENTITY_ATTRIBUTE', severity: 'LOW', label: 'DATE', lowConfidence: true, defaultOn: false,
      source: '(?<!\\d)(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])(?!\\d)', flags: '' },
    { id: 'US_SSN', category: 'GOVERNMENT_IDENTIFIER_GLOBAL', severity: 'CRITICAL', label: 'US_SSN',
      source: '(?<!\\d)(?:[0-9]{3}-[0-9]{2}-[0-9]{4})(?!\\d)', flags: '' },
    { id: 'US_PASSPORT_CONTEXT', category: 'GOVERNMENT_IDENTIFIER_GLOBAL', severity: 'HIGH', label: 'US_PASSPORT',
      source: '\\b(?:passport\\s*(?:no|number|#)?\\s*[:#-]?\\s*)([0-9]{9}|[A-Z]{1,2}[0-9]{6,9})\\b', flags: 'i', group: 1 },
    { id: 'UK_NINO_CONTEXT', category: 'GOVERNMENT_IDENTIFIER_GLOBAL', severity: 'HIGH', label: 'UK_NINO',
      source: '\\b(?:ni\\s*(?:no|number)|national\\s*insurance)\\s*[:#-]?\\s*([A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D])\\b', flags: 'i', group: 1 },
    { id: 'IBAN', category: 'FINANCIAL_IDENTIFIER_GLOBAL', severity: 'HIGH', label: 'IBAN',
      source: '(?<![A-Z0-9])[A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]){11,30}(?![A-Z0-9])', flags: 'i', validator: 'iban' },
    // A BIC is bank(4) + ISO-3166 country(2) + location(2) [+ branch(3)].
    // Without validating the country segment this pattern matches any 8-letter
    // uppercase word — it was matching the literal token "PASSWORD".
    // Even with ISO-3166 country validation this matches ordinary uppercase
    // tokens ("ROUTES1234X" → country segment "ES"), so it ships off.
    { id: 'SWIFT_BIC', category: 'FINANCIAL_IDENTIFIER_GLOBAL', severity: 'MEDIUM', label: 'SWIFT_BIC', lowConfidence: true, defaultOn: false,
      source: '\\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\\b', flags: '',
      validate: function (v) {
        var cc = v.slice(4, 6);
        return ISO3166_A2.indexOf(cc) !== -1;
      } },
    { id: 'AWS_ACCESS_KEY_ID', category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', label: 'AWS_KEY', secret: true,
      source: '(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])', flags: '' },
    { id: 'AWS_SECRET_KEY_CONTEXT', category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', label: 'AWS_SECRET', secret: true,
      source: '\\baws_secret_access_key\\s*[:=]\\s*([A-Za-z0-9/+=]{30,})', flags: 'i', group: 1 },
    { id: 'API_KEY_GENERIC', category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', label: 'API_KEY', secret: true,
      source: '\\b(?:api[_ -]?key|apikey)\\b\\s*[:=]\\s*["\']?([A-Za-z0-9_\\-]{16,})["\']?', flags: 'i', group: 1 },
    { id: 'JWT', category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', label: 'JWT', secret: true,
      source: '\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\b', flags: '' },
    { id: 'PRIVATE_KEY_HEADER', category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', label: 'PRIVATE_KEY', secret: true,
      source: '-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\\s\\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)?', flags: '' },
    { id: 'PASSWORD_CONTEXT', category: 'AUTHENTICATION_SECRET', severity: 'CRITICAL', label: 'PASSWORD', secret: true,
      source: '\\b(?:password|passwd|pwd)\\b\\s*[:=]\\s*([^\\s,;]{4,})', flags: 'i', group: 1 },
    { id: 'OTP_CONTEXT', category: 'AUTHENTICATION_SECRET', severity: 'CRITICAL', label: 'OTP', secret: true,
      source: '\\b(?:otp|one[- ]time\\s*password|verification\\s*code)\\b\\s*(?:is|:)?\\s*(\\d{4,8})\\b', flags: 'i', group: 1 },
    { id: 'PRIVATE_TOKEN_BEARER', category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', label: 'BEARER_TOKEN', secret: true,
      source: '\\bBearer\\s+([A-Za-z0-9._~+/=-]{20,})\\b', flags: 'i', group: 1 },
    { id: 'CRYPTO_PRIVATE_KEY_GENERIC', category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', label: 'SECRET_KEY', secret: true,
      source: '\\b(?:private[_ -]?key|secret[_ -]?key)\\b\\s*[:=]\\s*([A-Za-z0-9+/=_-]{16,})\\b', flags: 'i', group: 1 },
    // Delimiter is REQUIRED and the value is capped and space-limited. With it
    // optional the rule consumed 100 chars of any sentence containing a health
    // word ("medication schedule was reviewed with the care team").
    { id: 'HEALTH_CONTEXT', category: 'HEALTH_DATA', severity: 'HIGH', label: 'HEALTH',
      source: '\\b(?:diagnosis|medical\\s*record|patient\\s*id|prescription|medication|blood\\s*group|hospital\\s*id)\\b\\s*[:#=-]\\s*([^\\n,;]{2,60})', flags: 'i', group: 1,
      validate: function (v) {
        var t = v.trim();
        if (t.split(/\s+/).length > 6) return false;      // a sentence, not a value
        if (/\b(?:was|were|is|are|be|been|the|and|with|by|for|from|that|this|will|should|can)\b/i.test(t)) return false;
        if (/[(){}[\]<>]|=>|\breturn\b/.test(t)) return false;   // source code, not a clinical value
        return true;
      } },
    // Requires an actual value after the label. Matching the bare word raised a
    // CRITICAL alert on "browser fingerprinting" and "biometric auth RFC".
    { id: 'BIOMETRIC_CONTEXT', category: 'BIOMETRIC_DATA', severity: 'CRITICAL', label: 'BIOMETRIC',
      source: '\\b(?:biometric|fingerprint|face\\s*(?:template|scan)|iris\\s*(?:scan|template)|retina|voiceprint|facial\\s*embedding)[\\s_-]*(?:data|template|hash|id|value|vector)?\\s*[:=]\\s*([^\\s,;]{6,})', flags: 'i', group: 1 },
    { id: 'PRECISE_LOCATION_COORDS', category: 'LOCATION_DATA', severity: 'HIGH', label: 'GEO_COORDS',
      source: '\\b(?:lat(?:itude)?|latitude)\\s*[:=]\\s*[+-]?(?:90(?:\\.0+)?|[0-8]?\\d(?:\\.\\d+)?)\\s*[,; ]+\\s*(?:lon(?:gitude)?|longitude)\\s*[:=]\\s*[+-]?(?:180(?:\\.0+)?|1[0-7]\\d(?:\\.\\d+)?|[0-9]?\\d(?:\\.\\d+)?)\\b', flags: 'i' },
  ];

  // ── Developer-credential catalogue ───────────────────────────────────────
  // High-precision detectors for the credential formats users paste from code
  // and config. Each encodes a PUBLISHED, vendor-documented key format (the
  // AWS AKIA/ASIA prefix, OpenAI sk-proj-, GitHub ghp_, Stripe sk_live_ …) —
  // the same public format facts catalogued by gitleaks, trufflehog and
  // secrets-patterns-db (github.com/mazen160/secrets-patterns-db).
  // All classify as AUTHENTICATION_SECRET. `lit` is a cheap indexOf pre-gate;
  // a few carry an inline validate(value, fullText, start) to reject
  // look-alikes (git SHAs, checksums) that share the same shape.
  const CREDENTIAL_DEFS = [
  { id: "CRED_OPENAI_PROJECT_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "OPENAI_KEY",
    source: "(?<![A-Za-z0-9_])sk-proj-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])", flags: "", lit: "sk-proj-" },
  { id: "CRED_OPENAI_LEGACY_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "OPENAI_KEY",
    source: "(?<![A-Za-z0-9_])sk-(?!proj-|ant-)[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])", flags: "", lit: "sk-" },
  { id: "CRED_ANTHROPIC_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "ANTHROPIC_KEY",
    source: "(?<![A-Za-z0-9_])sk-ant-[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])", flags: "", lit: "sk-ant-" },
  { id: "CRED_GITHUB_PAT", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "GITHUB_PAT",
    source: "(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{20,}(?![A-Za-z0-9])", flags: "", lit: "ghp_" },
  { id: "CRED_GITHUB_FINE_GRAINED_PAT", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "GITHUB_PAT",
    source: "(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}(?![A-Za-z0-9_])", flags: "", lit: "github_pat_" },
  { id: "CRED_GITHUB_OAUTH_APP_TOKEN", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "GITHUB_TOKEN",
    source: "(?<![A-Za-z0-9_])gh[osur]_[A-Za-z0-9]{20,}(?![A-Za-z0-9])", flags: "", lit: "gh" },
  { id: "CRED_GOOGLE_OAUTH_CLIENT_SECRET", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "GOOGLE_OAUTH_SECRET",
    source: "(?<![A-Za-z0-9_])GOCSPX-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])", flags: "", lit: "gocspx-" },
  { id: "CRED_GOOGLE_OAUTH_REFRESH_TOKEN", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "GOOGLE_REFRESH_TOKEN",
    source: "(?<![A-Za-z0-9_/])1//[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])", flags: "", lit: "1//" },
  { id: "CRED_DOCKER_PAT", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "DOCKER_PAT",
    source: "(?<![A-Za-z0-9])dckr_pat_[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])", flags: "", lit: "dckr_pat_" },
  { id: "CRED_NPM_TOKEN", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "NPM_TOKEN",
    source: "(?<![A-Za-z0-9])npm_[A-Za-z0-9]{30,}(?![A-Za-z0-9])", flags: "", lit: "npm_" },
  { id: "CRED_BEARER_TOKEN", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "BEARER_TOKEN",
    source: "(?<![A-Za-z0-9_])bearer\\s+([A-Za-z0-9._~+/=-]{16,})", flags: "i", group: 1, lit: "bearer" },
  { id: "CRED_SLACK_WEBHOOK_MODERN_IDS", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "SLACK_WEBHOOK",
    source: "hooks\\.slack\\.com/services/T[A-Z0-9]{6,14}/B[A-Z0-9]{6,14}/[A-Za-z0-9]{16,}", flags: "", lit: "hooks.slack.com" },
  { id: "CRED_CONNECTION_STRING_PASSWORD", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "CONN_STRING",
    source: "(?<=\\b[a-z][a-z0-9+.\\-]*:\\/\\/[^:/\\s@]+:)[^\\s]+?(?=@[a-zA-Z0-9.\\-]+(?::\\d+)?(?:[/\\s]|$))", flags: "i", lit: "://" },
  { id: "CRED_AWS_SECRET_BARE", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, lowConfidence: true, label: "AWS_SECRET",
    source: "(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", flags: "",
    validate: function (v) {
      if (/^[0-9a-fA-F]{40}$/.test(v)) return false;
      return /[a-z]/.test(v) && /[A-Z]/.test(v) && /[0-9]/.test(v);
    } },
  { id: "CRED_ENV_VALUE", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, lowConfidence: true, label: "ENV_VALUE",
    source: "(?<=^\\s*(?:export\\s+)?[A-Z][A-Z0-9_]{2,}=[\"']?)[^\\s\"']{8,}", flags: "m",
    validate: function (v) {
      if (/^\d+$/.test(v)) return false;                       // ports, sizes
      if (/^(true|false|null|none|undefined|yes|no)$/i.test(v)) return false;
      if (/^[a-z]+$/.test(v) || /^[A-Z]+$/.test(v)) return false; // config words
      if (/^[/.$~]/.test(v)) return false;                     // paths, $refs
      return true;
    } },
  { id: "CRED_HEX_ENCODED_PRIVATE_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, lowConfidence: true, label: "CRYPTO_KEY",
    source: "(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])", flags: "",
    validate: function (_v, fullText, start) {
      const around = fullText.slice(Math.max(0, start - 60), start + 130).toLowerCase();
      const hashCtx = /sha[-_]?256|sha[-_]?512|checksum|hash|digest|integrity|etag|commit/.test(around);
      const secretCtx = /private|secret|wallet|seed|mnemonic|credential|key/.test(around);
      return !(hashCtx && !secretCtx);
    } },
  { id: "CRED_ETH_PRIVATE_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "ETH_PRIVATE_KEY",
    source: "(?<![A-Za-z0-9])0x[A-Fa-f0-9]{64}(?![A-Za-z0-9])", flags: "", lit: "0x" },
  { id: "CRED_BITCOIN_WIF_PRIVATE_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "BTC_WIF",
    source: "(?<![A-Za-z0-9])[5KL][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])", flags: "" },
  { id: "CRED_AWS_ARN", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "AWS_ARN",
    source: "(?<![A-Za-z0-9_])(?:arn:aws:[a-z0-9-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+:[A-Za-z0-9\\-_/:.*]+)(?![A-Za-z0-9_])", flags: "", lit: "arn" },
  { id: "CRED_AWS_CLIENT_ID", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "AWS_CLIENT_ID",
    source: "(?<![A-Za-z0-9_])(?:(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?![A-Za-z0-9_])", flags: "" },
  { id: "CRED_AWS_MWS_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "AWS_MWS_KEY",
    source: "(?<![A-Za-z0-9_])(?:amzn.mws.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![A-Za-z0-9_])", flags: "", lit: "amzn" },
  { id: "CRED_FCM_SERVER_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "FCM_SERVER_KEY",
    source: "(?<![A-Za-z0-9_])(?:(AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}))(?![A-Za-z0-9_])", flags: "i", lit: "aaaa" },
  { id: "CRED_FACEBOOK_ACCESS_TOKEN", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "FACEBOOK_ACCESS_TOKEN",
    source: "(?<![A-Za-z0-9_])(?:EAACEdEose0cBA[0-9a-z]+)(?![A-Za-z0-9_])", flags: "", lit: "eaacedeose0cba" },
  { id: "CRED_GOOGLE_API_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "GOOGLE_API_KEY",
    source: "(?<![A-Za-z0-9_])(?:AIza[0-9a-z-_]{35})(?![A-Za-z0-9_])", flags: "", lit: "aiza" },
  { id: "CRED_GOOGLE_OAUTH_ID", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "GOOGLE_OAUTH_ID",
    source: "(?<![A-Za-z0-9_])(?:[0-9]{1,100}-[0-9a-z_]{32}.apps.googleusercontent.com)(?![A-Za-z0-9_])", flags: "", lit: "googleusercontent" },
  { id: "CRED_HEROKU_API_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "HEROKU_API_KEY",
    source: "(?<![A-Za-z0-9_])(?:heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"])(?![A-Za-z0-9_])", flags: "", lit: "heroku" },
  { id: "CRED_MAILCHIMP_API_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "MAILCHIMP_API_KEY",
    source: "(?<![A-Za-z0-9_])(?:[0-9a-f]{32}-us[0-9]{1,2})(?![A-Za-z0-9_])", flags: "" },
  { id: "CRED_MAILGUN_API_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "MAILGUN_API_KEY",
    source: "(?<![A-Za-z0-9_])(?:key-[0-9a-z]{32})(?![A-Za-z0-9_])", flags: "", lit: "key" },
  { id: "CRED_PGP", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "PGP",
    source: "-----BEGIN PGP PRIVATE KEY BLOCK-----(?:[A-Za-z0-9+/=\\s]{0,4000}-----END[A-Za-z ]*-----)?", flags: "", lit: "private" },
  { id: "CRED_RKCS8", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "RKCS8",
    source: "-----BEGIN PRIVATE KEY-----(?:[A-Za-z0-9+/=\\s]{0,4000}-----END[A-Za-z ]*-----)?", flags: "", lit: "private" },
  { id: "CRED_RSA", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "RSA",
    source: "-----BEGIN RSA PRIVATE KEY-----(?:[A-Za-z0-9+/=\\s]{0,4000}-----END[A-Za-z ]*-----)?", flags: "", lit: "private" },
  { id: "CRED_SSH", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "SSH",
    source: "-----BEGIN OPENSSH PRIVATE KEY-----(?:[A-Za-z0-9+/=\\s]{0,4000}-----END[A-Za-z ]*-----)?", flags: "", lit: "openssh" },
  { id: "CRED_SLACK_TOKEN", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "SLACK_TOKEN",
    source: "(?<![A-Za-z0-9_])(?:xox[baprs]-([0-9a-z-]{10,48}))(?![A-Za-z0-9_])", flags: "", lit: "xox" },
  { id: "CRED_SQUARE_API_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "SQUARE_API_KEY",
    source: "(?<![A-Za-z0-9_])(?:sq0(atp|csp)-[0-9a-z-_]{22,43})(?![A-Za-z0-9_])", flags: "" },
  { id: "CRED_STRIPE_PUBLIC_LIVE_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "STRIPE_PUBLIC_LIVE_KEY",
    source: "(?<![A-Za-z0-9_])(?:pk_live_[0-9a-z]{24})(?![A-Za-z0-9_])", flags: "", lit: "live" },
  { id: "CRED_STRIPE_PUBLIC_TEST_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "STRIPE_PUBLIC_TEST_KEY",
    source: "(?<![A-Za-z0-9_])(?:pk_test_[0-9a-z]{24})(?![A-Za-z0-9_])", flags: "", lit: "test" },
  { id: "CRED_STRIPE_SECRET_LIVE_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "STRIPE_SECRET_LIVE_KEY",
    source: "(?<![A-Za-z0-9_])(?:(sk|rk)_live_[0-9a-z]{24})(?![A-Za-z0-9_])", flags: "" },
  { id: "CRED_STRIPE_SECRET_TEST_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "STRIPE_SECRET_TEST_KEY",
    source: "(?<![A-Za-z0-9_])(?:(sk|rk)_test_[0-9a-z]{24})(?![A-Za-z0-9_])", flags: "" },
  { id: "CRED_TELEGRAM_SECRET", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "TELEGRAM_SECRET",
    source: "(?<![A-Za-z0-9_])(?:\\d{5,}:A[A-Za-z0-9_-]{34})(?![A-Za-z0-9_])", flags: "" },
  { id: "CRED_TWILIO_API_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "TWILIO_API_KEY",
    source: "(?<![A-Za-z0-9_])(?:SK[0-9a-fA-F]{32})(?![A-Za-z0-9_])", flags: "" },
  { id: "CRED_ARTIFACTORY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "ARTIFACTORY",
    source: "(?<![A-Za-z0-9_])(?:(artifactory.{0,50}(\"|')?[a-zA-Z0-9=]{112}(\"|')?))(?![A-Za-z0-9_])", flags: "" },
  { id: "CRED_AZURE_BLOB", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "AZURE_BLOB",
    source: "(?<![A-Za-z0-9_])(?:(http(?:s)://.[^><'\" \\n)]+.blob.core.windows.net/.[^><'\" \\n/)]+./))(?![A-Za-z0-9_])", flags: "", lit: "windows" },
  { id: "CRED_DIGITALOCEAN_SPACE", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "DIGITALOCEAN_SPACE",
    source: "(?<![A-Za-z0-9_])(?:(http(?:s)://[^><.'\" \\n)]+.[^><.'\" \\n)]+.[^><.'\" \\n)]+.digitaloceanspaces.com))(?![A-Za-z0-9_])", flags: "", lit: "digitaloceanspaces" },
  { id: "CRED_GCP_API_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "GCP_API_KEY",
    source: "(?<![A-Za-z0-9_])(?:(AIza[0-9A-Za-z-_]{35}))(?![A-Za-z0-9_])", flags: "", lit: "aiza" },
  { id: "CRED_GOOGLE_OAUTH", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "GOOGLE_OAUTH",
    source: "(?<![A-Za-z0-9_])(?:(ya29.[0-9A-Za-z-_]+))(?![A-Za-z0-9_])", flags: "", lit: "ya29" },
  { id: "CRED_JSON_WEB1_TOKEN", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "JSON_WEB1_TOKEN",
    source: "(?<![A-Za-z0-9_])(?:(eyJ[a-zA-Z0-9-]{10,}.eyJ[a-zA-Z0-9-]{10,}.[a-zA-Z0-9-]{10,}))(?![A-Za-z0-9_])", flags: "", lit: "eyj" },
  { id: "CRED_NUGET_API_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "NUGET_API_KEY",
    source: "(?<![A-Za-z0-9_])(?:(oy2[a-z0-9]{43}))(?![A-Za-z0-9_])", flags: "", lit: "oy2" },
  { id: "CRED_SAUCE_TOKEN", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "SAUCE_TOKEN",
    source: "(?<![A-Za-z0-9_])(?:(sauce.{0,50}(\"|')?[0-9a-f-]{36}(\"|')?))(?![A-Za-z0-9_])", flags: "" },
  { id: "CRED_SENDGRID_API_KEY", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "SENDGRID_API_KEY",
    source: "(?<![A-Za-z0-9_])(?:(SG.[a-zA-Z0-9-]{16,32}.[a-zA-Z0-9-]{16,64}))(?![A-Za-z0-9_])", flags: "" },
  { id: "CRED_SLACK_API_TOKEN", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "SLACK_API_TOKEN",
    source: "(?<![A-Za-z0-9_])(?:(xox[aboprs]-([0-9a-zA-Z-]{8,})?))(?![A-Za-z0-9_])", flags: "", lit: "xox" },
  { id: "CRED_SLACK_WEBHOOK_URL", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "SLACK_WEBHOOK_URL",
    source: "(?<![A-Za-z0-9_])(?:(hooks.slack.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{1,}))(?![A-Za-z0-9_])", flags: "", lit: "services" },
  { id: "CRED_SQUARE_APP_SECRET", category: 'CREDENTIAL_SECRET', severity: 'CRITICAL', secret: true, label: "SQUARE_APP_SECRET",
    source: "(?<![A-Za-z0-9_])(?:(sq0[a-z]{3}-[0-9A-Za-z-_]{20,50}))(?![A-Za-z0-9_])", flags: "", lit: "sq0" },
  ];

  // Operator-supplied extended catalogue (extension/pattern-library.js), loaded
  // before this file. Each entry carries a confidence tier; candidate-tier
  // detectors ship DISABLED because they match bare digit/letter runs that
  // ordinary prose produces constantly.
  const LIBRARY_DEFS = (root.PromptrixPatternLibrary || []);
  const ALL_DEFS = RULE_DEFS.concat(CREDENTIAL_DEFS, LIBRARY_DEFS);

  // Compile each rule once. Every compiled regex gets g + d (hasIndices) so
  // scan() can walk matches and mask exact capture-group offsets; i/m/s/u from
  // the def are preserved.
  function compileFlags(f) {
    var out = 'gd';
    ('imsu').split('').forEach(function (c) { if (f && f.indexOf(c) !== -1) out += c; });
    return out;
  }
  const RULES = ALL_DEFS.map(function (def) {
    var regex;
    try {
      regex = new RegExp(def.source, compileFlags(def.flags));
    } catch (e) {
      // Fallback: environment without lookbehind/indices support — strip both.
      try {
        regex = new RegExp(def.source.replace(/\(\?<[!=][^)]*\)/g, ''), 'g' + (def.flags && def.flags.indexOf('i') !== -1 ? 'i' : ''));
      } catch (e2) {
        regex = null;
      }
    }
    return {
      id: def.id,
      category: def.category || def.family || 'GENERIC',
      // Library defs declare `classification` directly; spec defs derive it
      // from `category`. Without this the library's 131 rules all fell through
      // to the PERSONAL_DATA default, which broke matrix grouping, the
      // classification banner and the AUTHENTICATION_SECRET risk floor.
      classification: def.classification || classificationFor(def.category),
      severity: def.severity,
      label: def.label,
      group: def.group || 0,
      validator: def.validator || null,
      validate: typeof def.validate === 'function' ? def.validate : null,
      lit: def.lit ? String(def.lit).toLowerCase() : null,
      secret: !!def.secret,
      lowConfidence: !!def.lowConfidence,
      family: def.family || null,
      tier: def.tier || (def.lowConfidence ? 'candidate' : 'precise'),
      defaultOn: def.defaultOn !== undefined ? !!def.defaultOn : true,
      sample: def.sample || '',
      regex: regex,
      hasIndices: regex ? regex.flags.indexOf('d') !== -1 : false,
    };
  });

  // ── Synthetic-value suppression ────────────────────────────────────────
  // Documentation, templates and test fixtures are full of credential-SHAPED
  // strings that are not credentials. Rather than maintain an English word
  // list (which never generalises past the words in it), classify the VALUE
  // structurally: real secrets are high-entropy and character-diverse;
  // synthetic ones are templated, repetitive or dictionary-plain.
  //
  // Applied only to values captured by a rule's value-group — a vendor-prefix
  // match (AKIA…, sk-ant-…) is self-evidencing and never suppressed here.

  // Shannon entropy in bits/char over the observed alphabet.
  function shannonBits(s) {
    var freq = {}, n = s.length;
    if (!n) return 0;
    for (var i = 0; i < n; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
    var h = 0;
    for (var k in freq) { var p = freq[k] / n; h -= p * Math.log(p) / Math.LN2; }
    return h;
  }

  // Character-class diversity: how many of lower/upper/digit/symbol appear.
  function classDiversity(s) {
    return (/[a-z]/.test(s) ? 1 : 0) + (/[A-Z]/.test(s) ? 1 : 0) +
           (/[0-9]/.test(s) ? 1 : 0) + (/[^A-Za-z0-9]/.test(s) ? 1 : 0);
  }

  function isSyntheticValue(v) {
    var s = String(v).replace(/^["']|["']$/g, '');
    if (!s) return true;

    // 1. Template markers — the value is a slot, not a secret.
    //    <KEY>  ${KEY}  {{key}}  %KEY%  __KEY__  :key  @key@
    if (/^(<[^>]+>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[A-Za-z0-9_]+%|__[A-Za-z0-9_]+__|@[A-Za-z0-9_]+@)$/.test(s)) return true;
    if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(s)) return true;      // $ENV_REF
    if (/^(process\.env|os\.environ|System\.getenv)\b/.test(s)) return true;

    // 2. Filler runs — xxxx, ****, ----, 0000, abcabc…
    if (/^(.)\1+$/.test(s)) return true;                        // one char repeated
    if (/^(?:0123456789|abcdefgh|qwerty)/i.test(s)) return true;  // keyboard/sequence
    if (/^(?:x{4,}|\*{4,}|\.{4,}|-{4,}|_{4,}|#{4,}|\?{4,})$/i.test(s)) return true;

    // 3. Self-describing placeholders — the value NAMES itself as an example.
    //    Matched structurally (contains a slot noun adjacent to a hint word),
    //    not by exact string equality.
    var lower = s.toLowerCase();
    var slot = /(key|token|secret|password|passwd|pwd|credential|apikey|api_key)/;
    var hint = /(your|my|the|insert|enter|add|paste|replace|change|example|sample|dummy|test|fake|placeholder|here|xxx|todo)/;
    if (slot.test(lower) && hint.test(lower)) return true;
    if (/^(example|sample|dummy|placeholder|redacted|changeme|change_me|undefined|null|none|true|false)$/.test(lower)) return true;

    // 4. Entropy floor — a real credential is not a dictionary word.
    //    Short values are judged only on the rules above (too little signal).
    if (s.length >= 12) {
      var bits = shannonBits(s);
      var diversity = classDiversity(s);
      // Low entropy AND low diversity ⇒ prose/identifier, not key material.
      if (bits < 2.6 && diversity <= 2) return true;
      // Pure lowercase letters at any length reads as a word, not a secret.
      if (/^[a-z]+$/.test(s) && bits < 3.4) return true;
    }
    return false;
  }

  // ── Policy model ───────────────────────────────────────────────────────
  // Control is per data type (per rule). Each rule carries four switches:
  //   enabled — run this detector at all (the "Detect" / regex on-off)
  //   mask    — redact matches of this type in the outgoing prompt
  //   block   — stop the whole prompt when this type is present
  //   warn    — surface the on-page warning banner for this type
  // Defaults (per the requirement): detect ON, mask ON, block OFF, warn ON.
  // `labeling` is a single global switch that appends a Data-Classification
  // banner to a masked prompt. It ships OFF: the mask itself is the control,
  // and appending a banner alters the user's message to the model, which can
  // change the answer they get. Enable it only where an auditor requires the
  // classification to travel with the prompt.
  function defaultRule(on) {
    var e = on !== false;                    // candidate-tier rules start OFF
    return { enabled: e, mask: e, block: false, warn: e };
  }

  // Content-inspection policy lives in the Content Inspection Engine
  // (extension/content-inspector.js). The engine keeps only a reference copy
  // so a policy round-trip through storage never drops it.
  function defaultFilePolicy() {
    return (root.PromptrixInspector && root.PromptrixInspector.defaultInspectionPolicy)
      ? root.PromptrixInspector.defaultInspectionPolicy()
      : { enabled: true, depth: 'deep', maxSizeKB: 4096 };
  }
  function normalizeFilePolicy(f) {
    return (root.PromptrixInspector && root.PromptrixInspector.normalizeInspectionPolicy)
      ? root.PromptrixInspector.normalizeInspectionPolicy(f)
      : (f || defaultFilePolicy());
  }

  function defaultPolicy() {
    var patterns = {};
    RULES.forEach(function (r) { patterns[r.id] = defaultRule(r.defaultOn); });
    return { labeling: false, patterns: patterns, file: defaultFilePolicy() };
  }

  function normalizePolicy(p) {
    p = p && typeof p === 'object' ? p : {};
    // Back-compat: a previous version stored global masking/blocking/warning
    // plus boolean patterns. Fold those into per-rule defaults.
    var legacy = {
      mask: p.masking !== undefined ? !!p.masking : true,
      block: p.blocking !== undefined ? !!p.blocking : false,
      warn: p.warning !== undefined ? !!p.warning : true,
    };
    var src = p.patterns || {};
    var out = { labeling: p.labeling !== undefined ? !!p.labeling : false, patterns: {}, file: normalizeFilePolicy(p.file) };
    RULES.forEach(function (r) {
      var s = src[r.id];
      if (s && typeof s === 'object') {
        out.patterns[r.id] = {
          enabled: s.enabled !== undefined ? !!s.enabled : true,
          mask: s.mask !== undefined ? !!s.mask : legacy.mask,
          block: s.block !== undefined ? !!s.block : legacy.block,
          warn: s.warn !== undefined ? !!s.warn : legacy.warn,
        };
      } else if (typeof s === 'boolean') {
        out.patterns[r.id] = { enabled: s, mask: legacy.mask, block: legacy.block, warn: legacy.warn };
      } else {
        // Unseen rule (shipped in an update): honour its tier default so a
        // candidate-tier detector can never switch itself on silently.
        var on = r.defaultOn !== false;
        out.patterns[r.id] = { enabled: on, mask: on && legacy.mask, block: on && legacy.block, warn: on && legacy.warn };
      }
    });
    return out;
  }

  // ── Redaction helpers ──────────────────────────────────────────────────

  // A short, non-recoverable evidence sample for logs. Secrets never surface
  // any characters; other identifiers keep at most first/last char.
  function redactEvidence(rule, value) {
    var v = String(value || '');
    if (rule.secret) return '••••••';
    var stripped = v.replace(/\s/g, '');
    if (stripped.length <= 4) return '••••';
    return stripped[0] + '••••' + stripped[stripped.length - 1] + ' (' + stripped.length + ')';
  }

  // The mask replaces the sensitive span with a run of 'X' the same width as
  // the original value (so "BASS9987W" → "XXXXXXXXX"), capped for very long
  // secrets. An all-X run can never re-trigger a detector that needs digits,
  // and scan() explicitly skips all-X spans, so masking stays idempotent.
  var MASK_CHAR = 'X';
  var MASK_MIN = 4;
  var MASK_MAX = 32;
  function maskFor(width) {
    var n = width || 0;
    if (n < MASK_MIN) n = MASK_MIN;
    if (n > MASK_MAX) n = MASK_MAX;
    return new Array(n + 1).join(MASK_CHAR);
  }

  // ── Core scan ──────────────────────────────────────────────────────────
  // Returns { findings, classifications, counts, maxSeverity }.
  // findings: [{ ruleId, label, category, classification, severity, secret,
  //              start, end, evidence }]  (offsets index into `text`)
  var SEV_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

  function scan(text, policy) {
    var pol = normalizePolicy(policy);
    var raw = [];
    if (!text) return { findings: [], classifications: [], counts: {}, maxSeverity: null };

    // Unicode normalization + zero-width character stripping to prevent bypass
    if (typeof text.normalize === 'function') {
      text = text.normalize('NFC').replace(/[​‌‍﻿­⁠᠎]/g, '');
    }

    var lowerCache = null;
    var lower = function () { return lowerCache !== null ? lowerCache : (lowerCache = text.toLowerCase()); };

    // ── Redaction map ────────────────────────────────────────────────────
    // Content this engine has already redacted must be INERT on re-inspection.
    // Checking only for an all-X value was not enough: masking leaves HYBRID
    // spans behind — "PRIVATE_KEY=XXXXXXXX\nLEFTOVER_TAIL" — and generic
    // value rules then claim the whole span as a brand-new secret. The operator
    // pastes back a prompt we ourselves sanitized and gets stopped again, which
    // is the single behaviour that makes a DLP feel broken instead of
    // protective. Any span that OVERLAPS an existing redaction is the residue of
    // a previous decision, not a new finding, so it is not re-raised.
    var redacted = [];
    (function () {
      var re = new RegExp(MASK_CHAR + '{' + MASK_MIN + ',}', 'g'), mm;
      while ((mm = re.exec(text)) !== null) redacted.push([mm.index, mm.index + mm[0].length]);
    })();
    var inRedacted = function (s, e) {
      for (var i = 0; i < redacted.length; i++) {
        if (s < redacted[i][1] && e > redacted[i][0]) return true;   // any overlap
      }
      return false;
    };

    RULES.forEach(function (rule) {
      if (!rule.regex) return;
      var rc = pol.patterns[rule.id];
      if (rc && rc.enabled === false) return; // detector disabled for this type

      // Cheap literal pre-gate: a rule whose required substring is absent can't
      // match — indexOf is far cheaper than running the regex (matters for the
      // ~90-rule catalogue over large uploaded files).
      if (rule.lit && lower().indexOf(rule.lit) === -1) return;

      rule.regex.lastIndex = 0;
      var m;
      var guard = 0;
      var ruleStart = Date.now();
      while ((m = rule.regex.exec(text)) !== null && guard < 10000) {
        guard++;
        if (Date.now() - ruleStart > 50) break;
        if (m.index === rule.regex.lastIndex) rule.regex.lastIndex++; // zero-width guard

        // Resolve the span to mask (whole match or a capture group).
        var start, end, value;
        if (rule.group && m[rule.group] !== undefined) {
          if (rule.hasIndices && m.indices && m.indices[rule.group]) {
            start = m.indices[rule.group][0];
            end = m.indices[rule.group][1];
          } else {
            var off = m[0].indexOf(m[rule.group]);
            start = m.index + (off < 0 ? 0 : off);
            end = start + m[rule.group].length;
          }
          value = m[rule.group];
        } else {
          start = m.index;
          end = m.index + m[0].length;
          value = m[0];
        }
        if (!value) continue;

        // Skip spans that are already masked (an all-X run). Context rules keep
        // their keyword after masking (e.g. "password: XXXXXX"), so without this
        // guard they would re-match the mask as a new value and never converge.
        var strippedVal = value.replace(/\s/g, '');
        if (strippedVal && /^X+$/.test(strippedVal)) continue;

        // Already-redacted territory. Overlapping a redaction is not by itself
        // proof this is residue: a live secret written directly against a mask
        // run ("password=XXXXXXXXHunter2Real!") overlaps too, and blanket-
        // skipping those would turn the idempotency fix into an evasion path.
        // Strip the mask runs and judge what survives — our own output leaves
        // only placeholder remnants, whereas a real value remains substantial
        // and non-synthetic.
        if (inRedacted(start, end)) {
          // Heuristic catch-alls (candidate tier / low confidence) never re-raise
          // inside a redaction. The mask already records an adjudicated decision
          // for that region, and these broad rules are exactly the ones that
          // re-claimed our own output — a generic NAME=value matcher swallowing
          // "XXXXXXXX\nLEFTOVER_TAIL" and calling it a new secret. Precise,
          // self-evidencing detectors are held to the residual test below, so a
          // live secret written against a mask run is still caught.
          if (rule.lowConfidence || rule.tier === 'candidate') continue;
          var residual = value
            .replace(new RegExp(MASK_CHAR + '{' + MASK_MIN + ',}', 'g'), '')
            .replace(/^[\s:=;,.@#+/\\|'"()\[\]{}<>-]+|[\s:=;,.@#+/\\|'"()\[\]{}<>-]+$/g, '');
          if (residual.length < 8 || isSyntheticValue(residual)) continue;
        }

        // Drop synthetic/templated values — docs, fixtures and .env.example
        // files are full of credential-shaped text. Applied to value-group
        // captures and to heuristic (non-vendor-prefix) rules, where the match
        // IS the candidate value. Vendor-prefix rules are self-evidencing and
        // deliberately exempt: AKIA…/sk-ant-… means what it says.
        if ((rule.group || rule.lowConfidence) && isSyntheticValue(value)) continue;

        // Deterministic validator gate (spec §Core design principle).
        if (rule.validator && VALIDATORS[rule.validator]) {
          if (!VALIDATORS[rule.validator](value)) continue;
        }
        // Inline per-rule validator (credential heuristics: hex vs hash, etc.).
        if (rule.validate) {
          try { if (!rule.validate(value, text, start)) continue; } catch (e) {}
        }

        raw.push({
          ruleId: rule.id,
          label: rule.label,
          category: rule.category,
          classification: rule.classification,
          severity: rule.severity,
          secret: rule.secret,
          start: start,
          end: end,
          _token: maskFor(end - start),
          evidence: redactEvidence(rule, value),
          lowConfidence: rule.lowConfidence,
        });
      }
    });

    // Resolve overlaps: sort by start, then higher severity, then prefer a
    // high-confidence rule over a heuristic one (so a precise vendor key wins
    // over the broad bare-secret catch-all), then longer span.
    raw.sort(function (a, b) {
      if (a.start !== b.start) return a.start - b.start;
      var sa = SEV_RANK[a.severity] || 0, sb = SEV_RANK[b.severity] || 0;
      if (sa !== sb) return sb - sa;
      if (!!a.lowConfidence !== !!b.lowConfidence) return a.lowConfidence ? 1 : -1;
      return (b.end - b.start) - (a.end - a.start);
    });
    var findings = [];
    var lastEnd = -1;
    raw.forEach(function (f) {
      if (f.start >= lastEnd) { findings.push(f); lastEnd = f.end; }
    });

    var classSet = {};
    var counts = {};
    var maxSev = null;
    findings.forEach(function (f) {
      classSet[f.classification] = true;
      counts[f.label] = (counts[f.label] || 0) + 1;
      if (!maxSev || (SEV_RANK[f.severity] || 0) > (SEV_RANK[maxSev] || 0)) maxSev = f.severity;
    });

    return {
      findings: findings,
      classifications: Object.keys(classSet),
      counts: counts,
      maxSeverity: maxSev,
    };
  }

  // ── Sanitize ───────────────────────────────────────────────────────────
  // Per-rule policy resolution:
  //   • any finding whose type has block=ON  → action 'block' (nothing rewritten)
  //   • otherwise spans whose type has mask=ON are redacted        → 'mask'
  //   • types with warn=ON drive the on-page banner (`warn` flag)
  //   • no maskable finding and nothing to warn                    → 'allow'
  //
  // Returns:
  //   { action: 'allow'|'mask'|'block'|'warn', warn:boolean, findings,
  //     classifications, counts, maxSeverity, sanitized, original, banner }
  function sanitize(text, policy) {
    var pol = normalizePolicy(policy);
    var result = scan(text, pol);
    var findings = result.findings;
    var flags = function (f) { return pol.patterns[f.ruleId] || defaultRule(); };

    if (findings.length === 0) {
      return { action: 'allow', warn: false, findings: [], classifications: [], counts: {}, maxSeverity: null, sanitized: text, original: text, banner: '' };
    }

    var warnAny = findings.some(function (f) { return flags(f).warn; });
    var blockFindings = findings.filter(function (f) { return flags(f).block; });

    // Block wins: stop the whole prompt, rewrite nothing.
    if (blockFindings.length) {
      return { action: 'block', warn: warnAny, findings: findings, classifications: result.classifications, counts: result.counts, maxSeverity: result.maxSeverity, sanitized: text, original: text, banner: '' };
    }

    var maskFindings = findings.filter(function (f) { return flags(f).mask; });

    // Nothing to mask → warn only (or allow silently if warn is off everywhere).
    if (maskFindings.length === 0) {
      return { action: warnAny ? 'warn' : 'allow', warn: warnAny, findings: findings, classifications: result.classifications, counts: result.counts, maxSeverity: result.maxSeverity, sanitized: text, original: text, banner: '' };
    }

    // Mask the maskable spans, splicing from the end so offsets stay valid.
    var masked = text;
    for (var i = maskFindings.length - 1; i >= 0; i--) {
      var f = maskFindings[i];
      masked = masked.slice(0, f.start) + f._token + masked.slice(f.end);
    }

    // Classification banner reflects the types actually masked.
    var maskedClasses = {};
    maskFindings.forEach(function (f) { maskedClasses[f.classification] = true; });
    var banner = '';
    if (pol.labeling) {
      var labels = Object.keys(maskedClasses).map(function (c) { return CLASSIFICATION_SHORT[c] || c; });
      banner = '\n\n[Data Classification: ' + labels.join(', ') + ' — sanitized by Promptrix DLP]';
      masked = masked + banner;
    }

    return {
      action: 'mask',
      warn: warnAny,
      findings: findings,
      classifications: result.classifications,
      counts: result.counts,
      maxSeverity: result.maxSeverity,
      sanitized: masked,
      original: text,
      banner: banner,
    };
  }

  // Build a compact, safe log record from a sanitize() result.
  function buildLogEntry(res, meta) {
    var byLabel = {};
    res.findings.forEach(function (f) {
      if (!byLabel[f.label]) byLabel[f.label] = { label: f.label, classification: f.classification, severity: f.severity, count: 0, evidence: f.evidence };
      byLabel[f.label].count++;
    });
    return {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      ts: new Date().toISOString(),
      action: res.action,
      aiTool: (meta && meta.aiTool) || 'Unknown AI',
      url: (meta && meta.url) || '',
      maxSeverity: res.maxSeverity,
      classifications: res.classifications,
      totalFindings: res.findings.length,
      items: Object.keys(byLabel).map(function (k) { return byLabel[k]; }),
    };
  }

  var API = {
    RULES: RULES,
    RULE_DEFS: RULE_DEFS,
    CLASSIFICATION: CLASSIFICATION,
    CLASSIFICATION_SHORT: CLASSIFICATION_SHORT,
    STORAGE_KEYS: { policy: 'prompt_bin_dlp_policy', logs: 'prompt_bin_dlp_logs' },
    LOG_LIMIT: 1000,
    defaultPolicy: defaultPolicy,
    normalizePolicy: normalizePolicy,
    classificationFor: classificationFor,
    validators: VALIDATORS,
    scan: scan,
    sanitize: sanitize,
    buildLogEntry: buildLogEntry,
    // Content inspection policy (engine lives in content-inspector.js)
    defaultFilePolicy: defaultFilePolicy,
    normalizeFilePolicy: normalizeFilePolicy,
  };

  root.PromptrixDLP = API;
  if (typeof module !== 'undefined' && module.exports) module.exports = API;

})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this)));
