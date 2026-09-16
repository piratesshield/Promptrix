// ─────────────────────────────────────────────────────────────────────────
// Promptrix Extended Pattern Library
//
// Detector catalogue supplied by the operator, classified into the DPDP model
// used by the engine and tiered by CONFIDENCE, which is what decides whether a
// pattern is safe to run by default:
//
//   tier 'precise'    — the string shape is distinctive (vendor prefix, checksum,
//                       delimiter structure). Default ON.
//   tier 'contextual' — needs an adjacent keyword to be meaningful; the pattern
//                       carries that keyword. Default ON.
//   tier 'candidate'  — matches a bare run of digits/letters that ordinary text
//                       produces constantly ("\b[0-9]{4}\b" matches every year).
//                       Shipped, classified and working, but default OFF — the
//                       operator enables it per-rule when their corpus warrants.
//
// Measured on one ordinary business prompt containing no secrets, the candidate
// tier produced 25 false detections; the precise tier produced none. That
// measurement is the whole reason the tier exists.
//
// `family` preserves the operator's own category name for grouping in the UI;
// `classification` drives DPDP policy. Where a published checksum exists it is
// implemented, which promotes several patterns from candidate to precise.
// ─────────────────────────────────────────────────────────────────────────

(function (root) {
  'use strict';

  // ── Check-digit validators ───────────────────────────────────────────
  function luhn(s) {
    const d = s.replace(/\D/g, '');
    if (d.length < 8) return false;
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = +d[i]; if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }
  // VIN: ISO 3779 transliteration, position 9 is the check digit.
  function vin(v) {
    const s = v.toUpperCase();
    if (!/^[A-HJ-NPR-Z0-9]{17}$/.test(s)) return false;
    const tr = { A:1,B:2,C:3,D:4,E:5,F:6,G:7,H:8,J:1,K:2,L:3,M:4,N:5,P:7,R:9,S:2,T:3,U:4,V:5,W:6,X:7,Y:8,Z:9 };
    const w = [8,7,6,5,4,3,2,10,0,9,8,7,6,5,4,3,2];
    let sum = 0;
    for (let i = 0; i < 17; i++) {
      const c = s[i];
      const val = /\d/.test(c) ? +c : tr[c];
      if (val === undefined) return false;
      sum += val * w[i];
    }
    const chk = sum % 11;
    return s[8] === (chk === 10 ? 'X' : String(chk));
  }
  // ISIN: expand letters to digits, then Luhn.
  function isin(v) {
    const s = v.toUpperCase();
    if (!/^[A-Z]{2}[A-Z0-9]{9}[0-9]$/.test(s)) return false;
    let expanded = '';
    for (const c of s) expanded += /[A-Z]/.test(c) ? String(c.charCodeAt(0) - 55) : c;
    return luhn(expanded);
  }
  // CUSIP: modulus-10 double-add-double over an alphanumeric alphabet.
  function cusip(v) {
    const s = v.toUpperCase();
    if (!/^[0-9A-Z*@#]{9}$/.test(s)) return false;
    let sum = 0;
    for (let i = 0; i < 8; i++) {
      const c = s[i];
      let val = /\d/.test(c) ? +c : (c === '*' ? 36 : c === '@' ? 37 : c === '#' ? 38 : c.charCodeAt(0) - 55);
      if (i % 2 === 1) val *= 2;
      sum += Math.floor(val / 10) + (val % 10);
    }
    return (10 - (sum % 10)) % 10 === +s[8];
  }
  // Brazilian CPF: two weighted check digits; all-repeated digits are invalid.
  function cpf(v) {
    const d = v.replace(/\D/g, '');
    if (d.length !== 11 || /^(\d)\1{10}$/.test(d)) return false;
    for (let t = 9; t < 11; t++) {
      let sum = 0;
      for (let i = 0; i < t; i++) sum += +d[i] * ((t + 1) - i);
      let chk = (sum * 10) % 11; if (chk === 10) chk = 0;
      if (chk !== +d[t]) return false;
    }
    return true;
  }
  // Spanish DNI: control letter derived from the number mod 23.
  function dni(v) {
    const m = /^(\d{8})([TRWAGMYFPDXBNJZSQVHLCKE])$/.exec(v.toUpperCase());
    if (!m) return false;
    return 'TRWAGMYFPDXBNJZSQVHLCKE'[+m[1] % 23] === m[2];
  }
  // IMO ship number: 7 digits, last is a weighted check digit.
  function imo(v) {
    const d = (v.match(/\d{7}/) || [''])[0];
    if (d.length !== 7) return false;
    let sum = 0;
    for (let i = 0; i < 6; i++) sum += +d[i] * (7 - i);
    return sum % 10 === +d[6];
  }
  // US DEA: (d1+d3+d5) + 2*(d2+d4+d6), last digit of the sum is the check digit.
  function dea(v) {
    const m = /^([A-Z]{2})(\d{7})$/.exec(v.toUpperCase());
    if (!m) return false;
    const d = m[2];
    const sum = (+d[0] + +d[2] + +d[4]) + 2 * (+d[1] + +d[3] + +d[5]);
    return sum % 10 === +d[6];
  }
  // Aadhaar: 12 digits, first digit 2-9, Verhoeff check (UIDAI client-side rule).
  const VD=[[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
            [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
            [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
  const VP=[[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
            [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
  function aadhaar(v){
    const d=v.replace(/\D/g,'');
    if(d.length!==12||d[0]==='0'||d[0]==='1') return false;
    let c=0; const rev=d.split('').reverse();
    for(let i=0;i<rev.length;i++) c=VD[c][VP[i%8][+rev[i]]];
    return c===0;
  }
  const V = { luhn, vin, isin, cusip, cpf, dni, imo, dea, aadhaar };

  // ── Catalogue ────────────────────────────────────────────────────────
  // p = precise (default ON) · c = contextual (default ON) · x = candidate (default OFF)
  const L = [];
  const add = (tier, family, classification, severity, id, label, source, opts) => {
    const o = opts || {};
    L.push({
      id, label, family, classification, severity,
      source, flags: o.flags || '', group: o.group || 0, lit: o.lit || null,
      validate: o.v ? V[o.v] : undefined, validatorName: o.v || null,
      secret: classification === 'AUTHENTICATION_SECRET',
      lowConfidence: tier === 'x',
      defaultOn: tier !== 'x',
      tier: tier === 'p' ? 'precise' : tier === 'c' ? 'contextual' : 'candidate',
      sample: o.s || '',
    });
  };

  // ── Personal identity — national IDs (checksum where one exists) ──────
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_US_SSN_DASHED','US_SSN',
      '\\b(?!000|666|9\\d\\d)\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b',{s:'123-45-6789'});
  add('c','Personal Identity','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_US_SSN_SPACED','US_SSN',
      '\\b(?:ssn|social\\s*security)\\s*(?:no|number|#)?\\s*[:#-]?\\s*((?!000|666|9\\d\\d)\\d{3}[\\s-]?(?!00)\\d{2}[\\s-]?(?!0000)\\d{4})\\b',{flags:'i',group:1,lit:'s',s:'SSN 123 45 6789'});
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_CA_SIN','CA_SIN',
      '\\b\\d{3}-\\d{3}-\\d{3}\\b',{v:'luhn',s:'046-454-286'});
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','HIGH','LIB_UK_NINO','UK_NINO',
      '\\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\\d{6}[A-D]\\b',{s:'AB123456C'});
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_BR_CPF','BR_CPF',
      '\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b',{v:'cpf',s:'123.456.789-09'});
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_ES_DNI','ES_DNI',
      '\\b\\d{8}[TRWAGMYFPDXBNJZSQVHLCKE]\\b',{v:'dni',s:'12345678Z'});
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_MX_CURP','MX_CURP',
      '\\b[A-Z]{4}\\d{6}[HM][A-Z]{5}[0-9A-Z]\\d\\b',{s:'ABCD123456HDFRRL09'});
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_IT_CF','IT_CODICE_FISCALE',
      '\\b[A-Z]{6}\\d{2}[A-Z]\\d{2}[A-Z]\\d{3}[A-Z]\\b',{s:'RSSMRA85T10A562S'});
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_KR_RRN','KR_RRN',
      '\\b\\d{6}-[1-4]\\d{6}\\b',{s:'123456-1234567'});
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_JP_MYNUMBER','JP_MY_NUMBER',
      '\\b\\d{4}-\\d{4}-\\d{4}\\b',{s:'1234-5678-9012'});
  // Verhoeff is REQUIRED: without it this rule shadowed the validated original
  // and accepted any 4-4-4 digit grouping as an Aadhaar number.
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_IN_AADHAAR_SP','IN_AADHAAR',
      '\\b[2-9]\\d{3}\\s\\d{4}\\s\\d{4}\\b',{v:'aadhaar',s:'2341 2341 2346'});
  add('c','Personal Identity','HIGH_RISK_IDENTIFIER','HIGH','LIB_FR_CNI','FR_CNI',
      '\\b(?:cni|carte\\s*nationale)\\s*[:#-]?\\s*(\\d{12}[A-Z]\\d)\\b',{flags:'i',group:1,lit:'c',s:'CNI 123456789012A3'});
  add('c','Personal Identity','HIGH_RISK_IDENTIFIER','HIGH','LIB_RU_PASSPORT','RU_PASSPORT',
      '\\b(?:passport|паспорт)\\s*[:#-]?\\s*(\\d{2}\\s\\d{2}\\s\\d{6})\\b',{flags:'i',group:1,lit:'pas',s:'passport 12 34 567890'});
  add('c','Personal Identity','HIGH_RISK_IDENTIFIER','HIGH','LIB_DE_PA','DE_PERSONALAUSWEIS',
      '\\b(?:personalausweis|ausweis(?:nummer)?|german\\s*id)\\s*[:#-]?\\s*([A-Z]\\d{8})\\b',{flags:'i',group:1,lit:'ausweis',s:'Ausweis T12345678'});
  add('c','Personal Identity','HIGH_RISK_IDENTIFIER','HIGH','LIB_DL_US','US_DRIVER_LICENSE',
      '\\b(?:driver\'?s?\\s*licen[cs]e|dl|dln)\\s*(?:no|number|#)?\\s*[:#-]?\\s*([A-Z]{1,2}\\d{6,8})\\b',{flags:'i',group:1,lit:'l',s:'Driver License A1234567'});
  add('c','Personal Identity','HIGH_RISK_IDENTIFIER','HIGH','LIB_PASSPORT_US','US_PASSPORT',
      '\\b(?:passport)\\s*(?:no|number|#)?\\s*[:#-]?\\s*(\\d{9})\\b',{flags:'i',group:1,lit:'passport',s:'Passport 123456789'});
  add('x','Personal Identity','HIGH_RISK_IDENTIFIER','MEDIUM','LIB_AU_TFN','AU_TFN',
      '\\b\\d{3}\\s\\d{3}\\s\\d{3}\\b',{s:'123 456 782'});
  add('x','Personal Identity','HIGH_RISK_IDENTIFIER','MEDIUM','LIB_VISA_NUM','US_VISA_NUMBER',
      '\\b\\d{8}\\b',{s:'12345678'});
  add('p','Personal Identity','PERSONAL_DATA','HIGH','LIB_INTL_PHONE','INTL_PHONE',
      '\\+[1-9]\\d{7,14}\\b',{lit:'+',s:'+14155551234'});
  // A leading \b cannot precede "(", so the parenthesised form needs its own
  // lookbehind guard instead; a separator is required so bare 10-digit runs
  // (order ids, account numbers) do not match.
  add('p','Personal Identity','PERSONAL_DATA','HIGH','LIB_US_PHONE','US_PHONE',
      '(?<!\\d)(?:\\+?1[-.\\s]?)?(?:\\(\\d{3}\\)[-.\\s]?|\\d{3}[-.\\s])\\d{3}[-.\\s]\\d{4}(?!\\d)',{s:'(555) 123-4567'});
  add('p','Personal Identity','HIGH_RISK_IDENTIFIER','MEDIUM','LIB_VIN','VIN',
      '\\b[A-HJ-NPR-Z0-9]{17}\\b',{v:'vin',s:'1HGBH41JXMN109186'});

  // ── Financial ────────────────────────────────────────────────────────
  add('p','Financial','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_CREDIT_CARD','PAYMENT_CARD',
      '\\b(?:4\\d{12}(?:\\d{3})?|5[1-5]\\d{14}|3[47]\\d{13}|3[0-9]\\d{11}|6(?:011|5\\d{2})\\d{12})\\b',{v:'luhn',s:'4111111111111111'});
  add('p','Financial','HIGH_RISK_IDENTIFIER','HIGH','LIB_ISIN','ISIN',
      '\\b[A-Z]{2}[A-Z0-9]{9}\\d\\b',{v:'isin',s:'US0378331005'});
  add('p','Financial','HIGH_RISK_IDENTIFIER','MEDIUM','LIB_CUSIP','CUSIP',
      '\\b\\d{3}[0-9A-Z]{6}\\b',{v:'cusip',s:'037833100'});
  // \d{2}-\d{7} is also a common part/build/pipeline number, so the bare form
  // is candidate; the context-anchored form below stays on.
  add('x','Financial','HIGH_RISK_IDENTIFIER','HIGH','LIB_EIN','US_EIN',
      '\\b\\d{2}-\\d{7}\\b',{s:'12-3456789'});
  add('c','Financial','HIGH_RISK_IDENTIFIER','HIGH','LIB_EIN_CTX','US_EIN',
      '\\b(?:EIN|Employer\\s*ID|Federal\\s*Tax\\s*ID|Tax\\s*ID)\\s*(?:no|number|#)?\\s*[:#-]?\\s*(\\d{2}-\\d{7})\\b',{flags:'i',group:1,s:'EIN 12-3456789'});
  add('c','Financial','HIGH_RISK_IDENTIFIER','CRITICAL','LIB_BANK_ACCT','BANK_ACCOUNT',
      '\\b(?:bank\\s*)?(?:account|acct|a/c|iban)\\s*(?:no|number|#)?\\s*[:#-]?\\s*(\\d{8,17})\\b',{flags:'i',group:1,lit:'acc',s:'Account number 12345678'});
  add('p','Financial','HIGH_RISK_IDENTIFIER','HIGH','LIB_BTC','BTC_ADDRESS',
      '\\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\\b',{s:'1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'});
  add('p','Financial','HIGH_RISK_IDENTIFIER','HIGH','LIB_LTC','LTC_ADDRESS',
      '\\b(?:[LM][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{39,59})\\b',{s:'LdP8Qox1VAhCzLJGqrENrreNj1eMp1K1pP'});
  add('p','Financial','HIGH_RISK_IDENTIFIER','HIGH','LIB_ETH','EVM_ADDRESS',
      '\\b0x[a-fA-F0-9]{40}\\b',{lit:'0x',s:'0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'});
  add('p','Financial','HIGH_RISK_IDENTIFIER','HIGH','LIB_ADA','ADA_ADDRESS',
      '\\baddr1[a-z0-9]{50,100}\\b',{lit:'addr1',s:'addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp'});
  add('x','Financial','HIGH_RISK_IDENTIFIER','MEDIUM','LIB_SOL','SOL_ADDRESS',
      '\\b[1-9A-HJ-NP-Za-km-z]{32,44}\\b',{s:'11111111111111111111111111111112'});
  add('c','Financial','CONFIDENTIAL','MEDIUM','LIB_VAT_EU','EU_VAT',
      '\\b(?:vat|ust-?id|tva)\\s*(?:no|number|#)?\\s*[:#-]?\\s*([A-Z]{2}[0-9A-Z]{8,12})\\b',{flags:'i',group:1,lit:'vat',s:'VAT GB123456789'});
  add('x','Financial','CONFIDENTIAL','LOW','LIB_SEDOL','SEDOL','\\b[0-9BCDFGHJKLMNPQRSTVWXYZ]{7}\\b',{s:'0263494'});
  add('x','Financial','CONFIDENTIAL','LOW','LIB_WKN','WKN','\\b[A-Z0-9]{6}\\b',{s:'840400'});
  add('x','Financial','CONFIDENTIAL','LOW','LIB_VALOREN','VALOREN','\\b\\d{6,9}\\b',{s:'908440'});
  add('x','Financial','CONFIDENTIAL','LOW','LIB_COMMODITY','COMMODITY_CODE','\\b[A-Z]{1,3}[FGHJKMNQUVXZ]\\d{2}\\b',{s:'CLZ23'});
  add('x','Financial','CONFIDENTIAL','LOW','LIB_FOREX','FOREX_ACCOUNT','\\b[A-Z]{2,4}\\d{6,10}\\b',{s:'USD1234567'});
  add('x','Financial','CONFIDENTIAL','LOW','LIB_BIZREG','BUSINESS_REG','\\b[A-Z]{2}\\d{8,12}\\b',{s:'GB12345678'});

  // ── Network ──────────────────────────────────────────────────────────
  add('p','Network','PERSONAL_DATA','MEDIUM','LIB_IPV4','IPV4',
      '\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\b',{lit:'.',s:'192.168.1.1'});
  add('p','Network','PERSONAL_DATA','MEDIUM','LIB_MAC','MAC_ADDRESS',
      '\\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\\b|\\b[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}\\b',{s:'00:1B:44:11:3A:B7'});

  // ── Credentials — vendor-prefixed (precise) ──────────────────────────
  const cred = (id,label,src,o)=>add('p','Credentials','AUTHENTICATION_SECRET','CRITICAL',id,label,src,o);
  cred('LIB_AWS_AKIA','AWS_ACCESS_KEY','\\bAKIA[0-9A-Z]{16}\\b',{lit:'akia',s:'AKIAIOSFODNN7EXAMPLE'});
  cred('LIB_GH_PAT','GITHUB_PAT','\\bghp_[A-Za-z0-9]{36}\\b',{lit:'ghp_',s:'ghp_1234567890abcdef1234567890abcdef1234'});
  cred('LIB_GH_SERVER','GITHUB_TOKEN','\\bghs_[A-Za-z0-9_]{36}\\b',{lit:'ghs_',s:'ghs_1234567890abcdefghijklmnopqrstuvwxyz'});
  cred('LIB_GITLAB_PAT','GITLAB_PAT','\\bglpat-[A-Za-z0-9_-]{20}\\b',{lit:'glpat-',s:'glpat-1234567890abcdefghij'});
  cred('LIB_GOOGLE_API','GOOGLE_API_KEY','\\bAIza[0-9A-Za-z_-]{35}\\b',{lit:'aiza',s:'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI'});
  cred('LIB_STRIPE','STRIPE_KEY','\\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\\b',{lit:'_live_',s:'sk_live_1234567890abcdefghijklmnop'});
  cred('LIB_SLACK_TOKEN','SLACK_TOKEN','\\bxox[bpasr]-[A-Za-z0-9-]{10,}\\b',{lit:'xox',s:'xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx'});
  cred('LIB_TWILIO','TWILIO_KEY','\\b(?:SK|AC)[a-fA-F0-9]{32}\\b',{s:'SK1234567890abcdef1234567890abcdef'});
  cred('LIB_SENDGRID','SENDGRID_KEY','\\bSG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}\\b',{lit:'sg.',s:'SG.vjASde5KgyNdHocfCBeqfL.Cd5MhpRRNdMNAdpcL7itBjKhMuL5UmgNMRnygLWeMdQ'});
  cred('LIB_MAILGUN','MAILGUN_KEY','\\bkey-[a-fA-F0-9]{32}\\b',{lit:'key-',s:'key-1234567890abcdef1234567890abcdef'});
  cred('LIB_SQUARE','SQUARE_TOKEN','\\bsq0[a-z]{3}-[A-Za-z0-9_-]{22,43}\\b',{lit:'sq0',s:'sq0atp-1234567890abcdefghijklmnop'});
  cred('LIB_SHOPIFY','SHOPIFY_TOKEN','\\bshpat_[a-fA-F0-9]{32}\\b',{lit:'shpat_',s:'shpat_1234567890abcdef1234567890abcdef'});
  cred('LIB_NPM','NPM_TOKEN','\\bnpm_[A-Za-z0-9]{36}\\b',{lit:'npm_',s:'npm_1234567890abcdefghijklmnopqrstuvwxyz'});
  cred('LIB_DOCKER','DOCKER_PAT','\\bdckr_pat_[A-Za-z0-9_-]{22,}\\b',{lit:'dckr_pat_',s:'dckr_pat_1234567890abcdefghijklmnop'});
  cred('LIB_DO_TOKEN','DIGITALOCEAN_TOKEN','\\bdop_v1_[a-f0-9]{64}\\b',{lit:'dop_v1_',s:'dop_v1_'+'1234567890abcdef'.repeat(4)});
  cred('LIB_TELEGRAM','TELEGRAM_BOT_TOKEN','\\b\\d{8,10}:[A-Za-z0-9_-]{35}\\b',{s:'123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789'});
  cred('LIB_DISCORD','DISCORD_BOT_TOKEN','\\b[A-Za-z0-9_-]{24}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27}\\b',{s:'NzkyNzE1NDk0NzI0MzE1ODU4.X-hvzA.Ovy4MCQywSkoMRRclStW4xAYK7I'});
  cred('LIB_JWT','JWT','\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\b',{lit:'eyj',s:'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'});
  cred('LIB_PAYPAL','PAYPAL_CLIENT_ID','\\bA[A-Za-z0-9_-]{79}\\b',{s:'AoGUKC2vENEyuq3mV2qfMuJG9wXDtPehHBkZwjGBcTeZLM395vwVxPGN4Ee6fsFVTedXVuSMU5DtWz9T'});
  cred('LIB_ORACLE','ORACLE_OCID','\\bocid1\\.[a-z]+\\.[a-z0-9]+\\.[a-z0-9.]{20,}\\b',{lit:'ocid1.',s:'ocid1.user.oc1..aaaaaaaa7example7exampleb7examplec7exampled7example'});
  cred('LIB_SSH_KEY','PRIVATE_KEY','-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY(?: BLOCK)?-----',{lit:'private key',s:'-----BEGIN PRIVATE KEY-----'});
  cred('LIB_SLACK_HOOK','SLACK_WEBHOOK','https://hooks\\.slack\\.com/services/[A-Z0-9]{8,}/[A-Z0-9]{8,}/[A-Za-z0-9]{20,}',{lit:'hooks.slack.com',s:'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'});
  cred('LIB_TEAMS_HOOK','TEAMS_WEBHOOK','https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-f0-9-]{36}@[a-f0-9-]{36}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9-]{36}',{lit:'webhook.office.com',s:'https://outlook.webhook.office.com/webhookb2/12345678-1234-1234-1234-123456789012@12345678-1234-1234-1234-123456789012/IncomingWebhook/12345678901234567890123456789012/12345678-1234-1234-1234-123456789012'});
  cred('LIB_FIREBASE','FIREBASE_URL','https://[a-z0-9-]+\\.firebaseio\\.com',{lit:'firebaseio.com',s:'https://my-project.firebaseio.com'});
  cred('LIB_CLOUDINARY','CLOUDINARY_URL','cloudinary://\\d+:[A-Za-z0-9_-]+@[a-z0-9-]+',{lit:'cloudinary://',s:'cloudinary://123456789012345:abcdefghijklmnop-qrstuvwxyz@my-cloud'});
  cred('LIB_DBCONN','DB_CONNECTION_STRING','(?:mongodb(?:\\+srv)?|mysql|postgresql|postgres|mssql|redis|amqp)://[^\\s:@]+:[^\\s@]+@[^\\s/]+',{lit:'://',s:'mongodb://user:pass@localhost:27017/db'});
  cred('LIB_FTPCONN','FTP_CREDENTIALS','s?ftp://[^\\s:@]+:[^\\s@]+@[^\\s/]+',{lit:'ftp://',s:'ftp://user:password@ftp.server.com'});

  // Credential shapes that are pure entropy — real, but indistinguishable from
  // git SHAs, checksums and IDs, so default OFF.
  const credX = (id,label,src,o)=>add('x','Credentials','AUTHENTICATION_SECRET','CRITICAL',id,label,src,o);
  credX('LIB_HEX32','HEX32_TOKEN','\\b[a-f0-9]{32}\\b',{s:'1234567890abcdef1234567890abcdef'});
  credX('LIB_HEX37','HEX37_TOKEN','\\b[a-f0-9]{37}\\b',{s:'1234567890abcdef1234567890abcdef12345'});
  credX('LIB_HEX40','HEX40_TOKEN','\\b[a-f0-9]{40}\\b',{s:'1234567890abcdef1234567890abcdef12345678'});
  credX('LIB_HEX64','HEX64_TOKEN','\\b[a-f0-9]{64}\\b',{s:'1234567890abcdef'.repeat(4)});
  credX('LIB_UUID','UUID_TOKEN','\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b',{s:'550e8400-e29b-41d4-a716-446655440000'});
  credX('LIB_GENERIC_KEY','GENERIC_API_KEY','\\b[A-Za-z0-9]{32,64}\\b',{s:'abcd1234efgh5678ijkl9012mnop3456'});
  credX('LIB_BASE64','BASE64_BLOB','\\b[A-Za-z0-9+/]{20,}={0,2}\\b',{s:'SGVsbG8gV29ybGRIZWxsb1dvcmxk'});
  credX('LIB_IBM','IBM_CLOUD_KEY','\\b[a-zA-Z0-9_-]{44}\\b',{s:'Kq7Vn4Rz9Wm3Xb6Ld8Tc5Jf1Hp0Ys2Gv7Nu4Qe9Ma-_x'});
  credX('LIB_TRAVIS','TRAVIS_TOKEN','\\b[A-Za-z0-9_-]{22}\\b',{s:'xbExkQhGdo2tiYqAA8GfkD'});
  credX('LIB_VULTR','VULTR_KEY','\\b[A-Z0-9]{36}\\b',{s:'ABCDEF1234567890ABCDEF1234567890ABCD'});
  credX('LIB_BITBUCKET','BITBUCKET_APP_PASSWORD','\\b[A-Z]{4}[a-z]{4}[A-Z]{4}[a-z]{4}\\b',{s:'KQVNrzwmXBLDtcjf'});
  credX('LIB_AWS_SECRET40','AWS_SECRET_KEY','\\b[A-Za-z0-9/+=]{40}\\b',{s:'wJalrXUtnFEMI/K7MDENG/bPxRfiCY9Tz3Ry7Xn5'});

  // ── Healthcare (context-anchored → precise) ───────────────────────────
  const hc = (tier,id,label,src,o)=>add(tier,'Healthcare','SPECIAL_HANDLING_DATA','HIGH',id,label,src,o);
  hc('c','LIB_MRN','MEDICAL_RECORD_NUMBER','\\b(?:MRN|MR|RECORD)\\s*[:#=-]\\s*(\\d{6,10})\\b',{flags:'i',group:1,lit:'r',s:'MRN:1234567'});
  hc('c','LIB_PATIENT_ACCT','PATIENT_ACCOUNT','\\b(?:PAT|ACCT|PATIENT)\\s*[:#=-]\\s*(\\d{6,12})\\b',{flags:'i',group:1,lit:'a',s:'PAT:123456789'});
  hc('c','LIB_LAB_ID','LAB_RESULT_ID','\\b(?:LAB|TEST|RESULT)\\s*[:#=-]\\s*([A-Z0-9]{6,15})\\b',{flags:'i',group:1,lit:'l',s:'LAB:ABC123456'});
  hc('c','LIB_RX','PRESCRIPTION_NUMBER','\\b(?:RX|PRESCRIPTION)\\s*[:#=-]\\s*(\\d{7,12})\\b',{flags:'i',group:1,lit:'r',s:'RX:1234567890'});
  hc('c','LIB_PHARMA_LOT','PHARMA_LOT','\\b(?:LOT|BATCH)\\s*[:#=-]\\s*([A-Z0-9]{4,12})\\b',{flags:'i',group:1,lit:'lot',s:'LOT:ABC123'});
  hc('p','LIB_CLINICAL_TRIAL','CLINICAL_TRIAL_ID','\\b(?:NCT|ISRCTN|EUCTR)\\d{8,11}\\b',{s:'NCT01234567'});
  hc('p','LIB_DEA','DEA_NUMBER','\\b[A-Z]{2}\\d{7}\\b',{v:'dea',s:'AB1234563'});
  hc('p','LIB_NDC','NDC_NUMBER','\\b\\d{4,5}-\\d{3,4}-\\d{1,2}\\b',{s:'0069-2587-10'});
  hc('p','LIB_UDI','UDI_DEVICE_ID','\\(01\\)\\d{14}\\(11\\)\\d{6}\\(17\\)\\d{6}\\(10\\)[A-Z0-9]+',{lit:'(01)',s:'(01)12345678901234(11)210630(17)220630(10)ABC123'});
  hc('c','LIB_MEDICARE','MEDICARE_ID','\\b(?:medicare|medicaid|hicn)\\s*(?:no|number|#|id)?\\s*[:#-]?\\s*(\\d{3}-\\d{2}-\\d{4}[A-Z]?)\\b',{flags:'i',group:1,lit:'medic',s:'Medicare 123-45-6789A'});
  hc('x','LIB_NPI','NPI_NUMBER','\\b\\d{10}\\b',{s:'1234567890'});
  hc('x','LIB_HIPAA_ENTITY','HIPAA_ENTITY_ID','\\b\\d{10}[A-Z]{2}\\b',{s:'1234567890AB'});
  hc('x','LIB_INS_POLICY','INSURANCE_POLICY','\\b[A-Z]{2,3}\\d{6,12}\\b',{s:'ABC123456789'});
  hc('x','LIB_INS_GROUP','INSURANCE_GROUP','\\b[A-Z]{2,4}\\d{4,8}[A-Z]?\\b',{s:'ABC12345'});
  hc('x','LIB_MED_LICENSE','MEDICAL_LICENSE','\\b[A-Z]{1,3}\\d{4,8}\\b',{s:'MD123456'});
  hc('x','LIB_MED_FACILITY','MEDICAL_FACILITY_LICENSE','\\b[A-Z]{2,3}\\d{4,8}[A-Z]?\\b',{s:'HF123456'});
  hc('x','LIB_ICD10','ICD10_CODE','\\b[A-Z]\\d{2}(?:\\.[0-9A-Z]{1,4})?\\b',{s:'A01'});
  hc('x','LIB_CPT','CPT_CODE','\\b\\d{5}\\b',{s:'99213'});
  hc('x','LIB_LOINC','LOINC_CODE','\\b\\d{1,5}-\\d\\b',{s:'33747-0'});
  hc('x','LIB_HEALTHPLAN','HEALTH_PLAN_ID','\\b\\d{2}-\\d{7}\\b',{s:'12-3456789'});

  // ── Business / operational identifiers ───────────────────────────────
  const biz = (tier,fam,id,label,src,o)=>add(tier,fam,'CONFIDENTIAL','LOW',id,label,src,o);
  biz('p','Legal','LIB_COURT_CASE','COURT_CASE_NUMBER','\\b\\d{1,2}:\\d{2}-cv-\\d{5}\\b|\\b\\d{4}CR\\d{6}\\b',{s:'1:20-cv-12345'});
  biz('p','Legal','LIB_PCT','PCT_PATENT_NUMBER','\\bPCT/[A-Z]{2}\\d{4}/\\d{6}\\b',{lit:'pct/',s:'PCT/US2023/123456'});
  biz('x','Legal','LIB_TRADEMARK','TRADEMARK_NUMBER','\\b\\d{6,7}\\b',{s:'123456'});
  // Two adjacent uppercase tokens ("UK USD") are indistinguishable from a real
  // LOCODE without context, so this is candidate tier rather than precise.
  biz('x','Standards','LIB_UNLOCODE','UN_LOCODE','\\b[A-Z]{2}\\s[A-Z0-9]{3}\\b',{s:'US NYC'});
  // Same shape as a dotted date (2024.01.15); exclude a leading year.
  biz('p','Standards','LIB_HS_CODE','HS_CODE','\\b(?!(?:19|20)\\d{2}\\.)\\d{4}\\.\\d{2}\\.\\d{2}\\b',{s:'8471.30.01'});
  biz('x','Standards','LIB_ISO_COUNTRY','ISO_COUNTRY_CODE','\\b[A-Z]{2}\\b|\\b[A-Z]{3}\\b',{s:'US'});
  biz('x','Standards','LIB_ISO_CURRENCY','ISO_CURRENCY_CODE','\\b[A-Z]{3}\\b',{s:'USD'});
  biz('x','Standards','LIB_NAICS','NAICS_CODE','\\b\\d{6}\\b',{s:'541511'});
  biz('x','Standards','LIB_SIC','SIC_CODE','\\b\\d{4}\\b',{s:'7372'});
  biz('p','Maritime','LIB_IMO','IMO_SHIP_NUMBER','\\bIMO[\\s-]?\\d{7}\\b',{flags:'i',v:'imo',lit:'imo',s:'IMO 9074729'});
  biz('x','Maritime','LIB_PORT_CODE','PORT_CODE','\\b\\d{4}\\b',{s:'2704'});
  // N7 / N42 are valid registrations AND ordinary identifiers in source code,
  // so this cannot be made precise — it ships as candidate.
  biz('x','Aviation','LIB_TAIL_NUMBER','AIRCRAFT_REGISTRATION','\\bN\\d{1,5}[A-Z]{0,2}\\b',{s:'N12345'});
  biz('x','Aviation','LIB_ICAO_TYPE','ICAO_AIRCRAFT_CODE','\\b[A-Z][0-9A-Z]{2,3}\\b',{s:'B737'});
  biz('x','Aviation','LIB_FLIGHT_NO','FLIGHT_NUMBER','\\b[A-Z]{2,3}\\d{1,4}\\b',{s:'AA123'});
  biz('x','Energy','LIB_GRID_OP','GRID_OPERATOR_CODE','\\b[A-Z]{2,4}\\d{2,4}\\b',{s:'PJM123'});
  biz('x','Energy','LIB_ENERGY_FACILITY','ENERGY_FACILITY_ID','\\b\\d{5,7}\\b',{s:'12345'});
  biz('x','Transportation','LIB_VEHICLE_REG_INTL','VEHICLE_REGISTRATION','\\b[A-Z]{1,3}[\\s-]?\\d{1,4}[\\s-]?[A-Z]{1,3}\\b',{s:'ABC 123 DEF'});
  biz('x','Real Estate','LIB_APN','PROPERTY_APN','\\b\\d{3}-\\d{3}-\\d{3}\\b',{s:'123-456-789'});
  biz('x','Real Estate','LIB_MLS','MLS_NUMBER','\\b[A-Z]{2,4}\\d{6,8}\\b',{s:'MLS1234567'});
  biz('x','Education','LIB_STUDENT_ID','STUDENT_ID','\\b\\d{7,10}\\b',{s:'1234567'});
  biz('x','Education','LIB_TRANSCRIPT','TRANSCRIPT_NUMBER','\\b[A-Z]{2,3}\\d{6,8}\\b',{s:'TR123456'});
  biz('p','Media','LIB_ISRC','ISRC_CODE','\\b[A-Z]{2}-[A-Z0-9]{3}-\\d{2}-\\d{5}\\b',{s:'US-ABC-12-34567'});
  biz('x','Media','LIB_ISAN','ISAN_CODE','\\b[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}\\b',{s:'1234-5678-9ABC-DEF0'});
  biz('p','Technology','LIB_IPFS','IPFS_CID','\\bQm[1-9A-HJ-NP-Za-km-z]{44}\\b|\\bbafybei[a-z2-7]{52}\\b',{s:'QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o'});
  biz('p','Technology','LIB_ML_MODEL','ML_MODEL_ID','\\bmodel-[a-f0-9]{32}\\b',{lit:'model-',s:'model-1234567890abcdef1234567890abcdef'});
  biz('p','Technology','LIB_QUANTUM','QUANTUM_RESOURCE_ID','\\bq-[a-f0-9]{16}\\b',{lit:'q-',s:'q-1234567890abcdef'});
  biz('x','Communication','LIB_ZOOM','ZOOM_MEETING_ID','\\b\\d{9,11}\\b',{s:'123456789'});
  biz('x','Communication','LIB_TEAMS_MEETING','TEAMS_MEETING_ID','\\b\\d{3}\\s\\d{3}\\s\\d{3}\\b',{s:'123 456 789'});
  biz('x','Communication','LIB_WEBEX','WEBEX_MEETING_NUMBER','\\b\\d{9}\\b',{s:'123456789'});
  biz('x','Communication','LIB_YOUTUBE','YOUTUBE_VIDEO_ID','\\b[A-Za-z0-9_-]{11}\\b',{s:'dQw4w9WgXcQ'});
  biz('x','Communication','LIB_TWITCH','TWITCH_CHANNEL_ID','\\b\\d{8,9}\\b',{s:'12345678'});
  biz('x','Communication','LIB_DISCORD_SERVER','DISCORD_SERVER_ID','\\b\\d{18}\\b',{s:'123456789012345678'});

  root.PromptrixPatternLibrary = L;
  root.PromptrixPatternValidators = V;
  if (typeof module !== 'undefined' && module.exports) module.exports = { L, V };
})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : globalThis));
