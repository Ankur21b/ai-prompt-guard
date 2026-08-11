'use strict';

/**
 * AI Prompt Guard — PII Detector (Node.js)
 * Mirrors pii-detector.js but runs in Node.js (VS Code extension host).
 * Uses Node's built-in `crypto.webcrypto` for AES-GCM encryption.
 * No external dependencies.
 */

const { webcrypto } = require('node:crypto');
const subtle = webcrypto.subtle;

// ── Luhn checksum ─────────────────────────────────────────────────────────

function luhn(numStr) {
  const digits = numStr.replace(/\D/g, '');
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// ── Patterns ──────────────────────────────────────────────────────────────

const PATTERNS = [
  {
    category: 'ssn',
    regex: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
    label: 'SSN', confidence: 'high',
  },
  {
    category: 'credit_card',
    regex: /\b(?:4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    label: 'Credit Card', confidence: 'high',
    postFilter: (m) => luhn(m),
  },
  {
    category: 'email',
    regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    label: 'Email', confidence: 'high',
  },
  {
    category: 'phone',
    regex: /(?<!\d)(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})(?!\d)/g,
    label: 'Phone', confidence: 'medium',
  },
  {
    category: 'iban',
    regex: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b/g,
    label: 'IBAN', confidence: 'high',
  },
  {
    category: 'dob',
    regex: /\b(?:(0?[1-9]|[12]\d|3[01])[\/\-\.](0?[1-9]|[12]\d|3[01])[\/\-\.]\d{4}|\d{4}[\/\-\.](0?[1-9]|1[0-2])[\/\-\.](0?[1-9]|[12]\d|3[01]))\b/g,
    label: 'Date of Birth', confidence: 'medium',
    postFilter: (match, fullText, matchIndex) => {
      const before = fullText.slice(Math.max(0, matchIndex - 10), matchIndex).toLowerCase();
      const after  = fullText.slice(matchIndex + match.length, matchIndex + match.length + 6).toLowerCase();
      if (/(?:ver(?:sion)?|^v|page|p\.\s*|#\s*)\s*$/.test(before.trimStart())) return false;
      if (/^[a-z]/.test(after)) return false;
      return true;
    },
  },
  {
    category: 'health',
    regex: /\b(diagnos(?:ed|is)|patient\s+(?:id|name)?|medical\s+record|prescription|symptom|treatment(?:\s+plan)?|HIV|diabetes|cancer|hypertension|allergic|icd[-\s]?\d+)\b/gi,
    label: 'Health Data', confidence: 'medium',
  },
  {
    category: 'credentials',
    regex: /\b(password|passwd|secret|api[_\-\s]?key|token|private[_\-\s]?key)\s*[:=]\s*\S+/gi,
    label: 'Credentials', confidence: 'high',
  },
  {
    category: 'name',
    regex: /(?<=(?:(?:my\s+)?(?:full\s+)?name|patient|customer|employee|user|applicant)\s*(?:[:=\-]|is)\s*|(?:i\s+am|i'm|call\s+me|known\s+as)\s+|(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+)[A-Za-z][a-z]+(?:\s+[A-Za-z][a-z]+){0,3}\b/gi,
    label: 'Name', confidence: 'low',
    postFilter: v => {
      const STOP = /^(and|or|my|your|his|her|their|our|the|is|are|was|were|not|a|an|of|in|on|at|to|for|with|by|called|said|told|asked|number|email|phone|address|feeling|well|fine|here|there)$/i;
      const words = v.trim().split(/\s+/);
      // drop leading and trailing stop words
      while (words.length && STOP.test(words[0]))  words.shift();
      while (words.length && STOP.test(words[words.length - 1])) words.pop();
      if (words.length === 0) return false;
      // Real names are Title Case. The /i flag lets the regex match lowercase words
      // after context like "I am passionate…" — reject if any word is not capitalised.
      if (!words.every(w => /^[A-Z]/.test(w))) return false;
      const cleaned = words.join(' ');
      return cleaned !== v ? cleaned : true;
    },
  },
  {
    category: 'address',
    regex: /\b\d{1,5}\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\.?\b/gi,
    label: 'Address', confidence: 'medium',
  },
  {
    category: 'aadhaar',
    regex: /\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
    label: 'Aadhaar', confidence: 'medium',
    postFilter: (m) => m.replace(/\D/g, '').length === 12,
  },
  {
    category: 'pan',
    regex: /\b[A-Z]{3}[ABCFGHLJPTF][A-Z]\d{4}[A-Z]\b/gi,
    label: 'PAN Card', confidence: 'high',
  },
  {
    category: 'uk_ni',
    regex: /\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi,
    label: 'UK NI Number', confidence: 'high',
  },
  {
    category: 'passport',
    regex: /\b[A-Z]{1,2}\d{6,9}\b/g,
    label: 'Passport', confidence: 'low',
    postFilter: (match, fullText, matchIndex) => {
      const context = fullText.slice(Math.max(0, matchIndex - 40), matchIndex).toLowerCase();
      return /passport|travel\s+doc|travel\s+id/.test(context);
    },
  },
  {
    category: 'bank_account',
    regex: /(?:account(?:\s+number)?|acct\.?)\s*[:\-]?\s*\d{8,17}\b/gi,
    label: 'Bank Account', confidence: 'high',
  },
  // ── Global patterns (from pii-regex-library) ────────────────────────────
  {
    category: 'ipv4',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    label: 'IPv4 Address', confidence: 'medium',
    postFilter: (m) => {
      // Reject obvious non-IPs: version strings like 1.0.0.0, all-zeros
      if (/^0\.0\.0\.0$/.test(m)) return false;
      return true;
    },
  },
  {
    category: 'ipv6',
    regex: /\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:)*::(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4}\b/g,
    label: 'IPv6 Address', confidence: 'medium',
  },
  {
    category: 'geolocation',
    regex: /(?:lat(?:itude)?|lng|lon(?:gitude)?)\s*[:=]\s*-?(?:90(?:\.0+)?|[0-8]?\d(?:\.\d+)?)\s*,?\s*-?(?:180(?:\.0+)?|1[0-7]\d(?:\.\d+)?|[0-9]?\d(?:\.\d+)?)/gi,
    label: 'Geolocation', confidence: 'high',
  },
  {
    category: 'ethnicity',
    regex: /\b(?:ethnicity|race|racial\s+group)\s*[:=]\s*(?:asian|black|white|hispanic|latino|african[\s-]american|caucasian|arab|jewish|native[\s-]american|pacific[\s-]islander|biracial|multiracial)\b/gi,
    label: 'Ethnicity', confidence: 'high',
  },
  {
    category: 'religion',
    regex: /\b(?:religion|faith|belief)\s*[:=]\s*(?:christian|catholic|muslim|islam|hindu|buddhist|jewish|sikh|atheist|agnostic)\b/gi,
    label: 'Religion', confidence: 'high',
  },
  {
    category: 'gender',
    regex: /\b(?:gender|sex)\s*[:=]\s*(?:male|female|non[\s-]?binary|transgender|trans)\b/gi,
    label: 'Gender', confidence: 'medium',
  },
  {
    category: 'drivers_license',
    regex: /\b(?:driver'?s?\s+licen[sc]e|dl\s*(?:number|no|#)?)\s*[:=\-]?\s*[A-Z0-9]{5,15}\b/gi,
    label: "Driver's License", confidence: 'medium',
  },
  {
    category: 'vehicle_reg',
    regex: /\b(?:vehicle\s+reg(?:istration)?|license\s+plate|number\s+plate)\s*[:=\-]?\s*[A-Z0-9]{2,8}\b/gi,
    label: 'Vehicle Registration', confidence: 'medium',
  },
];

const REGULATION_MAP = {
  ssn:           ['GDPR', 'CCPA', 'HIPAA'],
  credit_card:   ['GDPR', 'CCPA', 'PCI-DSS'],
  email:         ['GDPR', 'CCPA'],
  phone:         ['GDPR', 'CCPA'],
  iban:          ['GDPR', 'PSD2'],
  dob:           ['GDPR', 'CCPA', 'HIPAA'],
  health:        ['GDPR', 'HIPAA'],
  credentials:   ['GDPR', 'CCPA'],
  name:          ['GDPR', 'CCPA'],
  address:       ['GDPR', 'CCPA'],
  aadhaar:       ['PDPA', 'GDPR'],
  pan:           ['PDPA'],
  uk_ni:         ['GDPR', 'UK-GDPR'],
  passport:      ['GDPR', 'CCPA'],
  bank_account:  ['GDPR', 'PCI-DSS'],
  ipv4:          ['GDPR', 'CCPA'],
  ipv6:          ['GDPR', 'CCPA'],
  geolocation:   ['GDPR', 'CCPA'],
  ethnicity:     ['GDPR Art.9', 'CCPA'],
  religion:      ['GDPR Art.9', 'CCPA'],
  gender:        ['GDPR Art.9', 'CCPA'],
  drivers_license: ['GDPR', 'CCPA'],
  vehicle_reg:   ['GDPR', 'CCPA'],
};

const HIGH_SEVERITY = new Set([
  'ssn', 'credit_card', 'health', 'credentials', 'iban', 'aadhaar', 'pan', 'uk_ni', 'bank_account',
  'ethnicity', 'religion', 'geolocation',
]);

// ── Custom rules (user-defined) ────────────────────────────────────────────

let _customRules = [];

/**
 * Load user-defined rules from VS Code settings.
 * Each rule: { label, pattern, flags, confidence }
 */
function setCustomRules(rules) {
  _customRules = (rules || []).map(r => {
    try {
      return {
        category: 'custom',
        regex:      new RegExp(r.pattern, (r.flags || 'gi').includes('g') ? r.flags || 'gi' : (r.flags || 'gi') + 'g'),
        label:      r.label || 'Custom',
        confidence: r.confidence || 'medium',
      };
    } catch (_) {
      return null; // invalid regex — skip silently
    }
  }).filter(Boolean);
}

// ── Core detection ─────────────────────────────────────────────────────────

function detect(text) {
  if (!text || typeof text !== 'string') {
    return { found: false, detections: [], sanitizedText: text, categories: [], regulations: [], highSeverity: false };
  }

  const detections = [];

  for (const { category, regex, label, confidence, postFilter } of PATTERNS) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(text)) !== null) {
      let value = match[0];
      if (postFilter) {
        const result = postFilter(value, text, match.index);
        if (!result) continue;
        if (typeof result === 'string') value = result;
      }
      detections.push({ category, label, value, confidence, index: match.index, end: match.index + value.length });
    }
    regex.lastIndex = 0;
  }

  for (const { category, regex, label, confidence } of _customRules) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(text)) !== null) {
      detections.push({ category, label, value: match[0], confidence, index: match.index, end: match.index + match[0].length });
    }
    regex.lastIndex = 0;
  }

  if (detections.length === 0) {
    return { found: false, detections: [], sanitizedText: text, categories: [], regulations: [], highSeverity: false };
  }

  detections.sort((a, b) => a.index - b.index || b.end - a.end);
  const resolved = [];
  let cursor = 0;
  for (const d of detections) {
    if (d.index >= cursor) { resolved.push(d); cursor = d.end; }
  }

  let sanitized = '', pos = 0;
  for (const d of resolved) {
    sanitized += text.slice(pos, d.index);
    sanitized += `[${d.label.toUpperCase().replace(/ /g, '_')}_REDACTED]`;
    pos = d.end;
  }
  sanitized += text.slice(pos);

  const categories  = [...new Set(resolved.map(d => d.category))];
  const regulations = [...new Set(categories.flatMap(c => REGULATION_MAP[c] || []))];
  const highSeverity = categories.some(c => HIGH_SEVERITY.has(c));

  return { found: true, detections: resolved, sanitizedText: sanitized, categories, regulations, highSeverity };
}

// ── Encryption (AES-GCM via Node webcrypto) ────────────────────────────────

let _cryptoKey = null;

async function _loadOrCreateKey(context) {
  if (_cryptoKey) return _cryptoKey;

  const stored = context?.globalState?.get('piiEncryptionKey');
  if (stored) {
    _cryptoKey = await subtle.importKey('jwk', stored, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
    return _cryptoKey;
  }

  _cryptoKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  if (context?.globalState) {
    const jwk = await subtle.exportKey('jwk', _cryptoKey);
    await context.globalState.update('piiEncryptionKey', jwk);
  }
  return _cryptoKey;
}

async function _encryptValue(plaintext, key) {
  const iv      = webcrypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const cipher  = await subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const combined = new Uint8Array(iv.byteLength + cipher.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipher), iv.byteLength);
  return Buffer.from(combined).toString('base64');
}

/**
 * detectAndEncrypt(text, vsCodeContext?)
 *   → Promise<{ found, encryptedText, detections, categories, regulations, highSeverity }>
 *
 * Detects PII and replaces each value with [ENC:category:base64] — safe to send to Claude.
 * vsCodeContext: the VS Code ExtensionContext for persisting the encryption key.
 */
async function detectAndEncrypt(text, context) {
  const result = detect(text);
  if (!result.found) return { found: false, encryptedText: text, ...result };

  const key = await _loadOrCreateKey(context);

  let encrypted = '', pos = 0;
  for (const d of result.detections) {
    encrypted += text.slice(pos, d.index);
    const token = await _encryptValue(d.value, key);
    encrypted += `[ENC:${d.category}:${token}]`;
    pos = d.end;
  }
  encrypted += text.slice(pos);

  return {
    found: true,
    encryptedText: encrypted,
    detections:    result.detections,
    categories:    result.categories,
    regulations:   result.regulations,
    highSeverity:  result.highSeverity,
  };
}

module.exports = { detect, detectAndEncrypt, setCustomRules };
