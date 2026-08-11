/**
 * AI Prompt Guard — Standalone PII Detector v2
 * Runs directly in the browser as a content script (no Node.js / require).
 * Exposes: window.PiiDetector.detect(text) → { found, detections, sanitizedText, categories, regulations, highSeverity }
 *
 * Improvements v2:
 *  - Luhn checksum validation on credit card matches (eliminates ~90% false positives)
 *  - Indian Aadhaar, PAN card, UK NI, Passport patterns
 *  - DOB false-positive guard (rejects version/code contexts like "v1.2" or "page 3/4")
 *  - Confidence score per detection: 'high' | 'medium' | 'low'
 *  - Allow list: matches in the user's allow list are silently skipped
 */
/* global _b */
(function () {
  'use strict';

  // ── Luhn checksum (credit card validation) ────────────────────────────────

  function luhn(numStr) {
    const digits = numStr.replace(/\D/g, '');
    let sum = 0;
    let alt = false;
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
      category:   'ssn',
      regex:      /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
      label:      'SSN',
      confidence: 'high',
    },
    {
      category:   'credit_card',
      // Visa · Mastercard · Amex · Discover — filtered by Luhn in postFilter
      regex:      /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
      label:      'Credit Card',
      confidence: 'high',
      postFilter: (match) => luhn(match),
    },
    {
      category:   'email',
      regex:      /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
      label:      'Email',
      confidence: 'high',
    },
    {
      category:   'phone',
      regex:      /(?<!\d)(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})(?!\d)/g,
      label:      'Phone',
      confidence: 'medium',
    },
    {
      category:   'iban',
      regex:      /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b/g,
      label:      'IBAN',
      confidence: 'high',
    },
    {
      category:   'dob',
      // Covers: DD/MM/YYYY · MM/DD/YYYY · DD-MM-YYYY · DD.MM.YYYY · YYYY-MM-DD
      // Year is any 4-digit number. postFilter rejects version/page/code contexts.
      regex:      /\b(?:(0?[1-9]|[12]\d|3[01])[\/\-\.](0?[1-9]|[12]\d|3[01])[\/\-\.]\d{4}|\d{4}[\/\-\.](0?[1-9]|1[0-2])[\/\-\.](0?[1-9]|[12]\d|3[01]))\b/g,
      label:      'Date of Birth',
      confidence: 'medium',
      // Reject if preceded by "v", "ver", "version", "page", "p.", "#", or followed by common code suffixes
      postFilter: (match, fullText, matchIndex) => {
        const before = fullText.slice(Math.max(0, matchIndex - 10), matchIndex).toLowerCase();
        const after  = fullText.slice(matchIndex + match.length, matchIndex + match.length + 6).toLowerCase();
        if (/(?:ver(?:sion)?|^v|page|p\.\s*|#\s*)\s*$/.test(before.trimStart())) return false;
        if (/^[a-z]/.test(after)) return false; // likely a version suffix like "2024-01-01-alpha"
        return true;
      },
    },
    {
      category:   'health',
      regex:      /\b(diagnos(?:ed|is)|patient\s+(?:id|name)?|medical\s+record|prescription|symptom|treatment(?:\s+plan)?|HIV|diabetes|cancer|hypertension|allergic|icd[-\s]?\d+)\b/gi,
      label:      'Health Data',
      confidence: 'medium',
    },
    {
      category:   'credentials',
      regex:      /\b(password|passwd|secret|api[_\-\s]?key|token|private[_\-\s]?key)\s*[:=]\s*\S+/gi,
      label:      'Credentials',
      confidence: 'high',
    },
    {
      category:   'name',
      // Lookbehind prefix only — requires explicit context before matching a name
      regex:      /(?<=(?:(?:my\s+)?(?:full\s+)?name|patient|customer|employee|user|applicant)\s*(?:[:=\-]|is)\s*|(?:i\s+am|i'm|call\s+me|known\s+as)\s+|(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+)[A-Za-z][a-z]+(?:\s+[A-Za-z][a-z]+){0,3}\b/gi,
      label:      'Name',
      confidence: 'low',
      postFilter: v => {
        const STOP = /^(and|or|my|your|his|her|their|our|the|is|are|was|were|not|a|an|of|in|on|at|to|for|with|by|called|said|told|asked|number|email|phone|address|feeling|well|fine|here|there)$/i;
        const words = v.trim().split(/\s+/);
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
      category:   'address',
      regex:      /\b\d{1,5}\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\.?\b/gi,
      label:      'Address',
      confidence: 'medium',
    },
    // ── Country-specific IDs ─────────────────────────────────────────────────
    {
      category:   'aadhaar',
      // Indian Aadhaar: 12 digits, often written as XXXX XXXX XXXX
      regex:      /\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
      label:      'Aadhaar',
      confidence: 'medium',
      postFilter: (match) => match.replace(/\D/g, '').length === 12,
    },
    {
      category:   'pan',
      // Indian PAN: ABCDE1234F
      regex:      /\b[A-Z]{3}[ABCFGHLJPTF][A-Z]\d{4}[A-Z]\b/gi,
      label:      'PAN Card',
      confidence: 'high',
    },
    {
      category:   'uk_ni',
      // UK National Insurance: AB 12 34 56 C
      regex:      /\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi,
      label:      'UK NI Number',
      confidence: 'high',
    },
    {
      category:   'passport',
      // Generic passport: letter(s) + 6–9 digits (covers US, UK, IN, DE formats)
      regex:      /\b[A-Z]{1,2}\d{6,9}\b/g,
      label:      'Passport',
      confidence: 'low',
      // Require passport context keyword within 40 chars before
      postFilter: (match, fullText, matchIndex) => {
        const context = fullText.slice(Math.max(0, matchIndex - 40), matchIndex).toLowerCase();
        return /passport|travel\s+doc|travel\s+id/.test(context);
      },
    },
    {
      category:   'bank_account',
      // Bank account when preceded by explicit keywords
      regex:      /(?:account(?:\s+number)?|acct\.?)\s*[:\-]?\s*\d{8,17}\b/gi,
      label:      'Bank Account',
      confidence: 'high',
    },
    // ── Global patterns (from pii-regex-library) ──────────────────────────
    {
      category:   'ipv4',
      regex:      /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
      label:      'IPv4 Address',
      confidence: 'medium',
      postFilter: (m) => !/^0\.0\.0\.0$/.test(m),
    },
    {
      category:   'ipv6',
      regex:      /\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:)*::(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4}\b/g,
      label:      'IPv6 Address',
      confidence: 'medium',
    },
    {
      category:   'geolocation',
      regex:      /(?:lat(?:itude)?|lng|lon(?:gitude)?)\s*[:=]\s*-?(?:90(?:\.0+)?|[0-8]?\d(?:\.\d+)?)\s*,?\s*-?(?:180(?:\.0+)?|1[0-7]\d(?:\.\d+)?|[0-9]?\d(?:\.\d+)?)/gi,
      label:      'Geolocation',
      confidence: 'high',
    },
    {
      category:   'ethnicity',
      regex:      /\b(?:ethnicity|race|racial\s+group)\s*[:=]\s*(?:asian|black|white|hispanic|latino|african[\s-]american|caucasian|arab|jewish|native[\s-]american|pacific[\s-]islander|biracial|multiracial)\b/gi,
      label:      'Ethnicity',
      confidence: 'high',
    },
    {
      category:   'religion',
      regex:      /\b(?:religion|faith|belief)\s*[:=]\s*(?:christian|catholic|muslim|islam|hindu|buddhist|jewish|sikh|atheist|agnostic)\b/gi,
      label:      'Religion',
      confidence: 'high',
    },
    {
      category:   'gender',
      regex:      /\b(?:gender|sex)\s*[:=]\s*(?:male|female|non[\s-]?binary|transgender|trans)\b/gi,
      label:      'Gender',
      confidence: 'medium',
    },
    {
      category:   'drivers_license',
      regex:      /\b(?:driver'?s?\s+licen[sc]e|dl\s*(?:number|no|#)?)\s*[:=\-]?\s*[A-Z0-9]{5,15}\b/gi,
      label:      "Driver's License",
      confidence: 'medium',
    },
    {
      category:   'vehicle_reg',
      regex:      /\b(?:vehicle\s+reg(?:istration)?|license\s+plate|number\s+plate)\s*[:=\-]?\s*[A-Z0-9]{2,8}\b/gi,
      label:      'Vehicle Registration',
      confidence: 'medium',
    },
  ];

  // Which regulations each category maps to
  const REGULATION_MAP = {
    ssn:             ['GDPR', 'CCPA', 'HIPAA'],
    credit_card:     ['GDPR', 'CCPA', 'PCI-DSS'],
    email:           ['GDPR', 'CCPA'],
    phone:           ['GDPR', 'CCPA'],
    iban:            ['GDPR', 'PSD2'],
    dob:             ['GDPR', 'CCPA', 'HIPAA'],
    health:          ['GDPR', 'HIPAA'],
    credentials:     ['GDPR', 'CCPA'],
    name:            ['GDPR', 'CCPA'],
    address:         ['GDPR', 'CCPA'],
    aadhaar:         ['PDPA', 'GDPR'],
    pan:             ['PDPA'],
    uk_ni:           ['GDPR', 'UK-GDPR'],
    passport:        ['GDPR', 'CCPA'],
    bank_account:    ['GDPR', 'PCI-DSS'],
    ipv4:            ['GDPR', 'CCPA'],
    ipv6:            ['GDPR', 'CCPA'],
    geolocation:     ['GDPR', 'CCPA'],
    ethnicity:       ['GDPR Art.9', 'CCPA'],
    religion:        ['GDPR Art.9', 'CCPA'],
    gender:          ['GDPR Art.9', 'CCPA'],
    drivers_license: ['GDPR', 'CCPA'],
    vehicle_reg:     ['GDPR', 'CCPA'],
  };

  // High-severity categories (trigger admin alert in backend)
  const HIGH_SEVERITY = new Set(['ssn', 'credit_card', 'health', 'credentials', 'iban', 'aadhaar', 'pan', 'uk_ni', 'bank_account', 'ethnicity', 'religion', 'geolocation']);

  // ── Custom rules (user-defined) ───────────────────────────────────────────

  let _customRules = [];

  /**
   * Load user-defined regex rules from _b.storage.
   * Each rule: { label, pattern, flags, confidence }
   */
  function setCustomRules(rules) {
    _customRules = (rules || []).map(r => {
      try {
        const flags = (r.flags || 'gi').includes('g') ? (r.flags || 'gi') : (r.flags || 'gi') + 'g';
        return { category: 'custom', regex: new RegExp(r.pattern, flags), label: r.label || 'Custom', confidence: r.confidence || 'medium' };
      } catch (_) { return null; }
    }).filter(Boolean);
  }

  // ── Allow list ────────────────────────────────────────────────────────────
  let _allowList = new Set();

  function _ctxOk() { return typeof chrome !== 'undefined' && !!chrome?.runtime?.id; }

  // Load allow list and custom rules from storage (non-blocking; chrome may not be available in tests)
  if (_ctxOk() && _b.storage) {
    _b.storage.local.get(['piiAllowList', 'customRules'], (data) => {
      if (_b.runtime.lastError) return;
      _allowList = new Set(data.piiAllowList || []);
      if (data.customRules) setCustomRules(data.customRules);
    });
    _b.storage.onChanged.addListener((changes) => {
      if ('piiAllowList' in changes) {
        _allowList = new Set(changes.piiAllowList.newValue || []);
      }
      if ('customRules' in changes) {
        setCustomRules(changes.customRules.newValue || []);
      }
    });
  }

  function addToAllowList(value) {
    _allowList.add(value.trim().toLowerCase());
    if (_ctxOk() && _b.storage) {
      try {
        _b.storage.local.set({ piiAllowList: [..._allowList] });
      } catch (_) { /* context invalidated */ }
    }
  }

  // ── Core detection ────────────────────────────────────────────────────────

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

        // Allow list check
        if (_allowList.has(value.trim().toLowerCase())) continue;

        // Post-filter (Luhn, context guards, name trimming, etc.)
        if (postFilter) {
          const result = postFilter(value, text, match.index);
          if (!result) continue;
          if (typeof result === 'string') value = result;
        }

        detections.push({
          category,
          label,
          value,
          confidence,
          index: match.index,
          end:   match.index + value.length,
        });
      }
      regex.lastIndex = 0;
    }

    for (const { category, regex, label, confidence } of _customRules) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(text)) !== null) {
        if (_allowList.has(match[0].trim().toLowerCase())) continue;
        detections.push({ category, label, value: match[0], confidence, index: match.index, end: match.index + match[0].length });
      }
      regex.lastIndex = 0;
    }

    if (detections.length === 0) {
      return { found: false, detections: [], sanitizedText: text, categories: [], regulations: [], highSeverity: false };
    }

    // Sort by position, resolve overlaps (keep longest span)
    detections.sort((a, b) => a.index - b.index || b.end - a.end);
    const resolved = [];
    let cursor = 0;
    for (const d of detections) {
      if (d.index >= cursor) {
        resolved.push(d);
        cursor = d.end;
      }
    }

    // Build sanitized text
    let sanitized = '';
    let pos = 0;
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

  // ── Encryption (AES-GCM via Web Crypto API) ───────────────────────────────

  let _cryptoKey = null;

  async function _loadOrCreateKey() {
    if (_cryptoKey) return _cryptoKey;

    // Try to load persisted key from storage
    if (_ctxOk() && _b.storage) {
      try {
        const data = await new Promise((resolve, reject) => {
          _b.storage.local.get(['piiEncryptionKey'], (d) => {
            if (_b.runtime.lastError) reject(_b.runtime.lastError);
            else resolve(d);
          });
        });
        if (data.piiEncryptionKey) {
          _cryptoKey = await crypto.subtle.importKey(
            'jwk', data.piiEncryptionKey,
            { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
          );
          return _cryptoKey;
        }
      } catch (_) { /* context invalidated or storage error — generate fresh key */ }
    }

    // Generate a new key and persist it if possible
    _cryptoKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
    if (_ctxOk() && _b.storage) {
      try {
        const jwk = await crypto.subtle.exportKey('jwk', _cryptoKey);
        _b.storage.local.set({ piiEncryptionKey: jwk });
      } catch (_) { /* context invalidated — key lives in memory only this session */ }
    }
    return _cryptoKey;
  }

  async function _encryptValue(plaintext, key) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const cipherBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, enc.encode(plaintext)
    );
    // Pack iv + ciphertext as base64
    const combined = new Uint8Array(iv.byteLength + cipherBuf.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipherBuf), iv.byteLength);
    return btoa(String.fromCharCode(...combined));
  }

  /**
   * detectAndEncrypt(text) → Promise<{ found, encryptedText, categories, regulations, highSeverity }>
   *
   * Detects PII in `text`, encrypts each value with AES-GCM, and returns the
   * text with tokens like [ENC:pan:base64...] — safe to pass to Claude.
   */
  async function detectAndEncrypt(text) {
    const result = detect(text);
    if (!result.found) return { found: false, encryptedText: text, ...result };

    const key = await _loadOrCreateKey();

    // Build encrypted text by walking resolved detections in order
    let encrypted = '';
    let pos = 0;
    for (const d of result.detections) {
      encrypted += text.slice(pos, d.index);
      const token = await _encryptValue(d.value, key);
      encrypted += `[ENC:${d.category}:${token}]`;
      pos = d.end;
    }
    encrypted += text.slice(pos);

    return {
      found:        true,
      encryptedText: encrypted,
      detections:   result.detections,
      categories:   result.categories,
      regulations:  result.regulations,
      highSeverity: result.highSeverity,
    };
  }

  // ── Export ────────────────────────────────────────────────────────────────

  window.PiiDetector = { detect, detectAndEncrypt, addToAllowList, setCustomRules };
})();
