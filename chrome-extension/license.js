'use strict';

/**
 * AI Prompt Guard — License Manager (Chrome Extension)
 *
 * Free features:  basic PII scan, site toggles, stats
 * Pro features:   custom rules, file scanning, audit log export
 */
/* global _b */

const LICENSE_API = 'https://ai-prompt-guard.onrender.com/api/license/validate';
const CACHE_TTL   = 24 * 60 * 60 * 1000; // 24 hours

const PRO_FEATURES = ['custom_rules', 'file_scanning', 'audit_log'];

const LicenseManager = {

  // ── Validate key against server (with 24h local cache) ────────────────────
  async validate(key) {
    if (!key) return { valid: false, plan: 'free', features: [] };

    // Check cache
    const cached = await this._getCached(key);
    if (cached) return cached;

    try {
      const res  = await fetch(LICENSE_API, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ key }),
      });
      const data = await res.json();
      if (data.valid) await this._setCache(key, data);
      return data;
    } catch {
      // Offline fallback — trust cached result if available (even expired)
      const stale = await this._getCached(key, true);
      if (stale) return { ...stale, offline: true };
      return { valid: false, plan: 'free', features: [], error: 'offline' };
    }
  },

  // ── Check if a specific feature is unlocked ───────────────────────────────
  async hasFeature(feature) {
    const { licenseKey, licenseCache } = await this._load();
    if (!licenseKey) return false;
    if (licenseCache?.features?.includes(feature)) return true;
    const result = await this.validate(licenseKey);
    return result.valid && result.features?.includes(feature);
  },

  // ── Save license key + trigger validation ─────────────────────────────────
  async activate(key) {
    const result = await this.validate(key);
    if (result.valid) {
      await new Promise(r => _b.storage.sync.set({ licenseKey: key }, r));
    }
    return result;
  },

  // ── Remove license ─────────────────────────────────────────────────────────
  async deactivate() {
    await new Promise(r => _b.storage.sync.remove(['licenseKey', 'licenseCache'], r));
  },

  // ── Get current plan info ─────────────────────────────────────────────────
  async getPlan() {
    const { licenseKey } = await this._load();
    if (!licenseKey) return { plan: 'free', features: [] };
    return this.validate(licenseKey);
  },

  // ── Internal helpers ──────────────────────────────────────────────────────
  async _load() {
    return new Promise(r => _b.storage.sync.get(['licenseKey', 'licenseCache'], r));
  },

  async _getCached(key, allowStale = false) {
    const { licenseCache } = await this._load();
    if (!licenseCache || licenseCache.key !== key) return null;
    if (!allowStale && Date.now() > licenseCache.expiresAt) return null;
    return licenseCache.data;
  },

  async _setCache(key, data) {
    const licenseCache = { key, data, expiresAt: Date.now() + CACHE_TTL };
    await new Promise(r => _b.storage.sync.set({ licenseCache }, r));
  },
};

// Export for use in popup.js and content.js
if (typeof module !== 'undefined') module.exports = LicenseManager;
else window.LicenseManager = LicenseManager;
