'use strict';

/**
 * AI Prompt Guard — License Manager (VS Code Extension)
 *
 * Free:       basic PII scan, highlights, toggle
 * Pro:        custom rules, file/doc scanning, audit log
 * Enterprise: all Pro + team policies, priority support
 */

const https   = require('https');
const vscode  = require('vscode');

const LICENSE_API_HOST = 'ai-prompt-guard.onrender.com';
const LICENSE_API_PATH = '/api/license/validate';
const CACHE_KEY        = 'apg.licenseCache';
const CACHE_TTL        = 24 * 60 * 60 * 1000; // 24h

function httpsPost(data) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(data);
    const req  = https.request(
      { hostname: LICENSE_API_HOST, path: LICENSE_API_PATH, method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      (res) => {
        let raw = '';
        res.on('data', c => raw += c);
        res.on('end',  () => { try { resolve(JSON.parse(raw)); } catch { reject(new Error('bad json')); } });
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

class LicenseManager {
  constructor(context) {
    this._ctx = context;
  }

  // ── Validate key (with 24h cache) ──────────────────────────────────────────
  async validate(key) {
    if (!key) return { valid: false, plan: 'free', features: [] };

    const cached = this._getCached(key);
    if (cached) return cached;

    try {
      const result = await httpsPost({ key });
      if (result.valid) this._setCache(key, result);
      return result;
    } catch {
      const stale = this._getCached(key, true);
      if (stale) return { ...stale, offline: true };
      return { valid: false, plan: 'free', features: [], error: 'offline' };
    }
  }

  // ── Check feature ──────────────────────────────────────────────────────────
  async hasFeature(feature) {
    const key = this._getStoredKey();
    if (!key) return false;
    const result = await this.validate(key);
    return result.valid && Array.isArray(result.features) && result.features.includes(feature);
  }

  // ── Activate from command ──────────────────────────────────────────────────
  async activateInteractive() {
    const key = await vscode.window.showInputBox({
      prompt:      'Enter your AI Prompt Guard Pro license key',
      placeHolder: 'APG-XXXX-XXXX-XXXX-XXXX',
      password:    false,
    });
    if (!key) return;

    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'Validating license key…' },
      async () => {
        const result = await this.validate(key);
        if (result.valid) {
          await this._ctx.globalState.update('apg.licenseKey', key);
          vscode.window.showInformationMessage(
            `✅ AI Prompt Guard ${result.plan.toUpperCase()} activated! Features: ${result.features.join(', ')}`
          );
        } else {
          vscode.window.showErrorMessage(`❌ Invalid key: ${result.error || 'Validation failed'}`);
        }
      }
    );
  }

  // ── Deactivate ─────────────────────────────────────────────────────────────
  async deactivate() {
    await this._ctx.globalState.update('apg.licenseKey', undefined);
    await this._ctx.globalState.update(CACHE_KEY, undefined);
    vscode.window.showInformationMessage('AI Prompt Guard license removed. Running in Free mode.');
  }

  // ── Get current plan ───────────────────────────────────────────────────────
  async getPlan() {
    const key = this._getStoredKey();
    if (!key) return { plan: 'free', features: [] };
    return this.validate(key);
  }

  // ── Internal ───────────────────────────────────────────────────────────────
  _getStoredKey() {
    return this._ctx.globalState.get('apg.licenseKey');
  }

  _getCached(key, allowStale = false) {
    const cache = this._ctx.globalState.get(CACHE_KEY);
    if (!cache || cache.key !== key) return null;
    if (!allowStale && Date.now() > cache.expiresAt) return null;
    return cache.data;
  }

  _setCache(key, data) {
    this._ctx.globalState.update(CACHE_KEY, { key, data, expiresAt: Date.now() + CACHE_TTL });
  }
}

module.exports = LicenseManager;
