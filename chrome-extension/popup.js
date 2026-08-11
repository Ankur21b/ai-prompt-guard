// AI Prompt Guard — Popup logic v2
// Uses _b (globalThis._b) set by browser-compat.js for Chrome/Firefox/Edge compatibility.
/* global _b, LicenseManager */

const toggleEl    = document.getElementById('toggle-enabled');
const statusBar   = document.getElementById('status-bar');
const statusDot   = document.getElementById('status-dot');
const statusLabel = document.getElementById('status-label');
const statScans   = document.getElementById('stat-scans');
const statBlocked = document.getElementById('stat-blocked');
const btnReset    = document.getElementById('btn-reset');
const sitesList   = document.getElementById('sites-list');
const allowlistSection = document.getElementById('allowlist-section');
const allowlistItems   = document.getElementById('allowlist-items');
const btnClearAllowlist = document.getElementById('btn-clear-allowlist');

// All supported sites
const SITES = [
  { key: 'claude.ai',              label: 'Claude' },
  { key: 'chat.openai.com',        label: 'ChatGPT' },
  { key: 'chatgpt.com',            label: 'ChatGPT (new)' },
  { key: 'gemini.google.com',      label: 'Gemini' },
  { key: 'copilot.microsoft.com',  label: 'Copilot' },
  { key: 'www.perplexity.ai',      label: 'Perplexity' },
  { key: 'chat.mistral.ai',        label: 'Mistral' },
  { key: 'huggingface.co',         label: 'HuggingFace' },
];

const siteKeys = SITES.map(s => `siteEnabled_${s.key}`);

// Load state
const keysToLoad = ['enabled', 'totalScans', 'totalPiiBlocked', 'piiAllowList', ...siteKeys];
_b.storage.local.get(keysToLoad, (data) => {
  const enabled = data.enabled !== false;
  toggleEl.checked       = enabled;
  statScans.textContent  = data.totalScans     || 0;
  statBlocked.textContent = data.totalPiiBlocked || 0;
  applyStatus(enabled);
  renderSiteToggles(data);
  renderAllowList(data.piiAllowList || []);
});

// Global toggle
toggleEl.addEventListener('change', () => {
  const enabled = toggleEl.checked;
  _b.storage.local.set({ enabled });
  applyStatus(enabled);
});

// Reset stats
btnReset.addEventListener('click', () => {
  _b.storage.local.set({ totalScans: 0, totalPiiBlocked: 0 });
  statScans.textContent  = '0';
  statBlocked.textContent = '0';
});

// Clear allow list
btnClearAllowlist.addEventListener('click', () => {
  _b.storage.local.set({ piiAllowList: [] });
  renderAllowList([]);
});

function applyStatus(enabled) {
  if (enabled) {
    statusBar.className   = 'status-bar status-on';
    statusDot.className   = 'dot dot-on';
    statusLabel.textContent = 'Active — prompts are being scanned';
  } else {
    statusBar.className   = 'status-bar status-off';
    statusDot.className   = 'dot dot-off';
    statusLabel.textContent = 'Paused — PII scanning disabled';
  }
}

function renderSiteToggles(data) {
  sitesList.innerHTML = '';
  SITES.forEach(site => {
    const storageKey = `siteEnabled_${site.key}`;
    const isOn = data[storageKey] !== false;

    const row = document.createElement('div');
    row.className = 'site-row';
    row.innerHTML = `
      <span class="site-label">${site.label}</span>
      <label class="toggle-sm">
        <input type="checkbox" data-site="${site.key}" ${isOn ? 'checked' : ''} />
        <span class="toggle-track-sm"></span>
      </label>
    `;
    sitesList.appendChild(row);

    row.querySelector('input').addEventListener('change', (e) => {
      _b.storage.local.set({ [storageKey]: e.target.checked });
    });
  });
}

function renderAllowList(items) {
  if (!items || items.length === 0) {
    allowlistSection.style.display = 'none';
    return;
  }
  allowlistSection.style.display = '';
  allowlistItems.innerHTML = '';
  items.forEach(value => {
    const chip = document.createElement('div');
    chip.className = 'allowlist-chip';
    chip.innerHTML = `
      <span class="allowlist-value">${escapeHtml(value)}</span>
      <button class="allowlist-remove" data-value="${escapeAttr(value)}" title="Remove">×</button>
    `;
    allowlistItems.appendChild(chip);

    chip.querySelector('.allowlist-remove').addEventListener('click', () => {
      _b.storage.local.get(['piiAllowList'], (data) => {
        const updated = (data.piiAllowList || []).filter(v => v !== value);
        _b.storage.local.set({ piiAllowList: updated });
        renderAllowList(updated);
      });
    });
  });
}

// Reflect allow list changes made by the content script
_b.storage.onChanged.addListener((changes) => {
  if ('piiAllowList' in changes) {
    renderAllowList(changes.piiAllowList.newValue || []);
  }
  if ('totalScans' in changes) statScans.textContent = changes.totalScans.newValue || 0;
  if ('totalPiiBlocked' in changes) statBlocked.textContent = changes.totalPiiBlocked.newValue || 0;
  if ('customRules' in changes) renderCustomRules(changes.customRules.newValue || []);
});

// ── Custom rules ──────────────────────────────────────────────────────────

const customRulesList  = document.getElementById('custom-rules-list');
const customRuleForm   = document.getElementById('custom-rule-form');
const btnAddRule       = document.getElementById('btn-add-rule');
const btnRuleSave      = document.getElementById('btn-rule-save');
const btnRuleCancel    = document.getElementById('btn-rule-cancel');
const ruleLabel        = document.getElementById('rule-label');
const rulePattern      = document.getElementById('rule-pattern');
const ruleFlags        = document.getElementById('rule-flags');
const ruleConfidence   = document.getElementById('rule-confidence');
const ruleError        = document.getElementById('rule-error');

_b.storage.local.get(['customRules'], (data) => {
  renderCustomRules(data.customRules || []);
});

btnAddRule.addEventListener('click', () => {
  customRuleForm.style.display = '';
  ruleLabel.value = '';
  rulePattern.value = '';
  ruleFlags.value = 'gi';
  ruleConfidence.value = 'medium';
  ruleError.textContent = '';
  ruleLabel.focus();
});

btnRuleCancel.addEventListener('click', () => {
  customRuleForm.style.display = 'none';
});

btnRuleSave.addEventListener('click', async () => {
  const hasPro = await LicenseManager.hasFeature('custom_rules');
  if (!hasPro) {
    ruleError.textContent = '🔒 Custom rules require a Pro license.';
    return;
  }

  const label   = ruleLabel.value.trim();
  const pattern = rulePattern.value.trim();
  const flags   = ruleFlags.value.trim() || 'gi';
  const confidence = ruleConfidence.value;

  if (!label)   { ruleError.textContent = 'Label required.'; return; }
  if (!pattern) { ruleError.textContent = 'Pattern required.'; return; }

  try { new RegExp(pattern, flags); } catch (e) {
    ruleError.textContent = 'Invalid regex: ' + e.message;
    return;
  }

  _b.storage.local.get(['customRules'], (data) => {
    const rules = data.customRules || [];
    rules.push({ label, pattern, flags, confidence });
    _b.storage.local.set({ customRules: rules });
    renderCustomRules(rules);
    customRuleForm.style.display = 'none';
  });
});

function renderCustomRules(rules) {
  customRulesList.innerHTML = '';
  if (!rules || rules.length === 0) return;
  rules.forEach((rule, idx) => {
    const chip = document.createElement('div');
    chip.className = 'rule-chip';
    chip.innerHTML = `
      <span class="rule-chip-label" title="${escapeHtml(rule.label)}">${escapeHtml(rule.label)}</span>
      <span class="rule-chip-pattern" title="${escapeHtml(rule.pattern)}">${escapeHtml(rule.pattern)}</span>
      <button class="rule-chip-remove" data-idx="${idx}" title="Remove">×</button>
    `;
    customRulesList.appendChild(chip);

    chip.querySelector('.rule-chip-remove').addEventListener('click', () => {
      _b.storage.local.get(['customRules'], (data) => {
        const updated = (data.customRules || []).filter((_, i) => i !== idx);
        _b.storage.local.set({ customRules: updated });
        renderCustomRules(updated);
      });
    });
  });
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeAttr(str) {
  return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── License UI ────────────────────────────────────────────────────────────────

const planBadge        = document.getElementById('plan-badge');
const licenseKeyInput  = document.getElementById('license-key-input');
const btnActivate      = document.getElementById('btn-activate');
const btnDeactivate    = document.getElementById('btn-deactivate');
const licenseError     = document.getElementById('license-error');
const licenseFree      = document.getElementById('license-free');
const licensePro       = document.getElementById('license-pro');
const customRulesSection = document.getElementById('custom-rules-section');

async function refreshLicenseUI() {
  const result = await LicenseManager.getPlan();
  const isPro  = result.valid && result.plan !== 'free';

  planBadge.textContent = isPro ? result.plan.toUpperCase() : 'FREE';
  planBadge.className   = `plan-badge plan-${isPro ? result.plan : 'free'}`;
  licenseFree.style.display = isPro ? 'none' : '';
  licensePro.style.display  = isPro ? ''     : 'none';

  // Gate custom rules section
  if (isPro) {
    customRulesSection.classList.remove('pro-locked');
    btnAddRule.style.display = '';
  } else {
    customRulesSection.classList.add('pro-locked');
    btnAddRule.style.display = 'none';
  }
}

refreshLicenseUI();

btnActivate.addEventListener('click', async () => {
  const key = licenseKeyInput.value.trim();
  if (!key) { licenseError.textContent = 'Enter a license key.'; return; }
  btnActivate.textContent = 'Checking…';
  btnActivate.disabled    = true;
  licenseError.textContent = '';

  const result = await LicenseManager.activate(key);
  btnActivate.textContent = 'Activate';
  btnActivate.disabled    = false;

  if (result.valid) {
    licenseKeyInput.value = '';
    refreshLicenseUI();
  } else {
    licenseError.textContent = result.error || 'Invalid key.';
  }
});

btnDeactivate.addEventListener('click', async () => {
  await LicenseManager.deactivate();
  refreshLicenseUI();
});
