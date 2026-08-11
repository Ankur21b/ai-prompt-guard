/**
 * AI Prompt Guard — Content Script v2
 * Intercepts prompt submission on Claude, ChatGPT, Gemini, Copilot, Perplexity, Mistral, HuggingFace.
 * Depends on pii-detector.js being loaded first (window.PiiDetector).
 *
 * v2 improvements:
 *  - Per-site on/off toggle (honoured from _b.storage per hostname)
 *  - "Mark as safe" allow-list button in overlay per detected item
 *  - Confidence badges (HIGH / MEDIUM / LOW) per detection
 *  - Extended site support: Perplexity, Mistral, HuggingFace Chat
 */
/* global _b */
(function () {
  'use strict';

  // ── Site configuration ────────────────────────────────────────────────────

  const SITE_CONFIG = {
    'claude.ai': {
      inputSel:  '[contenteditable="true"].ProseMirror, [contenteditable="true"][data-placeholder], div[contenteditable="true"][spellcheck]',
      submitSel: 'button[aria-label="Send message"], button[aria-label="Send Message"], button[data-testid="send-button"]',
      name: 'Claude',
    },
    'chat.openai.com': {
      inputSel:  '#prompt-textarea, [contenteditable="true"][data-placeholder]',
      submitSel: '[data-testid="send-button"], button[aria-label="Send prompt"]',
      name: 'ChatGPT',
    },
    'chatgpt.com': {
      inputSel:  '#prompt-textarea, [contenteditable="true"]',
      submitSel: '[data-testid="send-button"], button[aria-label="Send prompt"]',
      name: 'ChatGPT',
    },
    'gemini.google.com': {
      inputSel:  '.ql-editor, [contenteditable="true"]',
      submitSel: 'button[aria-label="Send message"], .send-button',
      name: 'Gemini',
    },
    'copilot.microsoft.com': {
      inputSel:  '#userInput, textarea[placeholder]',
      submitSel: 'button[aria-label="Submit"], button[type="submit"]',
      name: 'Copilot',
    },
    'www.perplexity.ai': {
      inputSel:  'textarea[placeholder]',
      submitSel: 'button[aria-label="Submit"], button[type="submit"]',
      name: 'Perplexity',
    },
    'chat.mistral.ai': {
      inputSel:  'textarea',
      submitSel: 'button[type="submit"], button[aria-label="Send"]',
      name: 'Mistral',
    },
    'huggingface.co': {
      inputSel:  'textarea[placeholder], [contenteditable="true"]',
      submitSel: 'button[type="submit"], button[aria-label="Send message"]',
      name: 'HuggingFace',
    },
  };

  // ── State ─────────────────────────────────────────────────────────────────

  const hostname        = location.hostname;
  let   enabled         = true;   // global on/off
  let   siteEnabled     = true;   // per-site on/off
  let   intercepting    = false;

  // ── Extension validity guard ───────────────────────────────────────────────
  // Returns false when the extension has been reloaded/updated and the context
  // is no longer valid. All chrome.* calls must be guarded with this check.
  function ctxOk() { return !!_b?.runtime?.id; }

  // ── Init ──────────────────────────────────────────────────────────────────

  const siteEnabledKey = `siteEnabled_${hostname}`;

  if (ctxOk()) {
    _b.storage.local.get(['enabled', siteEnabledKey], (data) => {
      if (_b.runtime.lastError) return;
      enabled     = data.enabled !== false;
      siteEnabled = data[siteEnabledKey] !== false;
      bootstrap();
    });

    _b.storage.onChanged.addListener((changes) => {
      if (!ctxOk()) return;
      if ('enabled' in changes)       enabled     = changes.enabled.newValue;
      if (siteEnabledKey in changes)  siteEnabled = changes[siteEnabledKey].newValue;
    });
  } else {
    bootstrap();
  }

  function isActive() { return enabled && siteEnabled; }

  function bootstrap() {
    const config = SITE_CONFIG[hostname];
    if (!config) return;

    attachToInputs(config);
    watchFileInputs();
  }

  function attachToInputs(config) {
    if (!document._pgKeyAttached) {
      document._pgKeyAttached = true;
      document.addEventListener('keydown', (e) => handleKeydown(e, config), true);
    }

    if (!document._pgClickAttached) {
      document._pgClickAttached = true;
      document.addEventListener('click', (e) => handleSubmitClick(e, config), true);
    }
  }

  // ── Intercept handlers ────────────────────────────────────────────────────

  function handleKeydown(e, config) {
    if (!isActive() || intercepting) return;
    if (e.key !== 'Enter' || e.shiftKey) return;

    const inputSelectors = config.inputSel.split(',').map(s => s.trim());
    const inputEl = inputSelectors.reduce((found, sel) => found || e.target.closest(sel), null);
    if (!inputEl) return;

    const text = getInputText(inputEl);
    if (!text.trim()) return;
    const result = window.PiiDetector.detect(text);
    reportScan(result.found);
    if (result.found) {
      e.preventDefault();
      e.stopImmediatePropagation();
      showOverlay(result, text,
        () => {
          setInputText(inputEl, result.sanitizedText);
          setTimeout(() => simulateEnter(inputEl), 50);
        },
        () => {
          // intercepting stays true so our handler won't re-block it
          removeOverlay();
          simulateEnter(inputEl);
          setTimeout(() => { intercepting = false; }, 100);
        }
      );
    }
  }

  function handleSubmitClick(e, config) {
    if (!isActive() || intercepting) return;
    const selectors = config.submitSel.split(',').map(s => s.trim());
    const isSubmit  = selectors.some(sel => e.target.closest(sel));
    if (!isSubmit) return;

    const inputSelectors = config.inputSel.split(',').map(s => s.trim());
    let inputEl = null;
    for (const sel of inputSelectors) {
      inputEl = document.querySelector(sel);
      if (inputEl) break;
    }
    if (!inputEl) return;

    const text = getInputText(inputEl);
    if (!text.trim()) return;

    const result = window.PiiDetector.detect(text);
    reportScan(result.found);

    if (result.found) {
      e.preventDefault();
      e.stopImmediatePropagation();
      showOverlay(result, text,
        () => {
          setInputText(inputEl, result.sanitizedText);
          setTimeout(() => {
            intercepting = false;
            const btn = e.target.closest(selectors.join(','));
            if (btn) btn.click();
          }, 80);
        },
        () => {
          removeOverlay();
          const btn = e.target.closest(selectors.join(','));
          if (btn) btn.click();
          setTimeout(() => { intercepting = false; }, 100);
        }
      );
    }
  }

  // ── Text helpers ──────────────────────────────────────────────────────────

  function getInputText(el) {
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') return el.value;
    return el.innerText || el.textContent || '';
  }

  function setInputText(el, text) {
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {
      const nativeInputValueSetter =
        Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value')?.set ||
        Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
      if (nativeInputValueSetter) {
        nativeInputValueSetter.call(el, text);
        el.dispatchEvent(new Event('input', { bubbles: true }));
      } else {
        el.value = text;
        el.dispatchEvent(new Event('input', { bubbles: true }));
      }
      return;
    }
    el.focus();
    document.execCommand('selectAll', false, null);
    document.execCommand('insertText', false, text);
  }

  function simulateEnter(el) {
    el.focus();
    el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
  }

  // ── Stats ─────────────────────────────────────────────────────────────────

  function reportScan(piiFound) {
    try {
      _b?.runtime?.sendMessage?.({ type: 'PG_SCAN_RESULT', piiFound });
    } catch (_) { /* context invalidated — ignore */ }
  }

  // ── Overlay ───────────────────────────────────────────────────────────────

  function showOverlay(result, originalText, onSendSanitized, onSendOriginal) {
    intercepting = true;
    removeOverlay();

    const overlay = document.createElement('div');
    overlay.id = 'pg-guard-overlay';
    overlay.innerHTML = buildOverlayHTML(result, originalText);
    document.body.appendChild(overlay);

    requestAnimationFrame(() => overlay.classList.add('pg-visible'));

    document.getElementById('pg-btn-sanitized').addEventListener('click', () => {
      intercepting = false;
      removeOverlay();
      onSendSanitized();
    });

    document.getElementById('pg-btn-original').addEventListener('click', () => {
      onSendOriginal();
    });

    document.getElementById('pg-btn-cancel').addEventListener('click', () => {
      intercepting = false;
      removeOverlay();
    });

    // "Mark as safe" — add value to allow list, refresh overlay
    overlay.querySelectorAll('[data-allow-value]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const value = btn.getAttribute('data-allow-value');
        window.PiiDetector.addToAllowList(value);
        btn.textContent = '✓ Saved';
        btn.disabled = true;

        // Re-scan with updated allow list; close if all items cleared
        const newResult = window.PiiDetector.detect(originalText);
        if (!newResult.found) {
          intercepting = false;
          removeOverlay();
        } else {
          // Rebuild content without removing the overlay (smooth UX)
          const modal = document.getElementById('pg-guard-modal');
          if (modal) {
            modal.outerHTML = buildOverlayHTML(newResult, originalText);
            // Re-bind after DOM replacement
            showOverlay(newResult, originalText, onSendSanitized, onSendOriginal);
          }
        }
      });
    });

    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) { intercepting = false; removeOverlay(); }
    });

    document.addEventListener('keydown', function escHandler(e) {
      if (e.key === 'Escape') {
        intercepting = false;
        removeOverlay();
        document.removeEventListener('keydown', escHandler);
      }
    });
  }

  function removeOverlay() {
    const existing = document.getElementById('pg-guard-overlay');
    if (existing) existing.remove();
  }

  function buildOverlayHTML(result, originalText) {
    const catBadges = result.categories
      .map(c => `<span class="pg-cat-badge">${c.replace(/_/g, ' ')}</span>`)
      .join('');

    const regBadges = result.regulations
      .map(r => `<span class="pg-reg-badge">${r}</span>`)
      .join('');

    const sanitizedHighlighted = escapeHtml(result.sanitizedText)
      .replace(/\[([A-Z_]+_REDACTED)\]/g, '<mark class="pg-redacted">[$1]</mark>');

    // Detection table: type · value · confidence · allow-list action
    const detectionRows = result.detections.map(d => {
      const conf = d.confidence || 'medium';
      return `
        <tr>
          <td class="pg-det-label">${escapeHtml(d.label || d.category)}</td>
          <td class="pg-det-value"><code>${escapeHtml(d.value)}</code></td>
          <td><span class="pg-conf-badge pg-conf-${conf}">${conf.toUpperCase()}</span></td>
          <td><button class="pg-allow-btn" data-allow-value="${escapeAttr(d.value)}">✓ Safe</button></td>
        </tr>`;
    }).join('');

    return `
      <div id="pg-guard-modal" role="dialog" aria-modal="true" aria-label="PII Detected">
        <div id="pg-guard-header">
          <div class="pg-header-left">
            <span class="pg-shield">🛡️</span>
            <div>
              <div class="pg-title">AI Prompt Guard</div>
              <div class="pg-subtitle">PII detected in your prompt</div>
            </div>
          </div>
          <div class="pg-token-count">${result.detections.length} item${result.detections.length !== 1 ? 's' : ''} found</div>
        </div>

        <div id="pg-guard-body">
          <div class="pg-compare">
            <div class="pg-pane pg-pane-original">
              <div class="pg-pane-label pg-pane-label-red">⛔ Original (contains PII)</div>
              <pre class="pg-pre pg-pre-red">${escapeHtml(originalText)}</pre>
            </div>
            <div class="pg-pane pg-pane-safe">
              <div class="pg-pane-label pg-pane-label-green">✅ Sanitized (safe to send)</div>
              <pre class="pg-pre pg-pre-green">${sanitizedHighlighted}</pre>
            </div>
          </div>

          <table class="pg-det-table">
            <thead>
              <tr><th>Type</th><th>Value</th><th>Confidence</th><th>Not PII?</th></tr>
            </thead>
            <tbody>${detectionRows}</tbody>
          </table>

          <div class="pg-tags-row">
            <div class="pg-tags-group">
              <span class="pg-tags-title">Categories:</span>${catBadges}
            </div>
            ${result.regulations.length > 0 ? `
            <div class="pg-tags-group">
              <span class="pg-tags-title">Regulations:</span>${regBadges}
            </div>` : ''}
          </div>
        </div>

        <div id="pg-guard-footer">
          <button id="pg-btn-sanitized" class="pg-btn pg-btn-primary">🔒 Send Sanitized</button>
          <button id="pg-btn-original" class="pg-btn pg-btn-warn">⚠️ Send Original Anyway</button>
          <button id="pg-btn-cancel" class="pg-btn pg-btn-secondary">Cancel</button>
        </div>
      </div>
    `;
  }

  // ── File attachment interception ──────────────────────────────────────────

  const attachedFileInputs = new WeakSet();

  function watchFileInputs() {
    document.querySelectorAll('input[type="file"]').forEach(attachFileListener);
    const fileObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType !== 1) return;
          if (node.matches('input[type="file"]')) attachFileListener(node);
          node.querySelectorAll?.('input[type="file"]').forEach(attachFileListener);
        });
      }
    });
    fileObserver.observe(document.body, { childList: true, subtree: true });
  }

  function attachFileListener(inputEl) {
    if (attachedFileInputs.has(inputEl)) return;
    attachedFileInputs.add(inputEl);
    inputEl.addEventListener('change', (e) => handleFileChange(e, inputEl), true);
  }

  async function handleFileChange(e, inputEl) {
    if (!isActive() || !inputEl.files || inputEl.files.length === 0) return;
    if (!window.FileScanner) return;

    const fileResults = await window.FileScanner.scanFiles(inputEl.files);
    const anyPii      = fileResults.some(r => r.found);
    fileResults.forEach(r => reportScan(r.found));
    if (!anyPii) return;

    e.preventDefault();
    e.stopImmediatePropagation();

    intercepting = true;
    showFileOverlay(
      fileResults,
      () => {
        intercepting = false;
        const dt = new DataTransfer();
        fileResults.forEach(r => dt.items.add(r.sanitizedFile || r.file));
        Object.defineProperty(inputEl, 'files', { value: dt.files, writable: true, configurable: true });
        inputEl.dispatchEvent(new Event('change', { bubbles: true }));
      },
      () => {
        intercepting = false;
        const dt = new DataTransfer();
        fileResults.forEach(r => dt.items.add(r.file));
        Object.defineProperty(inputEl, 'files', { value: dt.files, writable: true, configurable: true });
        inputEl.dispatchEvent(new Event('change', { bubbles: true }));
      }
    );
  }

  // ── File overlay ──────────────────────────────────────────────────────────

  function showFileOverlay(fileResults, onReplace, onOriginal) {
    removeOverlay();

    const overlay = document.createElement('div');
    overlay.id = 'pg-guard-overlay';
    overlay.innerHTML = buildFileOverlayHTML(fileResults);
    document.body.appendChild(overlay);

    requestAnimationFrame(() => overlay.classList.add('pg-visible'));

    document.getElementById('pg-btn-replace').addEventListener('click', () => {
      intercepting = false; removeOverlay(); onReplace();
    });
    document.getElementById('pg-btn-original').addEventListener('click', () => {
      intercepting = false; removeOverlay(); onOriginal();
    });
    document.getElementById('pg-btn-cancel').addEventListener('click', () => {
      intercepting = false; removeOverlay();
    });

    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) { intercepting = false; removeOverlay(); }
    });
    document.addEventListener('keydown', function esc(e) {
      if (e.key === 'Escape') { intercepting = false; removeOverlay(); document.removeEventListener('keydown', esc); }
    });
  }

  function buildFileOverlayHTML(fileResults) {
    const piiFiles   = fileResults.filter(r => r.found);
    const canReplace  = piiFiles.some(r => r.canSanitize);
    const binaryOnly  = piiFiles.every(r => r.kind === 'pdf');

    const fileCards = fileResults.map(r => {
      if (!r.found) {
        return `
          <div class="pg-file-card pg-file-clean">
            <div class="pg-file-name">📄 ${escapeHtml(r.name)}</div>
            <div class="pg-file-status pg-status-clean">✅ Clean — no PII detected</div>
          </div>`;
      }
      const cats = r.categories.map(c => `<span class="pg-cat-badge">${c.replace(/_/g, ' ')}</span>`).join('');
      const regs = r.regulations.map(reg => `<span class="pg-reg-badge">${reg}</span>`).join('');
      const actionNote = r.kind === 'pdf'
        ? `<div class="pg-file-note">⚠️ PDF files cannot be auto-sanitized — binary format. Redact manually before uploading.</div>`
        : r.kind === 'unsupported'
        ? `<div class="pg-file-note">⚠️ This file type cannot be parsed or sanitized.</div>`
        : `<div class="pg-file-note">✅ Will be replaced with: <em>${escapeHtml(r.name.replace(/(\.[^.]+)$/, '_sanitized$1'))}</em></div>`;

      return `
        <div class="pg-file-card pg-file-pii">
          <div class="pg-file-name">📄 ${escapeHtml(r.name)}</div>
          <div class="pg-file-pii-row">
            <span class="pg-file-count">${r.detections.length} item${r.detections.length !== 1 ? 's' : ''}</span>
            ${cats}
          </div>
          ${r.regulations.length > 0 ? `<div class="pg-file-regs">${regs}</div>` : ''}
          ${actionNote}
        </div>`;
    }).join('');

    const replaceLabel = binaryOnly
      ? '⚠️ Upload Originals (PII not removable)'
      : '🔒 Replace with Sanitized Files';

    return `
      <div id="pg-guard-modal" role="dialog" aria-modal="true">
        <div id="pg-guard-header">
          <div class="pg-header-left">
            <span class="pg-shield">🛡️</span>
            <div>
              <div class="pg-title">AI Prompt Guard — File Scan</div>
              <div class="pg-subtitle">${piiFiles.length} of ${fileResults.length} file${fileResults.length !== 1 ? 's' : ''} contain PII</div>
            </div>
          </div>
          <div class="pg-token-count">${piiFiles.length} file${piiFiles.length !== 1 ? 's' : ''} flagged</div>
        </div>
        <div id="pg-guard-body">
          <div class="pg-file-list">${fileCards}</div>
        </div>
        <div id="pg-guard-footer">
          ${canReplace
            ? `<button id="pg-btn-replace" class="pg-btn pg-btn-primary">${replaceLabel}</button>`
            : `<button id="pg-btn-replace" class="pg-btn pg-btn-warn">⚠️ Upload Anyway</button>`}
          <button id="pg-btn-original" class="pg-btn pg-btn-warn">Upload Originals Anyway</button>
          <button id="pg-btn-cancel" class="pg-btn pg-btn-secondary">Cancel</button>
        </div>
      </div>
    `;
  }

  // ─────────────────────────────────────────────────────────────────────────

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function escapeAttr(str) {
    return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
})();
