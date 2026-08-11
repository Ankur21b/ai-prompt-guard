'use strict';

// ─────────────────────────────────────────────
// AI Prompt Guard — VSCode Extension
//
// Features:
//   • Status bar: shows PII Guard status + last scan result
//   • Commands: scan selection, scan clipboard, scan file, toggle
//   • Inline decorations: highlights PII in the editor
//   • Auto-scan on type (optional, debounced)
//   • Works with Claude Code by intercepting text before submission
// ─────────────────────────────────────────────

const vscode = require('vscode');
const { detect, detectAndEncrypt, setCustomRules } = require('./pii-detector-node');
const { extractText, createSanitizedCopy, isSupported, canSanitize, supportedLabel, SUPPORTED_EXTENSIONS } = require('./doc-parser');

// ── State
let statusBarItem;
let enabled = true;
let lastScanResult = null;
let autoScanTimer = null;

// ── Pending chat state (module-level — synchronous, no async storage race)
let _pendingText      = null;
let _pendingSanitized = null;
let _pendingToken     = null;

// ── Decoration types per severity
const decorations = {
  high:   vscode.window.createTextEditorDecorationType({
    backgroundColor: new vscode.ThemeColor('diffEditor.removedTextBackground'),
    border: '1px solid #e53e3e',
    borderRadius: '3px',
  }),
  medium: vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(251,191,36,0.25)',
    border: '1px solid #d97706',
    borderRadius: '3px',
  }),
  low:    vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(99,102,241,0.15)',
    border: '1px solid #6366f1',
    borderRadius: '3px',
  }),
};

// ── Config helpers
function cfg() { return vscode.workspace.getConfiguration('promptguard'); }

function loadCustomRules() {
  setCustomRules(cfg().get('customRules', []));
}

// ── Update status bar
function updateStatusBar(scanning = false) {
  if (!statusBarItem) return;
  if (!enabled) {
    statusBarItem.text = '$(shield) PII Guard: Off';
    statusBarItem.backgroundColor = undefined;
    statusBarItem.tooltip = 'AI Prompt Guard is disabled. Click to enable.';
    statusBarItem.command = 'promptguard.toggleEnabled';
    return;
  }
  if (scanning) {
    statusBarItem.text = '$(loading~spin) PII Guard: Scanning…';
    statusBarItem.backgroundColor = undefined;
    return;
  }
  if (!lastScanResult) {
    statusBarItem.text = '$(shield) PII Guard: Ready';
    statusBarItem.backgroundColor = undefined;
    statusBarItem.tooltip = 'AI Prompt Guard is active.\nRight-click text → "PII Guard: Scan Selection"';
    statusBarItem.command = 'promptguard.scanFile';
    return;
  }
  if (lastScanResult.found) {
    const cats = lastScanResult.categories.slice(0, 3).join(', ');
    statusBarItem.text = `$(alert) PII: ${lastScanResult.detections.length} item(s) — ${cats}`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    statusBarItem.tooltip = [
      `⚠️  PII detected`,
      `Categories: ${lastScanResult.categories.join(', ')}`,
      `Regulations: ${lastScanResult.regulations.join(', ')}`,
      ``,
      `Click to scan the active file.`,
    ].join('\n');
    statusBarItem.command = 'promptguard.scanFile';
  } else {
    statusBarItem.text = '$(pass-filled) PII Guard: Clean';
    statusBarItem.backgroundColor = undefined;
    statusBarItem.tooltip = 'Last scan found no PII. Click to scan again.';
    statusBarItem.command = 'promptguard.scanFile';
  }
}

// ── Apply inline decorations to editor
function applyDecorations(editor, scanResult, originalText) {
  if (!cfg().get('highlightPii', true)) return;
  clearDecorations(editor);
  if (!scanResult?.found) return;

  const categoryRanges = { high: [], medium: [], low: [] };
  const originalLines  = originalText.split('\n');
  const sanitizedLines = scanResult.sanitizedText.split('\n');

  originalLines.forEach((origLine, i) => {
    const sanLine = sanitizedLines[i] || '';
    if (origLine !== sanLine) {
      const range = new vscode.Range(i, 0, i, origLine.length);
      // Use the first detection's confidence for line severity
      const det = scanResult.detections.find(d => {
        const lineStart = originalLines.slice(0, i).join('\n').length + (i > 0 ? 1 : 0);
        return d.index >= lineStart && d.index < lineStart + origLine.length;
      });
      const sev = det?.confidence || 'medium';
      categoryRanges[sev].push(range);
    }
  });

  editor.setDecorations(decorations.high,   categoryRanges.high);
  editor.setDecorations(decorations.medium, categoryRanges.medium);
  editor.setDecorations(decorations.low,    categoryRanges.low);
}

function clearDecorations(editor) {
  if (!editor) return;
  editor.setDecorations(decorations.high,   []);
  editor.setDecorations(decorations.medium, []);
  editor.setDecorations(decorations.low,    []);
}

// ── Scan + show result in notification
async function runScan(text, context = '', vsContext = null) {
  if (!enabled) {
    vscode.window.showWarningMessage('AI Prompt Guard is disabled.');
    return null;
  }
  if (!text?.trim()) {
    vscode.window.showInformationMessage('Nothing to scan.');
    return null;
  }

  updateStatusBar(true);
  const result = detect(text);
  lastScanResult = result;
  updateStatusBar(false);

  const editor = vscode.window.activeTextEditor;

  if (result.found) {
    applyDecorations(editor, result, text);
    const detail = `${result.detections.length} item(s) | ${result.categories.join(', ')} | ${result.regulations.join(', ')}`;

    // Offer save options when scanning a real file (not clipboard/selection-only)
    const filePath = editor?.document?.uri?.fsPath;
    const isFile = filePath && !editor.document.isUntitled && context !== 'clipboard';
    const actions = isFile
      ? ['Copy Sanitized', 'Copy Encrypted', 'Save Sanitized', 'Save Encrypted']
      : ['Copy Sanitized', 'Copy Encrypted'];

    const action = await vscode.window.showWarningMessage(
      `⚠️  PII detected in ${context || 'scanned text'}`,
      { detail, modal: false },
      ...actions
    );
    if (action === 'Copy Sanitized') {
      await vscode.env.clipboard.writeText(result.sanitizedText);
      vscode.window.showInformationMessage('Sanitized text copied to clipboard.');
    }
    if (action === 'Copy Encrypted') {
      const enc = await detectAndEncrypt(text, vsContext);
      await vscode.env.clipboard.writeText(enc.encryptedText);
      vscode.window.showInformationMessage('Encrypted text copied to clipboard. PII is AES-GCM encrypted.');
    }
    if (action === 'Save Sanitized') {
      const outPath = await createSanitizedCopy(filePath, result.detections, result.sanitizedText, 'sanitize');
      vscode.window.showInformationMessage(`✅ Saved: ${require('path').basename(outPath)}`, 'Open').then(b => {
        if (b === 'Open') vscode.window.showTextDocument(vscode.Uri.file(outPath));
      });
    }
    if (action === 'Save Encrypted') {
      const enc = await detectAndEncrypt(text, vsContext);
      const encMap = new Map(enc.detections.map(d => [d.value, enc.encryptedText.match(new RegExp(`\\[ENC:${d.category}:[^\\]]+\\]`))?.[0] || d.value]));
      const outPath = await createSanitizedCopy(filePath, result.detections, enc.encryptedText, 'encrypt', encMap);
      vscode.window.showInformationMessage(`✅ Encrypted copy saved: ${require('path').basename(outPath)}`, 'Open').then(b => {
        if (b === 'Open') vscode.window.showTextDocument(vscode.Uri.file(outPath));
      });
    }
  } else {
    clearDecorations(editor);
    vscode.window.showInformationMessage(`✅ PII Guard: No PII found in ${context || 'scanned text'}.`);
  }
  return result;
}

// ── Commands
async function cmdScanSelection(vsContext) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;

  const filePath = editor.document.uri.fsPath;

  // Binary format — always use doc-parser
  if (isSupported(filePath)) {
    await cmdScanDocument(vsContext, filePath);
    return;
  }

  const sel  = editor.selection;
  const text = editor.document.getText(sel.isEmpty ? undefined : sel);
  await runScan(text, sel.isEmpty ? 'entire file' : 'selection', vsContext);
}

async function cmdScanClipboard(vsContext) {
  const text = await vscode.env.clipboard.readText();
  await runScan(text, 'clipboard', vsContext);
}

async function cmdScanFile(vsContext) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;

  const filePath = editor.document.uri.fsPath;

  // Binary document formats — route through doc-parser instead of editor text
  if (isSupported(filePath)) {
    await cmdScanDocument(vsContext, filePath);
    return;
  }

  await runScan(editor.document.getText(), 'file', vsContext);
}

// Replaces PII directly in the active editor (selection or whole file)
async function cmdSanitizeInPlace(vsContext) {
  const editor = vscode.window.activeTextEditor;
  if (!editor || !enabled) return;

  const sel     = editor.selection;
  const lastLine = editor.document.lineAt(editor.document.lineCount - 1);
  const range   = sel.isEmpty
    ? new vscode.Range(0, 0, editor.document.lineCount - 1, lastLine.text.length)
    : sel;
  const text    = editor.document.getText(sel.isEmpty ? undefined : sel);
  const result  = detect(text);

  if (!result.found) {
    vscode.window.showInformationMessage('✅ No PII found — nothing to sanitize.');
    return;
  }

  const choice = await vscode.window.showWarningMessage(
    `⚠️  ${result.detections.length} PII item(s) found. Replace in editor?`,
    { modal: true },
    'Sanitize (redact)', 'Encrypt'
  );
  if (!choice) return;

  let replacement = result.sanitizedText;
  if (choice === 'Encrypt') {
    const enc = await detectAndEncrypt(text, vsContext);
    replacement = enc.encryptedText;
  }

  await editor.edit(editBuilder => editBuilder.replace(range, replacement));
  applyDecorations(editor, detect(replacement), replacement);
  vscode.window.showInformationMessage(`✅ PII ${choice === 'Encrypt' ? 'encrypted' : 'redacted'} in editor.`);
}

function cmdToggle() {
  enabled = !enabled;
  cfg().update('enabled', enabled, vscode.ConfigurationTarget.Global);
  updateStatusBar();
  vscode.window.showInformationMessage(`AI Prompt Guard is now ${enabled ? 'enabled' : 'disabled'}.`);
}

// ── @pii-guard chat participant
function registerChatParticipant(context) {
  if (!vscode.chat?.createChatParticipant) return; // VS Code < 1.90

  const participant = vscode.chat.createChatParticipant('pii-guard', async (request, _chatContext, stream, token) => {
    const text = request.prompt;
    if (!text?.trim()) {
      stream.markdown('Send me a message and I will scan it for PII before forwarding to Claude.');
      return;
    }

    const result = detect(text);

    if (!result.found) {
      stream.markdown('✅ **No PII detected.** Forwarding to Claude…\n\n---\n');
      await forwardToModel(text, stream, token);
      return;
    }

    // Show what was found
    const rows = result.detections
      .map(d => `| ${d.label} | \`${d.value}\` | ${d.confidence.toUpperCase()} |`)
      .join('\n');
    stream.markdown(
      `⚠️ **PII detected — ${result.detections.length} item(s)**\n\n` +
      `| Type | Value | Confidence |\n|---|---|---|\n${rows}\n\n` +
      `**Regulations:** ${result.regulations.join(', ')}\n\n`
    );

    // Ask user how to proceed
    stream.button({ command: 'promptguard._chatSendSanitized', title: '🔒 Send Sanitized' });
    stream.button({ command: 'promptguard._chatSendEncrypted', title: '🔐 Send Encrypted' });
    stream.button({ command: 'promptguard._chatSendOriginal',  title: '⚠️ Send Original Anyway' });

    // Store pending state in module-level vars (synchronous — no async race)
    _pendingText      = text;
    _pendingSanitized = result.sanitizedText;
    _pendingToken     = token;
  });

  participant.iconPath = new vscode.ThemeIcon('shield');
  context.subscriptions.push(participant);
}

async function forwardToModel(text, stream, token) {
  try {
    let models = await vscode.lm.selectChatModels({ vendor: 'copilot', family: 'claude' });
    if (!models?.length) models = await vscode.lm.selectChatModels();
    const model = models?.[0];
    if (!model) { stream.markdown('_No language model available._'); return; }

    const response = await model.sendRequest(
      [vscode.LanguageModelChatMessage.User(text)],
      {}, token
    );
    for await (const chunk of response.text) {
      stream.markdown(chunk);
    }
  } catch (err) {
    stream.markdown(`_Could not reach language model: ${err.message}_`);
  }
}

// Scan a PDF / Word / Excel file picked via file dialog
async function cmdScanDocument(vsContext, preselectedPath = null) {
  if (!enabled) { vscode.window.showWarningMessage('AI Prompt Guard is disabled.'); return; }

  let filePath = preselectedPath;

  if (!filePath) {
    const uris = await vscode.window.showOpenDialog({
      canSelectMany: false,
      openLabel: 'Scan for PII',
      filters: { 'Documents': ['pdf', 'docx', 'doc', 'xlsx', 'xls', 'csv'] },
    });
    if (!uris?.length) return;
    filePath = uris[0].fsPath;
  }
  const label    = supportedLabel(filePath);

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `PII Guard: Scanning ${label}…`, cancellable: false },
    async () => {
      let extracted;
      try {
        extracted = await extractText(filePath);
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to read ${label}: ${err.message}`);
        return;
      }

      const { text } = extracted;
      if (!text?.trim()) { vscode.window.showInformationMessage('Document appears to be empty.'); return; }

      const result = detect(text);
      lastScanResult = result;
      updateStatusBar(false);

      const meta = [];
      if (extracted.pageCount)  meta.push(`${extracted.pageCount} page(s)`);
      if (extracted.sheetNames) meta.push(`Sheets: ${extracted.sheetNames.join(', ')}`);
      const metaStr = meta.length ? ` (${meta.join(' · ')})` : '';

      if (!result.found) {
        vscode.window.showInformationMessage(`✅ No PII found in ${label}${metaStr}.`);
        return;
      }

      const detail  = `${result.detections.length} item(s) | ${result.categories.join(', ')} | ${result.regulations.join(', ')}`;
      const savable = canSanitize(filePath);
      const actions = savable
        ? ['Show Details', 'Save Sanitized Copy', 'Save Encrypted Copy', 'Copy Sanitized']
        : ['Show Details', 'Copy Sanitized'];

      const action = await vscode.window.showWarningMessage(
        `⚠️  PII detected in ${label}${metaStr} — ${result.detections.length} item(s)`,
        { detail, modal: false },
        ...actions
      );

      if (action === 'Save Sanitized Copy') {
        const outPath = await createSanitizedCopy(filePath, result.detections, result.sanitizedText, 'sanitize');
        vscode.window.showInformationMessage(`✅ Saved: ${require('path').basename(outPath)}`, 'Open').then(b => {
          if (b === 'Open') vscode.window.showTextDocument(vscode.Uri.file(outPath));
        });
      }
      if (action === 'Save Encrypted Copy') {
        const enc = await detectAndEncrypt(text, vsContext);
        // Build value→token map for createSanitizedCopy
        const encMap = new Map(enc.detections.map(d => [d.value, enc.encryptedText.match(new RegExp(`\\[ENC:${d.category}:[^\\]]+\\]`))?.[0] || d.value]));
        const outPath = await createSanitizedCopy(filePath, result.detections, enc.encryptedText, 'encrypt', encMap);
        vscode.window.showInformationMessage(`✅ Encrypted copy saved: ${require('path').basename(outPath)}`, 'Open').then(b => {
          if (b === 'Open') vscode.window.showTextDocument(vscode.Uri.file(outPath));
        });
      }
      if (action === 'Copy Sanitized') {
        await vscode.env.clipboard.writeText(result.sanitizedText);
        vscode.window.showInformationMessage('Sanitized text copied to clipboard.');
      }
      if (action === 'Show Details') {
        const lines = result.detections.map(
          (d, i) => `${i + 1}. [${d.label}] "${d.value}" — ${d.confidence} confidence`
        ).join('\n');
        const doc = await vscode.workspace.openTextDocument({
          content: [
            `PII Guard — Scan Results`,
            `${'─'.repeat(50)}`,
            `File        : ${filePath}${metaStr}`,
            `PII found   : ${result.detections.length} item(s)`,
            `Regulations : ${result.regulations.join(', ')}`,
            `${'─'.repeat(50)}`,
            ``,
            lines,
            ``,
            `${'─'.repeat(50)}`,
            `SANITIZED TEXT:`,
            ``,
            result.sanitizedText,
          ].join('\n'),
          language: 'plaintext',
        });
        await vscode.window.showTextDocument(doc);
      }
    }
  );
}

function cmdClearDecorations() {
  lastScanResult = null;
  updateStatusBar();
}

// ── Auto-scan on document change (debounced)
function setupAutoScan(context) {
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(() => {
      if (!enabled || !cfg().get('autoScanOnType', false)) return;
      if (autoScanTimer) clearTimeout(autoScanTimer);
      autoScanTimer = setTimeout(() => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;
        const text = editor.document.getText();
        if (!text.trim()) return;
        updateStatusBar(true);
        const result = detect(text);
        lastScanResult = result;
        updateStatusBar(false);
        applyDecorations(editor, result, text);
      }, 2000);
    })
  );
}

// ── Activation
function activate(context) {
  enabled = cfg().get('enabled', true);
  loadCustomRules();

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.show();
  updateStatusBar();
  context.subscriptions.push(statusBarItem);

  // Register commands — pass VS Code context so encryption key can be persisted
  context.subscriptions.push(
    vscode.commands.registerCommand('promptguard.scanSelection',    () => cmdScanSelection(context)),
    vscode.commands.registerCommand('promptguard.scanClipboard',    () => cmdScanClipboard(context)),
    vscode.commands.registerCommand('promptguard.scanFile',         () => cmdScanFile(context)),
    vscode.commands.registerCommand('promptguard.scanDocument',     () => cmdScanDocument(context)),
    vscode.commands.registerCommand('promptguard.sanitizeInPlace',  () => cmdSanitizeInPlace(context)),
    vscode.commands.registerCommand('promptguard.toggleEnabled',    cmdToggle),
    vscode.commands.registerCommand('promptguard.clearDecorations', cmdClearDecorations),

    // Chat participant button handlers
    vscode.commands.registerCommand('promptguard._chatSendSanitized', async () => {
      if (!_pendingSanitized) return;
      await vscode.env.clipboard.writeText(_pendingSanitized);
      vscode.window.showInformationMessage('✅ Sanitized text copied — paste it into the chat.');
    }),
    vscode.commands.registerCommand('promptguard._chatSendEncrypted', async () => {
      if (!_pendingText) return;
      const enc = await detectAndEncrypt(_pendingText, context);
      await vscode.env.clipboard.writeText(enc.encryptedText);
      vscode.window.showInformationMessage('✅ Encrypted text copied — paste it into the chat.');
    }),
    vscode.commands.registerCommand('promptguard._chatSendOriginal', async () => {
      if (!_pendingText) return;
      // Open a new chat pre-filled with the original text so VS Code
      // forwards it to the model in a fresh request (stream is already closed)
      try {
        await vscode.commands.executeCommand('workbench.action.chat.open', { query: _pendingText });
      } catch (_) {
        // Fallback: copy to clipboard if chat open fails
        await vscode.env.clipboard.writeText(_pendingText);
        vscode.window.showInformationMessage('⚠️ Original text copied — paste it into the chat.');
      }
    }),
  );

  // Config change listener
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('promptguard')) {
        enabled = cfg().get('enabled', true);
        loadCustomRules();
        updateStatusBar();
      }
    })
  );

  setupAutoScan(context);
  registerChatParticipant(context);

  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor && lastScanResult) applyDecorations(editor, lastScanResult, editor.document.getText());
    })
  );
}

function deactivate() {
  if (autoScanTimer) clearTimeout(autoScanTimer);
}

module.exports = { activate, deactivate };
