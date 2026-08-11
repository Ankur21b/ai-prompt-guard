# AI Prompt Guard — VS Code Extension

Detects PII in your editor and documents before it reaches any AI assistant. **No backend, no account, no internet required** — all detection and encryption runs entirely inside VS Code.

---

## Features

| Feature | Description |
|---|---|
| **Status bar** | Live indicator — Ready / PII detected / Off |
| **Scan Selection** | Right-click selected text → scan for PII |
| **Scan File** | Scan the entire active document |
| **Scan Clipboard** | Scan clipboard content before pasting |
| **Scan Document** | Scan a PDF, Word, or Excel file via file picker |
| **Sanitize In Place** | Replace PII directly in the editor (redact or encrypt) |
| **Inline highlights** | PII-containing lines highlighted in red/amber/indigo by severity |
| **Auto-scan on type** | Optional debounced scan-on-type (2 s delay) |
| **@pii-guard chat** | Chat participant that scans prompts before forwarding to Claude |

---

## Installation (Development)

1. Open the `vscode-extension/` folder in VS Code
2. Press **F5** to launch the Extension Development Host
3. The extension activates automatically — look for the shield icon in the status bar

To install as a `.vsix`:
```bash
cd vscode-extension
npm install
npx vsce package
code --install-extension ai-prompt-guard-*.vsix
```

---

## Configuration

Set in VS Code Settings (`Cmd+,` → search "Prompt Guard"):

| Setting | Default | Description |
|---|---|---|
| `promptguard.enabled` | `true` | Global on/off |
| `promptguard.autoScanOnType` | `false` | Scan while typing (debounced 2 s) |
| `promptguard.highlightPii` | `true` | Show inline decorations |
| `promptguard.customRules` | `[]` | User-defined PII regex rules (see below) |

No API URL, token, or backend setup required.

### Custom rules

Add organisation-specific patterns that aren't covered by the 23 built-in categories:

```json
// settings.json
"promptguard.customRules": [
  {
    "label": "Employee ID",
    "pattern": "EMP-\\d{6}",
    "flags": "gi",
    "confidence": "high"
  },
  {
    "label": "Project Code",
    "pattern": "PRJ-[A-Z]{3}-\\d{4}",
    "flags": "gi",
    "confidence": "medium"
  }
]
```

| Field | Required | Description |
|---|---|---|
| `label` | ✅ | Display name shown in scan results |
| `pattern` | ✅ | JavaScript regex pattern string |
| `flags` | — | Regex flags (default `gi`) |
| `confidence` | — | `high` / `medium` / `low` (default `medium`) |

Rules take effect immediately — no restart needed. Invalid regex patterns are silently skipped.

---

## Commands

Access all commands via `Cmd+Shift+P` → type "PII Guard":

| Command | How to invoke | Description |
|---|---|---|
| `PII Guard: Scan Selection` | Right-click → context menu | Scan selected text (or entire file if no selection) |
| `PII Guard: Scan Clipboard` | Command Palette | Scan clipboard content |
| `PII Guard: Scan Entire File` | Command Palette / click status bar | Scan active document |
| `PII Guard: Scan Document (PDF / Word / Excel)` | Command Palette | Open file picker → scan PDF, Word, or Excel |
| `PII Guard: Sanitize / Encrypt In Place` | Right-click → context menu | Replace PII in editor with redacted or encrypted text |
| `PII Guard: Toggle On/Off` | Command Palette / click status bar | Enable or disable scanning |
| `PII Guard: Clear Highlights` | Command Palette | Remove inline decorations |

When PII is found, scan commands offer these actions:
- **Copy Sanitized** — copies text with PII replaced by `[EMAIL_REDACTED]`, `[PAN_CARD_REDACTED]`, etc.
- **Copy Encrypted** — copies text with PII replaced by `[ENC:category:base64ciphertext]` using AES-GCM 256-bit encryption
- **Save Sanitized** *(file scan)* — writes a new file with PII replaced by `[CATEGORY_REDACTED]` tokens; DOCX and XLSX are fully rebuilt in the original format
- **Save Encrypted** *(file scan)* — writes a new file with PII replaced by `[ENC:category:base64]` AES-GCM ciphertext; DOCX and XLSX are fully rebuilt
- **Show Details** *(document scan only)* — opens a full report tab listing every detection and the sanitized text

---

## Scan Document — PDF, Word, Excel

`Cmd+Shift+P` → **PII Guard: Scan Document (PDF / Word / Excel)**

Opens a file picker. Select any supported file. All parsing happens **locally** — no file is uploaded anywhere.

### Supported formats

| Format | Extensions | Scan | Save Sanitized | Save Encrypted |
|---|---|---|---|---|
| Word | `.docx` `.doc` | ✅ Full text | ✅ Rebuilt DOCX (ZIP/XML) | ✅ Rebuilt DOCX (ZIP/XML) |
| Excel | `.xlsx` `.xls` | ✅ All sheets | ✅ Rebuilt XLSX (cell values) | ✅ Rebuilt XLSX (cell values) |
| CSV | `.csv` | ✅ Full text | ✅ New file | ✅ New file |
| PDF | `.pdf` | ✅ Text streams | ⛔ Binary — redact manually | ⛔ Binary — redact manually |

Opening a `.docx`, `.pdf`, or `.xlsx` directly in VS Code also routes through this parser automatically.

### After scanning, choose:
- **Save Sanitized** — writes `filename_sanitized.docx` next to the original; PII replaced with `[EMAIL_REDACTED]` tokens
- **Save Encrypted** — writes `filename_encrypted.docx`; PII replaced with `[ENC:category:base64]` AES-GCM ciphertext
- **Copy Sanitized** — redacted plain text copied to clipboard
- **Show Details** — opens a new editor tab with full detection report (file name, page/sheet count, all detections, sanitized text)

---

## Sanitize In Place

Right-click in the editor → **PII Guard: Sanitize / Encrypt In Place** (or select a region first).

A confirmation dialog appears with a count of detected items. Choose:
- **Sanitize (redact)** — replaces PII with `[CATEGORY_REDACTED]` tokens
- **Encrypt** — replaces PII with `[ENC:category:base64]` AES-GCM ciphertext

The edit is applied directly to the document. Undo with `Cmd+Z`.

---

## @pii-guard Chat Participant

Use `@pii-guard` in the VS Code chat panel to scan prompts before they reach Claude:

```
@pii-guard My customer John Smith (john@example.com) has a PAN ABCPS1234E — help me write a support note.
```

The participant will:
1. Scan the message for PII
2. Show a detection table (type, value, confidence)
3. Offer three buttons:
   - **🔒 Send Sanitized** — copies sanitized text to clipboard
   - **🔐 Send Encrypted** — copies AES-GCM encrypted text to clipboard
   - **⚠️ Send Original Anyway** — opens a new chat pre-filled with the original unmodified text

If no PII is found, the message is forwarded directly to Claude via the VS Code LM API.

---

## PII Categories Detected

| Category | Example | Confidence | Regulations |
|---|---|---|---|
| SSN | 123-45-6789 | High | GDPR · CCPA · HIPAA |
| Credit Card | 4111111111111111 | High | GDPR · CCPA · PCI-DSS |
| Email | user@company.com | High | GDPR · CCPA |
| IBAN | GB29NWBK60161331926819 | High | GDPR · PSD2 |
| Credentials | api_key = abc123 | High | GDPR · CCPA |
| PAN Card | ABCPS1234E | High | PDPA |
| Aadhaar | 2345 6789 0123 | Medium | PDPA · GDPR |
| UK NI Number | AB 12 34 56 C | High | GDPR · UK-GDPR |
| Bank Account | account: 12345678 | High | GDPR · PCI-DSS |
| Geolocation | lat=12.97, lon=77.59 | High | GDPR · CCPA |
| Ethnicity | ethnicity: Asian | High | GDPR Art.9 · CCPA |
| Religion | religion: Hindu | High | GDPR Art.9 · CCPA |
| Phone | 415-555-0100 | Medium | GDPR · CCPA |
| Date of Birth | 03/12/1985 | Medium | GDPR · CCPA · HIPAA |
| Health Data | diagnosed, prescription… | Medium | GDPR · HIPAA |
| IPv4 Address | 192.168.1.1 | Medium | GDPR · CCPA |
| IPv6 Address | 2001:db8::1 | Medium | GDPR · CCPA |
| Gender | gender: female | Medium | GDPR Art.9 · CCPA |
| Driver's License | DL: A1234567 | Medium | GDPR · CCPA |
| Vehicle Registration | license plate: MH12AB | Medium | GDPR · CCPA |
| Name | "My name is Jane Doe" | Low | GDPR · CCPA |
| Address | 123 Main Street | Medium | GDPR · CCPA |
| Passport | A1234567 (with context) | Low | GDPR · CCPA |

Credit cards are validated with a Luhn checksum to eliminate false positives.
Name detection requires explicit context (e.g. "My name is", "I am", "Mr./Dr.") to avoid false positives.
Ethnicity, religion, and gender are GDPR Article 9 **special category** data — flagged as high severity.

---

## Privacy

- All detection, parsing, and encryption runs **inside VS Code** — no data leaves your machine
- PDF, Word, and Excel files are parsed locally using `pdf-parse`, `mammoth`, and `xlsx` — no cloud services
- DOCX and XLSX sanitized copies are rebuilt locally using Node's built-in `zlib` and the `xlsx` library
- Encryption keys are generated locally and stored only in `context.globalState`
- No account, login, or backend required

---

## Files

```
vscode-extension/
  package.json              Extension manifest + command/config contributions
  src/
    extension.js            Main extension — commands, status bar, decorations, chat participant
    pii-detector-node.js    PII detection + AES-GCM encryption engine (Node.js, no dependencies)
    doc-parser.js           Document text extractor + sanitizer — PDF, Word, Excel, CSV
  images/
    icon.png                128×128 extension icon
```
