# AI Prompt Guard — Chrome Extension

Intercepts prompts on Claude, ChatGPT, Gemini, Copilot, Perplexity, Mistral, and HuggingFace. Detects PII before it leaves your browser. **No backend, no account, no internet required** — all detection and encryption runs entirely inside the browser.

---

## Installation (Developer Mode)

1. Open Chrome → `chrome://extensions`
2. Enable **Developer Mode** (toggle top-right)
3. Click **Load Unpacked** → select the `chrome-extension/` folder
4. The 🛡️ shield icon appears in your toolbar — pin it for easy access

**After any code change:** click the reload button on the extension card, then refresh the AI tab.

---

## How it works

### Prompt scanning
```
You type a prompt → press Enter or click Send
        ↓
Content script intercepts the submit event
        ↓
PII Detector scans the text (runs locally, no network)
        ↓
If PII found → overlay shows a before/after comparison + detection table
        ↓
Choose:  🔒 Send Sanitized  |  🔐 Send Encrypted  |  ⚠️ Send Original  |  Cancel
```

- **Send Sanitized** — replaces each PII value with `[EMAIL_REDACTED]`, `[PAN_CARD_REDACTED]`, etc.
- **Send Encrypted** — replaces each PII value with `[ENC:category:base64ciphertext]` using AES-GCM 256-bit encryption. The encryption key is stored only in your browser's local storage.

### File attachment scanning
```
You attach a file → content script intercepts the change event
        ↓
File Scanner reads and scans the file locally
        ↓
If PII found → overlay lists each file with categories and item count
        ↓
Text files (.txt .csv .md .json …) → replaced with sanitized copy
PDF files                           → flagged + warned (binary, cannot be rewritten)
        ↓
Choose:  🔒 Replace with Sanitized Files  |  Upload Originals Anyway  |  Cancel
```

---

## Supported sites

| Site | Hostname |
|---|---|
| Claude | claude.ai |
| ChatGPT | chatgpt.com · chat.openai.com |
| Gemini | gemini.google.com |
| Microsoft Copilot | copilot.microsoft.com |
| Perplexity | www.perplexity.ai |
| Mistral | chat.mistral.ai |
| HuggingFace Chat | huggingface.co |

---

## PII categories detected

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
| Phone | 415-555-0100 | Medium | GDPR · CCPA |
| Date of Birth | 03/12/1985 | Medium | GDPR · CCPA · HIPAA |
| Health Data | diagnosed, prescription… | Medium | GDPR · HIPAA |
| Name | "My name is Jane Doe" | Low | GDPR · CCPA |
| Address | 123 Main Street | Medium | GDPR · CCPA |
| Passport | A1234567 (with context) | Low | GDPR · CCPA |

Credit cards are validated with a Luhn checksum to eliminate false positives.

---

## Allow list

In the overlay, click **✓ Safe** next to any detection to add it to your allow list — it will never be flagged again. Allow list entries are stored in `chrome.storage.local`.

---

## Popup controls

- **Toggle** — pause/resume scanning without uninstalling
- **Per-site toggle** — disable on specific domains
- **Stats** — total prompts scanned and PII-blocked count
- **Reset stats** — clears the counters

---

## Privacy

- All detection and encryption runs **inside Chrome** — no data leaves your machine
- Encryption keys are generated locally and stored only in `chrome.storage.local`
- No account, login, or backend required

---

## Files

```
chrome-extension/
  manifest.json       MV3 extension manifest
  background.js       Service worker — tracks scan stats
  pii-detector.js     PII detection + AES-GCM encryption engine (no dependencies)
  file-scanner.js     File reader + sanitizer (text files + PDF text extraction)
  content.js          Injected into AI pages — intercepts prompts + files + shows overlay
  overlay.css         Styles for the PII warning modal
  popup.html          Extension popup UI
  popup.js            Popup logic (toggle, stats)
  popup.css           Popup styles
```
