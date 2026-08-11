# AI Prompt Guard 🛡️

> Automatically strips PII from your prompts **before** they reach any AI tool — Claude, ChatGPT, Copilot, Gemini, or any other.

Built entirely with Claude Code. It actually protected itself during its own development.

---

## The Problem

Every time you paste a document, email, or ticket into an AI tool, you risk leaking:
- Names, emails, phone numbers
- Credit card & bank account numbers
- Aadhaar, PAN, Passport, SSN numbers
- Dates of birth, National Insurance numbers
- And more...

**AI Prompt Guard intercepts the prompt before it leaves your device and sanitizes it automatically.**

---

## What's Inside

| Component | Description |
|-----------|-------------|
| `chrome-extension/` | Browser extension for Chrome, Edge, Brave, Arc |
| `vscode-extension/` | VS Code extension with Claude Code hook integration |

---

## Chrome Extension

### Install (Developer Mode)
1. Clone this repo
2. Open Chrome → `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** → select the `chrome-extension/` folder

### What it does
- Monitors text input on AI tool websites (ChatGPT, Claude, Gemini, Copilot, etc.)
- Detects PII in real time
- Warns you before submission
- Option to sanitize or send original

---

## VS Code Extension

### Install from VSIX
```bash
code --install-extension vscode-extension/ai-prompt-guard-2.0.0.vsix
```

### Install from source
```bash
cd vscode-extension
npm install
npm run package   # generates .vsix
code --install-extension ai-prompt-guard-*.vsix
```

### What it does
- Integrates with Claude Code as a pre-prompt hook
- Scans prompts for PII before they are sent
- Blocks or sanitizes based on your policy
- Shows a macOS/system notification when PII is detected

---

## PII Patterns Detected

- Email addresses
- Phone numbers (India, US, UK formats)
- Credit card numbers (with/without spaces)
- Aadhaar numbers
- PAN numbers
- Passport numbers
- SSN (US Social Security Numbers)
- UK National Insurance numbers
- Dates of birth
- Bank account numbers

---

## Custom Rules

You can add your own regex patterns via the VS Code extension settings or the Chrome extension popup.

---

## Contributing

Pull requests are welcome! Please open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push and open a PR

---

## License

[Apache 2.0](LICENSE) — free to use, modify, and distribute. Enterprise-friendly.

---

## Author

**Ankur Bhatnagar** — Built for the SAP Vibe Coding Challenge 2026
