# VibeSec ⚡🔒

A VS Code extension that scans your code for security issues — powered by [Semgrep](https://semgrep.dev) and designed for developers who move fast.

> Built as a capstone project. MVP-first, local-first, no cloud required.

---

## What It Does

1. You open a file in VS Code
2. You run **"VibeSec: Scan Current File"**
3. The extension scans it with Semgrep in the background
4. Security issues appear as **inline highlights** directly in your code
5. Results also show up in the **VibeSec Findings panel** in the sidebar
6. Click any finding in the panel to jump to the exact line

No accounts. No cloud. No telemetry. Everything runs on your machine.

---

## Screenshots

> *(Coming soon)*

---

## Features

| Feature | Status |
|---------|--------|
| Scan current file | ✅ v0.1.0 |
| Inline diagnostics (squiggly lines) | ✅ v0.1.0 |
| YAML policy file to control rules | ✅ v0.2.0 |
| Findings side panel | ✅ v0.2.0 |
| Bundled default ruleset (no internet) | ✅ v0.2.0 |
| AI-assisted fix suggestions | 🔜 Sprint 3 |
| Local scan history log | 🔜 Sprint 4 |

---

## Requirements

- [VS Code](https://code.visualstudio.com/) 1.85 or later
- [Semgrep CLI](https://semgrep.dev/docs/getting-started/) installed and on your PATH
- Node.js 18+ (for extension development only)

### Install Semgrep

```bash
# macOS / Linux
pip install semgrep

# or via Homebrew
brew install semgrep

# Windows
pip install semgrep
```

Verify it works:
```bash
semgrep --version
```

---

## Getting Started (Development)

### 1. Clone the repo

```bash
git clone https://github.com/Moawiah188/vibesec.git
cd vibesec
```

### 2. Install dependencies

```bash
npm install
```

### 3. Compile

```bash
npm run compile
```

### 4. Run in VS Code

1. Open the `vibesec` folder in VS Code
2. Press **F5**
3. A second VS Code window opens — this is your test environment
4. Open any file and run **Ctrl+Shift+P → VibeSec: Scan Current File**

---

## Try It With the Sample File

The repo includes an intentionally insecure Python file for testing:

```
test-samples/insecure.py
```

Open it in the Extension Development Host and run a scan. You should see findings for:
- Command injection via `subprocess`
- Insecure MD5 password hashing
- Hardcoded API key
- SQL injection via string concatenation

---

## Policy File (`.vibesec.yaml`)

Drop a `.vibesec.yaml` in your project root to control how VibeSec scans your code.

```yaml
# Which rule packs to use
presets:
  - vibesec:default        # Bundled OWASP rules — works offline

# Minimum severity to report
severity:
  minSeverity: warning     # error | warning | info

# Exclude paths from scanning
files:
  exclude:
    - "**/node_modules/**"
    - "**/*.test.ts"

# Add your own inline rules
rules:
  - id: my-custom-rule
    message: "Don't use eval()"
    severity: ERROR
    languages: [javascript]
    pattern: eval(...)
```

Use **Ctrl+Shift+P → VibeSec: Open Policy File** to create one with a starter template.
Use **VibeSec: Reload Policy** to pick up changes without restarting VS Code.

---

## Commands

| Command | Description |
|---------|-------------|
| `VibeSec: Scan Current File` | Scan the active file and show findings |
| `VibeSec: Open Policy File` | Create or open `.vibesec.yaml` in the workspace root |
| `VibeSec: Reload Policy` | Force-reload the policy file from disk |
| `VibeSec: Go to Finding` | Navigate to a finding's location (used by panel clicks) |

---

## Project Structure

```
vibesec/
├── src/
│   ├── extension.ts          # Entry point — registers commands, wires up UI
│   ├── scanner.ts            # Runs Semgrep, parses JSON output
│   ├── policy.ts             # Loads and validates .vibesec.yaml
│   ├── findingsProvider.ts   # Findings side panel (TreeView)
│   └── types.ts              # Internal data models
├── rules/
│   └── default.yaml          # Bundled OWASP-aligned Semgrep rules
├── test-samples/
│   ├── insecure.py           # Sample vulnerable Python file
│   ├── .vibesec.yaml         # Example policy (preset-based)
│   ├── .vibesec-custom.yaml  # Example policy (custom rules only)
│   └── custom-rules.yaml     # Example external rule file
├── .vscode/
│   └── launch.json           # F5 launch config
├── package.json              # Extension manifest
├── tsconfig.json             # TypeScript config
└── CHANGELOG.md              # Version history
```

---

## Bundled Rules

The `vibesec:default` preset includes ~30 rules covering the OWASP Top 10 — no internet required.

| Category | Examples |
|----------|---------|
| Injection | Command injection, SQL injection, `eval`/`exec` |
| Cryptographic Failures | MD5, SHA-1 weak hashing |
| Auth Failures | Hardcoded passwords, API keys, tokens |
| Integrity Failures | `pickle` deserialization, unsafe YAML load |
| XSS | `innerHTML`, `document.write` |
| Misconfiguration | Flask `debug=True`, CORS allow-all |
| Insecure Randomness | `random.random()`, `Math.random()` |
| Path Traversal | Unsanitized `open()`, `readFile()` |

Languages covered: **Python, JavaScript, TypeScript**

---

## Roadmap

- **v0.1.0** — Scan a file, show inline highlights ✅
- **v0.2.0** — Policy file, findings panel, bundled ruleset ✅
- **Sprint 3** — AI-assisted fix suggestions (OpenAI / Anthropic)
- **Sprint 4** — Local scan history saved to JSON

---

## Tech Stack

- TypeScript
- VS Code Extension API
- Semgrep CLI
- `js-yaml` — policy file parsing
- `minimatch` — glob-based file exclusions

No backend. No database. No cloud infrastructure.

---

## License

MIT
