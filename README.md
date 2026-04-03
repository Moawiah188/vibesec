# VibeSec ⚡🔒

A VS Code extension that scans your code for security issues — powered by [Semgrep](https://semgrep.dev) and designed for developers who move fast.

> Built as a capstone project. MVP-first, local-first, no cloud required.

---

## What It Does

1. You open a file in VS Code
2. You run **"VibeSec: Scan Current File"**
3. The extension scans it with Semgrep in the background
4. Security issues appear as **inline highlights** directly in your code
5. Hover over a highlight to read what the issue is and why it matters

No accounts. No cloud. No telemetry. Everything runs on your machine.

---

## Screenshots

> *(Coming soon)*

---

## Features

| Feature | Status |
|---------|--------|
| Scan current file | ✅ Sprint 1 |
| Inline diagnostics (squiggly lines) | ✅ Sprint 1 |
| YAML policy file to control rules | 🔜 Sprint 2 |
| Findings side panel | 🔜 Sprint 2 |
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
git clone https://github.com/YOUR_USERNAME/vibesec.git
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

---

## Project Structure

```
vibesec/
├── src/
│   ├── extension.ts     # Entry point — registers the command
│   ├── scanner.ts       # Runs Semgrep, parses JSON output
│   └── types.ts         # Internal Finding model
├── test-samples/
│   └── insecure.py      # Sample vulnerable file
├── .vscode/
│   └── launch.json      # F5 launch config
├── package.json         # Extension manifest
└── tsconfig.json        # TypeScript config
```

---

## How Rules Are Selected

VibeSec automatically picks Semgrep rules based on the file type:

| Language | Rules Used |
|----------|-----------|
| Python | `r/python.lang.security` |
| JavaScript | `r/javascript.lang.security` |
| TypeScript | `r/typescript.lang.security` |
| Java | `r/java.lang.security` |
| Go | `r/go.lang.security` |
| Ruby | `r/ruby.lang.security` |
| PHP | `r/php.lang.security` |
| Other | `r/generic.secrets` |

In Sprint 2, this will be overridden by a `.vibesec.yaml` policy file in your project root.

---

## Roadmap

- **Sprint 1** — Scan a file, show inline highlights ✅
- **Sprint 2** — YAML policy file controls rules and severity
- **Sprint 3** — AI-assisted fix suggestions (OpenAI / Anthropic)
- **Sprint 4** — Local scan history saved to JSON

---

## Tech Stack

- TypeScript
- VS Code Extension API
- Semgrep CLI
- Node.js (VS Code's built-in runtime)

No backend. No database. No cloud infrastructure.

---

## License

MIT
