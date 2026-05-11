# VibeSec ⚡🔒

A VS Code extension that scans your code for security issues — powered by [Semgrep](https://semgrep.dev) and designed for developers who move fast.

> Built as a capstone project. MVP-first, local-first, no cloud required.

---

## What It Does

1. Open a file in VS Code
2. Pick it in the **Scan panel** or just run **"VibeSec: Scan Current File"**
3. The extension runs Semgrep in the background
4. Security issues appear as **inline highlights** directly in your code
5. Results show up in the **Findings panel** grouped by folder and file
6. Click any finding to jump to the exact line — or copy its description to clipboard

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
| Activity bar icon + dedicated panels | ✅ v0.3.0 |
| Scan panel (file browser with multi-select) | ✅ v0.3.0 |
| Folder-grouped findings tree | ✅ v0.3.0 |
| Copy Description button | ✅ v0.3.0 |
| Configurable settings | ✅ v0.3.0 |
| First-install walkthrough | ✅ v0.3.0 |
| Scan whole project / multi-file scan | ✅ v0.4.0 |
| AI fix prompts (OpenAI / Anthropic / Gemini) | ✅ v0.4.0 |
| Secure API key storage | ✅ v0.4.0 |
| Copy-paste prompts per finding, file, or project | ✅ v0.4.0 |
| Analysis panel (React webview, sidebar) | ✅ v0.5.0 |
| Control Center (Dashboard / Settings / Logs / Rules) | ✅ v0.6.4 |
| Persistent scan history + sparkline | ✅ v0.6.4 |
| Structured logs with disk persistence + Output channel | ✅ v0.6.4 |
| Rule index browser with Open YAML | ✅ v0.6.4 |
| Taint analysis (source → sink data flow tracking) | ✅ v0.7.0 |
| Data flow visualisation in finding cards (click-to-jump) | ✅ v0.7.0 |
| TAINT chip on the Rules page | ✅ v0.7.0 |

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
- Command injection via `subprocess` and `os.system`
- Weak hashing with MD5 and SHA-1
- Hardcoded credentials and API keys
- SQL injection via string formatting
- Insecure deserialization with `pickle`
- Unsafe `yaml.load()`
- Insecure randomness with `random.random()`
- Code injection via `eval` and `exec`

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
| `VibeSec: Scan Selected` | Scan files/folders selected in the Scan panel |
| `VibeSec: Scan Whole Project` | Scan every scannable file in the workspace |
| `VibeSec: Open Policy File` | Create or open `.vibesec.yaml` in the workspace root |
| `VibeSec: Reload Policy` | Force-reload the policy file from disk |
| `VibeSec: Refresh File Tree` | Manually rebuild the Scan panel file list |
| `VibeSec: Set API Key` | Store an OpenAI, Anthropic, or Gemini API key securely |
| `VibeSec: Clear API Key` | Remove a stored API key |
| `VibeSec: Test API Key` | Verify a stored key is valid and accepted |
| `VibeSec: Generate Prompts` | Pre-generate AI fix prompts for all current findings |

---

## Project Structure

```
vibesec/
├── src/
│   ├── extension.ts            # Entry point — registers commands, wires up UI
│   ├── scanner.ts              # Runs Semgrep, parses JSON output
│   ├── policy.ts               # Loads and validates .vibesec.yaml
│   ├── findingsProvider.ts     # Findings panel (TreeView)
│   ├── scanProvider.ts         # Scan panel file browser (TreeView)
│   ├── scannableExtensions.ts  # Shared list of scannable file extensions
│   ├── secrets.ts              # Secure API key storage (VS Code SecretStorage)
│   ├── llmClient.ts            # HTTP clients for OpenAI, Anthropic, Gemini
│   ├── promptGenerator.ts      # Builds AI fix prompts from findings
│   └── types.ts                # Internal data models
├── media/
│   ├── vibesec-icon.svg      # Activity bar icon
│   └── walkthrough/          # First-install walkthrough content
├── rules/
│   └── default.yaml          # Bundled OWASP-aligned rules
├── test-samples/
│   ├── insecure.py           # Sample vulnerable Python file
│   ├── .vibesec.yaml         # Example policy (preset-based)
│   ├── .vibesec-custom.yaml  # Example policy (custom rules only)
│   └── custom-rules.yaml     # Example external rule file
├── design-mockups/           # UI design system and component mockups
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

- **v0.1.0** — Sprint 1 "Scan": scan a file, show inline highlights ✅
- **v0.2.0** — Sprint 2 "Policy": policy file, findings panel, bundled ruleset ✅
- **v0.3.0** — Sprint 3 "Interface": activity bar, scan panel, redesigned findings tree ✅
- **v0.4.0** — Sprint 4 "Prompts": multi-file scan, AI fix prompts, API key management ✅
- **v0.5.0** — Sprint 5 "Panel": React analysis sidebar, Full Fix tab, severity callouts ✅
- **v0.6.4** — Sprint 6 "Control Center": editor-area Dashboard / Settings / Logs / Rules, persistent scan history, structured logging ✅
- **v0.7.0** — Sprint 7 "Taint": bundled taint ruleset, dataflow extraction, data flow UI block, taint-aware AI prompts ✅
- **Next** — Sprint 8 "Rule Sources": external rule pack syncing, live per-rule toggles

---

## Taint Analysis

VibeSec ships a bundled **taint ruleset** that tracks how untrusted data flows from a *source* (HTTP request body, command-line argument, environment variable, file read) through variable assignments and helper calls to a *sink* (shell exec, SQL query, deserializer, outbound HTTP). This catches bugs that line-by-line pattern matching misses — e.g. when user input is read on line 12, stored in a variable, and only reaches `subprocess.run` on line 47.

**Enable it** by adding `vibesec:taint` to your `.vibesec.yaml`:

```yaml
presets:
  - vibesec:default
  - vibesec:taint
```

Bundled rules cover **command injection**, **SQL injection**, **path traversal**, **unsafe deserialization** (pickle / yaml), **XSS**, and **SSRF** for Python and JavaScript/TypeScript.

When a taint rule fires, the finding card shows a dedicated **Data flow** block:
- ① **SOURCE** — where the untrusted data enters
- ② **STEP N** — any intermediate variable assignments along the path
- ③ **SINK** — the dangerous call

Click any row to jump straight to that line. The AI fix prompt automatically includes the full data-flow path, so the assistant knows exactly where to add validation or sanitisation.

---

## AI Fix Prompts

After a scan, VibeSec can generate a copy-paste prompt you paste into Cursor, Claude Code, ChatGPT, or any AI assistant to get a fix back.

**Setup (one time):**
1. `Ctrl+Shift+P` → **VibeSec: Set API Key** — pick your provider (OpenAI, Anthropic, or Gemini) and paste your key. It's stored securely using VS Code's built-in secret storage and never written to disk.
2. Open **Settings → VibeSec** and choose your preferred **Prompt Mode**:
   - **Per File** *(default)* — one prompt per file, batching all findings in it
   - **Per Vulnerability** — one prompt per individual finding
   - **Per Project** — one prompt covering every finding across the whole scan

**Generating prompts:**
- Click the **$(sparkle) Generate Prompts** button in the Findings panel title bar to pre-generate all prompts at once
- Or hover any finding/file row and click the **$(comment-discussion) Copy Prompt** button to generate and copy on demand — no upfront cost

Prompts include the offending code with context lines, rule details, and instructions for the AI to explain the issue, show a corrected snippet, and list follow-up checks.

---

## Tech Stack

- TypeScript
- VS Code Extension API
- Semgrep CLI
- `js-yaml` — policy file parsing
- `minimatch` — glob-based file exclusions
- Node 18+ built-in `fetch` — LLM API calls (no extra HTTP library)

No backend. No database. No cloud infrastructure. Your API key stays on your machine.

---

## License

MIT
