# Changelog

All notable changes to VibeSec are documented here.

---

## [0.2.0] — 2026-04-04

### Overview
This release adds a full policy configuration system, a dedicated Findings side panel, and a bundled ruleset — turning VibeSec from a basic scanner into a configurable, team-ready security tool.

---

### Added

#### Policy File Support (`.vibesec.yaml`)
- New `policy.ts` module — loads and validates a `.vibesec.yaml` file from the workspace root
- Supports **presets** (e.g. `vibesec:default`) to activate bundled or registry rule packs
- Supports **severity filtering** via `minSeverity` (error / warning / info) and per-rule overrides
- Supports **inline custom rules** in Semgrep format directly inside the policy file
- Supports **external rule files** (workspace-relative YAML paths via `externalRuleFiles`)
- Supports **file exclusion patterns** (glob-based, e.g. `**/node_modules/**`, `**/*.test.ts`)
- Policy is **cached per workspace** — no re-parsing on every scan
- Always returns a usable config even if the file is missing or invalid (graceful degradation with error messages)
- New command: `VibeSec: Reload Policy` — force-reloads `.vibesec.yaml` from disk
- New command: `VibeSec: Open Policy File` — creates or opens `.vibesec.yaml` with a starter template

#### Findings Panel (TreeView)
- New `findingsProvider.ts` module — implements a VS Code side panel under the Explorer
- Findings are **grouped by file** in a collapsible tree
- Each finding shows severity icon, rule ID, message, and line number
- **Click a finding** to jump directly to its location in the editor
- **Hover a finding** for a rich markdown tooltip (rule ID, full message, code snippet)
- Panel badge shows total finding count
- Contextual empty-state messages guide the user when no scan has run or no issues were found
- New command: `VibeSec: Go to Finding` (used internally by tree-click navigation)

#### Bundled Default Ruleset (`rules/default.yaml`)
- ~30 rules included out of the box — no internet connection required
- Covers OWASP Top 10 categories:
  - **A03 Injection** — command injection (`subprocess`, `os.system`, `child_process`), SQL injection, code injection (`eval`, `exec`)
  - **A02 Cryptographic Failures** — weak hashing (MD5, SHA-1)
  - **A07 Auth Failures** — hardcoded passwords, API keys, secrets, tokens
  - **A08 Integrity Failures** — insecure deserialization (`pickle`), unsafe YAML load
  - **XSS** — `innerHTML`, `document.write`, `outerHTML` assignment
  - **A05 Misconfiguration** — Flask `debug=True`, CORS allow-all
  - **A06 Outdated Components** — `random.random()` (Python), `Math.random()` (JS)
  - **A04 Insecure Design** — path traversal (`open`, `readFile`)
- Rules cover Python, JavaScript, and TypeScript
- Each rule includes CWE mapping, OWASP category, confidence level, and a human-readable message
- Referenced via the `vibesec:default` preset in `.vibesec.yaml`

#### Test Sample Files
- `test-samples/.vibesec.yaml` — example policy using `vibesec:default` preset with severity filters and exclusions
- `test-samples/.vibesec-custom.yaml` — example policy with custom inline rules only (no presets)
- `test-samples/custom-rules.yaml` — example external rule file with hardcoded secret, SQL injection, and insecure random detections

#### New Dependencies
- `js-yaml` (^4.1.0) — YAML parsing for policy files and rule files
- `minimatch` (^9.0.4) — glob pattern matching for file exclusion

---

### Changed

#### `scanner.ts` — Rewritten to be Policy-Driven
- `scanFile()` now accepts a `PolicyConfig` and extension path as arguments (previously only took a file path)
- Removed `configForFile()` — the old function that picked Semgrep registry rules based on file extension (e.g. `r/python.lang.security`). Config is now fully driven by the policy file
- Added `buildConfigArgs()` — constructs `--config` arguments from active presets and custom rules
- Added `resolvePreset()` — maps `vibesec:` preset names to bundled rule file paths
- Added `writeTempRuleFile()` — serializes inline custom rules to a temp JSON file for Semgrep, then cleans up after scan
- Added `effectiveSeverity()` — applies per-rule severity overrides from policy
- Added `meetsMinSeverity()` — filters findings below the `minSeverity` threshold
- Added `cleanRuleId()` — strips path prefixes from Semgrep rule IDs for cleaner display

#### `extension.ts` — Expanded Orchestration
- Now manages a policy cache (`Map<string, PolicyConfig>`) keyed by workspace root
- Checks file exclusion patterns before scanning — skips excluded files with a notification
- Passes loaded policy into `scanFile()` on every scan
- Added progress notification UI (spinner with "Scanning…" message)
- Added policy error display — shows validation errors from `.vibesec.yaml` as warnings
- Added inline policy file template (used by the `openPolicyFile` command)
- Now wires up the `FindingsProvider` TreeView alongside the existing `DiagnosticCollection`

#### `types.ts` — Heavily Expanded
- Added `SeverityLevel` type (`"error" | "warning" | "info"`)
- Added `SEVERITY_RANK` numeric map for severity comparison
- Added `CustomRule` — full Semgrep-shaped rule definition (id, message, severity, languages, pattern/patterns)
- Added `PatternClause` — single pattern expression (pattern, pattern-not, pattern-inside, pattern-regex)
- Added `SeveritySettings` — minSeverity + per-rule override map
- Added `FilePatterns` — include/exclude glob arrays
- Added `RawPolicy` — unvalidated shape of a parsed `.vibesec.yaml`
- Added `PolicyConfig` — validated, ready-to-use config object (presets, severity, rules, files, isDefault flag)
- `Finding` interface: unchanged in shape, now typed against `SeverityLevel`

---

### Removed

- `configForFile()` from `scanner.ts` — replaced by the policy-driven `buildConfigArgs()` system. The old approach auto-selected Semgrep registry rule packs based on file extension (e.g. `.py` → `r/python.lang.security`). This was removed because it required internet access and offered no customization.

---

## [0.1.0] — Sprint 1 Initial Release

### Added
- `src/extension.ts` — VS Code entry point; registers `vibesec.scanCurrentFile` command, shows inline squiggles via `DiagnosticCollection`
- `src/scanner.ts` — Semgrep CLI runner; `scanFile(filePath)` executes Semgrep and returns findings; `configForFile()` picked rule packs by file extension; `parseSemgrepOutput()` converts JSON to `Finding[]`
- `src/types.ts` — `Finding` interface (ruleId, message, severity, filePath, line/col range, snippet)
- `test-samples/insecure.py` — intentionally vulnerable Python file for testing (command injection, weak hash, hardcoded secret, SQL injection)
- `package.json`, `tsconfig.json`, `.vscodeignore`, `package-lock.json`
- `.vscode/launch.json` — F5 debug launcher (Extension Development Host)
