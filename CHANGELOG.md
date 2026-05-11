# Changelog

All notable changes to VibeSec are documented here.

---

## [0.7.0] — Sprint 7 "Taint"

### Overview
Sprint 7 adds **taint analysis** — tracking how untrusted data flows from a *source* (user input, file read, environment variable) through assignments and helper calls to a *sink* (shell exec, SQL query, deserializer, HTTP request) within a single file. Built on Semgrep's free `mode: taint` engine — no Semgrep Pro, no new dependencies, no auth. The data flow is surfaced as a dedicated **Data flow** block in every taint-finding card with click-to-jump rows for source / intermediates / sink, included in every AI fix prompt so the model knows exactly where to sanitise, and flagged with a **TAINT** chip on the Control Center's Rules page.

---

### Added

#### Bundled taint ruleset (`rules/taint.yaml`)
- New `vibesec:taint` preset — 8 hand-written taint-mode rules across Python and JS/TS:
  - `vibesec.taint-command-injection-python` — `request.* / sys.argv / os.environ` → `subprocess.*(shell=True) / os.system / os.popen`, sanitised by `shlex.quote`.
  - `vibesec.taint-command-injection-node` — `req.body/query/params/headers/cookies / process.argv / process.env` → `child_process.exec*`.
  - `vibesec.taint-sql-injection-node` — `req.*` → `db.query/execute/run/all/get`.
  - `vibesec.taint-path-traversal-python` — `request.* / sys.argv / input()` → `open() / os.path.join`.
  - `vibesec.taint-path-traversal-node` — `req.*` → `fs.readFile* / fs.createReadStream`.
  - `vibesec.taint-unsafe-deserialization-python` — `request.* / sys.stdin.read()` → `pickle.loads / pickle.load / yaml.load`.
  - `vibesec.taint-xss-node` — `req.*` → `res.send / res.write / innerHTML / outerHTML / document.write`.
  - `vibesec.taint-ssrf-python` — `request.*` → `requests.get/post/request / urllib*.urlopen / httpx.*`.
- Opt-in via `presets: [vibesec:taint]` in `.vibesec.yaml`. The default policy template now ships a commented-out reference line so users see the option.

#### Scanner — dataflow extraction
- `src/scanner.ts` now parses `extra.dataflow_trace` from Semgrep's JSON output into a structured `Finding.taint` field. Defensive parser handles the `["CliLoc"|"CliCall", {...}]` tagged-tuple shape Semgrep emits, with graceful fallback to the finding's own location if the trace is partial.
- Each taint finding emits a dedicated `scan` info log (`Taint: <rule> — source L42 → sink L58`) so the Logs page shows the data flow without extra UI.

#### Finding type + panel adapter
- New `TaintFlow` and `TaintLocation` types in `src/types.ts`. `Finding.taint?` is optional — search-mode findings are unchanged.
- `PanelFinding.taint?` mirrors the same shape with workspace-relative paths. `webview/types.ts` updated in lockstep.
- New `goToLocation` wire message (`{ absPath, line }`) lets the React panel jump to arbitrary file:line — used by every step in a Data flow block.

#### Data flow UI in `VulnCard.tsx`
- New collapsible **Data flow** section below the metadata grid, rendered only when the finding carries taint data.
- Three row types: **SOURCE** (where untrusted data enters), **STEP N** (intermediate variable assignments), **SINK** (the dangerous call). Sink row uses a red callout border so the danger point is visually distinct.
- Each row is a button that dispatches `goToLocation` — one click opens the file and selects the line.
- A small accent-colored `TAINT` chip in the section header signals the analysis mode.

#### AI fix prompts include data flow
- `buildVulnInstruction` (per-vuln) injects a dedicated "Data flow:" section listing source, intermediate steps, and sink — each on its own line with the relevant snippet. The numbered checklist that follows adds an explicit step: *Identify where to sanitise or validate the data along the source-to-sink path.*
- `buildFileInstruction` (per-file) and `buildProjectInstruction` (per-project) tag each taint finding with a compact `taint: src L42 → sink L58` annotation so file-level and project-level prompts stay scannable.

#### Control Center Rules page
- `RuleEntry` gains a `mode: "search" | "taint"` field. `rulesIndex.ts` reads `mode` from raw YAML; `webview/controlCenter/types.ts` updated in lockstep.
- Each taint rule renders a small accent-colored `TAINT` chip next to its title in the Rules page detail table.
- The bundled `taint.yaml` file gets a hand-tuned description: *"Taint analysis — tracks user input from source to dangerous sink within a file."*

---

### Changed
- `vscode.ExtensionContext.subscriptions` registers no new disposables — taint integration reuses every existing channel (diagnostics, log bus, panel state, scan history).
- Version bumped `0.6.4` → `0.7.0`.

### Build / pipeline
- No new dependencies. No new build steps. `npm run compile` and the existing F5 launch configuration cover the full sprint.

---

## [0.6.4] — Sprint 6 "Control Center"

### Overview
Sprint 6 adds a second webview — the **VibeSec Control Center** — that opens as a full editor-area tab next to the existing Analysis sidebar. It surfaces four pages (Dashboard / Settings / Logs / Rules) sourced live from the extension's own state, makes every `vibesec.*` setting two-way bindable from a real UI, persists scan history per-workspace, and ships a structured logging pipeline with disk persistence so users can inspect what happened during prior sessions. Visual direction is from the Claude Design output at `Extension Design/VibeSec Extension Webview/` (CDN React/Babel and Google Fonts stripped, all assets bundled locally to satisfy CSP). The existing Analysis sidebar is untouched.

---

### Added

#### Control Center webview
- New `src/controlCenterView.ts` — `ControlCenterController` hosting a singleton editor-area `WebviewPanel` (`vibesec.controlCenter`). Mirrors the patterns in `panelView.ts`: per-render CSP nonce, `localResourceRoots` locked to `media/`, theme bridge via `onDidChangeActiveColorTheme`, ready-handshake replay, `retainContextWhenHidden: true`. Subsequent `show()` calls reveal the existing panel rather than spawning a duplicate.
- New `src/controlCenterMessages.ts` — discriminated-union wire protocol (mirrored verbatim in `webview/controlCenter/types.ts`). The `ready` → `init` handshake replays settings, scan history, log ring buffer, and the rules index in one message.
- New command `vibesec.openControlCenter` ("Open Control Center") with `$(settings-gear)` icon.
- New `view/title` menu binding so the gear button shows up in the Analysis sidebar's view title bar — both entry points open the same singleton panel.
- New `webview/controlCenter/` source folder, bundled by esbuild into `media/webview/controlCenter.{js,css}` via a second entry point in `esbuild.webview.mjs` (`entryNames: '[name]'` keeps outputs flat).
- Design CSS ported with two CSP-required substitutions: Google Fonts `@import` removed and `Geist` / `Geist Mono` rebound to `var(--vscode-font-family)` / `var(--vscode-editor-font-family)` so typography inherits the user's VS Code config.

#### Settings page (Phase 1)
- All 8 `vibesec.*` settings rendered as two-way-bound controls (text input / toggle / segmented enum), grouped per the design (Engine / Behavior / AI assistance).
- Default values are read live from `cfg.inspect(key).defaultValue` — no hardcoded duplication of `package.json` defaults.
- "Open settings.json" opens the workspace settings file (or user settings if no folder is open).
- "Reset to defaults" prompts via `vscode.window.showWarningMessage({ modal: true })` and only proceeds on explicit confirmation; clears each key with `cfg.update(k, undefined, target)` so values fall back to the package.json declared defaults.
- `vscode.workspace.onDidChangeConfiguration("vibesec")` listener pushes refreshed snapshots, keeping the UI in sync with external `settings.json` edits.

#### Dashboard + Scan history (Phase 2)
- New `src/scanHistoryStore.ts` — `workspaceState`-backed history capped at 200 entries; fires `onDidChange` after every mutation. Each entry tracks `{ ts, filesScanned, filesSkipped, duration, findings: { error, warning, info }, trigger }`.
- `runScanOnTargets` now records a history entry on every non-empty completion. The `trigger` field is sourced from the call site: explorer right-click → `selection`, on-save → `onSave`, everything else → `manual`.
- Dashboard renders:
  - 1d / 7d / 30d range selector (re-bucketed client-side; no extra round-trip).
  - Summary header: total findings, scan count, last-scan relative time, average duration, trigger label.
  - Severity breakdown cards (error / warning / info) with percentage of total.
  - Recent scans table (last 6 in range).
  - Right rail: 4 quick-action tiles wired to existing commands (`scanWorkspace`, focus Analysis panel, `openPolicyFile`, `reloadPolicy`); environment card; SVG sparkline of findings per bucket.
- "Clear history" affordance wipes `workspaceState` after a single confirmation.

#### Logs page + persistent log pipeline (Phase 3)
- New `src/logBus.ts` — process-wide singleton with `info / warn / error(type, msg, detail?)`, a 1000-event ring buffer, and a `subscribe()` API. Safe to import before activation.
- New `src/logStore.ts` — JSON Lines persistence under `<globalStorageUri>/logs/vibesec.log`, with rotation to `vibesec.log.1` at ~2 MB. On activation, the store tail-loads up to 1000 events back into the bus's ring buffer so the Logs page shows prior-session events immediately.
- Tee to `vscode.OutputChannel("VibeSec")` so users can read raw events from VS Code's standard Output panel.
- Instrumentation (no behavior change):
  - `src/scanner.ts` — fatal Semgrep exits log `semgrep error` with stderr; non-fatal stderr surfaces as `semgrep warn`.
  - `src/policy.ts` — load success / read failure / YAML parse error / partial-failure all log `policy` events.
  - `src/llmClient.ts` — `callLlm` is wrapped with start/success/error logs that include HTTP status and round-trip latency.
  - `src/promptGenerator.ts` — `prompt` info events per per-vuln / per-file / per-project build, with provider + model.
  - `src/extension.ts` — high-level `scan` events at start / cancel / complete / fully-failed; policy-excluded files batched into a single `skip warn`.
- Logs page:
  - Summary strip (total / errors / warnings / info).
  - Type filter (scan / prompt / skip / semgrep / policy / api / other) + level filter + free-text search across `msg + detail`.
  - Newest-first list, click-to-expand detail rows.
  - **Copy** filtered events to clipboard; **Clear** truncates ring buffer + on-disk file.

#### Rules page (Phase 4)
- New `src/rulesIndex.ts` — parses bundled `rules/*.yaml` and (when present) the workspace `.vibesec.yaml`, normalizing both into a `RuleFileEntry[]` + `RuleEntry[]` shape that mirrors the design. Best-effort: malformed YAML produces an empty file with `parseError` set instead of throwing. Confidence ladder maps `HIGH=0.95` / `MEDIUM=0.7` / `LOW=0.4`.
- Rules page renders:
  - Summary card: total rules, bundled / custom / external file counts.
  - Two-level navigation — file list grouped by source → per-file rule table.
  - Per-file row: name, source chip, description, severity dots, rule count, parse-error indicator if applicable.
  - Per-file detail: stat cards (Total / Enabled / Error / Warning / Info), search + severity filter, table with Severity / Rule (id + language tags) / Category / CWE / Confidence / On.
  - **Open YAML** button on file headers posts `openRuleFile`; the controller resolves the absolute path and opens it in a regular editor tab via `workspace.openTextDocument` + `window.showTextDocument`.
- File-system watchers on `**/.vibesec.yaml` and `<extensionUri>/rules/*.{yaml,yml}` push live `rulesUpdated` messages so edits in another tab reflect on the page without a manual refresh.
- Per-rule live toggles are intentionally deferred — the toggle column displays current state but is read-only in v1. The "external" group renders as a disabled placeholder.

#### Other
- `webview/AnalysisPanel.tsx` and the Control Center now consume the version string from `init` messages (sourced from `context.extension.packageJSON.version`) instead of a hardcoded literal — future bumps are a single `package.json` edit.
- New CSS primitives in `webview/controlCenter/controlCenter.css`: `.toggle`, `.segmented`, `.input`, `.settings-row`, `.kv-grid`, `.qa`, `.sev-card`, `.sev`, `.tag`, `.toast`, `.confidence-bar`/`.confidence-fill`, `.rule-file-row`, `.rule-source-tag`, `.rule-count-chip`, `.rules-header`, `.rule-row`, `.logs-header`, `.log-row`, `.log-detail`, `.search-wrap`, `.filter-row`, `.sidebar-version`.

### Changed
- `runScanOnTargets` now takes a `trigger` parameter; `vibesec.scanSelected` and the on-save handler pass it through. Cancelled scans with no findings are excluded from history to avoid noisy sparklines.
- The on-save listener now calls `runScanOnFile` directly with `trigger="onSave"` instead of dispatching `vibesec.scanCurrentFile`, so the scan-history entry is tagged correctly.
- Version bumped `0.5.0` → `0.6.4`. `package-lock.json` brought in sync (was still at `0.4.0`).

### Build / pipeline
- `esbuild.webview.mjs` now ships two entry pairs (Analysis panel + Control Center). `entryNames: '[name]'` keeps the output tree flat.
- Both webview bundles remain CSP-clean: only React's bundled error-decoder URL and W3C namespace constants appear as literal strings; no remote network requests.

---

## [0.5.0] — Sprint 5 "Panel"

### Overview
Sprint 5 replaces VibeSec's two native TreeView panels with a single React-based analysis webview that lives in the activity-bar sidebar. The new panel is a faithful port of the design mockup at `Extension Design/VibeSec extension/vibesec-panel/` — file picker with checkboxes, severity-filtered finding cards with metadata grid (Category / Confidence / CWE / OWASP), expandable details, and a Full Fix tab that surfaces ready-to-paste AI prompts grouped per file. Severity is now aligned 1:1 with the YAML policy schema (`error` / `warning` / `info`), and findings carry colored callout-style left borders so errors and warnings are visible at a glance. Under the hood, Semgrep rule metadata is now forwarded losslessly into every `Finding`, which is what powers the panel's metadata grid.

---

### Added

#### React Analysis Panel (sidebar webview view)
- New `src/panelView.ts` — `PanelController` implementing `vscode.WebviewViewProvider`. Owns the sidebar webview, builds CSP-locked HTML with a per-render nonce, hosts the message bridge, and exposes `pushState()`, `pushProgress()`, `notifyPromptCopied()`, `reveal()`
- New `webview/` source folder bundled by esbuild into `media/webview/`:
  - `AnalysisPanel.tsx` — top-level component; renders empty / loading / populated / noFindings / error states and the Results / Full Fix tabs
  - `FileTree.tsx` — multi-select file picker with checkboxes, indeterminate folder states, ext-color icons, and select-all / clear actions
  - `VulnCard.tsx` — expandable finding card with severity tag, rule id, title, description, file:line jump-link, and a 2×2 metadata grid (Category / Confidence / CWE / OWASP)
  - `FixFileGroup.tsx` — Full Fix tab's per-file prompt block (groups findings, exposes per-file Copy chip, calls into the existing prompt cache)
  - `SegmentedTabs.tsx`, `icons.tsx`, `vscode.ts`, `main.tsx`, `types.ts` — supporting primitives
  - `styles.css` — port of the design system (~1080 lines): dark + light themes, `vs-accent-green` / `vs-accent-mono` variants, `vs-density-comfortable` / `vs-density-compact`, callout-style severity borders, syntax tokens, animations, scrollbar treatments
- New `src/panelMessages.ts` — discriminated-union message protocol shared between the extension and the React bundle (mirrored verbatim in `webview/types.ts`)
- New `vibesec.analysisPanel` view registered under the existing `vibesec` activity-bar container as a webview view (replaces the old `vibesec.scanPanel` and `vibesec.findingsPanel` TreeViews)

#### Build Pipeline
- New `esbuild.webview.mjs` — IIFE-format browser bundle, no remote sources, no `eval`, `react` + `react-dom` bundled inline, optional `--watch` mode
- New `webview/tsconfig.json` — `jsx: "react-jsx"`, `module: "esnext"`, `noEmit: true` (esbuild handles emission)
- New npm scripts:
  - `compile` now runs `tsc -p ./ && node esbuild.webview.mjs`
  - `build:webview` and `watch:webview` for webview-only iterations
- New devDependencies: `esbuild`, `react`, `react-dom`, `@types/react`, `@types/react-dom`

#### Severity Tier Alignment + Callout Borders
- Filter chips reduced from the design's four-tier (Critical / High / Medium / Low) to the YAML policy's three actual tiers (Error / Warning / Info), so the UI never lies about what the schema can express
- New full-card-height callout-style left borders on finding cards (markdown blockquote vibe):
  - **Error** → solid red (`var(--sev-critical)`)
  - **Warning** → solid amber/yellow (`var(--sev-medium)`)
  - **Info** → default subtle border (no callout treatment)
- New severity tag pill rules (`.sev-tag-error`, `.sev-tag-warning`, `.sev-tag-info`) with both dark- and light-theme variants

#### Generate Prompts Button (panel-side)
- New `Wand` icon button in the panel side-header: pre-warms the prompt cache in the background by dispatching `vibesec.generatePrompts` (which respects the active `vibesec.promptMode` setting). Disabled until findings exist
- New accent-styled **Generate** button in the Full Fix tab summary bar, next to **Copy all** — same dispatch, contextually obvious placement
- Replaces the prior auto-on-scan generation pattern (it never auto-ran, but copy chips now have a clearer pre-warm path)

#### Theme Bridging
- Webview detects VS Code's body class on boot (`vscode-light`, `vscode-dark`, `vscode-high-contrast`, `vscode-high-contrast-light`) and applies the matching design class (`vs-theme-light` / `vs-theme-dark`)
- Re-themes within ~1 frame on `vscode.window.onDidChangeActiveColorTheme` via a `themeChanged` postMessage
- No `--vscode-*` token bridging — the design palette is preserved end-to-end for visual fidelity

#### Lossless Semgrep Rule Metadata
- `Finding.metadata` is a new optional `Record<string, unknown>` populated by the scanner directly from `semgrep --json`'s `extra.metadata` field. Whatever a rule (bundled, registry, or user-authored) carries — `cwe`, `owasp`, `references`, `likelihood`, `impact`, `technology`, `category`, `confidence` — flows untouched into the panel
- The panel's metadata adapter (`toPanelMeta` in `panelMessages.ts`) safely extracts CWE / OWASP arrays, Category, and Confidence with em-dash fallbacks so the metadata grid never shows blank cells

#### Broader Custom-Rule Schema
- `CustomRule` now accepts `pattern-either`, `pattern-regex`, taint mode (`mode: "taint"` with `pattern-sources` + `pattern-sinks`), and any extra Semgrep-recognised field via an open index signature
- Policy validation accepts any of: `pattern` / `patterns` / `pattern-either` / `pattern-regex`, OR taint mode with both sources and sinks
- Rule bodies are now passed through to Semgrep losslessly (`{ ...raw, ...normalised-fields }`), so registry rules and future rule sources retain `fix`, `paths`, `options`, `pattern-not`, etc. without needing per-field allowlisting

#### New Settings
- `vibesec.openPanelOnScan` (boolean, default `false`) — when on, focus the analysis panel automatically whenever a scan starts

---

### Changed

#### `src/extension.ts`
- Removed both `createTreeView` calls (`vibesec.scanPanel`, `vibesec.findingsPanel`); `FindingsProvider` is kept as the in-memory single source of truth for findings + prompt cache, but no longer registered as a TreeDataProvider
- New `PanelController` instantiation with hooks delegating back to `runScanOnTargets`, `goToFinding`, `copyPromptForFinding`, `copyPromptForFilePath`, `vibesec.copyPromptForAll`, `vibesec.generatePrompts`
- `runScanOnTargets` now calls `panel.pushProgress(percent, basename)` once per file so the panel's progress bar advances in step with the existing notification progress
- `vibesec.scanSelected` repurposed to read URIs from VS Code's Explorer right-click context (first arg = clicked URI, second arg = full multi-selection). The panel has its own internal file selection
- Stale fs watcher and workspace folder listener removed — the panel rebuilds its tree on demand via `getWorkspaceTree`

#### `package.json`
- `contributes.views.vibesec` collapsed to a single `vibesec.analysisPanel` webview view
- `contributes.viewsWelcome` cleared (the React panel handles all empty / error / no-findings states internally)
- `contributes.menus`:
  - All `view/title` and `view/item/*` entries scoped to the removed TreeViews dropped
  - New `explorer/context` "Scan with VibeSec" entry on `vibesec.scanSelected`
  - New `editor/title` "Scan Current File" entry on `vibesec.scanCurrentFile`
- Version bumped to `0.5.0`

### Removed
- `vibesec.scanPanel` and `vibesec.findingsPanel` TreeView registrations
- `vibesec.refreshScanTree` command (no provider to refresh)
- `vibesec.openPanel` command (the sidebar view IS the panel — no command needed)
- `src/scanProvider.ts` `ScanProvider` class, `ScanNode` types, `isScanFileNode` / `isScanFolderNode` helpers — file trimmed to a constants module exporting only `IGNORED_DIR_NAMES` (still used by both the multi-target scan walker and the panel's tree builder)

---

## [0.4.0] — Sprint 4 "Prompts"

### Overview
Sprint 4 unlocks two major capabilities: **multi-target scanning** (scan multiple files, folders, or the entire project in one go) and **AI fix prompts** (generate copy-paste instructions that tell an AI assistant exactly how to fix each finding). API keys are stored securely using VS Code's built-in secret storage — nothing is written to disk or settings files.

---

### Added

#### Multi-Target Scanning
- **Scan Whole Project** (`vibesec.scanWorkspace`) — new title-bar button (`$(run-all)`) on the Scan panel; walks the entire workspace recursively, skips ignored directories (`node_modules`, `.git`, `dist`, etc.) and non-scannable files, and aggregates all findings into one panel update
- **Scan Selected** now handles multiple files *and* folders — selecting a folder in the Scan panel and clicking play recursively scans every scannable file inside it
- Batch scans run under `vscode.window.withProgress` with a "Scanning N / M files…" counter and a **Cancel** button that stops mid-scan cleanly
- New async `expandTargetToFiles()` helper in `extension.ts` — walks directories using `fs.promises.readdir`, skips symlinks, dot-directories, and `IGNORED_DIR_NAMES`
- New `src/scannableExtensions.ts` module — single source of truth for which extensions are scannable; shared between the Scan panel file browser and the multi-target walker

#### AI Fix Prompts
- New `src/promptGenerator.ts` — builds structured natural-language instructions from one or more findings and sends them to the configured LLM; returns the model's response as plain text
  - `generatePromptForVuln(finding, opts)` — one model call per finding; includes ±5 lines of source context around the offending lines (marked with `>`)
  - `generatePromptForFile(filePath, findings, opts)` — one call batching all findings in a file
  - `generatePromptForProject(findings, opts)` — one call covering every finding across the whole scan
- New `src/llmClient.ts` — thin HTTP client for all three providers using Node 18+ built-in `fetch` (no new dependency)
  - OpenAI: `POST /v1/chat/completions`
  - Anthropic: `POST /v1/messages` with `anthropic-version: 2023-06-01` header
  - Gemini: `POST /v1beta/models/{model}:generateContent`
  - Friendly error messages for 401 (key rejected), 429 (rate limit), 5xx (provider down), and network failures
  - 60-second timeout via `AbortController`
  - `pingProvider()` helper sends a minimal 1-token request for key verification

#### Secure API Key Management
- New `src/secrets.ts` — wrapper around VS Code `SecretStorage`; keys stored under `vibesec.apiKey.openai`, `vibesec.apiKey.anthropic`, `vibesec.apiKey.gemini`
- `VibeSec: Set API Key` — picks provider from a quick-pick, prompts for key with `showInputBox({ password: true })` so the key is masked while typing
- `VibeSec: Clear API Key` — removes the stored key for a chosen provider
- `VibeSec: Test API Key` — sends a ping to verify the key works; shows a success or error notification

#### Prompt UI — Generate and Copy Prompts
- **Generate Prompts** (`$(sparkle)`) — title-bar button on the Findings panel; pre-generates prompts for all findings in batch according to the active `promptMode`; shows progress and supports cancellation
- **Copy Prompt for Vulnerability** (`$(comment-discussion)`) — inline button on individual finding rows; generates on demand (or reads cache) and copies to clipboard
- **Copy Prompt for File** (`$(comment-discussion)`) — inline button on file group rows
- **Copy Prompt for All** (`$(comment-discussion)`) — title-bar button; copies the single project-level prompt
- Prompts are **lazily generated** — no API call happens until the user clicks; scanning never triggers LLM calls automatically
- Generated prompts are **cached in memory** on `FindingsProvider` and reused on subsequent clicks; cache is cleared whenever a new scan runs

#### New Settings
Three new entries in **Settings → VibeSec**:

| Setting | Type | Default | Description |
|---|---|---|---|
| `vibesec.llmProvider` | dropdown | `anthropic` | Which AI provider to use (OpenAI / Anthropic / Gemini) |
| `vibesec.llmModel` | string | `claude-haiku-4-5` | Model ID — defaults to cheapest tier per provider |
| `vibesec.promptMode` | dropdown | `perFile` | How prompts are sliced: per file, per vulnerability, or per project |
| `vibesec.fileExtensions` | string | *(space-separated list)* | Space-separated file extensions to scan; edit in one text field |

- `vibesec.fileExtensions` changed from a JSON array (long list UI) to a plain string — users type extensions separated by spaces in a single compact text field
- `vibesec.llmProvider` auto-suggests the cheapest default model when changed: `gpt-5-nano` (OpenAI), `claude-haiku-4-5` (Anthropic), `gemini-2.5-flash-lite` (Gemini)

#### Onboarding Walkthrough — Step 4
- New walkthrough step "Hook up an AI provider for fix prompts" added to the existing first-install walkthrough; guides users to `VibeSec: Set API Key`; completes automatically once the command is run

---

### Changed

#### `src/extension.ts`
- `runScanOnFile()` is now the inner loop of a new `runScanOnTargets(targets)` batch runner
- `vibesec.scanSelected` now iterates all selected items, expands folders recursively, and passes the full file list to `runScanOnTargets`
- New `resolveModel(provider, configuredModel)` helper — detects provider-model mismatches using string-prefix heuristics and falls back to the provider default
- New `resolveLlmCallContext()` helper — reads provider + key + model from settings/secrets and surfaces actionable errors if anything is missing

#### `src/findingsProvider.ts`
- `setState()` clears the prompt cache on every call — stale prompts are never shown after a re-scan
- New accessors `getAllFindings()`, `getFindingsForFile()`, `getFilePaths()` used by prompt commands
- New static `FindingsProvider.keys` object exposes cache key helpers so callers don't need to import `types.ts` separately

#### `src/scanProvider.ts`
- `IGNORED_DIR_NAMES` is now exported — reused by the multi-target walker in `extension.ts`
- Removed local `SCANNABLE_EXTENSIONS` constant — replaced by `getScannableExtensions()` from `scannableExtensions.ts`
- Added `isScanFolderNode()` export

#### `src/types.ts`
- Added `LlmProvider` (`"openai" | "anthropic" | "gemini"`)
- Added `PromptMode` (`"perVulnerability" | "perFile" | "perProject"`)
- Added `FindingId` (branded string type for per-finding cache keys)
- Added `PromptCache` (`Map<string, string>`)
- Added `findingId(f)`, `promptCacheFileKey(path)`, `PROMPT_CACHE_PROJECT_KEY` helpers

#### `package.json`
- Version bumped `0.3.0` → `0.4.0`
- 8 new commands registered: `scanWorkspace`, `setApiKey`, `clearApiKey`, `testApiKey`, `generatePrompts`, `copyPromptForVuln`, `copyPromptForFile`, `copyPromptForAll`
- New title-bar and inline context-menu entries for prompt commands
- `commandPalette` visibility rules hide internal commands (`copyPromptForVuln`, `copyPromptForFile`) from the palette

---

### New Files

| File | Purpose |
|---|---|
| `src/scannableExtensions.ts` | Shared extension list + `isScannableUri()` helper |
| `src/secrets.ts` | VS Code SecretStorage wrapper, per-provider key management |
| `src/llmClient.ts` | HTTP clients for OpenAI, Anthropic, Gemini with error mapping |
| `src/promptGenerator.ts` | Prompt assembly engine, three granularities |

---

## [0.3.0] — Sprint 3 "Interface"

### Overview
Full UI/UX sprint. VibeSec gets its own activity bar icon, a **Scan panel** (multi-select file tree for choosing what to scan), a redesigned Findings panel with **folder grouping** (Folder → File → Finding → Detail) and severity-first visual hierarchy, a full accessibility pass, three user-configurable settings, auto-scan-on-save, a first-install walkthrough, and a Copy Description action. A UI style guide is included to keep future sprints consistent.

---

### Added

#### Activity Bar Icon
- VibeSec now has its own dedicated icon in the VS Code activity bar — a shield with a lightning bolt — separate from the Explorer sidebar
- New `media/vibesec-icon.svg` — single-path SVG with `fill="currentColor"` and `fill-rule="evenodd"` so VS Code can mask it correctly in dark, light, and high-contrast themes
- New `viewsContainers.activitybar` entry in `package.json` with id `vibesec`
- The Findings panel (`vibesec.findingsPanel`) is now hosted inside this dedicated container instead of the Explorer

#### Panel Title Bar Buttons
- **Scan** (`$(play)`) and **Reload Policy** (`$(refresh)`) buttons now appear directly in the Findings panel title bar — no need to open the command palette for the most common actions
- Wired via `contributes.menus["view/title"]` scoped to `view == vibesec.findingsPanel`

#### Scan Panel — Multi-Select File Tree
- New `vibesec.scanPanel` view in the VibeSec activity bar container, alongside Findings
- New `src/scanProvider.ts` — TreeDataProvider listing the workspace as a collapsible file tree with theme-aware icons
- Native `canSelectMany: true` — click to select, Ctrl/Cmd+click to add, Shift+click for range
- Auto-filters noise directories (node_modules, .git, dist, build, etc.) and identifies 25+ scannable file extensions
- `vibesec.scanSelected` command — title-bar play button reads selection and runs scan
- `vibesec.refreshScanTree` command — manual rebuild + auto-rebuild via filesystem watcher on create/delete

#### Findings Panel — Folder Grouping
- Tree hierarchy is now **Folder → File → Finding → FindingDetail** (was File → Finding → FindingDetail)
- Folder nodes show workspace-relative paths with severity-tinted icons
- Files within folders sorted by finding count then alphabetically

#### Declarative Empty / Error States (`viewsWelcome`)
- All three non-findings states are now rendered via `contributes.viewsWelcome` in `package.json` with clickable action buttons, replacing the plain text `treeView.message` strings from Sprint 2
- **`empty`** (no scan yet): "No scan has run yet." with `[$(play) Scan Current File]` and `[$(gear) Open Policy File]` buttons
- **`noFindings`** (clean scan): `$(pass-filled)` icon + "No security issues found. Your last scan came back clean."
- **`error`** (scan failed): `$(error)` icon + "Scan encountered an error." + `[$(settings-gear) Open VibeSec Settings]` deep-link
- State is driven by the `vibesec.panelState` context key, set via `vscode.commands.executeCommand("setContext", ...)` in `extension.ts` on every state transition

#### Redesigned Findings Tree — Compact Primary Row
- Finding nodes are now **two-level**: a compact primary row and an expandable description child
- **Primary row** (`vibesecFinding`): `Line N` as the label, `CATEGORY` as the dimmed description — the most important identifiers are visible at a glance without reading the full message
- **Description child** (`vibesecFindingDetail`): full finding message, expanded on demand — keeps the panel scannable when there are many findings
- Clicking the primary row still navigates to the finding in the editor; clicking the arrow expands the description

#### Copy Description
- New `vibesec.copyDescription` command registered in `extension.ts`
- A `$(copy)` **inline button** appears on the description child row when hovered — one click copies the full finding message to the clipboard
- Also available via right-click → **Copy Description** context menu on description nodes
- Both wired via `contributes.menus["view/item/inline"]` and `["view/item/context"]` scoped to `viewItem == vibesecFindingDetail`

#### Severity-Colored Icons
- All severity icons (`error`, `warning`, `info`) are now rendered with `vscode.ThemeColor` applied to their `ThemeIcon` — the icon tint matches the severity
- Three custom color tokens contributed via `contributes.colors`:
  - `vibesec.errorForeground` — defaults match VS Code's `errorForeground` (#F48771 dark / #E51400 light)
  - `vibesec.warningForeground` — matches `editorWarning.foreground` (#CCA700 dark / #915100 light)
  - `vibesec.infoForeground` — matches `editorInfo.foreground` (#75BEFF dark / #306EAD light)
- File node icons (`file-code`) are tinted with the **worst severity** color in that file — a file with any error shows a red icon; a warning-only file shows yellow
- Colors are consistent with VS Code's native diagnostic squiggles by design

#### Findings Sorting
- Findings within each file are now sorted: **errors first → warnings → info → then by ascending line number** within each severity tier
- Files are sorted by **most findings first**, then alphabetically by filename — the noisiest files surface to the top automatically

#### Rule Category Labels
- Finding primary rows show a short uppercase category tag derived from the rule ID (e.g. `vibesec.command-injection-os-system` → `COMMAND-INJECTION`, `vibesec.weak-hash-md5-python` → `WEAK-HASH`)
- Implemented in `formatRuleCategory()` in `findingsProvider.ts` — strips the `vibesec.` prefix and takes the first two dash-segments

#### File Node Directory Context
- File nodes now show the parent directory name in their description: e.g. `test-samples  ·  4 issues` instead of just `4 issues`
- Helps distinguish files with the same name in different directories when scanning across a project

#### Richer Tooltips
- Description child tooltips include a bold severity header (`$(error) **ERROR — vibesec.rule-id**`), the full message, and a **language-tagged code block** for the snippet — Python snippets get Python syntax highlighting, TypeScript gets TypeScript, etc.
- Severity is stated in plain text in the tooltip header, not conveyed by color alone

#### Accessibility — `accessibilityInformation`
- Both file nodes and finding nodes now set `item.accessibilityInformation` so screen readers announce useful descriptions instead of raw label/description strings:
  - File node: `"insecure.py, 4 issues, worst severity error"`
  - Finding node: `"error, line 12, COMMAND-INJECTION"`
  - Description child: `"Description: Command injection via subprocess.run(shell=True)..."`

#### Settings (`contributes.configuration`)
Three new user-configurable settings, accessible from **Settings → VibeSec**:

| Setting | Type | Default | Description |
|---|---|---|---|
| `vibesec.semgrepPath` | string | `"semgrep"` | Path to the Semgrep binary for non-standard installs |
| `vibesec.autoScanOnSave` | boolean | `false` | Auto-scan on file save — opt-in only |
| `vibesec.showInlineDecorations` | boolean | `true` | Toggle inline squiggles on/off without disabling the panel |

- `semgrepPath` is scoped `machine-overridable` (can be set per-machine or per-workspace)
- `autoScanOnSave` and `showInlineDecorations` are scoped `resource` (can vary per workspace folder)

#### Auto-Scan on Save
- New `vscode.workspace.onDidSaveTextDocument` listener in `extension.ts`
- Only triggers when `vibesec.autoScanOnSave` is `true` (off by default) and the saved document is the currently active file
- Re-reads the setting on every save event — toggling the setting takes effect immediately without reloading VS Code
- Reuses the existing `vibesec.scanCurrentFile` command rather than duplicating scan logic

#### Configurable Inline Decorations Toggle
- When `vibesec.showInlineDecorations` is `false`, the scan command calls `diagnosticCollection.delete()` instead of `set()` — the Findings panel still populates normally, but no squiggles appear in the editor

#### Configurable Semgrep Path
- `scanFile()` in `scanner.ts` now accepts an optional `semgrepPath` parameter (default: `"semgrep"`) passed through to `execFile()`
- The `extension.ts` scan command reads `vibesec.semgrepPath` from settings and forwards it on every scan

#### First-Install Onboarding Walkthrough
- New `contributes.walkthroughs` entry in `package.json` — appears in VS Code's **Help → Get Started** tab on first install
- Three guided steps:
  1. **Install Semgrep** — pip/brew install instructions, link to open terminal (no completion event — can't detect install)
  2. **Run your first scan** — auto-checks when the user runs `vibesec.scanCurrentFile` for the first time
  3. **Customize with a policy file** — auto-checks when the user runs `vibesec.openPolicyFile`
- Step content sourced from `media/walkthrough/install.md`, `scan.md`, and `policy.md`
- Walkthrough is re-openable anytime from the Welcome tab or `Welcome: Open Walkthrough` in the command palette — does not appear on every launch

#### UI Style Guide (`UI_STYLE_GUIDE.md`)
- New `UI_STYLE_GUIDE.md` at the repo root documenting the complete design system for future sprints:
  - Color tokens and their WCAG rationale
  - Icon system (codicons + custom SVG)
  - Typography conventions (label vs. description vs. tooltip)
  - Sorting rules
  - Accessibility requirements (contrast, screen-reader, keyboard, color-independence)
  - Empty/error state patterns
  - Settings reference
  - Guidelines for extending the design system in future sprints

---

### Changed

#### `package.json`
- Version bumped `0.2.0` → `0.3.0`
- All commands now have `"category": "VibeSec"` — they group cleanly in the command palette
- Added `vibesec.scanPanel` view, `scanSelected`, `refreshScanTree`, `copyDescription` commands
- `views` container changed from `"explorer"` to `"vibesec"` activity bar with dedicated icon
- Added `viewsWelcome` entries, `commandPalette` hiding for internal commands, color contributions, configuration settings, walkthrough

#### `src/findingsProvider.ts`
- Added `FolderNode` — tree hierarchy is now Folder → File → Finding → FindingDetail
- `severityIcon()` applies `vscode.ThemeColor` to each `ThemeIcon`
- Sorting: error → warning → info → line number within files; most findings first across files
- File icons tinted with worst severity; folder icons tinted similarly
- Compact primary row (Line N + category) with expandable description child
- `getViewMessage()` returns `undefined` — `viewsWelcome` handles all empty states

#### `src/extension.ts`
- New `runScanOnFile()` shared helper — `scanCurrentFile` and `scanSelected` funnel through it
- New `ScanProvider` + scan tree view with `canSelectMany: true`
- Filesystem watcher keeps scan tree in sync
- `updatePanel()` drives `setContext` for `viewsWelcome` when-clauses
- Reads `semgrepPath`, `autoScanOnSave`, `showInlineDecorations` from settings

#### `src/scanner.ts`
- `scanFile()` signature extended with an optional `semgrepPath: string = "semgrep"` parameter
- `execFile("semgrep", ...)` replaced with `execFile(semgrepPath, ...)` — the only line changed

---

### Accessibility Notes
- Severity is communicated through **three independent layers**: icon shape (circle-X / triangle / circle-i), text label (category + line), and color — color is never the sole indicator
- Custom color tokens inherit VS Code's WCAG AA-compliant diagnostic color defaults for dark, light, and both high-contrast themes
- `accessibilityInformation` is set on all tree nodes
- Keyboard navigation works natively via VS Code's TreeView (arrow keys, Enter to activate, F6 to focus panel toolbar)

---

## [0.2.0] — Sprint 2 "Policy"

### Overview
Adds a full policy configuration system, a dedicated Findings side panel, and a bundled ruleset — turning VibeSec from a basic scanner into a configurable, team-ready security tool.

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

## [0.1.0] — Sprint 1 "Scan"

### Added
- `src/extension.ts` — VS Code entry point; registers `vibesec.scanCurrentFile` command, shows inline squiggles via `DiagnosticCollection`
- `src/scanner.ts` — Semgrep CLI runner; `scanFile(filePath)` executes Semgrep and returns findings; `configForFile()` picked rule packs by file extension; `parseSemgrepOutput()` converts JSON to `Finding[]`
- `src/types.ts` — `Finding` interface (ruleId, message, severity, filePath, line/col range, snippet)
- `test-samples/insecure.py` — intentionally vulnerable Python file for testing (command injection, weak hash, hardcoded secret, SQL injection)
- `package.json`, `tsconfig.json`, `.vscodeignore`, `package-lock.json`
- `.vscode/launch.json` — F5 debug launcher (Extension Development Host)
