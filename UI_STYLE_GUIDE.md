# VibeSec UI Style Guide
Sprint 3 - "It Feels Right"

This document is the reference for all UI decisions in VibeSec. Future sprints should extend it rather than contradict it.

---

## Design Principles

1. **Stay native** — VibeSec looks and behaves like a built-in VS Code panel. Use built-in theme tokens, codicons, and the standard TreeView. No custom HTML/CSS.
2. **Error-first hierarchy** — The most severe findings always appear at the top of every list.
3. **Actionable at a glance** — Users understand severity, file, and category without clicking anything.
4. **Never color-only** — Severity is always expressed through icon shape + text label + color. Color is the third layer, not the first.
5. **No noise** — Info-level findings are styled subtly. Only errors demand attention.

---

## Color Tokens

Three custom tokens contributed via `contributes.colors` in `package.json`. Reference them in TypeScript as `new vscode.ThemeColor("vibesec.<token>")`.

| Token | Dark default | Light default | High contrast | Usage |
|---|---|---|---|---|
| `vibesec.errorForeground` | `#F48771` | `#E51400` | `#F48771` | Error icons, file icons with errors |
| `vibesec.warningForeground` | `#CCA700` | `#915100` | `#CCA700` | Warning icons, file icons with warnings |
| `vibesec.infoForeground` | `#75BEFF` | `#306EAD` | `#75BEFF` | Info icons |

Values match VS Code's own `errorForeground`, `editorWarning.foreground`, and `editorInfo.foreground` defaults — VibeSec findings look consistent with native editor diagnostics.

**Important:** Color is always paired with a distinct icon shape and a text label. Never use color as the sole indicator of severity.

---

## Icon System

All icons are VS Code Codicons. No custom icon font is used in the tree view.

| Context | Codicon | Shape | Color token |
|---|---|---|---|
| Error finding | `error` | Filled circle with X | `vibesec.errorForeground` |
| Warning finding | `warning` | Triangle with ! | `vibesec.warningForeground` |
| Info finding | `info` | Circle with i | `vibesec.infoForeground` |
| File node (worst=error) | `file-code` | File page | `vibesec.errorForeground` |
| File node (worst=warning) | `file-code` | File page | `vibesec.warningForeground` |
| File node (worst=info) | `file-code` | File page | `vibesec.infoForeground` |
| Scan button (title bar) | `$(play)` | — | — |
| Reload button (title bar) | `$(refresh)` | — | — |
| Activity bar | Custom SVG | Shield + bolt | — |

### Activity Bar Icon

Source: `media/vibesec-icon.svg`

Design: shield outline with a lightning bolt inside. Single `<path>` with `fill="currentColor"` and `fill-rule="evenodd"`. No embedded CSS, no gradients. VS Code masks it with its own theme-appropriate color.

---

## Typography

VS Code controls all font sizing and family. VibeSec does not override fonts.

- **TreeItem label** — default tree font, medium weight (the main message text)
- **TreeItem description** — same font, dimmed by VS Code (~60% opacity) — used for category + line
- **Tooltip headings** — `**bold**` via MarkdownString
- **Tooltip category** — backtick code span: `` `COMMAND-INJECTION` ``
- **Tooltip code** — triple-backtick code block with language tag for syntax highlighting

### Label format conventions

| Node type | `label` field | `description` field |
|---|---|---|
| File node | `basename.py` | `parent-dir  ·  N issue(s)` |
| Finding node | Full finding message | `CATEGORY  ·  Line N` |

---

## Sorting

- **Within a file:** errors first → warnings → info → ascending by line number within the same severity
- **Across files:** most total findings first → then alphabetical by filename

---

## Accessibility

### Contrast
The color tokens pass WCAG AA contrast ratios within VS Code's dark, light, and high-contrast themes (values sourced from VS Code's own diagnostic color defaults).

### Never color-only
Every severity indicator uses three layers simultaneously:
1. **Shape** — the codicon has a distinct shape (circle-X, triangle, circle-i)
2. **Text** — the `description` field shows `COMMAND-INJECTION · Line N` without any color
3. **Color** — applied on top as a third layer, never as the only differentiator

### Screen reader (`accessibilityInformation`)
Both node types set `item.accessibilityInformation` so screen readers announce useful natural-language descriptions:

| Node | Announced as |
|---|---|
| File node | `"filename.py, 3 issues, worst severity error"` |
| Finding node | `"error: Command injection detected, COMMAND-INJECTION, line 12"` |

### Keyboard navigation
VS Code TreeView handles arrow key navigation and Enter-to-activate natively. The scan and reload buttons in the panel title bar are reachable via F6 (focus panel toolbar) then Tab. `viewsWelcome` action links are focusable and activatable with Enter.

### Tooltip readability without color
Tooltips are written so severity is clear from text alone:
- Bold header: `**ERROR — vibesec.command-injection-os-system**`
- Codicon name is included as text: `$(error)` renders as the error icon but its name conveys the severity in screen-reader mode
- Category shown as a plain text badge: `` `COMMAND-INJECTION` ``

---

## Empty and Error States

Driven by the `vibesec.panelState` context key (set via `setContext` in `extension.ts`) and rendered via `contributes.viewsWelcome` in `package.json`.

| State | Icon | Message | Action |
|---|---|---|---|
| `empty` | none | "No scan has run yet." | [Scan Current File], [Open Policy File] |
| `noFindings` | `$(pass-filled)` | "No security issues found. Your last scan came back clean." | none |
| `error` | `$(error)` | "Scan encountered an error. Check that Semgrep is installed." | [Open VibeSec Settings] |

`treeView.message` is always `undefined` — `viewsWelcome` is the sole mechanism for empty-state display.

---

## Settings

Accessible from VS Code Settings UI (`Ctrl+,`) under the "VibeSec" section.

| Setting ID | Type | Default | Description |
|---|---|---|---|
| `vibesec.semgrepPath` | string | `"semgrep"` | Path to Semgrep binary (for non-standard installs) |
| `vibesec.autoScanOnSave` | boolean | `false` | Auto-scan on file save — opt-in only |
| `vibesec.showInlineDecorations` | boolean | `true` | Show inline squiggles in the editor |

`autoScanOnSave` defaults to `false` intentionally. Continuous scanning on every save can be disruptive; users must consciously enable it.

---

## Onboarding Walkthrough

Defined in `contributes.walkthroughs` in `package.json`. Uses VS Code's native "Get Started" tab (accessible via `Help → Get Started`).

Three steps:
1. **Install Semgrep** — no completion event (can't detect install)
2. **Run your first scan** — auto-completes on `onCommand:vibesec.scanCurrentFile`
3. **Customize with a policy file** — auto-completes on `onCommand:vibesec.openPolicyFile`

Step markdown source files: `media/walkthrough/install.md`, `scan.md`, `policy.md`.

---

## Spacing and Shape

VibeSec uses the VS Code native TreeView exclusively. No custom HTML/CSS is introduced. Indentation, row height, padding, and scrollbars are all inherited from the host theme.

---

## Future Sprint Guidelines

- All new colors → add to `contributes.colors` in `package.json`
- All new icons → use existing Codicons or add SVG files to `media/`
- Webviews (Sprint 4+) → use `--vscode-*` CSS custom properties, never hardcoded hex values
- New TreeItem types → follow the `kind: "file" | "finding"` discriminated union pattern
- Never express severity through color alone — always pair with shape + text
