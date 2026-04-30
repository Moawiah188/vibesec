// The TreeView-based Scan panel was retired in favor of the unified analysis
// webview (see src/panelView.ts). This file is kept as a tiny constants module
// so the workspace walker (extension.ts and panelView.ts) keeps the same set
// of "noisy" directories filtered out of every scan.

export const IGNORED_DIR_NAMES = new Set([
  "node_modules",
  ".git",
  ".vscode",
  ".idea",
  "out",
  "dist",
  "build",
  ".venv",
  "venv",
  "__pycache__",
  ".pytest_cache",
  ".mypy_cache",
  ".next",
  ".cache",
  "target",       // rust / java
  "bin",
  "obj",
]);
