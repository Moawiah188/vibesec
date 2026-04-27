import * as path from "path";
import * as vscode from "vscode";

// ── Scannable file extensions ────────────────────────────────────────────────
//
// Source of truth for "which files can VibeSec scan". Two consumers:
//   1. The Scan panel (scanProvider.ts) — used to mark non-scannable files
//      with the "not scannable" badge.
//   2. The multi-target scan walker (extension.ts) — used to skip files
//      that cannot be scanned when walking a folder/workspace.
//
// Defaults can be overridden by the user via the `vibesec.fileExtensions`
// setting. Any user-provided value replaces the default list entirely
// (we don't merge, so users can drop extensions they don't want).

const DEFAULT_SCANNABLE_EXTENSIONS: readonly string[] = [
  ".py",  ".pyi",
  ".js",  ".jsx",  ".mjs",  ".cjs",
  ".ts",  ".tsx",
  ".java",
  ".go",
  ".rb",
  ".php",
  ".c",   ".h",    ".cpp",  ".hpp",   ".cc",
  ".cs",
  ".rs",
  ".swift",
  ".kt",  ".kts",
  ".scala",
  ".yaml", ".yml",
  ".json",
  ".html", ".htm",
  ".sh",  ".bash",
];

export function getDefaultScannableExtensions(): string[] {
  return [...DEFAULT_SCANNABLE_EXTENSIONS];
}

/**
 * Read the `vibesec.fileExtensions` setting and return a normalized Set
 * of lowercase extensions, each prefixed with a single dot.
 *
 * Falls back to the default list when the setting is missing, empty, or
 * contains only invalid entries.
 */
export function getScannableExtensions(): Set<string> {
  const cfg = vscode.workspace.getConfiguration("vibesec");
  const raw = cfg.get<string>("fileExtensions") ?? "";
  const tokens = raw.trim() !== "" ? raw.trim().split(/\s+/) : DEFAULT_SCANNABLE_EXTENSIONS;

  const set = new Set<string>();
  for (const entry of tokens) {
    if (typeof entry !== "string") { continue; }
    const trimmed = entry.trim().toLowerCase();
    if (trimmed === "") { continue; }
    set.add(trimmed.startsWith(".") ? trimmed : `.${trimmed}`);
  }

  // If the user managed to wipe everything to invalid entries, fall back
  // to defaults so the extension still behaves usefully.
  if (set.size === 0) {
    for (const ext of DEFAULT_SCANNABLE_EXTENSIONS) { set.add(ext); }
  }
  return set;
}

export function isScannablePath(filePath: string, exts?: Set<string>): boolean {
  const set = exts ?? getScannableExtensions();
  return set.has(path.extname(filePath).toLowerCase());
}

export function isScannableUri(uri: vscode.Uri, exts?: Set<string>): boolean {
  return isScannablePath(uri.fsPath, exts);
}
