import * as path from "path";
import * as vscode from "vscode";
import {
  Finding,
  FindingId,
  PromptCache,
  PROMPT_CACHE_PROJECT_KEY,
  findingId,
  promptCacheFileKey,
} from "./types";

// ── Panel state ───────────────────────────────────────────────────────────────

export type PanelState =
  | { kind: "empty" }                        // extension just activated, no scan yet
  | { kind: "noFindings" }                   // scan ran cleanly, nothing found
  | { kind: "error"; message: string }       // policy load error or scan error
  | { kind: "findings"; findings: Finding[] };

// ── Tree node discriminated union ─────────────────────────────────────────────
//
// Hierarchy: Folder → File → Finding → FindingDetail
//
// The folder layer was added so multi-file scans (coming in a later sprint)
// group naturally. When a scan only touches one folder we still show the
// folder node — it stays consistent and gives users a "where" label.

interface FolderNode {
  kind:         "folder";
  /** Workspace-relative POSIX path, e.g. "src/auth" or "." for workspace root. */
  folderPath:   string;
  /** Absolute path for tooltips / resourceUri. */
  absoluteDir:  string;
  files:        FileGroup[];
}

interface FileGroup {
  filePath: string;
  findings: Finding[];
}

interface FileNode {
  kind:     "file";
  filePath: string;
  findings: Finding[];
}

interface FindingNode {
  kind:    "finding";
  finding: Finding;
}

interface FindingDetailNode {
  kind:    "findingDetail";
  finding: Finding;
}

type FindingsTreeNode = FolderNode | FileNode | FindingNode | FindingDetailNode;

// ── Severity → color token + codicon ─────────────────────────────────────────

const SEVERITY_COLOR: Record<Finding["severity"], string> = {
  error:   "vibesec.errorForeground",
  warning: "vibesec.warningForeground",
  info:    "vibesec.infoForeground",
};

const SEVERITY_CODICON: Record<Finding["severity"], string> = {
  error:   "error",
  warning: "warning",
  info:    "info",
};

// Distinct shape + color — severity is never communicated by color alone
function severityIcon(sev: Finding["severity"]): vscode.ThemeIcon {
  return new vscode.ThemeIcon(
    SEVERITY_CODICON[sev],
    new vscode.ThemeColor(SEVERITY_COLOR[sev]),
  );
}

// Sort order: error first, then warning, then info
const SEVERITY_SORT: Record<Finding["severity"], number> = {
  error:   0,
  warning: 1,
  info:    2,
};

function worstSeverity(findings: Finding[]): Finding["severity"] {
  if (findings.some((f) => f.severity === "error"))   { return "error"; }
  if (findings.some((f) => f.severity === "warning")) { return "warning"; }
  return "info";
}

// ── Rule ID → short category label ───────────────────────────────────────────

/**
 * Strip the "vibesec." prefix and return the first two dash-segments as an
 * uppercase category tag.
 *
 * Examples:
 *   "vibesec.command-injection-os-system" → "COMMAND-INJECTION"
 *   "vibesec.weak-hash-md5-python"        → "WEAK-HASH"
 *   "vibesec.hardcoded-secret"            → "HARDCODED-SECRET"
 */
function formatRuleCategory(ruleId: string): string {
  const stripped = ruleId.startsWith("vibesec.") ? ruleId.slice("vibesec.".length) : ruleId;
  const parts = stripped.split("-");
  return parts.slice(0, 2).join("-").toUpperCase();
}

// ── Workspace-relative path helpers ──────────────────────────────────────────

/**
 * Return the POSIX-form workspace-relative directory for a finding's file.
 * Falls back to the absolute directory if the file is outside every
 * workspace folder (e.g. a file opened ad-hoc).
 */
function relativeDir(absoluteFile: string): string {
  const folders = vscode.workspace.workspaceFolders ?? [];
  for (const folder of folders) {
    const rootFs = folder.uri.fsPath;
    if (absoluteFile.startsWith(rootFs + path.sep) || absoluteFile === rootFs) {
      const relFile = path.relative(rootFs, absoluteFile).replace(/\\/g, "/");
      const relDir = path.posix.dirname(relFile);
      return relDir === "" || relDir === "." ? "." : relDir;
    }
  }
  // Outside workspace — use the absolute POSIX directory
  return path.dirname(absoluteFile).replace(/\\/g, "/");
}

/**
 * Display label for a folder node. "." (workspace root) becomes a friendlier
 * "workspace root" so users aren't staring at a bare dot.
 */
function folderLabel(folderPath: string): string {
  return folderPath === "." ? "workspace root" : folderPath;
}

// ── Provider ──────────────────────────────────────────────────────────────────

export class FindingsProvider
  implements vscode.TreeDataProvider<FindingsTreeNode>
{
  private _onDidChangeTreeData =
    new vscode.EventEmitter<FindingsTreeNode | undefined | void>();

  readonly onDidChangeTreeData: vscode.Event<FindingsTreeNode | undefined | void> =
    this._onDidChangeTreeData.event;

  private state: PanelState = { kind: "empty" };

  // ── Prompt cache (Sprint 4) ──────────────────────────────────────────────
  //
  // Generated prompts are stored here keyed by:
  //   • findingId(f)             — per-vuln prompts
  //   • promptCacheFileKey(path) — per-file prompts
  //   • PROMPT_CACHE_PROJECT_KEY — the single project-level prompt
  // The cache is wiped any time setState is called with a fresh `findings`
  // payload so users never see stale prompts after re-scanning.
  private promptCache: PromptCache = new Map();

  /** Called by extension.ts after each scan or state change. */
  setState(state: PanelState): void {
    this.state = state;
    // Any new state means the previous prompts no longer match what's shown.
    this.promptCache.clear();
    this._onDidChangeTreeData.fire();
  }

  // ── Findings accessors (used by Copy/Generate Prompt commands) ──────────

  getAllFindings(): Finding[] {
    return this.state.kind === "findings" ? this.state.findings : [];
  }

  getFindingsForFile(filePath: string): Finding[] {
    return this.getAllFindings().filter((f) => f.filePath === filePath);
  }

  /** Distinct file paths in the current findings, in insertion order. */
  getFilePaths(): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const f of this.getAllFindings()) {
      if (!seen.has(f.filePath)) {
        seen.add(f.filePath);
        out.push(f.filePath);
      }
    }
    return out;
  }

  // ── Prompt cache API ─────────────────────────────────────────────────────

  getCachedPrompt(key: string): string | undefined {
    return this.promptCache.get(key);
  }

  setCachedPrompt(key: string, prompt: string): void {
    this.promptCache.set(key, prompt);
  }

  hasCachedPrompt(key: string): boolean {
    return this.promptCache.has(key);
  }

  clearPromptCache(): void {
    this.promptCache.clear();
  }

  // Convenience helpers so callers don't need to construct cache keys
  cachedPromptForFinding(f: Finding): string | undefined {
    return this.promptCache.get(findingId(f));
  }
  cachedPromptForFile(filePath: string): string | undefined {
    return this.promptCache.get(promptCacheFileKey(filePath));
  }
  cachedPromptForProject(): string | undefined {
    return this.promptCache.get(PROMPT_CACHE_PROJECT_KEY);
  }
  /** Re-export of the keying helpers so callers don't double-import types.ts. */
  static keys = {
    forFinding: (f: Finding): FindingId => findingId(f),
    forFile:    (p: string): string => promptCacheFileKey(p),
    forProject: (): string => PROMPT_CACHE_PROJECT_KEY,
  };

  /**
   * viewsWelcome in package.json now handles empty/noFindings/error states
   * declaratively. Always return undefined so treeView.message is never set.
   */
  getViewMessage(): string | undefined {
    return undefined;
  }

  // ── TreeDataProvider implementation ────────────────────────────────────────

  getTreeItem(element: FindingsTreeNode): vscode.TreeItem {
    switch (element.kind) {
      case "folder":        return this.buildFolderItem(element);
      case "file":          return this.buildFileItem(element);
      case "finding":       return this.buildFindingItem(element);
      case "findingDetail": return this.buildFindingDetailItem(element);
    }
  }

  getChildren(element?: FindingsTreeNode): FindingsTreeNode[] {
    if (element === undefined) {
      return this.getRootChildren();
    }
    if (element.kind === "folder") {
      return element.files.map(
        (group): FileNode => ({
          kind:     "file",
          filePath: group.filePath,
          findings: group.findings,
        }),
      );
    }
    if (element.kind === "file") {
      return element.findings.map(
        (f): FindingNode => ({ kind: "finding", finding: f }),
      );
    }
    if (element.kind === "finding") {
      // The message lives in a collapsible child so the primary row stays compact
      return [{ kind: "findingDetail", finding: element.finding }];
    }
    return [];  // detail nodes are leaves
  }

  // ── Root aggregation: Folder → File → Finding ─────────────────────────────

  private getRootChildren(): FindingsTreeNode[] {
    if (this.state.kind !== "findings") {
      return [];  // viewsWelcome handles empty/noFindings/error display
    }

    // Group by file first
    const byFile = new Map<string, Finding[]>();
    for (const f of this.state.findings) {
      const arr = byFile.get(f.filePath) ?? [];
      arr.push(f);
      byFile.set(f.filePath, arr);
    }

    // Sort findings within each file: error → warning → info, then by line
    for (const findings of byFile.values()) {
      findings.sort((a, b) => {
        const d = SEVERITY_SORT[a.severity] - SEVERITY_SORT[b.severity];
        return d !== 0 ? d : a.startLine - b.startLine;
      });
    }

    // Group files under their workspace-relative folder
    const byFolder = new Map<string, FileGroup[]>();
    for (const [filePath, findings] of byFile.entries()) {
      const folderPath = relativeDir(filePath);
      const arr = byFolder.get(folderPath) ?? [];
      arr.push({ filePath, findings });
      byFolder.set(folderPath, arr);
    }

    // Sort files within each folder: most findings first, then by basename
    for (const files of byFolder.values()) {
      files.sort((a, b) => {
        const d = b.findings.length - a.findings.length;
        return d !== 0
          ? d
          : path.basename(a.filePath).localeCompare(path.basename(b.filePath));
      });
    }

    // Sort folders: most total findings first, then alphabetical
    return Array.from(byFolder.entries())
      .sort(([pA, filesA], [pB, filesB]) => {
        const totalA = filesA.reduce((s, f) => s + f.findings.length, 0);
        const totalB = filesB.reduce((s, f) => s + f.findings.length, 0);
        const d = totalB - totalA;
        return d !== 0 ? d : pA.localeCompare(pB);
      })
      .map(([folderPath, files]): FolderNode => {
        // Resolve absolute directory path from the first file in this group
        const absoluteDir = path.dirname(files[0].filePath);
        return { kind: "folder", folderPath, absoluteDir, files };
      });
  }

  // ── Item builders ──────────────────────────────────────────────────────────

  private buildFolderItem(node: FolderNode): vscode.TreeItem {
    const allFindings = node.files.flatMap((f) => f.findings);
    const worst       = worstSeverity(allFindings);
    const fileCount   = node.files.length;
    const issueCount  = allFindings.length;

    const item = new vscode.TreeItem(
      folderLabel(node.folderPath),
      vscode.TreeItemCollapsibleState.Expanded,
    );
    item.description  = `${fileCount} file${fileCount !== 1 ? "s" : ""}  ·  ${issueCount} issue${issueCount !== 1 ? "s" : ""}`;
    item.tooltip      = node.absoluteDir;
    item.iconPath     = new vscode.ThemeIcon(
      "folder",
      new vscode.ThemeColor(SEVERITY_COLOR[worst]),
    );
    item.contextValue = "vibesecFolder";
    item.accessibilityInformation = {
      label: `Folder ${folderLabel(node.folderPath)}, ${fileCount} file${fileCount !== 1 ? "s" : ""}, ${issueCount} issue${issueCount !== 1 ? "s" : ""}, worst severity ${worst}`,
      role:  "treeitem",
    };
    return item;
  }

  private buildFileItem(node: FileNode): vscode.TreeItem {
    const fileName = path.basename(node.filePath);
    const count    = node.findings.length;
    const worst    = worstSeverity(node.findings);

    const item = new vscode.TreeItem(
      fileName,
      vscode.TreeItemCollapsibleState.Expanded,
    );
    item.description  = `${count} issue${count !== 1 ? "s" : ""}`;
    item.tooltip      = node.filePath;
    item.resourceUri  = vscode.Uri.file(node.filePath);  // theme-aware file icon
    // Severity-tinted file-code badge keeps the shape+color severity cue
    item.iconPath     = new vscode.ThemeIcon(
      "file-code",
      new vscode.ThemeColor(SEVERITY_COLOR[worst]),
    );
    item.contextValue = "vibesecFile";
    item.accessibilityInformation = {
      label: `${fileName}, ${count} issue${count !== 1 ? "s" : ""}, worst severity ${worst}`,
      role:  "treeitem",
    };
    return item;
  }

  private buildFindingItem(node: FindingNode): vscode.TreeItem {
    const f        = node.finding;
    const category = formatRuleCategory(f.ruleId);
    const lineNum  = f.startLine + 1;  // display as 1-based

    // Primary row: "Line N" label, "CATEGORY" description — compact at a glance
    const item = new vscode.TreeItem(
      `Line ${lineNum}`,
      vscode.TreeItemCollapsibleState.Collapsed,
    );
    item.description  = category;
    item.iconPath     = severityIcon(f.severity);  // shape + color, never color alone
    item.contextValue = "vibesecFinding";
    item.tooltip      = `${f.severity.toUpperCase()} — ${f.ruleId}\n${f.message}`;

    item.accessibilityInformation = {
      label: `${f.severity}, line ${lineNum}, ${category}`,
      role:  "treeitem",
    };

    // Click the row → navigate; click the arrow → expand to see message
    item.command = {
      command:   "vibesec.goToFinding",
      title:     "Go to Finding",
      arguments: [f],
    };

    return item;
  }

  private buildFindingDetailItem(node: FindingDetailNode): vscode.TreeItem {
    const f = node.finding;

    const item = new vscode.TreeItem(
      f.message,
      vscode.TreeItemCollapsibleState.None,
    );
    // contextValue enables the inline Copy Description button
    item.contextValue = "vibesecFindingDetail";

    // Tooltip: full diagnostic including code snippet
    const md = new vscode.MarkdownString(undefined, true);
    md.supportThemeIcons = true;
    const icon = f.severity === "error" ? "$(error)"
      : f.severity === "warning" ? "$(warning)"
      : "$(info)";
    md.appendMarkdown(`${icon} **${f.severity.toUpperCase()} — ${f.ruleId}**\n\n`);
    md.appendMarkdown(`${f.message}\n\n`);
    if (f.snippet.trim() !== "") {
      const lang = f.filePath.endsWith(".py")  ? "python"
        : f.filePath.endsWith(".ts") ? "typescript"
        : f.filePath.endsWith(".js") ? "javascript"
        : "";
      md.appendCodeblock(f.snippet.trim(), lang);
    }
    item.tooltip = md;

    item.accessibilityInformation = {
      label: `Description: ${f.message}`,
      role:  "treeitem",
    };

    return item;
  }
}
