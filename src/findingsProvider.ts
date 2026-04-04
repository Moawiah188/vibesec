import * as path from "path";
import * as vscode from "vscode";
import { Finding } from "./types";

// ── Panel state ───────────────────────────────────────────────────────────────

export type PanelState =
  | { kind: "empty" }                        // extension just activated, no scan yet
  | { kind: "noFindings" }                   // scan ran cleanly, nothing found
  | { kind: "error"; message: string }       // policy load error or scan error
  | { kind: "findings"; findings: Finding[] };

// ── Tree node discriminated union ─────────────────────────────────────────────

interface FileNode {
  kind:     "file";
  filePath: string;
  findings: Finding[];
}

interface FindingNode {
  kind:    "finding";
  finding: Finding;
}

type FindingsTreeNode = FileNode | FindingNode;

// ── Severity → VS Code ThemeIcon ──────────────────────────────────────────────

const SEVERITY_ICON: Record<Finding["severity"], string> = {
  error:   "error",
  warning: "warning",
  info:    "info",
};

// ── Provider ──────────────────────────────────────────────────────────────────

export class FindingsProvider
  implements vscode.TreeDataProvider<FindingsTreeNode>
{
  private _onDidChangeTreeData =
    new vscode.EventEmitter<FindingsTreeNode | undefined | void>();

  readonly onDidChangeTreeData: vscode.Event<FindingsTreeNode | undefined | void> =
    this._onDidChangeTreeData.event;

  private state: PanelState = { kind: "empty" };

  /** Called by extension.ts after each scan or state change. */
  setState(state: PanelState): void {
    this.state = state;
    this._onDidChangeTreeData.fire();
  }

  /**
   * Returns the message string for the TreeView's `.message` property.
   * VS Code shows this text inside the panel whenever `getChildren` returns
   * an empty root array. Set to `undefined` when there is content.
   */
  getViewMessage(): string | undefined {
    switch (this.state.kind) {
      case "empty":
        return "Run 'VibeSec: Scan Current File' to see findings here.";
      case "noFindings":
        return "No security issues found. Well done.";
      case "error":
        return `$(error) ${this.state.message}`;
      case "findings":
        return undefined;  // message is hidden when content is present
    }
  }

  // ── TreeDataProvider implementation ────────────────────────────────────────

  getTreeItem(element: FindingsTreeNode): vscode.TreeItem {
    return element.kind === "file"
      ? this.buildFileItem(element)
      : this.buildFindingItem(element);
  }

  getChildren(element?: FindingsTreeNode): FindingsTreeNode[] {
    if (element === undefined) {
      return this.getRootChildren();
    }
    if (element.kind === "file") {
      return element.findings.map(
        (f): FindingNode => ({ kind: "finding", finding: f })
      );
    }
    return [];  // finding nodes are leaves
  }

  // ── Private builders ───────────────────────────────────────────────────────

  private getRootChildren(): FindingsTreeNode[] {
    if (this.state.kind !== "findings") {
      return [];  // empty → treeView.message handles the display
    }

    // Group findings by file path, preserving scan order
    const byFile = new Map<string, Finding[]>();
    for (const f of this.state.findings) {
      const arr = byFile.get(f.filePath) ?? [];
      arr.push(f);
      byFile.set(f.filePath, arr);
    }

    return Array.from(byFile.entries()).map(
      ([filePath, findings]): FileNode => ({ kind: "file", filePath, findings })
    );
  }

  private buildFileItem(node: FileNode): vscode.TreeItem {
    const fileName = path.basename(node.filePath);
    const count    = node.findings.length;

    const item = new vscode.TreeItem(
      fileName,
      vscode.TreeItemCollapsibleState.Expanded
    );
    item.description  = `${count} issue${count !== 1 ? "s" : ""}`;
    item.tooltip      = node.filePath;
    item.iconPath     = new vscode.ThemeIcon("file-code");
    item.contextValue = "vibesecFile";
    return item;
  }

  private buildFindingItem(node: FindingNode): vscode.TreeItem {
    const f    = node.finding;
    // Label = the human-readable message; description = rule ID + line (dimmed)
    // This keeps the two clearly separate in the tree UI.
    const item = new vscode.TreeItem(
      f.message,
      vscode.TreeItemCollapsibleState.None
    );

    item.description  = `${f.ruleId}  ·  Line ${f.startLine + 1}`;
    item.iconPath     = new vscode.ThemeIcon(SEVERITY_ICON[f.severity]);
    item.contextValue = "vibesecFinding";

    // Rich tooltip: bold rule ID, message, then source snippet if available
    const md = new vscode.MarkdownString(undefined, true);
    md.appendMarkdown(`**\`${f.ruleId}\`**\n\n`);
    md.appendMarkdown(`${f.message}\n\n`);
    if (f.snippet.trim() !== "") {
      md.appendCodeblock(f.snippet, "");
    }
    item.tooltip = md;

    // Click → navigate to the finding in the editor
    item.command = {
      command:   "vibesec.goToFinding",
      title:     "Go to Finding",
      arguments: [f],
    };

    return item;
  }
}
