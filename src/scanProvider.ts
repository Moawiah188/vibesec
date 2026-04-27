import * as path from "path";
import * as vscode from "vscode";
import { isScannableUri as isScannableUriShared } from "./scannableExtensions";

// ── Scan panel tree ──────────────────────────────────────────────────────────
//
// The Scan panel shows the workspace as a file tree. Users select which files
// to scan using the same selection UX as the native File Explorer:
//
//   • Click a file          → select it (full row highlights blue natively)
//   • Ctrl / Cmd + click    → add to / remove from selection
//   • Shift + click         → select range
//   • Click empty space     → clear selection
//
// No custom checkboxes. The TreeView's native `canSelectMany: true` + theme
// selection colors (`list.activeSelectionBackground`) give us the smooth
// full-row blue highlight the design calls for, and it respects every
// VS Code theme for free.

// ── Ignored directory names ──────────────────────────────────────────────────
//
// Skipped entirely when walking the workspace. Matches the common noise
// folders across Node / Python / build tooling so users never see them.
// Exported so the multi-target scan walker (extension.ts) can apply the same
// filter when descending into a folder selection or whole-workspace scan.
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

// ── Tree node discriminated union ────────────────────────────────────────────

interface FolderNode {
  kind: "folder";
  uri:  vscode.Uri;
  name: string;
}

interface FileNode {
  kind: "file";
  uri:  vscode.Uri;
  name: string;
}

export type ScanNode = FolderNode | FileNode;

export function isScanFileNode(node: ScanNode): node is FileNode {
  return node.kind === "file";
}

export function isScanFolderNode(node: ScanNode): node is FolderNode {
  return node.kind === "folder";
}

// Re-export so existing call sites continue to compile.
export const isScannableUri = isScannableUriShared;

// ── Provider ─────────────────────────────────────────────────────────────────

export class ScanProvider implements vscode.TreeDataProvider<ScanNode> {
  private _onDidChangeTreeData =
    new vscode.EventEmitter<ScanNode | undefined | void>();
  readonly onDidChangeTreeData: vscode.Event<ScanNode | undefined | void> =
    this._onDidChangeTreeData.event;

  /** Rebuild the visible tree (e.g. after a file is created/deleted). */
  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  // ── TreeDataProvider implementation ────────────────────────────────────────

  getTreeItem(node: ScanNode): vscode.TreeItem {
    const item = new vscode.TreeItem(
      node.name,
      node.kind === "folder"
        ? vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None,
    );

    // resourceUri gives us theme-aware file/folder icons that match whatever
    // File Icon Theme the user has installed (Material, Seti, VS Code default).
    item.resourceUri = node.uri;

    if (node.kind === "folder") {
      item.contextValue = "vibesecScanFolder";
      item.tooltip      = node.uri.fsPath;
      return item;
    }

    // ── File rows ───────────────────────────────────────────────────────────
    const scannable = isScannableUri(node.uri);
    item.contextValue = scannable ? "vibesecScanFile" : "vibesecScanFileIneligible";

    if (scannable) {
      const md = new vscode.MarkdownString(
        `**${node.name}**\n\n` +
        `\`${node.uri.fsPath}\`\n\n` +
        `_Click to select · Ctrl+Click to add · Shift+Click for range_`,
      );
      md.supportThemeIcons = true;
      item.tooltip = md;
    } else {
      item.description = "not scannable";
      item.tooltip     = `VibeSec doesn't scan ${path.extname(node.name) || "this"} files yet.`;
    }

    // Clicking the row opens the file in the editor (preview mode), alongside
    // selecting the row. This mirrors VS Code's File Explorer behavior.
    item.command = {
      command:   "vscode.open",
      title:     "Open File",
      arguments: [node.uri, { preview: true }],
    };

    item.accessibilityInformation = {
      label: scannable
        ? `${node.name}, scannable`
        : `${node.name}, not scannable`,
      role: "treeitem",
    };

    return item;
  }

  async getChildren(element?: ScanNode): Promise<ScanNode[]> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) { return []; }

    // Root level
    if (!element) {
      if (folders.length === 1) {
        // Single-folder workspace — flatten into its contents directly
        return this.listDir(folders[0].uri);
      }
      // Multi-root workspace — show each folder as a top-level node
      return folders.map((f): FolderNode => ({
        kind: "folder",
        uri:  f.uri,
        name: f.name,
      }));
    }

    if (element.kind === "folder") {
      return this.listDir(element.uri);
    }
    return [];  // files are leaves
  }

  // ── Internal helpers ───────────────────────────────────────────────────────

  private async listDir(dirUri: vscode.Uri): Promise<ScanNode[]> {
    let entries: [string, vscode.FileType][];
    try {
      entries = await vscode.workspace.fs.readDirectory(dirUri);
    } catch (err) {
      console.error(`VibeSec: failed to read directory ${dirUri.fsPath}`, err);
      return [];
    }

    const nodes: ScanNode[] = [];
    for (const [name, fileType] of entries) {
      if (IGNORED_DIR_NAMES.has(name)) { continue; }
      if (name.startsWith(".") && fileType === vscode.FileType.Directory) {
        // Skip hidden dot-directories (e.g. .github) for cleanliness.
        // Hidden files (like .env) are still visible.
        continue;
      }
      const childUri = vscode.Uri.joinPath(dirUri, name);
      if (fileType === vscode.FileType.Directory) {
        nodes.push({ kind: "folder", uri: childUri, name });
      } else if (fileType === vscode.FileType.File) {
        nodes.push({ kind: "file", uri: childUri, name });
      }
      // Symlinks etc. are ignored
    }

    // Folders before files, alphabetical within each group
    nodes.sort((a, b) => {
      if (a.kind !== b.kind) { return a.kind === "folder" ? -1 : 1; }
      return a.name.localeCompare(b.name);
    });
    return nodes;
  }
}
