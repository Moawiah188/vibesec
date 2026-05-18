import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { isScannablePath, getScannableExtensions } from "./scannableExtensions";
import { IGNORED_DIR_NAMES } from "./scanProvider";
import type { Finding } from "./types";
import type { FindingsProvider } from "./findingsProvider";
import {
  ExtensionToWebview,
  PanelFinding,
  PanelStateMsg,
  PanelTreeNode,
  ThemeKind,
  WebviewToExtension,
  toPanelFinding,
} from "./panelMessages";
import type { PanelState } from "./findingsProvider";

// PanelController — the WebviewViewProvider that fills the VibeSec activity-bar
// slot. Single source of truth for rendering the React analysis UI inside the
// sidebar.
//
// Lifecycle:
//   const panel = new PanelController(context, findingsProvider, hooks);
//   vscode.window.registerWebviewViewProvider(PanelController.viewId, panel);
//   panel.pushState(panelState);             // forward extension state
//   panel.pushProgress(percent, fileName);   // forward scan progress
//   panel.reveal();                          // bring the sidebar view into focus
//
// The view is provided by VS Code itself — when the user clicks the activity
// bar icon (or runs the focus command) VS Code calls `resolveWebviewView`, at
// which point we build the HTML and start listening for messages.

export class PanelController
  implements vscode.WebviewViewProvider, vscode.Disposable
{
  /** Matches the `id` in package.json `contributes.views.vibesec[]`. */
  static readonly viewId = "vibesec.analysisPanel";

  private view: vscode.WebviewView | undefined;
  private readonly subs: vscode.Disposable[] = [];
  private latestState: PanelState = { kind: "empty" };
  private latestProgress: { percent: number; currentFile: string } | null = null;
  private readonly extraFiles = new Set<string>();
  private readonly extraFolders = new Set<string>();
  private panelWorkspaceFolder: string | undefined;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly findingsProvider: FindingsProvider,
    private readonly hooks: PanelControllerHooks,
  ) {
    // Re-push theme to the live webview when VS Code's color theme changes.
    this.subs.push(
      vscode.window.onDidChangeActiveColorTheme(() => {
        this.postMessage({ type: "themeChanged", theme: this.detectTheme() });
      }),
    );
  }

  // ── WebviewViewProvider contract ──────────────────────────────────────────

  resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken,
  ): void {
    this.view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [
        vscode.Uri.joinPath(this.context.extensionUri, "media"),
      ],
    };

    webviewView.webview.html = this.buildHtml(webviewView.webview);

    webviewView.webview.onDidReceiveMessage(
      (msg: WebviewToExtension) => this.handleMessage(msg),
      undefined,
      this.subs,
    );

    webviewView.onDidDispose(
      () => {
        this.view = undefined;
      },
      undefined,
      this.subs,
    );
  }

  // ── Public API ────────────────────────────────────────────────────────────

  /** Bring the sidebar view into focus (e.g. when a scan starts). */
  reveal(): void {
    void vscode.commands.executeCommand(`${PanelController.viewId}.focus`);
  }

  /** Forward the latest extension state to the webview. Stored even when the
   *  view isn't resolved yet so the next `ready` replay shows the right state. */
  pushState(state: PanelState): void {
    this.latestState = state;
    if (state.kind !== "error") {
      this.latestProgress = null;
    }
    this.postMessage({
      type: "stateUpdated",
      state: toStateMsg(state, this.workspaceRoot()),
    });
  }

  /** Forward incremental scan progress. */
  pushProgress(percent: number, currentFile: string): void {
    this.latestProgress = { percent, currentFile };
    this.postMessage({ type: "progressUpdated", percent, currentFile });
    // Also flip state to "loading" so the panel shows skeletons even if the
    // caller forgot to call pushState first.
    if (this.latestState.kind !== "findings") {
      this.postMessage({
        type: "stateUpdated",
        state: { kind: "loading", percent, currentFile },
      });
    }
  }

  /** Notify the webview a prompt was successfully copied. */
  notifyPromptCopied(scope: "vuln" | "file" | "all", key: string): void {
    this.postMessage({ type: "promptCopied", scope, key });
  }

  dispose(): void {
    while (this.subs.length > 0) { this.subs.pop()?.dispose(); }
    this.view = undefined;
  }

  // ── Message handling ──────────────────────────────────────────────────────

  private async handleMessage(msg: WebviewToExtension): Promise<void> {
    switch (msg.type) {
      case "ready": {
        // Replay current state and theme on connect/reconnect.
        const version =
          (this.context.extension.packageJSON?.version as string | undefined) ?? "unknown";
        this.postMessage({
          type: "init",
          theme: this.detectTheme(),
          accent: "green",
          density: "comfortable",
          version,
        });
        this.postMessage({
          type: "stateUpdated",
          state: toStateMsg(this.latestState, this.workspaceRoot()),
        });
        if (this.latestProgress) {
          this.postMessage({
            type: "progressUpdated",
            percent: this.latestProgress.percent,
            currentFile: this.latestProgress.currentFile,
          });
        }
        break;
      }
      case "getWorkspaceTree": {
        const { tree, defaultSelected } = await this.buildWorkspaceTree();
        this.postMessage({ type: "workspaceTree", tree, defaultSelected });
        break;
      }
      case "openFolder": {
        await this.pickAndOpenFolder();
        break;
      }
      case "newFile": {
        await this.createNewWorkspaceFile();
        break;
      }
      case "openControlCenter": {
        await vscode.commands.executeCommand("vibesec.openControlCenter");
        break;
      }
      case "scanRequested": {
        const uris = msg.filePaths.map((p) => vscode.Uri.file(p));
        await this.hooks.runScanOnTargets(uris);
        break;
      }
      case "scanCancel": {
        // Cancellation is handled inside withProgress on the extension side.
        break;
      }
      case "goToFinding": {
        const f = this.findFindingById(msg.findingId);
        if (f) { await this.hooks.goToFinding(f); }
        break;
      }
      case "goToLocation": {
        // Used by the Data flow block in VulnCard to jump to a taint source,
        // intermediate variable, or sink. `line` is 1-based from the panel.
        try {
          const uri = vscode.Uri.file(msg.absPath);
          const doc = await vscode.workspace.openTextDocument(uri);
          const targetLine = Math.max(0, msg.line - 1);
          const pos = new vscode.Position(targetLine, 0);
          await vscode.window.showTextDocument(doc, {
            selection:     new vscode.Range(pos, pos),
            preserveFocus: false,
          });
        } catch (err: unknown) {
          const detail = err instanceof Error ? err.message : String(err);
          this.postMessage({
            type: "toast",
            tone: "error",
            message: `VibeSec: Could not open ${msg.absPath}: ${detail}`,
          });
        }
        break;
      }
      case "copyPromptForVuln": {
        const f = this.findFindingById(msg.findingId);
        if (f) {
          await this.hooks.copyPromptForFinding(f);
          this.notifyPromptCopied("vuln", msg.findingId);
        }
        break;
      }
      case "copyPromptForFile": {
        const abs = this.absoluteFromPanelPath(msg.filePath);
        if (abs) {
          await this.hooks.copyPromptForFilePath(abs);
          this.notifyPromptCopied("file", msg.filePath);
        }
        break;
      }
      case "copyPromptForAll": {
        await this.hooks.copyPromptForAll();
        this.notifyPromptCopied("all", "all");
        break;
      }
      case "generatePrompts": {
        await this.hooks.generatePrompts();
        break;
      }
    }
  }


  private async createNewWorkspaceFile(): Promise<void> {
    const root = this.workspaceRoot();
    if (!root) {
      await vscode.commands.executeCommand("workbench.action.files.newUntitledFile");
      return;
    }
    const rel = await vscode.window.showInputBox({
      title: "VibeSec — New file",
      prompt: "Enter a workspace-relative file path, for example src/example.js",
      placeHolder: "src/example.js",
      ignoreFocusOut: true,
      validateInput: (value) => {
        const trimmed = value.trim();
        if (!trimmed) { return "File path is required."; }
        if (path.isAbsolute(trimmed)) { return "Use a workspace-relative path."; }
        if (trimmed.split(/[\\/]+/).includes("..")) { return "Path cannot contain '..'."; }
        return null;
      },
    });
    if (!rel) { return; }
    const abs = path.join(root, rel.trim());
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    if (!fs.existsSync(abs)) { fs.writeFileSync(abs, "", "utf-8"); }
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(abs));
    await vscode.window.showTextDocument(doc);
    const { tree, defaultSelected } = await this.buildWorkspaceTree();
    this.postMessage({ type: "workspaceTree", tree, defaultSelected });
  }

  private async pickAndOpenFolder(): Promise<void> {
    const picks = await vscode.window.showOpenDialog({
      title: "VibeSec — Open folder inside Analysis panel",
      canSelectFiles: false,
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: "Open in VibeSec",
    });
    const picked = picks?.[0];
    if (!picked) { return; }

    try {
      // Treat the selected folder as the active VibeSec workspace inside the tool.
      // This does not open a new VS Code window and does not add a normal VS Code workspace folder.
      this.panelWorkspaceFolder = picked.fsPath;
      this.extraFolders.clear();
      this.extraFiles.clear();
      const { tree, defaultSelected } = await this.buildWorkspaceTree();
      this.postMessage({ type: "workspaceTree", tree, defaultSelected });
      this.postMessage({ type: "toast", tone: "info", message: `VibeSec workspace opened: ${path.basename(picked.fsPath)}` });
    } catch (err: unknown) {
      const detail = err instanceof Error ? err.message : String(err);
      this.postMessage({
        type: "toast",
        tone: "error",
        message: `VibeSec: Could not open folder: ${detail}`,
      });
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private postMessage(msg: ExtensionToWebview): void {
    this.view?.webview.postMessage(msg);
  }

  private detectTheme(): ThemeKind {
    const k = vscode.window.activeColorTheme.kind;
    if (k === vscode.ColorThemeKind.HighContrastLight) { return "hc-light"; }
    if (k === vscode.ColorThemeKind.HighContrast)      { return "hc-dark"; }
    if (k === vscode.ColorThemeKind.Light)             { return "light"; }
    return "dark";
  }

  private workspaceRoot(): string | undefined {
    return this.panelWorkspaceFolder ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  }

  private findFindingById(id: string): Finding | undefined {
    return this.findingsProvider
      .getAllFindings()
      .find((f) => `${f.filePath}:${f.startLine}:${f.startCol}:${f.ruleId}` === id);
  }

  private absoluteFromPanelPath(panelPath: string): string | undefined {
    const all = this.findingsProvider.getAllFindings();
    const root = this.workspaceRoot();
    for (const f of all) {
      const rel = root && f.filePath.startsWith(root)
        ? f.filePath.slice(root.length + 1).replace(/\\/g, "/")
        : f.filePath.replace(/\\/g, "/");
      if (rel === panelPath || f.filePath === panelPath) {
        return f.filePath;
      }
    }
    return undefined;
  }

  // ── Workspace tree builder ────────────────────────────────────────────────

  private async buildWorkspaceTree(): Promise<{
    tree: PanelTreeNode[];
    defaultSelected: string[];
  }> {
    const folders = vscode.workspace.workspaceFolders ?? [];
    const exts = getScannableExtensions();

    const buildFolder = (
      absDir: string,
      name: string,
      depth: number,
    ): PanelTreeNode | null => {
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(absDir, { withFileTypes: true });
      } catch {
        return null;
      }

      const folderEntries = entries
        .filter((e) => e.isDirectory() && !e.isSymbolicLink())
        .filter((e) => !IGNORED_DIR_NAMES.has(e.name) && !e.name.startsWith("."))
        .sort((a, b) => a.name.localeCompare(b.name));

      const fileEntries = entries
        .filter((e) => e.isFile() && !e.isSymbolicLink())
        .sort((a, b) => a.name.localeCompare(b.name));

      const children: PanelTreeNode[] = [];

      for (const e of folderEntries) {
        const child = buildFolder(path.join(absDir, e.name), e.name, depth + 1);
        if (child && (child.children?.length ?? 0) > 0) {
          children.push(child);
        }
      }
      for (const e of fileEntries) {
        const fullPath = path.join(absDir, e.name);
        const scannable = isScannablePath(fullPath, exts);
        if (!scannable) { continue; }
        const ext = e.name.includes(".")
          ? e.name.slice(e.name.lastIndexOf(".") + 1).toLowerCase()
          : undefined;
        children.push({
          id: fullPath,
          type: "file",
          name: e.name,
          ext,
          depth: depth + 1,
          open: false,
          scannable: true,
        });
      }

      if (children.length === 0) { return null; }

      return {
        id: absDir,
        type: "folder",
        name,
        depth,
        // Auto-expand top two levels for an inviting first impression.
        open: depth < 2,
        children,
      };
    };

    const tree: PanelTreeNode[] = [];

    if (this.panelWorkspaceFolder) {
      const rootNode = buildFolder(
        this.panelWorkspaceFolder,
        path.basename(this.panelWorkspaceFolder) || this.panelWorkspaceFolder,
        0,
      );
      if (rootNode?.children) { tree.push(...rootNode.children); }
      return { tree, defaultSelected: [] };
    }

    if (folders.length === 1) {
      const rootNode = buildFolder(folders[0].uri.fsPath, folders[0].name, 0);
      if (rootNode?.children) { tree.push(...rootNode.children); }
    } else {
      for (const f of folders) {
        const node = buildFolder(f.uri.fsPath, f.name, 0);
        if (node) { tree.push(node); }
      }
    }

    for (const folderPath of Array.from(this.extraFolders).sort()) {
      const alreadyInWorkspace = folders.some((f) => folderPath === f.uri.fsPath || folderPath.startsWith(f.uri.fsPath + path.sep));
      if (alreadyInWorkspace) { continue; }
      const node = buildFolder(folderPath, path.basename(folderPath) || folderPath, 0);
      if (node) { tree.push(node); }
    }

    for (const filePath of Array.from(this.extraFiles).sort()) {
      const alreadyInWorkspace = folders.some((f) => filePath.startsWith(f.uri.fsPath + path.sep));
      if (alreadyInWorkspace) { continue; }
      if (!isScannablePath(filePath, exts)) { continue; }
      const name = path.basename(filePath);
      const ext = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1).toLowerCase() : undefined;
      tree.push({
        id: filePath,
        type: "file",
        name,
        ext,
        depth: 0,
        open: false,
        scannable: true,
      });
    }

    return { tree, defaultSelected: [] };
  }

  // ── HTML template ─────────────────────────────────────────────────────────

  private buildHtml(webview: vscode.Webview): string {
    const nonce = makeNonce();
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this.context.extensionUri, "media", "design", "main.js"),
    );
    const stylesUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this.context.extensionUri, "media", "design", "styles.css"),
    );
    const logoUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this.context.extensionUri, "media", "vibesec-icon.svg"),
    );

    const csp = [
      "default-src 'none'",
      `img-src ${webview.cspSource} data:`,
      `script-src 'nonce-${nonce}'`,
      `style-src ${webview.cspSource} 'unsafe-inline'`,
      `font-src ${webview.cspSource}`,
    ].join("; ");

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="Content-Security-Policy" content="${csp}" />
  <title>VibeSec</title>
  <link rel="stylesheet" href="${stylesUri}" />
  <style>
    html, body { margin: 0; padding: 0; height: 100%; overflow: hidden; }
    #root { width: 100%; height: 100%; display: flex; }
  </style>
</head>
<body>
  <div id="root"></div>
  <script nonce="${nonce}">window.__VIBESEC_LOGO_URI__ = ${JSON.stringify(logoUri.toString())};</script>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
  }
}

// ── Hooks the controller calls back into ──────────────────────────────────

export interface PanelControllerHooks {
  runScanOnTargets(targets: vscode.Uri[]): Promise<void>;
  goToFinding(f: Finding): Promise<void>;
  copyPromptForFinding(f: Finding): Promise<void>;
  copyPromptForFilePath(filePath: string): Promise<void>;
  copyPromptForAll(): Promise<void>;
  generatePrompts(): Promise<void>;
}

// ── Adapters ──────────────────────────────────────────────────────────────

function toStateMsg(state: PanelState, workspaceRoot: string | undefined): PanelStateMsg {
  switch (state.kind) {
    case "empty":      return { kind: "empty" };
    case "noFindings": return { kind: "noFindings" };
    case "error":      return { kind: "error", message: state.message };
    case "findings": {
      const findings: PanelFinding[] = state.findings.map((f) =>
        toPanelFinding(f, workspaceRoot),
      );
      return { kind: "findings", findings };
    }
  }
}

function makeNonce(): string {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 32; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}
