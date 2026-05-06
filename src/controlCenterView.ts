import * as vscode from "vscode";
import {
  CcExtensionToWebview,
  CcWebviewToExtension,
  ControlCenterPage,
  SettingsKey,
  SettingsState,
  SettingsValues,
} from "./controlCenterMessages";
import { logBus } from "./logBus";
import type { LogStore } from "./logStore";
import type { ThemeKind } from "./panelMessages";
import { PanelController } from "./panelView";
import { buildRulesIndex } from "./rulesIndex";
import type { ScanHistoryStore } from "./scanHistoryStore";

// The full list of vibesec.* keys exposed in the Control Center. Must match
// `contributes.configuration` in package.json. TypeScript catches missing keys
// here against SettingsValues; the values themselves are read at runtime from
// VS Code via `cfg.inspect(key).defaultValue`, so package.json stays the
// single source of truth for defaults.
const SETTINGS_KEYS: readonly SettingsKey[] = [
  "semgrepPath",
  "fileExtensions",
  "autoScanOnSave",
  "showInlineDecorations",
  "openPanelOnScan",
  "llmProvider",
  "llmModel",
  "promptMode",
] as const;

// Last-resort fallbacks if VS Code somehow returns no defaultValue for a key
// (it shouldn't — every key declares a default in package.json). Kept narrow
// so the panel never renders an undefined into the UI.
const FALLBACK_DEFAULTS: SettingsValues = {
  semgrepPath:           "",
  fileExtensions:        "",
  autoScanOnSave:        false,
  showInlineDecorations: true,
  openPanelOnScan:       false,
  llmProvider:           "anthropic",
  llmModel:              "",
  promptMode:            "perFile",
};

// ControlCenterController — singleton editor-area WebviewPanel that hosts the
// VibeSec Control Center (Dashboard / Settings / Logs / Rules).
//
// Lifecycle:
//   const cc = new ControlCenterController(context, hooks);
//   cc.show();           // creates the panel on first call, reveals it on subsequent calls
//
// Two entry points trigger `show()`:
//   1. The `vibesec.openControlCenter` command (palette + keybindings).
//   2. The gear button in the existing Analysis panel's view title bar
//      (wired in package.json under `contributes.menus.view/title`).
//
// Mirrors the patterns in `panelView.ts` — CSP-locked HTML with a per-render
// nonce, theme bridge, ready handshake. The bundle is loaded from
// `media/webview/controlCenter.js` + `controlCenter.css`, produced by the
// second esbuild entry in `esbuild.webview.mjs`.

export class ControlCenterController implements vscode.Disposable {
  static readonly viewType = "vibesec.controlCenter";

  private panel: vscode.WebviewPanel | undefined;
  private readonly subs: vscode.Disposable[] = [];
  /** Theme listener stays alive for the lifetime of the controller, even
   *  while the panel is closed, so `show()` always has a fresh value. */
  private readonly globalSubs: vscode.Disposable[] = [];

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly hooks: ControlCenterHooks,
  ) {
    this.globalSubs.push(
      vscode.window.onDidChangeActiveColorTheme(() => {
        this.postMessage({ type: "themeChanged", theme: this.detectTheme() });
      }),
      // External edits to settings.json (or any other surface) must reflect
      // back into the panel — keep the listener alive even when the panel is
      // closed so reopen always shows the latest snapshot.
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration("vibesec")) {
          this.postMessage({
            type: "settingsUpdated",
            settings: this.readSettingsState(),
          });
        }
      }),
      // Stream scan-history mutations and log events live to the panel. These
      // listeners stay armed even when the panel is closed; messages to a
      // disposed webview are no-ops via `postMessage()`'s guard.
      hooks.scanHistory.onDidChange((entries) => {
        this.postMessage({ type: "scanHistoryUpdated", entries });
      }),
      { dispose: logBus.subscribe((event) => {
        this.postMessage({ type: "logAppended", event });
      }) },
      // Watch the workspace `.vibesec.yaml` and the bundled `rules/*.yaml`
      // so the Rules page reflects edits without a manual refresh. Both the
      // raw save events and reloadPolicy command land here via this watcher.
      ...this.installRuleWatchers(),
    );
  }

  /**
   * Build FileSystemWatchers for every YAML source the rules index reads.
   * Returns a disposables array that the caller threads into globalSubs so
   * the watchers are torn down with the controller.
   */
  private installRuleWatchers(): vscode.Disposable[] {
    const subs: vscode.Disposable[] = [];
    const pushRules = (): void => {
      this.postMessage({ type: "rulesUpdated", rules: this.readRulesIndex() });
    };

    // Workspace policy file. Use a workspace-relative pattern so VS Code
    // routes file events through its workspace-fs APIs.
    const workspaceWatcher = vscode.workspace.createFileSystemWatcher("**/.vibesec.yaml");
    subs.push(workspaceWatcher);
    subs.push(workspaceWatcher.onDidCreate(pushRules));
    subs.push(workspaceWatcher.onDidChange(pushRules));
    subs.push(workspaceWatcher.onDidDelete(pushRules));

    // Bundled rules. Watching the extension's own folder relative to the
    // RelativePattern lets VS Code surface user edits during local
    // development of the extension itself; in a packaged install these
    // files are read-only so the watcher just sits idle.
    const bundledDir = vscode.Uri.joinPath(this.context.extensionUri, "rules");
    const bundledWatcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(bundledDir, "*.{yaml,yml}"),
    );
    subs.push(bundledWatcher);
    subs.push(bundledWatcher.onDidCreate(pushRules));
    subs.push(bundledWatcher.onDidChange(pushRules));
    subs.push(bundledWatcher.onDidDelete(pushRules));

    return subs;
  }

  /** Open the Control Center, or reveal it if already open. */
  show(opts?: { initialPage?: ControlCenterPage }): void {
    if (this.panel) {
      this.panel.reveal(this.panel.viewColumn ?? vscode.ViewColumn.Active);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      ControlCenterController.viewType,
      "VibeSec Control Center",
      vscode.ViewColumn.Active,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [
          vscode.Uri.joinPath(this.context.extensionUri, "media"),
        ],
      },
    );

    this.panel = panel;
    panel.iconPath = vscode.Uri.joinPath(
      this.context.extensionUri,
      "media",
      "vibesec-icon.svg",
    );
    panel.webview.html = this.buildHtml(panel.webview);

    this.subs.push(
      panel.webview.onDidReceiveMessage((msg: CcWebviewToExtension) =>
        this.handleMessage(msg, opts?.initialPage ?? "dashboard"),
      ),
    );
    this.subs.push(
      panel.onDidDispose(() => {
        while (this.subs.length > 0) { this.subs.pop()?.dispose(); }
        this.panel = undefined;
      }),
    );
  }

  dispose(): void {
    while (this.subs.length > 0) { this.subs.pop()?.dispose(); }
    while (this.globalSubs.length > 0) { this.globalSubs.pop()?.dispose(); }
    this.panel?.dispose();
    this.panel = undefined;
  }

  // ── Message handling ──────────────────────────────────────────────────────

  private async handleMessage(
    msg: CcWebviewToExtension,
    initialPage: ControlCenterPage,
  ): Promise<void> {
    switch (msg.type) {
      case "ready": {
        // Replay everything the panel needs on connect/reconnect: theme,
        // initial page, current settings, full scan history, the log
        // ring buffer (already seeded from disk on activation), and the
        // freshly-read rules index.
        const version =
          (this.context.extension.packageJSON?.version as string | undefined) ?? "unknown";
        this.postMessage({
          type: "init",
          theme: this.detectTheme(),
          initialPage,
          settings: this.readSettingsState(),
          scanHistory: this.hooks.scanHistory.getAll(),
          logs: logBus.getRing(),
          rules: this.readRulesIndex(),
          version,
        });
        break;
      }
      case "runQuickAction": {
        switch (msg.action) {
          case "scan":
            await vscode.commands.executeCommand("vibesec.scanWorkspace");
            break;
          case "openPanel":
            await vscode.commands.executeCommand(
              `${PanelController.viewId}.focus`,
            );
            break;
          case "openPolicy":
            await vscode.commands.executeCommand("vibesec.openPolicyFile");
            break;
          case "reloadPolicy":
            await vscode.commands.executeCommand("vibesec.reloadPolicy");
            break;
        }
        break;
      }
      case "setSetting": {
        const target = this.writeTarget();
        try {
          await vscode.workspace
            .getConfiguration("vibesec")
            .update(msg.key, msg.value, target);
        } catch (err: unknown) {
          const text = err instanceof Error ? err.message : String(err);
          this.postMessage({
            type: "toast",
            tone: "error",
            message: `Could not save vibesec.${msg.key}: ${text}`,
          });
        }
        // The onDidChangeConfiguration listener will push the refreshed
        // snapshot so we don't need to echo here.
        break;
      }
      case "openSettingsJson": {
        // Workspace settings file when a folder is open, user settings.json
        // otherwise. The user explicitly clicks "Open settings.json" expecting
        // the file backing the controls they just changed.
        const command =
          this.writeTarget() === vscode.ConfigurationTarget.Workspace
            ? "workbench.action.openWorkspaceSettingsFile"
            : "workbench.action.openSettingsJson";
        await vscode.commands.executeCommand(command);
        break;
      }
      case "resetSettingsToDefaults": {
        const proceed = await vscode.window.showWarningMessage(
          "Reset all VibeSec settings to their defaults?",
          {
            modal: true,
            detail:
              "This clears every vibesec.* override at the current scope " +
              "(workspace if a folder is open, otherwise user settings).",
          },
          "Reset",
        );
        if (proceed !== "Reset") { break; }

        const target = this.writeTarget();
        const cfg = vscode.workspace.getConfiguration("vibesec");
        const failures: string[] = [];
        for (const key of SETTINGS_KEYS) {
          try {
            // Passing `undefined` clears the override at the chosen scope; the
            // value then falls back to the package.json default automatically.
            await cfg.update(key, undefined, target);
          } catch (err: unknown) {
            failures.push(`${key} (${err instanceof Error ? err.message : String(err)})`);
          }
        }
        if (failures.length > 0) {
          vscode.window.showWarningMessage(
            `VibeSec: Reset finished with ${failures.length} failure(s): ${failures.join(", ")}`,
          );
        } else {
          this.postMessage({
            type: "toast",
            tone: "info",
            message: "VibeSec settings reset to defaults.",
          });
        }
        break;
      }
      case "clearScanHistory": {
        await this.hooks.scanHistory.clear();
        this.postMessage({
          type: "toast",
          tone: "info",
          message: "Scan history cleared.",
        });
        break;
      }
      case "clearLogs": {
        await this.hooks.logStore.clear();
        this.postMessage({ type: "logsCleared" });
        break;
      }
      case "refreshRules": {
        // Manual re-read; useful after the user edits a rules file in another
        // tab and wants to be sure the Rules page caught up.
        this.postMessage({ type: "rulesUpdated", rules: this.readRulesIndex() });
        break;
      }
      case "openRuleFile": {
        const idx = this.readRulesIndex();
        const file = idx.files.find((f) => f.id === msg.fileId);
        if (!file || !file.absPath) {
          this.postMessage({
            type: "toast",
            tone: "warn",
            message:
              file?.source === "external"
                ? "External rule registries aren't connected yet — coming in a later sprint."
                : "VibeSec couldn't find that rule file on disk.",
          });
          break;
        }
        try {
          const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(file.absPath));
          await vscode.window.showTextDocument(doc);
        } catch (err: unknown) {
          this.postMessage({
            type: "toast",
            tone: "error",
            message: `Could not open ${file.path}: ${err instanceof Error ? err.message : String(err)}`,
          });
        }
        break;
      }
    }
  }

  // ── Settings helpers ──────────────────────────────────────────────────────

  /**
   * Snapshot of every vibesec.* setting plus the package.json defaults. Both
   * effective values and defaults are sourced from VS Code's configuration
   * API so package.json stays the single source of truth — there is nothing
   * to keep in sync here when a setting's default changes.
   */
  private readSettingsState(): SettingsState {
    const cfg = vscode.workspace.getConfiguration("vibesec");
    const values = {} as SettingsValues;
    const defaults = {} as SettingsValues;
    for (const key of SETTINGS_KEYS) {
      const inspected = cfg.inspect(key);
      const dflt = (inspected?.defaultValue as SettingsValues[typeof key] | undefined)
        ?? FALLBACK_DEFAULTS[key];
      const value = (cfg.get(key) as SettingsValues[typeof key] | undefined) ?? dflt;
      // Cast through unknown — the runtime invariant is enforced by package.json
      // (which declares both the key and its type); a settings.json with the
      // wrong type is coerced or rejected by VS Code before we read it.
      (values   as unknown as Record<string, unknown>)[key] = value;
      (defaults as unknown as Record<string, unknown>)[key] = dflt;
    }
    return {
      values,
      defaults,
      scope: this.writeTarget() === vscode.ConfigurationTarget.Workspace
        ? "workspace"
        : "global",
    };
  }

  private writeTarget(): vscode.ConfigurationTarget {
    return (vscode.workspace.workspaceFolders?.length ?? 0) > 0
      ? vscode.ConfigurationTarget.Workspace
      : vscode.ConfigurationTarget.Global;
  }

  private readRulesIndex(): ReturnType<typeof buildRulesIndex> {
    return buildRulesIndex(
      this.context.extensionUri.fsPath,
      vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
    );
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private postMessage(msg: CcExtensionToWebview): void {
    this.panel?.webview.postMessage(msg);
  }

  private detectTheme(): ThemeKind {
    const k = vscode.window.activeColorTheme.kind;
    if (k === vscode.ColorThemeKind.HighContrastLight) { return "hc-light"; }
    if (k === vscode.ColorThemeKind.HighContrast)      { return "hc-dark"; }
    if (k === vscode.ColorThemeKind.Light)             { return "light"; }
    return "dark";
  }

  // ── HTML template ─────────────────────────────────────────────────────────

  private buildHtml(webview: vscode.Webview): string {
    const nonce = makeNonce();
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(
        this.context.extensionUri,
        "media",
        "webview",
        "controlCenter.js",
      ),
    );
    const stylesUri = webview.asWebviewUri(
      vscode.Uri.joinPath(
        this.context.extensionUri,
        "media",
        "webview",
        "controlCenter.css",
      ),
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
  <title>VibeSec Control Center</title>
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

export interface ControlCenterHooks {
  /** Workspace-state-backed history of scan completions. */
  scanHistory: ScanHistoryStore;
  /** Disk-persistent log store, used to clear logs on demand. */
  logStore:    LogStore;
}

function makeNonce(): string {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 32; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}
