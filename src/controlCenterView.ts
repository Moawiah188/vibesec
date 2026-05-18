import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import * as yaml from "js-yaml";
import {
  CcExtensionToWebview,
  CcWebviewToExtension,
  ControlCenterPage,
  SettingsKey,
  SettingsState,
  SettingsValues,
} from "./controlCenterMessages";
import { logBus } from "./logBus";
import { LlmClientError, pingProvider } from "./llmClient";
import {
  isBuiltInDefaultModel,
  providerFromKeyHint,
  PROVIDER_DEFAULT_MODEL,
  resolveProviderModel,
  validateProviderSelection,
} from "./llmModels";
import type { LlmProvider } from "./types";
import { clearApiKey, getApiKey, PROVIDER_LABEL, setApiKey } from "./secrets";
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
  "llmCustomProviderName",
  "llmCustomBaseUrl",
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
  llmCustomProviderName: "",
  llmCustomBaseUrl:      "",
  promptMode:            "perFile",
};


const CUSTOM_RULE_FILE_TEMPLATE = `# VibeSec custom policy
# Purpose: project-specific rules created by your team.
# Activate this file from Control Center → Rules.

activePolicyKind: custom
presets: []

severity:
  minSeverity: warning

files:
  exclude:
    - "**/node_modules/**"
    - "**/dist/**"
    - "**/*.test.*"

# Add normal Semgrep rules or taint rules under rules:.
# Keep this list empty until you add your own rules.
rules: []

# Example normal rule structure:
# rules:
#   - id: custom.no-console-log
#     message: Avoid console.log in production code.
#     severity: INFO
#     languages: [javascript, typescript]
#     pattern: console.log(...)
#     metadata:
#       category: code-quality
#       confidence: LOW
`;

const NORMAL_POLICY_TEMPLATE = `# VibeSec normal scan policy
# Purpose: standard pattern-based scanning.
# Activate this file from Control Center → Rules.
# This file starts empty. Turn ON rules/default.yaml separately if you want the bundled default rules.

activePolicyKind: normal
presets: []

severity:
  minSeverity: warning

files:
  exclude:
    - "**/node_modules/**"
    - "**/dist/**"
    - "**/build/**"
    - "**/*.test.*"

# Rules turned OFF from Control Center can be tracked here.
disabledRules: []

# Optional custom normal Semgrep rules.
# Keep rules empty unless you want to add project-specific checks.
rules: []

# Example normal rule structure:
# rules:
#   - id: custom.javascript.eval
#     message: Avoid eval() because it can execute untrusted code.
#     severity: WARNING
#     languages: [javascript, typescript]
#     pattern: eval(...)
#     metadata:
#       category: security
#       cwe: "CWE-95"
#       confidence: MEDIUM
`;

const TAINT_POLICY_TEMPLATE = `# VibeSec taint analysis policy
# Purpose: source → flow → sink tracking.
# Activate this file from Control Center → Rules.
# This file starts empty. Turn ON rules/taint.yaml separately if you want the bundled taint rules.

activePolicyKind: taint
presets: []

severity:
  minSeverity: warning

files:
  exclude:
    - "**/node_modules/**"
    - "**/dist/**"
    - "**/build/**"
    - "**/*.test.*"

# Rules turned OFF from Control Center can be tracked here.
disabledRules: []

# Optional custom taint rules.
# Keep rules empty unless you want to add project-specific source/sink checks.
rules: []

# Example taint rule structure:
# rules:
#   - id: custom.node.sql-injection
#     mode: taint
#     message: User input reaches a SQL execution sink.
#     severity: ERROR
#     languages: [javascript, typescript]
#     pattern-sources:
#       - pattern: $REQ.query.$FIELD
#       - pattern: $REQ.body.$FIELD
#       - pattern: $REQ.params.$FIELD
#     pattern-sinks:
#       - patterns:
#           - pattern: $DB.query($QUERY, ...)
#           - focus-metavariable: $QUERY
#     pattern-sanitizers:
#       - pattern: Number(...)
#       - pattern: parseInt(...)
#     metadata:
#       category: security
#       cwe: "CWE-89"
#       owasp: "A03:2021 Injection"
#       confidence: MEDIUM
`;

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
    const workspaceWatcher = vscode.workspace.createFileSystemWatcher("**/.vibesec*.yaml");
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

    const toolPolicyDir = vscode.Uri.joinPath(this.context.extensionUri, "rules", "policies");
    const toolPolicyWatcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(toolPolicyDir, "*.{yaml,yml}"),
    );
    subs.push(toolPolicyWatcher);
    subs.push(toolPolicyWatcher.onDidCreate(pushRules));
    subs.push(toolPolicyWatcher.onDidChange(pushRules));
    subs.push(toolPolicyWatcher.onDidDelete(pushRules));

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
          case "openFolder":
            await this.pickAndOpenFolder();
            break;
          case "openFile":
            await this.pickAndOpenFile();
            break;
          case "newFile":
            await this.createNewWorkspaceFile();
            break;
          case "newNormalPolicy":
            await this.createPolicyFile("normal");
            break;
          case "newTaintPolicy":
            await this.createPolicyFile("taint");
            break;
        }
        break;
      }
      case "setSetting": {
        const target = this.writeTarget();
        try {
          const cfg = vscode.workspace.getConfiguration("vibesec");
          await cfg.update(msg.key, msg.value, target);
          if (msg.key === "llmProvider") {
            const provider = msg.value as LlmProvider;
            await cfg.update("llmModel", PROVIDER_DEFAULT_MODEL[provider], target);
          }
          this.postMessage({ type: "settingsUpdated", settings: this.readSettingsState() });
        } catch (err: unknown) {
          const text = err instanceof Error ? err.message : String(err);
          this.postMessage({
            type: "toast",
            tone: "error",
            message: `Could not save vibesec.${msg.key}: ${text}`,
          });
        }
        break;
      }
      case "saveApiKey": {
        const key = msg.key.trim();
        if (!key) {
          this.postMessage({ type: "toast", tone: "warn", message: "API key is empty. Nothing was saved." });
          break;
        }
        try {
          const provider = providerFromKeyHint(msg.provider, key);
          await setApiKey(this.context, provider, key);

          // Make the key usable immediately: saving a provider key also selects
          // that provider. If the key looks like a Groq gsk_ key, VibeSec selects
          // Groq and fills its default model so the user only has to paste the key.
          const target = this.writeTarget();
          const cfg = vscode.workspace.getConfiguration("vibesec");
          await cfg.update("llmProvider", provider, target);
          const currentModel = (cfg.get<string>("llmModel", "") || "").trim();
          if (provider === "custom") {
            // Do not accidentally send a built-in provider's default model to a
            // custom endpoint. The user can replace this with any exact model id.
            if (!currentModel || isBuiltInDefaultModel(currentModel)) {
              await cfg.update("llmModel", PROVIDER_DEFAULT_MODEL.custom, target);
            }
          } else {
            const resolved = resolveProviderModel(provider, currentModel);
            if (resolved !== currentModel || !currentModel) {
              await cfg.update("llmModel", PROVIDER_DEFAULT_MODEL[provider], target);
            }
          }

          this.postMessage({ type: "settingsUpdated", settings: this.readSettingsState() });
          this.postMessage({
            type: "toast",
            tone: "info",
            message: provider === "custom"
              ? `${PROVIDER_LABEL[provider]} API key saved and selected. Add the custom endpoint and exact model name, then click Test.`
              : `${PROVIDER_LABEL[provider]} API key saved and selected as the active provider.`,
          });
        } catch (err: unknown) {
          this.postMessage({
            type: "toast",
            tone: "error",
            message: `Could not save API key: ${err instanceof Error ? err.message : String(err)}`,
          });
        }
        break;
      }
      case "clearApiKey": {
        const ok = await vscode.window.showWarningMessage(
          `Clear the saved ${PROVIDER_LABEL[msg.provider]} API key?`,
          { modal: true, detail: "The key will be removed from VS Code SecretStorage." },
          "Clear",
        );
        if (ok !== "Clear") { break; }
        await clearApiKey(this.context, msg.provider);
        this.postMessage({
          type: "toast",
          tone: "info",
          message: `${PROVIDER_LABEL[msg.provider]} API key cleared.`,
        });
        break;
      }
      case "testApiKey": {
        const key = await getApiKey(this.context, msg.provider);
        if (!key) {
          this.postMessage({
            type: "toast",
            tone: "warn",
            message: `No ${PROVIDER_LABEL[msg.provider]} API key is saved yet. Paste one and click Save key first.`,
          });
          break;
        }
        const cfg = vscode.workspace.getConfiguration("vibesec");
        // Always read the model field for testing. resolveProviderModel() will
        // fall back to provider defaults for built-in providers when the typed
        // model belongs to another provider, while custom providers keep the
        // exact model name the user wrote.
        const activeProvider = cfg.get<LlmProvider>("llmProvider", "anthropic");
        const configuredModel = msg.provider === activeProvider
          ? cfg.get<string>("llmModel", "")
          : "";
        const model = resolveProviderModel(msg.provider, configuredModel);
        const baseUrl = msg.provider === "custom" ? cfg.get<string>("llmCustomBaseUrl", "") : undefined;
        const selectionError = validateProviderSelection(msg.provider, model, baseUrl);
        if (selectionError) {
          this.postMessage({
            type: "toast",
            tone: "warn",
            message: selectionError,
          });
          break;
        }
        this.postMessage({
          type: "toast",
          tone: "info",
          message: `Testing ${PROVIDER_LABEL[msg.provider]} API key with ${model}…`,
        });
        try {
          await pingProvider(msg.provider, key, model, baseUrl);
          this.postMessage({
            type: "toast",
            tone: "info",
            message: `${PROVIDER_LABEL[msg.provider]} API key works.`,
          });
        } catch (err: unknown) {
          this.postMessage({
            type: "toast",
            tone: err instanceof LlmClientError && err.statusCode === 429 ? "warn" : "error",
            message: err instanceof Error ? err.message : String(err),
          });
        }
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
      case "createCustomRuleFile": {
        await this.createPolicyFile("custom");
        break;
      }
      case "createPolicyFile": {
        await this.createPolicyFile(msg.kind);
        break;
      }
      case "deletePolicyFile": {
        await this.deletePolicyFile(msg.fileId);
        break;
      }
      case "setRuleFileEnabled": {
        await this.setRuleFileEnabled(msg.fileId, msg.enabled);
        break;
      }
      case "setRuleEnabled": {
        await this.setRuleEnabled(msg.ruleId, msg.enabled);
        break;
      }
      case "importRuleFileFromUrl": {
        await this.importRuleFileFromUrl();
        break;
      }
    }
  }


  // ── Policy/rule mutation helpers ───────────────────────────────────────────

  private workspaceRoot(): string | undefined {
    return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  }

  private policyPath(): string | undefined {
    const root = this.workspaceRoot();
    return root ? path.join(root, ".vibesec.yaml") : undefined;
  }

  private toolPoliciesDir(): string {
    return path.join(this.context.extensionUri.fsPath, "rules", "policies");
  }

  private ensureToolPoliciesDir(): string {
    const dir = this.toolPoliciesDir();
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  }

  private toolPolicyRelPath(fileName: string): string {
    return path.posix.join("rules", "policies", fileName.replace(/\\/g, "/"));
  }

  private resolvePolicyFileRelPath(relPath: string, workspaceRoot?: string): string {
    const normalized = relPath.replace(/\\/g, "/");
    if (path.isAbsolute(normalized)) { return normalized; }
    if (normalized.startsWith("rules/policies/")) {
      return path.join(this.context.extensionUri.fsPath, ...normalized.split("/"));
    }
    return workspaceRoot ? path.join(workspaceRoot, normalized) : path.join(this.context.extensionUri.fsPath, normalized);
  }

  private readPolicyDocument(): Record<string, unknown> {
    const policyPath = this.policyPath();
    if (!policyPath || !fs.existsSync(policyPath)) {
      return {
        activePolicyFiles: ["rules/default.yaml"],
        presets: ["vibesec:default"],
        severity: { minSeverity: "warning" },
        disabledRules: [],
      };
    }
    try {
      const raw = yaml.load(fs.readFileSync(policyPath, "utf-8"));
      if (raw && typeof raw === "object" && !Array.isArray(raw)) {
        return raw as Record<string, unknown>;
      }
    } catch {
      // Fall through to a safe replacement document. The original file can be
      // opened via Open YAML if the user wants to repair it manually.
    }
    return {
      activePolicyFiles: ["rules/default.yaml"],
      presets: ["vibesec:default"],
      severity: { minSeverity: "warning" },
      disabledRules: [],
    };
  }

  private async writePolicyDocument(doc: Record<string, unknown>): Promise<void> {
    const policyPath = this.policyPath();
    if (!policyPath) {
      throw new Error("No workspace folder is open.");
    }
    fs.writeFileSync(
      policyPath,
      "# .vibesec.yaml — edited by VibeSec Control Center\n" + yaml.dump(doc, { lineWidth: 100 }),
      "utf-8",
    );
  }

  private readStringArray(doc: Record<string, unknown>, key: string): string[] {
    const raw = doc[key];
    return Array.isArray(raw) ? raw.filter((v): v is string => typeof v === "string") : [];
  }

  private setStringArrayValue(
    doc: Record<string, unknown>,
    key: string,
    value: string,
    enabled: boolean,
  ): void {
    const values = this.readStringArray(doc, key);
    const next = enabled
      ? Array.from(new Set([...values, value]))
      : values.filter((v) => v !== value);
    doc[key] = next;
  }

  private presetFromBundledFileId(fileId: string): string | null {
    const prefix = "bundled/";
    if (!fileId.startsWith(prefix)) { return null; }
    const filename = fileId.slice(prefix.length);
    const stem = filename.replace(/\.ya?ml$/i, "");
    return `vibesec:${stem}`;
  }

  private relPathFromFileId(fileId: string): string | null {
    const preset = this.presetFromBundledFileId(fileId);
    if (preset === "vibesec:default") { return "rules/default.yaml"; }
    if (preset === "vibesec:taint") { return "rules/taint.yaml"; }
    if (fileId.startsWith("custom/")) { return fileId.slice("custom/".length).replace(/\\/g, "/"); }
    return null;
  }

  private externalRelPathFromFileId(fileId: string): string | null {
    const prefix = "external/";
    if (!fileId.startsWith(prefix) || fileId === "external/placeholder") { return null; }
    return fileId.slice(prefix.length);
  }

  private policyKindForRelPath(relPath: string): "normal" | "taint" {
    const normalized = relPath.replace(/\\/g, "/");
    if (normalized === "rules/taint.yaml" || /(^|\/)taint[-_]/i.test(normalized)) { return "taint"; }
    if (normalized === "rules/default.yaml" || /(^|\/)normal[-_]/i.test(normalized)) { return "normal"; }

    const abs = this.resolvePolicyFileRelPath(normalized, this.workspaceRoot());
    try {
      const raw = yaml.load(fs.readFileSync(abs, "utf-8"));
      if (raw && typeof raw === "object" && !Array.isArray(raw)) {
        const obj = raw as Record<string, unknown>;
        if (obj.activePolicyKind === "taint") { return "taint"; }
        if (obj.activePolicyKind === "default" || obj.activePolicyKind === "normal") { return "normal"; }
        const presets = Array.isArray(obj.presets) ? obj.presets.filter((v): v is string => typeof v === "string") : [];
        if (presets.includes("vibesec:taint") && !presets.includes("vibesec:default")) { return "taint"; }
        if (Array.isArray(obj.rules)) {
          const hasTaintRule = obj.rules.some((rule) => !!(rule && typeof rule === "object" && !Array.isArray(rule) && (rule as Record<string, unknown>).mode === "taint"));
          if (hasTaintRule) { return "taint"; }
        }
      }
    } catch {
      // Fall back to normal below. A parse error will still be displayed on the Rules page.
    }
    return "normal";
  }

  private normalizePolicyRelPath(value: string): string {
    return value.trim().replace(/\\/g, "/");
  }

  private uniquePolicyFiles(values: string[]): string[] {
    return Array.from(new Set(values.map((v) => this.normalizePolicyRelPath(v)).filter((v) => v.length > 0)));
  }

  private readActivePolicyFiles(doc: Record<string, unknown>): string[] {
    // v0.8.6: explicit list supports any number of active policies. Empty list is valid.
    if (Array.isArray(doc.activePolicyFiles)) {
      return this.uniquePolicyFiles(doc.activePolicyFiles.filter((v): v is string => typeof v === "string"));
    }

    // Backward compatibility with v0.8.5 two-slot selector and older single-slot selector.
    const active: string[] = [];
    if (typeof doc.activeNormalPolicyFile === "string") { active.push(doc.activeNormalPolicyFile); }
    if (typeof doc.activeTaintPolicyFile === "string") { active.push(doc.activeTaintPolicyFile); }
    if (active.length === 0 && typeof doc.activePolicyFile === "string") { active.push(doc.activePolicyFile); }

    const presets = this.readStringArray(doc, "presets");
    if (active.length === 0 && presets.includes("vibesec:default")) { active.push("rules/default.yaml"); }
    if (presets.includes("vibesec:taint")) { active.push("rules/taint.yaml"); }
    return this.uniquePolicyFiles(active);
  }

  private updatePresetMirror(doc: Record<string, unknown>): void {
    const active = new Set(this.readActivePolicyFiles(doc));
    const presets: string[] = [];
    if (active.has("rules/default.yaml")) { presets.push("vibesec:default"); }
    if (active.has("rules/taint.yaml")) { presets.push("vibesec:taint"); }
    doc.presets = presets;
  }

  private setPolicyFileActive(doc: Record<string, unknown>, fileId: string, enabled: boolean): string | null {
    const rel = this.relPathFromFileId(fileId);
    if (!rel) { return null; }

    const current = this.readActivePolicyFiles(doc);
    const next = enabled
      ? this.uniquePolicyFiles([...current, rel])
      : current.filter((item) => item !== rel);

    doc.activePolicyFiles = next;

    // v0.8.6 replaces the older single-slot/two-slot selector fields.
    delete doc.activePolicyFile;
    delete doc.activePolicyKind;
    delete doc.activeNormalPolicyFile;
    delete doc.activeTaintPolicyFile;
    doc.externalRuleFiles = [];
    doc.disabledRules = Array.isArray(doc.disabledRules) ? doc.disabledRules : [];
    this.updatePresetMirror(doc);
    return rel;
  }

  private async setRuleFileEnabled(fileId: string, enabled: boolean): Promise<void> {
    const root = this.workspaceRoot();
    if (!root) {
      this.postMessage({ type: "toast", tone: "warn", message: "Open a workspace folder first." });
      return;
    }

    try {
      const doc = this.readPolicyDocument();
      const rel = this.setPolicyFileActive(doc, fileId, enabled);
      if (!rel) {
        this.postMessage({ type: "toast", tone: "warn", message: "This policy file cannot be changed." });
        return;
      }

      await this.writePolicyDocument(doc);
      await vscode.commands.executeCommand("vibesec.reloadPolicy");
      this.postMessage({ type: "rulesUpdated", rules: this.readRulesIndex() });
      const activeCount = this.readActivePolicyFiles(doc).length;
      this.postMessage({
        type: "toast",
        tone: "info",
        message: enabled
          ? `${rel} activated. ${activeCount} policy file${activeCount === 1 ? "" : "s"} active.`
          : `${rel} deactivated. ${activeCount} policy file${activeCount === 1 ? "" : "s"} active.`,
      });
    } catch (err: unknown) {
      this.postMessage({
        type: "toast",
        tone: "error",
        message: `Could not update policy: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  private splitScopedRuleId(scopedRuleId: string): { fileId: string; ruleId: string } | null {
    const sep = "::";
    const idx = scopedRuleId.indexOf(sep);
    if (idx === -1) { return null; }
    return {
      fileId: scopedRuleId.slice(0, idx),
      ruleId: scopedRuleId.slice(idx + sep.length),
    };
  }

  private async setRuleEnabled(scopedRuleId: string, enabled: boolean): Promise<void> {
    const root = this.workspaceRoot();
    if (!root) {
      this.postMessage({ type: "toast", tone: "warn", message: "Open a workspace folder first." });
      return;
    }

    const scoped = this.splitScopedRuleId(scopedRuleId);
    const idx = this.readRulesIndex();
    const rule = idx.rules.find((r) => r.id === scopedRuleId || r.ruleId === scopedRuleId);
    const file = scoped
      ? idx.files.find((f) => f.id === scoped.fileId)
      : rule
        ? idx.files.find((f) => f.id === rule.file)
        : undefined;
    const ruleId = scoped?.ruleId ?? rule?.ruleId ?? scopedRuleId;

    try {
      const doc = this.readPolicyDocument();
      let changedYaml = false;

      // Keep disabledRules as a backup/filter so scans stay correct even if the
      // target file is read-only. The visible YAML block is still commented when
      // the file can be edited.
      this.setStringArrayValue(doc, "disabledRules", ruleId, !enabled);

      const targetIsPolicy = file?.absPath !== undefined && file.absPath === this.policyPath();
      if (targetIsPolicy) {
        // .vibesec.yaml stores the disabledRules list and can also contain inline
        // rules. Write the policy fields first, then comment/uncomment the rule
        // block so yaml.dump does not erase our visible comment markers.
        await this.writePolicyDocument(doc);
        changedYaml = this.setRuleCommented(file!.absPath!, ruleId, !enabled);
      } else {
        if (file?.absPath) {
          changedYaml = this.setRuleCommented(file.absPath, ruleId, !enabled);
        }
        await this.writePolicyDocument(doc);
      }
      await vscode.commands.executeCommand("vibesec.reloadPolicy");
      this.postMessage({ type: "rulesUpdated", rules: this.readRulesIndex() });
      this.postMessage({
        type: "toast",
        tone: changedYaml || !file?.absPath ? "info" : "warn",
        message: enabled
          ? changedYaml ? "Rule uncommented and enabled." : "Rule enabled in policy filter."
          : changedYaml ? "Rule commented out and disabled." : "Rule disabled in policy filter.",
      });
    } catch (err: unknown) {
      this.postMessage({
        type: "toast",
        tone: "error",
        message: `Could not update rule: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  private static readonly disabledRulePrefix = "# VIBESEC_DISABLED ";

  private stripDisabledPrefix(line: string): string | null {
    return line.startsWith(ControlCenterController.disabledRulePrefix)
      ? line.slice(ControlCenterController.disabledRulePrefix.length)
      : null;
  }

  private ruleIdPattern(ruleId: string): RegExp {
    const escaped = ruleId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`^\\s*-\\s+id\\s*:\\s*['\"]?${escaped}['\"]?\\s*$`);
  }

  private setRuleCommented(absPath: string, ruleId: string, commented: boolean): boolean {
    let content: string;
    try { content = fs.readFileSync(absPath, "utf-8"); }
    catch { return false; }

    const hasFinalNewline = /\r?\n$/.test(content);
    const lines = content.replace(/\r\n/g, "\n").split("\n");
    if (hasFinalNewline) { lines.pop(); }
    const ruleStart = this.ruleIdPattern(ruleId);

    if (commented) {
      for (let i = 0; i < lines.length; i++) {
        if (!ruleStart.test(lines[i])) { continue; }
        const indent = (lines[i].match(/^(\s*)-/)?.[1]) ?? "";
        let end = i + 1;
        while (end < lines.length) {
          if (new RegExp(`^${indent.replace(/ /g, " ")}-\\s+id\\s*:`).test(lines[end])) { break; }
          end++;
        }
        for (let j = i; j < end; j++) {
          if (!lines[j].startsWith(ControlCenterController.disabledRulePrefix)) {
            lines[j] = ControlCenterController.disabledRulePrefix + lines[j];
          }
        }
        fs.writeFileSync(absPath, lines.join("\n") + (hasFinalNewline ? "\n" : ""), "utf-8");
        return true;
      }
      return false;
    }

    for (let i = 0; i < lines.length; i++) {
      const stripped = this.stripDisabledPrefix(lines[i]);
      if (stripped === null || !ruleStart.test(stripped)) { continue; }
      let end = i + 1;
      while (end < lines.length && this.stripDisabledPrefix(lines[end]) !== null) { end++; }
      for (let j = i; j < end; j++) {
        const restored = this.stripDisabledPrefix(lines[j]);
        if (restored !== null) { lines[j] = restored; }
      }
      fs.writeFileSync(absPath, lines.join("\n") + (hasFinalNewline ? "\n" : ""), "utf-8");
      return true;
    }
    return false;
  }

  private slugifyPolicyName(input: string): string {
    const slug = input
      .trim()
      .replace(/\.ya?ml$/i, "")
      .replace(/^\.vibesec[-_]*/i, "")
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/-+/g, "-")
      .replace(/^[-.]+|[-.]+$/g, "");
    return slug || "policy";
  }

  private async promptPolicyFilePath(kind: "normal" | "taint" | "custom"): Promise<string | undefined> {
    const label = kind === "taint" ? "taint" : kind === "custom" ? "custom" : "normal";
    const dir = this.ensureToolPoliciesDir();
    const entered = await vscode.window.showInputBox({
      title: `VibeSec — New ${label} policy`,
      prompt: `Enter a name. VibeSec will create a separate YAML file inside the tool policy folder: rules/policies/.`,
      placeHolder: kind === "taint" ? "taint-api-checks" : kind === "custom" ? "team-custom-rules" : "normal-baseline",
      ignoreFocusOut: true,
      validateInput: (value) => {
        const slug = this.slugifyPolicyName(value);
        if (!value.trim()) { return "Policy name is required."; }
        const fileName = `${label}-${slug}.yaml`;
        if (fs.existsSync(path.join(dir, fileName))) { return `${fileName} already exists. Choose another name.`; }
        return null;
      },
    });
    if (!entered) { return undefined; }
    const slug = this.slugifyPolicyName(entered);
    return path.join(dir, `${label}-${slug}.yaml`);
  }

  private policyTemplate(kind: "normal" | "taint" | "custom"): string {
    if (kind === "taint") { return TAINT_POLICY_TEMPLATE; }
    if (kind === "custom") { return CUSTOM_RULE_FILE_TEMPLATE; }
    return NORMAL_POLICY_TEMPLATE;
  }

  private async createPolicyFile(kind: "normal" | "taint" | "custom"): Promise<void> {
    const filePath = await this.promptPolicyFilePath(kind);
    if (!filePath) { return; }

    fs.writeFileSync(filePath, this.policyTemplate(kind), "utf-8");
    this.postMessage({ type: "rulesUpdated", rules: this.readRulesIndex() });
    const opened = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
    await vscode.window.showTextDocument(opened);
    const rel = this.toolPolicyRelPath(path.basename(filePath));
    this.postMessage({
      type: "toast",
      tone: "info",
      message: `Created ${rel}. Turn it ON in Rules to make it the active policy.`,
    });
  }

  private async deletePolicyFile(fileId: string): Promise<void> {
    if (!fileId.startsWith("custom/")) {
      this.postMessage({ type: "toast", tone: "warn", message: "Bundled default and taint policies cannot be deleted." });
      return;
    }
    const root = this.workspaceRoot();
    const rel = fileId.slice("custom/".length).replace(/\\/g, "/");
    const abs = this.resolvePolicyFileRelPath(rel, root);
    if (!fs.existsSync(abs)) {
      this.postMessage({ type: "toast", tone: "warn", message: "That policy file no longer exists." });
      return;
    }
    const answer = await vscode.window.showWarningMessage(
      `Delete ${rel}?`,
      { modal: true, detail: "Bundled policies will remain. If this was active, it will simply be removed from activePolicyFiles." },
      "Delete",
    );
    if (answer !== "Delete") { return; }

    fs.unlinkSync(abs);

    const policyPath = this.policyPath();
    if (policyPath && fs.existsSync(policyPath)) {
      try {
        const raw = yaml.load(fs.readFileSync(policyPath, "utf-8"));
        if (raw && typeof raw === "object" && !Array.isArray(raw)) {
          const doc = raw as Record<string, unknown>;
          const before = this.readActivePolicyFiles(doc);
          const after = before.filter((item) => item !== rel);
          if (after.length !== before.length || doc.activeNormalPolicyFile === rel || doc.activeTaintPolicyFile === rel || doc.activePolicyFile === rel) {
            doc.activePolicyFiles = after;
            delete doc.activePolicyFile;
            delete doc.activePolicyKind;
            delete doc.activeNormalPolicyFile;
            delete doc.activeTaintPolicyFile;
            this.updatePresetMirror(doc);
            fs.writeFileSync(policyPath, "# .vibesec.yaml — edited by VibeSec Control Center\n" + yaml.dump(doc, { lineWidth: 100 }), "utf-8");
          }
        }
      } catch {
        // Ignore and let reloadPolicy fall back if needed.
      }
    }

    await vscode.commands.executeCommand("vibesec.reloadPolicy");
    this.postMessage({ type: "rulesUpdated", rules: this.readRulesIndex() });
    this.postMessage({ type: "toast", tone: "info", message: `${rel} deleted.` });
  }

  private async pickAndOpenFolder(): Promise<void> {
    const picks = await vscode.window.showOpenDialog({
      title: "VibeSec — Open folder",
      canSelectFiles: false,
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: "Open folder",
    });
    const picked = picks?.[0];
    if (!picked) { return; }

    try {
      const alreadyOpen = vscode.workspace.workspaceFolders?.some((f) => f.uri.fsPath === picked.fsPath) ?? false;
      if (!alreadyOpen) {
        const insertAt = vscode.workspace.workspaceFolders?.length ?? 0;
        vscode.workspace.updateWorkspaceFolders(insertAt, 0, { uri: picked });
      }
      this.postMessage({ type: "toast", tone: "info", message: `Folder opened: ${path.basename(picked.fsPath)}` });
    } catch (err: unknown) {
      this.postMessage({
        type: "toast",
        tone: "error",
        message: `Could not open folder: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  private async pickAndOpenFile(): Promise<void> {
    const picks = await vscode.window.showOpenDialog({
      title: "VibeSec — Open file",
      canSelectFiles: true,
      canSelectFolders: false,
      canSelectMany: false,
      openLabel: "Open file",
    });
    const picked = picks?.[0];
    if (!picked) { return; }

    try {
      const doc = await vscode.workspace.openTextDocument(picked);
      await vscode.window.showTextDocument(doc);
      this.postMessage({ type: "toast", tone: "info", message: `File opened: ${path.basename(picked.fsPath)}` });
    } catch (err: unknown) {
      this.postMessage({
        type: "toast",
        tone: "error",
        message: `Could not open file: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  private githubUrlToRaw(input: string): string {
    try {
      const url = new URL(input);
      if (url.hostname === "github.com") {
        const parts = url.pathname.split("/").filter(Boolean);
        const blobIndex = parts.indexOf("blob");
        const rawIndex = parts.indexOf("raw");
        const index = blobIndex !== -1 ? blobIndex : rawIndex;
        if (parts.length >= index + 3 && index >= 2) {
          const owner = parts[0];
          const repo = parts[1];
          const branch = parts[index + 1];
          const filePath = parts.slice(index + 2).join("/");
          return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;
        }
      }
    } catch {
      // The caller validates the URL separately; keep the original value if URL
      // construction fails for any reason.
    }
    return input;
  }

  private fileNameFromUrl(input: string): string {
    try {
      const url = new URL(input);
      const last = decodeURIComponent(url.pathname.split("/").filter(Boolean).pop() ?? "");
      const base = last.replace(/[^a-zA-Z0-9._-]/g, "-");
      if (/\.ya?ml$/i.test(base)) { return base; }
    } catch {
      // Fall through to default.
    }
    return "vibesec-imported-rules.yaml";
  }

  private uniqueWorkspaceYamlPath(root: string, desiredName: string): { relPath: string; absPath: string } {
    const clean = desiredName.replace(/[^a-zA-Z0-9._-]/g, "-") || "vibesec-imported-rules.yaml";
    const ext = path.extname(clean) || ".yaml";
    const stem = path.basename(clean, ext);
    let relPath = `vibesec-imported-${stem}`.replace(/-+/g, "-");
    if (!/\.ya?ml$/i.test(relPath)) { relPath += ext; }
    let absPath = path.join(root, relPath);
    let i = 2;
    while (fs.existsSync(absPath)) {
      relPath = `vibesec-imported-${stem}-${i}${ext}`;
      absPath = path.join(root, relPath);
      i++;
    }
    return { relPath, absPath };
  }

  private looksLikePolicyDocument(obj: Record<string, unknown>): boolean {
    return ["presets", "severity", "disabledRules", "externalRuleFiles", "knownRuleFiles", "files"].some((k) => k in obj);
  }

  private buildImportedPolicyContent(originalText: string, obj: Record<string, unknown>, sourceUrl: string): string {
    // If the URL points to a raw Semgrep rule file, wrap it in VibeSec's
    // standard custom-policy structure so the imported file is ready to use
    // as a selectable policy. If the URL already points to a full VibeSec
    // policy, preserve it exactly.
    if (Array.isArray(obj.rules) && !this.looksLikePolicyDocument(obj)) {
      const wrapped = {
        activePolicyKind: "custom",
        presets: [],
        severity: {
          minSeverity: "warning",
        },
        files: {
          exclude: [
            "**/node_modules/**",
            "**/dist/**",
            "**/build/**",
            "**/*.test.*",
          ],
        },
        rules: obj.rules,
      };
      return `# VibeSec imported custom policy\n# Source: ${sourceUrl}\n\n${yaml.dump(wrapped, { lineWidth: -1, noRefs: true })}`;
    }
    return originalText.endsWith("\n") ? originalText : originalText + "\n";
  }

  private async importRuleFileFromUrl(): Promise<void> {
    const dir = this.ensureToolPoliciesDir();

    const entered = await vscode.window.showInputBox({
      title: "VibeSec — Import policy YAML from URL",
      prompt: "Paste a GitHub YAML link or any direct link to a valid .yaml/.yml file.",
      placeHolder: "https://github.com/user/repo/blob/main/rules/security.yaml",
      ignoreFocusOut: true,
      validateInput: (value) => {
        const trimmed = value.trim();
        if (!trimmed) { return "URL is required."; }
        try {
          const url = new URL(trimmed);
          if (url.protocol !== "https:" && url.protocol !== "http:") { return "Use an http or https URL."; }
        } catch {
          return "Enter a valid URL.";
        }
        return null;
      },
    });
    if (!entered) { return; }

    const originalUrl = entered.trim();
    const downloadUrl = this.githubUrlToRaw(originalUrl);

    try {
      const response = await fetch(downloadUrl, { headers: { "User-Agent": "VibeSec" } });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} ${response.statusText}`);
      }
      const text = await response.text();
      const parsed = yaml.load(text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("YAML must be a top-level mapping/object.");
      }
      const obj = parsed as Record<string, unknown>;
      if (!Array.isArray(obj.rules) && !this.looksLikePolicyDocument(obj)) {
        throw new Error("YAML must contain either a top-level rules: array or VibeSec policy keys such as presets/severity/files.");
      }

      const suggested = this.fileNameFromUrl(originalUrl).replace(/\.ya?ml$/i, "") || "imported-policy";
      const name = await vscode.window.showInputBox({
        title: "VibeSec — Name imported policy",
        prompt: "Enter a name for this imported policy. VibeSec will create a new separate policy file.",
        value: suggested,
        ignoreFocusOut: true,
        validateInput: (value) => {
          const slug = this.slugifyPolicyName(value);
          if (!value.trim()) { return "Policy name is required."; }
          const fileName = `imported-${slug}.yaml`;
          if (fs.existsSync(path.join(dir, fileName))) { return `${fileName} already exists. Choose another name.`; }
          return null;
        },
      });
      if (!name) { return; }

      const absPath = path.join(dir, `imported-${this.slugifyPolicyName(name)}.yaml`);
      const content = this.buildImportedPolicyContent(text, obj, originalUrl);
      fs.writeFileSync(absPath, content, "utf-8");

      this.postMessage({ type: "rulesUpdated", rules: this.readRulesIndex() });
      const opened = await vscode.workspace.openTextDocument(vscode.Uri.file(absPath));
      await vscode.window.showTextDocument(opened);
      this.postMessage({ type: "toast", tone: "info", message: `Imported ${this.toolPolicyRelPath(path.basename(absPath))}. Turn it ON in Rules to make it active.` });
    } catch (err: unknown) {
      this.postMessage({
        type: "toast",
        tone: "error",
        message: `Import failed: ${err instanceof Error ? err.message : String(err)}`,
      });
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
    if (!fs.existsSync(abs)) {
      fs.writeFileSync(abs, "", "utf-8");
    }
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(abs));
    await vscode.window.showTextDocument(doc);
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
      this.workspaceRoot(),
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
        "design",
        "controlCenter.js",
      ),
    );
    const stylesUri = webview.asWebviewUri(
      vscode.Uri.joinPath(
        this.context.extensionUri,
        "media",
        "design",
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
