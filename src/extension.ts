import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { minimatch } from "minimatch";
import { FindingsProvider, PanelState } from "./findingsProvider";
import { LlmClientError, PROVIDER_DEFAULT_MODEL, pingProvider } from "./llmClient";
import { loadPolicy, PolicyLoadResult } from "./policy";
import {
  generatePromptForFile,
  generatePromptForProject,
  generatePromptForVuln,
  GenerateOptions,
} from "./promptGenerator";
import {
  getScannableExtensions,
  isScannablePath,
} from "./scannableExtensions";
import { scanFile } from "./scanner";
import {
  IGNORED_DIR_NAMES,
  ScanNode,
  ScanProvider,
  isScanFileNode,
  isScanFolderNode,
} from "./scanProvider";
import {
  PROVIDER_LABEL,
  clearApiKey,
  getApiKey,
  pickProvider,
  setApiKey,
} from "./secrets";
import {
  Finding,
  LlmProvider,
  PolicyConfig,
  PromptMode,
  findingId,
  promptCacheFileKey,
  PROMPT_CACHE_PROJECT_KEY,
} from "./types";

// ── Policy template written when openPolicyFile creates a new file ────────────

const POLICY_TEMPLATE = `# .vibesec.yaml — VibeSec policy file
# Place this file at your workspace root.
# All fields are optional. Missing file = defaults (r/generic.secrets).

# Rule presets — these run 100% locally, no internet required
# "vibesec:default" is the bundled OWASP-style ruleset shipped with VibeSec
# You can also use Semgrep registry packs (e.g. p/owasp-top-ten) but those
# require internet access and may need "semgrep login" first.
presets:
  - vibesec:default

# Severity filter
severity:
  minSeverity: warning   # error | warning | info
  # overrides:
  #   some.rule.id: error

# Inline custom rules (Semgrep-style)
# rules:
#   - id: my-team.no-eval
#     message: "eval() executes arbitrary code and is a security risk."
#     severity: WARNING
#     languages: [javascript, typescript]
#     pattern: eval(...)
#     metadata:
#       category: security
#       cwe: "CWE-95"

# External rule files (workspace-relative paths)
# externalRuleFiles:
#   - custom-rules.yaml

# File patterns
# files:
#   exclude:
#     - "**/node_modules/**"
#     - "**/*.test.ts"
`;

// ── Diagnostics ───────────────────────────────────────────────────────────────

const diagnosticCollection =
  vscode.languages.createDiagnosticCollection("vibesec");

function toDiagnostic(finding: Finding): vscode.Diagnostic {
  const range = new vscode.Range(
    finding.startLine,
    finding.startCol,
    finding.endLine,
    finding.endCol
  );
  const severityMap: Record<Finding["severity"], vscode.DiagnosticSeverity> = {
    error:   vscode.DiagnosticSeverity.Error,
    warning: vscode.DiagnosticSeverity.Warning,
    info:    vscode.DiagnosticSeverity.Information,
  };
  const diag = new vscode.Diagnostic(
    range,
    `[${finding.ruleId}] ${finding.message}`,
    severityMap[finding.severity]
  );
  diag.source = "VibeSec";
  return diag;
}

// ── Navigation helper ─────────────────────────────────────────────────────────

async function goToFinding(finding: Finding): Promise<void> {
  const uri      = vscode.Uri.file(finding.filePath);
  const position = new vscode.Position(finding.startLine, finding.startCol);
  const range    = new vscode.Range(position, position);
  const doc      = await vscode.workspace.openTextDocument(uri);
  await vscode.window.showTextDocument(doc, {
    selection:     range,
    preserveFocus: false,
  });
}

// ── Files-exclude check ───────────────────────────────────────────────────────

/**
 * Returns true if `filePath` matches any of the exclude globs in the policy.
 * Globs are matched against the workspace-relative POSIX path.
 */
function isFileExcluded(filePath: string, workspaceRoot: string, policy: PolicyConfig): boolean {
  if (policy.files.exclude.length === 0) { return false; }
  const relative = path.relative(workspaceRoot, filePath).replace(/\\/g, "/");
  return policy.files.exclude.some((glob) =>
    minimatch(relative, glob, { dot: true, matchBase: false })
  );
}

// ── Folder walking (Sprint 4: multi-target scanning) ─────────────────────────

/**
 * Resolve a target path (file or folder) to the list of scannable files
 * underneath it. For files this returns `[path]` when scannable, `[]` when
 * not. For folders this recursively collects scannable files, skipping
 * IGNORED_DIR_NAMES and dot-directories. Symlinks are not followed to avoid
 * cycle hazards.
 */
async function expandTargetToFiles(
  targetPath: string,
  scannableExts: Set<string>,
): Promise<string[]> {
  let stat: fs.Stats;
  try { stat = await fs.promises.lstat(targetPath); }
  catch { return []; }

  if (stat.isFile()) {
    return isScannablePath(targetPath, scannableExts) ? [targetPath] : [];
  }
  if (!stat.isDirectory()) { return []; }

  const out: string[] = [];
  const stack: string[] = [targetPath];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try { entries = await fs.promises.readdir(dir, { withFileTypes: true }); }
    catch { continue; }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) { continue; }
      if (entry.isDirectory()) {
        if (IGNORED_DIR_NAMES.has(entry.name)) { continue; }
        if (entry.name.startsWith(".")) { continue; }
        stack.push(full);
      } else if (entry.isFile()) {
        if (isScannablePath(full, scannableExts)) { out.push(full); }
      }
    }
  }
  return out;
}

// ── Policy cache (per workspace root) ────────────────────────────────────────

const policyCache = new Map<string, PolicyConfig>();

/**
 * Return the cached policy for `workspaceRoot`, or load + cache it.
 * Pass `forceReload = true` to bypass the cache (used by reloadPolicy command).
 */
function getOrLoadPolicy(
  workspaceRoot: string,
  forceReload = false
): PolicyLoadResult {
  if (!forceReload && policyCache.has(workspaceRoot)) {
    return { ok: true, policy: policyCache.get(workspaceRoot)! };
  }
  const result = loadPolicy(workspaceRoot);
  policyCache.set(workspaceRoot, result.policy);
  return result;
}

// ── Policy error presentation ─────────────────────────────────────────────────

function showPolicyErrors(errors: string[], source: "load" | "reload"): void {
  const first = errors[0];
  const count = errors.length;

  if (count === 1 && first.includes("No .vibesec.yaml")) {
    // Most common case: friendly info-level nudge, not a warning
    vscode.window.showInformationMessage(`VibeSec: ${first}`);
    return;
  }

  const prefix = source === "reload" ? "VibeSec (reload): " : "VibeSec: ";
  vscode.window.showWarningMessage(
    `${prefix}${count} policy error${count !== 1 ? "s" : ""}: ${first}` +
    (count > 1 ? ` (+${count - 1} more — see Output for details)` : "")
  );
}

// ── Activate ──────────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  // ── 1. Findings tree view ─────────────────────────────────────────────────
  const findingsProvider = new FindingsProvider();
  const treeView = vscode.window.createTreeView("vibesec.findingsPanel", {
    treeDataProvider: findingsProvider,
    showCollapseAll:  true,
  });
  treeView.message = findingsProvider.getViewMessage();

  // ── 1b. Scan tree view (workspace files with multi-select) ────────────────
  //
  // canSelectMany: true gives us the full-row blue highlight via the theme's
  // list.activeSelectionBackground — no checkboxes, same UX as the native
  // File Explorer (Ctrl/Cmd+click to add, Shift+click for range).
  const scanProvider = new ScanProvider();
  const scanTreeView = vscode.window.createTreeView("vibesec.scanPanel", {
    treeDataProvider: scanProvider,
    showCollapseAll:  true,
    canSelectMany:    true,
  });

  function refreshScanPanelState(): void {
    const hasWorkspace = !!vscode.workspace.workspaceFolders?.length;
    vscode.commands.executeCommand(
      "setContext",
      "vibesec.scanPanelState",
      hasWorkspace ? "ready" : "noWorkspace",
    );
  }
  refreshScanPanelState();

  // Keep the Scan panel tree in sync with workspace folder and file changes.
  const workspaceFolderListener =
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      refreshScanPanelState();
      scanProvider.refresh();
    });

  // Light-weight file system watcher: rebuild the scan tree when files are
  // created, deleted, or renamed anywhere in the workspace. We do NOT watch
  // content changes — those don't affect the tree structure.
  const fsWatcher = vscode.workspace.createFileSystemWatcher("**/*");
  fsWatcher.onDidCreate(() => scanProvider.refresh());
  fsWatcher.onDidDelete(() => scanProvider.refresh());

  function getConfig() {
    const cfg = vscode.workspace.getConfiguration("vibesec");
    return {
      semgrepPath:           cfg.get<string>("semgrepPath", "semgrep"),
      autoScanOnSave:        cfg.get<boolean>("autoScanOnSave", false),
      showInlineDecorations: cfg.get<boolean>("showInlineDecorations", true),
      llmProvider:           cfg.get<LlmProvider>("llmProvider", "anthropic"),
      llmModel:              (cfg.get<string>("llmModel", "") || "").trim(),
      promptMode:            cfg.get<PromptMode>("promptMode", "perFile"),
    };
  }

  /**
   * Resolve the model id to use for a given provider. Falls back to the
   * provider's default if the user hasn't set llmModel or set it to a
   * model that obviously belongs to a different provider.
   */
  function resolveModel(provider: LlmProvider, configured: string): string {
    const fallback = PROVIDER_DEFAULT_MODEL[provider];
    if (configured === "") { return fallback; }
    // Heuristic: if the model id obviously belongs to another provider, fall
    // back to the chosen provider's default. Saves users from "anthropic +
    // gpt-5-nano" misconfigurations after switching providers.
    const looksLikeOpenAI    = /^gpt[-_]/i.test(configured) || /^o\d/i.test(configured);
    const looksLikeAnthropic = /^claude[-_]/i.test(configured);
    const looksLikeGemini    = /^gemini[-_]/i.test(configured);
    if (provider === "anthropic" && (looksLikeOpenAI || looksLikeGemini)) { return fallback; }
    if (provider === "openai"    && (looksLikeAnthropic || looksLikeGemini)) { return fallback; }
    if (provider === "gemini"    && (looksLikeOpenAI    || looksLikeAnthropic)) { return fallback; }
    return configured;
  }

  function setContextState(kind: PanelState["kind"]): void {
    vscode.commands.executeCommand("setContext", "vibesec.panelState", kind);
  }

  setContextState("empty");

  function updatePanel(state: PanelState): void {
    setContextState(state.kind);
    findingsProvider.setState(state);
    treeView.message = findingsProvider.getViewMessage();

    // Badge: show finding count, clear when no findings
    if (state.kind === "findings") {
      treeView.badge = {
        value:   state.findings.length,
        tooltip: `${state.findings.length} security issue${state.findings.length !== 1 ? "s" : ""} found`,
      };
    } else {
      treeView.badge = undefined;
    }
  }

  // ── Shared scan runner ───────────────────────────────────────────────────
  //
  // Runs Semgrep across one or more targets (each a file or folder URI).
  // Folders are walked recursively, skipping IGNORED_DIR_NAMES, dot-dirs, and
  // files whose extension isn't in the configured fileExtensions set.
  // Each file still passes through the policy's `files.exclude` globs.
  // Findings from every file are aggregated into a single panel update.
  async function runScanOnTargets(targets: vscode.Uri[]): Promise<void> {
    if (targets.length === 0) {
      vscode.window.showWarningMessage("VibeSec: No files selected to scan.");
      return;
    }

    // Resolve a workspace root. Use the workspace folder of the first target
    // when possible, otherwise fall back to the first open workspace folder.
    const firstFolder = vscode.workspace.getWorkspaceFolder(targets[0]);
    const workspaceRoot = firstFolder?.uri.fsPath
      ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

    if (!workspaceRoot) {
      vscode.window.showWarningMessage(
        "VibeSec: No workspace folder is open. Open a folder to use VibeSec.",
      );
      updatePanel({ kind: "error", message: "No workspace folder is open." });
      return;
    }

    const policyResult = getOrLoadPolicy(workspaceRoot);
    if (!policyResult.ok) {
      showPolicyErrors(policyResult.errors, "load");
    }
    const policy = policyResult.policy;

    // Expand folder targets into the files they contain. Apply scannable-
    // extension and policy-exclude filters as we walk so the progress count
    // reflects only files we'll actually scan.
    const exts = getScannableExtensions();
    const expanded: string[] = [];
    const seen = new Set<string>();
    for (const uri of targets) {
      const expandedFiles = await expandTargetToFiles(uri.fsPath, exts);
      for (const fp of expandedFiles) {
        if (seen.has(fp)) { continue; }
        if (isFileExcluded(fp, workspaceRoot, policy)) { continue; }
        seen.add(fp);
        expanded.push(fp);
      }
    }

    if (expanded.length === 0) {
      vscode.window.showInformationMessage(
        "VibeSec: Nothing to scan — selection contained no scannable files (after applying file-extension and policy filters).",
      );
      return;
    }

    const { semgrepPath, showInlineDecorations } = getConfig();
    const aggregated: Finding[] = [];
    const failures: { filePath: string; message: string }[] = [];

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title:    `VibeSec: Scanning ${expanded.length} file${expanded.length !== 1 ? "s" : ""}…`,
        cancellable: true,
      },
      async (progress, token) => {
        const total = expanded.length;
        const step  = 100 / total;

        for (let i = 0; i < total; i++) {
          if (token.isCancellationRequested) { break; }
          const filePath = expanded[i];
          progress.report({
            increment: i === 0 ? 0 : step,
            message:   `(${i + 1}/${total}) ${path.basename(filePath)}`,
          });

          try {
            const findings = await scanFile(filePath, policy, context.extensionPath, semgrepPath);
            const fileUri = vscode.Uri.file(filePath);
            if (showInlineDecorations) {
              diagnosticCollection.set(fileUri, findings.map(toDiagnostic));
            } else {
              diagnosticCollection.delete(fileUri);
            }
            aggregated.push(...findings);
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            failures.push({ filePath, message: msg });
          }
        }

        // Final tick so the bar reaches 100% before disappearing.
        progress.report({ increment: step });
      },
    );

    // ── Present results ─────────────────────────────────────────────────────
    if (aggregated.length === 0 && failures.length > 0 && failures.length === expanded.length) {
      // Every file failed. Surface the first error.
      const first = failures[0];
      updatePanel({ kind: "error", message: first.message });
      vscode.window.showErrorMessage(
        `VibeSec scan failed: ${first.message}` +
        (failures.length > 1 ? ` (and ${failures.length - 1} more)` : ""),
      );
      return;
    }

    if (aggregated.length === 0) {
      updatePanel({ kind: "noFindings" });
      const suffix = failures.length > 0
        ? ` (${failures.length} file${failures.length !== 1 ? "s" : ""} failed to scan — see Output.)`
        : "";
      vscode.window.showInformationMessage(`VibeSec: No issues found in ${expanded.length} file${expanded.length !== 1 ? "s" : ""}.${suffix}`);
    } else {
      updatePanel({ kind: "findings", findings: aggregated });
      const fileCount = new Set(aggregated.map((f) => f.filePath)).size;
      const suffix = failures.length > 0
        ? ` (${failures.length} file${failures.length !== 1 ? "s" : ""} failed to scan.)`
        : "";
      vscode.window.showWarningMessage(
        `VibeSec: Found ${aggregated.length} issue${aggregated.length !== 1 ? "s" : ""} across ${fileCount} file${fileCount !== 1 ? "s" : ""}.${suffix}`,
      );
    }
  }

  /** Single-file convenience wrapper for the scanCurrentFile command. */
  async function runScanOnFile(filePath: string): Promise<void> {
    await runScanOnTargets([vscode.Uri.file(filePath)]);
  }

  // ── 2. vibesec.scanCurrentFile ────────────────────────────────────────────
  const scanCmd = vscode.commands.registerCommand(
    "vibesec.scanCurrentFile",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("VibeSec: No file is open.");
        return;
      }
      await runScanOnFile(editor.document.uri.fsPath);
    },
  );

  // ── 2b. vibesec.scanSelected ─────────────────────────────────────────────
  //
  // Reads the Scan panel's native selection (set via click / Ctrl+click /
  // Shift+click) and scans every file selected, plus every scannable file
  // underneath any selected folders.
  const scanSelectedCmd = vscode.commands.registerCommand(
    "vibesec.scanSelected",
    async () => {
      const selection = scanTreeView.selection;
      const targets: vscode.Uri[] = selection
        .filter((n: ScanNode) => isScanFileNode(n) || isScanFolderNode(n))
        .map((n: ScanNode) => n.uri);

      if (targets.length === 0) {
        vscode.window.showWarningMessage(
          "VibeSec: Select one or more files or folders in the Scan panel first. " +
          "(Click to select, Ctrl/Cmd+Click to add more, Shift+Click for a range.)",
        );
        return;
      }

      await runScanOnTargets(targets);
    },
  );

  // ── 2c. vibesec.refreshScanTree ──────────────────────────────────────────
  const refreshScanTreeCmd = vscode.commands.registerCommand(
    "vibesec.refreshScanTree",
    () => {
      scanProvider.refresh();
    },
  );

  // ── 2d. vibesec.scanWorkspace ────────────────────────────────────────────
  //
  // Scans every workspace folder. Honors IGNORED_DIR_NAMES, dot-dirs, the
  // configured fileExtensions setting, and `.vibesec.yaml` excludes.
  const scanWorkspaceCmd = vscode.commands.registerCommand(
    "vibesec.scanWorkspace",
    async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage(
          "VibeSec: No workspace folder is open. Open a folder to use VibeSec.",
        );
        return;
      }
      await runScanOnTargets(folders.map((f) => f.uri));
    },
  );

  // ── 3. vibesec.goToFinding ────────────────────────────────────────────────
  const goToCmd = vscode.commands.registerCommand(
    "vibesec.goToFinding",
    async (finding: Finding) => {
      try {
        await goToFinding(finding);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(
          `VibeSec: Could not navigate to finding: ${msg}`
        );
      }
    }
  );

  // ── 4. vibesec.reloadPolicy ───────────────────────────────────────────────
  const reloadCmd = vscode.commands.registerCommand(
    "vibesec.reloadPolicy",
    () => {
      const editor = vscode.window.activeTextEditor;
      const fileUri = editor?.document.uri;
      const folder  = fileUri
        ? vscode.workspace.getWorkspaceFolder(fileUri)
        : undefined;
      const workspaceRoot = folder?.uri.fsPath
        ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

      if (!workspaceRoot) {
        vscode.window.showWarningMessage(
          "VibeSec: No workspace folder open — nothing to reload."
        );
        return;
      }

      const result = getOrLoadPolicy(workspaceRoot, /* forceReload */ true);

      // Clear stale findings from the panel after a reload so users
      // re-scan with the fresh policy rather than seeing stale results
      updatePanel({ kind: "empty" });
      diagnosticCollection.clear();

      if (result.ok) {
        vscode.window.showInformationMessage("VibeSec: Policy reloaded successfully.");
      } else {
        showPolicyErrors(result.errors, "reload");
      }
    }
  );

  // ── 5. vibesec.openPolicyFile ─────────────────────────────────────────────
  const openPolicyCmd = vscode.commands.registerCommand(
    "vibesec.openPolicyFile",
    async () => {
      const editor = vscode.window.activeTextEditor;
      const fileUri = editor?.document.uri;
      const folder  = fileUri
        ? vscode.workspace.getWorkspaceFolder(fileUri)
        : undefined;
      const workspaceRoot = folder?.uri.fsPath
        ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

      if (!workspaceRoot) {
        vscode.window.showWarningMessage(
          "VibeSec: No workspace folder open — cannot create policy file."
        );
        return;
      }

      const policyPath = path.join(workspaceRoot, ".vibesec.yaml");

      if (!fs.existsSync(policyPath)) {
        try {
          fs.writeFileSync(policyPath, POLICY_TEMPLATE, "utf-8");
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          vscode.window.showErrorMessage(
            `VibeSec: Could not create .vibesec.yaml: ${msg}`
          );
          return;
        }
      }

      const uri = vscode.Uri.file(policyPath);
      await vscode.window.showTextDocument(uri);
    }
  );

  // ── 6. vibesec.copyDescription ───────────────────────────────────────────────
  //
  // Copies a human-readable one-liner: "rule-id · Line N · message".
  // The TreeView delivers the detail node whose `finding` holds everything.
  const copyDescCmd = vscode.commands.registerCommand(
    "vibesec.copyDescription",
    async (node: { finding?: Finding }) => {
      const f = node?.finding;
      if (!f) { return; }
      const lineNum = f.startLine + 1;
      const text = `${f.ruleId}  ·  ${path.basename(f.filePath)}:${lineNum}  ·  ${f.message}`;
      await vscode.env.clipboard.writeText(text);
      vscode.window.showInformationMessage("VibeSec: Description copied to clipboard.");
    },
  );

  // ── 7. API key management (Sprint 4) ─────────────────────────────────────
  //
  // API keys live in VS Code's SecretStorage, never in settings.json. Each
  // provider has its own slot so users can keep keys for OpenAI, Anthropic,
  // and Gemini and switch between them via the `vibesec.llmProvider` setting.
  const setApiKeyCmd = vscode.commands.registerCommand(
    "vibesec.setApiKey",
    async () => {
      const provider = await pickProvider("Which provider's API key are you setting?");
      if (!provider) { return; }
      const key = await vscode.window.showInputBox({
        title:        `VibeSec — set ${PROVIDER_LABEL[provider]} API key`,
        prompt:       `Paste your ${PROVIDER_LABEL[provider]} API key. It will be stored securely and never written to settings.`,
        password:     true,
        ignoreFocusOut: true,
        placeHolder:  PROVIDER_LABEL[provider] + " API key",
      });
      if (!key) { return; }
      const trimmed = key.trim();
      if (trimmed === "") {
        vscode.window.showWarningMessage("VibeSec: Empty key — nothing was saved.");
        return;
      }
      await setApiKey(context, provider, trimmed);
      vscode.window.showInformationMessage(
        `VibeSec: ${PROVIDER_LABEL[provider]} API key saved. Run "VibeSec: Test API Key" to verify it.`,
      );
    },
  );

  const clearApiKeyCmd = vscode.commands.registerCommand(
    "vibesec.clearApiKey",
    async () => {
      const provider = await pickProvider("Which provider's API key do you want to remove?");
      if (!provider) { return; }
      await clearApiKey(context, provider);
      vscode.window.showInformationMessage(
        `VibeSec: ${PROVIDER_LABEL[provider]} API key removed.`,
      );
    },
  );

  const testApiKeyCmd = vscode.commands.registerCommand(
    "vibesec.testApiKey",
    async () => {
      const provider = await pickProvider("Which provider's API key do you want to test?");
      if (!provider) { return; }
      const key = await getApiKey(context, provider);
      if (!key) {
        vscode.window.showWarningMessage(
          `VibeSec: No ${PROVIDER_LABEL[provider]} API key is set. Run "VibeSec: Set API Key" first.`,
        );
        return;
      }
      const cfg   = getConfig();
      const model = resolveModel(provider, provider === cfg.llmProvider ? cfg.llmModel : "");
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title:    `VibeSec: Testing ${PROVIDER_LABEL[provider]} (${model})…`,
        },
        async () => {
          try {
            await pingProvider(provider, key, model);
            vscode.window.showInformationMessage(
              `VibeSec: ${PROVIDER_LABEL[provider]} (${model}) responded — your key works.`,
            );
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            vscode.window.showErrorMessage(`VibeSec: ${msg}`);
          }
        },
      );
    },
  );

  // ── 8. Prompt generation (Sprint 4) ──────────────────────────────────────
  //
  // generatePromptsCmd populates the cache for whichever granularity the
  // user has selected (perFile / perVulnerability / perProject). The three
  // copyPrompt* commands read from that cache and lazily fill it on miss.

  /** Resolve provider + apiKey + model, or show a friendly error and return undefined. */
  async function resolveLlmCallContext(): Promise<
    | { ok: true; opts: GenerateOptions; provider: LlmProvider }
    | { ok: false }
  > {
    const cfg      = getConfig();
    const provider = cfg.llmProvider;
    const apiKey   = await getApiKey(context, provider);
    if (!apiKey) {
      const action = "Set API Key";
      const choice = await vscode.window.showWarningMessage(
        `VibeSec: No ${PROVIDER_LABEL[provider]} API key is set. Generate prompts after saving a key.`,
        action,
      );
      if (choice === action) {
        await vscode.commands.executeCommand("vibesec.setApiKey");
      }
      return { ok: false };
    }
    const model = resolveModel(provider, cfg.llmModel);
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    return {
      ok: true,
      provider,
      opts: { provider, apiKey, model, workspaceRoot },
    };
  }

  function reportLlmFailure(err: unknown): void {
    const msg = err instanceof LlmClientError
      ? err.message
      : err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`VibeSec: ${msg}`);
  }

  const generatePromptsCmd = vscode.commands.registerCommand(
    "vibesec.generatePrompts",
    async () => {
      const findings = findingsProvider.getAllFindings();
      if (findings.length === 0) {
        vscode.window.showInformationMessage(
          "VibeSec: No findings to generate prompts for. Run a scan first.",
        );
        return;
      }
      const ctx = await resolveLlmCallContext();
      if (!ctx.ok) { return; }

      const cfg = getConfig();
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title:    `VibeSec: Generating prompts (${cfg.promptMode}, ${PROVIDER_LABEL[ctx.provider]})…`,
          cancellable: true,
        },
        async (progress, token) => {
          try {
            const optsWithSignal = (signal: AbortSignal): GenerateOptions =>
              ({ ...ctx.opts, signal });
            const controller = new AbortController();
            token.onCancellationRequested(() => controller.abort());

            switch (cfg.promptMode) {
              case "perVulnerability": {
                // Bottom-up: per-vuln, then per-file, then project-level.
                const filePaths = findingsProvider.getFilePaths();
                const totalSteps = findings.length + filePaths.length + 1;
                const step = 100 / totalSteps;
                let n = 0;
                for (const f of findings) {
                  if (token.isCancellationRequested) { return; }
                  n++;
                  progress.report({
                    increment: step,
                    message: `Vulnerability ${n}/${findings.length} — ${path.basename(f.filePath)}:${f.startLine + 1}`,
                  });
                  const key = findingId(f);
                  if (findingsProvider.hasCachedPrompt(key)) { continue; }
                  const text = await generatePromptForVuln(f, optsWithSignal(controller.signal));
                  findingsProvider.setCachedPrompt(key, text);
                }
                let i = 0;
                for (const fp of filePaths) {
                  if (token.isCancellationRequested) { return; }
                  i++;
                  progress.report({
                    increment: step,
                    message: `File ${i}/${filePaths.length} — ${path.basename(fp)}`,
                  });
                  const key = promptCacheFileKey(fp);
                  if (findingsProvider.hasCachedPrompt(key)) { continue; }
                  const text = await generatePromptForFile(
                    fp,
                    findingsProvider.getFindingsForFile(fp),
                    optsWithSignal(controller.signal),
                  );
                  findingsProvider.setCachedPrompt(key, text);
                }
                progress.report({ increment: step, message: "Project-level prompt…" });
                if (!findingsProvider.hasCachedPrompt(PROMPT_CACHE_PROJECT_KEY)) {
                  const text = await generatePromptForProject(findings, optsWithSignal(controller.signal));
                  findingsProvider.setCachedPrompt(PROMPT_CACHE_PROJECT_KEY, text);
                }
                break;
              }
              case "perFile": {
                const filePaths = findingsProvider.getFilePaths();
                const step = 100 / Math.max(1, filePaths.length);
                let i = 0;
                for (const fp of filePaths) {
                  if (token.isCancellationRequested) { return; }
                  i++;
                  progress.report({
                    increment: step,
                    message: `File ${i}/${filePaths.length} — ${path.basename(fp)}`,
                  });
                  const key = promptCacheFileKey(fp);
                  if (findingsProvider.hasCachedPrompt(key)) { continue; }
                  const text = await generatePromptForFile(
                    fp,
                    findingsProvider.getFindingsForFile(fp),
                    optsWithSignal(controller.signal),
                  );
                  findingsProvider.setCachedPrompt(key, text);
                }
                break;
              }
              case "perProject": {
                progress.report({ increment: 100, message: "Project-level prompt…" });
                if (!findingsProvider.hasCachedPrompt(PROMPT_CACHE_PROJECT_KEY)) {
                  const text = await generatePromptForProject(findings, optsWithSignal(controller.signal));
                  findingsProvider.setCachedPrompt(PROMPT_CACHE_PROJECT_KEY, text);
                }
                break;
              }
            }

            vscode.window.showInformationMessage(
              "VibeSec: Prompts ready. Right-click a finding or file in the Findings panel and pick Copy Prompt.",
            );
          } catch (err) {
            reportLlmFailure(err);
          }
        },
      );
    },
  );

  // Copy commands. Each one reads from cache on hit, generates lazily on miss.
  async function copyPromptForFinding(f: Finding): Promise<void> {
    const cached = findingsProvider.cachedPromptForFinding(f);
    if (cached) {
      await vscode.env.clipboard.writeText(cached);
      vscode.window.showInformationMessage("VibeSec: Prompt copied to clipboard.");
      return;
    }
    const ctx = await resolveLlmCallContext();
    if (!ctx.ok) { return; }
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title:    `VibeSec: Generating prompt for ${path.basename(f.filePath)}:${f.startLine + 1}…`,
      },
      async () => {
        try {
          const text = await generatePromptForVuln(f, ctx.opts);
          findingsProvider.setCachedPrompt(findingId(f), text);
          await vscode.env.clipboard.writeText(text);
          vscode.window.showInformationMessage("VibeSec: Prompt copied to clipboard.");
        } catch (err) { reportLlmFailure(err); }
      },
    );
  }

  async function copyPromptForFilePath(filePath: string): Promise<void> {
    const cached = findingsProvider.cachedPromptForFile(filePath);
    if (cached) {
      await vscode.env.clipboard.writeText(cached);
      vscode.window.showInformationMessage("VibeSec: File prompt copied to clipboard.");
      return;
    }
    const findings = findingsProvider.getFindingsForFile(filePath);
    if (findings.length === 0) {
      vscode.window.showWarningMessage("VibeSec: No findings for this file.");
      return;
    }
    const ctx = await resolveLlmCallContext();
    if (!ctx.ok) { return; }
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title:    `VibeSec: Generating prompt for ${path.basename(filePath)}…`,
      },
      async () => {
        try {
          const text = await generatePromptForFile(filePath, findings, ctx.opts);
          findingsProvider.setCachedPrompt(promptCacheFileKey(filePath), text);
          await vscode.env.clipboard.writeText(text);
          vscode.window.showInformationMessage("VibeSec: File prompt copied to clipboard.");
        } catch (err) { reportLlmFailure(err); }
      },
    );
  }

  const copyPromptForVulnCmd = vscode.commands.registerCommand(
    "vibesec.copyPromptForVuln",
    async (node: { finding?: Finding }) => {
      const f = node?.finding;
      if (!f) { return; }
      await copyPromptForFinding(f);
    },
  );

  const copyPromptForFileCmd = vscode.commands.registerCommand(
    "vibesec.copyPromptForFile",
    async (node: { filePath?: string }) => {
      const fp = node?.filePath;
      if (!fp) { return; }
      await copyPromptForFilePath(fp);
    },
  );

  const copyPromptForAllCmd = vscode.commands.registerCommand(
    "vibesec.copyPromptForAll",
    async () => {
      const findings = findingsProvider.getAllFindings();
      if (findings.length === 0) {
        vscode.window.showInformationMessage(
          "VibeSec: No findings to generate a prompt for. Run a scan first.",
        );
        return;
      }
      const cached = findingsProvider.cachedPromptForProject();
      if (cached) {
        await vscode.env.clipboard.writeText(cached);
        vscode.window.showInformationMessage("VibeSec: Project prompt copied to clipboard.");
        return;
      }
      const ctx = await resolveLlmCallContext();
      if (!ctx.ok) { return; }
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title:    "VibeSec: Generating project-wide prompt…",
        },
        async () => {
          try {
            const text = await generatePromptForProject(findings, ctx.opts);
            findingsProvider.setCachedPrompt(PROMPT_CACHE_PROJECT_KEY, text);
            await vscode.env.clipboard.writeText(text);
            vscode.window.showInformationMessage("VibeSec: Project prompt copied to clipboard.");
          } catch (err) { reportLlmFailure(err); }
        },
      );
    },
  );

  // ── 9. Settings change listener ──────────────────────────────────────────
  //
  // Refresh the Scan tree when the file-extension list changes so the
  // "not scannable" badges stay in sync with the user's preference.
  const configListener = vscode.workspace.onDidChangeConfiguration((event) => {
    if (event.affectsConfiguration("vibesec.fileExtensions")) {
      scanProvider.refresh();
    }
  });

  const onSaveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
    if (!getConfig().autoScanOnSave) { return; }
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.uri.fsPath !== document.uri.fsPath) { return; }
    await vscode.commands.executeCommand("vibesec.scanCurrentFile");
  });

  context.subscriptions.push(
    diagnosticCollection,
    treeView,
    scanTreeView,
    workspaceFolderListener,
    fsWatcher,
    scanCmd,
    scanSelectedCmd,
    refreshScanTreeCmd,
    scanWorkspaceCmd,
    goToCmd,
    reloadCmd,
    openPolicyCmd,
    copyDescCmd,
    setApiKeyCmd,
    clearApiKeyCmd,
    testApiKeyCmd,
    generatePromptsCmd,
    copyPromptForVulnCmd,
    copyPromptForFileCmd,
    copyPromptForAllCmd,
    configListener,
    onSaveListener,
  );
}

export function deactivate(): void {
  diagnosticCollection.clear();
  policyCache.clear();
}
