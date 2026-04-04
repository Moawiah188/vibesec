import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { minimatch } from "minimatch";
import { FindingsProvider, PanelState } from "./findingsProvider";
import { getDefaultPolicy, loadPolicy, PolicyLoadResult } from "./policy";
import { scanFile } from "./scanner";
import { Finding, PolicyConfig } from "./types";

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
  // ── 1. Set up TreeView ────────────────────────────────────────────────────
  const findingsProvider = new FindingsProvider();
  const treeView = vscode.window.createTreeView("vibesec.findingsPanel", {
    treeDataProvider: findingsProvider,
    showCollapseAll:  true,
  });
  treeView.message = findingsProvider.getViewMessage();

  function updatePanel(state: PanelState): void {
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

  // ── 2. vibesec.scanCurrentFile ────────────────────────────────────────────
  const scanCmd = vscode.commands.registerCommand(
    "vibesec.scanCurrentFile",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("VibeSec: No file is open.");
        return;
      }

      const fileUri  = editor.document.uri;
      const filePath = fileUri.fsPath;

      // Resolve workspace root from the active file
      const folder        = vscode.workspace.getWorkspaceFolder(fileUri);
      const workspaceRoot = folder?.uri.fsPath
        ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

      if (!workspaceRoot) {
        vscode.window.showWarningMessage(
          "VibeSec: No workspace folder is open. Open a folder to use VibeSec."
        );
        updatePanel({ kind: "error", message: "No workspace folder is open." });
        return;
      }

      // Load (or use cached) policy for this workspace root
      const policyResult = getOrLoadPolicy(workspaceRoot);
      if (!policyResult.ok) {
        showPolicyErrors(policyResult.errors, "load");
      }
      const policy = policyResult.policy;

      // Check files.exclude before scanning
      if (isFileExcluded(filePath, workspaceRoot, policy)) {
        vscode.window.showInformationMessage(
          "VibeSec: This file is excluded by policy (files.exclude). Skipping scan."
        );
        return;
      }

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title:    "VibeSec: Scanning...",
        },
        async () => {
          try {
            const findings = await scanFile(filePath, policy, context.extensionPath);

            // Sprint 1 behaviour preserved: inline diagnostics
            diagnosticCollection.set(fileUri, findings.map(toDiagnostic));

            if (findings.length === 0) {
              updatePanel({ kind: "noFindings" });
              vscode.window.showInformationMessage("VibeSec: No issues found.");
            } else {
              updatePanel({ kind: "findings", findings });
              vscode.window.showWarningMessage(
                `VibeSec: Found ${findings.length} issue${findings.length !== 1 ? "s" : ""}.`
              );
            }
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            updatePanel({ kind: "error", message: msg });
            vscode.window.showErrorMessage(`VibeSec scan failed: ${msg}`);
          }
        }
      );
    }
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

  context.subscriptions.push(
    diagnosticCollection,
    treeView,
    scanCmd,
    goToCmd,
    reloadCmd,
    openPolicyCmd,
  );
}

export function deactivate(): void {
  diagnosticCollection.clear();
  policyCache.clear();
}
