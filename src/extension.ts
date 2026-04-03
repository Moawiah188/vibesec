import * as vscode from "vscode";
import { scanFile } from "./scanner";
import { Finding } from "./types";

// Single diagnostic collection shared across scans
const diagnosticCollection = vscode.languages.createDiagnosticCollection("vibesec");

// Convert our Finding model into a VS Code Diagnostic
function toDiagnostic(finding: Finding): vscode.Diagnostic {
  const range = new vscode.Range(
    finding.startLine,
    finding.startCol,
    finding.endLine,
    finding.endCol
  );

  const severityMap: Record<Finding["severity"], vscode.DiagnosticSeverity> = {
    error: vscode.DiagnosticSeverity.Error,
    warning: vscode.DiagnosticSeverity.Warning,
    info: vscode.DiagnosticSeverity.Information,
  };

  const diag = new vscode.Diagnostic(
    range,
    `[${finding.ruleId}] ${finding.message}`,
    severityMap[finding.severity]
  );
  diag.source = "VibeSec";
  return diag;
}

export function activate(context: vscode.ExtensionContext) {
  const cmd = vscode.commands.registerCommand("vibesec.scanCurrentFile", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage("VibeSec: No file is open.");
      return;
    }

    const filePath = editor.document.uri.fsPath;

    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "VibeSec: Scanning..." },
      async () => {
        try {
          const findings = await scanFile(filePath);
          const diagnostics = findings.map(toDiagnostic);
          diagnosticCollection.set(editor.document.uri, diagnostics);

          if (findings.length === 0) {
            vscode.window.showInformationMessage("VibeSec: No issues found.");
          } else {
            vscode.window.showWarningMessage(
              `VibeSec: Found ${findings.length} issue(s).`
            );
          }
        } catch (err: any) {
          vscode.window.showErrorMessage(`VibeSec scan failed: ${err.message}`);
        }
      }
    );
  });

  context.subscriptions.push(cmd, diagnosticCollection);
}

export function deactivate() {
  diagnosticCollection.clear();
}
