"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const scanner_1 = require("./scanner");
// Single diagnostic collection shared across scans
const diagnosticCollection = vscode.languages.createDiagnosticCollection("vibesec");
// Convert our Finding model into a VS Code Diagnostic
function toDiagnostic(finding) {
    const range = new vscode.Range(finding.startLine, finding.startCol, finding.endLine, finding.endCol);
    const severityMap = {
        error: vscode.DiagnosticSeverity.Error,
        warning: vscode.DiagnosticSeverity.Warning,
        info: vscode.DiagnosticSeverity.Information,
    };
    const diag = new vscode.Diagnostic(range, `[${finding.ruleId}] ${finding.message}`, severityMap[finding.severity]);
    diag.source = "VibeSec";
    return diag;
}
function activate(context) {
    const cmd = vscode.commands.registerCommand("vibesec.scanCurrentFile", async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage("VibeSec: No file is open.");
            return;
        }
        const filePath = editor.document.uri.fsPath;
        await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "VibeSec: Scanning..." }, async () => {
            try {
                const findings = await (0, scanner_1.scanFile)(filePath);
                const diagnostics = findings.map(toDiagnostic);
                diagnosticCollection.set(editor.document.uri, diagnostics);
                if (findings.length === 0) {
                    vscode.window.showInformationMessage("VibeSec: No issues found.");
                }
                else {
                    vscode.window.showWarningMessage(`VibeSec: Found ${findings.length} issue(s).`);
                }
            }
            catch (err) {
                vscode.window.showErrorMessage(`VibeSec scan failed: ${err.message}`);
            }
        });
    });
    context.subscriptions.push(cmd, diagnosticCollection);
}
function deactivate() {
    diagnosticCollection.clear();
}
//# sourceMappingURL=extension.js.map