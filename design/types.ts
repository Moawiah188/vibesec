// Verbatim copy of the wire types from src/panelMessages.ts.
// Kept in sync by hand — if you change one, change the other.

export type ThemeKind = "dark" | "light" | "hc-dark" | "hc-light";

export type PanelSeverity = "error" | "warning" | "info";
export type PanelSeverityLabel = "Error" | "Warning" | "Info";

export interface PanelMeta {
  category:   string;
  cwe:        string;
  owasp:      string;
  confidence: string;
}

export interface PanelTaintStep {
  path:    string;
  absPath: string;
  line:    number;
  snippet: string;
}

export interface PanelTaint {
  source:        PanelTaintStep;
  sink:          PanelTaintStep;
  intermediates: PanelTaintStep[];
}

export interface PanelFinding {
  id:        string;
  ruleId:    string;
  severity:  PanelSeverity;
  sevLabel:  PanelSeverityLabel;
  title:     string;
  desc:      string;
  path:      string;
  absPath:   string;
  line:      number;
  meta:      PanelMeta;
  taint?:    PanelTaint;
}

export interface PanelTreeNode {
  id:       string;
  type:     "file" | "folder";
  name:     string;
  ext?:     string;
  depth:    number;
  open:     boolean;
  scannable?: boolean;
  children?: PanelTreeNode[];
}

export type PanelStateMsg =
  | { kind: "empty" }
  | { kind: "loading"; percent: number; currentFile: string }
  | { kind: "noFindings" }
  | { kind: "error"; message: string }
  | { kind: "findings"; findings: PanelFinding[] };

export type ExtensionToWebview =
  | { type: "init"; theme: ThemeKind; accent: "green"; density: "comfortable"; version: string }
  | { type: "workspaceTree"; tree: PanelTreeNode[]; defaultSelected: string[] }
  | { type: "stateUpdated"; state: PanelStateMsg }
  | { type: "progressUpdated"; percent: number; currentFile: string }
  | { type: "promptCopied"; scope: "vuln" | "file" | "all"; key: string }
  | { type: "themeChanged"; theme: ThemeKind }
  | { type: "toast"; message: string; tone: "info" | "warn" | "error" };

export type WebviewToExtension =
  | { type: "ready" }
  | { type: "getWorkspaceTree" }
  | { type: "openFolder" }
  | { type: "newFile" }
  | { type: "openControlCenter" }
  | { type: "scanRequested"; filePaths: string[] }
  | { type: "scanCancel" }
  | { type: "goToFinding"; findingId: string }
  | { type: "goToLocation"; absPath: string; line: number }
  | { type: "copyPromptForVuln"; findingId: string }
  | { type: "copyPromptForFile"; filePath: string }
  | { type: "copyPromptForAll" }
  | { type: "generatePrompts" };
