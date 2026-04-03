// Internal model for a single security finding
export interface Finding {
  ruleId: string;
  message: string;
  severity: "error" | "warning" | "info";
  filePath: string;
  startLine: number;   // 0-based for VS Code
  startCol: number;
  endLine: number;
  endCol: number;
  snippet: string;
}
