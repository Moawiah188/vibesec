import { execFile } from "child_process";
import * as path from "path";
import { Finding } from "./types";

// Map Semgrep severity strings to VS Code diagnostic levels
function mapSeverity(sev: string): Finding["severity"] {
  switch (sev.toUpperCase()) {
    case "ERROR":
      return "error";
    case "WARNING":
      return "warning";
    default:
      return "info";
  }
}

// Pick a Semgrep config based on the file extension
function configForFile(filePath: string): string[] {
  const ext = path.extname(filePath).toLowerCase();
  const langConfigs: Record<string, string[]> = {
    ".py":   ["r/python.lang.security"],
    ".js":   ["r/javascript.lang.security"],
    ".ts":   ["r/typescript.lang.security"],
    ".jsx":  ["r/javascript.lang.security"],
    ".tsx":  ["r/typescript.lang.security"],
    ".java": ["r/java.lang.security"],
    ".go":   ["r/go.lang.security"],
    ".rb":   ["r/ruby.lang.security"],
    ".php":  ["r/php.lang.security"],
  };
  return langConfigs[ext] || ["r/generic.secrets"];
}

// Parse Semgrep JSON output into our internal Finding model
function parseSemgrepOutput(json: string): Finding[] {
  const data = JSON.parse(json);
  const results: any[] = data.results || [];

  return results.map((r) => ({
    ruleId: r.check_id || "unknown",
    message: r.extra?.message || "Security issue detected",
    severity: mapSeverity(r.extra?.severity || "WARNING"),
    filePath: r.path,
    startLine: (r.start?.line ?? 1) - 1,   // Semgrep is 1-based, VS Code is 0-based
    startCol: (r.start?.col ?? 1) - 1,
    endLine: (r.end?.line ?? 1) - 1,
    endCol: (r.end?.col ?? 1) - 1,
    snippet: r.extra?.lines || "",
  }));
}

// Run Semgrep on a single file and return parsed findings
export function scanFile(filePath: string): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    const configs = configForFile(filePath);
    const configArgs = configs.flatMap((c) => ["--config", c]);

    execFile(
      "semgrep",
      ["scan", "--json", ...configArgs, filePath],
      {
        maxBuffer: 10 * 1024 * 1024,
        timeout: 120_000,
        env: { ...process.env, PYTHONIOENCODING: "utf-8" },
      },
      (error, stdout, _stderr) => {
        // Semgrep exits with code 1 when it finds issues — that's normal
        if (error && error.code !== 1 && !stdout) {
          reject(new Error(`Semgrep failed: ${error.message}`));
          return;
        }
        try {
          const findings = parseSemgrepOutput(stdout);
          resolve(findings);
        } catch (parseErr: any) {
          reject(new Error(`Failed to parse Semgrep output: ${parseErr.message}`));
        }
      }
    );
  });
}
