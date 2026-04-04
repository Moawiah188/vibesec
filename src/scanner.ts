import { execFile } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Finding, PolicyConfig, SEVERITY_RANK, SeverityLevel } from "./types";

// ── Severity helpers ──────────────────────────────────────────────────────────

function mapSeverity(sev: string): Finding["severity"] {
  switch (sev.toUpperCase()) {
    case "ERROR":   return "error";
    case "WARNING": return "warning";
    default:        return "info";
  }
}

/**
 * Returns the effective severity for a finding, honouring per-rule overrides
 * from the policy. Falls back to the severity Semgrep reported.
 */
function effectiveSeverity(finding: Finding, policy: PolicyConfig): SeverityLevel {
  return policy.severity.overrides[finding.ruleId] ?? finding.severity;
}

function meetsMinSeverity(finding: Finding, policy: PolicyConfig): boolean {
  const effective = effectiveSeverity(finding, policy);
  return SEVERITY_RANK[effective] >= SEVERITY_RANK[policy.severity.minSeverity];
}

// ── Semgrep output parsing ────────────────────────────────────────────────────

/**
 * Semgrep prepends the dot-encoded config file path to every local rule ID.
 * e.g.  "C.Users.foo.vibesec.rules.default.vibesec.hardcoded-secret"
 *                                                   ^^^^^^^^^^^^^^^^^^^ ← what we want
 *
 * Strip the path prefix so callers see only the id defined in the YAML.
 * Registry rules (e.g. "python.lang.security.audit.foo") pass through unchanged
 * because they won't contain ".rules.<name>." or ".custom-rules.".
 */
function cleanRuleId(checkId: string): string {
  // Semgrep encodes the config directory path as dot-separated segments and
  // appends the rule's YAML id.  The filename stem is NOT included — only the
  // directory.  So for a rule "vibesec.hardcoded-secret" in rules/default.yaml
  // the check_id is:
  //   "C.Users.foo.vibesec.rules.vibesec.hardcoded-secret"
  //                             ^^^^^^^ last ".rules." → strip everything before
  //
  // Use lastIndexOf so we handle paths that contain a "rules" directory above.
  const rulesIdx = checkId.lastIndexOf(".rules.");
  if (rulesIdx !== -1) {
    return checkId.slice(rulesIdx + ".rules.".length);
  }
  // Temp custom-rule file written by writeTempRuleFile():  "…custom-rules.<id>"
  const customIdx = checkId.lastIndexOf(".custom-rules.");
  if (customIdx !== -1) {
    return checkId.slice(customIdx + ".custom-rules.".length);
  }
  return checkId;
}

function parseSemgrepOutput(json: string): Finding[] {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const data = JSON.parse(json) as { results?: any[] };
  const results = data.results ?? [];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return results.map((r: any): Finding => ({
    ruleId:    cleanRuleId(r.check_id ?? "unknown"),
    message:   r.extra?.message ?? "Security issue detected",
    severity:  mapSeverity(r.extra?.severity ?? "WARNING"),
    filePath:  r.path,
    startLine: (r.start?.line ?? 1) - 1,   // Semgrep is 1-based, VS Code is 0-based
    startCol:  (r.start?.col  ?? 1) - 1,
    endLine:   (r.end?.line   ?? 1) - 1,
    endCol:    (r.end?.col    ?? 1) - 1,
    snippet:   r.extra?.lines ?? "",
  }));
}

// ── Temp file for custom rules ────────────────────────────────────────────────

interface TempRuleFile {
  filePath: string;
  dirPath:  string;
}

/**
 * Writes custom rules to a temp JSON file.
 * JSON is used because it is valid YAML and avoids pulling js-yaml into
 * scanner.ts — the YAML dependency stays isolated in policy.ts.
 * Returns null when there are no custom rules.
 */
function writeTempRuleFile(policy: PolicyConfig): TempRuleFile | null {
  if (policy.rules.length === 0) { return null; }

  const ruleDoc  = { rules: policy.rules };
  const content  = JSON.stringify(ruleDoc, null, 2);
  const tmpDir   = fs.mkdtempSync(path.join(os.tmpdir(), "vibesec-"));
  const tmpFile  = path.join(tmpDir, "custom-rules.json");
  fs.writeFileSync(tmpFile, content, "utf-8");
  return { filePath: tmpFile, dirPath: tmpDir };
}

function cleanupTempRuleFile(tmp: TempRuleFile | null): void {
  if (tmp === null) { return; }
  try {
    fs.unlinkSync(tmp.filePath);
    fs.rmdirSync(tmp.dirPath);
  } catch {
    // Best-effort — ignore errors (file may already be gone)
  }
}

// ── Preset resolution ─────────────────────────────────────────────────────────

/**
 * Resolve a preset reference to a concrete --config value.
 *
 *   "vibesec:default"       → <extensionPath>/rules/default.yaml  (bundled)
 *   "vibesec:<name>"        → <extensionPath>/rules/<name>.yaml   (bundled)
 *   "./my-rules.yaml"       → kept as-is (workspace-relative, Semgrep handles it)
 *   "/abs/path/rules.yaml"  → kept as-is
 *   "p/owasp-top-ten"       → kept as-is (Semgrep registry — requires internet)
 *   "r/python.lang.security" → kept as-is (Semgrep registry — requires internet)
 */
function resolvePreset(preset: string, extensionPath: string): string {
  if (preset.startsWith("vibesec:")) {
    const name = preset.slice("vibesec:".length);
    return path.join(extensionPath, "rules", `${name}.yaml`);
  }
  return preset;
}

// ── Semgrep argument construction ─────────────────────────────────────────────

function buildConfigArgs(
  policy: PolicyConfig,
  tmp: TempRuleFile | null,
  extensionPath: string
): string[] {
  const args: string[] = [];
  for (const preset of policy.presets) {
    args.push("--config", resolvePreset(preset, extensionPath));
  }
  if (tmp !== null) {
    args.push("--config", tmp.filePath);
  }
  // Safety net: if nothing is configured, fall back to bundled default
  if (policy.presets.length === 0 && policy.rules.length === 0) {
    args.push("--config", path.join(extensionPath, "rules", "default.yaml"));
  }
  return args;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Run Semgrep on a single file using the supplied policy and return filtered
 * findings.
 *
 * @param filePath      Absolute path to the file to scan.
 * @param policy        Resolved policy from policy.ts.
 * @param extensionPath Absolute path to the extension root — used to resolve
 *                      bundled presets (`vibesec:default`, etc.).
 */
export function scanFile(
  filePath: string,
  policy: PolicyConfig,
  extensionPath: string
): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    let tmp: TempRuleFile | null = null;

    try {
      tmp = writeTempRuleFile(policy);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      reject(new Error(`VibeSec: Could not write temp rule file: ${msg}`));
      return;
    }

    const configArgs = buildConfigArgs(policy, tmp, extensionPath);

    execFile(
      "semgrep",
      ["scan", "--json", "--metrics=off", ...configArgs, filePath],
      {
        maxBuffer: 10 * 1024 * 1024,
        timeout:   120_000,
        env:       { ...process.env, PYTHONIOENCODING: "utf-8" },
      },
      (error, stdout, stderr) => {
        // Always clean up temp file regardless of success or failure
        cleanupTempRuleFile(tmp);

        // Semgrep exit codes:
        //   0 = success, no findings
        //   1 = success, findings found  ← normal, not an error
        //   2 = fatal error (bad config, auth required, etc.)
        //   4 = network error (can't fetch registry rules)
        if (error && error.code !== 1) {
          // Prefer stderr for the real error message; fall back to error.message
          const detail = stderr.trim() || error.message;
          // Surface the first non-empty line of stderr — it's usually the most useful
          const firstLine = detail.split("\n").find((l) => l.trim() !== "") ?? detail;
          reject(new Error(`Semgrep failed (exit ${error.code ?? "?"}): ${firstLine}`));
          return;
        }

        let allFindings: Finding[];
        try {
          allFindings = parseSemgrepOutput(stdout);
        } catch (parseErr: unknown) {
          const msg = parseErr instanceof Error ? parseErr.message : String(parseErr);
          reject(new Error(`Failed to parse Semgrep output: ${msg}`));
          return;
        }

        // Apply severity overrides and minSeverity filter
        const filtered = allFindings.filter((f) => meetsMinSeverity(f, policy));

        // Mutate severity to the effective value so diagnostics and the tree
        // view both reflect the override — not the raw Semgrep severity
        const normalised = filtered.map((f): Finding => ({
          ...f,
          severity: effectiveSeverity(f, policy),
        }));

        resolve(normalised);
      }
    );
  });
}
