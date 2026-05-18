import { execFile } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { logBus } from "./logBus";
import {
  Finding,
  PolicyConfig,
  SEVERITY_RANK,
  SeverityLevel,
  TaintFlow,
  TaintLocation,
} from "./types";

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
  return results.map((r: any): Finding => {
    const finding: Finding = {
      ruleId:    cleanRuleId(r.check_id ?? "unknown"),
      message:   r.extra?.message ?? "Security issue detected",
      severity:  mapSeverity(r.extra?.severity ?? "WARNING"),
      filePath:  r.path,
      startLine: (r.start?.line ?? 1) - 1,   // Semgrep is 1-based, VS Code is 0-based
      startCol:  (r.start?.col  ?? 1) - 1,
      endLine:   (r.end?.line   ?? 1) - 1,
      endCol:    (r.end?.col    ?? 1) - 1,
      snippet:   r.extra?.lines ?? "",
      // Semgrep echoes the matched rule's metadata back here. Preserved verbatim
      // so the findings panel can render whatever fields are present (cwe, owasp,
      // references, likelihood, impact, technology, …) without us pre-filtering.
      metadata:  r.extra?.metadata,
    };
    const taint = parseDataflowTrace(r.extra?.dataflow_trace, r.path, finding);
    if (taint) {
      finding.taint = taint;
    }
    return finding;
  });
}

// ── Taint dataflow extraction (Sprint 7) ─────────────────────────────────────
//
// Semgrep emits `extra.dataflow_trace` whenever a `mode: taint` rule fires.
// The shape varies slightly across Semgrep versions:
//
//   {
//     "taint_source":      <CallTrace>,
//     "intermediate_vars": [<IntermediateVar>, ...],
//     "taint_sink":        <CallTrace>
//   }
//
// A CallTrace is either an object with `{ location, content }`, or a tagged
// tuple like `["CliLoc", {location, content}]` / `["CliCall", {location, content}, [...]]`.
// We extract leaf locations defensively — unknown shapes degrade to the
// finding's own location rather than throwing.

function extractTaintLocation(node: unknown, fallback: TaintLocation): TaintLocation {
  // Tagged tuple: ["CliLoc"|"CliCall", { location, content }, ...]
  if (Array.isArray(node)) {
    for (const item of node) {
      const loc = tryReadLocation(item);
      if (loc) { return loc; }
    }
    return fallback;
  }
  const loc = tryReadLocation(node);
  return loc ?? fallback;
}

function tryReadLocation(node: unknown): TaintLocation | null {
  if (!node || typeof node !== "object" || Array.isArray(node)) { return null; }
  const obj = node as Record<string, unknown>;
  const rawLoc = obj.location;
  if (!rawLoc || typeof rawLoc !== "object" || Array.isArray(rawLoc)) { return null; }
  const locObj = rawLoc as Record<string, unknown>;
  const filePath = typeof locObj.path === "string" ? locObj.path : "";
  const start = locObj.start as { line?: number } | undefined;
  const line = typeof start?.line === "number" ? start.line - 1 : 0;
  const snippet = typeof obj.content === "string" ? obj.content.trim() : "";
  if (!filePath) { return null; }
  return { filePath, line, snippet };
}

function parseDataflowTrace(
  trace: unknown,
  findingFilePath: string,
  finding: Finding,
): TaintFlow | undefined {
  if (!trace || typeof trace !== "object" || Array.isArray(trace)) { return undefined; }
  const t = trace as Record<string, unknown>;
  // If neither taint_source nor taint_sink is present, the rule wasn't taint mode.
  if (t.taint_source === undefined && t.taint_sink === undefined) { return undefined; }

  // The finding's own range serves as a safe fallback for either endpoint.
  const fallback: TaintLocation = {
    filePath: findingFilePath,
    line:     finding.startLine,
    snippet:  finding.snippet.split(/\r?\n/)[0]?.trim() ?? "",
  };

  const source = extractTaintLocation(t.taint_source, fallback);
  const sink   = extractTaintLocation(t.taint_sink,   fallback);

  const intermediates: TaintLocation[] = [];
  if (Array.isArray(t.intermediate_vars)) {
    for (const iv of t.intermediate_vars) {
      const loc = tryReadLocation(iv);
      if (loc) { intermediates.push(loc); }
    }
  }

  return { source, sink, intermediates };
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
  // No safety fallback here. If the user turns every policy file OFF, the
  // policy intentionally has zero configs and scanFile returns zero findings.
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
  extensionPath: string,
  semgrepPath: string = "semgrep"
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
    if (configArgs.length === 0) {
      cleanupTempRuleFile(tmp);
      logBus.info(
        "scan",
        `No active policy configs for ${path.basename(filePath)} — skipping Semgrep`,
        "Turn ON one or more policy files in Control Center → Rules to scan again.",
      );
      resolve([]);
      return;
    }

    execFile(
      semgrepPath,
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
          logBus.error(
            "semgrep",
            `Semgrep exited with status ${error.code ?? "?"} on ${path.basename(filePath)}`,
            `binary=${semgrepPath}\nfile=${filePath}\nstderr: ${detail}`,
          );
          reject(new Error(`Semgrep failed (exit ${error.code ?? "?"}): ${firstLine}`));
          return;
        }
        // Surface non-fatal stderr noise (deprecation hints, version warnings,
        // ignored config) so power users can spot Semgrep complaints in the
        // Logs page without watching the OutputChannel themselves.
        if (stderr.trim() !== "") {
          const firstLine = stderr.split("\n").find((l) => l.trim() !== "") ?? stderr;
          logBus.warn(
            "semgrep",
            `Semgrep wrote to stderr while scanning ${path.basename(filePath)}`,
            `file=${filePath}\nstderr: ${stderr.trim()}`,
          );
          void firstLine;
        }

        let allFindings: Finding[];
        try {
          allFindings = parseSemgrepOutput(stdout);
        } catch (parseErr: unknown) {
          const msg = parseErr instanceof Error ? parseErr.message : String(parseErr);
          reject(new Error(`Failed to parse Semgrep output: ${msg}`));
          return;
        }

        // Apply disabledRules, severity overrides and minSeverity filter.
        const disabled = new Set(policy.disabledRules);
        const enabledFindings = allFindings.filter((f) => !disabled.has(f.ruleId));
        const filtered = enabledFindings.filter((f) => meetsMinSeverity(f, policy));

        // Mutate severity to the effective value so diagnostics and the tree
        // view both reflect the override — not the raw Semgrep severity
        const normalised = filtered.map((f): Finding => ({
          ...f,
          severity: effectiveSeverity(f, policy),
        }));

        // Emit one log entry per taint finding so the Logs page surfaces the
        // source/sink hop without adding new UI elsewhere.
        for (const f of normalised) {
          if (f.taint) {
            logBus.info(
              "scan",
              `Taint: ${f.ruleId} — source L${f.taint.source.line + 1} → sink L${f.taint.sink.line + 1}`,
              `file=${path.basename(f.filePath)}\n` +
                `source: ${f.taint.source.snippet || "(no snippet)"}\n` +
                `sink:   ${f.taint.sink.snippet   || "(no snippet)"}`,
            );
          }
        }

        resolve(normalised);
      }
    );
  });
}
