import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import type { SeverityLevel } from "./types";

// rulesIndex — single source of truth for the Control Center Rules page.
//
// We surface two layers:
//
//   • RuleFileEntry — one card per rule-file (bundled `rules/*.yaml`, the
//     workspace `.vibesec.yaml`, plus a placeholder for the design's
//     "external" group which is intentionally empty in v1).
//
//   • RuleEntry — a normalised view of a single Semgrep rule scoped to its
//     parent file. The shape mirrors the design's mock so the React page
//     ports cleanly.
//
// Reading is best-effort: malformed YAML produces an empty file with
// `parseError` set, and we never throw upward — broken rules must not
// prevent the panel from opening.

export type RuleSource = "bundled" | "custom" | "external";

/** Analysis mode for a rule. "search" = standard pattern-based; "taint" = data
 *  flow tracking via Semgrep's mode: taint. Drives the TAINT chip on the Rules
 *  page so users can see at a glance which rules participate in dataflow. */
export type RuleMode = "search" | "taint";

export interface RuleEntry {
  /** Stable id as scoped per-file: "<fileId>::<ruleId>" so duplicate ruleIds
   *  across files don't collide in the webview's React list. */
  id:       string;
  /** Original Semgrep rule id, e.g. "vibesec.sql-injection-prepared". */
  ruleId:   string;
  /** Parent file id this rule was loaded from. */
  file:     string;
  /** Pretty title — last dot-segment of ruleId, dashes/underscores → spaces. */
  name:     string;
  sev:      SeverityLevel;
  cat:      string;            // "Injection", "Crypto", … or "—"
  langs:    string[];
  cwe:      string;            // "CWE-78" or "—"
  owasp:    string;            // "A03:2021 Injection" or "—"
  /** 0–1. Mirrors Semgrep's confidence ladder (HIGH=0.95, MEDIUM=0.7, LOW=0.4). */
  conf:     number;
  source:   RuleSource;
  mode:     RuleMode;
  /** v1 reads policy `disabledRules` if it ever appears; today the schema
   *  doesn't write it, so this is always `true` for bundled rules. */
  enabled:  boolean;
}

export interface RuleFileEntry {
  /** Stable id used for the URL-like file row. Matches RuleEntry.file. */
  id:           string;
  /** Display path. Bundled = relative to extension `rules/`; custom = workspace path. */
  path:         string;
  /** Absolute path on disk. `null` for the placeholder external group. */
  absPath:      string | null;
  source:       RuleSource;
  desc:         string;
  /** ISO date "YYYY-MM-DD" of file mtime, or null when unknown / placeholder. */
  updatedAt:    string | null;
  ruleCount:    number;
  /** Per-severity rule counts for the design's badge dots. */
  severities:   { error: number; warning: number; info: number };
  /** Whether this whole file is active in the workspace policy. */
  enabled:      boolean;
  /** When non-empty, the file existed but YAML parsing failed. */
  parseError?:  string;
}

export interface RulesIndex {
  files: RuleFileEntry[];
  rules: RuleEntry[];
}

// ── Confidence mapping ───────────────────────────────────────────────────────
//
// Semgrep's `metadata.confidence` is a string ladder. We project it to a 0–1
// number so the design's confidence bar can render directly. Unknown values
// land at 0.5 — neutral — rather than vanishing the bar.

function confidenceToScore(raw: unknown): number {
  if (typeof raw !== "string") { return 0.5; }
  switch (raw.toUpperCase()) {
    case "HIGH":   return 0.95;
    case "MEDIUM": return 0.7;
    case "LOW":    return 0.4;
    default:       return 0.5;
  }
}

function severityFromYaml(raw: unknown): SeverityLevel {
  if (typeof raw === "string") {
    switch (raw.toUpperCase()) {
      case "ERROR":   return "error";
      case "WARNING": return "warning";
      case "INFO":    return "info";
    }
  }
  // Unknown / missing: lean towards info so a malformed rule stays visible
  // but isn't loud.
  return "info";
}

function prettifyTitle(ruleId: string): string {
  const last = ruleId.includes(".") ? ruleId.split(".").pop()! : ruleId;
  const spaced = last.replace(/[-_]+/g, " ").trim();
  if (spaced.length === 0) { return ruleId; }
  return spaced[0].toUpperCase() + spaced.slice(1);
}

function metadataString(meta: Record<string, unknown> | undefined, key: string): string {
  if (!meta) { return "—"; }
  const v = meta[key];
  if (Array.isArray(v)) {
    const strs = v.filter((x): x is string => typeof x === "string");
    return strs.length === 0 ? "—" : strs.join(", ");
  }
  if (typeof v === "string" && v.length > 0) { return v; }
  return "—";
}

// ── YAML parsing ─────────────────────────────────────────────────────────────

interface RawRule {
  id?:        unknown;
  severity?:  unknown;
  languages?: unknown;
  metadata?:  unknown;
  mode?:      unknown;
}

interface RawRuleDoc {
  rules?: unknown;
}

interface ParseResult {
  rules: RuleEntry[];
  parseError?: string;
  severities: { error: number; warning: number; info: number };
}

const DISABLED_RULE_PREFIX = "# VIBESEC_DISABLED ";

function stripDisabledRulePrefix(line: string): string | null {
  return line.startsWith(DISABLED_RULE_PREFIX)
    ? line.slice(DISABLED_RULE_PREFIX.length)
    : null;
}

function readDisabledRuleBlocks(content: string): unknown[] {
  const blocks: string[][] = [];
  let current: string[] = [];

  const flush = (): void => {
    if (current.length > 0) {
      blocks.push(current);
      current = [];
    }
  };

  for (const line of content.split(/\r?\n/)) {
    const stripped = stripDisabledRulePrefix(line);
    if (stripped === null) {
      flush();
      continue;
    }
    if (/^\s*-\s+id\s*:/.test(stripped)) {
      flush();
    }
    current.push(stripped);
  }
  flush();

  const out: unknown[] = [];
  for (const block of blocks) {
    try {
      const parsed = yaml.load(`rules:\n${block.join("\n")}`);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const rulesRaw = (parsed as RawRuleDoc).rules;
        if (Array.isArray(rulesRaw)) {
          out.push(...rulesRaw);
        }
      }
    } catch {
      // Ignore broken commented blocks. The normal YAML parser still reports
      // active-file errors separately, and users can open the YAML to repair.
    }
  }
  return out;
}

function parseRulesFile(
  absPath: string,
  fileId: string,
  source: RuleSource,
  disabledRules: Set<string>,
  fileEnabled: boolean,
): ParseResult {
  const empty: ParseResult = {
    rules: [],
    severities: { error: 0, warning: 0, info: 0 },
  };

  let content: string;
  try { content = fs.readFileSync(absPath, "utf-8"); }
  catch (err) {
    return { ...empty, parseError: `Could not read: ${err instanceof Error ? err.message : String(err)}` };
  }

  let raw: unknown;
  try { raw = yaml.load(content); }
  catch (err) {
    return { ...empty, parseError: `Invalid YAML: ${err instanceof Error ? err.message : String(err)}` };
  }

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ...empty, parseError: "Top-level YAML must be a mapping" };
  }

  const rules: RuleEntry[] = [];
  const tally = { error: 0, warning: 0, info: 0 };
  const seen = new Set<string>();

  const appendRules = (rulesRaw: unknown[], forcedEnabled?: boolean): void => {
    for (const item of rulesRaw) {
      if (!item || typeof item !== "object") { continue; }
      const r = item as RawRule;
      if (typeof r.id !== "string" || r.id.trim() === "") { continue; }
      const ruleId = r.id.trim();
      const scopedId = `${fileId}::${ruleId}`;
      if (seen.has(scopedId)) { continue; }
      seen.add(scopedId);

      const sev = severityFromYaml(r.severity);
      const meta = (typeof r.metadata === "object" && r.metadata !== null && !Array.isArray(r.metadata))
        ? r.metadata as Record<string, unknown>
        : undefined;
      const langs = Array.isArray(r.languages)
        ? r.languages.filter((l): l is string => typeof l === "string")
        : [];

      const mode: RuleMode = r.mode === "taint" ? "taint" : "search";
      rules.push({
        id:      scopedId,
        ruleId,
        file:    fileId,
        name:    prettifyTitle(ruleId),
        sev,
        cat:     metadataString(meta, "category"),
        langs,
        cwe:     metadataString(meta, "cwe"),
        owasp:   metadataString(meta, "owasp"),
        conf:    confidenceToScore(meta?.confidence),
        source,
        mode,
        enabled: forcedEnabled ?? (fileEnabled && !disabledRules.has(ruleId)),
      });
      tally[sev]++;
    }
  };

  const rulesRaw = (raw as RawRuleDoc).rules;
  if (Array.isArray(rulesRaw)) {
    appendRules(rulesRaw);
  }

  // Rules that the UI disables are physically commented with
  // "# VIBESEC_DISABLED" so Semgrep cannot run them. We still recover their
  // metadata here so the Rules page can display them as OFF and re-enable them.
  appendRules(readDisabledRuleBlocks(content), false);

  return { rules, severities: tally };
}

function fileMtimeIso(absPath: string): string | null {
  try {
    const stat = fs.statSync(absPath);
    return stat.mtime.toISOString().slice(0, 10);
  } catch {
    return null;
  }
}


type PolicySlotKind = "normal" | "taint" | "custom";

interface WorkspacePolicyState {
  policyExists: boolean;
  presets: string[];
  disabledRules: Set<string>;
  /** v0.8.6: any number of active policy files. */
  activePolicyFiles: Set<string>;
  hasInlineRules: boolean;
}

function asStringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) { return null; }
  const out = value.filter((v): v is string => typeof v === "string");
  return out.length === value.length ? out : null;
}

function normalizeRelPath(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.trim().replace(/\\/g, "/") : null;
}

function policyKindFromRaw(raw: unknown, relPath: string): PolicySlotKind {
  const lowerRel = relPath.toLowerCase();
  if (lowerRel === "rules/taint.yaml" || /(^|\/)taint[-_]/.test(lowerRel)) { return "taint"; }
  if (lowerRel === "rules/default.yaml" || /(^|\/)normal[-_]/.test(lowerRel)) { return "normal"; }
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const obj = raw as Record<string, unknown>;
    if (obj.activePolicyKind === "taint") { return "taint"; }
    if (obj.activePolicyKind === "default" || obj.activePolicyKind === "normal") { return "normal"; }
    const presets = asStringArray(obj.presets) ?? [];
    if (presets.includes("vibesec:taint") && !presets.includes("vibesec:default")) { return "taint"; }
    if (presets.includes("vibesec:default")) { return "normal"; }
    if (Array.isArray(obj.rules)) {
      const hasTaint = obj.rules.some((rule) => !!(rule && typeof rule === "object" && !Array.isArray(rule) && (rule as Record<string, unknown>).mode === "taint"));
      if (hasTaint) { return "taint"; }
    }
  }
  return "normal";
}

function readPolicyFileKind(absPath: string, relPath: string): PolicySlotKind {
  if (relPath === "rules/default.yaml") { return "normal"; }
  if (relPath === "rules/taint.yaml") { return "taint"; }
  try {
    return policyKindFromRaw(yaml.load(fs.readFileSync(absPath, "utf-8")), relPath);
  } catch {
    return policyKindFromRaw(undefined, relPath);
  }
}

function readWorkspacePolicyState(workspaceRoot: string | undefined, extensionPath: string): WorkspacePolicyState {
  const fallback: WorkspacePolicyState = {
    policyExists: false,
    presets: ["vibesec:default"],
    disabledRules: new Set<string>(),
    activePolicyFiles: new Set<string>(["rules/default.yaml"]),
    hasInlineRules: false,
  };
  if (!workspaceRoot) { return fallback; }
  const policyPath = path.join(workspaceRoot, ".vibesec.yaml");
  if (!fs.existsSync(policyPath)) { return fallback; }

  try {
    const raw = yaml.load(fs.readFileSync(policyPath, "utf-8"));
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      return { ...fallback, policyExists: true };
    }
    const obj = raw as Record<string, unknown>;
    const presets = obj.presets === undefined
      ? ["vibesec:default"]
      : asStringArray(obj.presets) ?? ["vibesec:default"];
    const disabled = asStringArray(obj.disabledRules) ?? [];
    const hasInlineRules = Array.isArray(obj.rules) && obj.rules.length > 0;

    const activePolicyFiles = new Set<string>();

    // v0.8.6: any number of active policy files. Empty array means none.
    const explicitMany = asStringArray(obj.activePolicyFiles);
    if (Array.isArray(obj.activePolicyFiles) && explicitMany) {
      for (const rel of explicitMany) {
        const normalized = normalizeRelPath(rel);
        if (normalized) { activePolicyFiles.add(normalized); }
      }
    } else {
      // Backward compatibility: v0.8.5 stored one normal and one taint slot.
      const activeNormalPolicyFile = normalizeRelPath(obj.activeNormalPolicyFile);
      const activeTaintPolicyFile = normalizeRelPath(obj.activeTaintPolicyFile);
      if (activeNormalPolicyFile) { activePolicyFiles.add(activeNormalPolicyFile); }
      if (activeTaintPolicyFile) { activePolicyFiles.add(activeTaintPolicyFile); }

      // Backward compatibility: old VibeSec versions stored a single activePolicyFile.
      const legacy = normalizeRelPath(obj.activePolicyFile);
      if (legacy && activePolicyFiles.size === 0) {
        activePolicyFiles.add(legacy);
      }

      if (activePolicyFiles.size === 0 && presets.includes("vibesec:default")) {
        activePolicyFiles.add("rules/default.yaml");
      }
      if (activePolicyFiles.size === 0 && presets.includes("vibesec:taint")) {
        activePolicyFiles.add("rules/taint.yaml");
      }
      if (activePolicyFiles.size > 0 && presets.includes("vibesec:taint")) {
        activePolicyFiles.add("rules/taint.yaml");
      }
    }

    return {
      policyExists: true,
      presets,
      disabledRules: new Set(disabled),
      activePolicyFiles,
      hasInlineRules,
    };
  } catch {
    return { ...fallback, policyExists: true };
  }
}

function presetForBundled(filename: string): string {
  const stem = filename.replace(/\.ya?ml$/i, "");
  return `vibesec:${stem}`;
}

function externalFileId(relPath: string): string {
  return `external/${relPath.replace(/\\/g, "/")}`;
}

function discoverWorkspacePolicyFiles(workspaceRoot: string): string[] {
  try {
    return fs.readdirSync(workspaceRoot)
      .filter((name) => name === ".vibesec.yaml" || /^\.vibesec-.+\.ya?ml$/i.test(name))
      .sort();
  } catch {
    return [];
  }
}

function discoverToolPolicyFiles(extensionPath: string): { rel: string; abs: string }[] {
  const dir = path.join(extensionPath, "rules", "policies");
  try {
    return fs.readdirSync(dir)
      .filter((name) => /\.ya?ml$/i.test(name))
      .sort()
      .map((name) => ({
        rel: path.posix.join("rules", "policies", name),
        abs: path.join(dir, name),
      }));
  } catch {
    return [];
  }
}

function isSelectorPolicyFile(absPath: string): boolean {
  try {
    const raw = yaml.load(fs.readFileSync(absPath, "utf-8"));
    return !!(raw && typeof raw === "object" && !Array.isArray(raw) && typeof (raw as Record<string, unknown>).activePolicyFile === "string");
  } catch {
    return false;
  }
}



// ── Public builder ───────────────────────────────────────────────────────────

/**
 * Builds the Rules page payload by walking:
 *   • <extensionPath>/rules/*.yaml  → bundled
 *   • <workspaceRoot>/.vibesec.yaml → custom (when the file exists)
 *   • a single placeholder entry for the design's "external" tab
 */
export function buildRulesIndex(
  extensionPath: string,
  workspaceRoot: string | undefined,
): RulesIndex {
  const files: RuleFileEntry[] = [];
  const rules: RuleEntry[] = [];
  const policyState = readWorkspacePolicyState(workspaceRoot, extensionPath);

  // ── Bundled ────────────────────────────────────────────────────────────
  const bundledDir = path.join(extensionPath, "rules");
  let bundledNames: string[] = [];
  try {
    bundledNames = fs
      .readdirSync(bundledDir)
      .filter((n) => /\.ya?ml$/i.test(n))
      .filter((n) => n === "default.yaml" || n === "taint.yaml")
      .sort();
  } catch {
    // Extension was never installed correctly — emit a zero-file index so the
    // page still renders an empty state instead of crashing.
  }
  for (const name of bundledNames) {
    const absPath = path.join(bundledDir, name);
    const fileId  = `bundled/${name}`;
    const relPath = `rules/${name}`;
    const enabled = policyState.activePolicyFiles.has(relPath);
    const parsed  = parseRulesFile(absPath, fileId, "bundled", policyState.disabledRules, enabled);
    files.push({
      id:         fileId,
      path:       relPath,
      absPath,
      source:     "bundled",
      desc:       describeBundled(name),
      updatedAt:  fileMtimeIso(absPath),
      ruleCount:  parsed.rules.length,
      severities: parsed.severities,
      enabled,
      parseError: parsed.parseError,
    });
    rules.push(...parsed.rules);
  }

  // ── Tool policy folder ───────────────────────────────────────────────
  for (const item of discoverToolPolicyFiles(extensionPath)) {
    const fileId = `custom/${item.rel}`;
    const enabled = policyState.activePolicyFiles.has(item.rel);
    const parsed = parseRulesFile(item.abs, fileId, "custom", policyState.disabledRules, enabled);
    files.push({
      id:         fileId,
      path:       item.rel,
      absPath:    item.abs,
      source:     "custom",
      desc:       "Tool policy file — stored inside VibeSec's rules/policies folder.",
      updatedAt:  fileMtimeIso(item.abs),
      ruleCount:  parsed.rules.length,
      severities: parsed.severities,
      enabled,
      parseError: parsed.parseError,
    });
    rules.push(...parsed.rules);
  }

  // Workspace-created .vibesec*.yaml files are intentionally not listed here.
  // New policies created from VibeSec are stored in the tool policy folder
  // (rules/policies) so the workspace file tree stays clean.


  return { files, rules };
}

// Hand-tuned descriptions for the bundled file rows. Today there's only
// `default.yaml`; if more bundled files ship, add one line per filename here
// rather than parsing YAML comments.
function describeBundled(filename: string): string {
  switch (filename) {
    case "default.yaml":
      return "OWASP Top 10 baseline — injection, crypto, secrets, XSS, auth, integrity.";
    case "taint.yaml":
      return "Taint analysis — tracks user input from source to dangerous sink within a file.";
    default:
      return "Bundled Semgrep rules.";
  }
}
