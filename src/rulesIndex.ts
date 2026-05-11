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

function parseRulesFile(absPath: string, fileId: string, source: RuleSource): ParseResult {
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
  const rulesRaw = (raw as RawRuleDoc).rules;
  if (!Array.isArray(rulesRaw)) {
    // .vibesec.yaml is allowed to omit `rules:` — that's not an error, just zero rules.
    return empty;
  }

  const rules: RuleEntry[] = [];
  const tally = { error: 0, warning: 0, info: 0 };
  for (const item of rulesRaw) {
    if (!item || typeof item !== "object") { continue; }
    const r = item as RawRule;
    if (typeof r.id !== "string" || r.id.trim() === "") { continue; }
    const sev = severityFromYaml(r.severity);
    const meta = (typeof r.metadata === "object" && r.metadata !== null && !Array.isArray(r.metadata))
      ? r.metadata as Record<string, unknown>
      : undefined;
    const langs = Array.isArray(r.languages)
      ? r.languages.filter((l): l is string => typeof l === "string")
      : [];

    const mode: RuleMode = r.mode === "taint" ? "taint" : "search";
    rules.push({
      id:      `${fileId}::${r.id}`,
      ruleId:  r.id,
      file:    fileId,
      name:    prettifyTitle(r.id),
      sev,
      cat:     metadataString(meta, "category"),
      langs,
      cwe:     metadataString(meta, "cwe"),
      owasp:   metadataString(meta, "owasp"),
      conf:    confidenceToScore(meta?.confidence),
      source,
      mode,
      enabled: true,
    });
    tally[sev]++;
  }
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

  // ── Bundled ────────────────────────────────────────────────────────────
  const bundledDir = path.join(extensionPath, "rules");
  let bundledNames: string[] = [];
  try {
    bundledNames = fs
      .readdirSync(bundledDir)
      .filter((n) => /\.ya?ml$/i.test(n))
      .sort();
  } catch {
    // Extension was never installed correctly — emit a zero-file index so the
    // page still renders an empty state instead of crashing.
  }
  for (const name of bundledNames) {
    const absPath = path.join(bundledDir, name);
    const fileId  = `bundled/${name}`;
    const parsed  = parseRulesFile(absPath, fileId, "bundled");
    files.push({
      id:         fileId,
      path:       `rules/${name}`,
      absPath,
      source:     "bundled",
      desc:       describeBundled(name),
      updatedAt:  fileMtimeIso(absPath),
      ruleCount:  parsed.rules.length,
      severities: parsed.severities,
      parseError: parsed.parseError,
    });
    rules.push(...parsed.rules);
  }

  // ── Custom (workspace .vibesec.yaml) ───────────────────────────────────
  if (workspaceRoot) {
    const customAbs = path.join(workspaceRoot, ".vibesec.yaml");
    if (fs.existsSync(customAbs)) {
      const fileId = "custom/.vibesec.yaml";
      const parsed = parseRulesFile(customAbs, fileId, "custom");
      files.push({
        id:         fileId,
        path:       ".vibesec.yaml",
        absPath:    customAbs,
        source:     "custom",
        desc:       "Workspace policy — presets, severity overrides, custom rules.",
        updatedAt:  fileMtimeIso(customAbs),
        ruleCount:  parsed.rules.length,
        severities: parsed.severities,
        parseError: parsed.parseError,
      });
      rules.push(...parsed.rules);
    }
  }

  // ── External placeholder ───────────────────────────────────────────────
  // Reserved tab so the design's three-column summary (Bundled / Custom /
  // External) keeps its shape. The Rules page renders this row as a
  // disabled "coming soon" affordance — no rules attach to it in v1.
  files.push({
    id:         "external/placeholder",
    path:       "external registries",
    absPath:    null,
    source:     "external",
    desc:       "Pull packs from p/owasp-top-ten, r/python.lang.security, etc. Coming in a later sprint.",
    updatedAt:  null,
    ruleCount:  0,
    severities: { error: 0, warning: 0, info: 0 },
  });

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
