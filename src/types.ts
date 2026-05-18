// ── Finding ──────────────────────────────────────────────────────────────────

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
  // Whatever metadata Semgrep emits for the matched rule. Open by design so
  // VibeSec rules, Semgrep registry rules (p/owasp-top-ten, p/cwe), and any
  // future rule source can carry their full metadata through to the UI.
  metadata?: Record<string, unknown>;
  // Populated only for taint-mode findings (Sprint 7). Parsed from Semgrep's
  // `extra.dataflow_trace` — source, sink, and intermediate variable hops.
  // Absent for regular pattern-based findings.
  taint?: TaintFlow;
}

// ── Taint flow (Sprint 7) ─────────────────────────────────────────────────────

/** One step in a taint flow — a source, an intermediate variable, or a sink. */
export interface TaintLocation {
  /** Absolute path to the file holding this step. */
  filePath: string;
  /** 0-based line for VS Code, matching the Finding shape. */
  line: number;
  /** Source snippet for this step (single line, may be empty). */
  snippet: string;
}

export interface TaintFlow {
  source: TaintLocation;
  sink:   TaintLocation;
  /** Zero or more variable assignments between source and sink. */
  intermediates: TaintLocation[];
}

// ── Severity ──────────────────────────────────────────────────────────────────

export type SeverityLevel = "error" | "warning" | "info";

/** Numeric rank for minSeverity comparisons. Higher = more severe. */
export const SEVERITY_RANK: Record<SeverityLevel, number> = {
  error:   3,
  warning: 2,
  info:    1,
};

// ── Custom Rules (Semgrep-shaped) ─────────────────────────────────────────────

/**
 * A pattern clause is whatever Semgrep accepts inside a `patterns:` /
 * `pattern-either:` / `pattern-sources:` / `pattern-sinks:` array. Kept open
 * (`pattern`, `pattern-not`, `pattern-inside`, `pattern-not-inside`,
 * `pattern-regex`, `pattern-not-regex`, `metavariable-pattern`,
 * `metavariable-regex`, `focus-metavariable`, …). We don't validate the inside
 * of patterns — Semgrep does, and its errors are more helpful than ours.
 */
export type PatternClause = Record<string, unknown>;

/**
 * One custom rule, shaped exactly like a Semgrep rule. Strict on identity and
 * scan logic; permissive and lossless on everything else, so registry rules
 * and future rule sources pass through with their full data intact.
 *
 * `severity` is stored uppercase because Semgrep's rule YAML requires it
 * (e.g. `severity: ERROR`). Normalisation happens during policy validation.
 */
export interface CustomRule {
  id:        string;
  message:   string;
  severity:  string;        // uppercase: ERROR | WARNING | INFO
  languages: string[];

  // Pattern shapes — at least one is required (validated in policy.ts).
  pattern?:           string;
  patterns?:          PatternClause[];
  "pattern-either"?:  PatternClause[];
  "pattern-regex"?:   string;

  // Taint analysis (alternative to the pattern shapes above).
  mode?:              string;        // "search" (default) | "taint" | other
  "pattern-sources"?: PatternClause[];
  "pattern-sinks"?:   PatternClause[];

  // Open metadata bag — preserved verbatim from the YAML source.
  metadata?: Record<string, unknown>;

  // Pass-through for any other Semgrep-recognised field (fix, paths, options,
  // pattern-not, …). Forwarded to Semgrep without inspection.
  [key: string]: unknown;
}

// ── Policy ────────────────────────────────────────────────────────────────────

export interface SeveritySettings {
  minSeverity: SeverityLevel;
  overrides:   Record<string, SeverityLevel>;  // ruleId → overridden severity
}

export interface FilePatterns {
  include: string[];
  exclude: string[];
}

/**
 * Raw shape of .vibesec.yaml before validation.
 * Every field is `unknown` to force explicit narrowing inside policy.ts.
 */
export interface RawPolicy {
  presets?:           unknown;
  severity?:          unknown;
  rules?:             unknown;
  externalRuleFiles?: unknown;
  disabledRules?:     unknown;
  files?:             unknown;
}

/**
 * Validated, resolved, ready-to-use policy.
 * This is what scanner.ts and extension.ts receive.
 */
export interface PolicyConfig {
  presets:       string[];
  severity:      SeveritySettings;
  rules:         CustomRule[];   // inline + all external files merged + deduplicated
  disabledRules: string[];       // rule IDs disabled from the Control Center
  files:         FilePatterns;
  isDefault:     boolean;        // true when no .vibesec.yaml was found
}

// ── Prompt generation (Sprint 4) ─────────────────────────────────────────────

export type LlmProvider = "openai" | "anthropic" | "gemini" | "groq" | "custom";

export type PromptMode = "perFile" | "perVulnerability" | "perProject";

/**
 * Stable identity for a finding within a single scan. Used as a cache key
 * for per-vuln prompts. Format: "<filePath>:<startLine>:<startCol>:<ruleId>".
 */
export type FindingId = string;

export function findingId(f: Finding): FindingId {
  return `${f.filePath}:${f.startLine}:${f.startCol}:${f.ruleId}`;
}

/**
 * In-memory cache of generated prompts for the current scan.
 * Keys:
 *   - per-vuln entries:  findingId(f)
 *   - per-file entries:  "file:<absoluteFilePath>"
 *   - project entry:     "_all"
 */
export type PromptCache = Map<string, string>;

export const PROMPT_CACHE_PROJECT_KEY = "_all";
export function promptCacheFileKey(filePath: string): string {
  return `file:${filePath}`;
}
