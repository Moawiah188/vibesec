// ── Finding (Sprint 1 — unchanged) ───────────────────────────────────────────

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

// ── Severity ──────────────────────────────────────────────────────────────────

export type SeverityLevel = "error" | "warning" | "info";

/** Numeric rank for minSeverity comparisons. Higher = more severe. */
export const SEVERITY_RANK: Record<SeverityLevel, number> = {
  error:   3,
  warning: 2,
  info:    1,
};

// ── Custom Rules (Semgrep-shaped) ─────────────────────────────────────────────

export interface CustomRuleMetadata {
  category?:   string;
  cwe?:        string;
  confidence?: string;
  [key: string]: string | undefined;  // extensible
}

/** A single pattern clause used inside a `patterns` array. */
export interface PatternClause {
  pattern?:              string;
  "pattern-not"?:        string;
  "pattern-inside"?:     string;
  "pattern-not-inside"?: string;
  "pattern-regex"?:      string;
}

/**
 * One custom rule definition, shaped after the real Semgrep rule schema.
 * `severity` is stored uppercase because Semgrep's inline YAML requires it
 * (e.g. `severity: ERROR`). Normalisation happens during policy validation.
 */
export interface CustomRule {
  id:        string;
  message:   string;
  severity:  string;        // uppercase: ERROR | WARNING | INFO
  languages: string[];
  pattern?:  string;        // single-pattern shorthand
  patterns?: PatternClause[];
  metadata?: CustomRuleMetadata;
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
  files?:             unknown;
}

/**
 * Validated, resolved, ready-to-use policy.
 * This is what scanner.ts and extension.ts receive.
 */
export interface PolicyConfig {
  presets:   string[];
  severity:  SeveritySettings;
  rules:     CustomRule[];   // inline + all external files merged + deduplicated
  files:     FilePatterns;
  isDefault: boolean;        // true when no .vibesec.yaml was found
}

// ── Prompt generation (Sprint 4) ─────────────────────────────────────────────

export type LlmProvider = "openai" | "anthropic" | "gemini";

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
