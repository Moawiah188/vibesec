import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import { logBus } from "./logBus";
import {
  CustomRule,
  FilePatterns,
  PolicyConfig,
  RawPolicy,
  SEVERITY_RANK,
  SeverityLevel,
  SeveritySettings,
} from "./types";

// ── Defaults ──────────────────────────────────────────────────────────────────

const DEFAULT_PRESETS: string[] = ["vibesec:default"];

const DEFAULT_SEVERITY: SeveritySettings = {
  minSeverity: "info",
  overrides: {},
};

const DEFAULT_FILES: FilePatterns = {
  include: [],
  exclude: [],
};

export function getDefaultPolicy(): PolicyConfig {
  return {
    presets:   DEFAULT_PRESETS.slice(),
    severity:  { ...DEFAULT_SEVERITY, overrides: {} },
    rules:     [],
    files:     { include: [], exclude: [] },
    isDefault: true,
  };
}

// ── Result type ───────────────────────────────────────────────────────────────

export type PolicyLoadResult =
  | { ok: true;  policy: PolicyConfig }
  | { ok: false; policy: PolicyConfig; errors: string[] };

// ── Type guards ───────────────────────────────────────────────────────────────

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// ── Severity helpers ──────────────────────────────────────────────────────────

const VALID_SEVERITIES = new Set<string>(["error", "warning", "info"]);

function isValidSeverity(raw: unknown): raw is string {
  return typeof raw === "string" && VALID_SEVERITIES.has(raw.toLowerCase());
}

/** Normalise to lowercase SeverityLevel; falls back to "info" for unknowns. */
function normalizeSeverity(raw: string): SeverityLevel {
  const lower = raw.toLowerCase();
  return VALID_SEVERITIES.has(lower) ? (lower as SeverityLevel) : "info";
}

// ── Section parsers ───────────────────────────────────────────────────────────

function parsePresets(raw: unknown, errors: string[]): string[] {
  if (raw === undefined || raw === null) {
    return DEFAULT_PRESETS.slice();
  }
  if (!isStringArray(raw)) {
    errors.push('"presets" must be an array of strings (e.g. ["p/owasp-top-ten"])');
    return DEFAULT_PRESETS.slice();
  }
  // Empty array is intentional — user wants custom rules only
  return raw;
}

function parseSeveritySection(raw: unknown, errors: string[]): SeveritySettings {
  if (raw === undefined || raw === null) {
    return { ...DEFAULT_SEVERITY, overrides: {} };
  }
  if (!isRecord(raw)) {
    errors.push('"severity" must be a mapping (object), not a string or array');
    return { ...DEFAULT_SEVERITY, overrides: {} };
  }

  let minSeverity: SeverityLevel = "info";
  if (raw.minSeverity !== undefined) {
    if (!isValidSeverity(raw.minSeverity)) {
      errors.push(
        `"severity.minSeverity" must be one of: "error", "warning", "info" — got "${raw.minSeverity}"`
      );
    } else {
      minSeverity = normalizeSeverity(raw.minSeverity as string);
    }
  }

  const overrides: Record<string, SeverityLevel> = {};
  if (raw.overrides !== undefined) {
    if (!isRecord(raw.overrides)) {
      errors.push('"severity.overrides" must be a mapping of ruleId to severity string');
    } else {
      for (const [ruleId, sev] of Object.entries(raw.overrides)) {
        if (!isValidSeverity(sev)) {
          errors.push(
            `"severity.overrides.${ruleId}" must be one of: "error", "warning", "info" — got "${sev}"`
          );
        } else {
          overrides[ruleId] = normalizeSeverity(sev as string);
        }
      }
    }
  }

  return { minSeverity, overrides };
}

function parseCustomRule(
  raw: unknown,
  index: number,
  errors: string[]
): CustomRule | null {
  if (!isRecord(raw)) {
    errors.push(`rules[${index}] must be a mapping (object)`);
    return null;
  }

  const ruleErrors: string[] = [];

  if (typeof raw.id !== "string" || raw.id.trim() === "") {
    ruleErrors.push(`rules[${index}].id must be a non-empty string`);
  }
  if (typeof raw.message !== "string" || raw.message.trim() === "") {
    ruleErrors.push(`rules[${index}].message must be a non-empty string`);
  }
  if (!isValidSeverity(raw.severity)) {
    ruleErrors.push(
      `rules[${index}].severity must be one of: "error", "warning", "info" — got "${raw.severity}"`
    );
  }
  if (!isStringArray(raw.languages) || raw.languages.length === 0) {
    ruleErrors.push(`rules[${index}].languages must be a non-empty array of strings`);
  }

  // Pattern-shape validation: a rule must have at least one of the recognised
  // top-level pattern shapes, OR be in taint mode with both sources and sinks.
  // Inside the patterns themselves we don't validate — Semgrep's errors are
  // more specific than anything we'd write here.
  const hasPattern       = typeof raw.pattern === "string" && raw.pattern.trim() !== "";
  const hasPatterns      = Array.isArray(raw.patterns) && raw.patterns.length > 0;
  const hasPatternEither = Array.isArray(raw["pattern-either"]) && (raw["pattern-either"] as unknown[]).length > 0;
  const hasPatternRegex  = typeof raw["pattern-regex"] === "string" && (raw["pattern-regex"] as string).trim() !== "";
  const isTaintMode      = raw.mode === "taint";
  const hasSources       = Array.isArray(raw["pattern-sources"]) && (raw["pattern-sources"] as unknown[]).length > 0;
  const hasSinks         = Array.isArray(raw["pattern-sinks"])   && (raw["pattern-sinks"]   as unknown[]).length > 0;

  if (isTaintMode) {
    if (!hasSources || !hasSinks) {
      ruleErrors.push(
        `rules[${index}] uses "mode: taint" and must define non-empty "pattern-sources" and "pattern-sinks" arrays`
      );
    }
  } else if (raw.mode === undefined || raw.mode === "search") {
    if (!hasPattern && !hasPatterns && !hasPatternEither && !hasPatternRegex) {
      ruleErrors.push(
        `rules[${index}] must have one of: "pattern", "patterns", "pattern-either", "pattern-regex", or "mode: taint" with sources/sinks`
      );
    }
  }
  // Other Semgrep modes (extract, join, …) pass through unchecked — Semgrep
  // surfaces specific errors if their structure is wrong.

  if (ruleErrors.length > 0) {
    errors.push(...ruleErrors);
    return null;
  }

  // Preserve every field from the raw YAML (fix, paths, options, mode-specific
  // pattern-* fields, metadata, …) and only override the ones we strictly
  // normalise. This is what makes the rule body lossless end-to-end: whatever
  // a Semgrep registry rule or future rule source carries reaches the temp
  // config Semgrep reads back, and reaches Finding.metadata in scanner.ts.
  const result: CustomRule = {
    ...raw,
    id:        (raw.id as string).trim(),
    message:   (raw.message as string).trim(),
    // Semgrep requires uppercase severity in rule YAML
    severity:  normalizeSeverity(raw.severity as string).toUpperCase(),
    languages: raw.languages as string[],
  } as CustomRule;

  return result;
}

function parseRulesSection(raw: unknown, errors: string[]): CustomRule[] {
  if (raw === undefined || raw === null) { return []; }
  if (!Array.isArray(raw)) {
    errors.push('"rules" must be an array of rule objects');
    return [];
  }
  const rules: CustomRule[] = [];
  for (let i = 0; i < raw.length; i++) {
    const rule = parseCustomRule(raw[i], i, errors);
    if (rule !== null) { rules.push(rule); }
  }
  return rules;
}

function parseFilesSection(raw: unknown, errors: string[]): FilePatterns {
  if (raw === undefined || raw === null) {
    return { include: [], exclude: [] };
  }
  if (!isRecord(raw)) {
    errors.push('"files" must be a mapping with optional "include" and "exclude" arrays');
    return { include: [], exclude: [] };
  }

  let include: string[] = [];
  let exclude: string[] = [];

  if (raw.include !== undefined) {
    if (!isStringArray(raw.include)) {
      errors.push('"files.include" must be an array of glob pattern strings');
    } else {
      include = raw.include;
    }
  }
  if (raw.exclude !== undefined) {
    if (!isStringArray(raw.exclude)) {
      errors.push('"files.exclude" must be an array of glob pattern strings');
    } else {
      exclude = raw.exclude;
    }
  }

  return { include, exclude };
}

// ── External rule file loading ────────────────────────────────────────────────

function loadExternalRuleFile(filePath: string, errors: string[]): CustomRule[] {
  if (!fs.existsSync(filePath)) {
    errors.push(`External rule file not found: "${filePath}"`);
    return [];
  }

  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Could not read external rule file "${filePath}": ${msg}`);
    return [];
  }

  let parsed: unknown;
  try {
    parsed = yaml.load(content);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Invalid YAML in external rule file "${filePath}": ${msg}`);
    return [];
  }

  if (!isRecord(parsed)) {
    errors.push(
      `External rule file "${filePath}" must be a YAML mapping with a top-level "rules:" array`
    );
    return [];
  }
  if (!Array.isArray(parsed.rules)) {
    errors.push(
      `External rule file "${filePath}" must have a top-level "rules:" array`
    );
    return [];
  }

  const fileErrors: string[] = [];
  const rules = parseRulesSection(parsed.rules, fileErrors);
  for (const e of fileErrors) {
    errors.push(`In file "${filePath}": ${e}`);
  }
  return rules;
}

function parseExternalRuleFiles(
  raw: unknown,
  workspaceRoot: string,
  errors: string[]
): CustomRule[] {
  if (raw === undefined || raw === null) { return []; }
  if (!isStringArray(raw)) {
    errors.push('"externalRuleFiles" must be an array of file path strings');
    return [];
  }
  const allRules: CustomRule[] = [];
  for (const relPath of raw) {
    const absPath = path.resolve(workspaceRoot, relPath);
    allRules.push(...loadExternalRuleFile(absPath, errors));
  }
  return allRules;
}

// ── Duplicate rule ID detection ───────────────────────────────────────────────

function deduplicateRules(rules: CustomRule[], errors: string[]): CustomRule[] {
  const seen = new Map<string, number>();
  const deduped: CustomRule[] = [];
  for (const rule of rules) {
    if (seen.has(rule.id)) {
      errors.push(
        `Duplicate rule id "${rule.id}" — only the first definition will be used`
      );
    } else {
      seen.set(rule.id, 1);
      deduped.push(rule);
    }
  }
  return deduped;
}

// ── Main entry point ──────────────────────────────────────────────────────────

/**
 * Load and validate .vibesec.yaml from `workspaceRoot`.
 * Always returns a usable PolicyConfig even on failure.
 * Callers should check `result.ok` to decide whether to show error messages.
 *
 * @param workspaceRoot  Absolute path to the workspace folder containing the
 *                       active file. Resolved by the caller so policy.ts stays
 *                       workspace-agnostic and testable.
 */
export function loadPolicy(workspaceRoot: string): PolicyLoadResult {
  const policyPath = path.join(workspaceRoot, ".vibesec.yaml");

  // Missing file is not an error — inform user and use defaults
  if (!fs.existsSync(policyPath)) {
    logBus.info(
      "policy",
      "No .vibesec.yaml — falling back to default policy",
      `workspaceRoot=${workspaceRoot}\npresets=${DEFAULT_PRESETS.join(", ")}`,
    );
    return {
      ok: false,
      policy: getDefaultPolicy(),
      errors: [
        `No .vibesec.yaml found in workspace root. ` +
        `Using default scan settings (${DEFAULT_PRESETS.join(", ")}).`,
      ],
    };
  }

  let content: string;
  try {
    content = fs.readFileSync(policyPath, "utf-8");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logBus.error("policy", "Could not read .vibesec.yaml", `path=${policyPath}\n${msg}`);
    return {
      ok: false,
      policy: getDefaultPolicy(),
      errors: [`Could not read .vibesec.yaml: ${msg}`],
    };
  }

  let raw: unknown;
  try {
    raw = yaml.load(content);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logBus.error("policy", "Invalid YAML syntax in .vibesec.yaml", `path=${policyPath}\n${msg}`);
    return {
      ok: false,
      policy: getDefaultPolicy(),
      errors: [`Invalid YAML syntax in .vibesec.yaml: ${msg}`],
    };
  }

  // Empty file / bare "---" produces null
  if (raw === null || raw === undefined) {
    return { ok: true, policy: getDefaultPolicy() };
  }

  if (!isRecord(raw)) {
    return {
      ok: false,
      policy: getDefaultPolicy(),
      errors: [".vibesec.yaml must be a YAML mapping (object), not a plain string or array"],
    };
  }

  const rawPolicy = raw as RawPolicy;
  const errors: string[] = [];

  const presets       = parsePresets(rawPolicy.presets, errors);
  const severity      = parseSeveritySection(rawPolicy.severity, errors);
  const inlineRules   = parseRulesSection(rawPolicy.rules, errors);
  const externalRules = parseExternalRuleFiles(rawPolicy.externalRuleFiles, workspaceRoot, errors);
  const files         = parseFilesSection(rawPolicy.files, errors);

  const mergedRules  = [...inlineRules, ...externalRules];
  const uniqueRules  = deduplicateRules(mergedRules, errors);

  // Validate that we have something to scan with
  if (presets.length === 0 && uniqueRules.length === 0) {
    errors.push(
      'No "presets" and no "rules" defined. ' +
      `Falling back to default preset (${DEFAULT_PRESETS.join(", ")}).`
    );
    presets.push(...DEFAULT_PRESETS);
  }

  // Warn if minSeverity would filter everything
  const minRank = SEVERITY_RANK[severity.minSeverity];
  if (minRank > SEVERITY_RANK["warning"]) {
    // minSeverity: error — INFO and WARNING findings will be silently dropped
    // This is intentional, but worth noting for new users
  }

  const policy: PolicyConfig = {
    presets,
    severity,
    rules:     uniqueRules,
    files,
    isDefault: false,
  };

  if (errors.length > 0) {
    logBus.warn(
      "policy",
      `Policy loaded with ${errors.length} error${errors.length !== 1 ? "s" : ""}`,
      `path=${policyPath}\n${errors.join("\n")}`,
    );
    return { ok: false, policy, errors };
  }
  logBus.info(
    "policy",
    `Policy loaded (${policy.presets.length} preset${policy.presets.length !== 1 ? "s" : ""}, ` +
      `${policy.rules.length} custom rule${policy.rules.length !== 1 ? "s" : ""})`,
    `path=${policyPath}\nminSeverity=${policy.severity.minSeverity}\n` +
      `excludeGlobs=${policy.files.exclude.length}`,
  );
  return { ok: true, policy };
}
