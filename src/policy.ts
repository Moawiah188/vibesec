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
    rules:         [],
    disabledRules: [],
    files:         { include: [], exclude: [] },
    isDefault:     true,
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


function parseDisabledRules(raw: unknown, errors: string[]): string[] {
  if (raw === undefined || raw === null) { return []; }
  if (!isStringArray(raw)) {
    errors.push('"disabledRules" must be an array of rule id strings');
    return [];
  }
  return Array.from(new Set(raw.map((r) => r.trim()).filter((r) => r.length > 0)));
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


interface SelectorPolicyEntry {
  rel: string;
  kind: "normal" | "taint" | "custom";
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.map((v) => v.trim()).filter((v) => v.length > 0)));
}

function rawString(raw: Record<string, unknown>, key: string): string | null {
  const value = raw[key];
  return typeof value === "string" && value.trim() !== "" ? value.trim().replace(/\\/g, "/") : null;
}

function rawStringArray(raw: Record<string, unknown>, key: string): string[] {
  const value = raw[key];
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function looksLikeVibeSecPolicy(raw: Record<string, unknown>): boolean {
  return ["presets", "severity", "disabledRules", "externalRuleFiles", "files", "activePolicyKind", "activePolicyFiles", "activeNormalPolicyFile", "activeTaintPolicyFile"].some((k) => k in raw);
}

function resolveSelectorPath(activeRel: string, workspaceRoot: string, extensionRoot?: string): string | null {
  const normalized = activeRel.replace(/\\/g, "/");
  if (path.isAbsolute(normalized)) { return normalized; }
  if (normalized.startsWith("rules/policies/") || normalized.startsWith("rules/")) {
    if (!extensionRoot) { return null; }
    const abs = path.resolve(extensionRoot, ...normalized.split("/"));
    const allowedRulesDir = path.resolve(extensionRoot, "rules");
    if (!abs.startsWith(allowedRulesDir + path.sep) && abs !== allowedRulesDir) { return null; }
    return abs;
  }
  const abs = path.resolve(workspaceRoot, normalized);
  if (!abs.startsWith(workspaceRoot + path.sep) && abs !== workspaceRoot) { return null; }
  return abs;
}

function rawPolicyFromSelectorEntry(entry: SelectorPolicyEntry, workspaceRoot: string, extensionRoot: string | undefined, errors: string[]): Record<string, unknown> | null {
  if (entry.rel === "rules/default.yaml") {
    return { presets: ["vibesec:default"] };
  }
  if (entry.rel === "rules/taint.yaml") {
    return { presets: ["vibesec:taint"] };
  }
  const abs = resolveSelectorPath(entry.rel, workspaceRoot, extensionRoot);
  if (!abs) {
    errors.push(`Policy path is not allowed or cannot be resolved: ${entry.rel}`);
    return null;
  }
  if (!fs.existsSync(abs)) {
    errors.push(`Active ${entry.kind} policy file not found: ${entry.rel}`);
    return null;
  }
  try {
    const loaded = yaml.load(fs.readFileSync(abs, "utf-8"));
    if (!isRecord(loaded)) {
      errors.push(`Active ${entry.kind} policy file must be a YAML mapping: ${entry.rel}`);
      return null;
    }
    // A raw Semgrep rule file has only top-level rules:. Treat it as a policy
    // that contributes custom rules. A full VibeSec policy is preserved.
    if (Array.isArray(loaded.rules) && !looksLikeVibeSecPolicy(loaded)) {
      return { presets: [], rules: loaded.rules };
    }
    return loaded;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Could not load active ${entry.kind} policy file ${entry.rel}: ${msg}`);
    return null;
  }
}

function mergeFilePatterns(rawFiles: unknown[]): FilePatterns {
  const include: string[] = [];
  const exclude: string[] = [];
  for (const item of rawFiles) {
    if (!isRecord(item)) { continue; }
    if (Array.isArray(item.include)) {
      include.push(...item.include.filter((v): v is string => typeof v === "string"));
    }
    if (Array.isArray(item.exclude)) {
      exclude.push(...item.exclude.filter((v): v is string => typeof v === "string"));
    }
  }
  return { include: uniqueStrings(include), exclude: uniqueStrings(exclude) };
}

function mergeSelectorPolicies(selector: Record<string, unknown>, docs: Record<string, unknown>[]): Record<string, unknown> {
  const all = [...docs, selector];
  const presets: string[] = [];
  const rules: unknown[] = [];
  const externalRuleFiles: string[] = [];
  const disabledRules: string[] = [];
  const fileSections: unknown[] = [];
  let severity: unknown = undefined;

  for (const doc of all) {
    presets.push(...rawStringArray(doc, "presets"));
    externalRuleFiles.push(...rawStringArray(doc, "externalRuleFiles"));
    disabledRules.push(...rawStringArray(doc, "disabledRules"));
    if (Array.isArray(doc.rules)) { rules.push(...doc.rules); }
    if (doc.files !== undefined) { fileSections.push(doc.files); }
    if (doc.severity !== undefined) { severity = doc.severity; }
  }

  const merged: Record<string, unknown> = {
    presets: uniqueStrings(presets),
    rules,
    externalRuleFiles: uniqueStrings(externalRuleFiles),
    disabledRules: uniqueStrings(disabledRules),
    files: mergeFilePatterns(fileSections),
  };
  if (severity !== undefined) { merged.severity = severity; }
  return merged;
}

function selectorKindFromRel(rel: string, rawKind?: unknown): "normal" | "taint" | "custom" {
  if (rawKind === "taint") { return "taint"; }
  if (rawKind === "normal" || rawKind === "default") { return "normal"; }
  if (rel === "rules/default.yaml" || /(^|\/)normal[-_]/i.test(rel)) { return "normal"; }
  if (rel === "rules/taint.yaml" || /(^|\/)taint[-_]/i.test(rel)) { return "taint"; }
  return "custom";
}

function hasSelectorPolicyFields(raw: Record<string, unknown>): boolean {
  return Array.isArray(raw.activePolicyFiles) ||
    typeof raw.activeNormalPolicyFile === "string" ||
    typeof raw.activeTaintPolicyFile === "string" ||
    typeof raw.activePolicyFile === "string";
}

function selectorEntriesFromRaw(raw: Record<string, unknown>): SelectorPolicyEntry[] {
  const entries: SelectorPolicyEntry[] = [];

  // v0.8.6: the workspace selector can hold any number of active policy files.
  // Empty array is meaningful: scan with zero policy files and return zero findings.
  const many = rawStringArray(raw, "activePolicyFiles");
  if (Array.isArray(raw.activePolicyFiles)) {
    for (const rel of uniqueStrings(many.map((v) => v.replace(/\\/g, "/")))) {
      entries.push({ rel, kind: selectorKindFromRel(rel) });
    }
    return entries;
  }

  // Backward compatibility with v0.8.5 two-slot selector.
  const normal = rawString(raw, "activeNormalPolicyFile");
  const taint = rawString(raw, "activeTaintPolicyFile");
  if (normal) { entries.push({ rel: normal, kind: "normal" }); }
  if (taint) { entries.push({ rel: taint, kind: "taint" }); }

  // Backward compatibility with v0.8.4 and earlier.
  const legacy = rawString(raw, "activePolicyFile");
  if (entries.length === 0 && legacy) {
    entries.push({ rel: legacy, kind: selectorKindFromRel(legacy, raw.activePolicyKind) });
  }
  return entries;
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
export function loadPolicy(workspaceRoot: string, extensionRoot?: string): PolicyLoadResult {
  let policyPath = path.join(workspaceRoot, ".vibesec.yaml");

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

  // .vibesec.yaml may act as a selector for any number of active policy
  // files. v0.8.6 supports mixing multiple normal and taint policies together.
  // An empty activePolicyFiles array is intentional and means "scan with no
  // policies" instead of silently falling back to bundled defaults.
  if (isRecord(raw)) {
    const selector = raw as Record<string, unknown>;
    if (hasSelectorPolicyFields(selector)) {
      const entries = selectorEntriesFromRaw(selector);
      const selectorErrors: string[] = [];
      const docs: Record<string, unknown>[] = [];
      for (const entry of entries) {
        const doc = rawPolicyFromSelectorEntry(entry, workspaceRoot, extensionRoot, selectorErrors);
        if (doc) { docs.push(doc); }
      }
      if (selectorErrors.length > 0) {
        return {
          ok: false,
          policy: getDefaultPolicy(),
          errors: selectorErrors,
        };
      }
      raw = mergeSelectorPolicies(selector, docs);
    }
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
  const disabledRules = parseDisabledRules(rawPolicy.disabledRules, errors);
  const files         = parseFilesSection(rawPolicy.files, errors);

  const mergedRules  = [...inlineRules, ...externalRules];
  const uniqueRules  = deduplicateRules(mergedRules, errors);

  // A policy with zero presets and zero rules is valid in v0.8.6.
  // It means the user intentionally turned every policy file OFF, so scans
  // should return zero findings instead of silently running default.yaml.

  // Warn if minSeverity would filter everything
  const minRank = SEVERITY_RANK[severity.minSeverity];
  if (minRank > SEVERITY_RANK["warning"]) {
    // minSeverity: error — INFO and WARNING findings will be silently dropped
    // This is intentional, but worth noting for new users
  }

  const policy: PolicyConfig = {
    presets,
    severity,
    rules:         uniqueRules,
    disabledRules,
    files,
    isDefault:     false,
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
