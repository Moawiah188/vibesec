import * as fs from "fs";
import * as path from "path";
import { callLlm } from "./llmClient";
import { logBus } from "./logBus";
import { Finding, LlmProvider } from "./types";

// ── Prompt generation engine (Sprint 4) ──────────────────────────────────────
//
// Builds a structured natural-language instruction from one or more findings,
// asks the configured LLM to produce a copy-paste fix prompt, and returns the
// model's response as plain text.
//
// Three granularities are supported:
//   • per-vuln    — one model call per finding
//   • per-file    — one model call covering all findings in a single file
//   • per-project — one model call covering every finding in the scan
//
// Each public function returns a Promise<string> — the prompt text the user
// can paste into Cursor / Claude Code / ChatGPT / etc. Failures throw the
// underlying LlmClientError; the caller (extension.ts) maps those to user-
// facing notifications.

const CONTEXT_LINES_BEFORE = 5;
const CONTEXT_LINES_AFTER  = 5;

const PROVIDER_RESPONSE_BUDGET: Record<LlmProvider, {
  cap: number;
  vuln: number;
  file: number;
  project: number;
  perFileFinding: number;
  perProjectFinding: number;
}> = {
  // Keep budgets conservative so the same prompt structure works across the
  // smaller/cheaper models users commonly choose from the settings UI.
  openai:    { cap: 3_500, vuln: 1_400, file: 2_200, project: 2_700, perFileFinding: 120, perProjectFinding: 100 },
  anthropic: { cap: 3_500, vuln: 1_400, file: 2_200, project: 2_700, perFileFinding: 120, perProjectFinding: 100 },
  gemini:    { cap: 3_000, vuln: 1_300, file: 2_000, project: 2_400, perFileFinding: 100, perProjectFinding: 90 },
  groq:      { cap: 1_800, vuln: 800,   file: 1_150, project: 1_350, perFileFinding: 70,  perProjectFinding: 50 },
  custom:    { cap: 2_500, vuln: 1_200, file: 1_800, project: 2_100, perFileFinding: 90,  perProjectFinding: 80 },
};

export interface GenerateOptions {
  provider: LlmProvider;
  apiKey:   string;
  model:    string;
  baseUrl?: string;
  /** Workspace root used to make file paths relative in the prompt. Optional. */
  workspaceRoot?: string;
  /** Optional cancellation. */
  signal?: AbortSignal;
}

export async function generatePromptForVuln(
  finding: Finding,
  opts: GenerateOptions,
): Promise<string> {
  const instruction = buildVulnInstruction(finding, opts.workspaceRoot);
  logBus.info(
    "prompt",
    `Building per-vulnerability prompt (${finding.ruleId})`,
    `file=${relativize(finding.filePath, opts.workspaceRoot)}:${finding.startLine + 1}\n` +
      `provider=${opts.provider} model=${opts.model}`,
  );
  return callLlm(opts.provider, {
    apiKey: opts.apiKey,
    model:  opts.model,
    baseUrl: opts.baseUrl,
    prompt: instruction,
    maxTokens: responseTokenBudget(opts.provider, "vuln", 1),
    signal: opts.signal,
  });
}

export async function generatePromptForFile(
  filePath: string,
  findings: Finding[],
  opts: GenerateOptions,
): Promise<string> {
  if (findings.length === 0) {
    throw new Error("generatePromptForFile called with no findings.");
  }
  const instruction = buildFileInstruction(filePath, findings, opts.workspaceRoot);
  logBus.info(
    "prompt",
    `Building per-file prompt — ${findings.length} finding${findings.length !== 1 ? "s" : ""}`,
    `file=${relativize(filePath, opts.workspaceRoot)}\n` +
      `provider=${opts.provider} model=${opts.model}`,
  );
  return callLlm(opts.provider, {
    apiKey: opts.apiKey,
    model:  opts.model,
    baseUrl: opts.baseUrl,
    prompt: instruction,
    maxTokens: responseTokenBudget(opts.provider, "file", findings.length),
    signal: opts.signal,
  });
}

export async function generatePromptForProject(
  findings: Finding[],
  opts: GenerateOptions,
): Promise<string> {
  if (findings.length === 0) {
    throw new Error("generatePromptForProject called with no findings.");
  }
  const instruction = buildProjectInstruction(findings, opts.workspaceRoot);
  logBus.info(
    "prompt",
    `Building project-wide prompt — ${findings.length} finding${findings.length !== 1 ? "s" : ""}`,
    `provider=${opts.provider} model=${opts.model}`,
  );
  return callLlm(opts.provider, {
    apiKey: opts.apiKey,
    model:  opts.model,
    baseUrl: opts.baseUrl,
    prompt: instruction,
    maxTokens: responseTokenBudget(opts.provider, "project", findings.length),
    signal: opts.signal,
  });
}

// ── Instruction builders ─────────────────────────────────────────────────────

function relativize(filePath: string, workspaceRoot?: string): string {
  if (!workspaceRoot) { return filePath; }
  const rel = path.relative(workspaceRoot, filePath);
  if (rel === "" || rel.startsWith("..")) { return filePath; }
  return rel.replace(/\\/g, "/");
}

function readFileSafe(filePath: string): string | undefined {
  try { return fs.readFileSync(filePath, "utf-8"); }
  catch { return undefined; }
}

function responseTokenBudget(
  provider: LlmProvider,
  mode: "vuln" | "file" | "project",
  findingCount: number,
): number {
  const budget = PROVIDER_RESPONSE_BUDGET[provider];
  const base = mode === "vuln"
    ? budget.vuln
    : mode === "file"
      ? budget.file
      : budget.project;
  const perFinding = mode === "vuln"
    ? 0
    : mode === "file"
      ? budget.perFileFinding
      : budget.perProjectFinding;
  return Math.min(budget.cap, base + Math.max(0, findingCount - 1) * perFinding);
}

function appendRepairPromptStructure(lines: string[], scope: "single" | "file" | "project"): void {
  lines.push("");
  lines.push(`Prompt contract (${scope} scope):`);
  lines.push("  Sections: Task, Evidence, Patch Plan, Constraints, Expected Output, Verification, Self-check.");
  lines.push("  Ask for a minimal behavior-preserving patch using exact file paths, rule ids, severity, messages, and code context.");
  lines.push("  Require the concrete security property to enforce, valid imports/variables, idiomatic code, and no syntax errors.");
  lines.push("  Reject comment-only fixes, TODOs, fake placeholders, disabled warnings, cosmetic rewrites, and blind one-line substitutions.");
  lines.push("  Keep the generated prompt compact: bullets over paragraphs, no tables, no duplicate section headings, no invented finding counts.");
  lines.push("  Require tests/checks that fail before and pass after; require remaining-risk assumptions when context is incomplete.");
  if (scope !== "single") { lines.push("  Group related findings by root cause and fix highest-risk issues first."); }
}

function appendUniversalSecurityQualityBar(lines: string[]): void {
  lines.push("");
  lines.push("Universal guardrails:");
  lines.push("  - Preserve legitimate behavior; reject or safely handle malicious input; fail closed.");
  lines.push("  - Use exact VibeSec severity labels from the report: error, warning, info. Do not translate them to High/Medium/Low.");
  lines.push("  - Identify trust boundary, untrusted input, sensitive sink, and validation/sanitization/encoding.");
  lines.push("  - Rule messages are evidence, not patch instructions; choose safer native APIs when available.");
  lines.push("  - Do not invent files, APIs, line numbers, dependencies, or runnable-looking code unsupported by context.");
  lines.push("  - Patch Plan must cover every evidence bullet exactly once or as part of a named combined root-cause fix.");
  lines.push("  - Name required dependency/config/secret-rotation changes explicitly.");
}

function appendSecurityPatchQualityBar(lines: string[], scope: "single" | "file" | "project"): void {
  appendRepairPromptStructure(lines, scope);
  appendUniversalSecurityQualityBar(lines);
  lines.push("");
  lines.push("Common rules when relevant:");
  lines.push("  - Secrets: use env/secret storage and rotate exposed values; no fake safe strings.");
  lines.push("  - Passwords: use Argon2id/bcrypt/scrypt/PBKDF2/framework helpers, not raw MD5/SHA/SHA-1/SHA-256.");
  lines.push("  - Commands: prefer native APIs; if process is unavoidable use fixed executable, allowlisted args list, shell=false.");
  lines.push("  - File deletion/writes: validate inside allowed base dir, then use native filesystem APIs; do not shell out to rm/del.");
  lines.push("  - SSRF: parse URL, restrict scheme/host, resolve DNS, reject private/loopback/link-local/metadata addresses and unsafe redirects.");
  lines.push("  - Deserialization: prefer explicit data formats/schema validation; YAML requires safe_load plus shape validation.");
  lines.push("  - XSS/access/config/dependencies: use safe framework APIs, server-side authorization, secure defaults, smallest compatible change.");
  lines.push("  - Forbidden patch-plan text: subprocess.run(f\"...\"); subprocess.run(\"...\"); shell out to rm/del; bcrypt for non-password checksums; ast.literal_eval as a drop-in replacement for arbitrary code execution.");
}

function findingSpecificGuidance(finding: Finding): string[] {
  const haystack = `${finding.ruleId} ${finding.message} ${finding.snippet}`.toLowerCase();
  const out: string[] = [];

  if (/password|hash|md5|sha-?1|sha256|crypto|credential/.test(haystack)) {
    out.push("Password/crypto guidance: if this is password storage, replace fast hashes with a password hashing helper; if this is a non-password checksum, explain that distinction and keep the narrow checksum use.");
  }
  if (/command|os\.system|popen|subprocess|exec\(|shell/.test(haystack)) {
    out.push("Command execution guidance: do not blindly replace shell strings with subprocess. Prefer native APIs for the operation (for example pathlib.Path.unlink for file deletion). If a child process is unavoidable, use a fixed executable, allowlisted arguments, args as a list, shell=False, check=True, and validate any user-controlled path or argument first.");
    out.push("Forbidden command-fix examples: do not suggest subprocess.run(f\"...{user_input}...\", shell=False); do not shell out to rm/del for file deletion; do not pass one command string to subprocess when arguments should be a list.");
  }
  if (/eval|exec\(|code injection/.test(haystack)) {
    out.push("Code execution guidance: remove eval/exec. Use a parser for the specific data format, such as json.loads for JSON or ast.literal_eval only for Python literals.");
    out.push("Forbidden code-execution fix examples: do not claim ast.literal_eval is a safe replacement for an arbitrary code-execution feature; redesign around explicit allowed operations or structured input.");
  }
  if (/yaml|pickle|deserial/.test(haystack)) {
    out.push("Deserialization guidance: never deserialize untrusted objects. Prefer JSON/schema validation only when the expected wire format is JSON; otherwise define an explicit safe migration format or reject untrusted serialized input. If YAML is required, use yaml.safe_load and validate the resulting shape.");
  }
  if (/ssrf|requests|get\(|url|http|metadata|loopback/.test(haystack)) {
    out.push("SSRF guidance: validate and normalize URLs before requests; allow only http/https when intended, resolve DNS, and block localhost, loopback, private ranges, link-local, and cloud metadata IPs.");
  }
  if (/\bsql\b|database|db\.|cursor|select\s+.+from|insert\s+into|update\s+.+set|delete\s+from/.test(haystack)) {
    out.push("SQL guidance: use parameterized queries/placeholders or safe ORM APIs. Do not build SQL with f-strings, concatenation, format(), or template strings.");
  }
  if (/path|traversal|open\(|filename|file/.test(haystack)) {
    out.push("File path guidance: normalize paths, enforce a base directory, reject traversal and absolute paths, and prefer allowlisted filenames or generated server-side names. For deletion or writes, use safe filesystem APIs after the path is proven inside the allowed directory.");
  }
  if (/secret|api[_ -]?key|token|password/.test(haystack)) {
    out.push("Secret guidance: remove hardcoded secrets, load from secret storage/environment variables, and say that already-exposed credentials must be rotated.");
  }
  if (/debug|flask|cors|configuration/.test(haystack)) {
    out.push("Configuration guidance: set safe production defaults in code/config and make insecure development-only settings explicit and isolated.");
  }

  return Array.from(new Set(out));
}

function appendFindingSpecificGuidance(lines: string[], findings: Finding[]): void {
  const guidance = Array.from(new Set(findings.flatMap(findingSpecificGuidance)));
  if (guidance.length === 0) { return; }
  lines.push("");
  lines.push("Finding-specific guidance:");
  for (const item of guidance) {
    lines.push(`  - ${item}`);
  }
}

function sourceLineAtFinding(finding: Finding): string {
  const source = readFileSafe(finding.filePath);
  if (source) {
    const line = source.split(/\r?\n/)[finding.startLine]?.trim();
    if (line) { return line; }
  }
  return finding.snippet.split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? "";
}

function evidenceMessage(message: string): string {
  const first = message
    .split(/(?<=[.!?])\s+/)
    .find((sentence) => {
      const lower = sentence.toLowerCase();
      return !(
        lower.includes("replace with") ||
        lower.includes("use ") ||
        lower.includes("migrate to") ||
        lower.includes("switch to")
      );
    });
  return (first ?? message).trim();
}

function compactEvidenceLine(finding: Finding, workspaceRoot?: string): string {
  const snippet = sourceLineAtFinding(finding);
  const taintNote = finding.taint
    ? `; taint source L${finding.taint.source.line + 1} -> sink L${finding.taint.sink.line + 1}`
    : "";
  return `- ${relativize(finding.filePath, workspaceRoot)}:${finding.startLine + 1} ${finding.severity} ${finding.ruleId}: ${evidenceMessage(finding.message)}${taintNote}${snippet ? `; code=\`${snippet}\`` : ""}`;
}

function appendExactEvidenceContract(
  lines: string[],
  findings: Finding[],
  workspaceRoot?: string,
): void {
  lines.push("");
  lines.push("Exact evidence bullets:");
  lines.push("  Copy these bullets into the generated prompt's Evidence section. Do not convert them to a table, translate severities, invent counts, or hide separate findings.");
  for (const finding of findings) {
    lines.push(`  ${compactEvidenceLine(finding, workspaceRoot)}`);
  }
}

function metadataValue(meta: Record<string, unknown> | undefined, key: string): string {
  if (!meta) { return ""; }
  const value = meta[key];
  if (Array.isArray(value)) {
    return value
      .filter((item): item is string => typeof item === "string" && item.trim() !== "")
      .join(", ");
  }
  return typeof value === "string" ? value.trim() : "";
}

function appendPolicyRuleReference(lines: string[], findings: Finding[]): void {
  lines.push("");
  lines.push("Policy/rule reference:");
  lines.push("  Treat rule metadata as policy evidence. If metadata and context conflict, preserve stricter safe behavior and state the assumption.");
  lines.push("  Do not blindly reuse remediation wording from rule messages.");

  const seen = new Set<string>();
  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.severity}:${finding.message}`;
    if (seen.has(key)) { continue; }
    seen.add(key);

    const parts: string[] = [
      `rule=${finding.ruleId}`,
      `severity=${finding.severity}`,
    ];
    const category = metadataValue(finding.metadata, "category");
    const cwe = metadataValue(finding.metadata, "cwe");
    const owasp = metadataValue(finding.metadata, "owasp");
    const confidence = metadataValue(finding.metadata, "confidence");
    const references = metadataValue(finding.metadata, "references");
    if (category) { parts.push(`category=${category}`); }
    if (cwe) { parts.push(`cwe=${cwe}`); }
    if (owasp) { parts.push(`owasp=${owasp}`); }
    if (confidence) { parts.push(`confidence=${confidence}`); }
    if (references) { parts.push(`references=${references}`); }
    lines.push(`  - ${parts.join("; ")}; message=${evidenceMessage(finding.message)}`);
  }
}

/**
 * Returns a small block of source lines around a finding, with line numbers
 * prepended. Falls back to the finding's own snippet if the file can't be
 * read (e.g. it has been deleted between scan and prompt).
 */
function getContextBlock(finding: Finding): string {
  const source = readFileSafe(finding.filePath);
  if (!source) {
    return finding.snippet.trim() || "(source unavailable)";
  }
  const lines = source.split(/\r?\n/);
  const start = Math.max(0, finding.startLine - CONTEXT_LINES_BEFORE);
  const end   = Math.min(lines.length - 1, finding.endLine + CONTEXT_LINES_AFTER);
  const width = String(end + 1).length;
  const out: string[] = [];
  for (let i = start; i <= end; i++) {
    const lineNo  = String(i + 1).padStart(width, " ");
    const marker  = i >= finding.startLine && i <= finding.endLine ? ">" : " ";
    out.push(`${marker} ${lineNo} | ${lines[i] ?? ""}`);
  }
  return out.join("\n");
}

function buildVulnInstruction(finding: Finding, workspaceRoot?: string): string {
  const fileRel = relativize(finding.filePath, workspaceRoot);
  const lineNum = finding.startLine + 1;
  const context = getContextBlock(finding);

  const out: string[] = [
    "You are a senior application security engineer helping a developer fix a vulnerability.",
    "Produce a single fix-prompt that the developer can paste into an AI coding assistant (Cursor, Claude Code, ChatGPT, etc.) to get a correct, minimal patch.",
    "",
    "Vulnerability details:",
    `  • File:     ${fileRel}`,
    `  • Line:     ${lineNum}`,
    `  • Rule:     ${finding.ruleId}`,
    `  • Severity: ${finding.severity}`,
    `  • Issue:    ${evidenceMessage(finding.message)}`,
  ];

  appendSecurityPatchQualityBar(out, "single");
  appendFindingSpecificGuidance(out, [finding]);
  appendPolicyRuleReference(out, [finding]);
  appendExactEvidenceContract(out, [finding], workspaceRoot);

  if (finding.taint) {
    out.push("");
    out.push("Data flow (taint analysis — source → sink):");
    out.push(`  Source: line ${finding.taint.source.line + 1} — ${finding.taint.source.snippet || "(no snippet)"}`);
    for (let i = 0; i < finding.taint.intermediates.length; i++) {
      const iv = finding.taint.intermediates[i];
      out.push(`  Step ${i + 1}: line ${iv.line + 1} — ${iv.snippet || "(no snippet)"}`);
    }
    out.push(`  Sink:   line ${finding.taint.sink.line + 1} — ${finding.taint.sink.snippet || "(no snippet)"}`);
  }

  out.push("");
  out.push("Code context (the offending lines are marked with `>`):");
  out.push("```");
  out.push(context);
  out.push("```");
  out.push("");
  out.push("Your output must be the final repair prompt, using clear section headings:");
  out.push("  1. Task");
  out.push("  2. Evidence");
  out.push("  3. Required Fix");
  out.push("  4. Constraints");
  out.push("  5. Expected Output");
  out.push("  6. Verification");
  out.push("  7. Self-check");
  out.push("Use compact bullets, not tables. Copy the exact evidence bullet above into the Evidence section.");
  if (finding.taint) {
    out.push("The Required Fix section must identify where to validate, sanitize, encode, parameterize, or otherwise constrain data along the source-to-sink path.");
  } else {
    out.push("The Required Fix section must state the concrete behavior the patch must enforce.");
  }
  out.push("The Expected Output section must ask for corrected code or a patch, not just explanation.");
  out.push("The Self-check section must ask the coding assistant to confirm the fix is not comment-only, placeholder-only, or still using the vulnerable behavior unsafely.");
  out.push("");
  out.push("Respond with the prompt only — no preamble, no closing remarks. The user will copy it verbatim.");
  return out.join("\n");
}

function buildFileInstruction(
  filePath: string,
  findings: Finding[],
  workspaceRoot?: string,
): string {
  const fileRel = relativize(filePath, workspaceRoot);
  const lines: string[] = [
    "You are a senior application security engineer helping a developer fix multiple vulnerabilities in a single file.",
    `Produce one consolidated fix-prompt the developer can paste into an AI coding assistant to repair every issue listed below in the file ${fileRel}.`,
    "",
    `Findings in ${fileRel}:`,
  ];
  appendSecurityPatchQualityBar(lines, "file");
  appendFindingSpecificGuidance(lines, findings);
  appendPolicyRuleReference(lines, findings);
  appendExactEvidenceContract(lines, findings, workspaceRoot);
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    lines.push("");
    lines.push(`Finding ${i + 1}:`);
    lines.push(`  • Line:     ${f.startLine + 1}`);
    lines.push(`  • Rule:     ${f.ruleId}`);
    lines.push(`  • Severity: ${f.severity}`);
    lines.push(`  • Issue:    ${evidenceMessage(f.message)}`);
    if (f.taint) {
      lines.push(`  • Taint:    source L${f.taint.source.line + 1} → sink L${f.taint.sink.line + 1}`);
    }
    lines.push("  • Context:");
    lines.push("    ```");
    lines.push(indent(getContextBlock(f), "    "));
    lines.push("    ```");
  }
  lines.push("");
  lines.push("Your output must be one final repair prompt, using clear section headings:");
  lines.push("  1. Task");
  lines.push("  2. Findings and Evidence");
  lines.push("  3. Patch Plan");
  lines.push("  4. Implementation Constraints");
  lines.push("  5. Expected Output");
  lines.push("  6. Verification");
  lines.push("  7. Self-check");
  lines.push("Use compact bullets, not tables. Copy every exact evidence bullet above into the Findings and Evidence section.");
  lines.push("The Patch Plan must group findings that share the same root cause into one coherent fix.");
  lines.push("Each Patch Plan bullet must include one concrete required fix and the affected rule id(s). Avoid generic summaries.");
  lines.push("The Expected Output section must ask for corrected runnable code or a patch/diff, plus any tests/config/dependency changes.");
  lines.push("The Self-check section must ask the coding assistant to confirm that no fix is comment-only, placeholder-only, or still using the vulnerable behavior unsafely.");
  lines.push("");
  lines.push("Respond with the prompt only — no preamble, no closing remarks.");
  return lines.join("\n");
}

function buildProjectInstruction(
  findings: Finding[],
  workspaceRoot?: string,
): string {
  // Group by file so the prompt is scannable
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = byFile.get(f.filePath) ?? [];
    arr.push(f);
    byFile.set(f.filePath, arr);
  }

  const lines: string[] = [
    "You are a senior application security engineer reviewing a static-analysis report covering an entire project.",
    "Produce one consolidated fix-prompt the developer can paste into an AI coding assistant to repair every issue across every file listed below.",
    "",
    `Total findings: ${findings.length} across ${byFile.size} file${byFile.size !== 1 ? "s" : ""}.`,
    "",
  ];
  appendSecurityPatchQualityBar(lines, "project");
  appendFindingSpecificGuidance(lines, findings);
  appendPolicyRuleReference(lines, findings);
  appendExactEvidenceContract(lines, findings, workspaceRoot);

  let fileIndex = 1;
  for (const [filePath, fileFindings] of byFile.entries()) {
    const fileRel = relativize(filePath, workspaceRoot);
    lines.push(`File ${fileIndex}: ${fileRel} (${fileFindings.length} finding${fileFindings.length !== 1 ? "s" : ""})`);
    fileIndex++;
    for (let i = 0; i < fileFindings.length; i++) {
      const f = fileFindings[i];
      const taintNote = f.taint
        ? ` · taint: src L${f.taint.source.line + 1} → sink L${f.taint.sink.line + 1}`
        : "";
      lines.push(`  - Line ${f.startLine + 1} · ${f.severity.toUpperCase()} · ${f.ruleId}${taintNote}`);
      lines.push(`      ${evidenceMessage(f.message)}`);
      lines.push("      Context:");
      lines.push("      ```");
      lines.push(indent(getContextBlock(f), "      "));
      lines.push("      ```");
    }
    lines.push("");
  }

  lines.push("Your output must be one final project repair prompt, using clear section headings:");
  lines.push("  1. Task");
  lines.push("  2. Risk Priorities");
  lines.push("  3. Findings and Evidence");
  lines.push("  4. Patch Plan by File");
  lines.push("  5. Implementation Constraints");
  lines.push("  6. Expected Output");
  lines.push("  7. Verification");
  lines.push("  8. Self-check");
  lines.push("Use compact bullets, not tables. Copy every exact evidence bullet above into the Findings and Evidence section.");
  lines.push("The Risk Priorities section must tell the coding assistant to fix exploitable/high-impact issues first.");
  lines.push("The Patch Plan by File section must combine overlapping findings into coherent root-cause fixes.");
  lines.push("Each Patch Plan bullet must include one concrete required fix and the affected rule id(s). Avoid generic summaries.");
  lines.push("The Expected Output section must ask for corrected runnable code or a patch/diff, plus any tests/config/dependency changes.");
  lines.push("The Self-check section must ask the coding assistant to confirm that no fix is comment-only, placeholder-only, or still using vulnerable behavior unsafely.");
  lines.push("");
  lines.push("Respond with the prompt only — no preamble, no closing remarks.");
  return lines.join("\n");
}

function indent(text: string, prefix: string): string {
  return text.split("\n").map((l) => prefix + l).join("\n");
}
