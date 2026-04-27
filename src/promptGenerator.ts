import * as fs from "fs";
import * as path from "path";
import { callLlm } from "./llmClient";
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

export interface GenerateOptions {
  provider: LlmProvider;
  apiKey:   string;
  model:    string;
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
  return callLlm(opts.provider, {
    apiKey: opts.apiKey,
    model:  opts.model,
    prompt: instruction,
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
  return callLlm(opts.provider, {
    apiKey: opts.apiKey,
    model:  opts.model,
    prompt: instruction,
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
  return callLlm(opts.provider, {
    apiKey: opts.apiKey,
    model:  opts.model,
    prompt: instruction,
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

  return [
    "You are a senior application security engineer helping a developer fix a vulnerability.",
    "Produce a single fix-prompt that the developer can paste into an AI coding assistant (Cursor, Claude Code, ChatGPT, etc.) to get a correct, minimal patch.",
    "",
    "Vulnerability details:",
    `  • File:     ${fileRel}`,
    `  • Line:     ${lineNum}`,
    `  • Rule:     ${finding.ruleId}`,
    `  • Severity: ${finding.severity}`,
    `  • Issue:    ${finding.message}`,
    "",
    "Code context (the offending lines are marked with `>`):",
    "```",
    context,
    "```",
    "",
    "Your output must:",
    "  1. Briefly explain *why* the code is unsafe (1–2 sentences).",
    "  2. State the exact change to make, in plain language.",
    "  3. Show a corrected code snippet using a fenced code block.",
    "  4. Note any follow-up checks the developer should run (tests, dependency updates).",
    "",
    "Respond with the prompt only — no preamble, no closing remarks. The user will copy it verbatim.",
  ].join("\n");
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
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    lines.push("");
    lines.push(`Finding ${i + 1}:`);
    lines.push(`  • Line:     ${f.startLine + 1}`);
    lines.push(`  • Rule:     ${f.ruleId}`);
    lines.push(`  • Severity: ${f.severity}`);
    lines.push(`  • Issue:    ${f.message}`);
    lines.push("  • Context:");
    lines.push("    ```");
    lines.push(indent(getContextBlock(f), "    "));
    lines.push("    ```");
  }
  lines.push("");
  lines.push("Your output must:");
  lines.push(`  1. Open with one short sentence summarizing the issues in ${fileRel}.`);
  lines.push("  2. Provide a numbered list of fixes — one bullet per finding — each with: the change to make and a corrected code snippet.");
  lines.push("  3. End with any follow-up checks (tests, regenerate locks, rotate secrets) the developer should run.");
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

  let fileIndex = 1;
  for (const [filePath, fileFindings] of byFile.entries()) {
    const fileRel = relativize(filePath, workspaceRoot);
    lines.push(`File ${fileIndex}: ${fileRel} (${fileFindings.length} finding${fileFindings.length !== 1 ? "s" : ""})`);
    fileIndex++;
    for (let i = 0; i < fileFindings.length; i++) {
      const f = fileFindings[i];
      lines.push(`  - Line ${f.startLine + 1} · ${f.severity.toUpperCase()} · ${f.ruleId}`);
      lines.push(`      ${f.message}`);
      lines.push("      Context:");
      lines.push("      ```");
      lines.push(indent(getContextBlock(f), "      "));
      lines.push("      ```");
    }
    lines.push("");
  }

  lines.push("Your output must:");
  lines.push("  1. Open with a one-paragraph summary of the riskiest themes (e.g. injection, secrets, weak crypto).");
  lines.push("  2. Group fixes by file, with a numbered list of changes per file. Each item: the change in plain language plus a corrected code snippet.");
  lines.push("  3. Recommend follow-up actions for the developer (running tests, rotating credentials, updating dependencies).");
  lines.push("");
  lines.push("Respond with the prompt only — no preamble, no closing remarks.");
  return lines.join("\n");
}

function indent(text: string, prefix: string): string {
  return text.split("\n").map((l) => prefix + l).join("\n");
}
