// Shared message-protocol types for the VibeSec analysis webview.
//
// SOURCE OF TRUTH for the panel <-> extension wire format. A verbatim copy of
// these types lives in `webview/types.ts` so the React bundle compiles standalone.
// If you change anything here, mirror it there.

import { Finding, SeverityLevel } from "./types";

// ── Theme ─────────────────────────────────────────────────────────────────────

export type ThemeKind = "dark" | "light" | "hc-dark" | "hc-light";

// ── Severity ──────────────────────────────────────────────────────────────────
//
// Three tiers — exactly what the YAML policy schema supports. The design's
// "Critical" and "Medium" chips were dropped per design decisions.

export type PanelSeverity = "error" | "warning" | "info";
export type PanelSeverityLabel = "Error" | "Warning" | "Info";

export function toPanelSeverity(s: SeverityLevel): {
  severity: PanelSeverity;
  sevLabel: PanelSeverityLabel;
} {
  return s === "error"
    ? { severity: "error",   sevLabel: "Error" }
    : s === "warning"
    ? { severity: "warning", sevLabel: "Warning" }
    : { severity: "info",    sevLabel: "Info" };
}

// ── Metadata extraction (from Semgrep rule metadata bag) ──────────────────────

export interface PanelMeta {
  category:   string;
  cwe:        string;
  owasp:      string;
  confidence: string;
}

export function toPanelMeta(meta: Record<string, unknown> | undefined): PanelMeta {
  const m = meta ?? {};
  const arr = (v: unknown): string =>
    Array.isArray(v)
      ? v.filter((x): x is string => typeof x === "string").join(", ")
      : typeof v === "string"
      ? v
      : "";
  const titleCase = (v: unknown): string =>
    typeof v === "string" && v.length > 0
      ? v[0].toUpperCase() + v.slice(1).toLowerCase()
      : "";
  return {
    category:   (typeof m.category === "string" && m.category) || "—",
    cwe:        arr(m.cwe)        || "—",
    owasp:      arr(m.owasp)      || "—",
    confidence: titleCase(m.confidence) || "—",
  };
}

// ── Title prettifier ──────────────────────────────────────────────────────────
//
// Take the last dot-segment of a ruleId, replace dashes/underscores with spaces,
// sentence-case it. "vibesec.sql-injection-raw-query" -> "Sql injection raw query".

export function prettifyRuleTitle(ruleId: string): string {
  const lastSeg = ruleId.includes(".") ? ruleId.split(".").pop()! : ruleId;
  const spaced = lastSeg.replace(/[-_]+/g, " ").trim();
  if (spaced.length === 0) { return ruleId; }
  return spaced[0].toUpperCase() + spaced.slice(1);
}

// ── Panel-side finding shape (post-adapter) ───────────────────────────────────

export interface PanelTaintStep {
  /** Workspace-relative POSIX path for display. */
  path:    string;
  /** Absolute fs path — used by goToLocation. */
  absPath: string;
  /** 1-based line number for display. */
  line:    number;
  snippet: string;
}

export interface PanelTaint {
  source:        PanelTaintStep;
  sink:          PanelTaintStep;
  intermediates: PanelTaintStep[];
}

export interface PanelFinding {
  /** Stable id = findingId(f) from src/types.ts */
  id:        string;
  ruleId:    string;
  severity:  PanelSeverity;
  sevLabel:  PanelSeverityLabel;
  title:     string;
  desc:      string;
  /** Workspace-relative POSIX path. */
  path:      string;
  /** Absolute fs path — used by goToFinding. */
  absPath:   string;
  /** 1-based line number for display. */
  line:      number;
  meta:      PanelMeta;
  /** Present only for taint-mode findings (Sprint 7). */
  taint?:    PanelTaint;
}

// ── File tree node (sent to webview's FileTree component) ────────────────────

export interface PanelTreeNode {
  /** Absolute fs path — used as both id and selection key. */
  id:       string;
  type:     "file" | "folder";
  name:     string;
  /** Lower-case extension (no dot), e.g. "ts". Files only. */
  ext?:     string;
  depth:    number;
  /** Initial expanded state. */
  open:     boolean;
  /** Whether this file is scannable per current settings. Files only. */
  scannable?: boolean;
  children?: PanelTreeNode[];
}

// ── Panel state ───────────────────────────────────────────────────────────────

export type PanelStateMsg =
  | { kind: "empty" }
  | { kind: "loading"; percent: number; currentFile: string }
  | { kind: "noFindings" }
  | { kind: "error"; message: string }
  | { kind: "findings"; findings: PanelFinding[] };

// ── Wire types ────────────────────────────────────────────────────────────────

export type ExtensionToWebview =
  | { type: "init"; theme: ThemeKind; accent: "green"; density: "comfortable"; version: string }
  | { type: "workspaceTree"; tree: PanelTreeNode[]; defaultSelected: string[] }
  | { type: "stateUpdated"; state: PanelStateMsg }
  | { type: "progressUpdated"; percent: number; currentFile: string }
  | { type: "promptCopied"; scope: "vuln" | "file" | "all"; key: string }
  | { type: "themeChanged"; theme: ThemeKind }
  | { type: "toast"; message: string; tone: "info" | "warn" | "error" };

export type WebviewToExtension =
  | { type: "ready" }
  | { type: "getWorkspaceTree" }
  | { type: "openFolder" }
  | { type: "newFile" }
  | { type: "openControlCenter" }
  | { type: "scanRequested"; filePaths: string[] }
  | { type: "scanCancel" }
  | { type: "goToFinding"; findingId: string }
  | { type: "goToLocation"; absPath: string; line: number }
  | { type: "copyPromptForVuln"; findingId: string }
  | { type: "copyPromptForFile"; filePath: string }
  | { type: "copyPromptForAll" }
  | { type: "generatePrompts" };

// ── Finding -> PanelFinding adapter ───────────────────────────────────────────

export function toPanelFinding(f: Finding, workspaceRoot: string | undefined): PanelFinding {
  const { severity, sevLabel } = toPanelSeverity(f.severity);
  const meta = toPanelMeta(f.metadata);
  const id = `${f.filePath}:${f.startLine}:${f.startCol}:${f.ruleId}`;
  const path = relativePosix(f.filePath, workspaceRoot);
  const out: PanelFinding = {
    id,
    ruleId:   f.ruleId,
    severity,
    sevLabel,
    title:    prettifyRuleTitle(f.ruleId),
    desc:     f.message,
    path,
    absPath:  f.filePath,
    line:     f.startLine + 1,
    meta,
  };
  if (f.taint) {
    const step = (s: import("./types").TaintLocation): PanelTaintStep => ({
      path:    relativePosix(s.filePath, workspaceRoot),
      absPath: s.filePath,
      line:    s.line + 1,
      snippet: s.snippet,
    });
    out.taint = {
      source:        step(f.taint.source),
      sink:          step(f.taint.sink),
      intermediates: f.taint.intermediates.map(step),
    };
  }
  return out;
}

function relativePosix(absPath: string, workspaceRoot: string | undefined): string {
  if (!workspaceRoot) { return absPath.replace(/\\/g, "/"); }
  const abs = absPath.replace(/\\/g, "/");
  const root = workspaceRoot.replace(/\\/g, "/").replace(/\/+$/, "");
  if (abs === root) { return "."; }
  if (abs.startsWith(root + "/")) { return abs.slice(root.length + 1); }
  return abs;
}
