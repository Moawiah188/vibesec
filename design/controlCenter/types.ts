// Verbatim copy of the wire types from src/controlCenterMessages.ts.
// Kept in sync by hand — if you change one, change the other.

export type ThemeKind = "dark" | "light" | "hc-dark" | "hc-light";

export type ControlCenterPage = "dashboard" | "settings" | "logs" | "rules";

export type ControlCenterQuickAction =
  | "scan"
  | "openPanel"
  | "openPolicy"
  | "reloadPolicy";

export type LlmProvider = "openai" | "anthropic" | "gemini";
export type PromptMode = "perFile" | "perVulnerability" | "perProject";

export interface SettingsValues {
  semgrepPath:           string;
  fileExtensions:        string;
  autoScanOnSave:        boolean;
  showInlineDecorations: boolean;
  openPanelOnScan:       boolean;
  llmProvider:           LlmProvider;
  llmModel:              string;
  promptMode:            PromptMode;
}

export type SettingsKey = keyof SettingsValues;

export interface SettingsState {
  values:   SettingsValues;
  defaults: SettingsValues;
  scope: "workspace" | "global";
}

// ── Dashboard / scan history ─────────────────────────────────────────────────

export interface ScanHistoryEntry {
  ts:           number;
  filesScanned: number;
  filesSkipped: number;
  duration:     number;
  findings:     { error: number; warning: number; info: number };
  trigger:      "manual" | "onSave" | "selection";
}

// ── Logs ─────────────────────────────────────────────────────────────────────

export type LogEventType = "scan" | "prompt" | "skip" | "semgrep" | "policy" | "api" | "other";
export type LogLevel = "info" | "warn" | "error";

export interface LogEvent {
  t:       string;
  type:    LogEventType;
  level:   LogLevel;
  msg:     string;
  detail?: string;
}

// ── Rules ────────────────────────────────────────────────────────────────────

export type RuleSource = "bundled" | "custom" | "external";
export type RuleMode = "search" | "taint";
export type Severity = "error" | "warning" | "info";

export interface RuleEntry {
  id:      string;
  ruleId:  string;
  file:    string;
  name:    string;
  sev:     Severity;
  cat:     string;
  langs:   string[];
  cwe:     string;
  owasp:   string;
  conf:    number;
  source:  RuleSource;
  mode:    RuleMode;
  enabled: boolean;
}

export interface RuleFileEntry {
  id:           string;
  path:         string;
  absPath:      string | null;
  source:       RuleSource;
  desc:         string;
  updatedAt:    string | null;
  ruleCount:    number;
  severities:   { error: number; warning: number; info: number };
  parseError?:  string;
}

export interface RulesIndex {
  files: RuleFileEntry[];
  rules: RuleEntry[];
}

export type CcExtensionToWebview =
  | {
      type: "init";
      theme: ThemeKind;
      initialPage: ControlCenterPage;
      settings: SettingsState;
      scanHistory: ScanHistoryEntry[];
      logs: LogEvent[];
      rules: RulesIndex;
      version: string;
    }
  | { type: "themeChanged"; theme: ThemeKind }
  | { type: "settingsUpdated"; settings: SettingsState }
  | { type: "scanHistoryUpdated"; entries: ScanHistoryEntry[] }
  | { type: "logAppended"; event: LogEvent }
  | { type: "logsCleared" }
  | { type: "rulesUpdated"; rules: RulesIndex }
  | { type: "toast"; message: string; tone: "info" | "warn" | "error" };

export type CcWebviewToExtension =
  | { type: "ready" }
  | { type: "runQuickAction"; action: ControlCenterQuickAction }
  | { type: "setSetting"; key: SettingsKey; value: SettingsValues[SettingsKey] }
  | { type: "openSettingsJson" }
  | { type: "resetSettingsToDefaults" }
  | { type: "clearScanHistory" }
  | { type: "clearLogs" }
  | { type: "refreshRules" }
  | { type: "openRuleFile"; fileId: string };
