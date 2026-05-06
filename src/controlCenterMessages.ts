// Wire-protocol types for the VibeSec Control Center webview.
//
// SOURCE OF TRUTH for the control-center <-> extension messages. A verbatim
// copy lives in `webview/controlCenter/types.ts` so the React bundle compiles
// standalone (matches the existing `panelMessages.ts` / `webview/types.ts`
// pattern). If you change anything here, mirror it there.

import type { LogEvent } from "./logBus";
import type { ScanHistoryEntry } from "./scanHistoryStore";
import type { RulesIndex } from "./rulesIndex";
import type { LlmProvider, PromptMode } from "./types";
import type { ThemeKind } from "./panelMessages";

export type ControlCenterPage = "dashboard" | "settings" | "logs" | "rules";

export type ControlCenterQuickAction =
  | "scan"            // run vibesec.scanWorkspace
  | "openPanel"       // focus the Analysis sidebar view
  | "openPolicy"      // run vibesec.openPolicyFile
  | "reloadPolicy";   // run vibesec.reloadPolicy

// ── Settings ─────────────────────────────────────────────────────────────────
//
// Keys are unprefixed (we always read/write under the "vibesec" config root).
// Value types mirror the contributes.configuration entries in package.json.
// If you add a setting there, add it here and in webview/controlCenter/types.ts.

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

/** Snapshot of current values plus the package.json defaults for "Reset" copy. */
export interface SettingsState {
  values:   SettingsValues;
  defaults: SettingsValues;
  /** Where writes will land — drives the "scoped to workspace" footer copy. */
  scope: "workspace" | "global";
}

// ── Dashboard / scan history ─────────────────────────────────────────────────
//
// Re-export the stored shape so the webview only imports from this file. The
// `LogEvent`-style discriminated unions below also live here for the same
// reason — one place for the protocol means one place to keep in sync.

export type { ScanHistoryEntry } from "./scanHistoryStore";
export type { LogEvent, LogEventType, LogLevel } from "./logBus";
export type { RuleEntry, RuleFileEntry, RuleSource, RulesIndex } from "./rulesIndex";

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
