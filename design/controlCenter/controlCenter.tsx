import * as React from "react";
import { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Dashboard } from "./Dashboard";
import { Logs } from "./Logs";
import { Rules } from "./Rules";
import { Settings } from "./Settings";
import { onMessage, postMessage } from "./vscode";
import type {
  CcExtensionToWebview,
  ControlCenterPage,
  ControlCenterQuickAction,
  LogEvent,
  RulesIndex,
  ScanHistoryEntry,
  SettingsKey,
  SettingsState,
  SettingsValues,
  ThemeKind,
} from "./types";

// ── Theme detection ──────────────────────────────────────────────────────────
//
// VS Code drops `vscode-light`/`vscode-dark`/`vscode-high-contrast(-light)`
// classes on <body>. We sniff that synchronously on first render so the
// design tokens resolve correctly before the extension's `init` message
// arrives. Subsequent themeChanged messages keep us in sync if the user
// switches color theme while the panel is open.

function detectThemeFromBody(): ThemeKind {
  const cls = document.body.classList;
  if (cls.contains("vscode-high-contrast-light")) { return "hc-light"; }
  if (cls.contains("vscode-high-contrast"))       { return "hc-dark"; }
  if (cls.contains("vscode-light"))               { return "light"; }
  return "dark";
}

// The design ships only two palettes (dark / light); collapse the high-
// contrast variants onto the closest one.
function applyTheme(theme: ThemeKind): void {
  const dark = theme === "dark" || theme === "hc-dark";
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
}

// ── Icons (inline so CSP-safe; no external icon library) ─────────────────────

interface IconProps { className?: string; }
const stroke: React.SVGProps<SVGSVGElement> = {
  width: 16, height: 16, viewBox: "0 0 24 24", fill: "none",
  stroke: "currentColor", strokeWidth: 1.5, strokeLinecap: "round", strokeLinejoin: "round",
};

const IconDashboard: React.FC<IconProps> = ({ className }) => (
  <svg {...stroke} className={className}>
    <rect x="3" y="3" width="7" height="9" rx="1" />
    <rect x="14" y="3" width="7" height="5" rx="1" />
    <rect x="14" y="12" width="7" height="9" rx="1" />
    <rect x="3" y="16" width="7" height="5" rx="1" />
  </svg>
);
const IconRules: React.FC<IconProps> = ({ className }) => (
  <svg {...stroke} className={className}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6" />
    <path d="M9 13h6M9 17h4" />
  </svg>
);
const IconLogs: React.FC<IconProps> = ({ className }) => (
  <svg {...stroke} className={className}>
    <path d="M4 6h16M4 12h16M4 18h10" />
  </svg>
);
const IconSettings: React.FC<IconProps> = ({ className }) => (
  <svg {...stroke} className={className}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h0a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
  </svg>
);
const IconPlay: React.FC<IconProps> = ({ className }) => (
  <svg {...stroke} className={className}>
    <polygon points="5 3 19 12 5 21 5 3" fill="currentColor" stroke="none" />
  </svg>
);

interface NavEntry {
  id: ControlCenterPage;
  label: string;
  icon: React.FC<IconProps>;
}

const NAV: NavEntry[] = [
  { id: "dashboard", label: "Dashboard", icon: IconDashboard },
  { id: "rules",     label: "Rules",     icon: IconRules     },
  { id: "logs",      label: "Logs",      icon: IconLogs      },
  { id: "settings",  label: "Settings",  icon: IconSettings  },
];

const TITLES: Record<ControlCenterPage, string> = {
  dashboard: "Dashboard",
  settings:  "Settings",
  logs:      "Logs",
  rules:     "Rules",
};

// ── Components ───────────────────────────────────────────────────────────────

interface SidebarProps {
  page:    ControlCenterPage;
  setPage: (p: ControlCenterPage) => void;
  version: string;
}

const Sidebar: React.FC<SidebarProps> = ({ page, setPage, version }) => (
  <aside className="sidebar">
    <div className="brand">
      <div className="brand-mark">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <rect x="3" y="3"  width="2" height="2" fill="#101410" />
          <rect x="5" y="3"  width="2" height="2" fill="#101410" />
          <rect x="7" y="5"  width="2" height="2" fill="#101410" />
          <rect x="9" y="7"  width="2" height="2" fill="#101410" />
          <rect x="11" y="9" width="2" height="2" fill="#101410" />
          <rect x="9" y="11" width="2" height="2" fill="#101410" />
          <rect x="7" y="11" width="2" height="2" fill="#101410" />
        </svg>
      </div>
      <div>
        <div className="brand-name">VibeSec</div>
        <div className="brand-tag">control center</div>
      </div>
    </div>

    <div className="nav-section">Workspace</div>
    {NAV.map((n) => {
      const Ico = n.icon;
      return (
        <div
          key={n.id}
          className={`nav-item ${page === n.id ? "active" : ""}`}
          onClick={() => setPage(n.id)}
        >
          <Ico className="nav-icon" />
          <span>{n.label}</span>
        </div>
      );
    })}

    <div className="sidebar-footer">
      <div className="status-pill">
        <span className="dot ok" />
        <span className="mono">idle</span>
      </div>
      {version && <span className="mono sidebar-version">v{version}</span>}
    </div>
  </aside>
);

interface TopbarProps {
  page:   ControlCenterPage;
  onScan: () => void;
}

const Topbar: React.FC<TopbarProps> = ({ page, onScan }) => (
  <div className="topbar">
    <h1>{TITLES[page]}</h1>
    <span className="crumb">vibesec › {page}</span>
    <div className="topbar-actions">
      <button className="btn sm" onClick={onScan}>
        <IconPlay />
        Scan project
      </button>
    </div>
  </div>
);

const Placeholder: React.FC<{ phase: string; title: string }> = ({ phase, title }) => (
  <div className="placeholder">
    <div>
      <strong>{title}</strong>
      Lands in {phase}.
    </div>
  </div>
);

interface ToastMsg {
  id:      number;
  tone:    "info" | "warn" | "error";
  message: string;
}

const Toast: React.FC<{ toast: ToastMsg }> = ({ toast }) => (
  <div className={`toast ${toast.tone}`}>{toast.message}</div>
);

// ── App ──────────────────────────────────────────────────────────────────────

const App: React.FC = () => {
  const [theme, setTheme] = useState<ThemeKind>(() => detectThemeFromBody());
  const [page,  setPage]  = useState<ControlCenterPage>("dashboard");
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [history,  setHistory]  = useState<ScanHistoryEntry[]>([]);
  const [logs,     setLogs]     = useState<LogEvent[]>([]);
  const [rules,    setRules]    = useState<RulesIndex>({ files: [], rules: [] });
  const [version,  setVersion]  = useState<string>("");
  const [toast, setToast] = useState<ToastMsg | null>(null);
  const toastTimer = useRef<number | undefined>(undefined);

  const showToast = (tone: ToastMsg["tone"], message: string): void => {
    if (toastTimer.current !== undefined) { window.clearTimeout(toastTimer.current); }
    setToast({ id: Date.now(), tone, message });
    toastTimer.current = window.setTimeout(() => setToast(null), 3500);
  };

  useEffect(() => { applyTheme(theme); }, [theme]);

  useEffect(() => {
    const off = onMessage((msg: CcExtensionToWebview) => {
      switch (msg.type) {
        case "init":
          setTheme(msg.theme);
          setPage(msg.initialPage);
          setSettings(msg.settings);
          setHistory(msg.scanHistory);
          setLogs(msg.logs);
          setRules(msg.rules);
          setVersion(msg.version);
          break;
        case "themeChanged":
          setTheme(msg.theme);
          break;
        case "settingsUpdated":
          setSettings(msg.settings);
          break;
        case "scanHistoryUpdated":
          setHistory(msg.entries);
          break;
        case "logAppended":
          // Append + cap at 1000 to mirror the extension-side ring buffer.
          // Without the cap the in-memory log would grow unbounded across
          // long-lived panel sessions, even though the extension's ring is
          // bounded.
          setLogs((prev) => {
            const next = [...prev, msg.event];
            if (next.length > 1000) { next.splice(0, next.length - 1000); }
            return next;
          });
          break;
        case "logsCleared":
          setLogs([]);
          break;
        case "rulesUpdated":
          setRules(msg.rules);
          break;
        case "toast":
          showToast(msg.tone, msg.message);
          break;
      }
    });

    postMessage({ type: "ready" });
    return () => {
      off();
      if (toastTimer.current !== undefined) { window.clearTimeout(toastTimer.current); }
    };
  }, []);

  const runQuickAction = (action: ControlCenterQuickAction): void => {
    postMessage({ type: "runQuickAction", action });
  };

  // Two-way binding: optimistically update local state so the control feels
  // responsive, then post to the extension. The settingsUpdated message that
  // follows will reconcile if the write was rejected (e.g. invalid value).
  const setSetting = <K extends SettingsKey>(key: K, value: SettingsValues[K]): void => {
    setSettings((prev) =>
      prev ? { ...prev, values: { ...prev.values, [key]: value } } : prev,
    );
    postMessage({ type: "setSetting", key, value });
  };

  const copyAllLogs = (text: string): void => {
    // navigator.clipboard works inside the webview (CSP allows it; no scheme
    // required). Fall back to a brief toast on rejection so users notice.
    void navigator.clipboard.writeText(text).then(
      () => showToast("info", `Copied ${text.split("\n").filter(Boolean).length} lines to clipboard.`),
      (err) => showToast("error", `Copy failed: ${err instanceof Error ? err.message : String(err)}`),
    );
  };

  return (
    <div className="app">
      <Sidebar page={page} setPage={setPage} version={version} />
      <div className="main">
        <Topbar page={page} onScan={() => runQuickAction("scan")} />
        <div className="content">
          <div className="page">
            {page === "dashboard" && (
              settings
                ? (
                  <Dashboard
                    history={history}
                    settings={settings}
                    onAction={runQuickAction}
                    onClearHistory={() => postMessage({ type: "clearScanHistory" })}
                  />
                )
                : <div className="placeholder"><div><strong>Dashboard</strong>Loading…</div></div>
            )}
            {page === "settings"  && (
              settings
                ? (
                  <Settings
                    state={settings}
                    onSet={setSetting}
                    onOpenJson={() => postMessage({ type: "openSettingsJson" })}
                    onResetDefaults={() => postMessage({ type: "resetSettingsToDefaults" })}
                    onSaveApiKey={(provider, key) => postMessage({ type: "saveApiKey", provider, key })}
                    onClearApiKey={(provider) => postMessage({ type: "clearApiKey", provider })}
                    onTestApiKey={(provider) => postMessage({ type: "testApiKey", provider })}
                  />
                )
                : <div className="placeholder"><div><strong>Settings</strong>Loading…</div></div>
            )}
            {page === "logs"  && (
              <Logs
                logs={logs}
                onClear={() => postMessage({ type: "clearLogs" })}
                onCopyAll={copyAllLogs}
              />
            )}
            {page === "rules" && (
              <Rules
                index={rules}
                onOpenFile={(fileId) => postMessage({ type: "openRuleFile", fileId })}
                onRefresh={() => postMessage({ type: "refreshRules" })}
                onToggleRule={(ruleId, enabled) => postMessage({ type: "setRuleEnabled", ruleId, enabled })}
                onToggleFile={(fileId, enabled) => postMessage({ type: "setRuleFileEnabled", fileId, enabled })}
                onCreateRuleFile={() => postMessage({ type: "createCustomRuleFile" })}
                onCreatePolicyFile={(kind) => postMessage({ type: "createPolicyFile", kind })}
                onDeletePolicyFile={(fileId) => postMessage({ type: "deletePolicyFile", fileId })}
                onImportRuleFile={() => postMessage({ type: "importRuleFileFromUrl" })}
              />
            )}
          </div>
        </div>
      </div>
      {toast && <Toast toast={toast} />}
    </div>
  );
};

const rootEl = document.getElementById("root");
if (rootEl) {
  applyTheme(detectThemeFromBody());
  createRoot(rootEl).render(<App />);
}
