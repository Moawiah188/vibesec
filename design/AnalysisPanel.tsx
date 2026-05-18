import * as React from "react";
import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Bug,
  Check,
  Copy,
  Lightning,
  Plus,
  Refresh,
  Folder,
  Settings,
  Shield,
  ShieldCheck,
  Wand,
} from "./icons";
import { FileTree } from "./FileTree";
import { FixFileGroup } from "./FixFileGroup";
import { SegmentedTabs } from "./SegmentedTabs";
import { VulnCard } from "./VulnCard";
import { postMessage } from "./vscode";
import type {
  PanelFinding,
  PanelSeverity,
  PanelStateMsg,
  PanelTreeNode,
} from "./types";

interface Props {
  state:    PanelStateMsg;
  tree:     PanelTreeNode[];
  selected: Set<string>;
  onSelectionChange: (s: Set<string>) => void;
  logoUri:  string;
  version:  string;
}

type Tab = "results" | "fullfix";
type Filter = "all" | PanelSeverity;

// Section primitive --------------------------------------------------------

const SectionLabel: React.FC<{
  children:  React.ReactNode;
  count?:    number | null;
  action?:   React.ReactNode;
}> = ({ children, count, action }) => (
  <div className="vs-section-label">
    <span>
      {children}
      {count != null && (
        <span className="vs-count" style={{ marginLeft: 6 }}>{count}</span>
      )}
    </span>
    {action}
  </div>
);

// Analyze CTA --------------------------------------------------------------

const AnalyzeButton: React.FC<{
  disabled: boolean;
  loading:  boolean;
  progress: number;
  onClick:  () => void;
}> = ({ disabled, loading, progress, onClick }) => {
  if (loading) {
    return (
      <button className="vs-cta-btn is-loading">
        <span
          className="vs-dot"
          style={{
            width: 6,
            height: 6,
            borderRadius: 999,
            background: "var(--accent)",
            animation: "vs-pulse 1.2s ease-in-out infinite",
          }}
        />
        <span>Analyzing… {Math.round(progress)}%</span>
      </button>
    );
  }
  return (
    <button
      className={`vs-cta-btn ${disabled ? "is-disabled" : ""}`}
      disabled={disabled}
      onClick={onClick}
    >
      <Lightning size={13} />
      <span>Analyze</span>
    </button>
  );
};

// Main panel ---------------------------------------------------------------

export const AnalysisPanel: React.FC<Props> = ({
  state,
  tree,
  selected,
  onSelectionChange,
  logoUri,
  version,
}) => {
  const [tab, setTab] = useState<Tab>("results");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [toast, setToast] = useState<string | null>(null);

  // Convert state into the small slice each section needs ------------------
  const isLoading  = state.kind === "loading";
  const isError    = state.kind === "error";
  const isEmpty    = state.kind === "empty";
  const isClean    = state.kind === "noFindings";
  const isFindings = state.kind === "findings";
  const findings: PanelFinding[] = isFindings ? state.findings : [];

  const counts = useMemo(
    () => ({
      all:     findings.length,
      error:   findings.filter((f) => f.severity === "error").length,
      warning: findings.filter((f) => f.severity === "warning").length,
      info:    findings.filter((f) => f.severity === "info").length,
    }),
    [findings],
  );

  const filtered = useMemo(
    () => (filter === "all" ? findings : findings.filter((f) => f.severity === filter)),
    [filter, findings],
  );

  // Group by file for the Full Fix tab -------------------------------------
  const byFile = useMemo(() => {
    const groups = new Map<string, PanelFinding[]>();
    for (const f of findings) {
      const arr = groups.get(f.path) ?? [];
      arr.push(f);
      groups.set(f.path, arr);
    }
    return Array.from(groups.entries()); // [filePath, findings[]]
  }, [findings]);

  // Toast helper -----------------------------------------------------------
  const showToast = (msg: string): void => {
    setToast(msg);
    setTimeout(() => setToast(null), 1500);
  };

  // Listen for promptCopied messages (relayed via window.message) ----------
  useEffect(() => {
    const onMsg = (event: MessageEvent): void => {
      const data = event.data;
      if (data && typeof data === "object" && data.type === "promptCopied") {
        const key =
          data.scope === "vuln"
            ? data.key
            : data.scope === "file"
            ? `file:${data.key}`
            : "all";
        setCopiedKey(key);
        showToast(
          data.scope === "all"
            ? "Project prompt copied"
            : data.scope === "file"
            ? "File prompt copied"
            : "Fix prompt copied",
        );
        setTimeout(() => setCopiedKey(null), 1400);
      } else if (data && typeof data === "object" && data.type === "toast") {
        showToast(data.message);
      }
    };
    window.addEventListener("message", onMsg);
    return () => window.removeEventListener("message", onMsg);
  }, []);

  // Actions ----------------------------------------------------------------
  const onAnalyze = (): void => {
    if (selected.size === 0 || isLoading) { return; }
    postMessage({ type: "scanRequested", filePaths: Array.from(selected) });
  };

  const onCopyVuln = (id: string): void => {
    postMessage({ type: "copyPromptForVuln", findingId: id });
  };
  const onCopyFile = (filePath: string): void => {
    postMessage({ type: "copyPromptForFile", filePath });
  };
  const onCopyAll = (): void => {
    postMessage({ type: "copyPromptForAll" });
  };
  const onOpenSource = (f: PanelFinding): void => {
    postMessage({ type: "goToFinding", findingId: f.id });
  };
  const onJumpToLocation = (absPath: string, line: number): void => {
    postMessage({ type: "goToLocation", absPath, line });
  };

  const canAnalyze = selected.size > 0 && !isLoading;
  const loadingPercent = isLoading ? state.percent : 0;
  const loadingFile    = isLoading ? state.currentFile : "";

  return (
    <div className="vs-panel" style={{ position: "relative" }}>
      <div className="vs-side">
        <div className="vs-side-header">
          <span>VibeSec — Analysis</span>
          <div className="vs-actions">
            <button
              className="vs-btn-icon"
              title="Refresh file tree"
              onClick={() => postMessage({ type: "getWorkspaceTree" })}
            >
              <Refresh size={13} />
            </button>
            <button
              className="vs-btn-icon"
              title="Open folder"
              onClick={() => postMessage({ type: "openFolder" })}
            >
              <Folder size={13} />
            </button>
            <button
              className="vs-btn-icon"
              title="Open Control Center"
              onClick={() => postMessage({ type: "openControlCenter" })}
            >
              <Settings size={13} />
            </button>
            <button
              className="vs-btn-icon"
              title={
                isFindings
                  ? "Generate AI fix prompts for every finding"
                  : "Run a scan first to generate prompts"
              }
              disabled={!isFindings}
              style={!isFindings ? { opacity: 0.4, cursor: "not-allowed" } : undefined}
              onClick={() => postMessage({ type: "generatePrompts" })}
            >
              <Wand size={13} />
            </button>
          </div>
        </div>

        <div className="vs-side-body">
          {/* Header */}
          <div className="vs-an-header">
            <div className="vs-an-titlerow">
              {logoUri && <img className="vs-an-logo" src={logoUri} alt="" />}
              <span className="vs-an-title">Analysis</span>
              {version && <span className="vs-an-version">v{version}</span>}
            </div>
            <div className="vs-an-sub">
              Scan source for vulnerabilities and generate ready-to-paste fix prompts.
            </div>
          </div>

          {/* Files */}
          <div className="vs-section">
            <SectionLabel
              count={selected.size || null}
              action={
                <span
                  style={{
                    fontFamily: "var(--vs-mono)",
                    fontSize: 10,
                    color: "var(--text-faint)",
                    textTransform: "none",
                    letterSpacing: "0.02em",
                    fontWeight: 400,
                  }}
                >
                  workspace
                </span>
              }
            >
              Files
            </SectionLabel>
            <FileTree
              tree={tree}
              selected={selected}
              onSelectionChange={onSelectionChange}
            />
          </div>

          {/* CTA */}
          <div className="vs-cta">
            <AnalyzeButton
              disabled={!canAnalyze}
              loading={isLoading}
              progress={loadingPercent}
              onClick={onAnalyze}
            />
            {isLoading && (
              <>
                <div className="vs-progress">
                  <div
                    className="vs-progress-bar"
                    style={{ width: `${loadingPercent}%` }}
                  />
                </div>
                <div className="vs-progress-meta">
                  <span
                    style={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      maxWidth: "70%",
                    }}
                  >
                    ↳ {loadingFile}
                  </span>
                  <span>{Math.round(loadingPercent)}%</span>
                </div>
              </>
            )}
          </div>

          {/* Error */}
          {isError && (
            <div className="vs-error">
              <span className="vs-error-icon">
                <AlertTriangle size={15} />
              </span>
              <div style={{ flex: 1 }}>
                <strong>Scan failed</strong>
                <p>{state.message}</p>
                <div className="vs-error-actions">
                  <button className="vs-btn" onClick={onAnalyze}>
                    <Refresh size={11} /> Retry
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Results section */}
          {(isFindings || isLoading) && (
            <>
              <div className="vs-section" style={{ marginTop: 18 }}>
                <SectionLabel>Output</SectionLabel>
                <SegmentedTabs<Tab>
                  value={tab}
                  onChange={setTab}
                  options={[
                    {
                      value: "results",
                      label: "Results",
                      count: isLoading ? null : findings.length,
                      icon: <Bug size={11} />,
                    },
                    {
                      value: "fullfix",
                      label: "Full Fix",
                      count: isLoading ? null : byFile.length,
                      icon: <Wand size={11} />,
                    },
                  ]}
                />
              </div>

              {isLoading && (
                <>
                  <div className="vs-load-status">
                    <span className="vs-dot" />
                    <span>Analyzing — {loadingFile}</span>
                  </div>
                  <div
                    style={{
                      padding: "0 14px",
                      display: "flex",
                      flexDirection: "column",
                      gap: 8,
                    }}
                  >
                    {[1, 2, 3].map((i) => (
                      <div
                        key={i}
                        style={{
                          border: "1px solid var(--border)",
                          borderRadius: 6,
                          padding: 12,
                          background: "var(--surface)",
                        }}
                      >
                        <div className="vs-skel" style={{ height: 8, width: "30%", marginBottom: 8 }} />
                        <div className="vs-skel" style={{ height: 12, width: "85%", marginBottom: 6 }} />
                        <div className="vs-skel" style={{ height: 10, width: "60%" }} />
                      </div>
                    ))}
                  </div>
                </>
              )}

              {isFindings && tab === "results" && (
                <>
                  <div
                    style={{
                      padding: "10px 14px 0",
                      display: "flex",
                      gap: 4,
                      flexWrap: "wrap",
                    }}
                  >
                    {(
                      [
                        { v: "all",     label: "All",     c: counts.all },
                        { v: "error",   label: "Error",   c: counts.error },
                        { v: "warning", label: "Warning", c: counts.warning },
                        { v: "info",    label: "Info",    c: counts.info },
                      ] as const
                    )
                      .filter((o) => o.c > 0 || o.v === "all")
                      .map((o) => (
                        <button
                          key={o.v}
                          onClick={() => setFilter(o.v as Filter)}
                          className="vs-btn"
                          style={{
                            height: 22,
                            padding: "0 8px",
                            fontSize: 11,
                            background:
                              filter === o.v ? "var(--accent-soft)" : "transparent",
                            borderColor:
                              filter === o.v ? "var(--accent-border)" : "var(--border)",
                            color: filter === o.v ? "var(--accent)" : "var(--text-muted)",
                          }}
                        >
                          {o.label}
                          <span
                            style={{
                              fontFamily: "var(--vs-mono)",
                              fontSize: 10,
                              opacity: 0.7,
                            }}
                          >
                            {o.c}
                          </span>
                        </button>
                      ))}
                  </div>

                  <div className="vs-results-list">
                    {filtered.map((v) => (
                      <VulnCard
                        key={v.id}
                        v={v}
                        expanded={!!expanded[v.id]}
                        onToggle={() =>
                          setExpanded((e) => ({ ...e, [v.id]: !e[v.id] }))
                        }
                        onCopy={onCopyVuln}
                        copied={copiedKey === v.id}
                        onGoToFix={() => setTab("fullfix")}
                        onOpenSource={onOpenSource}
                        onJumpToLocation={onJumpToLocation}
                      />
                    ))}
                    {filtered.length === 0 && (
                      <div className="vs-empty" style={{ marginTop: 12 }}>
                        <div className="vs-empty-icon"><ShieldCheck size={14} /></div>
                        <div className="vs-empty-text">
                          <strong>No findings at this severity</strong>
                          <p>Try a broader filter or rescan after recent changes.</p>
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}

              {isFindings && tab === "fullfix" && (
                <div className="vs-patchroot">
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      padding: "8px 10px",
                      background: "var(--surface)",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                      fontSize: 11.5,
                      color: "var(--text-muted)",
                    }}
                  >
                    <Wand size={13} />
                    <span>
                      <strong style={{ color: "var(--text)" }}>
                        {findings.length} fix prompt{findings.length === 1 ? "" : "s"}
                      </strong>{" "}
                      across {byFile.length} file{byFile.length === 1 ? "" : "s"}
                    </span>
                    <button
                      className="vs-btn"
                      style={{
                        marginLeft: "auto",
                        height: 22,
                        padding: "0 8px",
                        fontSize: 11,
                        background: "var(--accent-soft)",
                        borderColor: "var(--accent-border)",
                        color: "var(--accent)",
                      }}
                      title="Pre-generate AI fix prompts for every finding"
                      onClick={() => postMessage({ type: "generatePrompts" })}
                    >
                      <Wand size={12} /> Generate
                    </button>
                    <button
                      className="vs-btn"
                      style={{
                        height: 22,
                        padding: "0 8px",
                        fontSize: 11,
                      }}
                      onClick={onCopyAll}
                    >
                      {copiedKey === "all" ? <Check size={12} /> : <Copy size={12} />}{" "}
                      Copy all
                    </button>
                  </div>

                  {byFile.map(([filePath, fs]) => (
                    <FixFileGroup
                      key={filePath}
                      filePath={filePath}
                      findings={fs}
                      onCopyFile={onCopyFile}
                      copiedKey={copiedKey}
                    />
                  ))}
                </div>
              )}
            </>
          )}

          {/* Empty state */}
          {isEmpty && (
            <div
              className="vs-section"
              style={{ marginTop: 22, marginBottom: 22 }}
            >
              <div
                className="vs-empty"
                style={{
                  flexDirection: "column",
                  alignItems: "stretch",
                  textAlign: "left",
                  padding: 18,
                }}
              >
                <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <div className="vs-empty-icon"><Shield size={16} /></div>
                  <div className="vs-empty-text">
                    <strong>Ready when you are</strong>
                    <p>
                      Pick files or a folder above, then run Analyze. VibeSec scans
                      using your <code>.vibesec.yaml</code> policy and bundled
                      OWASP-style rules.
                    </p>
                  </div>
                </div>
                <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
                  <button
                    className="vs-btn"
                    style={{ flex: 1 }}
                    onClick={() => postMessage({ type: "getWorkspaceTree" })}
                  >
                    <Plus size={12} /> Refresh files
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* No findings */}
          {isClean && (
            <div className="vs-section" style={{ marginTop: 22, marginBottom: 22 }}>
              <div
                className="vs-empty"
                style={{
                  flexDirection: "column",
                  alignItems: "stretch",
                  textAlign: "left",
                  padding: 18,
                }}
              >
                <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <div className="vs-empty-icon"><ShieldCheck size={16} /></div>
                  <div className="vs-empty-text">
                    <strong>No security issues found</strong>
                    <p>Your last scan came back clean. Nice.</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Status bar */}
        <div className="vs-status">
          <span className="vs-status-item">
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: 999,
                background:
                  isError
                    ? "var(--sev-critical)"
                    : isLoading
                    ? "var(--accent)"
                    : "var(--green)",
              }}
            />
            {isLoading ? "scanning" : isError ? "error" : "ready"}
          </span>
          <span className="vs-status-item">
            findings <span style={{ color: "var(--text)" }}>{findings.length}</span>
          </span>
          <span className="vs-spacer" />
          {version && <span className="vs-status-item">VibeSec {version}</span>}
        </div>

        {toast && (
          <div className="vs-toast">
            <Check size={12} />
            <span>{toast}</span>
          </div>
        )}
      </div>
    </div>
  );
};
