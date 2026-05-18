import * as React from "react";
import { Check, ChevronDown, ChevronRight, Copy, Eye, File as FileIcon, Wand } from "./icons";
import type { PanelFinding, PanelTaintStep } from "./types";

interface Props {
  v:         PanelFinding;
  expanded:  boolean;
  onToggle:  () => void;
  onCopy:    (id: string) => void;
  copied:    boolean;
  onGoToFix: (id: string) => void;
  onOpenSource: (f: PanelFinding) => void;
  /** Jump to an arbitrary file:line — used by taint flow rows. */
  onJumpToLocation: (absPath: string, line: number) => void;
}

export const VulnCard: React.FC<Props> = ({
  v,
  expanded,
  onToggle,
  onCopy,
  copied,
  onGoToFix,
  onOpenSource,
  onJumpToLocation,
}) => {
  return (
    <div
      className={`vs-vuln sev-${v.severity} ${expanded ? "is-expanded" : ""}`}
      title="Double-click to open this finding in the source file"
      onDoubleClick={(e) => {
        e.stopPropagation();
        onOpenSource(v);
      }}
    >
      <div className="vs-vuln-head" onClick={onToggle}>
        <div className={`vs-vuln-sev sev-${v.severity}`} />
        <div className="vs-vuln-body">
          <div className="vs-vuln-meta-row">
            <span className={`vs-sev-tag sev-tag-${v.severity}`}>{v.sevLabel}</span>
            <span className="vs-cwe" title={v.meta.cwe}>{v.ruleId}</span>
          </div>
          <div className="vs-vuln-title">{v.title}</div>
          <div className="vs-vuln-desc">{v.desc}</div>
          <div
            className="vs-vuln-path"
            title={`${v.path}:${v.line}`}
            onClick={(e) => {
              e.stopPropagation();
              onOpenSource(v);
            }}
          >
            <FileIcon size={10} />
            <span className="vs-path-text">{v.path}</span>
            <span className="vs-path-line">:{v.line}</span>
          </div>
        </div>
        <div className="vs-vuln-actions" onClick={(e) => e.stopPropagation()}>
          <button
            className="vs-btn-icon"
            title="Copy fix prompt"
            onClick={() => onCopy(v.id)}
          >
            {copied ? <Check size={13} /> : <Copy size={13} />}
          </button>
          <button
            className="vs-btn-icon"
            title={expanded ? "Collapse" : "Expand"}
            onClick={onToggle}
          >
            {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </button>
        </div>
      </div>

      {/* TaintFlow appears below */}
      {expanded && (
        <div className="vs-fix">
          <div className="vs-fix-head">
            <Eye size={11} />
            <span>Details</span>
          </div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "1px",
              background: "var(--border-soft)",
              borderBottom: "1px solid var(--border-soft)",
            }}
          >
            {[
              { label: "Category", value: v.meta.category },
              { label: "Confidence", value: v.meta.confidence },
              { label: "CWE", value: v.meta.cwe },
              { label: "OWASP", value: v.meta.owasp },
            ].map(({ label, value }) => (
              <div key={label} style={{ background: "var(--bg-deep)", padding: "7px 10px" }}>
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 600,
                    textTransform: "uppercase",
                    letterSpacing: "0.07em",
                    color: "var(--text-faint)",
                    marginBottom: 3,
                  }}
                >
                  {label}
                </div>
                <div
                  style={{
                    fontSize: 11.5,
                    color: "var(--text)",
                    lineHeight: 1.35,
                  }}
                >
                  {value}
                </div>
              </div>
            ))}
          </div>
          {v.taint && (
            <TaintFlow taint={v.taint} onJump={onJumpToLocation} />
          )}
          <div
            style={{
              padding: "9px 10px",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <Wand size={11} />
            <span style={{ fontSize: 11.5, color: "var(--text-muted)", flex: 1 }}>
              Fix available in the Full Fix tab
            </span>
            <button
              className="vs-btn"
              style={{
                height: 24,
                padding: "0 10px",
                fontSize: 11.5,
                background: "var(--accent-soft)",
                borderColor: "var(--accent-border)",
                color: "var(--accent)",
              }}
              onClick={(e) => {
                e.stopPropagation();
                onGoToFix(v.id);
              }}
            >
              View Fix →
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// ── Data flow block (Sprint 7 — taint findings) ──────────────────────────────
//
// Rendered inside an expanded VulnCard when the underlying finding came from a
// `mode: taint` rule. Each step is click-to-jump using the goToLocation wire
// message. Severity-aligned border on the left echoes the parent card's
// callout treatment so the visual language stays consistent.

interface TaintFlowProps {
  taint: NonNullable<PanelFinding["taint"]>;
  onJump: (absPath: string, line: number) => void;
}

const TaintFlow: React.FC<TaintFlowProps> = ({ taint, onJump }) => {
  return (
    <div
      style={{
        padding: "10px 12px",
        borderBottom: "1px solid var(--border-soft)",
        background: "var(--bg-deep)",
      }}
    >
      <div
        style={{
          fontSize: 10,
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: "0.07em",
          color: "var(--text-faint)",
          marginBottom: 6,
          display: "flex",
          alignItems: "center",
          gap: 6,
        }}
      >
        <span>Data flow</span>
        <span
          style={{
            fontFamily: "var(--vs-mono)",
            fontSize: 9.5,
            color: "var(--accent)",
            background: "var(--accent-soft)",
            border: "1px solid var(--accent-border)",
            borderRadius: 3,
            padding: "1px 5px",
            letterSpacing: "0.04em",
          }}
        >
          TAINT
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        <TaintStepRow label="Source" step={taint.source} onJump={onJump} />
        {taint.intermediates.map((iv, i) => (
          <TaintStepRow
            key={`${iv.absPath}:${iv.line}:${i}`}
            label={`Step ${i + 1}`}
            step={iv}
            onJump={onJump}
            faint
          />
        ))}
        <TaintStepRow label="Sink" step={taint.sink} onJump={onJump} emphasize />
      </div>
    </div>
  );
};

interface TaintStepRowProps {
  label: string;
  step: PanelTaintStep;
  onJump: (absPath: string, line: number) => void;
  emphasize?: boolean;
  faint?: boolean;
}

const TaintStepRow: React.FC<TaintStepRowProps> = ({ label, step, onJump, emphasize, faint }) => {
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onJump(step.absPath, step.line);
      }}
      title={`Open ${step.path}:${step.line}`}
      style={{
        all: "unset",
        display: "grid",
        gridTemplateColumns: "60px 1fr auto",
        gap: 8,
        alignItems: "center",
        padding: "5px 7px",
        border: "1px solid var(--border-soft)",
        borderLeft: emphasize
          ? "2px solid var(--sev-critical)"
          : "2px solid var(--border)",
        borderRadius: 4,
        background: "var(--surface)",
        cursor: "pointer",
        opacity: faint ? 0.85 : 1,
      }}
    >
      <span
        style={{
          fontFamily: "var(--vs-mono)",
          fontSize: 10,
          color: emphasize ? "var(--sev-critical)" : "var(--text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          fontWeight: 600,
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontFamily: "var(--vs-mono)",
          fontSize: 11,
          color: "var(--text)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {step.snippet || step.path}
      </span>
      <span
        style={{
          fontFamily: "var(--vs-mono)",
          fontSize: 10,
          color: "var(--text-faint)",
        }}
      >
        {step.path}:{step.line}
      </span>
    </button>
  );
};
