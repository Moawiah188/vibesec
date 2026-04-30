import * as React from "react";
import { Check, ChevronDown, ChevronRight, Copy, Eye, File as FileIcon, Wand } from "./icons";
import type { PanelFinding } from "./types";

interface Props {
  v:         PanelFinding;
  expanded:  boolean;
  onToggle:  () => void;
  onCopy:    (id: string) => void;
  copied:    boolean;
  onGoToFix: (id: string) => void;
  onOpenSource: (f: PanelFinding) => void;
}

export const VulnCard: React.FC<Props> = ({
  v,
  expanded,
  onToggle,
  onCopy,
  copied,
  onGoToFix,
  onOpenSource,
}) => {
  return (
    <div className={`vs-vuln sev-${v.severity} ${expanded ? "is-expanded" : ""}`}>
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
