import * as React from "react";
import { useState } from "react";
import { Check, ChevronDown, Copy } from "./icons";
import type { PanelFinding } from "./types";

interface Props {
  filePath:  string;
  findings:  PanelFinding[];
  onCopyFile: (filePath: string) => void;
  copiedKey: string | null;
}

// Repurposed from the design's diff-hunks view: instead of rendering a unified
// diff, show each finding's title + the cached fix prompt as monospace text.
// The chrome (file header, copy chip, expand/collapse) is unchanged.

export const FixFileGroup: React.FC<Props> = ({
  filePath,
  findings,
  onCopyFile,
  copiedKey,
}) => {
  const [open, setOpen] = useState(true);
  const fileKey = `file:${filePath}`;
  const promptCount = findings.length;

  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: 6,
        background: "var(--surface)",
        overflow: "hidden",
      }}
    >
      <div
        onClick={() => setOpen((o) => !o)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "7px 10px",
          background: "var(--surface-2)",
          borderBottom: open ? "1px solid var(--border)" : "none",
          cursor: "pointer",
        }}
      >
        <span
          style={{
            color: "var(--text-faint)",
            transition: "transform 0.15s",
            display: "inline-flex",
            transform: open ? "none" : "rotate(-90deg)",
          }}
        >
          <ChevronDown size={11} />
        </span>
        <span
          style={{
            fontFamily: "var(--vs-mono)",
            fontSize: 11,
            color: "var(--text)",
            flex: 1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            letterSpacing: "-0.01em",
          }}
        >
          {filePath}
        </span>
        <span
          style={{
            fontFamily: "var(--vs-mono)",
            fontSize: 10.5,
            color: "var(--text-faint)",
          }}
        >
          {promptCount} {promptCount === 1 ? "fix" : "fixes"}
        </span>
        <button
          className="vs-btn-icon"
          title="Copy fix prompt for this file"
          onClick={(e) => {
            e.stopPropagation();
            onCopyFile(filePath);
          }}
          style={{ flexShrink: 0 }}
        >
          {copiedKey === fileKey ? <Check size={12} /> : <Copy size={12} />}
        </button>
      </div>

      {open && (
        <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
          <div
            style={{
              padding: "10px 12px 6px",
              borderBottom: "1px solid var(--border-soft)",
            }}
          >
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 4,
                marginBottom: 4,
              }}
            >
              {findings.map((v) => (
                <div
                  key={v.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    fontSize: 11.5,
                    color: "var(--text-muted)",
                  }}
                >
                  <span className={`vs-sev-tag sev-tag-${v.severity}`}>{v.sevLabel}</span>
                  <span style={{ color: "var(--text)" }}>{v.title}</span>
                  <span
                    style={{
                      fontFamily: "var(--vs-mono)",
                      fontSize: 10.5,
                      color: "var(--text-faint)",
                      marginLeft: "auto",
                    }}
                  >
                    :{v.line}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div className="vs-prompt-empty">
            Click the copy button above to put the ready-to-paste AI fix prompt
            for this file on your clipboard. Paste it into ChatGPT, Claude, or
            Cursor to generate the fix.
          </div>
        </div>
      )}
    </div>
  );
};
