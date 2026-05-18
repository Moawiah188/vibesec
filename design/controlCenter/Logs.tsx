import * as React from "react";
import { useMemo, useState } from "react";
import type { LogEvent, LogEventType, LogLevel } from "./types";

// Filters: "all" plus the seven LogEventType variants and the three LogLevel
// variants. Defined statically so the segmented buttons render in a stable
// order independent of which event types happen to appear in the buffer.

const TYPE_FILTERS: ReadonlyArray<"all" | LogEventType> = [
  "all", "scan", "prompt", "skip", "semgrep", "policy", "api", "other",
];
const LEVEL_FILTERS: ReadonlyArray<"all" | LogLevel> = ["all", "info", "warn", "error"];

const stroke: React.SVGProps<SVGSVGElement> = {
  width: 13, height: 13, viewBox: "0 0 24 24", fill: "none",
  stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round", strokeLinejoin: "round",
};

const IconSearch: React.FC = () => (
  <svg {...stroke}>
    <circle cx={11} cy={11} r={7} />
    <path d="M21 21l-4.3-4.3" />
  </svg>
);

const IconCopy: React.FC = () => (
  <svg {...stroke}>
    <rect x={9} y={9} width={11} height={11} rx={2} />
    <path d="M5 15V5a2 2 0 0 1 2-2h10" />
  </svg>
);

const IconTrash: React.FC = () => (
  <svg {...stroke}>
    <path d="M3 6h18" />
    <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
  </svg>
);
const IconLatest: React.FC = () => (
  <svg {...stroke}>
    <path d="M12 5v14" />
    <path d="M18 13l-6 6-6-6" />
    <path d="M5 5h14" />
  </svg>
);

// ── Helpers ──────────────────────────────────────────────────────────────────

function timeOf(iso: string): string {
  // ISO timestamps look like "2026-04-30T22:14:07.512Z" — slice out HH:MM:SS.
  // Parsing through Date() to honor the user's local timezone gives the right
  // experience for someone debugging "what just happened?" on the Logs page.
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) { return iso.slice(11, 19); }
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function levelColor(level: LogLevel): string {
  if (level === "error") { return "var(--sev-error)"; }
  if (level === "warn")  { return "var(--sev-warning)"; }
  return "var(--text-muted)";
}

// ── Summary stat card (matches the design's SummaryStat) ─────────────────────

interface SummaryStatProps {
  label: string;
  value: number;
  sub:   string;
  tone?: "error" | "warn" | "info";
}

const SummaryStat: React.FC<SummaryStatProps> = ({ label, value, sub, tone }) => {
  const toneColor =
    tone === "error" ? "var(--sev-error)" :
    tone === "warn"  ? "var(--sev-warning)" :
    "var(--text)";
  return (
    <div className="card" style={{ padding: "10px 14px" }}>
      <div className="mono faint" style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
      <div className="row" style={{ alignItems: "baseline", gap: 8, marginTop: 2 }}>
        <span className="tnum" style={{ fontSize: 22, fontWeight: 600, color: toneColor }}>{value}</span>
        <span className="mono faint" style={{ fontSize: 10.5 }}>{sub}</span>
      </div>
    </div>
  );
};

// ── Page ─────────────────────────────────────────────────────────────────────

interface LogsProps {
  logs:      LogEvent[];
  onClear:   () => void;
  onCopyAll: (text: string) => void;
}

export const Logs: React.FC<LogsProps> = ({ logs, onClear, onCopyAll }) => {
  const [q,        setQ]        = useState("");
  const [type,     setType]     = useState<"all" | LogEventType>("all");
  const [level,    setLevel]    = useState<"all" | LogLevel>("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  // Show newest first: the design's table sorts old → new but for a debugging
  // surface that updates live, top-of-list = most recent feels right.
  const reversed = useMemo(() => [...logs].reverse(), [logs]);

  const counts = useMemo(() => {
    const c = { info: 0, warn: 0, error: 0, total: logs.length };
    for (const l of logs) { c[l.level]++; }
    return c;
  }, [logs]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return reversed.filter((l) =>
      (type === "all"  || l.type  === type) &&
      (level === "all" || l.level === level) &&
      (needle === ""   || (l.msg + " " + (l.detail ?? "")).toLowerCase().includes(needle)),
    );
  }, [reversed, q, type, level]);

  const copyAll = (): void => {
    const text = filtered.map((l) =>
      `${l.t}  [${l.level.toUpperCase()}] ${l.type}  ${l.msg}` +
        (l.detail ? `\n  ${l.detail.split("\n").join("\n  ")}` : ""),
    ).join("\n");
    onCopyAll(text);
  };

  const rowId = (l: LogEvent, i: number): string => `${l.t}-${l.type}-${l.level}-${i}`;
  const openLatest = (): void => {
    if (filtered.length === 0) { return; }
    setExpanded(rowId(filtered[0], 0));
  };

  return (
    <div className="page">
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 14 }}>
        <SummaryStat label="Events"   value={counts.total} sub="in buffer" />
        <SummaryStat label="Errors"   value={counts.error} sub="needs attention" tone="error" />
        <SummaryStat label="Warnings" value={counts.warn}  sub="non-blocking"    tone="warn"  />
        <SummaryStat label="Info"     value={counts.info}  sub="normal activity" />
      </div>

      <div className="filter-row">
        <div className="search-wrap" style={{ maxWidth: 320 }}>
          <IconSearch />
          <input
            className="input"
            placeholder="Search messages, files, request ids…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <div className="segmented">
          {TYPE_FILTERS.map((t) => (
            <button key={t} className={type === t ? "on" : ""} onClick={() => setType(t)} type="button">
              {t === "all" ? "All types" : t}
            </button>
          ))}
        </div>
        <div className="segmented">
          {LEVEL_FILTERS.map((l) => (
            <button key={l} className={level === l ? "on" : ""} onClick={() => setLevel(l)} type="button">
              {l}
            </button>
          ))}
        </div>
        <span className="spacer" />
        <span className="mono faint" style={{ fontSize: 11 }}>
          {filtered.length} of {logs.length}
        </span>
        <button className="btn sm ghost" onClick={openLatest} type="button" disabled={filtered.length === 0}>
          <IconLatest /> Latest
        </button>
        <button className="btn sm ghost" onClick={copyAll} type="button" disabled={filtered.length === 0}>
          <IconCopy /> Copy
        </button>
        <button className="btn sm ghost" onClick={onClear} type="button" disabled={logs.length === 0}>
          <IconTrash /> Clear
        </button>
      </div>

      <div className="card logs-card">
        <div className="logs-header">
          <span>Time</span><span>Type</span><span>Level</span><span>Message</span>
        </div>

        {filtered.length === 0 && (
          <div style={{ padding: 40, textAlign: "center" }}>
            <div className="mono faint">{logs.length === 0 ? "no events yet" : "no events match"}</div>
          </div>
        )}

        {filtered.map((l, i) => {
          const id = rowId(l, i);
          const isExpanded = expanded === id;
          const lc = levelColor(l.level);
          return (
            <div
              key={id}
              className={`log-row ${isExpanded ? "expanded" : ""}`}
              onClick={() => setExpanded(isExpanded ? null : id)}
            >
              <span className="log-time">{timeOf(l.t)}</span>
              <span className="log-type">{l.type}</span>
              <span className="log-level" style={{ color: lc }}>
                <span
                  style={{
                    display: "inline-block", width: 6, height: 6, borderRadius: "50%",
                    background: lc, marginRight: 6, verticalAlign: "middle",
                  }}
                />
                {l.level}
              </span>
              <span className="log-msg">{l.msg}</span>
              {isExpanded && (
                <div className="log-detail mono">{l.detail || l.msg}</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
