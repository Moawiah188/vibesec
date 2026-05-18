import * as React from "react";
import { useMemo, useState } from "react";
import type {
  ControlCenterQuickAction,
  LlmProvider,
  ScanHistoryEntry,
  SettingsState,
} from "./types";
import { PROVIDER_DEFAULT_MODEL } from "./llmModels";

// ── Range buckets ────────────────────────────────────────────────────────────
//
// The design's sparkline expects 7 evenly-spaced points. We bucket the raw
// scan history into 7 windows of equal duration spanning the selected range
// and aggregate findings + scan counts per bucket.

type Range = "1d" | "7d" | "30d";

const RANGE_MS: Record<Range, number> = {
  "1d":  24  * 60 * 60 * 1000,
  "7d":  7   * 24 * 60 * 60 * 1000,
  "30d": 30  * 24 * 60 * 60 * 1000,
};

const RANGE_LABEL: Record<Range, string> = {
  "1d":  "last 24h",
  "7d":  "last 7 days",
  "30d": "last 30 days",
};

interface BucketTotals {
  scans:    number;
  findings: number;
  error:    number;
  warning:  number;
  info:     number;
}

interface AggregatedRange {
  buckets:    BucketTotals[];
  total:      BucketTotals;
  /** Filtered entries within the range, oldest → newest. */
  entries:    ScanHistoryEntry[];
  /** Most recent scan entry in the range, or null if there are none. */
  lastScan:   ScanHistoryEntry | null;
  /** Cross-entry averages — only reported when `entries.length > 0`. */
  avgDurationMs: number;
}

function aggregate(history: ScanHistoryEntry[], range: Range, now: number): AggregatedRange {
  const windowMs = RANGE_MS[range];
  const start = now - windowMs;
  const within = history.filter((e) => e.ts >= start && e.ts <= now);

  const buckets: BucketTotals[] = Array.from({ length: 7 }, () => emptyTotals());
  const bucketMs = windowMs / 7;
  for (const e of within) {
    const idx = Math.min(6, Math.max(0, Math.floor((e.ts - start) / bucketMs)));
    buckets[idx].scans   += 1;
    buckets[idx].findings += e.findings.error + e.findings.warning + e.findings.info;
    buckets[idx].error   += e.findings.error;
    buckets[idx].warning += e.findings.warning;
    buckets[idx].info    += e.findings.info;
  }

  const total = within.reduce<BucketTotals>(
    (acc, e) => {
      acc.scans   += 1;
      acc.findings += e.findings.error + e.findings.warning + e.findings.info;
      acc.error   += e.findings.error;
      acc.warning += e.findings.warning;
      acc.info    += e.findings.info;
      return acc;
    },
    emptyTotals(),
  );

  const lastScan = within.length > 0 ? within[within.length - 1] : null;
  const avgDurationMs = within.length > 0
    ? within.reduce((s, e) => s + e.duration, 0) / within.length
    : 0;

  return { buckets, total, entries: within, lastScan, avgDurationMs };
}

function emptyTotals(): BucketTotals {
  return { scans: 0, findings: 0, error: 0, warning: 0, info: 0 };
}

// ── Formatting helpers ───────────────────────────────────────────────────────

function relativeTime(ts: number, now: number): string {
  const diff = Math.max(0, now - ts);
  const sec = Math.floor(diff / 1000);
  if (sec < 5)    { return "just now"; }
  if (sec < 60)   { return `${sec}s ago`; }
  const min = Math.floor(sec / 60);
  if (min < 60)   { return `${min} min ago`; }
  const hr = Math.floor(min / 60);
  if (hr < 24)    { return `${hr}h ago`; }
  const day = Math.floor(hr / 24);
  if (day < 30)   { return `${day}d ago`; }
  const mo = Math.floor(day / 30);
  return `${mo}mo ago`;
}

function formatDuration(ms: number): string {
  if (ms <= 0)    { return "—"; }
  if (ms < 1000)  { return `${ms}ms`; }
  return `${(ms / 1000).toFixed(1)}s`;
}

function displayModel(provider: LlmProvider, configured: string): string {
  const fallback = PROVIDER_DEFAULT_MODEL[provider] ?? configured;
  if (provider === "custom") { return configured || fallback; }
  if (!configured) { return fallback; }
  const looksOpenAI = /^gpt[-_]/i.test(configured) || /^o\d/i.test(configured);
  const looksAnthropic = /^claude[-_]/i.test(configured);
  const looksGemini = /^gemini[-_]/i.test(configured);
  const looksGroq = /^llama[-_]/i.test(configured) || /^mixtral[-_]/i.test(configured) || /^gemma[-_]/i.test(configured) || /^qwen[-_]/i.test(configured) || /groq/i.test(configured);
  if (provider === "openai" && (looksAnthropic || looksGemini || looksGroq)) { return fallback; }
  if (provider === "anthropic" && (looksOpenAI || looksGemini || looksGroq)) { return fallback; }
  if (provider === "gemini" && (looksOpenAI || looksAnthropic || looksGroq)) { return fallback; }
  if (provider === "groq" && (looksOpenAI || looksAnthropic || looksGemini || configured === "custom-model")) { return fallback; }
  return configured;
}

// ── Sparkline ────────────────────────────────────────────────────────────────

interface SparklineProps {
  data: number[];
}

const Sparkline: React.FC<SparklineProps> = ({ data }) => {
  const w = 280, h = 48, pad = 4;
  const max = Math.max(...data, 1);
  const min = Math.min(...data);
  const range = max - min || 1;
  const pts = data.map<[number, number]>((v, i) => {
    const x = pad + (i / (data.length - 1 || 1)) * (w - pad * 2);
    const y = h - pad - ((v - min) / range) * (h - pad * 2);
    return [x, y];
  });
  const d = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const area = `${d} L ${w - pad} ${h - pad} L ${pad} ${h - pad} Z`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} role="img" aria-label="Findings trend">
      <path d={area} fill="var(--accent-soft)" />
      <path d={d} stroke="var(--accent)" strokeWidth={1.5} fill="none" />
      {pts.map((p, i) => (
        <circle key={i} cx={p[0]} cy={p[1]} r={2} fill="var(--accent)" />
      ))}
    </svg>
  );
};

// ── Quick action tile ────────────────────────────────────────────────────────

interface QuickActionDef {
  id:    ControlCenterQuickAction;
  title: string;
  sub:   string;
  icon:  React.FC<{ className?: string }>;
}

const stroke: React.SVGProps<SVGSVGElement> = {
  width: 16, height: 16, viewBox: "0 0 24 24", fill: "none",
  stroke: "currentColor", strokeWidth: 1.5, strokeLinecap: "round", strokeLinejoin: "round",
};

const IconPlay: React.FC<{ className?: string }> = ({ className }) => (
  <svg {...stroke} className={className}>
    <polygon points="5 3 19 12 5 21 5 3" fill="currentColor" stroke="none" />
  </svg>
);
const IconExternal: React.FC<{ className?: string }> = ({ className }) => (
  <svg {...stroke} className={className}>
    <path d="M14 3h7v7" />
    <path d="M21 3l-9 9" />
    <path d="M21 14v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h6" />
  </svg>
);
const IconFile: React.FC<{ className?: string }> = ({ className }) => (
  <svg {...stroke} className={className}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6" />
  </svg>
);
const IconFolder: React.FC<{ className?: string }> = ({ className }) => (
  <svg {...stroke} className={className}>
    <path d="M3 6.5V18a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7l-2-2H5a2 2 0 0 0-2 2.5z" />
  </svg>
);
const IconPlusFile: React.FC<{ className?: string }> = ({ className }) => (
  <svg {...stroke} className={className}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6" />
    <path d="M12 12v6" />
    <path d="M9 15h6" />
  </svg>
);
const IconRefresh: React.FC<{ className?: string }> = ({ className }) => (
  <svg {...stroke} className={className}>
    <path d="M3 12a9 9 0 0 1 15.5-6.4L21 8" />
    <path d="M21 3v5h-5" />
    <path d="M21 12a9 9 0 0 1-15.5 6.4L3 16" />
    <path d="M3 21v-5h5" />
  </svg>
);

const QUICK_ACTIONS: QuickActionDef[] = [
  { id: "scan",            title: "Scan project",      sub: "Run full Semgrep sweep",              icon: IconPlay    },
  { id: "openPolicy",      title: "Open policy file",  sub: "Choose any VibeSec policy to open",  icon: IconFile    },
  { id: "reloadPolicy",    title: "Reload policy",     sub: "Re-parse rules from disk",           icon: IconRefresh },
  { id: "newNormalPolicy", title: "New normal policy", sub: "Create a named normal scan policy",  icon: IconFile    },
  { id: "newTaintPolicy",  title: "New taint policy",  sub: "Create a named taint scan policy",   icon: IconFile    },
];

// ── Page ─────────────────────────────────────────────────────────────────────

interface DashboardProps {
  history:        ScanHistoryEntry[];
  settings:       SettingsState;
  onAction:       (a: ControlCenterQuickAction) => void;
  onClearHistory: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  history,
  settings,
  onAction,
  onClearHistory,
}) => {
  const [range, setRange] = useState<Range>("7d");
  // Sample `now` once per render so all derivations agree on the same window.
  const now = Date.now();

  const aggregated = useMemo(
    () => aggregate(history, range, now),
    // We intentionally re-aggregate on every render — `now` changes each
    // mount and `history` is a fresh array reference whenever the extension
    // pushes an update, so the dependency tracker would just re-run anyway.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [history, range],
  );

  const { total, lastScan, buckets, avgDurationMs } = aggregated;

  const sevCards = [
    { key: "error",   label: "Error",   count: total.error,   cls: "sev-error"   },
    { key: "warning", label: "Warning", count: total.warning, cls: "sev-warning" },
    { key: "info",    label: "Info",    count: total.info,    cls: "sev-info"    },
  ];

  const trendData = buckets.map((b) => b.findings);
  const hasHistory = total.scans > 0;

  return (
    <div className="page" style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 18 }}>
      <div className="stack">
        {/* Summary header */}
        <div
          className="card card-pad"
          style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 20, alignItems: "center" }}
        >
          <div>
            <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
              <span style={{ fontSize: 22, fontWeight: 700, letterSpacing: "-0.02em" }}>
                {total.findings}
              </span>
              <span className="muted" style={{ fontSize: 13 }}>findings</span>
              <span className="mono faint" style={{ fontSize: 11 }}>
                across {total.scans} scan{total.scans !== 1 ? "s" : ""} · {RANGE_LABEL[range]}
              </span>
            </div>
            <div className="muted" style={{ fontSize: 12, marginTop: 3 }}>
              {lastScan ? (
                <>
                  Last scan {relativeTime(lastScan.ts, now)} · avg {formatDuration(avgDurationMs)} · trigger{" "}
                  <span className="mono">{lastScan.trigger}</span>
                </>
              ) : (
                <>No scans recorded yet — run one from the analysis panel or the quick actions →</>
              )}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div className="segmented">
              {(["1d", "7d", "30d"] as Range[]).map((r) => (
                <button
                  key={r}
                  className={range === r ? "on" : ""}
                  onClick={() => setRange(r)}
                  type="button"
                >
                  {r}
                </button>
              ))}
            </div>

          </div>
        </div>

        {/* Severity breakdown */}
        <section>
          <h3 className="section-title">Severity breakdown</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
            {sevCards.map((c) => (
              <div key={c.key} className={`sev-card ${c.cls}`}>
                <span className="accent-bar" />
                <span className="label">{c.label}</span>
                <span className="count tnum">{c.count}</span>
                <span className="mono faint" style={{ fontSize: 10.5 }}>
                  {total.findings === 0
                    ? "no scans"
                    : c.count === 0
                      ? "none"
                      : `${Math.round((c.count / total.findings) * 100)}% of ${total.findings}`}
                </span>
              </div>
            ))}
          </div>
        </section>

        {/* Recent scans table */}
        <section className="card card-pad">
          <div className="row between" style={{ marginBottom: 10 }}>
            <h3 className="section-title" style={{ margin: 0 }}>Recent scans</h3>
            {hasHistory && (
              <button
                className="btn sm ghost"
                onClick={onClearHistory}
                type="button"
                title="Clear scan history (does not affect findings)"
              >
                Clear history
              </button>
            )}
          </div>
          {hasHistory
            ? (
              <div style={{ display: "grid", gridTemplateColumns: "auto 1fr auto auto auto", columnGap: 14, rowGap: 6 }}>
                <span className="mono faint" style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: "0.06em" }}>When</span>
                <span className="mono faint" style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: "0.06em" }}>Trigger</span>
                <span className="mono faint" style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: "0.06em" }}>Files</span>
                <span className="mono faint" style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: "0.06em" }}>Findings</span>
                <span className="mono faint" style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: "0.06em" }}>Duration</span>
                {aggregated.entries.slice(-6).reverse().map((e) => (
                  <React.Fragment key={e.ts}>
                    <span className="mono" style={{ fontSize: 11.5 }}>{relativeTime(e.ts, now)}</span>
                    <span className="mono muted" style={{ fontSize: 11.5 }}>{e.trigger}</span>
                    <span className="mono tnum" style={{ fontSize: 11.5 }}>{e.filesScanned}</span>
                    <span className="mono tnum" style={{ fontSize: 11.5 }}>
                      <span className="sev-error" style={{ marginRight: 6 }}>{e.findings.error}</span>
                      <span className="sev-warning" style={{ marginRight: 6 }}>{e.findings.warning}</span>
                      <span className="sev-info">{e.findings.info}</span>
                    </span>
                    <span className="mono tnum" style={{ fontSize: 11.5 }}>{formatDuration(e.duration)}</span>
                  </React.Fragment>
                ))}
              </div>
            )
            : (
              <div className="placeholder" style={{ padding: 24 }}>
                <div>
                  <strong>No scans in {RANGE_LABEL[range]}</strong>
                  Scan history populates as you run scans.
                </div>
              </div>
            )}
        </section>
      </div>

      {/* Right rail */}
      <div className="stack">
        <section className="card card-pad">
          <h3 className="section-title">Quick actions</h3>
          <div className="stack" style={{ gap: 8 }}>
            {QUICK_ACTIONS.map((a) => {
              const Ico = a.icon;
              return (
                <button key={a.id} className="qa" onClick={() => onAction(a.id)} type="button">
                  <span className="qa-icon"><Ico /></span>
                  <span className="qa-body">
                    <div className="qa-title">{a.title}</div>
                    <div className="qa-sub">{a.sub}</div>
                  </span>
                </button>
              );
            })}
          </div>
        </section>

        <section className="card card-pad">
          <h3 className="section-title">Environment</h3>
          <dl className="kv-grid">
            <dt>Provider</dt>
            <dd className="row" style={{ gap: 6 }}>
              <span className="dot ok" />
              <span className="mono">{settings.values.llmProvider === "custom" ? (settings.values.llmCustomProviderName || "custom") : settings.values.llmProvider}</span>
            </dd>
            <dt>Model</dt>
            <dd className="mono" style={{ fontSize: 12 }}>{displayModel(settings.values.llmProvider, settings.values.llmModel)}</dd>
            <dt>Prompt mode</dt>
            <dd className="mono">{settings.values.promptMode}</dd>
            <dt>Semgrep</dt>
            <dd className="mono" style={{ fontSize: 12 }}>{settings.values.semgrepPath}</dd>
            <dt>Policy</dt>
            <dd className="mono">.vibesec.yaml</dd>
          </dl>
        </section>

        <section className="card card-pad">
          <h3 className="section-title">Trend · {RANGE_LABEL[range]}</h3>
          {hasHistory
            ? <Sparkline data={trendData} />
            : <div className="placeholder" style={{ padding: 18, marginTop: 4 }}>
                <div className="mono faint" style={{ fontSize: 11 }}>no data yet</div>
              </div>
          }
          <div className="row between mono faint" style={{ fontSize: 10.5, marginTop: 6 }}>
            <span>{total.scans} scan{total.scans !== 1 ? "s" : ""}</span>
            <span>{total.error > 0 ? `${total.error} error${total.error !== 1 ? "s" : ""}` : "no errors"}</span>
          </div>
        </section>
      </div>
    </div>
  );
};
