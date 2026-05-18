import * as React from "react";
import { useMemo, useState } from "react";
import type {
  RuleEntry,
  RuleFileEntry,
  RuleSource,
  RulesIndex,
  Severity,
} from "./types";

// Rules page — two-level navigation.
// Level 1: file cards grouped by source (bundled / custom / external).
// Level 2: per-file rule table with search + severity filter.
//
// Per-rule and per-file toggles dispatch to the extension. The extension
// updates .vibesec.yaml using presets, externalRuleFiles and disabledRules,
// then reloads the policy so the next scan matches this UI.

const SOURCE_ORDER: readonly RuleSource[] = ["bundled", "custom"];
const SOURCE_LABEL: Record<RuleSource, string> = {
  bundled:  "Default policies",
  custom:   "Custom policy",
  external: "Imported policies",
};

const SEV_ORDER: readonly Severity[] = ["error", "warning", "info"];
const SEV_LABEL: Record<Severity, string> = {
  error:   "Error",
  warning: "Warning",
  info:    "Info",
};

// ── Icons (inline SVG, CSP-safe) ─────────────────────────────────────────────

const stroke: React.SVGProps<SVGSVGElement> = {
  width: 14, height: 14, viewBox: "0 0 24 24", fill: "none",
  stroke: "currentColor", strokeWidth: 1.5, strokeLinecap: "round", strokeLinejoin: "round",
};

const IconFile: React.FC = () => (
  <svg {...stroke}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6" />
  </svg>
);
const IconChevron: React.FC = () => (
  <svg {...stroke}>
    <polyline points="9 18 15 12 9 6" />
  </svg>
);
const IconBack: React.FC = () => (
  <svg {...stroke}>
    <polyline points="15 18 9 12 15 6" />
  </svg>
);
const IconExternal: React.FC = () => (
  <svg {...stroke}>
    <path d="M14 3h7v7" />
    <path d="M21 3l-9 9" />
    <path d="M21 14v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h6" />
  </svg>
);
const IconRefresh: React.FC = () => (
  <svg {...stroke}>
    <path d="M3 12a9 9 0 0 1 15.5-6.4L21 8" />
    <path d="M21 3v5h-5" />
    <path d="M21 12a9 9 0 0 1-15.5 6.4L3 16" />
    <path d="M3 21v-5h5" />
  </svg>
);
const IconSearch: React.FC = () => (
  <svg {...stroke} width={13} height={13}>
    <circle cx={11} cy={11} r={7} />
    <path d="M21 21l-4.3-4.3" />
  </svg>
);
const IconLink: React.FC = () => (
  <svg {...stroke}>
    <path d="M10 13a5 5 0 0 0 7.1 0l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1" />
    <path d="M14 11a5 5 0 0 0-7.1 0l-2 2a5 5 0 0 0 7.1 7.1l1.1-1.1" />
  </svg>
);

// ── Top summary card ─────────────────────────────────────────────────────────

interface SummaryCardProps {
  label:    string;
  value:    number;
  sub:      string;
  emphasis?: boolean;
}

const SummaryCard: React.FC<SummaryCardProps> = ({ label, value, sub, emphasis }) => (
  <div
    className="card"
    style={{
      padding: "10px 14px",
      borderColor: emphasis ? "var(--accent)" : "var(--border)",
    }}
  >
    <div className="mono faint" style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: "0.06em" }}>
      {label}
    </div>
    <div style={{ display: "flex", alignItems: "baseline", gap: 6, marginTop: 2 }}>
      <span
        className="tnum"
        style={{ fontSize: 22, fontWeight: 600, color: emphasis ? "var(--accent)" : "var(--text)" }}
      >
        {value}
      </span>
      <span className="mono faint" style={{ fontSize: 10.5 }}>{sub}</span>
    </div>
  </div>
);

// ── File row ─────────────────────────────────────────────────────────────────

const SOURCE_DOT_COLOR: Record<RuleSource, string> = {
  bundled:  "var(--text-faint)",
  custom:   "var(--accent)",
  external: "var(--sev-warning)",
};

interface FileRowProps {
  file:     RuleFileEntry;
  onClick:  () => void;
  onToggle: (enabled: boolean) => void;
  onDelete: () => void;
}

const FileRow: React.FC<FileRowProps> = ({ file, onClick, onToggle, onDelete }) => {
  return (
    <div
      className="rule-file-row"
      onClick={onClick}
      style={{ cursor: "pointer", opacity: file.enabled ? 1 : 0.62 }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
        <div className="rule-file-icon" style={{ color: SOURCE_DOT_COLOR[file.source] }}>
          <IconFile />
        </div>
        <div style={{ minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span className="mono" style={{ fontSize: 12.5, fontWeight: 500 }}>{file.path}</span>
            <span className="rule-source-tag" style={{ color: SOURCE_DOT_COLOR[file.source] }}>
              {file.source}
            </span>
            {file.parseError && (
              <span className="rule-source-tag" style={{ color: "var(--sev-error)" }}>parse error</span>
            )}
          </div>
          <div className="muted" style={{ fontSize: 11.5, marginTop: 2 }}>{file.desc}</div>
          {file.updatedAt && (
            <div className="mono faint" style={{ fontSize: 10.5, marginTop: 3 }}>
              updated {file.updatedAt}
            </div>
          )}
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 14, flexShrink: 0 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {SEV_ORDER.map((s) => {
            const c = file.severities[s];
            if (!c) { return null; }
            return (
              <span
                key={s}
                className={`mono sev-${s}`}
                style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11 }}
              >
                <span
                  style={{
                    width: 6, height: 6, borderRadius: "50%",
                    background: `var(--sev-${s})`, display: "inline-block",
                  }}
                />
                {c}
              </span>
            );
          })}
        </div>
        <div className="rule-count-chip">
          <span style={{ fontFamily: "var(--vsc-mono)", fontSize: 16, fontWeight: 600, lineHeight: 1 }}>
            {file.ruleCount}
          </span>
          <span className="mono faint" style={{ fontSize: 10 }}>rules</span>
        </div>
        <button
          className={`toggle ${file.enabled ? "on" : ""}`}
          title={file.enabled ? "Deactivate this policy" : "Activate this policy. You can activate multiple normal and taint policies together."}
          aria-label={file.enabled ? "Deactivate policy" : "Activate policy"}
          onClick={(e) => {
            e.stopPropagation();
            onToggle(!file.enabled);
          }}
          type="button"
        />
        {file.source === "custom" && (
          <button
            className="btn sm ghost"
            title="Delete this policy file"
            onClick={(e) => {
              e.stopPropagation();
              onDelete();
            }}
            type="button"
          >
            Delete
          </button>
        )}
        <span style={{ color: "var(--text-faint)", display: "flex" }}><IconChevron /></span>
      </div>
    </div>
  );
};

// ── File list (level 1) ──────────────────────────────────────────────────────

interface RuleFileListProps {
  index:            RulesIndex;
  onSelect:         (fileId: string) => void;
  onToggleFile:     (fileId: string, enabled: boolean) => void;
  onCreateRuleFile: () => void;
  onCreatePolicyFile: (kind: "normal" | "taint" | "custom") => void;
  onDeletePolicyFile: (fileId: string) => void;
  onImportRuleFile: () => void;
}

const RuleFileList: React.FC<RuleFileListProps> = ({ index, onSelect, onToggleFile, onCreateRuleFile, onCreatePolicyFile, onDeletePolicyFile, onImportRuleFile }) => {
  const grouped = useMemo(() =>
    SOURCE_ORDER.map((src) => ({
      src,
      files: index.files.filter((f) => f.source === src),
    })),
  [index.files]);

  const totalRules   = index.rules.length;
  const totalEnabled = index.rules.filter((r) => r.enabled).length;
  const activeFiles  = index.files.filter((f) => f.enabled).length;
  const counts: Record<RuleSource, number> = {
    bundled:  index.files.filter((f) => f.source === "bundled").length,
    custom:   index.files.filter((f) => f.source === "custom").length,
    external: 0,
  };

  return (
    <div className="page">
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 20 }}>
        <SummaryCard
          label="Total rules"
          value={totalRules}
          sub={`${totalEnabled} enabled`}
          emphasis
        />
        <SummaryCard label="Active files" value={activeFiles} sub="policies" />
        <SummaryCard label="Custom"  value={counts.custom}  sub="policy files" />
      </div>

      <div className="row between" style={{ marginBottom: 12 }}>
        <div className="muted" style={{ fontSize: 12 }}>Turn ON any number of policy files. Normal and taint policies can run together, or all can be OFF.</div>
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <button className="btn sm" onClick={onImportRuleFile} type="button" title="Import valid YAML from a GitHub or raw URL">
            <IconLink /> Import policy link
          </button>
          <button className="btn sm" onClick={() => onCreatePolicyFile("normal")} type="button">
            <IconFile /> New normal policy
          </button>
          <button className="btn sm" onClick={() => onCreatePolicyFile("taint")} type="button">
            <IconFile /> New taint policy
          </button>
          <button className="btn sm" onClick={() => onCreatePolicyFile("custom")} type="button">
            <IconFile /> New custom policy
          </button>
        </div>
      </div>

      <div className="stack" style={{ gap: 20 }}>
        {grouped.map(({ src, files }) => {
          if (files.length === 0) { return null; }
          return (
            <section key={src}>
              <div className="row between" style={{ marginBottom: 8 }}>
                <h3 className="section-title" style={{ margin: 0 }}>{SOURCE_LABEL[src]}</h3>
                <span className="mono faint" style={{ fontSize: 10.5 }}>
                  {files.length} file{files.length !== 1 ? "s" : ""}
                </span>
              </div>
              <div className="stack" style={{ gap: 6 }}>
                {files.map((f) => (
                  <FileRow
                    key={f.id}
                    file={f}
                    onClick={() => onSelect(f.id)}
                    onToggle={(enabled) => onToggleFile(f.id, enabled)}
                    onDelete={() => onDeletePolicyFile(f.id)}
                  />
                ))}
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
};

// ── File detail (level 2) ────────────────────────────────────────────────────

interface RuleFileDetailProps {
  index:        RulesIndex;
  fileId:       string;
  onBack:       () => void;
  onOpenFile:   (fileId: string) => void;
  onRefresh:    () => void;
  onToggleRule: (ruleId: string, enabled: boolean) => void;
  onToggleFile: (fileId: string, enabled: boolean) => void;
  onDeleteFile: (fileId: string) => void;
}

const RuleFileDetail: React.FC<RuleFileDetailProps> = ({ index, fileId, onBack, onOpenFile, onRefresh, onToggleRule, onToggleFile, onDeleteFile }) => {
  const file = index.files.find((f) => f.id === fileId);
  const fileRules = useMemo(
    () => index.rules.filter((r) => r.file === fileId),
    [index.rules, fileId],
  );

  const [q,   setQ]   = useState("");
  const [sev, setSev] = useState<"all" | Severity>("all");

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return fileRules.filter((r) =>
      (sev === "all" || r.sev === sev) &&
      (needle === "" ||
        r.name.toLowerCase().includes(needle) ||
        r.ruleId.toLowerCase().includes(needle) ||
        r.cat.toLowerCase().includes(needle)),
    );
  }, [fileRules, q, sev]);

  if (!file) {
    return (
      <div className="page">
        <button className="btn ghost sm" onClick={onBack} type="button">
          <IconBack /> Rules
        </button>
        <div className="placeholder" style={{ padding: 30, marginTop: 16 }}>
          <div>
            <strong>File not found</strong>
            The rules index doesn't include this file anymore. It may have been removed.
          </div>
        </div>
      </div>
    );
  }

  const enabledCount = fileRules.filter((r) => r.enabled).length;

  return (
    <div className="page">
      <div className="row" style={{ gap: 6, marginBottom: 16 }}>
        <button className="btn ghost sm" onClick={onBack} type="button" style={{ gap: 4, padding: "4px 8px" }}>
          <IconBack /> Rules
        </button>
        <span className="faint">/</span>
        <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)" }}>{file.path}</span>
      </div>

      <div
        className="card card-pad"
        style={{ marginBottom: 16, display: "grid", gridTemplateColumns: "1fr auto", gap: 20, alignItems: "start" }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
            <div
              className="rule-file-icon"
              style={{ color: file.source === "custom" ? "var(--accent)" : "var(--text-muted)" }}
            >
              <IconFile />
            </div>
            <div>
              <div className="mono" style={{ fontSize: 13, fontWeight: 600 }}>{file.path}</div>
              <div className="mono faint" style={{ fontSize: 10.5 }}>
                {file.updatedAt ? `last updated ${file.updatedAt} · ` : ""}{file.source}
              </div>
            </div>
          </div>
          <div className="muted" style={{ fontSize: 12 }}>{file.desc}</div>
          {file.parseError && (
            <div
              className="mono"
              style={{
                fontSize: 11, marginTop: 8, padding: "8px 10px",
                background: "var(--bg-deep)", border: "1px solid var(--sev-error)",
                borderRadius: 5, color: "var(--sev-error)",
              }}
            >
              YAML parse error — {file.parseError}
            </div>
          )}
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button
            className={`toggle ${file.enabled ? "on" : ""}`}
            title={file.enabled ? "Deactivate this policy" : "Activate this policy. Multiple policy files can be active together."}
            aria-label={file.enabled ? "Deactivate policy" : "Activate policy"}
            onClick={() => onToggleFile(file.id, !file.enabled)}
            type="button"
          />
          {file.absPath && (
            <button className="btn sm" onClick={() => onOpenFile(file.id)} type="button">
              <IconExternal /> Open YAML
            </button>
          )}
          {file.source === "custom" && (
            <button className="btn sm ghost" onClick={() => onDeleteFile(file.id)} type="button" title="Delete this workspace policy file">
              Delete
            </button>
          )}
          <button className="btn sm ghost" onClick={onRefresh} type="button">
            <IconRefresh /> Refresh
          </button>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10, marginBottom: 14 }}>
        <SummaryCard label="Total"   value={fileRules.length}        sub=""              />
        <SummaryCard label="Enabled" value={enabledCount}             sub=""              />
        <SummaryCard label="Error"   value={file.severities.error}   sub="" emphasis={file.severities.error > 0} />
        <SummaryCard label="Warning" value={file.severities.warning} sub=""              />
        <SummaryCard label="Info"    value={file.severities.info}    sub=""              />
      </div>

      <div className="filter-row">
        <div className="search-wrap" style={{ maxWidth: 280 }}>
          <IconSearch />
          <input
            className="input"
            placeholder="Search rules…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <div className="segmented">
          {(["all", "error", "warning", "info"] as const).map((s) => (
            <button
              key={s}
              className={sev === s ? "on" : ""}
              onClick={() => setSev(s)}
              type="button"
            >
              {s === "all" ? "All severity" : SEV_LABEL[s]}
            </button>
          ))}
        </div>
        <span className="spacer" />
        <span className="mono faint" style={{ fontSize: 11 }}>
          {filtered.length} rule{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div className="card" style={{ overflow: "hidden" }}>
        <div className="rules-header">
          <span>Severity</span>
          <span>Rule</span>
          <span>Category</span>
          <span>CWE</span>
          <span>Confidence</span>
          <span>On</span>
        </div>

        {filtered.length === 0 && (
          <div style={{ padding: 40, textAlign: "center" }}>
            <div className="mono faint">no rules match</div>
          </div>
        )}

        {filtered.map((r) => (
          <RuleRow key={r.id} rule={r} onToggle={(enabled) => onToggleRule(r.id, enabled)} />
        ))}
      </div>
    </div>
  );
};

// ── Single rule row ──────────────────────────────────────────────────────────

const RuleRow: React.FC<{ rule: RuleEntry; onToggle: (enabled: boolean) => void }> = ({ rule, onToggle }) => {
  const confPct = Math.round(rule.conf * 100);
  return (
    <div className="rule-row" style={{ opacity: rule.enabled ? 1 : 0.5 }}>
      <span className={`sev sev-${rule.sev}`}>{rule.sev}</span>
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 12.5, fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{rule.name}</span>
          {rule.mode === "taint" && (
            <span
              className="mono"
              style={{
                fontSize: 9.5,
                fontWeight: 600,
                letterSpacing: "0.06em",
                color: "var(--accent)",
                background: "var(--accent-soft)",
                border: "1px solid var(--accent-border)",
                borderRadius: 3,
                padding: "1px 5px",
                flexShrink: 0,
              }}
              title="Tracks data flow from source to sink"
            >
              TAINT
            </span>
          )}
        </div>
        <div className="mono faint" style={{ fontSize: 10.5, marginTop: 1 }}>{rule.ruleId}</div>
        {rule.langs.length > 0 && (
          <div style={{ display: "flex", gap: 4, marginTop: 4, flexWrap: "wrap" }}>
            {rule.langs.map((l) => (
              <span key={l} className="tag">{l}</span>
            ))}
          </div>
        )}
      </div>
      <span style={{ fontSize: 12 }}>{rule.cat}</span>
      <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{rule.cwe}</span>
      <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span className="confidence-bar"><span className="confidence-fill" style={{ width: `${confPct}%` }} /></span>
        <span className="mono faint" style={{ fontSize: 10.5 }}>{confPct}</span>
      </span>
      <button
        className={`toggle ${rule.enabled ? "on" : ""}`}
        title={rule.enabled ? "Disable this rule" : "Enable this rule"}
        aria-label={rule.enabled ? "Disable this rule" : "Enable this rule"}
        onClick={() => onToggle(!rule.enabled)}
        type="button"
      />
    </div>
  );
};

// ── Public page ──────────────────────────────────────────────────────────────

interface RulesProps {
  index:            RulesIndex;
  onOpenFile:       (fileId: string) => void;
  onRefresh:        () => void;
  onToggleRule:     (ruleId: string, enabled: boolean) => void;
  onToggleFile:     (fileId: string, enabled: boolean) => void;
  onCreateRuleFile: () => void;
  onCreatePolicyFile: (kind: "normal" | "taint" | "custom") => void;
  onDeletePolicyFile: (fileId: string) => void;
  onImportRuleFile: () => void;
}

export const Rules: React.FC<RulesProps> = ({ index, onOpenFile, onRefresh, onToggleRule, onToggleFile, onCreateRuleFile, onCreatePolicyFile, onDeletePolicyFile, onImportRuleFile }) => {
  const [selected, setSelected] = useState<string | null>(null);

  if (selected) {
    return (
      <RuleFileDetail
        index={index}
        fileId={selected}
        onBack={() => setSelected(null)}
        onOpenFile={onOpenFile}
        onRefresh={onRefresh}
        onToggleRule={onToggleRule}
        onToggleFile={onToggleFile}
        onDeleteFile={onDeletePolicyFile}
      />
    );
  }
  return (
    <RuleFileList
      index={index}
      onSelect={setSelected}
      onToggleFile={onToggleFile}
      onCreateRuleFile={onCreateRuleFile}
      onCreatePolicyFile={onCreatePolicyFile}
      onDeletePolicyFile={onDeletePolicyFile}
      onImportRuleFile={onImportRuleFile}
    />
  );
};
