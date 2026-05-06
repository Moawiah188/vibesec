import * as React from "react";
import { useEffect, useState } from "react";
import type {
  SettingsKey,
  SettingsState,
  SettingsValues,
} from "./types";

// Group + control descriptors for the Settings page UI. The keys must match
// SettingsValues; types map to control variants. Mirrors the design's
// page-settings.jsx structure (Engine / Behavior / AI assistance) so future
// design tweaks port cleanly.

interface BoolDef {
  type: "bool";
  key: SettingsKey;
  label: string;
  help: string;
}

interface StringDef {
  type: "string";
  key: SettingsKey;
  label: string;
  help: string;
  placeholder?: string;
}

interface EnumDef<V extends string = string> {
  type: "enum";
  key: SettingsKey;
  label: string;
  help: string;
  options: readonly V[];
  /** Optional pretty label per option, e.g. perFile -> "Per file". */
  optionLabels?: Record<V, string>;
}

type SettingDef = BoolDef | StringDef | EnumDef;

interface SettingGroup {
  section: string;
  items: SettingDef[];
}

const SETTINGS_DEFS: SettingGroup[] = [
  {
    section: "Engine",
    items: [
      {
        type: "string",
        key: "semgrepPath",
        label: "Semgrep path",
        help: "Executable used to invoke Semgrep. Change this if semgrep is not on your PATH.",
        placeholder: "semgrep",
      },
      {
        type: "string",
        key: "fileExtensions",
        label: "Scannable file extensions",
        help: "Space-separated list. Files outside this set are skipped during multi-target scans.",
        placeholder: ".ts .tsx .js .py …",
      },
    ],
  },
  {
    section: "Behavior",
    items: [
      {
        type: "bool",
        key: "autoScanOnSave",
        label: "Auto-scan on save",
        help: "Re-scan the active file each time it is saved.",
      },
      {
        type: "bool",
        key: "showInlineDecorations",
        label: "Show inline squiggles",
        help: "Underline findings directly in the editor.",
      },
      {
        type: "bool",
        key: "openPanelOnScan",
        label: "Open analysis panel on scan",
        help: "Reveal the VibeSec analysis panel automatically when a scan starts.",
      },
    ],
  },
  {
    section: "AI assistance",
    items: [
      {
        type: "enum",
        key: "llmProvider",
        label: "AI provider",
        help: "Provider used to draft remediation prompts.",
        options: ["anthropic", "openai", "gemini"] as const,
      } satisfies EnumDef<"anthropic" | "openai" | "gemini">,
      {
        type: "string",
        key: "llmModel",
        label: "AI model",
        help: "Model identifier passed to the provider. Leave matching the provider's default if unsure.",
        placeholder: "claude-haiku-4-5",
      },
      {
        type: "enum",
        key: "promptMode",
        label: "Prompt mode",
        help: "How findings are grouped when generating prompts.",
        options: ["perFile", "perVulnerability", "perProject"] as const,
        optionLabels: {
          perFile: "Per file",
          perVulnerability: "Per vulnerability",
          perProject: "Per project",
        },
      } satisfies EnumDef<"perFile" | "perVulnerability" | "perProject">,
    ],
  },
];

// ── Per-control components ───────────────────────────────────────────────────

interface StringFieldProps {
  value: string;
  placeholder?: string;
  onCommit: (next: string) => void;
}

/**
 * Tracks input state locally; only fires onCommit on blur or Enter so the
 * extension isn't flooded with config updates on every keystroke. Also keeps
 * the field in sync if the underlying value changes from outside (e.g. a
 * direct edit in settings.json).
 */
const StringField: React.FC<StringFieldProps> = ({ value, placeholder, onCommit }) => {
  const [draft, setDraft] = useState(value);
  useEffect(() => { setDraft(value); }, [value]);

  const commit = (): void => {
    if (draft !== value) { onCommit(draft); }
  };

  return (
    <input
      className="input"
      value={draft}
      placeholder={placeholder}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === "Enter") { (e.target as HTMLInputElement).blur(); }
        else if (e.key === "Escape") { setDraft(value); (e.target as HTMLInputElement).blur(); }
      }}
    />
  );
};

interface ToggleProps {
  value: boolean;
  onChange: (v: boolean) => void;
}

const Toggle: React.FC<ToggleProps> = ({ value, onChange }) => (
  <div
    className={`toggle ${value ? "on" : ""}`}
    role="switch"
    aria-checked={value}
    tabIndex={0}
    onClick={() => onChange(!value)}
    onKeyDown={(e) => {
      if (e.key === " " || e.key === "Enter") {
        e.preventDefault();
        onChange(!value);
      }
    }}
  />
);

interface SegmentedProps<V extends string> {
  value: V;
  options: readonly V[];
  labels?: Record<V, string>;
  onChange: (v: V) => void;
}

function Segmented<V extends string>({ value, options, labels, onChange }: SegmentedProps<V>): React.ReactElement {
  return (
    <div className="segmented">
      {options.map((opt) => (
        <button
          key={opt}
          className={value === opt ? "on" : ""}
          onClick={() => onChange(opt)}
          type="button"
        >
          {labels?.[opt] ?? opt}
        </button>
      ))}
    </div>
  );
}

// ── Row + page ───────────────────────────────────────────────────────────────

interface SettingsRowProps {
  def:      SettingDef;
  values:   SettingsValues;
  defaults: SettingsValues;
  onSet:    <K extends SettingsKey>(key: K, value: SettingsValues[K]) => void;
}

const SettingsRow: React.FC<SettingsRowProps> = ({ def, values, defaults, onSet }) => {
  const fullKey = `vibesec.${def.key}`;
  const defaultValue = defaults[def.key];

  return (
    <div className="settings-row">
      <div>
        <div className="label-line">
          <span className="name">{def.label}</span>
          <span className="key">{fullKey}</span>
        </div>
        <div className="help">{def.help}</div>
        <div className="default">
          default: <strong>{formatDefault(defaultValue)}</strong>
        </div>
      </div>
      <div className="control">
        {def.type === "bool" && (
          <Toggle
            value={values[def.key] as boolean}
            onChange={(v) => onSet(def.key, v as SettingsValues[typeof def.key])}
          />
        )}
        {def.type === "string" && (
          <StringField
            value={values[def.key] as string}
            placeholder={def.placeholder}
            onCommit={(v) => onSet(def.key, v as SettingsValues[typeof def.key])}
          />
        )}
        {def.type === "enum" && (
          <Segmented
            value={values[def.key] as string}
            options={def.options}
            labels={def.optionLabels}
            onChange={(v) => onSet(def.key, v as SettingsValues[typeof def.key])}
          />
        )}
      </div>
    </div>
  );
};

function formatDefault(v: unknown): string {
  if (typeof v === "boolean") { return v ? "true" : "false"; }
  if (typeof v === "string" && v === "") { return "(empty)"; }
  return String(v);
}

interface SettingsProps {
  state:           SettingsState;
  onSet:           <K extends SettingsKey>(key: K, value: SettingsValues[K]) => void;
  onOpenJson:      () => void;
  onResetDefaults: () => void;
}

export const Settings: React.FC<SettingsProps> = ({
  state,
  onSet,
  onOpenJson,
  onResetDefaults,
}) => (
  <div className="page" style={{ maxWidth: 760 }}>
    <div className="stack" style={{ gap: 22 }}>
      {SETTINGS_DEFS.map((group) => (
        <section key={group.section}>
          <div className="row between" style={{ marginBottom: 10 }}>
            <h3 className="section-title" style={{ margin: 0 }}>{group.section}</h3>
            <span className="mono faint" style={{ fontSize: 10.5 }}>
              {group.items.length} setting{group.items.length === 1 ? "" : "s"}
            </span>
          </div>
          <div className="card">
            {group.items.map((def) => (
              <SettingsRow
                key={def.key}
                def={def}
                values={state.values}
                defaults={state.defaults}
                onSet={onSet}
              />
            ))}
          </div>
        </section>
      ))}

      <div className="row" style={{ gap: 8, marginTop: 4 }}>
        <button className="btn" onClick={onOpenJson} type="button">
          Open settings.json
        </button>
        <button className="btn ghost" onClick={onResetDefaults} type="button">
          Reset to defaults
        </button>
        <span className="spacer" />
        <span className="mono faint" style={{ fontSize: 11 }}>
          scoped to {state.scope}
        </span>
      </div>
    </div>
  </div>
);
