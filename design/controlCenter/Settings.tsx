import * as React from "react";
import { useEffect, useState } from "react";
import type {
  SettingsKey,
  SettingsState,
  SettingsValues,
  LlmProvider,
} from "./types";
import {
  PROVIDER_DEFAULT_MODEL,
  PROVIDER_LABEL,
  providerModelPresets,
} from "./llmModels";

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
        key: "showInlineDecorations",
        label: "Show inline squiggles",
        help: "Underline findings directly in the editor.",
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
        help: "Provider used to draft remediation prompts. Choose Custom / Other for any OpenAI-compatible LLM endpoint.",
        options: ["anthropic", "openai", "gemini", "groq", "custom"] as const,
        optionLabels: {
          anthropic: "Anthropic",
          openai: "OpenAI",
          gemini: "Gemini",
          groq: "Groq",
          custom: "Custom / Other",
        },
      } satisfies EnumDef<"anthropic" | "openai" | "gemini" | "groq" | "custom">,
      {
        type: "string",
        key: "llmModel",
        label: "AI model name",
        help: "Write the exact model name you want to use, for example gpt-5-nano, claude-haiku-4-5, gemini-2.5-flash-lite, llama-3.1-8b-instant, or a custom model id.",
        placeholder: "write model name here",
      },
      {
        type: "string",
        key: "llmCustomProviderName",
        label: "Custom LLM name",
        help: "Optional display name for your own LLM provider, such as Groq, OpenRouter, Together, Local LLM, or Company AI.",
        placeholder: "OpenRouter / Groq / Local LLM",
      },
      {
        type: "string",
        key: "llmCustomBaseUrl",
        label: "Custom LLM API endpoint",
        help: "Full OpenAI-compatible chat completions URL, for example https://api.example.com/v1/chat/completions.",
        placeholder: "https://api.example.com/v1/chat/completions",
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

interface ModelFieldProps {
  provider: LlmProvider;
  value: string;
  onCommit: (next: string) => void;
}

const ModelField: React.FC<ModelFieldProps> = ({ provider, value, onCommit }) => {
  const presets = providerModelPresets(provider);
  const isPreset = presets.includes(value);
  const [forceCustom, setForceCustom] = useState(false);

  useEffect(() => { setForceCustom(false); }, [provider, value]);

  if (provider === "custom" || presets.length === 0) {
    return (
      <StringField
        value={value}
        placeholder="exact model id from your provider"
        onCommit={onCommit}
      />
    );
  }

  const customMode = forceCustom || !isPreset;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8, width: "100%" }}>
      <select
        className="input"
        value={customMode ? "__custom__" : value}
        onChange={(e) => {
          const next = e.target.value;
          if (next === "__custom__") {
            setForceCustom(true);
            return;
          }
          setForceCustom(false);
          onCommit(next);
        }}
      >
        {presets.map((model) => (
          <option key={model} value={model}>
            {model === PROVIDER_DEFAULT_MODEL[provider] ? `${model} (default)` : model}
          </option>
        ))}
        <option value="__custom__">Custom exact model id...</option>
      </select>
      {customMode && (
        <StringField
          value={value}
          placeholder={`${PROVIDER_LABEL[provider]} model id`}
          onCommit={onCommit}
        />
      )}
    </div>
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
          def.key === "llmModel"
            ? (
              <ModelField
                provider={values.llmProvider}
                value={values.llmModel}
                onCommit={(v) => onSet("llmModel", v)}
              />
            )
            : (
              <StringField
                value={values[def.key] as string}
                placeholder={def.placeholder}
                onCommit={(v) => onSet(def.key, v as SettingsValues[typeof def.key])}
              />
            )
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


const PROVIDERS: { id: LlmProvider; label: string; hint: string }[] = [
  { id: "anthropic", label: PROVIDER_LABEL.anthropic, hint: "Claude API key" },
  { id: "openai",    label: PROVIDER_LABEL.openai,    hint: "OpenAI API key" },
  { id: "gemini",    label: PROVIDER_LABEL.gemini,    hint: "Google AI Studio API key" },
  { id: "groq",      label: PROVIDER_LABEL.groq,      hint: "Groq API key. Paste your gsk_ key only; VibeSec uses the Groq endpoint automatically" },
  { id: "custom",    label: PROVIDER_LABEL.custom,    hint: "API key for another OpenAI-compatible LLM provider" },
];

interface ApiKeyManagerProps {
  activeProvider: LlmProvider;
  onSave:  (provider: LlmProvider, key: string) => void;
  onClear: (provider: LlmProvider) => void;
  onTest:  (provider: LlmProvider) => void;
}

const ApiKeyManager: React.FC<ApiKeyManagerProps> = ({ activeProvider, onSave, onClear, onTest }) => {
  const [drafts, setDrafts] = useState<Record<LlmProvider, string>>({
    anthropic: "",
    openai: "",
    gemini: "",
    groq: "",
    custom: "",
  });

  const setDraft = (provider: LlmProvider, value: string): void => {
    setDrafts((prev) => ({ ...prev, [provider]: value }));
  };

  const save = (provider: LlmProvider): void => {
    const key = drafts[provider].trim();
    if (!key) { return; }
    onSave(provider, key);
    setDraft(provider, "");
  };

  return (
    <section>
      <div className="row between" style={{ marginBottom: 10 }}>
        <h3 className="section-title" style={{ margin: 0 }}>API keys</h3>
        <span className="mono faint" style={{ fontSize: 10.5 }}>stored securely</span>
      </div>
      <div className="card">
        <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--border-soft)" }}>
          <div className="help" style={{ margin: 0 }}>
            Save a separate API key for each provider. Keys are stored in VS Code SecretStorage, not in settings.json.
            The active provider is <strong>{activeProvider}</strong>. Saving a key also selects that provider. For Groq, paste only the <strong>gsk_</strong> API key and VibeSec will use the Groq endpoint automatically. For Custom / Other, write the exact model name and API endpoint above, then click Test.
          </div>
        </div>
        {PROVIDERS.map((provider) => (
          <div className="settings-row" key={provider.id}>
            <div>
              <div className="label-line">
                <span className="name">{provider.label} API key</span>
                {provider.id === activeProvider && <span className="key">active provider</span>}
              </div>
              <div className="help">{provider.hint}. Paste the key, press Save, then use Test to verify it.</div>
              <div className="default">value: <strong>hidden for security</strong></div>
            </div>
            <div className="control" style={{ flexDirection: "column", alignItems: "stretch", gap: 8 }}>
              <input
                className="input"
                type="password"
                value={drafts[provider.id]}
                placeholder={`Paste ${provider.label} key`}
                onChange={(e) => setDraft(provider.id, e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") { save(provider.id); }
                  else if (e.key === "Escape") { setDraft(provider.id, ""); }
                }}
              />
              <div className="row" style={{ gap: 6, justifyContent: "flex-end", flexWrap: "wrap" }}>
                <button className="btn sm primary" type="button" disabled={!drafts[provider.id].trim()} onClick={() => save(provider.id)}>
                  Save & use
                </button>
                <button className="btn sm" type="button" onClick={() => onTest(provider.id)}>
                  Test
                </button>
                <button className="btn sm ghost" type="button" onClick={() => onClear(provider.id)}>
                  Clear
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
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
  onSaveApiKey:    (provider: LlmProvider, key: string) => void;
  onClearApiKey:   (provider: LlmProvider) => void;
  onTestApiKey:    (provider: LlmProvider) => void;
}

export const Settings: React.FC<SettingsProps> = ({
  state,
  onSet,
  onOpenJson,
  onResetDefaults,
  onSaveApiKey,
  onClearApiKey,
  onTestApiKey,
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

      <ApiKeyManager
        activeProvider={state.values.llmProvider}
        onSave={onSaveApiKey}
        onClear={onClearApiKey}
        onTest={onTestApiKey}
      />

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
