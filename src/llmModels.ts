import type { LlmProvider } from "./types";

export const ALL_PROVIDERS: readonly LlmProvider[] = [
  "anthropic",
  "openai",
  "gemini",
  "groq",
  "custom",
] as const;

export const PROVIDER_LABEL: Record<LlmProvider, string> = {
  openai:    "OpenAI",
  anthropic: "Anthropic",
  gemini:    "Gemini",
  groq:      "Groq",
  custom:    "Custom / Other",
};

export const PROVIDER_DEFAULT_MODEL: Record<LlmProvider, string> = {
  openai:    "gpt-5-nano",
  anthropic: "claude-haiku-4-5",
  gemini:    "gemini-2.5-flash-lite",
  groq:      "llama-3.1-8b-instant",
  custom:    "custom-model",
};

export const PROVIDER_MODEL_PRESETS: Record<LlmProvider, readonly string[]> = {
  openai: [
    "gpt-5.5",
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.4-nano",
    "gpt-5-nano",
    "gpt-5-mini",
    "gpt-5",
    "gpt-4.1-mini",
    "gpt-4o-mini",
  ],
  anthropic: [
    "claude-opus-4-7",
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
    "claude-haiku-4-5-20251001",
  ],
  gemini: [
    "gemini-2.5-flash-lite",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
  ],
  groq: [
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
    "openai/gpt-oss-20b",
    "openai/gpt-oss-120b",
  ],
  custom: [],
};

export function providerFromKeyHint(provider: LlmProvider, key: string): LlmProvider {
  return /^gsk_/i.test(key.trim()) ? "groq" : provider;
}

export function isBuiltInDefaultModel(model: string): boolean {
  const normalized = model.trim();
  return Object.values(PROVIDER_DEFAULT_MODEL).some((value) => value === normalized);
}

function modelProviderHint(model: string): LlmProvider | "unknown" {
  const normalized = model.trim().toLowerCase();
  if (!normalized) { return "unknown"; }
  if (normalized.startsWith("openai/gpt-oss")) { return "groq"; }
  if (/^(gpt[-_]|o\d|chatgpt[-_])/.test(normalized) || normalized.includes("openai/")) {
    return "openai";
  }
  if (normalized.startsWith("claude-")) { return "anthropic"; }
  if (normalized.startsWith("gemini-")) { return "gemini"; }
  if (
    normalized.startsWith("llama-") ||
    normalized.startsWith("mixtral-") ||
    normalized.startsWith("gemma-") ||
    normalized.startsWith("qwen-") ||
    normalized.includes("groq")
  ) {
    return "groq";
  }
  if (normalized === PROVIDER_DEFAULT_MODEL.custom) { return "custom"; }
  return "unknown";
}

/**
 * Keep one global llmModel setting usable while users switch providers.
 * Provider-looking model ids are respected only for their matching provider;
 * otherwise the selected provider's default is used.
 */
export function resolveProviderModel(provider: LlmProvider, configured: string): string {
  const fallback = PROVIDER_DEFAULT_MODEL[provider];
  const model = configured.trim();
  if (!model) { return fallback; }

  if (provider === "custom") {
    const hint = modelProviderHint(model);
    return hint === "custom" ? fallback : model;
  }

  const hint = modelProviderHint(model);
  if (hint !== "unknown" && hint !== provider) { return fallback; }
  return model;
}

export function validateProviderSelection(
  provider: LlmProvider,
  model: string,
  baseUrl?: string,
): string | null {
  const trimmedModel = model.trim();
  if (!trimmedModel || trimmedModel === PROVIDER_DEFAULT_MODEL.custom) {
    return provider === "custom"
      ? "Custom / Other needs an exact model id before testing or generating prompts."
      : `${PROVIDER_LABEL[provider]} needs a model id. Pick a model in VibeSec Settings.`;
  }

  if (provider === "custom") {
    const endpoint = (baseUrl ?? "").trim();
    if (!endpoint) {
      return "Custom / Other needs an OpenAI-compatible chat completions endpoint.";
    }
    try {
      const url = new URL(endpoint);
      if (url.protocol !== "https:" && url.protocol !== "http:") {
        return "Custom / Other endpoint must start with http:// or https://.";
      }
    } catch {
      return "Custom / Other endpoint is not a valid URL.";
    }
  }

  return null;
}
