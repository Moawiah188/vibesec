import type { LlmProvider } from "./types";

export const PROVIDER_LABEL: Record<LlmProvider, string> = {
  openai: "OpenAI",
  anthropic: "Anthropic",
  gemini: "Gemini",
  groq: "Groq",
  custom: "Custom / Other",
};

export const PROVIDER_DEFAULT_MODEL: Record<LlmProvider, string> = {
  openai: "gpt-5-nano",
  anthropic: "claude-haiku-4-5",
  gemini: "gemini-2.5-flash-lite",
  groq: "llama-3.1-8b-instant",
  custom: "custom-model",
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

export function providerModelPresets(provider: LlmProvider): readonly string[] {
  return PROVIDER_MODEL_PRESETS[provider] ?? [];
}
