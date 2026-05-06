import { logBus } from "./logBus";
import { LlmProvider } from "./types";

// ── Thin LLM HTTP client (Sprint 4) ──────────────────────────────────────────
//
// One small function per provider. We use Node 18+'s built-in `fetch` (VS Code
// 1.85+ ships with Node 18+), so no extra dependency is needed.
//
// Each client takes an instruction and returns the raw text response from the
// model. Higher layers (promptGenerator.ts) decide what to put in the
// instruction and what to do with the response. Errors are normalized to
// LlmClientError with a friendly message that's safe to show in a VS Code
// notification.

export class LlmClientError extends Error {
  constructor(
    message: string,
    readonly provider: LlmProvider,
    readonly statusCode?: number,
  ) {
    super(message);
    this.name = "LlmClientError";
  }
}

export interface LlmCallOptions {
  apiKey:  string;
  model:   string;
  /** Plain-text instruction for the model. */
  prompt:  string;
  /** Optional override; defaults to a sane upper bound per provider. */
  maxTokens?: number;
  /** Optional abort signal so callers can cancel in-flight requests. */
  signal?: AbortSignal;
}

const DEFAULT_MAX_TOKENS = 1024;
const REQUEST_TIMEOUT_MS = 60_000;

export const PROVIDER_DEFAULT_MODEL: Record<LlmProvider, string> = {
  openai:    "gpt-5-nano",
  anthropic: "claude-haiku-4-5",
  gemini:    "gemini-2.5-flash-lite",
};

// ── Public dispatch ──────────────────────────────────────────────────────────

export async function callLlm(
  provider: LlmProvider,
  opts: LlmCallOptions,
): Promise<string> {
  const start = Date.now();
  logBus.info(
    "api",
    `${provider} request started`,
    `model=${opts.model}\nprompt-length=${opts.prompt.length}`,
  );
  try {
    const out = await dispatchProvider(provider, opts);
    const ms = Date.now() - start;
    logBus.info(
      "api",
      `${provider} request succeeded (${ms}ms)`,
      `model=${opts.model}\nresponse-length=${out.length}`,
    );
    return out;
  } catch (err: unknown) {
    const ms = Date.now() - start;
    const status = err instanceof LlmClientError ? err.statusCode : undefined;
    const msg    = err instanceof Error ? err.message : String(err);
    logBus.error(
      "api",
      `${provider} request failed${status !== undefined ? ` (HTTP ${status})` : ""} after ${ms}ms`,
      `model=${opts.model}\n${msg}`,
    );
    throw err;
  }
}

function dispatchProvider(provider: LlmProvider, opts: LlmCallOptions): Promise<string> {
  switch (provider) {
    case "openai":    return callOpenAI(opts);
    case "anthropic": return callAnthropic(opts);
    case "gemini":    return callGemini(opts);
  }
}

/**
 * Send a tiny "ping" prompt to confirm the API key + model + network all work.
 * Resolves with the response text on success; rejects with LlmClientError.
 */
export async function pingProvider(
  provider: LlmProvider,
  apiKey: string,
  model: string,
): Promise<string> {
  return callLlm(provider, {
    apiKey,
    model,
    prompt: "Reply with the single word: pong.",
    maxTokens: 16,
  });
}

// ── Shared fetch helper with timeout ─────────────────────────────────────────

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  externalSignal?: AbortSignal,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  if (externalSignal) {
    if (externalSignal.aborted) { controller.abort(); }
    else { externalSignal.addEventListener("abort", () => controller.abort()); }
  }
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function friendlyError(provider: LlmProvider, status: number, body: string): LlmClientError {
  if (status === 401 || status === 403) {
    return new LlmClientError(
      `${provider}: API key was rejected (HTTP ${status}). Run "VibeSec: Set API Key" to update it.`,
      provider, status,
    );
  }
  if (status === 429) {
    return new LlmClientError(
      `${provider}: rate limit hit (HTTP 429). Wait a moment and try again.`,
      provider, status,
    );
  }
  if (status >= 500) {
    return new LlmClientError(
      `${provider}: server error (HTTP ${status}). The provider may be down — try again shortly.`,
      provider, status,
    );
  }
  // Try to surface the provider's error message but truncate noise
  const snippet = body.replace(/\s+/g, " ").trim().slice(0, 240);
  return new LlmClientError(
    `${provider}: request failed (HTTP ${status}). ${snippet}`,
    provider, status,
  );
}

function networkError(provider: LlmProvider, err: unknown): LlmClientError {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.includes("aborted") || msg.includes("AbortError")) {
    return new LlmClientError(
      `${provider}: request timed out or was cancelled.`,
      provider,
    );
  }
  return new LlmClientError(
    `${provider}: network error — ${msg}. Check your internet connection.`,
    provider,
  );
}

// ── OpenAI ───────────────────────────────────────────────────────────────────

async function callOpenAI(opts: LlmCallOptions): Promise<string> {
  const { apiKey, model, prompt, maxTokens, signal } = opts;
  const url = "https://api.openai.com/v1/chat/completions";
  const body = {
    model,
    messages: [{ role: "user", content: prompt }],
    max_completion_tokens: maxTokens ?? DEFAULT_MAX_TOKENS,
  };

  let res: Response;
  try {
    res = await fetchWithTimeout(url, {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
    }, REQUEST_TIMEOUT_MS, signal);
  } catch (err) { throw networkError("openai", err); }

  const text = await res.text();
  if (!res.ok) { throw friendlyError("openai", res.status, text); }

  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const parsed = JSON.parse(text) as any;
    const content = parsed?.choices?.[0]?.message?.content;
    if (typeof content !== "string" || content.trim() === "") {
      throw new Error("OpenAI returned an empty response.");
    }
    return content;
  } catch (err) {
    throw new LlmClientError(
      `openai: could not parse response — ${err instanceof Error ? err.message : String(err)}`,
      "openai",
    );
  }
}

// ── Anthropic ────────────────────────────────────────────────────────────────

async function callAnthropic(opts: LlmCallOptions): Promise<string> {
  const { apiKey, model, prompt, maxTokens, signal } = opts;
  const url = "https://api.anthropic.com/v1/messages";
  const body = {
    model,
    max_tokens: maxTokens ?? DEFAULT_MAX_TOKENS,
    messages: [{ role: "user", content: prompt }],
  };

  let res: Response;
  try {
    res = await fetchWithTimeout(url, {
      method:  "POST",
      headers: {
        "Content-Type":      "application/json",
        "x-api-key":         apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(body),
    }, REQUEST_TIMEOUT_MS, signal);
  } catch (err) { throw networkError("anthropic", err); }

  const text = await res.text();
  if (!res.ok) { throw friendlyError("anthropic", res.status, text); }

  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const parsed = JSON.parse(text) as any;
    // Anthropic returns: { content: [{ type: "text", text: "..." }] }
    const blocks = parsed?.content;
    if (!Array.isArray(blocks)) { throw new Error("missing content array"); }
    const collected = blocks
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .filter((b: any) => b?.type === "text" && typeof b.text === "string")
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .map((b: any) => b.text)
      .join("\n")
      .trim();
    if (collected === "") { throw new Error("empty text content"); }
    return collected;
  } catch (err) {
    throw new LlmClientError(
      `anthropic: could not parse response — ${err instanceof Error ? err.message : String(err)}`,
      "anthropic",
    );
  }
}

// ── Gemini ───────────────────────────────────────────────────────────────────

async function callGemini(opts: LlmCallOptions): Promise<string> {
  const { apiKey, model, prompt, maxTokens, signal } = opts;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;
  const body = {
    contents: [{ role: "user", parts: [{ text: prompt }] }],
    generationConfig: { maxOutputTokens: maxTokens ?? DEFAULT_MAX_TOKENS },
  };

  let res: Response;
  try {
    res = await fetchWithTimeout(url, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    }, REQUEST_TIMEOUT_MS, signal);
  } catch (err) { throw networkError("gemini", err); }

  const text = await res.text();
  if (!res.ok) { throw friendlyError("gemini", res.status, text); }

  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const parsed = JSON.parse(text) as any;
    const parts = parsed?.candidates?.[0]?.content?.parts;
    if (!Array.isArray(parts)) { throw new Error("missing parts array"); }
    const collected = parts
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .map((p: any) => (typeof p?.text === "string" ? p.text : ""))
      .join("")
      .trim();
    if (collected === "") { throw new Error("empty response"); }
    return collected;
  } catch (err) {
    throw new LlmClientError(
      `gemini: could not parse response — ${err instanceof Error ? err.message : String(err)}`,
      "gemini",
    );
  }
}
