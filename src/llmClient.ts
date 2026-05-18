import { logBus } from "./logBus";
import { PROVIDER_DEFAULT_MODEL, PROVIDER_LABEL } from "./llmModels";
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
  /** For custom/OpenAI-compatible providers, the full chat completions endpoint URL. */
  baseUrl?: string;
  /** Optional abort signal so callers can cancel in-flight requests. */
  signal?: AbortSignal;
}

const DEFAULT_MAX_TOKENS = 1024;
const REQUEST_TIMEOUT_MS = 60_000;

export { PROVIDER_DEFAULT_MODEL };

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
    case "groq":      return callGroq(opts);
    case "custom":    return callCustomOpenAICompatible(opts);
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
  baseUrl?: string,
): Promise<string> {
  return callLlm(provider, {
    apiKey,
    model,
    baseUrl,
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
  const label = PROVIDER_LABEL[provider];
  if (status === 401 || status === 403) {
    return new LlmClientError(
      `${label}: API key was rejected (HTTP ${status}). Run "VibeSec: Set API Key" to update it.`,
      provider, status,
    );
  }
  if (status === 429) {
    const snippet = body.replace(/\s+/g, " ").trim().slice(0, 180);
    const detail = snippet ? ` Provider said: ${snippet}` : "";
    return new LlmClientError(
      `${label}: rate limit hit (HTTP 429). Your API key reached the provider, but this account or selected model is being throttled. Wait for the provider limit to reset, choose another model/provider, or use a key with more quota.${detail}`,
      provider, status,
    );
  }
  if (status === 413) {
    return new LlmClientError(
      `${label}: request is too large for the selected model/account limit (HTTP 413). Try a smaller prompt mode, fewer findings, a larger model, or another provider.`,
      provider, status,
    );
  }
  if (status >= 500) {
    return new LlmClientError(
      `${label}: server error (HTTP ${status}). The provider may be down; try again shortly.`,
      provider, status,
    );
  }
  // Try to surface the provider's error message but truncate noise
  const snippet = body.replace(/\s+/g, " ").trim().slice(0, 240);
  return new LlmClientError(
    `${label}: request failed (HTTP ${status}). ${snippet}`,
    provider, status,
  );
}

function networkError(provider: LlmProvider, err: unknown): LlmClientError {
  const label = PROVIDER_LABEL[provider];
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.includes("aborted") || msg.includes("AbortError")) {
    return new LlmClientError(
      `${label}: request timed out or was cancelled.`,
      provider,
    );
  }
  return new LlmClientError(
    `${label}: network error: ${msg}. Check your internet connection.`,
    provider,
  );
}

// ── OpenAI ───────────────────────────────────────────────────────────────────

async function callOpenAI(opts: LlmCallOptions): Promise<string> {
  const { apiKey, model, prompt, maxTokens, signal } = opts;
  const url = "https://api.openai.com/v1/chat/completions";
  const buildBody = (tokenField: "max_completion_tokens" | "max_tokens") => ({
    model,
    messages: [{ role: "user", content: prompt }],
    [tokenField]: maxTokens ?? DEFAULT_MAX_TOKENS,
  });

  const post = async (tokenField: "max_completion_tokens" | "max_tokens"): Promise<Response> =>
    fetchWithTimeout(url, {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${apiKey}`,
      },
      body: JSON.stringify(buildBody(tokenField)),
    }, REQUEST_TIMEOUT_MS, signal);

  let res: Response;
  try {
    res = await post("max_completion_tokens");
  } catch (err) { throw networkError("openai", err); }

  let text = await res.text();
  if (!res.ok && res.status === 400 && /max_completion_tokens/i.test(text)) {
    try {
      res = await post("max_tokens");
      text = await res.text();
    } catch (err) { throw networkError("openai", err); }
  }
  if (!res.ok) { throw friendlyError("openai", res.status, text); }

  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const parsed = JSON.parse(text) as any;
    const content = parsed?.choices?.[0]?.message?.content;
    if (typeof content !== "string" || content.trim() === "") {
      if (Array.isArray(content)) {
        const joined = content
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          .map((part: any) => typeof part?.text === "string" ? part.text : typeof part?.content === "string" ? part.content : "")
          .join("\n")
          .trim();
        if (joined) { return joined; }
      }
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


// ── Groq / OpenAI-compatible ────────────────────────────────────────────────

async function callGroq(opts: LlmCallOptions): Promise<string> {
  // Groq uses an OpenAI-compatible chat-completions API. Users only need to
  // paste a Groq API key that starts with gsk_; VibeSec supplies the endpoint.
  return callOpenAICompatible("groq", {
    ...opts,
    baseUrl: opts.baseUrl || "https://api.groq.com/openai/v1/chat/completions",
  });
}

// ── Custom / OpenAI-compatible ──────────────────────────────────────────────

/**
 * Users often paste either the full chat-completions URL or only the provider
 * base URL. Accept both so custom providers such as OpenRouter, Groq, Together,
 * LM Studio, Ollama gateways, and company gateways are easier to configure.
 */
function normalizeCustomChatCompletionsUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) { return ""; }
  const withoutSlash = trimmed.replace(/\/+$/, "");
  if (/\/chat\/completions$/i.test(withoutSlash)) { return withoutSlash; }
  if (/\/v1$/i.test(withoutSlash) || /\/openai\/v1$/i.test(withoutSlash)) {
    return `${withoutSlash}/chat/completions`;
  }
  return withoutSlash;
}

async function callCustomOpenAICompatible(opts: LlmCallOptions): Promise<string> {
  return callOpenAICompatible("custom", opts);
}

async function callOpenAICompatible(
  provider: "groq" | "custom",
  opts: LlmCallOptions,
): Promise<string> {
  const { apiKey, model, prompt, maxTokens, signal } = opts;
  const url = normalizeCustomChatCompletionsUrl(opts.baseUrl || "");
  if (!url) {
    throw new LlmClientError(
      `${PROVIDER_LABEL[provider]}: missing API endpoint. Add an OpenAI-compatible endpoint in VibeSec Settings, for example https://openrouter.ai/api/v1/chat/completions or https://api.groq.com/openai/v1/chat/completions.`,
      provider,
    );
  }
  if (!model.trim() || model.trim() === "custom-model") {
    throw new LlmClientError(
      `${PROVIDER_LABEL[provider]}: missing model name. Write the exact model id in VibeSec Settings before testing or generating prompts.`,
      provider,
    );
  }

  const body = {
    model: model.trim(),
    messages: [{ role: "user", content: prompt }],
    max_tokens: maxTokens ?? DEFAULT_MAX_TOKENS,
  };

  let res: Response;
  try {
    res = await fetchWithTimeout(url, {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${apiKey}`,
        // OpenRouter accepts these optional headers; other OpenAI-compatible
        // providers normally ignore unknown headers.
        "HTTP-Referer":  "https://vibesec.local",
        "X-Title":       "VibeSec",
      },
      body: JSON.stringify(body),
    }, REQUEST_TIMEOUT_MS, signal);
  } catch (err) { throw networkError(provider, err); }

  const text = await res.text();
  if (!res.ok) { throw friendlyError(provider, res.status, text); }

  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const parsed = JSON.parse(text) as any;
    const msg = parsed?.choices?.[0]?.message;
    const content = msg?.content;
    if (typeof content === "string" && content.trim() !== "") { return content; }
    if (Array.isArray(content)) {
      const joined = content
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .map((part: any) => typeof part?.text === "string" ? part.text : typeof part?.content === "string" ? part.content : "")
        .join("\n")
        .trim();
      if (joined) { return joined; }
    }

    // Some compatible providers return plain text in different places.
    const alt = parsed?.choices?.[0]?.text ?? parsed?.output_text ?? parsed?.text;
    if (typeof alt === "string" && alt.trim() !== "") { return alt; }
    throw new Error("missing message content");
  } catch (err) {
    throw new LlmClientError(
      `${PROVIDER_LABEL[provider]}: could not parse response: ${err instanceof Error ? err.message : String(err)}`,
      provider,
    );
  }
}
