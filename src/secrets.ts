import * as vscode from "vscode";
import { ALL_PROVIDERS, PROVIDER_LABEL } from "./llmModels";
import { LlmProvider } from "./types";

// ── Secret storage wrapper (Sprint 4) ────────────────────────────────────────
//
// API keys are stored using VS Code's built-in `context.secrets` so they
// never appear in settings.json or sync via Settings Sync. Each provider
// gets its own slot so users can keep keys for multiple providers at once
// and switch between them via the `vibesec.llmProvider` setting.

const KEY_PREFIX = "vibesec.apiKey";

function storageKey(provider: LlmProvider): string {
  return `${KEY_PREFIX}.${provider}`;
}

export { ALL_PROVIDERS, PROVIDER_LABEL };

export async function getApiKey(
  context: vscode.ExtensionContext,
  provider: LlmProvider,
): Promise<string | undefined> {
  return context.secrets.get(storageKey(provider));
}

export async function setApiKey(
  context: vscode.ExtensionContext,
  provider: LlmProvider,
  key: string,
): Promise<void> {
  await context.secrets.store(storageKey(provider), key);
}

export async function clearApiKey(
  context: vscode.ExtensionContext,
  provider: LlmProvider,
): Promise<void> {
  await context.secrets.delete(storageKey(provider));
}

/**
 * Prompt the user to pick a provider via QuickPick. Returns the chosen
 * provider, or undefined if they cancelled.
 */
export async function pickProvider(
  placeHolder: string,
): Promise<LlmProvider | undefined> {
  const items: (vscode.QuickPickItem & { value: LlmProvider })[] = ALL_PROVIDERS.map(
    (p) => ({ label: PROVIDER_LABEL[p], value: p }),
  );
  const choice = await vscode.window.showQuickPick(items, { placeHolder, ignoreFocusOut: true });
  return choice?.value;
}
