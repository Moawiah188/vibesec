// Typed wrapper around acquireVsCodeApi(). The function is injected by the
// VS Code webview runtime; it must be called exactly once per webview instance.

import type { ExtensionToWebview, WebviewToExtension } from "./types";

interface VsCodeApi {
  postMessage(msg: unknown): void;
  getState(): unknown;
  setState(state: unknown): void;
}

declare function acquireVsCodeApi(): VsCodeApi;

let api: VsCodeApi | null = null;

function getApi(): VsCodeApi {
  if (api === null) {
    api = acquireVsCodeApi();
  }
  return api;
}

export function postMessage(msg: WebviewToExtension): void {
  getApi().postMessage(msg);
}

export function onMessage(handler: (msg: ExtensionToWebview) => void): () => void {
  const listener = (event: MessageEvent): void => {
    handler(event.data as ExtensionToWebview);
  };
  window.addEventListener("message", listener);
  return () => window.removeEventListener("message", listener);
}
