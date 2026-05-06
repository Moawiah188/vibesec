// Typed wrapper around acquireVsCodeApi() for the Control Center webview.
// Mirrors webview/vscode.ts — both webviews need their own typed bridge
// because they have different message protocols.

import type { CcExtensionToWebview, CcWebviewToExtension } from "./types";

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

export function postMessage(msg: CcWebviewToExtension): void {
  getApi().postMessage(msg);
}

export function onMessage(handler: (msg: CcExtensionToWebview) => void): () => void {
  const listener = (event: MessageEvent): void => {
    handler(event.data as CcExtensionToWebview);
  };
  window.addEventListener("message", listener);
  return () => window.removeEventListener("message", listener);
}
