import * as React from "react";
import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { AnalysisPanel } from "./AnalysisPanel";
import { onMessage, postMessage } from "./vscode";
import type { ExtensionToWebview, PanelStateMsg, PanelTreeNode, ThemeKind } from "./types";

// Theme detection — read VS Code's body class once, fall back to dark.
function detectThemeFromBody(): ThemeKind {
  const cls = document.body.classList;
  if (cls.contains("vscode-high-contrast-light")) { return "hc-light"; }
  if (cls.contains("vscode-high-contrast"))       { return "hc-dark"; }
  if (cls.contains("vscode-light"))               { return "light"; }
  return "dark";
}

function themeToDesignClass(t: ThemeKind): string {
  return t === "light" || t === "hc-light" ? "vs-theme-light" : "vs-theme-dark";
}

interface AppProps {
  logoUri: string;
}

const App: React.FC<AppProps> = ({ logoUri }) => {
  const [theme, setTheme] = useState<ThemeKind>(() => detectThemeFromBody());
  const [state, setState] = useState<PanelStateMsg>({ kind: "empty" });
  const [tree, setTree] = useState<PanelTreeNode[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [version, setVersion] = useState<string>("");

  useEffect(() => {
    const off = onMessage((msg: ExtensionToWebview) => {
      switch (msg.type) {
        case "init":
          setTheme(msg.theme);
          setVersion(msg.version);
          break;
        case "themeChanged":
          setTheme(msg.theme);
          break;
        case "workspaceTree":
          setTree(msg.tree);
          if (msg.defaultSelected.length > 0) {
            setSelected(new Set(msg.defaultSelected));
          }
          break;
        case "stateUpdated":
          setState(msg.state);
          break;
        case "progressUpdated":
          setState((prev) =>
            prev.kind === "loading"
              ? { kind: "loading", percent: msg.percent, currentFile: msg.currentFile }
              : prev,
          );
          break;
      }
    });

    postMessage({ type: "ready" });
    postMessage({ type: "getWorkspaceTree" });

    return off;
  }, []);

  const themeClass = themeToDesignClass(theme);

  return (
    <div
      className={`${themeClass} vs-accent-green vs-density-comfortable`}
      style={{ width: "100%", height: "100%", display: "flex" }}
    >
      <AnalysisPanel
        state={state}
        tree={tree}
        selected={selected}
        onSelectionChange={setSelected}
        logoUri={logoUri}
        version={version}
      />
    </div>
  );
};

const rootEl = document.getElementById("root");
if (rootEl) {
  // The HTML template injects window.__VIBESEC_LOGO_URI__ via asWebviewUri().
  const logoUri = (window as unknown as { __VIBESEC_LOGO_URI__?: string }).__VIBESEC_LOGO_URI__ ?? "";
  createRoot(rootEl).render(<App logoUri={logoUri} />);
}
