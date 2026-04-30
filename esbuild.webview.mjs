// Bundles the React-based VibeSec analysis panel into a single IIFE
// that can be loaded by a VS Code webview under a strict CSP nonce.
//
// Outputs:
//   media/webview/main.js
//   media/webview/styles.css
//
// Usage:
//   node esbuild.webview.mjs            # one-shot production build
//   node esbuild.webview.mjs --watch    # rebuild on change

import * as esbuild from "esbuild";

const watch = process.argv.includes("--watch");

const config = {
  entryPoints: ["webview/main.tsx", "webview/styles.css"],
  outdir: "media/webview",
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "es2020",
  loader: { ".css": "css", ".svg": "dataurl", ".png": "dataurl" },
  define: { "process.env.NODE_ENV": "\"production\"" },
  jsx: "automatic",
  minify: true,
  sourcemap: false,
  logLevel: "info",
};

if (watch) {
  const ctx = await esbuild.context(config);
  await ctx.watch();
  console.log("[esbuild] watching webview/...");
} else {
  await esbuild.build(config);
}
