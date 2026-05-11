// Bundles the React-based VibeSec webviews into IIFEs that can be loaded
// by VS Code under a strict CSP nonce.
//
// Outputs:
//   media/design/main.js          (Analysis panel — sidebar)
//   media/design/styles.css       (Analysis panel styles)
//   media/design/controlCenter.js (Control Center — editor-area panel)
//   media/design/controlCenter.css(Control Center styles)
//
// `entryNames: '[name]'` flattens output so the controlCenter sources can
// live in their own subdirectory without nesting in the output tree.
//
// Usage:
//   node esbuild.design.mjs            # one-shot production build
//   node esbuild.design.mjs --watch    # rebuild on change

import * as esbuild from "esbuild";

const watch = process.argv.includes("--watch");

const config = {
  entryPoints: [
    "design/main.tsx",
    "design/styles.css",
    "design/controlCenter/controlCenter.tsx",
    "design/controlCenter/controlCenter.css",
  ],
  outdir: "media/design",
  entryNames: "[name]",
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
  console.log("[esbuild] watching design/...");
} else {
  await esbuild.build(config);
}
