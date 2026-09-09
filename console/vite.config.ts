/**
 * The console build, shaped by the policy it is served under (ADR-0009).
 *
 * Four settings here are security decisions rather than preferences:
 *
 *  - `base: './'` — every asset URL the manifest names is *relative*, and the
 *    entry document is served at `/admin/` (with the trailing slash) so that
 *    they resolve against it. A tenant reachable only at `/t/{id}/…` would
 *    lose its prefix on a root-relative URL, which is the failure the browser
 *    sweep's fixture notes already record for the interaction pages.
 *  - `manifest: true` — the server renders the entry document itself, because
 *    a static `index.html` cannot carry a nonce that changes per response. The
 *    manifest is how the build tells it which hashed files to name.
 *  - `modulePreload.polyfill: false` — the polyfill is an *inline* script Vite
 *    injects into its own `index.html`. Nothing inline can run under
 *    `script-src 'nonce-…'`, and every browser this console supports has
 *    module preload natively.
 *  - `cssCodeSplit: false` — one stylesheet, named by the manifest, so the
 *    document can put a nonce on one `<link>` rather than discovering more of
 *    them at runtime, which `style-src 'nonce-…'` would then block.
 *
 * React 19's automatic JSX runtime is taken from `tsconfig.json`
 * (`"jsx": "react-jsx"`), which the transform reads: no Babel plugin in the
 * dependency tree to keep patched, and no `import React` in every file.
 *
 * There is no dev server configuration and that is deliberate: its hot-reload
 * transport is a websocket to a different origin, which `connect-src 'self'`
 * refuses. The console is developed against a built bundle served by the
 * binary.
 */
import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    manifest: true,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
    // A source map would be a second file per chunk shipped inside the binary,
    // describing the admin surface to anyone who fetches it.
    sourcemap: false,
    rollupOptions: {
      input: 'src/main.tsx',
    },
  },
});
