# Vendored fonts

Both fonts are distributed under the adjacent `OFL.txt` (SIL OFL 1.1).
Geist Variable is shared by the interaction pages and console.

Geist Mono Variable was copied without modification from
`vercel/geist-font` commit `10dc7658f13c38a474cde201bb09a4617267545b`,
`fonts/GeistMono/webfonts/GeistMono[wght].woff2`.
The upstream OFL file matches the existing license byte for byte.

The console imports both fonts through `console/src/fonts.css`. Vite emits
hashed WOFF2 assets, which the existing console asset route embeds and serves.
