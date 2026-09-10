# Third-party assets embedded in the binary

Every byte a user's browser fetches for a sign-in page comes from this
directory, compiled into the server with `include_bytes!`/`include_str!`. There
is no CDN, no `@import` and no `<link>` to an origin nobody reviewed: the
Content-Security-Policy (`asterius_web::csp`) is `default-src 'none'` with
`font-src 'self'`, so anything not served from here could not load anyway.

Both licences are reproduced beside the files they cover, which is what both of
them require of a redistribution.

## `fonts/Geist-Variable.woff2`

* Upstream: <https://github.com/vercel/geist-font>, tag `v1.7.2`,
  `packages/next/dist/fonts/geist-sans/Geist-Variable.woff2`.
* `sha256: 2ffebe993e969069a9789d15164b7715d42491b5835516c5e3b935d5f81b05f1`
* 69 760 bytes, unmodified.
* Licence: SIL Open Font License 1.1 — `fonts/OFL.txt`, the upstream `OFL.txt`
  of the same tag.

One variable file rather than three static ones: the design asks for 400, 500
and 600, and three static faces would be three requests and roughly three times
the bytes. The `@font-face` in `crates/web/templates/base.html` declares
`font-weight: 100 900` because that is the axis range the file really carries.

The URL carries a hash of these bytes (`asterius_web::brand::FONT`), so the
response is `Cache-Control: public, max-age=31536000, immutable`: a new file is
a new URL and there is nothing to revalidate.

## `icons/*.svg`

* Upstream: <https://github.com/lucide-icons/lucide>, tag `1.44.0`, `icons/`.
* Licence: ISC — `icons/LICENSE`, the upstream `LICENSE` of the same tag.

**Modified.** Each file here holds only the *geometry* of the upstream icon:
the `<svg>` wrapper and every presentation attribute (size, `viewBox`,
`stroke`, `stroke-width`, `stroke-linecap`, `stroke-linejoin`) is written by
`asterius_web::brand`, not read from the file. That is deliberate: the markup
is inlined into a document unescaped, so the smaller the surface that comes
from a file, the smaller the thing a review has to look at. The elements a body
may contain are checked by `brand`'s tests over all twenty-four files.

`fingerprint` is absent from upstream 1.44.0 under that name; `id-card` stands
in for it in the curated set.
