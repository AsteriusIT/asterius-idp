# Browser sweep

The only tests in this repository that run a browser. Everything else asserts
what the source says; these assert what Chromium does with it.

```sh
./scripts/browser-tests.sh                  # both suites
./scripts/browser-tests.sh --project=no-js  # only the no-JS suite
./scripts/browser-tests.sh --headed         # watch it happen
```

Arguments are passed through to `playwright test`. The script starts everything
it needs — a certificate, a server, the fixture rows — and deletes it again.
Nothing is left behind except rows in the development database.

## What it proves that nothing else can

- **The pages work with JavaScript disabled.** `crates/web/src/source_audit.rs`
  proves no template contains a `<script>`. It cannot prove that a browser with
  script switched off can actually sign in and consent.
- **The `__Host-` cookie is accepted.** The prefix's guarantees are enforced by
  the browser: a cookie that fails any of them is dropped silently, and a server
  cannot tell. Its presence in `context.cookies()` is the proof that the
  attributes in `asterius_web::interaction` earn the prefix.
- **No page provokes a CSP violation**, in either the no-JS or the JS suite, and
  a page that does fails the run — see the negative proof below.

## The suites

`playwright.config.ts` defines two projects. **no-js** is the one this
repository cares most about and is where the flow runs. **js** is not redundant:
`script-src 'nonce-…' 'strict-dynamic'` says nothing at all to a browser that
will not run script, so only a scripted browser can tell a correct nonce from a
missing one.

The pages that carry script — `passkey.html` and, since `ast-2vk.4`, the passkey
block on `login.html` — are exempted by name in `SCRIPTED_TEMPLATES`, and both
are swept with script enabled: `tests/csp-sweep.spec.ts` runs their nonced
bootstraps, and `tests/passkey-ceremony.spec.ts` runs a whole WebAuthn ceremony
through them.

## The negative proof

`tests/csp-gate.spec.ts` serves a page that violates the policy — an image from
an origin `img-src` does not name, an inline style, an inline script — under the
**real** policy header, read off a live response from the server under test, and
asserts that the same `assertClean` every other test relies on refuses it. It
runs in both projects, because a gate that only fires when script is enabled
would leave the no-JS suite unguarded.

Without it the sweep would pass just as happily against a browser reporting
nothing at all.

## What this suite found

The last hop in `tests/no-js-flow.spec.ts` was a documented `test.fail()` until
`ast-jsq`: Chromium enforces `form-action` across the *redirects* of a form
submission, and the consent page was served `form-action 'self'`, so the 303
carrying the authorization code to the client was refused — the code and the
grant were written and the browser simply never followed. The consent page now
uses `Policy::with_form_post_to` and names the origin of the `redirect_uri` this
authorization was validated against, one origin and that page only.
`tests/csp-sweep.spec.ts` asserts both halves: the widening on the consent page,
and its absence on every other page.

## Fixture notes

- The tenant is given a `custom_host` by `fixtures/seed.sql`, after the server
  has booted. `/authorize` redirects to `/interaction/{id}` and both pages post
  to `/interaction/{id}` — root-relative, with no tenant prefix — so a tenant
  reachable only at `/t/{id}/…` loses its tenant on the second hop.
  `crates/server/src/tenancy.rs` resolves a prefix-less path by host, and
  `by_host` is indexed on `custom_host` alone. There is no configuration key for
  it yet, so the harness writes the column. The seed runs *after* boot because
  the tenant upsert at startup writes `custom_host` back to NULL.
- The client's callback is `https://rp.example.test:{port}/cb`: a name RFC 6761
  reserves, mapped to the loopback by `--host-resolver-rules` in
  `playwright.config.ts`. Cross-origin from the server on purpose — a
  same-origin callback is what passed while the flow was broken for every real
  client — and unroutable off the machine, so a code cannot escape. What answers
  there is the server itself with a 404; the assertion is the URL the browser
  arrived at. A Playwright `route` cannot stand in for it: interception is never
  offered the redirect hop of a form submission, so it reports a DNS failure
  where the browser was in fact willing to navigate.
- The server terminates TLS with a certificate issued for the run. Loopback
  would be treated as a secure origin over plain HTTP too, which is exactly why
  it is not good enough: it would prove the cookie survives on the one origin
  where the rule is relaxed.
- There are **two** tenants, and the second one exists for one reason
  (`ast-kb0`). The RP ID this server derives is the issuer's host with the port
  removed, so the sweep tenant — issued at `https://127.0.0.1:{port}/t/e2e` —
  cannot run a WebAuthn ceremony at all: an IP literal is not a domain and
  Chromium refuses before any authenticator is consulted. The address was
  chosen deliberately and still is, so `e2e-webauthn` was added on `localhost`
  beside it rather than moving it. `localhost` and not a `.test` name: browsers
  accept it as an RP ID, the run certificate already carries it, and no
  resolver has to be taught anything. The `::1`-first hazard the fixture warns
  about is answered rather than ignored: Chromium is pinned to the loopback by
  `--host-resolver-rules`, and `scripts/browser-tests.sh` refuses to start the
  sweep unless `https://localhost:{port}/readyz` answers, so a name that
  resolves away from the bound socket is a precondition failure with a sentence
  attached. Reaching that tenant at `127.0.0.1/t/e2e-webauthn` instead is not
  an option and should not be made one: `tenancy::resolve` requires the `Host`
  to be one the tenant answers to, which is what stops
  `https://anything/t/x/token` minting tokens for an issuer the request never
  reached.
- `E2E_RESET_DB=1` drops and recreates the public schema first, for a
  development database that predates a change to the baseline migration.

## The toolchain

Node lives here and nowhere else: one directory, one committed `package-lock.json`,
exact versions in `package.json` (no `^`), and one browser (`chromium`). The CI
job installs from the lockfile.
