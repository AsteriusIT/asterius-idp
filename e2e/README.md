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

The one page in the tree that carries script — `crates/web/templates/passkey.html`,
exempted by name in `SCRIPTED_TEMPLATES` — has no route yet (`ast-2vk.15` owns
`/passkeys/options` and `/passkeys/finish`). Until it does, the JS suite
exercises `'strict-dynamic'` only through the negative proof. The assertion is
written and marked `fixme` in `tests/csp-sweep.spec.ts`.

## The negative proof

`tests/csp-gate.spec.ts` serves a page that violates the policy — an image from
an origin `img-src` does not name, an inline style, an inline script — under the
**real** policy header, read off a live response from the server under test, and
asserts that the same `assertClean` every other test relies on refuses it. It
runs in both projects, because a gate that only fires when script is enabled
would leave the no-JS suite unguarded.

Without it the sweep would pass just as happily against a browser reporting
nothing at all.

## Known failure

`tests/no-js-flow.spec.ts` marks the last hop `test.fail()`: Chromium enforces
`form-action` across the redirects of a form submission, and the consent page is
served `form-action 'self'`, so the 303 carrying the authorization code to the
client is refused. The code and the grant are written; the browser simply never
follows. The seam to fix it exists — `Policy::with_form_post_to` — and is not
used by the consent page. The annotation is `fail` and not `skip` so that the
run goes red the day it starts passing.

## Fixture notes

- The tenant is given a `custom_host` by `fixtures/seed.sql`, after the server
  has booted. `/authorize` redirects to `/interaction/{id}` and both pages post
  to `/interaction/{id}` — root-relative, with no tenant prefix — so a tenant
  reachable only at `/t/{id}/…` loses its tenant on the second hop.
  `crates/server/src/tenancy.rs` resolves a prefix-less path by host, and
  `by_host` is indexed on `custom_host` alone. There is no configuration key for
  it yet, so the harness writes the column. The seed runs *after* boot because
  the tenant upsert at startup writes `custom_host` back to NULL.
- The server terminates TLS with a certificate issued for the run. Loopback
  would be treated as a secure origin over plain HTTP too, which is exactly why
  it is not good enough: it would prove the cookie survives on the one origin
  where the rule is relaxed.
- `E2E_RESET_DB=1` drops and recreates the public schema first, for a
  development database that predates a change to the baseline migration.

## The toolchain

Node lives here and nowhere else: one directory, one committed `package-lock.json`,
exact versions in `package.json` (no `^`), and one browser (`chromium`). The CI
job installs from the lockfile.
