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
- **A rotation an operator performs really rotates.** `tests/key-rotation.spec.ts`
  presses the console's button and then fetches the published JWK Set the way a
  relying party would: the new `kid` is signing and the previous one is still
  published (OIDC Core §10.1.1). The API-level proof (`ast-f7m.7`) cannot say
  what the button does.
- **A cloned authenticator is refused and the credential is blocked.**
  `tests/passkey-clone.spec.ts` (`ast-qwu`) enrols a passkey, signs in with it,
  then puts the same private key back into the virtual authenticator at an older
  signature counter — a clone, as far as WebAuthn L3 §7.2 step 21 is concerned.
  The sign-in is refused, the credential stays refused when the *genuine* device
  comes back ahead of the stored counter, and the audit trail carries
  `auth.failed` with `reason = sign_count_regression`. No Rust test can make a
  clone: it takes an authenticator that will sign with a key the test chose.
- **Every page a route really renders passes axe** at WCAG 2.1 AA —
  `tests/accessibility.spec.ts` for the server-rendered ones, `console.spec.ts`
  and `key-rotation.spec.ts` for the console's screens. The templates that are
  wired to no handler yet (device flow, registration, password recovery) are
  deliberately absent: a test of an unreachable page is a test of nothing.

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

The signed-out page in `tests/accessibility.spec.ts` is a documented
`test.fail()` for the same kind of reason (`ast-rna`). The logout confirmation
posts to the bare `/logout`, root-relative and with no mount prefix, so on a
path-routed tenant the answer lands on a 404 and pressing "Log out" ends
nothing. `ast-295` gave the rendered URLs their prefix and
`crates/server/src/http/logout.rs::confirmation_page` was missed; `ast-f0y`
then removed the `custom_host` fixture that had been hiding it. The day the
action carries its prefix, the test passes unexpectedly and the annotation
comes off.

## Fixture notes

- Both tenants are addressed by their path — `https://127.0.0.1:{port}/t/e2e`
  and `https://localhost:{port}/t/e2e-webauthn`, which are their issuers. That
  is the shape a deployment gets without extra DNS, and it is the shape the
  sweep should walk.

  It used to be impossible: `/authorize` named `/interaction/{id}` root-relative,
  with no tenant prefix, so the browser lost its tenant on the second hop and met
  a 404. The harness papered over it by writing `custom_host` on the tenant after
  boot — the seed had to run after boot because the tenant upsert at startup
  writes that column back to NULL — which made the tenant host-routed and left
  the path-based flow untested. `ast-295` made every URL a handler renders to
  the browser carry the mount prefix, and `ast-f0y` removed the fixture
  statement: a workaround kept past its cause hides the next regression.
  `crates/server/tests/authorize.rs::the_redirect_keeps_the_prefix_the_request_arrived_under`
  is where that promise is asserted at the unit level.

  `/healthz`, `/readyz` and `/metrics` stay at the origin: they describe the
  process, not a tenant, and `scripts/browser-tests.sh` polls them there.
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
