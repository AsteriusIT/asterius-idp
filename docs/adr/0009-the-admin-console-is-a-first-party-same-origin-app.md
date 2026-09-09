# ADR-0009: The admin console is a first-party same-origin app, not an OAuth client

- **Status:** Accepted
- **Date:** 2026-09-09
- **Bead:** ast-f7m.2
- **Deciders:** Quentin RODIC
- **Refines:** [ADR-0002](0002-fapi-2-0-as-the-only-mode.md)

## Context

`crates/admin-api` is a `Cargo.toml`, a module doc and `#![forbid(unsafe_code)]`.
Nothing is built yet, which is the only reason this decision is still open: the
console (`ast-f7m.3`) and the first administrator (`ast-1cj`) both need to know
what an admin *is* before either can be written, and that follows from how the
console authenticates rather than the other way round.

The obvious shape for an admin UI is a single-page application holding an access
token. This repository cannot have that one, and the reason is in the profile it
already committed to.

**FAPI 2.0 SP §5.3.2.1 item 3 says authorization servers "shall only support
confidential clients as defined in [RFC6749]".** That is an obligation on *this
server*, not advice to client authors: there is no conforming way for Asterius
to register a public client, so "should the console be a public client with
DPoP?" is not a trade-off here, it is a request to break the baseline ADR-0002
already recorded ("No implicit flow, no hybrid flow, no ROPC, no public
clients"). The bridge to the console is RFC 6749 §2.1, which defines the client
type the clause points at: a "user-agent-based application is a public client in
which the client code is downloaded from a web server and executes within a
user-agent (e.g., web browser) … Protocol data and credentials are easily
accessible (and often visible) to the resource owner." A bundle served to a
browser cannot hold a `private_key_jwt` key or an mTLS certificate, which are
the only two client authentication methods §5.3.2.1 item 6 leaves, so it is
public by construction and the server may not register it.

Two corrections to the framing this bead was filed with, because an ADR that
repeats a bad citation is worse than no ADR:

- **The FAPI clause never mentions SPAs.** It is a constraint on what the server
  supports; "a browser SPA cannot be a FAPI 2.0 client" is a *derivation* from
  it through RFC 6749 §2.1, and the derivation is worth writing down because the
  conclusion is not literally in the cited sentence. It also has an escape hatch
  that matters below: a browser app whose token handling happens in a server it
  owns is a "web application" in the same taxonomy — a confidential client —
  which is exactly what option (c) proposes, and why (c) is rejected on cost
  rather than on conformance.
- **RFC 9700 §4 is not a section about browser-based applications.** §4 is
  "Attacks and Mitigations" in general. RFC 9700 has no browser-app section at
  all; the nearest normative material is §2.1.2, which says clients "SHOULD NOT
  use the implicit grant … or other response types issuing access tokens in the
  authorization response" because "no standardized method for sender-
  constraining exists to bind access tokens to a specific client … when the
  access tokens are issued in the authorization response", plus §4.3.2 on access
  tokens reaching browser history. The honest citation for "no tokens in this
  browser" is §2.1.2 and §4.3.2, and the honest reading of §4 as a whole is that
  it nowhere blesses a token-holding browser client. The §4 clause relevant to
  what is decided *here* is §4.7 (CSRF), and it arrives as a **cost** of the
  decision rather than as support for it.

The other half of the context is what the tree already provides, because the
cheapest console is the one that adds nothing.

**A first-party session already exists and is already hardened.**
`crates/web/src/session.rs` (ast-o4u.1) writes one `__Host-asterius_session`
cookie with `Secure; HttpOnly; SameSite=Lax; Path=/`, from a single attribute
list shared by set and clear. `Session`
(`crates/domain/src/entities/session.rs`) carries a `tenant`, a `user`, `acr`,
`amr` and two clocks, is stored only as a digest, and rotates its id whenever
the authentication behind it changes. A console that reuses it inherits fixation
resistance, idle and absolute expiry, revocation, and an `amr` an authorization
check can read — none of which a bearer token in `localStorage` would have.

**The strict CSP is already the one a console needs, and it is not free.**
`crates/web/src/csp.rs` emits `default-src 'none'; script-src 'nonce-…'
'strict-dynamic'; style-src 'nonce-…'; img-src 'self' data:; font-src 'self';
connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none';
object-src 'none'`, with no `'unsafe-inline'` and no `'unsafe-eval'` anywhere —
a source audit fails the build if one appears. `connect-src 'self'` is the
load-bearing line for this decision: a console calling a *different* origin
would need that directive widened, and a console calling `/admin/api` needs
nothing. The costs it imposes on `ast-f7m.3` are real and are named now rather
than discovered later: the entry document must be rendered by the server so that
every `<script>`, `<link rel="stylesheet">` and `<link rel="modulepreload">`
carries the request's nonce, since a static `index.html` emitted by a bundler
cannot — the nonce changes per response; the build must emit no inline handlers
and no `eval`, which also rules out the dev server's hot-reload transport, whose
websocket is a different origin that `connect-src 'self'` refuses; and
`crates/web/src/document.rs` applies `Cache-Control: no-store` to *documents*
only, so hashed asset responses keep their own caching.

**The CSRF machinery that exists does not cover this case.** Today's tokens are
per-interaction: `Interaction::issue_csrf` / `check_csrf` store a digest on the
interaction row, and the logout confirmation derives its synchroniser from the
session cookie. Both are form posts. A console is `fetch` against a JSON API,
and there is no interaction row to hang a token on. So option (a) is compatible
with the existing *session* but not with the existing *CSRF code*: `ast-f7m.3`
has to add a session-bound mechanism. That is the honest shape of the
adjustment, and it is small — but it is not zero, and this ADR would be lying if
it claimed the console merely reuses what is there.

**One binary and one PostgreSQL is a product promise, not an accident.**
ADR-0001 records it, the `Dockerfile` builds a `gcr.io/distroless/cc-debian12:nonroot`
image with no shell, and `docker-compose.yml` ships exactly one service — a
database for local development, with the server run from cargo. Note also that
nothing in the tree serves static assets yet: no `ServeDir`, no `rust-embed`, no
`include_dir`. Whatever ships the console ships new code under *any* option; the
question is only whether it also ships a new process.

## Decision

The admin console is a **first-party, same-origin application of the IdP**. It
authenticates with the same `__Host-asterius_session` cookie as the rest of the
first-party surface, its entry document is rendered by this server under the
existing strict CSP, and it calls `/admin/api` on the same origin. **No OAuth
token of any kind reaches the browser** — no access token, no ID token, no
refresh token, no DPoP key. The console is not registered as a client, does not
appear in `clients`, and is not reachable through the authorization endpoint.

Because the session cookie now authorises state-changing requests that are not
form posts, `/admin/api` gets a **session-bound CSRF defence**, built by
`ast-f7m.3`, that this ADR requires to be layered: a synchroniser token derived
from the session and compared in constant time on every non-`GET`, *and* an
`Origin` / `Sec-Fetch-Site` check. `SameSite=Lax` is a third layer and
deliberately not the first — it is `Lax` rather than `Strict` for the reason
`session.rs` documents (a top-level navigation back from a relying party is how
a user arrives), so it does not protect a top-level `GET`, and every
`/admin/api` route that changes state must therefore refuse `GET`.

That refusal is **structural, not editorial**. `ast-f7m.3` builds it into the
router — a state-changing route cannot be mounted on `GET` — and a test fails
if one ever is. A rule that lives only in this document is a rule a reviewer
has to remember at the moment they are least likely to; `ast-t9k` records the
same lesson about the logout ordering, where a guarantee described as
type-enforced turned out to rest on one caller staying private.

The alternatives considered:

- **(b) The console as an OIDC public client with DPoP.** Rejected on
  conformance, not on preference. FAPI 2.0 SP §5.3.2.1 item 3 — "shall only
  support confidential clients as defined in [RFC6749]" — with RFC 6749 §2.1,
  which makes a user-agent-based application a public client by definition,
  together mean this server cannot register the console without ceasing to be
  the thing ADR-0002 says it is. DPoP does not rescue it: sender-constraining
  bounds what a *stolen* token buys, while §5.3.2.1 item 6 still requires mTLS
  or `private_key_jwt` for client authentication, neither of which a downloaded
  bundle can perform. It is also worse on the merits with the profile set aside
  — RFC 9700 §2.1.2 and §4.3.2 exist to keep tokens out of exactly this place,
  and a token in a browser is a credential that outlives the tab that minted it,
  whereas a session cookie is `HttpOnly`, revocable, and already bounded by two
  clocks.
- **(c) A separate BFF service holding a confidential client.** Conformant — a
  BFF is RFC 6749 §2.1's "web application", a confidential client, and it is the
  standard answer for an SPA that must speak OAuth. Rejected on cost, and the
  cost is specific to this product rather than generic. It is a second process
  to build, configure, monitor, back up and upgrade in lockstep, in a product
  whose packaging (`ast-p2l.7`) is one distroless image with no shell and a
  compose file with one service, and whose ADR-0001 refuses even a Redis on the
  grounds that "no operator of a self-hosted IdP wants to run seven deployments
  to get a login page". It adds a trust boundary — a service holding a client
  credential able to mint admin-scoped tokens — and with it a new secret to
  distribute and rotate, in order to bridge a gap that does not exist: the
  console and the IdP are the same origin, the same release and the same
  operator. A BFF earns its cost when the UI and the authorization server are
  owned by different teams or deployed separately. Here they are the same
  binary, and the token round trip would be this server issuing itself a
  credential to talk to itself.
- **(d) A server-rendered admin UI with no client-side application.** Not in the
  bead; worth a line because it is the one option needing no new CSRF code, the
  form machinery being already built. Rejected because the console's work —
  audit search, client editing, key rotation — is interactive in a way form
  posts serve badly, and because the CSRF adjustment (a) needs is small and
  bounded.

## Consequences

**The risk moves; it does not vanish.** Two things get worse than they would be
under a token-bearing SPA, and both are the price of this decision rather than
oversights:

- A same-origin session cookie is attached by the browser to cross-site requests
  that a bearer `Authorization` header would never be attached to, so CSRF
  (RFC 9700 §4.7) becomes a live threat against the admin API where it was not
  one for the token endpoints.
- An XSS anywhere on the IdP's origin becomes an *administrator session*
  compromise rather than a defacement: the cookie is `HttpOnly`, so injected
  script cannot read it, but it can issue same-origin `fetch` calls that carry
  it, and it can read the CSRF token the page must contain. The strict CSP is
  the primary control, and this is why it has no `'unsafe-inline'` escape hatch.

Both are recorded as rows in [the threat model](../threat-model.md) §3 under
"Admin console", which is this bead's other acceptance criterion.

**`ast-f7m.3`** builds: a server-rendered entry document carrying the
per-response nonce on every script and style tag it emits; the asset serving
that does not exist yet; and the session-bound CSRF token plus the `Origin` /
`Sec-Fetch-Site` check on `/admin/api`. It widens no CSP directive. If it finds
that it must, that is a finding worth a new ADR rather than a patch.

**`ast-1cj`** inherits a constraint and one open question. The constraint: an
administrator authenticates through the *same* login flow as everyone else,
because that flow is what produces a `Session`, and a `Session` carries a
`tenant` and a `user` UUID. So an admin is **a user holding an administrative
role**, not a separate credential store, a separate cookie or a separate login
page — a second authentication path would be a second thing to get wrong, and
would discard the `acr` / `amr` on which "administrative actions require a
phishing-resistant authenticator" can later be built. What this ADR does *not*
settle, and what `ast-1cj` must settle before it can seed anything: sessions are
per tenant, so a tenant-scoped administrator has a natural home and a
*deployment-wide* one does not. Whether the first admin is a user in a
designated tenant or a new kind of principal is a modelling decision that (a)
does not imply, and it needs its own bead.

**The way in was left open here, and `ast-wr4` closes it.** This ADR says what
the console is not; it does not say how a session comes to exist for it, and
the constraint above — that an administrator authenticates through the same
flow as everyone else — is what made that a real question, because that flow is
driven by an authorization request. The answer is a **first-party continuation
of the interaction**: `GET /t/{tenant}/admin/` without a usable session opens
an interaction whose continuation is `Continuation::FirstParty(AdminConsole)`
rather than a client's `redirect_uri`, and hands the browser to the ordinary
`/interaction/{id}` pages. The session is still made by
`interaction::sign_in` and by nothing else, so the throttle, the rotation, the
single failure message and the recorded `acr`/`amr` are the same code rather
than the same intention. The destination is a **variant of a closed enum, never
a parameter** — there is no `next=`, so there is no URL to validate and no
allow-list to keep in step with the router. Under ADR-0010 the console lives
under its tenant's URL space and there is none at the root: a session belongs to
a tenant, so a tenant administrator signs in under their own.

**Audit.** `AuditActor::Admin(String)` already exists in
`crates/domain/src/audit/mod.rs`, described there as "an administrator using the
admin API or console". Under this decision the string it carries is a user
identifier, not a client identifier, and that is what the admin API should
write.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| FAPI 2.0 SP §5.3.2.1 item 3 | Authorization servers "shall only support confidential clients as defined in [RFC6749]" | The console is not a client at all, so no public client is registered; option (b), which would have required one, is refused |
| RFC 6749 §2.1 | A "user-agent-based application is a public client in which the client code is downloaded from a web server and executes within a user-agent"; its protocol data and credentials "are easily accessible (and often visible) to the resource owner" | This is the derivation that makes item 3 bite on a browser bundle, and the reason no browser-held credential is issued |
| RFC 9700 §2.1.2 | Clients "SHOULD NOT use the implicit grant … or other response types issuing access tokens in the authorization response", partly because such tokens cannot be sender-constrained | No token is issued to the browser under any response type; the console holds an `HttpOnly` session cookie instead |
| RFC 9700 §4.7 | CSRF: an attacker injects a request that the victim's browser authenticates with ambient credentials | A session-bound synchroniser token on every non-`GET` `/admin/api` request, an `Origin` / `Sec-Fetch-Site` check, and `SameSite=Lax` as a third layer; state-changing routes refuse `GET` |
| RFC 9700 §4.16 | "Authorization servers MUST prevent clickjacking attacks", and "SHOULD also use Content Security Policy (CSP) level 2 … or greater", which "must be used on the authorization endpoint and, if applicable, other endpoints used to authenticate the user and authorize the client" | Cited for scope as much as for content: the console is *not* one of the endpoints §4.16 names, so nothing here is required by it. It is held to the same nonce-based `default-src 'none'` policy with `frame-ancestors 'none'` anyway, because a framed admin console is the same attack against a more privileged user, and because keeping one policy is cheaper than justifying a second |
