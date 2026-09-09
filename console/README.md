# The admin console

A React + TypeScript application, built by Vite and **embedded in the server
binary**. It is not a separate deployment, not an OAuth client and not reachable
from any origin but the IdP's own: [ADR-0009](../docs/adr/0009-the-admin-console-is-a-first-party-same-origin-app.md)
records why.

```sh
./scripts/build-console.sh   # or: make console
cargo build --bin asterius   # embeds console/dist
```

A checkout without Node still compiles. `crates/admin-api/build.rs` then embeds
an empty bundle and `/admin/` answers 503 naming the command that was not run,
rather than failing a build that has nothing to do with JavaScript.

## What the policy decides

Everything unusual here follows from one header, which the console does not get
to change (`crates/web/src/csp.rs`):

```
default-src 'none'; script-src 'nonce-…' 'strict-dynamic'; style-src 'nonce-…';
img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self';
frame-ancestors 'none'; base-uri 'none'; object-src 'none'
```

- **There is no `index.html`.** The nonce changes per response, so a bundler's
  static page could never carry the right one. The server renders the entry
  document from `crates/admin-api/templates/console.html` and puts the
  response's nonce on the `<script>` and on every `<link rel="stylesheet">`.
  Vite's input is therefore the module, not a page.
- **Nothing is inline.** No inline script, no inline style, no event handler
  attribute, no `eval`. `modulePreload.polyfill` is off because that polyfill
  is an inline script.
- **Nothing is off-origin.** No CDN, no web font, no analytics. System fonts
  only, because `font-src 'self'` admits nothing else and because an admin
  console should not tell a third party who is administering what.
- **There is no dev server.** Vite's hot-reload transport is a websocket to
  another origin, which `connect-src 'self'` refuses. Develop against a built
  bundle served by the binary; `./scripts/build-console.sh` takes a second.

## Why the URLs are relative and the routes are fragments

The document is served at `/admin/`, and a tenant may be reached at
`/t/{id}/admin/`. The tenancy middleware strips that prefix before routing, so
no handler can see it and a root-relative URL would drop it — the same failure
`e2e/README.md` records for the interaction pages. So every asset and API URL
is relative, and the console routes on the fragment (`#/tenants`) rather than
on the path, which keeps the document URL — and therefore the base every
relative URL resolves against — exactly where the server put it.

## How a session starts (`ast-wr4`)

There is one console per tenant, at `/t/{id}/admin/`, and none at the root. A
session belongs to a tenant (ADR-0010) and the deployment administrator is a
user of the reserved tenant (`ast-1cj`), so an administrator signs in under
their own tenant and a session opened in one is not a session in another.

`GET /t/{id}/admin/` without a usable session does not serve this bundle. The
server opens an **interaction** — the same row the login and consent pages are
driven by — whose continuation is a first-party destination rather than a
client's `redirect_uri`, and redirects to `/interaction/{id}`. The visitor then
meets the ordinary login page, and `interaction::sign_in` produces the session:
the same rotation, the same throttle, the same one sentence for "no such user"
and "wrong password", the same recorded `acr`/`amr`. ADR-0009 requires exactly
that — an administrator authenticates through the same flow as everyone else,
because a second authentication path is a second thing to get wrong.

**There is no `next` parameter, and there must never be one.** The destination
is a variant of a closed enum (`FirstPartyDestination`), which the server maps
to a compiled-in relative path. Nothing a browser sends can move it, so the
open redirect is impossible rather than guarded. If a future screen needs to be
returned to, it is a new variant, not a new parameter.

The `SignedOut` screen therefore reloads this document instead of naming a
sign-in URL: reloading is the entry, and it keeps the tenant prefix without
this bundle ever knowing what it was. It is reached when a session *ends*
mid-visit; a visitor who never had one does not get this far.

## The API, and CSRF

`src/api.ts` is the only place that calls the server. Reads are plain `GET`s;
anything that changes state sends `X-CSRF-Token` with the token
`GET /admin/api/v1/session` handed back, because the API compares it in
constant time and also checks `Origin` / `Sec-Fetch-Site`
(`crates/admin-api/src/csrf.rs`). A state-changing route cannot be mounted on
`GET` at all — that is a property of the router's types, not a convention.

## Navigation and roles

`src/navigation.ts` hides what the signed-in roles cannot use. That is a
courtesy, not a control: every route re-checks its own authority server-side,
so a console that showed every link would leak nothing.

## Tests

The browser sweep covers this application: `e2e/tests/console.spec.ts` asserts
that the shell starts with no CSP violation, makes no off-origin request,
handles a 401 by asking for a sign-in, serves hashed assets as `immutable` and
passes axe. Run it with `./scripts/browser-tests.sh --project=js`.
