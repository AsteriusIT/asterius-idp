# Configuration reference

<!-- Generated file. Do not edit by hand: run `cargo run --quiet --bin asterius -- --config-reference > docs/configuration.md`. -->

Asterius reads one TOML file, named by `--config` or `ASTERIUS_CONFIG` and
defaulting to `asterius.toml` in the working directory.

**An unknown key is a startup error, not a warning.** A typo in a security flag
must never be silently ignored, so every table rejects keys it does not know and
the error names the full key path. Validation problems are accumulated and
reported together: fixing a configuration should take one round trip, not one
restart per mistake.

**Every key can be set from the environment** as `ASTERIUS__<TABLE>__<KEY>`,
upper-cased, with `__` between path segments:

```sh
ASTERIUS__DATABASE__URL=postgres://asterius@db:5432/asterius
ASTERIUS__SERVER__BIND=0.0.0.0:9443
ASTERIUS__FEATURES__SSF=true
```

The value is parsed as a TOML scalar, so `true` and `16` mean what they say and
anything that is not valid TOML on its own is taken as a string — which is what
makes an unquoted connection URL work.

## Top level

Keys that belong to the process rather than to any one part of it.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `log_format` | `"text"` or `"json"` | `"text"` | `json` for a log pipeline, `text` for a terminal. Either way every field passes through the redaction formatter first, so a credential cannot reach an appender (RFC 9700 §4.2-4.3). |

## `[server]` — listener and transport

Where the process listens and how TLS reaches it.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `server.bind` | socket address | `"0.0.0.0:9443"` | Deliberately not `:8443`, which `tailscale serve` binds on a node's Tailscale addresses. |
| `server.mode` | `"terminate_tls"` or `"behind_proxy"` | `"behind_proxy"` | `terminate_tls` requires `[server.tls]` and rejects `[server.proxy]`; `behind_proxy` is the mirror image. A deployment that configures certificates while running behind a proxy usually believes it is doing TLS and is not. |
| `server.request_body_limit_bytes` | integer | `65536` | FAPI 2.0 request bodies are small — a PAR request, a token request, a registration document — so anything larger is a mistake or an attempt. Over the limit: 413. |
| `server.request_timeout_seconds` | integer | `10` | Long enough for a slow client on a bad link, short enough that holding a connection open is not a denial-of-service primitive. |

## `[server.tls]` — this process's certificate

Required when `server.mode = "terminate_tls"`, and rejected otherwise. TLS 1.2 and 1.3 only, with the BCP 195 cipher suites FAPI 2.0 SP §5.2.1-5.2.2 permits. There is no knob to widen either set.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `server.tls.certificate` | path | **required** in `terminate_tls` mode | PEM certificate chain, leaf first. |
| `server.tls.private_key` | path | **required** in `terminate_tls` mode | PEM private key. Mounted read-only and never baked into an image; see "Secret sources" below. |

## `[server.proxy]` — who may speak for a client

Only meaningful when `server.mode = "behind_proxy"`, and rejected otherwise.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `server.proxy.trusted_cidrs` | array of CIDR blocks | `["127.0.0.0/8", "::1/128"]` | `X-Forwarded-For` and `Forwarded` are assertions any client can make, so they are believed only when the immediate peer is listed here. The resolved address feeds rate limiting, login abuse protection and the audit trail: a spoofable address means a spoofable rate-limit bucket and an audit record naming the wrong person. |

## `[database]` — PostgreSQL

One PostgreSQL instance holds everything. There is no second store to keep consistent.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `database.url` | connection URL (**secret**) | **required** | Contains a password, so it is held redacted and prints as `[REDACTED]` wherever the configuration is logged. Prefer supplying it through `ASTERIUS__DATABASE__URL` from a secret store over writing it in the file. |
| `database.max_connections` | integer | `16` | Per process. Multiply by the replica count before comparing it with the server's `max_connections`. |

## `[keys]` — the key-encryption key

**Required, with no default.** Signing keys are encrypted at rest under this key, and one generated at each boot could not open yesterday's rows — the failure would look like corruption rather than like configuration. Set exactly one of the two keys below; setting both is an error, because the server would otherwise choose between them silently. The value is 32 bytes, base64: `head -c 32 /dev/urandom | base64`.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `keys.kek_file` | path (**points at a secret**) | **required**, unless `kek_env` is set | The production shape: the orchestrator mounts the file read-only and it is never in the image. |
| `keys.kek_env` | variable name (**names a secret**) | **required**, unless `kek_file` is set | Convenient in a container and readable through `/proc/self/environ`, so the file is preferred. |
| `keys.kek_previous_file` | path (**points at a secret**) | optional | The key a rotation is moving *away* from, during the rotation only. A row that does not open under the current key is retried under this one, which is what lets `asterius rewrap-kek` run without a window in which a replica cannot open a row that has already moved. Nothing is ever written under it. **Remove it once the re-wrap is complete**: while it is set, a retired key stays readable by this process. See `docs/runbooks/backup-restore.md` §4. |
| `keys.kek_previous_env` | variable name (**names a secret**) | optional | The same, from the environment. Set at most one of `kek_previous_file` and `kek_previous_env`. |

## `[features]` — optional capabilities

Everything is off unless switched on here, and what is switched on is exactly what appears in the discovery metadata and on `/readyz`. There is no flag that weakens the FAPI 2.0 baseline (ADR-0002) and no `rs256` (ADR-0003). One capability is missing from this table on purpose: `dynamic_client_registration` follows `[registration] mode` and has no key here, so that "who may register" is written once — see below.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `features.mtls` | boolean | `false` | mTLS client authentication and certificate-bound tokens (RFC 8705). |
| `features.grant_management` | boolean | `false` | Grant Management for OAuth 2.0 (Implementer's Draft). |
| `features.ciba` | boolean | `false` | CIBA Core 1.0 backchannel authentication, poll and ping. |
| `features.device_flow` | boolean | `false` | Device Authorization Grant (RFC 8628). |
| `features.token_exchange` | boolean | `false` | Token Exchange (RFC 8693) with delegation chains. |
| `features.ssf` | boolean | `false` | Shared Signals Framework transmitter and CAEP/RISC events. |
| `features.authzen` | boolean | `false` | AuthZEN Authorization API 1.0 policy decision point. |
| `features.dpop_nonce` | boolean | `false` | Server-issued DPoP nonces (RFC 9449 §8). |
| `features.request_object` | boolean | `false` | Signed request objects inside a pushed request (JAR, RFC 9101). |

## `[registration]` — dynamic client registration

`POST /register` (RFC 7591 §3). Omit the table entirely and the endpoint registers nobody. That is a deliberate departure from RFC 7591 §3's SHOULD: the SHOULD exists so clients can interoperate with servers nobody has agreed with in advance, and a FAPI deployment's clients are counterparties rather than strangers. The cost of the other default is an internet-writable row in `clients`.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `registration.mode` | `"closed"`, `"initial_access_token"` or `"open"` | **required** when `[registration]` is present | Never inferred from whether tokens are present: deleting the last token would otherwise turn a gated endpoint into an open one. |
| `registration.initial_access_tokens` | array of strings (**secret**) | **required** under `initial_access_token`, rejected otherwise | Hashed at startup, so the running process holds only digests. Each must be at least 22 characters, which is the 128 bits FAPI 2.0 SP §5.4.1 requires of a credential no end user handles. |

`registration.mode` also decides whether the endpoint exists at all. It drives the `dynamic_client_registration` capability, which gates both the `registration_endpoint` member of the discovery document and the route itself (`ast-m9c.6`): a closed deployment advertises no such URL and answers 404 at `/register`, rather than advertising one that refuses everybody. The flag is not writable under `[features]` — writing it there is a configuration error naming the key, because "who may register" belongs in one place.

### Per-tenant registration policy

The deployment's posture is a ceiling, not the whole answer. Each tenant carries a `registration_policy` document in its settings (`PUT /tenants/{id}/settings` in the admin API), and it may only narrow what the deployment allows:

```json
{
  "profile": "agent",
  "mode": "initial_access_token",
  "token_endpoint_auth_methods": ["private_key_jwt"],
  "grant_types": ["client_credentials"],
  "scopes": ["agent:read"],
  "resources": ["https://api.example.com"],
  "redirect_uri_hosts": ["app.example.com"],
  "jwks": "uri",
  "software_statement": {
    "required": true,
    "issuers": [
      { "issuer": "https://vouch.example.com", "jwks_uri": "https://vouch.example.com/jwks" }
    ]
  },
  "max_clients_per_initial_access_token": 25,
  "unused_client_expiry_seconds": 2592000
}
```

Every member is optional and every list is *closed*: an absent list means "this tenant has no opinion", and an empty one means "none". `mode: "closed"` removes the endpoint from that tenant's discovery document and unmounts its route; `mode: "open"` cannot open an endpoint the deployment gated. `profile: "agent"` selects the preset for onboarding agents — `client_credentials` only, no callbacks, a software statement required, a quota and an expiry — which the other members then override; a policy that requires a statement and names no trusted issuer is refused, because nothing could ever register under it.

A software statement issuer is a **root of trust**: RFC 7591 §2.3 makes a statement's claims override the request's, so whoever holds that signing key can create clients in this tenant with metadata of their choosing. Both URLs must be `https`, the `iss` is compared byte-exactly, and the keys are fetched through the one outbound path. See `docs/threat-model.md`.

Both quota members are enforced since `ast-cu3`:

* **`max_clients_per_initial_access_token`** is stamped onto every token the admin API issues for this tenant (`POST /admin/api/v1/initial-access-tokens`), and charged atomically at `POST /register`. It applies to the tenant's own tokens, which are rows; the initial access tokens an operator configures in this file belong to the *deployment* and still have no quota. A tenant that sets `mode: "initial_access_token"` therefore stops accepting the deployment's tokens and starts accepting only its own — which is the point, and which means such a tenant must issue at least one token before anybody can register.
* **`unused_client_expiry_seconds`** is honoured by the retention sweep: a client that has not authenticated at the token endpoint or PAR for that long is deleted, dated by `clients.last_used_at` and falling back to `created_at` for a client that has never authenticated. A tenant that sets nothing here keeps every client for ever, which stays the default. `last_used_at` is written at most once per client per hour, so the value is accurate to the hour against a window measured in days.

## `[login]` — abuse protection at sign-in

Failed sign-ins are counted per client address and per typed identifier, in fixed windows held in the database so that every replica sees the same counter (NIST SP 800-63B §5.2.2). Both limits apply and they stop different attacks: the per-account one bounds the guessing of one password, the per-address one bounds a sweep across many accounts. The identifier is hashed before it is counted and the bucket exists whether the account does or not, so a locked-out identifier and one that was never registered are the same observable.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `login.failure_window_seconds` | integer seconds | 900 | How long failures are remembered. At least 30: a window shorter than that resets before an attacker's attempts add up, which is a limit in name only. |
| `login.max_failures_per_account` | integer | 10 | Failures tolerated per window against one typed identifier before sign-ins are refused with a retry hint. Raising it buys an attacker guesses; lowering it makes a targeted lockout of one user cheaper to cause. |
| `login.max_failures_per_address` | integer | 100 | Failures tolerated per window from one client address. Higher than the per-account limit because one address is legitimately many people — an office, a carrier's NAT — and because behind a proxy it is only as trustworthy as `[server.proxy] trusted_cidrs` makes it. |

## `[limits]` — abuse protection at the protocol endpoints

Requests — not failures — are counted per endpoint, in the same fixed windows and the same database table the sign-in limiter uses, so every replica sees one counter. A **successful** request from a client that authenticated is charged to that client; everything else is charged to the address it came from. That is what keeps one busy relying party from spending the budget of everyone behind the same NAT, and what stops a caller from exhausting a competitor's budget by naming their `client_id` in a request that fails. Exceeding a limit is answered with 429 and `Retry-After`, counted in `asterius_endpoint_throttled_total`, and written to the audit trail once per window rather than once per request. `/authorize` and the interaction pages are not here: the sign-in behind them is bounded by `[login]`, and a second counter over the same requests would halve a number set once.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `limits.window_seconds` | integer seconds | 60 | How long requests are counted for, for every endpoint below. At least 10. Shorter than `[login]`'s window on purpose: these limits bound load rather than guessing, and a caller refused for a quarter of an hour over a five-second burst is an outage rather than a defence. |
| `limits.registration_per_address` | integer | 20 | Requests per window to `POST /register` (RFC 7591) from one address. The tightest limit here: with `[registration] mode = "open"` this is the one endpoint that both needs no credential and creates a row per accepted request. There is no per-client limit, because registration is where a client comes from. |
| `limits.client_configuration_per_address` | integer | 60 | Requests per window to the RFC 7592 configuration endpoint from one address. What it bounds is a caller trying registration access tokens against a client id it guessed; the bucket is the address and never the id in the path, which anybody can write. |
| `limits.par_per_address` | integer | 60 | Requests per window to `POST /par` (RFC 9126) from one address, for requests that do not end in a successful push. Each accepted request stores a row, so an abusive caller here fills a table. |
| `limits.par_per_client` | integer | 600 | Successful pushes per window by one authenticated client. An order of magnitude above the address limit, because one relying party is legitimately many users starting authorization at once. |
| `limits.token_per_address` | integer | 120 | Requests per window to `POST /token` from one address, for requests that do not end in a token. Every attempt costs a signature verification, and replaying an authorization code revokes the grant it belongs to, so abuse here has a side effect as well as a cost. |
| `limits.token_per_client` | integer | 1200 | Successful token responses per window for one authenticated client. The busiest endpoint a working deployment has — every authorization and every refresh passes through it — so this is the number to raise first when a large client is refused. |
| `limits.userinfo_per_address` | integer | 600 | Requests per window to UserInfo from one address. The most generous of the five: its callers are resource servers rather than browsers, so one address is legitimately a fleet making a request per API call. There is no per-client limit, because the caller presents an access token and reading a client out of it before verifying it would be trusting a string the caller wrote. |

## `[[tenant]]` — one table per tenant

A tenant is an issuer. This array is the source of truth for which tenants exist at boot; the admin API adds more at runtime. The upsert is idempotent, so a restart re-asserts the declared shape.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `tenant.id` | string | **required** | Becomes a path segment in the issuer and in every request URL, so it is validated rather than trusted. |
| `tenant.issuer` | https URL, no query, no fragment | **required** | Normalised once at startup — scheme and host lower-cased, a default `:443` dropped, a trailing slash removed — and the canonical form is what appears in every `iss` claim (RFC 8414 §2, OIDC Discovery §3). |
| `tenant.default_resource` | https URL, no fragment | the tenant's `issuer` | The `aud` an access token carries when the authorization request named no `resource` of its own (RFC 8707 §2, RFC 9068 §3). The default means "a token for this server's own protected resources"; a deployment fronting a separate API names that API here. |

## `[tenant.refresh]` — refresh tokens

Omit the table and this tenant gets FAPI 2.0 SP's position: no rotation, a refresh token that only works with the DPoP key it was issued to, and the lifetimes below. The table is per tenant because how long an authorization may be acted on without the user present is a question two tenants of one deployment routinely answer differently.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `tenant.refresh.absolute_lifetime_seconds` | positive integer | `2592000` (30 days) | How long a refresh token may live at all. It never moves: using the token does not push it out, which is what makes it the one deadline an attacker holding the token cannot extend. Past it the client sends the user through authorization again. |
| `tenant.refresh.idle_lifetime_seconds` | positive integer, or `0` to disable | `1209600` (14 days) | How long the token may sit unused. Every successful refresh pushes it out, so it answers "is this integration still in use" rather than "is this authorization still fresh". Capped at `absolute_lifetime_seconds`, because a longer value is not a stricter setting but one with no effect. `0` switches the idle clock off; the absolute deadline still runs. |
| `tenant.refresh.bind_to_dpop_key` | boolean | `false` | Whether the refresh token may only be presented with the DPoP key it was issued to. Off by default because that is RFC 9449 §5: a refresh token issued to a *confidential* client is not bound to the proof key, being sender-constrained by client authentication already, and this server registers no public clients. A client may therefore roll its DPoP key and keep its authorizations, and the new access token is bound to the key it proves. Turning it on is a local hardening — a refresh token copied out of a client's store is then useless without that client's DPoP private key as well — and it breaks any client that rolls that key. |
| `tenant.refresh.rotation` | `"none"` or `"migration"` | `"none"` | FAPI 2.0 SP §5.3.2.1 item 9: an authorization server "shall not use refresh token rotation except in extraordinary circumstances". `"none"` returns the same token unchanged. `"migration"` is Note 1's exception and exists for one purpose — moving off a server that rotated, where clients in the field discard a refresh token they did not just receive. It is not a hardening measure, it is a compatibility shim, and it is meant to be switched off again. |
| `tenant.refresh.rotation_grace_seconds` | positive integer, at most 3600 | **required** with `rotation = "migration"`, and refused otherwise | How long the superseded token stays acceptable, so a client that crashed between receiving the response and storing it can retry. It is a window in which two refresh tokens are live for one grant, which is the state rotation exists to eliminate — hence the hour ceiling and hence the refusal to accept the key at all under `rotation = "none"`, where it would describe something the server does not do. |

## `[admin]` — the deployment admin

Omit the table and nothing is seeded. A deployment admin is a user of a *reserved tenant* holding a deployment-scoped role (ADR-0010): the tenant is created if it is absent, marked reserved, and cannot be deleted afterwards — the cascade from `tenants` is what would otherwise remove every admin in one statement. The seed runs on every boot and is idempotent; it finishes by verifying the configured password through the ordinary login verifier, and the server refuses to start if the account it just asserted could not sign in.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `admin.tenant` | string | `"admin"` | The reserved tenant's id. It must not also be declared as a `[[tenant]]`: the seed is what creates and marks it. Discoverable by anyone who can list tenants, deliberately — an admin surface that hides where its authority lives is harder to audit, not safer. |
| `admin.issuer` | https URL, no query, no fragment | **required** when `[admin]` is present | The reserved tenant is a real tenant and needs an issuer like any other, with the same normalisation and the same host check. Its login surface therefore deserves the same scrutiny as any tenant's. |
| `admin.username` | string | `"admin"` | The login identifier, unique within the reserved tenant. |
| `admin.password_file` | path (**points at a secret**) | **required**, unless `password_env` is set | The production shape: a file the orchestrator mounts read-only. Leading and trailing whitespace is stripped, so a trailing newline is not part of the password. |
| `admin.password_env` | variable name (**names a secret**) | **required**, unless `password_file` is set | The named variable, injected by the orchestrator. Readable through `/proc/self/environ`, so the file is preferred. There is no key that takes the password itself: a credential written in the file is a credential in version control and in every copy of the image. |

## `[dpop]` — the shared nonce secret

Only read when the `dpop_nonce` feature is on. **Per process if absent**: each replica then derives nonces from a key it generated at boot, so a nonce issued by one is refused by another and by the same one after a restart. That is safe — RFC 9449 §8's handshake tells the client to retry with the nonce it was just handed — but it turns `use_dpop_nonce` from a once-per-client event into a per-request one, which is the round trip the one-window lookback exists to avoid. Set one secret across every replica and the retry goes back to being rare. Set exactly one of the two keys below; the value is 32 bytes, base64: `head -c 32 /dev/urandom | base64`. It is held redacted in the process and prints as `[REDACTED]` wherever the configuration is logged.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `dpop.nonce_secret_file` | path (**points at a secret**) | per-process secret | The production shape, spelt like `keys.kek_file` and read by the same parser: the orchestrator mounts the file read-only and it is never in the image. A file that cannot be read, or that does not hold 32 base64 bytes, stops the server — an unreadable secret and an absent one would otherwise look the same, and one of them is a supported deployment. |
| `dpop.nonce_secret_env` | variable name (**names a secret**) | per-process secret | The named variable, injected by the orchestrator. Readable through `/proc/self/environ`, so the file is preferred. There is no key that takes the secret itself, for the reason `[admin]` has none. |

## `[mtls]` — client certificates (RFC 8705 §2)

Read only when `[features] mtls` is on. This table says *how* a certificate reaches the server and whose CAs vouch for it; whether any of it happens is the flag. There is deliberately no `mode` key: whether TLS is terminated here or by a proxy is `[server] mode`, and which peers may speak for a client is `[server.proxy] trusted_cidrs` — the same set that decides whether `X-Forwarded-For` is believed. A second spelling of either would be a second answer to "who is this server behind", and behind a proxy the proxy chooses which certificate this server sees, so it can authenticate any client it likes. That is the trust root this table adds; the other is each tenant's CAs, which can mint a certificate for any of that tenant's clients that registered a matching name.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `mtls.certificate_header` | string | x-client-cert | The header a reverse proxy forwards the client certificate in — nginx's `ssl_client_escaped_cert`, HAProxy's `ssl_c_der,base64`. Percent-encoded PEM, PEM whose newlines the proxy escaped, and bare base64 DER are all accepted, because they are one certificate in three transport encodings. **The header is read only from a peer inside `[server.proxy] trusted_cidrs`**; from anywhere else it is dropped without being parsed, which is what stops a caller from choosing its own identity. A proxy that forwards this header must also strip an inbound one. |
| `mtls.trust_anchors` | table of tenant id to PEM path | none | The CAs each tenant's `tls_client_auth` clients are validated against (§2.1), one PEM file per tenant. Per tenant and never global: one process serves several, and a CA one tenant trusts must not be able to mint clients for another. A tenant with no entry cannot use the PKI method at all — it fails closed rather than falling back to the outbound roots, which are for *server* certificates and would let the public web CAs mint clients. The `self_signed_tls_client_auth` method (§2.2) needs nothing here: it matches the certificate against the client's own JWKS. A file named and unreadable stops the process rather than starting a server that refuses every client of that tenant. |

## Client key fetches — outbound traffic you did not ask for

Not configurable, and here because it is traffic your deployment sends to somebody else. A client registered with a `jwks_uri` has its key set fetched by this server; a fetch that fails is remembered so that a broken — or third-party — URL is not fetched again on every request naming that client. The intervals are built in: keys are served for 10 minutes before they are fetched again, an unknown `kid` provokes at most one refresh per client per 60 seconds, and a failed fetch suppresses the next one for 60 seconds.

Those last 60 seconds are a *shared* decision, not a per-process one. Each failure writes a row to `client_key_fetches` — the tenant, the client, a SHA-256 of the URL, the reason, and the instant before which nobody fetches again — and every replica reads it before opening a socket. Without that table the interval would be divided by the number of replicas you run and reset by every restart, which is a rate nobody chose and which the operator of the URL, not you, would notice first. The reason is bounded and the URL is only ever stored as a digest, because a `jwks_uri` may carry a query parameter the client considers a secret.

Rows are removed when a fetch for that URL succeeds, and swept by the retention pass once their window has passed; nothing here needs an operator's attention unless the table is growing, which means clients are registering `jwks_uri` values that never work.

## Secret sources

Six values in this file are credentials, and each has a supported production
shape. Nothing here belongs in an image layer, in a `docker-compose.yml` or in
version control; the example stack under `deploy/compose/` uses obvious
development values and says so in every file.

| Secret | Key | How to supply it |
| --- | --- | --- |
| Key-encryption key | `keys.kek_file` | A file the orchestrator mounts read-only (Kubernetes `Secret` volume, Docker secret, systemd credential). Preferred: a file is not readable through `/proc/self/environ` and does not appear in a process listing. |
| Key-encryption key | `keys.kek_env` | The named variable, injected by the orchestrator. Convenient, and second-best. |
| Database password | `database.url` | `ASTERIUS__DATABASE__URL` from the same secret store. The value is held redacted in the process and prints as `[REDACTED]` wherever the configuration is logged. |
| TLS private key | `server.tls.private_key` | A read-only mount, rotated by whatever issues the certificate. The process reads it at startup. |
| Initial access tokens | `registration.initial_access_tokens` | Only needed under `mode = "initial_access_token"`. Hashed at startup, so the running process holds nothing replayable. |
| Deployment admin password | `admin.password_file`, `admin.password_env` | A read-only mount, or a variable from the same secret store. Hashed with Argon2id at startup, so the database holds no plaintext; the source is read on every boot, which is what makes rotating it an edit to the secret and a restart. |
| DPoP nonce secret | `dpop.nonce_secret_file`, `dpop.nonce_secret_env` | Only meaningful under `features.dpop_nonce`. The same shapes and the same parser as the key-encryption key, and the same 32 bytes of base64. Absent means per-process nonces, which is a round trip rather than a failure. |

Rotating the key-encryption key is not a restart with a new value: the old key
must still be able to open existing rows while they are re-wrapped. Until the
rotation runbook lands, treat the KEK as unrotatable and keep it backed up —
losing it loses every signing key in the database.

### Generating the values

```sh
# Key-encryption key: 32 bytes, base64.
head -c 32 /dev/urandom | base64 > /etc/asterius/kek
chmod 400 /etc/asterius/kek

# An initial access token: 128 bits of entropy, base64url, unpadded.
head -c 16 /dev/urandom | basenc --base64url | tr -d '='
```
