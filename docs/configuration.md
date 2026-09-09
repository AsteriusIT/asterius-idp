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

## `[features]` — optional capabilities

Everything is off unless switched on here, and what is switched on is exactly what appears in the discovery metadata and on `/readyz`. There is no flag that weakens the FAPI 2.0 baseline (ADR-0002) and no `rs256` (ADR-0003).

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

## `[registration]` — dynamic client registration

`POST /register` (RFC 7591 §3). Omit the table entirely and the endpoint registers nobody. That is a deliberate departure from RFC 7591 §3's SHOULD: the SHOULD exists so clients can interoperate with servers nobody has agreed with in advance, and a FAPI deployment's clients are counterparties rather than strangers. The cost of the other default is an internet-writable row in `clients`.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `registration.mode` | `"closed"`, `"initial_access_token"` or `"open"` | **required** when `[registration]` is present | Never inferred from whether tokens are present: deleting the last token would otherwise turn a gated endpoint into an open one. |
| `registration.initial_access_tokens` | array of strings (**secret**) | **required** under `initial_access_token`, rejected otherwise | Hashed at startup, so the running process holds only digests. Each must be at least 22 characters, which is the 128 bits FAPI 2.0 SP §5.4.1 requires of a credential no end user handles. |

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
| `tenant.refresh.bind_to_dpop_key` | boolean | `true` | Whether the refresh token may only be presented with the DPoP key it was issued to (RFC 9449 §5). Required for public clients; on by default for confidential ones too, which is the stricter reading — a refresh token copied out of a client's store is then useless without that client's DPoP private key as well as its credentials. Turning it off means a confidential client may refresh with any key it proves, and the new access token is bound to that key. |
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

## Secret sources

Five values in this file are credentials, and each has a supported production
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
