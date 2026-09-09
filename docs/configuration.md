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

## `[[tenant]]` — one table per tenant

A tenant is an issuer. This array is the source of truth for which tenants exist at boot; the admin API adds more at runtime. The upsert is idempotent, so a restart re-asserts the declared shape.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `tenant.id` | string | **required** | Becomes a path segment in the issuer and in every request URL, so it is validated rather than trusted. |
| `tenant.issuer` | https URL, no query, no fragment | **required** | Normalised once at startup — scheme and host lower-cased, a default `:443` dropped, a trailing slash removed — and the canonical form is what appears in every `iss` claim (RFC 8414 §2, OIDC Discovery §3). |
| `tenant.default_resource` | https URL, no fragment | the tenant's `issuer` | The `aud` an access token carries when the authorization request named no `resource` of its own (RFC 8707 §2, RFC 9068 §3). The default means "a token for this server's own protected resources"; a deployment fronting a separate API names that API here. |

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
