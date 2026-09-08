# Asterius IdP — v1 backlog (Beads epics & stories)

17 epics, 130 stories. Source of truth for `beads-import.sh`. Each story = one spec section or endpoint, with acceptance tests derived from the normative text, and blocking dependencies.

## How to use

1. In the repo: `bd init --prefix ast` (once), then `./beads-import.sh` (re-runnable; ids cached in `.beads/asterius-backlog-ids.env`).
2. `bd ready` lists unblocked work; `bd dep tree <epic-id>` shows an epic; labels filter by area/spec/flag (`bd list -l area:token`).
3. Priorities: **P0** = critical path; **P1** = v1 core; **P2** = v1 differentiator; **P3** = optional; **P4** = track only.
4. Labels: `area:*` (module), `spec:*` (normative source), `status:final|impl-draft|draft` (spec maturity), `flag:*` (feature flag), `differentiator:*`, `adr` (decision beads), `track` (not implemented in v1).
5. Definition of done (project rule): spec-derived or conformance-suite test passes; fuzz target exists for every new parser/validator; threat-model note updated; no new `unsafe`; generated crypto/parsing code is not done until a human has read the cited spec sections.

## Fixed product decisions this backlog encodes

- FAPI 2.0 Security Profile (Final) is the only mode: PAR-only, `response_type=code`, PKCE S256, private_key_jwt (mTLS optional), DPoP-bound access tokens always, exact redirect URIs, codes ≤ 60 s, `iss` in responses, **no refresh-token rotation** (SP §5.3.2.1 item 9), confidential clients only.
- Signing: EdDSA (Ed25519) default, ES256, PS256; RS256 only behind a non-FAPI flag (decision E01_12 — FAPI 2.0 SP §5.4.1 does not permit RS256).
- Modular monolith, one binary, one PostgreSQL, no Redis (transactional outbox instead).
- Server-rendered login/consent/error pages, no tenant JavaScript, strict nonce CSP, `response_mode=form_post` without JS.
- Differentiators: agents (RFC 8693 delegation chains, RAR, DPoP, device flow, CIBA poll/ping, DCR policy, MCP compatibility for confidential clients, per-agent audit), SSF/CAEP transmitter, AuthZEN PDP, Grant Management (Implementer's Draft, behind flag).
- Out of v1: SAML, LDAP, VCs, Federation, IDA — tracked in E17.

## Spec status used in this backlog

| Spec | Status | Used for |
|---|---|---|
| FAPI 2.0 Security Profile / Attacker Model | Final (2025-02) | baseline everywhere |
| FAPI 2.0 Message Signing | Implementer's Draft (draft-02) | track only (E17_01); JAR in PAR optional (E05_09) |
| OIDC Core / Discovery / Registration (errata) | Final | E04–E09 |
| RP-Initiated Logout, Back-Channel Logout | Final | E10 |
| Session Management, Front-Channel Logout | Final but not planned (decision E10_04) | — |
| Prompt Create, Unmet Authentication Requirements, EAP ACR values | Final | E05_08, E06_07 |
| CIBA Core 1.0 | Final (2021-09) | E11_04–E11_07 |
| Grant Management for OAuth 2.0 | Implementer's Draft 1 (2023-07, draft-03) | E07_02, E07_04, E07_05 behind `grant_management` flag |
| Shared Signals Framework 1.0, CAEP 1.0, RISC 1.0 | Final (2025-09) | E12 |
| CAEP Interoperability Profile | Implementer's Draft | track (E17_10) |
| AuthZEN Authorization API 1.0 | Final (2026-01-12) | E13 |
| JARM | Final (errata 1) | track with Message Signing |
| MCP Authorization (2025-11-25) | MCP spec (references OAuth 2.1 draft, CIMD draft-00) | E11_08, decisions E03_08 |
| IETF: RFC 6749/6750/7009/7519/7521/7523/7591/7592/7636/7662/8414/8628/8693/8705/8707/8725/8935/8936/9068/9101/9126/9207/9396/9449/9493/9700/9728 | RFCs | cited per story (section numbers from memory where noted — verify while implementing) |
| OAuth 2.1, RFC 7523bis, Client ID Metadata Documents, Identity Assertion Authz Grant | IETF working drafts | track (E17_02, E17_03, E17_11) |

## Epic map & suggested order

| Epic | Title | P | Stories | Blocked by (epics) |
|---|---|---|---|---|
| E01 | Foundation & toolchain | P0 | 12 | — |
| E02 | Key management & JOSE | P0 | 6 | E01 |
| E03 | Clients, client authentication & dynamic registration | P0 | 8 | E01, E02 |
| E04 | Discovery & authorization-server metadata | P0 | 3 | E01, E02 |
| E05 | Pushed authorization requests & authorization endpoint | P0 | 9 | E02, E03, E06, E07, E15 |
| E06 | Authentication, sessions & identity model | P0 | 10 | E01, E15 |
| E07 | Consent, grants & Grant Management | P1 | 6 | E01, E03, E05, E06, E08 |
| E08 | Token endpoint, token formats & sender-constraining | P0 | 9 | E01, E02, E03, E05, E07, E09 |
| E09 | Introspection, revocation, UserInfo & claims resolution | P1 | 4 | E03, E06, E08 |
| E10 | Logout & session lifecycle | P1 | 4 | E01, E02, E06, E08, E12, E14 |
| E11 | AI-agent-native authorization | P2 | 10 | E01, E03, E04, E05, E06, E07, E08, E12, E13 |
| E12 | Continuous access: Shared Signals Framework / CAEP transmitter | P2 | 9 | E01, E02, E04, E06, E08 |
| E13 | AuthZEN Policy Decision Point (Authorization API 1.0) | P2 | 6 | E01, E04, E06, E07, E08 |
| E14 | Admin API & admin console | P1 | 9 | E01, E02, E06, E08, E10, E11, E12, E13, E15 |
| E15 | Theming, templates & browser security | P1 | 5 | E01, E05, E06, E11 |
| E16 | Security hardening, conformance & release | P1 | 8 | E01, E05, E08, E09, E11, E12 |
| E17 | Track, don't implement (post-v1 and working drafts) | P4 | 12 | E03, E12 |

Critical path to the first conformant code flow: E01 → E02 → E03 (E03_01, E03_02, E03_07) → E04 → E15_03 → E06 (E06_01, E06_02, E06_06, E06_03/E06_04) → E07 (E07_01, E07_02) → E05 → E08 → E09_04 → E16_01. Differentiators (E11, E12, E13) hang off E08/E07/E06 and can proceed in parallel once the token endpoint is stable.

## E01 — Foundation & toolchain  (P0, epic)

Cargo workspace, modular-monolith crate layout, PostgreSQL schema, HTTP bootstrap, CI, fuzz/property harness, conformance harness, tenancy, audit core, threat-model baseline. Everything else depends on this epic.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E01_01 | Cargo workspace & modular-monolith crate layout (ports & adapters) | chore | P0 | — |
| E01_02 | Configuration, feature flags & issuer identity validation | task | P0 | E01_01 |
| E01_03 | PostgreSQL schema baseline & sqlx migrations | task | P0 | E01_01 |
| E01_04 | HTTP server bootstrap & transport hardening (TLS, HSTS, 303, no CORS on /authorize) | task | P0 | E01_02 |
| E01_05 | Observability: tracing, redaction, metrics, health endpoints | task | P1 | E01_04 |
| E01_06 | CI pipeline (fmt, clippy, tests, sqlx check, cargo-deny/audit, fuzz smoke) | chore | P0 | E01_01 |
| E01_07 | Fuzz & property-test harness with parser-coverage gate | chore | P0 | E01_06 |
| E01_08 | OIDF conformance-suite harness (local + nightly) | chore | P1 | E01_04 |
| E01_09 | Threat model & ADR log baseline (FAPI 2.0 Attacker Model mapping) | task | P0 | E01_01 |
| E01_10 | Multi-tenancy & issuer resolution middleware | task | P0 | E01_03 |
| E01_11 | Audit event core (append-only, actor/agent aware) | task | P0 | E01_03 |
| E01_12 | Decision: signing algorithm set (EdDSA/ES256/PS256; RS256 is non-FAPI) | decision | P0 | E01_09 |

### E01_01 — Cargo workspace & modular-monolith crate layout (ports & adapters)

*chore · P0 · labels: area:foundation*

**Spec:** Project ADR 0001 (modular monolith); FAPI 2.0 SP §5.1.1 (build on complete, correct implementations).

Single binary `asterius` with crates: `domain` (entities, ports), `oidc` (protocol logic, no I/O), `jose` (KeyStore/Signer port + josekit adapter), `store-pg` (sqlx adapters), `web` (askama SSR pages), `admin-api`, `server` (axum wiring). Protocol crates must not depend on sqlx/axum.

**Acceptance tests**

- `cargo build --workspace` succeeds; crate dependency graph is acyclic and `oidc`/`domain` have no sqlx/axum/tokio-net dependency (checked by a script in CI).
- Every crate root has `#![forbid(unsafe_code)]`; `cargo clippy --all-targets -- -D warnings` with pedantic group enabled passes.
- `deny.toml` present; `cargo deny check` (licenses, advisories, bans) passes.
- README documents the crate map and the rule 'protocol code talks to the outside world only through ports'.

**Depends on:** —

### E01_02 — Configuration, feature flags & issuer identity validation

*task · P0 · labels: area:foundation*

**Spec:** RFC 8414 §2 (issuer: https URL, no query/fragment); OIDC Discovery §3 (issuer); FAPI 2.0 SP §5.3.2.1 item 1.

Typed configuration (file + env overrides) and a feature-flag registry (`mtls`, `compat.rs256`, `grant_management`, `ciba`, `device_flow`, `token_exchange`, `ssf`, `authzen`, `dpop_nonce`). Secrets are typed `Secret<T>` and never Debug-printed.

**Acceptance tests**

- Server refuses to start when any tenant issuer is not `https`, contains a query or fragment, or ends with `/` inconsistently (normalised once, stored canonical).
- Unknown config keys fail startup with the key path in the error; missing required keys list every missing key at once.
- `Secret<T>` Debug/Display prints `[REDACTED]` (unit test); zeroized on drop.
- Feature flags are readable from a single `Capabilities` struct that downstream metadata generation (E04_03) consumes.

**Depends on:** E01_01

### E01_03 — PostgreSQL schema baseline & sqlx migrations

*task · P0 · labels: area:foundation, area:storage*

**Spec:** FAPI 2.0 SP §5.4.1 item 4 (≥128-bit credentials, stored hashed); RFC 6749 §10.3 (access/refresh tokens and codes must be kept confidential in storage).

Initial migration set: tenants, clients, client_keys, users, credentials, sessions, auth_requests (PAR + interaction state), authorization_codes, grants, refresh_tokens, access_token_jti (denylist), signing_keys, audit_events, outbox, rate_limits. Every tenant-scoped table carries `tenant_id` and composite indexes. Opaque credentials (codes, refresh tokens, registration tokens, device codes, auth_req_id) are stored as SHA-256 digests only.

**Acceptance tests**

- `sqlx migrate run` on an empty database succeeds and is idempotent on re-run; CI runs migrations on a fresh PostgreSQL 16 service.
- `cargo sqlx prepare --check` passes in offline mode.
- A test asserts that no column that stores a credential is plain text (naming convention `*_hash` enforced by a schema test).
- Repository traits take `TenantId` on every call; a cross-tenant read is impossible by construction (compile-time) and covered by an integration test.

**Depends on:** E01_01

### E01_04 — HTTP server bootstrap & transport hardening (TLS, HSTS, 303, no CORS on /authorize)

*task · P0 · labels: area:foundation, area:transport*

**Spec:** FAPI 2.0 SP §5.2.1 (TLS ≥1.2, BCP195, RFC 9525 cert check), §5.2.2 (server-to-server cipher suites), §5.2.3 (HSTS/TLS stripping, cipher suites, no CORS on authorization endpoint); §5.3.2.2 items 10–11 (never HTTP 307; use 303).

axum + rustls bootstrap with two modes: terminate TLS (rustls, TLS 1.2/1.3, BCP195 suites only) or `behind_proxy` (trust `X-Forwarded-*`/`Forwarded` only from configured CIDRs). Shared middleware: request id, body size limits, timeouts, HSTS on browser-facing routes, redirect helper that only ever emits 303.

**Acceptance tests**

- TLS handshake test: TLS 1.0/1.1 rejected; only BCP195-recommended suites offered on server-to-server endpoints.
- Integration test: `OPTIONS /authorize` and `GET /authorize` with `Origin` header never return `Access-Control-*` headers.
- Grep-style test over the codebase: no `StatusCode::TEMPORARY_REDIRECT` (307) usage; redirect helper unit-tested to emit 303.
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on all HTML/redirect responses.
- Request body limit (default 64 KiB) and header limits enforced with 413/431.

**Depends on:** E01_02

### E01_05 — Observability: tracing, redaction, metrics, health endpoints

*task · P1 · labels: area:foundation, area:ops*

**Spec:** RFC 9700 §4.2/§4.3 (credential leakage via logs/referrers — informational).

tracing with per-request span (request id, tenant, client_id, sub hashed), structured JSON logs, a redaction layer for anything that looks like a token/code/assertion/password, Prometheus metrics, `/healthz` and `/readyz` (DB ping).

**Acceptance tests**

- Redaction test: run a full code flow with logging at TRACE and assert with regexes that no authorization code, access/refresh token, client assertion, DPoP proof, password or `client_notification_token` appears in captured logs.
- Metrics exposed for token issuance by grant type, error codes, latency histograms per endpoint.
- `/readyz` returns 503 while migrations are pending or DB unreachable.

**Depends on:** E01_04

### E01_06 — CI pipeline (fmt, clippy, tests, sqlx check, cargo-deny/audit, fuzz smoke)

*chore · P0 · labels: area:foundation, area:ci*

**Spec:** Project DoD (conformance test, fuzz target, threat-model note, no new unsafe).

GitHub Actions: fmt, clippy -D warnings, unit+integration tests against PostgreSQL service, `cargo sqlx prepare --check`, cargo-deny, cargo-audit, 60 s fuzz smoke per target, nightly conformance job (E01_08).

**Acceptance tests**

- PR pipeline < 15 min; nightly job runs fuzz (10 min/target) and conformance suite and uploads reports as artifacts.
- A `unsafe` grep/cargo-geiger step fails the build if any `unsafe` block appears outside vendored deps.
- Branch protection requires the pipeline to pass.

**Depends on:** E01_01

### E01_07 — Fuzz & property-test harness with parser-coverage gate

*chore · P0 · labels: area:foundation, area:security*

**Spec:** Project DoD: fuzz target for every parser/validator.

cargo-fuzz workspace + proptest conventions. A script maps every module under `parsers/` or `validators/` (or tagged `#[fuzzable]`) to a fuzz target and fails CI when one is missing. First targets: `application/x-www-form-urlencoded` parser, JWT compact-serialisation parser, JSON metadata parser.

**Acceptance tests**

- `cargo fuzz list` shows at least the three initial targets; each runs 60 s in CI without crash.
- Coverage gate script passes and is documented in CONTRIBUTING.md.
- proptest strategies exist for `Scope`, `RedirectUri`, `ClientId`, `Jwt` types and are reused by later stories.

**Depends on:** E01_06

### E01_08 — OIDF conformance-suite harness (local + nightly)

*chore · P1 · labels: area:foundation, area:conformance*

**Spec:** FAPI 2.0 SP §6.6 (use certified/complete implementations); OIDF conformance suite plan `fapi2-security-profile-final` (client auth private_key_jwt, sender-constraining DPoP).

docker-compose that runs the OpenID conformance suite against a local instance with a seeded tenant + two test clients (private_key_jwt + DPoP); CI job runs the FAPI2 SP plan and archives the report. Plans for OIDC Core are gated by decision E16_02.

**Acceptance tests**

- `make conformance` brings up PG + Asterius + conformance suite and runs the plan headless; exit code reflects pass/fail.
- Nightly CI publishes the HTML report; a failing test blocks release tags (E16_01).
- Seed script registers clients with the suite's JWKS and redirect URIs exactly.

**Depends on:** E01_04

### E01_09 — Threat model & ADR log baseline (FAPI 2.0 Attacker Model mapping)

*task · P0 · labels: area:security, area:docs*

**Spec:** FAPI 2.0 Attacker Model §3–§4 (attackers A1–A5: web attacker, network attacker, read/inject authorization request/response, read/inject token request/response); FAPI 2.0 SP §6 (security considerations).

`docs/threat-model.md` listing each attacker capability, the security goal it threatens (authorization, session integrity, token confidentiality) and the control + bead that mitigates it. `docs/adr/` with template and ADR-0001 modular monolith, ADR-0002 FAPI 2.0 as the only mode, ADR-0003 signing algorithm set (see E01_12).

**Acceptance tests**

- Every attacker A1–A5 has at least one row with a linked control; table is kept current by later stories (DoD).
- ADR template includes Context / Decision / Consequences / Spec clauses.
- CONTRIBUTING.md states: generated crypto or parsing code is not done until a human has read the relevant RFC section.

**Depends on:** E01_01

### E01_10 — Multi-tenancy & issuer resolution middleware

*task · P0 · labels: area:foundation, area:tenancy*

**Spec:** RFC 8414 §3.1 (path-insertion well-known form for issuers with a path); OIDC Discovery §4 (path-appending form); MCP Authorization 2025-11-25 'Authorization Server Metadata Discovery' (clients try both forms).

Tenant = issuer. Issuer shape `https://{host}/t/{tenant}` (path-based) with optional custom host per tenant. Middleware resolves the tenant from host/path before any protocol handler runs; all protocol routes are tenant-scoped; all keys, clients, users, sessions are tenant-partitioned.

**Acceptance tests**

- Two seeded tenants have distinct issuers, JWKS and clients; a client of tenant A cannot authenticate at tenant B's endpoints (`invalid_client`).
- Both `/.well-known/openid-configuration/t/{tenant}` and `/t/{tenant}/.well-known/openid-configuration` resolve (ties into E04_01).
- Tenant lookups are cached in-process with invalidation on admin change; no Redis.

**Depends on:** E01_03

### E01_11 — Audit event core (append-only, actor/agent aware)

*task · P0 · labels: area:foundation, area:audit*

**Spec:** FAPI 2.0 SP §6.8 item 4 (credential linking — record relationships so linked credentials can be revoked together); product requirement: per-agent audit trail.

`audit_events` append-only table written from domain events: timestamp, tenant, actor (user | client | admin | system), subject, client, session, grant, agent delegation chain (`act` chain), event type, outcome/error code, request id, hashed IP/UA. Optional per-tenant hash chain for tamper evidence. Retention job.

**Acceptance tests**

- Integration test: one code flow produces exactly the expected sequence of audit events (par.accepted, auth.login, consent.granted, code.issued, token.issued) with consistent ids.
- Schema test: audit payload contains no raw token/code/assertion (redaction applied before insert).
- Hash chain, when enabled, verifies end-to-end and detects a mutated row in a test.
- Retention job deletes events older than the tenant policy and is idempotent.

**Depends on:** E01_03

### E01_12 — Decision: signing algorithm set (EdDSA/ES256/PS256; RS256 is non-FAPI)

*decision · P0 · labels: area:security, adr*

**Spec:** FAPI 2.0 SP §5.4.1: JWTs 'shall use PS256, ES256, or EdDSA (using the Ed25519 variant) algorithms; and not use or accept the none algorithm'; RFC 8725 §3.1–3.2.

The product note says 'RS256 behind a flag'. FAPI 2.0 permits PS256 but not RS256, so an RS256 flag is by definition a non-compliant mode. Proposal: EdDSA default, ES256 always on, PS256 as the RSA compatibility algorithm, and `compat.rs256` as an explicitly non-FAPI flag that prints a startup warning and is excluded from conformance builds.

**Acceptance tests**

- ADR-0003 merged with the decision and the consequence for metadata (`id_token_signing_alg_values_supported`, `token_endpoint_auth_signing_alg_values_supported`, `dpop_signing_alg_values_supported`).
- If `compat.rs256` is kept: startup log warning + `/readyz` reports `fapi_compliant=false`.

**Depends on:** E01_09

## E02 — Key management & JOSE  (P0, epic)

KeyStore/Signer port with josekit adapter, JWKS endpoint, key lifecycle/rotation, JWT verification service (alg allow-list, explicit typ, clock-skew policy, duplicate-kid handling), client key resolution, CSPRNG/secret utilities.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E02_01 | KeyStore/Signer port + josekit adapter with algorithm allow-list | feature | P0 | E01_01, E01_03 |
| E02_02 | JWKS endpoint (`jwks_uri`) | feature | P0 | E02_01, E02_03 |
| E02_03 | Key lifecycle & automated rotation (encrypted at rest, KMS port) | feature | P0 | E02_01 |
| E02_04 | JWT verification service (typ, crit, skew window, duplicate-kid selection) | feature | P0 | E02_01 |
| E02_05 | Client key resolution & caching (`jwks` / `jwks_uri`, SSRF guard) | feature | P0 | E02_04 |
| E02_06 | CSPRNG token generation & secret-handling utilities (constant-time compare, zeroize) | task | P0 | E01_01 |

### E02_01 — KeyStore/Signer port + josekit adapter with algorithm allow-list

*feature · P0 · labels: area:keys, spec:fapi2-sp, spec:rfc8725, status:final*

**Spec:** FAPI 2.0 SP §5.4.1 items 1–3 (RFC 8725 adherence; PS256/ES256/EdDSA(Ed25519) only; no `none`; RSA ≥2048; EC ≥224 bits); RFC 8725 §3.1 (verify alg), §3.2 (restrict algs), §3.11 (explicit typ); RFC 7515/7517/7518.

Trait `Signer { fn sign(&self, header: Header, claims: &[u8]) -> Result<Jws> }` and `KeyStore` (active key per (tenant, purpose, alg), lookup by kid). josekit adapter with aws-lc-rs/ring backends. Every issued JWT sets `kid`, `alg` and an explicit `typ`.

**Acceptance tests**

- Constructing a signer with `none`, `HS*`, or (without `compat.rs256`) `RS256` is a compile-time or startup error; unit tests cover each.
- Ed25519 keys sign/verify (EdDSA), P-256 (ES256), RSA-2048/3072/4096 (PS256); RSA-1024 key import rejected.
- Property test: sign→verify round-trip for random payloads and all enabled algs; tampering any byte fails verification.
- Fuzz target `jwt_compact` (header/payload/signature splitting, base64url) runs clean 10 min.

**Depends on:** E01_01, E01_03

### E02_02 — JWKS endpoint (`jwks_uri`)

*feature · P0 · labels: area:keys, spec:oidc-discovery, spec:fapi2-sp, status:final*

**Spec:** OIDC Discovery §3 (`jwks_uri`: keys used to sign ID Tokens; `use` parameter); OIDC Core §10.1.1 (key rotation via JWKS); FAPI 2.0 SP §5.4.2 (serve only over TLS; should not use `x5u`/`jku`; should not serve multiple keys with the same `kid`).

`GET /t/{tenant}/jwks` returning public members of active + retiring signing keys, with `kid`, `kty`, `crv`/`alg`, `use: sig`. Cache headers tuned to rotation cadence.

**Acceptance tests**

- Response never contains `d`, `p`, `q`, `dp`, `dq`, `qi` or symmetric `k` (schema test).
- Test rejects a key set with duplicate `kid` at generation time; retiring keys remain published for the configured grace period after rotation.
- `Cache-Control: public, max-age=<rotation/4>`; ETag supported.
- Emitted JWS headers never include `x5u`/`jku` (unit test on header builder).

**Depends on:** E02_01, E02_03

### E02_03 — Key lifecycle & automated rotation (encrypted at rest, KMS port)

*feature · P0 · labels: area:keys, spec:oidc-core, status:final*

**Spec:** OIDC Core §10.1.1 (rotation of asymmetric signing keys: publish new key, then sign with it; keep old for verification); FAPI 2.0 SP §6.8 (key compromise: automated regular rotation, single-purpose keys).

States `pending → active → retiring → retired`. Per-tenant rotation schedule; private keys encrypted with a KEK obtained from a `Kek` port (local file / env for dev, cloud KMS adapters later). Separate keys per purpose (id_token/access_token signing, SET signing may share; encryption keys separate).

**Acceptance tests**

- Rotation test: tokens signed before rotation still verify via JWKS until grace end; new tokens use the new `kid`; retired keys are not published.
- Private key material at rest is ciphertext (test reads DB row and asserts it does not parse as JWK).
- Admin API endpoint triggers rotation; audit event emitted; concurrent rotations serialised with a DB lock.
- Same key is never used for both signing and encryption (enforced by `purpose` column + test).

**Depends on:** E02_01

### E02_04 — JWT verification service (typ, crit, skew window, duplicate-kid selection)

*feature · P0 · labels: area:keys, spec:fapi2-sp, spec:rfc8725, status:final*

**Spec:** RFC 8725 §3.1–3.3 (alg verification, key/alg binding), §3.5 (crit), §3.8–3.9 (validate all claims, use UTC), §3.11 (explicit typ); FAPI 2.0 SP §5.3.2.1 item 13 ('shall accept JWTs with an iat or nbf timestamp between 0 and 10 seconds in the future but shall reject JWTs with an iat or nbf timestamp greater than 60 seconds in the future'); §5.4.3 (duplicate kid selection algorithm).

One verifier used for client assertions, DPoP proofs, request objects, id_token_hint, CIBA signed requests, logout tokens received in tests. Callers pass an expected `typ`, allowed algs, expected `iss`/`aud`, and a key resolver.

**Acceptance tests**

- Missing or mismatching `typ` rejected when the context requires one (`dpop+jwt`, `oauth-authz-req+jwt`, `at+jwt`, `logout+jwt`, `secevent+jwt`).
- Unknown `crit` parameter → reject; `alg` outside caller's allow-list → reject; key type/alg mismatch → reject (RS/HS confusion test).
- Clock skew: iat/nbf up to +10 s accepted; +11..+60 s accepted only if tenant config raises the window (max 60); +61 s rejected; expired `exp` rejected with 0 s leeway by default.
- Duplicate-kid test set: verifier iterates candidate keys matching `kid` and selects by `alg`/`kty`/`crv`/`use` per FAPI 2.0 SP §5.4.3.
- Maximum JWT size 8 KiB (configurable); fuzz target on claims parsing.

**Depends on:** E02_01

### E02_05 — Client key resolution & caching (`jwks` / `jwks_uri`, SSRF guard)

*feature · P0 · labels: area:keys, spec:rfc7591, spec:fapi2-sp, status:final*

**Spec:** RFC 7591 §2 (`jwks_uri` and `jwks` MUST NOT both be present); OIDC Registration §2; OIDC Core §10.1.1 (fetch JWKS again on unknown kid); FAPI 2.0 SP §5.4.2 (JWKS over TLS; recommend jwks_uri or jwks + RFC 7591/7592).

Resolver used by private_key_jwt, DPoP (no — DPoP uses embedded jwk), request objects, CIBA signed requests. Fetches `jwks_uri` over TLS with strict limits and caches per client.

**Acceptance tests**

- Registration with both `jwks` and `jwks_uri` → `invalid_client_metadata`; `jwks_uri` must be `https` and not resolve to loopback/link-local/private ranges unless tenant allowlists it (SSRF test with DNS stub).
- Fetch: timeout 5 s, max 64 KiB, follows no redirects, requires `application/json`/`application/jwk-set+json`.
- Unknown `kid` triggers at most one refetch per 60 s per client (negative cache); hit/miss metrics.
- Key with private members in a client JWKS is rejected at registration and at fetch.

**Depends on:** E02_04

### E02_06 — CSPRNG token generation & secret-handling utilities (constant-time compare, zeroize)

*task · P0 · labels: area:keys, area:security, spec:fapi2-sp, status:final*

**Spec:** FAPI 2.0 SP §5.4.1 item 4 (credentials not handled by end users ≥128 bits of entropy); RFC 6749 §10.10 (credential guessing); RFC 8628 §6.1 (user-code entropy — used later).

`OpaqueToken::generate(bits)` (default 256) base64url without padding; `Secret<T>` with `zeroize`; `ct_eq` wrapper (subtle) used for every secret comparison; hashing helper `sha256_hex` for at-rest storage.

**Acceptance tests**

- Statistical sanity test on generator output (no repeats in 10^6 draws, byte distribution).
- A custom lint/grep test fails the build if `==` is used on `Secret`/`OpaqueToken` types.
- All comparisons of codes, tokens, PKCE verifiers, CSRF tokens go through `ct_eq` (reviewed checklist in PR template).

**Depends on:** E01_01

## E03 — Clients, client authentication & dynamic registration  (P0, epic)

Confidential-only client model with FAPI 2.0 metadata, private_key_jwt (and optional mTLS) authentication, exact redirect-URI matching, RFC 7591/7592 registration endpoints, software statements and a per-tenant DCR policy engine (the AI-agent onboarding path).

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E03_01 | Client model & metadata validation (confidential clients only) | feature | P0 | E01_03, E01_10 |
| E03_02 | Client authentication: private_key_jwt | feature | P0 | E03_01, E02_04, E02_05 |
| E03_03 | Client authentication: mTLS (`tls_client_auth`, `self_signed_tls_client_auth`) [flag: mtls] | feature | P2 | E03_01, E01_04 |
| E03_04 | Dynamic Client Registration endpoint (POST /register) | feature | P1 | E03_01, E03_07 |
| E03_05 | Client configuration endpoint (GET/PUT/DELETE registration_client_uri) | feature | P1 | E03_04 |
| E03_06 | Software statements & per-tenant DCR policy engine (agent onboarding profile) | feature | P2 | E03_04, E02_04 |
| E03_07 | Redirect URI validation: exact match, https-only, loopback exception | feature | P0 | E03_01 |
| E03_08 | Decision: MCP public clients & Client ID Metadata Documents (CIMD) | decision | P2 | E01_09 |

### E03_01 — Client model & metadata validation (confidential clients only)

*feature · P0 · labels: area:clients, spec:rfc7591, spec:oidc-registration, spec:fapi2-sp, status:final*

**Spec:** RFC 7591 §2 (client metadata), §2.1 (grant_types ↔ response_types consistency); OIDC Registration §2 (application_type, subject_type, sector_identifier_uri, id_token_signed_response_alg, token_endpoint_auth_method …); RFC 9126 §6 (`require_pushed_authorization_requests`); RFC 9449 §12 (`dpop_bound_access_tokens`); RFC 9396 §9.2 (`authorization_details_types`); CIBA §4 (backchannel_* client metadata); FAPI 2.0 SP §5.2.2.1.1 (`use_mtls_endpoint_aliases`), §5.3.2.1 item 3 ('shall only support confidential clients').

`Client` aggregate + validating parser used by DCR, admin API and seed scripts. Defaults are the FAPI values; anything weaker is rejected, not defaulted.

**Acceptance tests**

- `token_endpoint_auth_method` accepted values: `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` (last two only with `mtls` flag); `client_secret_*` and `none` → `invalid_client_metadata`.
- `response_types` must be `["code"]`; `grant_types` ⊆ {authorization_code, refresh_token, client_credentials, urn:ietf:params:oauth:grant-type:token-exchange, urn:ietf:params:oauth:grant-type:device_code, urn:openid:params:grant-type:ciba}; RFC 7591 §2.1 consistency enforced.
- `redirect_uris` required when `authorization_code` is present; each validated by E03_07 rules; `application_type=native` unlocks loopback only.
- `id_token_signed_response_alg`/`request_object_signing_alg`/`backchannel_authentication_request_signing_alg` must be in the tenant alg allow-list; `none` rejected.
- `jwks` xor `jwks_uri` required for private_key_jwt clients; `sector_identifier_uri` validated when `subject_type=pairwise` (https; JSON array that MUST include all registered redirect_uris — OIDC Registration §5 — and, for CIBA clients, the jwks_uri / notification endpoint per CIBA §4).
- `dpop_bound_access_tokens` defaults to true and cannot be set false unless `tls_client_certificate_bound_access_tokens` is true.
- proptest strategies for valid/invalid metadata; fuzz target `client_metadata_json`.

**Depends on:** E01_03, E01_10

### E03_02 — Client authentication: private_key_jwt

*feature · P0 · labels: area:clients, spec:oidc-core, spec:rfc7523, spec:fapi2-sp, status:final*

**Spec:** OIDC Core §9 (private_key_jwt: iss=sub=client_id, aud, jti, exp; MAY contain iat); RFC 7523 §3 (JWT format and processing; jti MAY be used to reject replay); RFC 7521 §4.2 (client_assertion_type urn:ietf:params:oauth:client-assertion-type:jwt-bearer); FAPI 2.0 SP §5.3.2.1 item 6 (authenticate with mTLS or private_key_jwt), item 8 ('shall only accept its issuer identifier value … as a string in the aud claim'); CIBA §7.1 (backchannel endpoint MUST also accept token endpoint URL / backchannel endpoint URL as aud).

Shared authenticator used by token, PAR, introspection, revocation, device-authorization and backchannel-authentication endpoints. Keys resolved via E02_05.

**Acceptance tests**

- Assertion with `aud` = issuer identifier (string) accepted; `aud` as array or token-endpoint URL rejected with `invalid_client` — except at the backchannel authentication endpoint where the three CIBA §7.1 values are accepted (documented interop note).
- `iss` ≠ `sub` ≠ authenticated `client_id` → `invalid_client`; missing `jti` → reject; `exp` more than 10 min in the future (tenant-configurable) → reject; `iat`/`nbf` skew per E02_04.
- `jti` replay within its validity window → `invalid_client` (PostgreSQL-backed replay store keyed by client_id+jti, expiring at `exp`).
- `client_id` form parameter, if present, must equal assertion `sub`; multiple client authentication methods in one request → `invalid_request` (RFC 6749 §2.3).
- Failure paths take the same time whether client exists or not (dummy verification); errors return 401 with `WWW-Authenticate` only for header-based schemes.
- Fuzz target `client_assertion`; FAPI2 conformance client-auth tests pass (E16_01).

**Depends on:** E03_01, E02_04, E02_05

### E03_03 — Client authentication: mTLS (`tls_client_auth`, `self_signed_tls_client_auth`) [flag: mtls]

*feature · P2 · labels: area:clients, spec:rfc8705, spec:fapi2-sp, status:final, flag:mtls*

**Spec:** RFC 8705 §2.1 (PKI method: subject DN / SAN matching), §2.1.2 (client metadata tls_client_auth_subject_dn, *_san_dns/uri/ip/email), §2.2 (self-signed: match against registered JWKS `x5c`), §5 (`mtls_endpoint_aliases`); FAPI 2.0 SP §5.2.2 (MTLS ecosystems), §5.3.2.1 item 6.

Certificate arrives either from rustls (terminate mode) or from a proxy header (`behind_proxy` + trusted CIDR only). Exactly one of the subject/SAN metadata fields is registered and matched exactly.

**Acceptance tests**

- Without `mtls` flag the auth methods are rejected at registration and metadata omits them.
- PKI mode: cert chain validated against tenant trust anchors; registered DN/SAN compared exactly (RFC 4514 string form for DN).
- Self-signed mode: certificate must match an `x5c` in the client JWKS (thumbprint compare).
- Proxy header ignored unless remote address in `trusted_proxies`; test proves header spoofing from untrusted address fails.
- `mtls_endpoint_aliases` published for token, PAR, introspection, revocation, device, backchannel endpoints.

**Depends on:** E03_01, E01_04

### E03_04 — Dynamic Client Registration endpoint (POST /register)

*feature · P1 · labels: area:clients, spec:rfc7591, spec:oidc-registration, status:final*

**Spec:** RFC 7591 §3.1 (request), §3.2.1 (201 response: client_id, client_id_issued_at, echoed metadata), §3.2.2 (errors invalid_redirect_uri, invalid_client_metadata, invalid_software_statement, unapproved_software_statement); OIDC Registration §3.1–3.3 (registration_access_token, registration_client_uri, client_secret_expires_at=0 semantics); RFC 7591 §5 (security: initial access token, rate limiting).

Tenant-scoped registration endpoint. Default: bearer initial access token required (issued by admin API with a policy and quota); tenant may enable open registration only together with a DCR policy (E03_06).

**Acceptance tests**

- `POST application/json` returns 201 with `client_id` (random ≥128 bits, never user-like — FAPI 2.0 SP §6.6), `client_id_issued_at`, `registration_access_token` (≥256 bits, stored hashed), `registration_client_uri`, and all accepted metadata; no `client_secret` ever.
- Metadata validated by E03_01; failures map to RFC 7591 §3.2.2 error codes with HTTP 400; unknown fields are ignored and not echoed.
- Missing/invalid initial access token → 401; per-token quota and per-IP rate limit (429).
- Registration writes an audit event with the policy decision; conformance `oidcc-dynamic-registration` style tests pass where compatible with PAR-only.

**Depends on:** E03_01, E03_07

### E03_05 — Client configuration endpoint (GET/PUT/DELETE registration_client_uri)

*feature · P1 · labels: area:clients, spec:rfc7592, spec:oidc-registration, status:final*

**Spec:** RFC 7592 §2.1 (read; unknown client/invalid token → 401 and token SHOULD be revoked), §2.2 (update: full replacement, client_id immutable), §2.3 (delete → 204), §3 (responses); OIDC Registration §4.1 (endpoint URL), §4.2–4.3 (read request/response), §4.4 (error: 401 invalid/unknown, 403 no permission, MUST NOT return 404).

Bearer `registration_access_token` protected management of one client. PUT validates the full document with E03_01; DELETE cascades to grants/tokens/streams.

**Acceptance tests**

- GET returns current metadata (no secrets); PUT with changed `client_id` → 400 `invalid_client_metadata`; PUT re-issues `registration_access_token` when tenant policy says rotate.
- DELETE → 204, all grants, refresh tokens, PAR requests, device/CIBA requests and SSF streams of the client revoked (integration test).
- Invalid registration access token, or token for client A used on client B's URI, or unknown client → 401 and the presented token is revoked (OIDC Registration §4.4: endpoints MUST NOT return 404; RFC 7592 §2.1); a valid token lacking permission → 403.
- All operations audited.

**Depends on:** E03_04

### E03_06 — Software statements & per-tenant DCR policy engine (agent onboarding profile)

*feature · P2 · labels: area:clients, spec:rfc7591, status:final, differentiator:agents*

**Spec:** RFC 7591 §2.3 (software statement JWT: signed by trusted issuer, values override plain metadata), §3.1.1 (registration with software statement), §5 (security: software statement trust, open registration risks).

Declarative policy per tenant evaluated on every registration/update: allowed auth methods, grant types, scopes, audience/resource allowlist, redirect-URI host allowlist, require `jwks`/`jwks_uri`, require software statement from configured issuers (JWKS), max clients per initial access token, auto-expire unused clients, and a preset `agent` profile (E11_01).

**Acceptance tests**

- Software statement: signature verified against configured issuer JWKS; claims override request values (RFC 7591 §2.3); untrusted issuer → `unapproved_software_statement`; malformed → `invalid_software_statement`.
- Policy denial returns `invalid_client_metadata` with a safe description and is audited with the failing rule id.
- Policy is data (JSON/YAML stored per tenant), validated against a schema; no tenant-supplied code.
- Property test: policy evaluation is deterministic and total (never panics) on random metadata.

**Depends on:** E03_04, E02_04

### E03_07 — Redirect URI validation: exact match, https-only, loopback exception

*feature · P0 · labels: area:clients, area:authz, spec:rfc6749, spec:rfc9700, spec:fapi2-sp, status:final*

**Spec:** RFC 6749 §3.1.2.2–3.1.2.3 (registered redirect URI; comparison); RFC 9700 §4.1 (exact string matching, no pattern matching); RFC 8252 §7.3 (loopback interface redirection, any port); FAPI 2.0 SP §5.3.2.2 item 8 ('shall not allow redirect URIs that use the http scheme except for native clients that use loopback interface redirection').

One function used at registration, PAR and token endpoint. FAPI 2.0 permits unregistered redirect URIs via PAR; this product deliberately keeps exact matching against the registered set (defense in depth; documented in ADR).

**Acceptance tests**

- Comparison is byte-exact (RFC 3986 §6.2.1 simple string comparison) against the registered list; no prefix/pattern/case-insensitive matching (tests: trailing slash, case, added query, userinfo, IDN forms all fail).
- `https` required; `http://127.0.0.1:*` and `http://[::1]:*` accepted only for `application_type=native`, port ignored in comparison per RFC 8252 §7.3; `http://localhost` rejected.
- Fragments rejected at registration; custom schemes rejected (no public clients).
- Fuzz target `redirect_uri` with structured URI generator; proptest that normalisation is never applied.

**Depends on:** E03_01

### E03_08 — Decision: MCP public clients & Client ID Metadata Documents (CIMD)

*decision · P2 · labels: adr, differentiator:agents, spec:mcp, status:draft*

**Spec:** MCP Authorization (2025-11-25): AS MUST implement OAuth 2.1 'for both confidential and public clients'; AS SHOULD support Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-00 — IETF working draft: track, don't implement); AS MAY support RFC 7591; FAPI 2.0 SP §5.3.2.1 item 3 (confidential clients only).

Two fixed product decisions conflict for off-the-shelf MCP clients (public, no PAR, localhost redirect). Options: (a) FAPI-only — MCP compatibility limited to confidential MCP clients registered via DCR with `jwks` + private_key_jwt, PAR and DPoP (E11_08); (b) a tenant-level 'OAuth 2.1 public-client profile' (PKCE S256 + DPoP-bound tokens + exact loopback redirect, PAR optional) that weakens the baseline. Recommendation: (a) for v1; revisit when CIMD is an RFC and OIDF conformance has a public-client FAPI-adjacent profile.

**Acceptance tests**

- ADR written with the option chosen and its consequence on metadata (`client_id_metadata_document_supported` absent) and on the MCP compatibility story E11_08.
- If (b) is ever chosen it must be a separate tenant mode that fails `fapi_compliant` readiness reporting.

**Depends on:** E01_09

## E04 — Discovery & authorization-server metadata  (P0, epic)

OpenID Provider configuration and RFC 8414 metadata generated from a single capability registry, served in every URL form MCP and RFC 8414 clients try.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E04_01 | OpenID Provider Configuration endpoint (`/.well-known/openid-configuration`) | feature | P0 | E04_03, E02_02, E01_10 |
| E04_02 | OAuth 2.0 Authorization Server Metadata (`/.well-known/oauth-authorization-server`) | feature | P1 | E04_01 |
| E04_03 | Capability registry → metadata (single source of truth, route/metadata parity test) | task | P1 | E01_02 |

### E04_01 — OpenID Provider Configuration endpoint (`/.well-known/openid-configuration`)

*feature · P0 · labels: area:discovery, spec:oidc-discovery, spec:fapi2-sp, spec:mcp, status:final*

**Spec:** OIDC Discovery §3 (OpenID Provider Metadata: REQUIRED issuer, authorization_endpoint, token_endpoint, jwks_uri, response_types_supported, subject_types_supported, id_token_signing_alg_values_supported; others), §4.1 (request), §4.2 (response: application/json, 200), §4.3 (validation: issuer MUST be identical to the URL used); FAPI 2.0 SP §5.3.2.1 item 1 (distribute metadata via OIDD/RFC 8414); RFC 9126 §5; RFC 9207 §3; RFC 9449 §11; RFC 9396 §9.1; MCP Authorization 2025-11-25 ('Authorization servers providing OpenID Connect Discovery 1.0 MUST include code_challenge_methods_supported').

Rendered from the capability registry (E04_03) per tenant; served at the path-appended form and the path-inserted form.

**Acceptance tests**

- Golden-file test of the document for the reference tenant: `issuer` exact; `response_types_supported: ["code"]`; `grant_types_supported` from flags; `token_endpoint_auth_methods_supported: ["private_key_jwt"]` (+ mTLS methods when flagged); `token_endpoint_auth_signing_alg_values_supported`/`id_token_signing_alg_values_supported`/`request_object_signing_alg_values_supported` = allow-list; `code_challenge_methods_supported: ["S256"]`; `require_pushed_authorization_requests: true`; `pushed_authorization_request_endpoint`; `authorization_response_iss_parameter_supported: true`; `dpop_signing_alg_values_supported`; `response_modes_supported: ["query","form_post"]`; `subject_types_supported: ["public","pairwise"]`; `claims_supported`, `scopes_supported`, `claims_parameter_supported: true`, `request_parameter_supported` per flag, `request_uri_parameter_supported: false` (only PAR-issued), `end_session_endpoint`, `backchannel_logout_supported`, `backchannel_logout_session_supported`, `introspection_endpoint`, `revocation_endpoint` and their `*_auth_methods_supported`, `ui_locales_supported`, `acr_values_supported`, `prompt_values_supported`.
- Both `https://host/t/x/.well-known/openid-configuration` and `https://host/.well-known/openid-configuration/t/x` return the identical document (MCP path-insertion form).
- `Content-Type: application/json`, cacheable 5 min; no metadata key is emitted for a disabled feature (test iterates flags).
- OIDF conformance discovery checks pass (E16_01).

**Depends on:** E04_03, E02_02, E01_10

### E04_02 — OAuth 2.0 Authorization Server Metadata (`/.well-known/oauth-authorization-server`)

*feature · P1 · labels: area:discovery, spec:rfc8414, spec:mcp, status:final*

**Spec:** RFC 8414 §2 (metadata), §3.1 (well-known path insertion between host and path), §3.2 (response), §3.3 (validation: issuer identical), §5 (compatibility with OIDC Discovery).

Same document as E04_01, served at the RFC 8414 location (path-inserted form) so MCP clients' first probe succeeds.

**Acceptance tests**

- `GET /.well-known/oauth-authorization-server/t/{tenant}` returns the same bytes as the OIDC document (test compares JSON equality).
- For a host-based tenant (no path) `GET /.well-known/oauth-authorization-server` works.
- 404 for unknown tenant (no information leak about tenant existence beyond 404).

**Depends on:** E04_01

### E04_03 — Capability registry → metadata (single source of truth, route/metadata parity test)

*task · P1 · labels: area:discovery, area:foundation*

**Spec:** OIDC Discovery §3; RFC 8414 §2 (metadata MUST reflect actual behaviour).

`Capabilities` (E01_02 flags + tenant settings + alg allow-list) is the only input to metadata generation and to router construction, so an endpoint cannot be advertised without existing or exist without being advertised.

**Acceptance tests**

- Parity test: every `*_endpoint` URL in metadata responds (not 404) and every mounted protocol route is present in metadata (allowlist for UI routes).
- Toggling each flag in a test flips exactly the documented metadata keys (table-driven test).

**Depends on:** E01_02

## E05 — Pushed authorization requests & authorization endpoint  (P0, epic)

PAR-only authorization endpoint at the FAPI 2.0 baseline: client-authenticated PAR, PKCE S256, exact redirect URI, code ≤60 s single-use, `iss` in responses, form_post, RAR, resource indicators, prompt/max_age/hints, optional JAR inside PAR.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E05_01 | Pushed Authorization Request endpoint (RFC 9126) | feature | P0 | E03_02, E03_07, E05_03 |
| E05_02 | Authorization endpoint: PAR-only request handling & interaction hand-off | feature | P0 | E05_01, E06_01 |
| E05_03 | PKCE S256 enforcement (no plain, no missing) | feature | P0 | E02_06 |
| E05_04 | Authorization response: code issuance (≤60 s, single-use, replay revocation) with `iss` | feature | P0 | E05_02, E06_02, E07_01 |
| E05_05 | response_mode=form_post (server-rendered auto-submit, works without JavaScript) | feature | P0 | E05_04, E15_03 |
| E05_06 | Rich Authorization Requests (`authorization_details`, RFC 9396) | feature | P1 | E05_01, E07_02 |
| E05_07 | Resource indicators (`resource`, RFC 8707) driving `aud` | feature | P1 | E05_01 |
| E05_08 | prompt / max_age / id_token_hint / login_hint / acr_values handling and unmet-requirements error | feature | P1 | E05_02, E06_07 |
| E05_09 | Signed request objects (JAR) inside PAR [optional] | feature | P3 | E05_01, E02_04 |

### E05_01 — Pushed Authorization Request endpoint (RFC 9126)

*feature · P0 · labels: area:authz, spec:rfc9126, spec:fapi2-sp, status:final*

**Spec:** RFC 9126 §2.1 (request: client auth, all authorization parameters, `request_uri` MUST NOT be present), §2.2 (201 with `request_uri` urn:ietf:params:oauth:request_uri:… and `expires_in`), §2.3 (errors incl. `invalid_request`, `invalid_client` 401), §2.4 (redirect URI management), §7.1 (request_uri guessing), §7.3 (replay); FAPI 2.0 SP §5.3.2.2 items 2–4 (support client-authenticated PAR; reject requests without PAR; reject PAR without client auth), 6 (`redirect_uri` required in PAR), 12 (`expires_in` < 600 s), Note 3 (enforce one-time use at authorization, not page load).

Validates the whole authorization request at push time with the same rules as E05_02, stores it keyed by a ≥128-bit reference bound to the client, and returns the `request_uri`.

**Acceptance tests**

- Unauthenticated PAR → 401 `invalid_client`; PAR body containing `request_uri` → 400 `invalid_request`.
- `redirect_uri` missing → 400 `invalid_request`; not exactly registered → 400 `invalid_request` (never redirect from PAR).
- 201 body `{request_uri: "urn:ietf:params:oauth:request_uri:<≥128-bit>", expires_in: 90}` with `expires_in` < 600 (tenant-configurable, capped).
- `request_uri` of client A presented by client B at `/authorize` → error page (no redirect); expired → error page.
- One-time use is consumed when the user completes authorization/denial, not when the page is loaded (test: reload authorization page twice before consenting succeeds; replay after consent fails).
- All parameter validation (response_type, scope, PKCE S256, nonce length, RAR, resource, prompt combos) happens here; conformance `fapi2-security-profile` PAR tests pass; fuzz target `par_form`.

**Depends on:** E03_02, E03_07, E05_03

### E05_02 — Authorization endpoint: PAR-only request handling & interaction hand-off

*feature · P0 · labels: area:authz, spec:oidc-core, spec:rfc6749, spec:rfc9126, spec:fapi2-sp, status:final*

**Spec:** OIDC Core §3.1.2.1 (authentication request parameters; GET or POST; scope openid), §3.1.2.2 (request validation: 'MUST validate all OAuth 2.0 parameters'; 'MUST verify that a scope parameter is present and contains the openid scope value' for OIDC; ignore unrecognised parameters), §3.1.2.6 (error response); RFC 6749 §4.1.1, §4.1.2.1 (if redirect URI/client_id invalid: 'MUST NOT automatically redirect'); RFC 9126 §4 (client_id + request_uri at authorization endpoint); FAPI 2.0 SP §5.3.2.2 item 1 (`response_type` = `code`), item 3 (reject non-PAR), item 14 (nonce up to 64 chars).

`GET|POST /t/{tenant}/authorize?client_id&request_uri` loads the pushed request, re-checks binding, creates an interaction (E06_01) and redirects (303) to the login/consent pages. Pure-OAuth requests (no `openid` scope) are allowed and yield no ID token.

**Acceptance tests**

- Request without `request_uri` or with any other parameter than `client_id`/`request_uri` → rendered error page `invalid_request` (never a redirect, since the redirect_uri is untrusted).
- `client_id` mismatch with the pushed request's client → error page; expired/unknown/consumed `request_uri` → error page.
- Errors detectable only after the pushed request is trusted (e.g., `login_required`) are redirected to the pushed `redirect_uri` with `error`, `error_description`, `state`, `iss` (RFC 9207).
- `nonce` longer than 64 chars → `invalid_request`; unknown parameters ignored (test with 100 random params).
- `Cache-Control: no-store` on every response; interaction id is unguessable (≥128 bits) and bound to a `__Host-` cookie.
- FAPI2 conformance authorization endpoint tests pass; fuzz target `authorize_query`.

**Depends on:** E05_01, E06_01

### E05_03 — PKCE S256 enforcement (no plain, no missing)

*feature · P0 · labels: area:authz, spec:rfc7636, spec:fapi2-sp, spec:rfc9700, status:final*

**Spec:** RFC 7636 §4.1 (verifier 43–128 unreserved chars), §4.2 (S256 = BASE64URL(SHA256(ASCII(verifier)))), §4.3 (client sends challenge), §4.4 (server associates challenge with code), §4.5 (client sends verifier), §4.6 (server verifies), §7.2 (entropy); FAPI 2.0 SP §5.3.2.2 item 5 ('shall require PKCE with S256'); RFC 9700 §4.8 (PKCE downgrade attack: reject token requests without verifier when challenge was present, and never accept codes issued without PKCE).

Validation at PAR (challenge present, method S256, well-formed) and at the token endpoint (verifier present, S256 match, constant-time).

**Acceptance tests**

- PAR without `code_challenge` or with `code_challenge_method` absent/`plain` → `invalid_request`.
- `code_challenge` not 43 chars base64url → `invalid_request`; token request `code_verifier` outside 43–128 unreserved chars → `invalid_grant`.
- Verifier/challenge mismatch → `invalid_grant`, code consumed and any tokens from that code revoked.
- Property test: for random verifiers, S256(verifier) matches; comparison uses `ct_eq`.
- Fuzz target `pkce`.

**Depends on:** E02_06

### E05_04 — Authorization response: code issuance (≤60 s, single-use, replay revocation) with `iss`

*feature · P0 · labels: area:authz, spec:oidc-core, spec:rfc6749, spec:rfc9207, spec:fapi2-sp, status:final*

**Spec:** OIDC Core §3.1.2.5 (successful authentication response: code, state), §3.1.2.6 (error response); RFC 6749 §4.1.2 (code lifetime SHOULD be short, MUST NOT be used more than once; on reuse 'SHOULD revoke all tokens previously issued based on that authorization code'), §4.1.2.1; RFC 9207 §2 (`iss` parameter MUST be included in successful and error responses when supported); FAPI 2.0 SP §5.3.2.2 item 7 (`iss` per RFC 9207), item 9 (reject previously used code), items 10–11 (no 307; 303), Note 1.

After consent, mint an authorization code bound to client_id, redirect_uri, scope, nonce, PKCE challenge, `dpop_jkt`, resources, authorization_details, session id, auth_time, acr; persist hash; redirect via query or form_post.

**Acceptance tests**

- Code is ≥128 bits random, stored as SHA-256, `expires_at` ≤ 60 s from issuance (tenant-configurable, hard cap 60).
- Redirect uses 303 with `code`, `state` (verbatim, if supplied) and `iss` (tenant issuer); error redirects also carry `iss`.
- Second redemption of the same code → `invalid_grant` and all access/refresh tokens issued from it are revoked (test verifies introspection `active:false`).
- Denied consent → `access_denied` redirect with `state`/`iss`.
- FAPI2 conformance tests for code reuse and `iss` pass.

**Depends on:** E05_02, E06_02, E07_01

### E05_05 — response_mode=form_post (server-rendered auto-submit, works without JavaScript)

*feature · P0 · labels: area:authz, area:web, spec:oauth-form-post, spec:oauth-multiple-response-types, status:final*

**Spec:** OAuth 2.0 Form Post Response Mode §2 (HTML form POST to redirect_uri with `application/x-www-form-urlencoded` body containing all response parameters; MUST NOT be cached); OAuth 2.0 Multiple Response Type Encoding Practices §2.1 (`response_mode`); FAPI 2.0 SP §5.2.3 (browser endpoints).

Template renders a hidden form with `code`, `state`, `iss`; a nonce-CSP script auto-submits; `<noscript>` shows a Continue button. Only `query` and `form_post` are accepted for `response_type=code`.

**Acceptance tests**

- `response_mode=form_post` → 200 HTML, `Cache-Control: no-store`, form `method=post` `action` = exact redirect_uri, hidden inputs escaped; auto-submit script carries the per-response CSP nonce; page works with JS disabled (Playwright no-JS test submits via button).
- `response_mode=fragment` or unknown → `invalid_request` at PAR (documented interop note).
- Error responses honour form_post too.
- CSP `form-action` allows exactly the redirect_uri origin for this response.

**Depends on:** E05_04, E15_03

### E05_06 — Rich Authorization Requests (`authorization_details`, RFC 9396)

*feature · P1 · labels: area:authz, spec:rfc9396, status:final, differentiator:agents*

**Spec:** RFC 9396 §2 (JSON array of objects; `type` REQUIRED), §2.1 (authorization details types), §2.2 (common fields locations, actions, datatypes, identifier, privileges), §3 (authorization request), §6 (token response MAY include enriched `authorization_details`), §7 (token error `invalid_authorization_details` — section number from memory, verify), §8.1 (`authorization_details` claim in JWT access tokens), §9.1 (`authorization_details_types_supported`), §9.2 (client `authorization_details_types`). FAPI 2.0 SP §5.3.2.2 Note 5 (RAR recommended when scope is not expressive enough).

Per-tenant registry of RAR types with JSON Schema and consent template; parsing with depth/size limits; client allow-list; persisted on the grant; propagated to access tokens, introspection and the Grant Management resource.

**Acceptance tests**

- `authorization_details` that is not a JSON array of objects, or an element without string `type`, or a type not registered/not allowed for the client → `invalid_authorization_details` (PAR 400).
- Each element validated against the type's JSON Schema; `locations` must be a subset of the client's allowed resources; unknown extra members allowed only if the schema permits.
- Consent page renders each element with the type's template (no raw JSON to the user).
- Token response echoes the granted (possibly enriched) details; JWT AT and introspection carry them; `authorization_details_types_supported` published.
- Limits: ≤ 16 elements, ≤ 8 KiB, depth ≤ 8; fuzz target `authorization_details`.

**Depends on:** E05_01, E07_02

### E05_07 — Resource indicators (`resource`, RFC 8707) driving `aud`

*feature · P1 · labels: area:authz, spec:rfc8707, spec:mcp, status:final*

**Spec:** RFC 8707 §2 (absolute URI, no fragment, SHOULD be most specific; multiple allowed), §2.1 (authorization request), §2.2 (token request; MUST be a subset of the authorized set; `invalid_target` error), §3 (security: audience restriction); RFC 9068 §3 (`aud` from resource); MCP Authorization 2025-11-25 'Resource Parameter Implementation' (clients MUST send `resource` in both requests; canonical MCP server URI).

Registered resource servers per tenant (identifier URI, allowed scopes, default token lifetime). `resource` values must be registered; otherwise `invalid_target`. Access tokens are always audience-bound: if a client sends no `resource`, its registered default audiences apply, and a client with none cannot get an access token.

**Acceptance tests**

- `resource` with fragment, relative URI or unregistered value → `invalid_target` (PAR and token endpoint).
- Token-request `resource` ⊄ authorization-request `resource` set → `invalid_target`.
- Issued AT `aud` equals the requested resource(s); scope filtered to what the resource allows; test with two resources issues one token with array `aud` or (policy) rejects multi-audience.
- Client with no `resource` and no default audiences → `invalid_target` (no audience-less tokens).

**Depends on:** E05_01

### E05_08 — prompt / max_age / id_token_hint / login_hint / acr_values handling and unmet-requirements error

*feature · P1 · labels: area:authz, spec:oidc-core, spec:oidc-prompt-create, spec:oidc-unmet-authn-req, status:final*

**Spec:** OIDC Core §3.1.2.1 (prompt none|login|consent|select_account and combination rules; max_age; id_token_hint 'MUST be validated' / 'SHOULD' sub match; login_hint; acr_values), §3.1.2.3 (re-authentication rules), §3.1.2.6 (login_required, consent_required, interaction_required, account_selection_required), §5.5.1.1 (essential acr); OpenID Connect Prompt Create 1.0 §3–§4 (prompt=create; `prompt_values_supported`); OpenID Connect Core Unmet Authentication Requirements 1.0 §2 (`unmet_authentication_requirements`).

Deterministic decision table from (session state, prompt, max_age, hints, acr policy) to {silent, login, consent, register, error}.

**Acceptance tests**

- `prompt=none` without a usable session → redirect `login_required` without rendering UI; `prompt=none` combined with any other value → `invalid_request`.
- `prompt=login` forces re-authentication and updates `auth_time`; `max_age` exceeded forces re-authentication; ID token carries `auth_time` in both cases.
- `id_token_hint`: signature verified with our current or retired keys, `iss` ours, `aud` contains client; expired hints accepted within tenant grace; `sub` ≠ session user → `login_required` (or account chooser when tenant enables).
- `prompt=create` routes to registration when the tenant enables it; when disabled the tenant omits `create` from `prompt_values_supported` and the request fails with `invalid_request` (Prompt Create §4 leaves unsupported handling to the OP — documented choice).
- Essential `acr` (via `claims`) or `acr_values` that the tenant policy cannot satisfy → `unmet_authentication_requirements` redirect.
- Table-driven tests for every row of the decision table.

**Depends on:** E05_02, E06_07

### E05_09 — Signed request objects (JAR) inside PAR [optional]

*feature · P3 · labels: area:authz, spec:rfc9101, spec:rfc9126, spec:oidc-core, status:final*

**Spec:** RFC 9126 §3 (`request` parameter in PAR; `request_uri` by reference MUST NOT be used in PAR); RFC 9101 §4 (request object claims; `typ` oauth-authz-req+jwt), §6.1 (all parameters in the JWT; parameters outside are ignored except client auth), §6.3 (validation); OIDC Core §6.1 (`request` parameter), §6.3 (validation: iss=client_id, aud=issuer).

Optional non-repudiation hook (prerequisite for FAPI 2.0 Message Signing later — Implementer's Draft, tracked in E17). Off by default.

**Acceptance tests**

- `request` accepted only in the PAR body; `request_uri` in PAR → `invalid_request`.
- JWT must be signed (no `none`), `typ` `oauth-authz-req+jwt` required when tenant sets strict mode, alg = client's `request_object_signing_alg`, `iss` = client_id, `aud` = issuer (string), `exp` present and ≤ 10 min ahead.
- Parameters outside the JWT are ignored except client authentication parameters; `client_id` outside must equal `iss`.
- `request_parameter_supported: true` only when enabled.

**Depends on:** E05_01, E02_04

## E06 — Authentication, sessions & identity model  (P0, epic)

Server-rendered interaction engine, server-side sessions, passkeys as primary credential, Argon2id passwords, issuer-agnostic user/claims model, ACR/AMR policy & step-up, self-registration, abuse protection, account recovery.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E06_01 | Interaction engine & SSR page framework (CSRF, CSP nonce, no-JS) | feature | P0 | E01_04, E01_10, E15_03 |
| E06_02 | Server-side session management (`sid`, lifetimes, participating clients) | feature | P0 | E01_03, E06_01 |
| E06_03 | Passkey registration (WebAuthn L3 via webauthn-rs) | feature | P0 | E06_02, E06_06 |
| E06_04 | Passkey authentication (discoverable credentials, conditional UI as enhancement) | feature | P0 | E06_03 |
| E06_05 | Password authentication with Argon2id (secondary credential) | feature | P1 | E06_02, E06_06 |
| E06_06 | User & issuer-agnostic claims model (public/pairwise subjects) | feature | P0 | E01_03, E01_10 |
| E06_07 | ACR/AMR policy, `acr_values` processing & step-up authentication | feature | P1 | E06_04, E06_05 |
| E06_08 | Self-registration (`prompt=create`) & account self-service pages | feature | P2 | E06_03, E06_05 |
| E06_09 | Login abuse protection (rate limits, generic errors, no enumeration) | task | P1 | E06_04, E06_05 |
| E06_10 | Account recovery (email reset token, passkey re-enrolment) | feature | P2 | E06_06 |

### E06_01 — Interaction engine & SSR page framework (CSRF, CSP nonce, no-JS)

*feature · P0 · labels: area:authn, area:web, spec:oidc-core, spec:fapi2-sp, status:final*

**Spec:** OIDC Core §3.1.2.3 (authorization server authenticates end-user; MUST NOT interact if prompt=none), §3.1.2.4; FAPI 2.0 SP §5.2.3 (browser endpoints), §6.5 (browser-swapping: keep authorization response confidential); RFC 9700 §4 (clickjacking and open-redirector countermeasures — exact section number from memory, verify).

An `Interaction` (id ≥128 bits, bound to the PAR request and to a `__Host-asterius_ix` cookie) drives a state machine login → step-up → consent → response. askama templates with autoescape; per-response CSP nonce; synchroniser CSRF token per form; every page usable without JavaScript.

**Acceptance tests**

- Interaction id in path + `__Host-` cookie (Secure, HttpOnly, SameSite=Lax) must both match; mismatch → error page, interaction invalidated.
- Every POST form carries a CSRF token validated with `ct_eq`; missing/invalid → 403 page.
- Playwright no-JS test completes login (password) → consent → code redirect.
- Template snapshot tests prove untrusted values (client_name, state, login_hint) are escaped; no template uses `|safe` on request data.
- Error pages show a correlation id and a generic message; never echo `error_description` from request parameters.

**Depends on:** E01_04, E01_10, E15_03

### E06_02 — Server-side session management (`sid`, lifetimes, participating clients)

*feature · P0 · labels: area:authn, area:sessions, spec:oidc-core, spec:oidc-backchannel-logout, status:final*

**Spec:** OIDC Core §3.1.2.3; OpenID Connect Back-Channel Logout §2.1 (`backchannel_logout_session_supported`), §2.4 (`sid` claim in ID Token and Logout Token — section numbers as in the Final spec); OWASP ASVS V3 (session lifetime, rotation).

Sessions in PostgreSQL keyed by an opaque id (≥128 bits, hashed at rest) carried by `__Host-asterius_session`. Tracks user, auth_time, acr/amr, idle/absolute expiry, participating clients (for back-channel logout) and device summary.

**Acceptance tests**

- Session id rotated on login and on step-up; old id invalid immediately (test).
- Idle timeout and absolute lifetime per tenant; expired session → `login_required` for prompt=none.
- ID tokens carry `sid`; the session records every client that received an ID token in it.
- Revoke by id/user/admin; revoked session cannot be used for prompt=none; audit event and CAEP hook (E12_08).

**Depends on:** E01_03, E06_01

### E06_03 — Passkey registration (WebAuthn L3 via webauthn-rs)

*feature · P0 · labels: area:authn, area:passkeys, spec:webauthn, status:final*

**Spec:** W3C WebAuthn Level 3 §7.1 (registering a new credential: challenge, origin, RP ID, UV, attestation); FIDO Alliance passkey guidance (discoverable credentials).

RP ID = tenant host (configurable subdomain policy). Discoverable credentials requested, user verification required by default, attestation `none` unless tenant enables enterprise attestation with an AAGUID allowlist.

**Acceptance tests**

- Challenge ≥ 16 bytes, single-use, ≤ 5 min TTL, bound to the session/interaction.
- Origin and RP ID verified exactly; UV flag required when policy `uv=required`; failing either → registration rejected with generic error.
- Credential id uniqueness enforced across the tenant; backup-eligible/backup-state flags and sign count stored; user can name/rename/delete passkeys (account page E06_08).
- Without JavaScript the page shows the password/alternative path and an explanation (no dead end).
- Audit event + CAEP `credential-change` (create) emitted (E12_08).

**Depends on:** E06_02, E06_06

### E06_04 — Passkey authentication (discoverable credentials, conditional UI as enhancement)

*feature · P0 · labels: area:authn, area:passkeys, spec:webauthn, spec:rfc8176, status:final*

**Spec:** WebAuthn L3 §7.2 (verifying an authentication assertion: challenge, origin, rpIdHash, UP/UV flags, sign count); RFC 8176 (`amr` values: `hwk`, `swk`, `user`, `pin`); OIDC Core §2 (acr, amr, auth_time).

Username-less flow first (discoverable credential), username-first fallback. Conditional UI (autofill) is progressive enhancement only.

**Acceptance tests**

- Assertion validated per §7.2; sign-count regression flagged in audit and (policy) blocks the credential.
- `amr` set to [`hwk`|`swk`, `user`] (+`pin` when UV via PIN is reported) and `acr` mapped by tenant policy (E06_07); `auth_time` updated.
- Challenge single-use; failed attempts rate-limited per IP and per user (E06_09).
- No-JS fallback path exists; JS-enabled path adds passkeys and autofill.
- Integration test with a virtual authenticator (Playwright CDP) covers registration + login.

**Depends on:** E06_03

### E06_05 — Password authentication with Argon2id (secondary credential)

*feature · P1 · labels: area:authn, area:passwords, spec:rfc9106, status:final*

**Spec:** RFC 9106 (Argon2id parameters); OWASP Password Storage Cheat Sheet (Argon2id m=19 MiB, t=2, p=1 minimum); NIST SP 800-63B §5.1.1 (min 8 chars, allow ≥64, no composition rules, breach list check, Unicode NFKC).

Passwords are a secondary factor/legacy path; passkeys remain primary in UX. Argon2id with configurable parameters (floor enforced), transparent rehash, timing-equalised failure path, per-account/IP throttling.

**Acceptance tests**

- Parameters below the floor (m<19456 KiB, t<2) rejected at startup; rehash happens on next successful login after parameters increase (test).
- Unknown user path runs a dummy Argon2id verify so timing is indistinguishable (statistical test within tolerance).
- Password policy: length 8–128 after NFKC, no composition rules, deny top-N common list, optional breach-check port (no external call by default).
- Password change invalidates other sessions when tenant policy says so and emits CAEP `credential-change`.
- `amr: ["pwd"]`; acr per policy.

**Depends on:** E06_02, E06_06

### E06_06 — User & issuer-agnostic claims model (public/pairwise subjects)

*feature · P0 · labels: area:authn, area:identity, spec:oidc-core, spec:oidc-registration, status:final*

**Spec:** OIDC Core §5.1 (standard claims), §5.7 (claim stability and uniqueness: sub locally unique, never reassigned), §8 (subject identifier types public/pairwise), §8.1 (pairwise algorithm: sector identifier from `sector_identifier_uri` host or redirect_uri host; MUST NOT be reversible; salt), §5.6.2 (aggregated/distributed claims — schema readiness only); OIDC Registration §5 (sector_identifier_uri validation).

`users` (stable `sub`, status, tenant), `identifiers` (email/phone with `verified`), `claims` JSONB where every claim carries `value`, `source` (local|admin|import|<issuer>) and `verified_at` so future aggregated/verified claims fit without a schema change. Pairwise `sub` = base64url(SHA-256(sector || local_sub || tenant_salt)).

**Acceptance tests**

- `sub` is never reused after deletion (tombstone table + test).
- Pairwise: two clients with different sectors get different `sub`; same sector → same `sub`; salt rotation is impossible by design (documented).
- `sector_identifier_uri` fetched over https at registration time (OIDC Registration §5), must list all `redirect_uris` (and `jwks_uri`/`backchannel_client_notification_endpoint` for CIBA clients) else `invalid_client_metadata`.
- Standard claims (`name`, `email`, `email_verified`, `phone_number`, `address`, `locale`, `zoneinfo`, `updated_at` …) round-trip through the claims service with language tags (`name#ja-Kana-JP`).
- Admin CRUD for users and identifiers; account states active/disabled/locked drive `login_required`/error handling.

**Depends on:** E01_03, E01_10

### E06_07 — ACR/AMR policy, `acr_values` processing & step-up authentication

*feature · P1 · labels: area:authn, spec:oidc-core, spec:oidc-unmet-authn-req, spec:oidc-eap-acr, status:final*

**Spec:** OIDC Core §2 (acr/amr/auth_time semantics), §3.1.2.1 (acr_values: voluntary), §5.5.1.1 (essential acr via `claims`: 'MUST return an acr Claim' matching one of the requested values or fail), §3.1.2.3; Unmet Authentication Requirements 1.0 §2 (`unmet_authentication_requirements` when the OP cannot meet the requested acr); EAP ACR Values 1.0 (`phr`, `phrh` — Final, informational for naming).

Tenant policy: ordered ACR levels with the credential combinations that satisfy them (e.g., `urn:asterius:acr:passkey-uv` → passkey with UV; `phrh` mapping optional). Voluntary `acr_values` picks the highest achievable; essential picks exactly one of the requested or fails. Step-up reuses the session and re-authenticates with a stronger credential.

**Acceptance tests**

- Voluntary request for an unreachable acr proceeds with the achieved level and reports it in `acr` (Core §3.1.2.1).
- Essential acr not achievable → `unmet_authentication_requirements`; achievable → step-up prompt then ID token `acr` equals a requested value.
- `acr_values_supported` published from policy; `amr` always present in ID tokens (tenant-configurable).
- Step-up updates `auth_time`, `acr`, `amr` on the session and rotates the session id.

**Depends on:** E06_04, E06_05

### E06_08 — Self-registration (`prompt=create`) & account self-service pages

*feature · P2 · labels: area:authn, area:web, spec:oidc-prompt-create, status:final*

**Spec:** OpenID Connect Prompt Create 1.0 §3 (`prompt=create`), §4 (`prompt_values_supported`); OIDC Core §5.1 (email_verified semantics).

SSR registration with email verification (single-use ≥128-bit token, 15 min), then passkey enrolment. Account pages: passkeys (add/rename/remove), password (set/change), sessions (list/revoke), grants (list/revoke → E07_06).

**Acceptance tests**

- `prompt=create` lands on registration when enabled for the tenant; after success the interaction continues to consent.
- Email verification token hashed at rest, single-use, expires; unverified users cannot complete OIDC login when tenant requires verification.
- Removing the last passkey requires a password or re-auth; all changes audited and emit CAEP `credential-change`.
- Pages work without JavaScript except the passkey ceremony itself.

**Depends on:** E06_03, E06_05

### E06_09 — Login abuse protection (rate limits, generic errors, no enumeration)

*task · P1 · labels: area:authn, area:security*

**Spec:** NIST SP 800-63B §5.2.2 (rate limiting online guessing); OWASP ASVS V2.2; RFC 6749 §10.x (brute force on codes/tokens — informational).

Sliding-window limits per IP, per account and per tenant for login, passkey challenges, password reset, registration and email verification; generic error messages; audit of failures.

**Acceptance tests**

- Limits configurable; exceeding returns the same page with a generic message and a `Retry-After`-like hint; no difference between 'unknown user' and 'wrong password'.
- Registration and reset flows never reveal whether an email exists (same response either way).
- Metrics for throttled attempts.

**Depends on:** E06_04, E06_05

### E06_10 — Account recovery (email reset token, passkey re-enrolment)

*feature · P2 · labels: area:authn, area:passwords*

**Spec:** NIST SP 800-63B §6.1.2.3 (recovery); OWASP Forgot Password Cheat Sheet.

Email-based recovery producing a single-use ≥128-bit token (15 min, hashed at rest); on use, forces new credential set-up and invalidates other sessions; emits CAEP `credential-change`.

**Acceptance tests**

- Token single-use, expires, invalidated on password change; brute force limited (E06_09).
- Recovery flow works without JavaScript; audit trail complete.
- Notification port used (no built-in SMTP dependency in protocol crates).

**Depends on:** E06_06

## E07 — Consent, grants & Grant Management  (P1, epic)

Informed consent UI, explicit grant model linking every token to a revocable grant, consent memory and offline_access rules, Grant Management (Implementer's Draft 1, behind flag) request parameters and API, user-facing grants dashboard.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E07_01 | Consent screen (client identity, scopes, claims, RAR, resources; no JS) | feature | P0 | E06_01, E06_02 |
| E07_02 | Grant model & persistence (every token links to a revocable grant) | feature | P0 | E01_03, E03_01, E06_06 |
| E07_03 | Consent memory & offline_access / refresh-token consent rules | feature | P1 | E07_01, E07_02 |
| E07_04 | Grant Management authorization-request parameters (`grant_id`, `grant_management_action`) [flag: grant_management] | feature | P2 | E07_02, E05_01 |
| E07_05 | Grant Management API (GET/DELETE /grants/{grant_id}) + token-response `grant_id` + metadata | feature | P2 | E07_04, E08_08, E08_06 |
| E07_06 | User-facing grants dashboard (list & revoke standing consents) | feature | P2 | E07_02, E06_08 |

### E07_01 — Consent screen (client identity, scopes, claims, RAR, resources; no JS)

*feature · P0 · labels: area:consent, area:web, spec:oidc-core, spec:fapi2-sp, status:final*

**Spec:** OIDC Core §3.1.2.4 (obtain end-user consent/authorization); FAPI 2.0 SP §5.3.2.2 item 13 (provide all information for an informed decision: client identity and scope), §7 (privacy: client misidentification, insufficient understanding, inadequate choice); RFC 9396 §2 (render authorization details).

SSR consent page listing client name/URI (text only; logo only if uploaded to the IdP), scopes with tenant descriptions, requested claims, RAR items rendered by type template, target resources, offline access, and Approve/Deny. Deny is a first-class outcome.

**Acceptance tests**

- Page shows `client_name` and the redirect target's host; no remote assets are loaded (CSP `img-src 'self' data:`).
- Approve/Deny are plain form POSTs with CSRF; Deny → `access_denied` redirect (E05_04).
- Consent decision (scopes/claims/details actually granted, which may be a subset when tenant allows partial consent) is recorded on the grant with timestamp and audit event.
- Snapshot tests for the page in en/fr and for RAR rendering; no-JS Playwright test.

**Depends on:** E06_01, E06_02

### E07_02 — Grant model & persistence (every token links to a revocable grant)

*feature · P0 · labels: area:consent, spec:oauth-grant-management, spec:fapi2-sp, status:impl-draft*

**Spec:** Grant Management for OAuth 2.0 ID1 (draft-03) §5.6 'Lifecycle of the grant' (active once tokens claimed; delete unclaimed after timeout; AS may modify); FAPI 2.0 SP §6.8 item 4 (record relationships between credentials issued for the same authorization so they can be revoked together).

`grants` row: tenant, client, user (null for client_credentials), scopes, claims, authorization_details, resources, status (pending|active|revoked|expired), created_at, last_updated_at, expires_at, updated_by. Codes, refresh tokens, access-token jti and device/CIBA requests reference `grant_id`.

**Acceptance tests**

- Every token issuance path (code, refresh, client_credentials, token exchange, device, CIBA) requires a `grant_id` (compile-time non-optional).
- Revoking a grant marks refresh tokens revoked and inserts their access-token jti into the denylist until `exp` (introspection returns `active:false`).
- Unclaimed grants (no token issued) are garbage-collected after tenant timeout.
- Single active default grant per (client,user) unless Grant Management `create` action is used (E07_04) — concurrent grants supported by schema.

**Depends on:** E01_03, E03_01, E06_06

### E07_03 — Consent memory & offline_access / refresh-token consent rules

*feature · P1 · labels: area:consent, spec:oidc-core, status:final*

**Spec:** OIDC Core §11 (Offline Access: `offline_access` scope; 'MUST ignore the offline_access request unless the Client is using a response_type value that would result in an Authorization Code being returned'; OP 'MUST obtain explicit consent' — prompt=consent expected unless other conditions), §3.1.2.4.

Skip the consent screen when the user previously granted a superset for this client (and prompt≠consent); always show it when new scopes/claims/details/resources are requested or when `offline_access` is requested for the first time.

**Acceptance tests**

- Previously granted scopes → no consent prompt; any new scope/claim/RAR/resource → prompt limited to the delta (tenant option: full re-consent).
- `prompt=consent` always prompts; `prompt=none` with missing consent → `consent_required`.
- `offline_access` without explicit consent (prompt=consent or first-time consent screen shown) → refresh token not issued and scope omitted from the response.
- Tenant switch 'always ask' honoured; consent records visible in audit and grants dashboard.

**Depends on:** E07_01, E07_02

### E07_04 — Grant Management authorization-request parameters (`grant_id`, `grant_management_action`) [flag: grant_management]

*feature · P2 · labels: area:consent, spec:oauth-grant-management, status:impl-draft, flag:grant_management*

**Spec:** Grant Management for OAuth 2.0 ID1 (2023-07-10, draft-03) §5.1 (confidential clients only), §5.2 (`grant_id`; `grant_management_action` = create | merge | replace; merge/replace 'shall invalidate existing refresh tokens'), §5.3 (no change to authorization response), §5.4 (errors: `invalid_grant_id`; `invalid_request` when grant_id with create, action missing with grant_id, unsupported action, or action required but absent), §7.1 (`grant_management_action_required`). Status: Implementer's Draft — isolated behind a flag and a thin port so spec churn is cheap.

Parameters accepted in PAR and CIBA requests; semantics applied at consent/grant persistence time.

**Acceptance tests**

- `grant_management_action=create` with `grant_id` → `invalid_request`; `grant_id` without action → `invalid_request`; unsupported action → `invalid_request`.
- Unknown `grant_id`, grant of another client, or grant whose user ≠ authenticated user → `invalid_grant_id`.
- `merge` unions permissions and revokes the grant's existing refresh tokens; `replace` sets permissions exactly and revokes existing refresh tokens; both keep the same `grant_id`.
- Tenant `grant_management_action_required=true` → requests without the action fail `invalid_request`; metadata reflects it.
- With the flag off, both parameters are ignored and metadata omits `grant_management_*`.

**Depends on:** E07_02, E05_01

### E07_05 — Grant Management API (GET/DELETE /grants/{grant_id}) + token-response `grant_id` + metadata

*feature · P2 · labels: area:consent, spec:oauth-grant-management, status:impl-draft, flag:grant_management*

**Spec:** Grant Management ID1 §5.5 (token response `grant_id` MUST be returned when a valid action was requested), §6.1 (scopes `grant_management_query`, `grant_management_revoke`), §6.2 (https endpoint; `grant_management_endpoint`), §6.3 (resource URL = endpoint + '/' + grant_id), §6.4 (query response: scopes[{scope,resource}], claims, authorization_details, created_at, last_updated_at, expires_at, updated_by; no tokens exposed), §6.5 (DELETE → 204; 'MUST revoke the grant and all refresh tokens'; should revoke access tokens), §6.6 (404 unknown, 403 unauthorized, 401 `invalid_token`), §7.1 (`grant_management_actions_supported`, `grant_management_endpoint`, `grant_management_action_required`).

Access with a DPoP-bound client_credentials access token carrying the query/revoke scope and `aud` = grant management resource; only the owning client can address a grant.

**Acceptance tests**

- `GET` returns the §6.4 JSON for the caller's own grant; a `grant_id` belonging to another client → 404 (unknown resource URL from the caller's perspective); valid token without the `grant_management_query` scope → 403; missing/invalid token → 401 `invalid_token` — tests for all three.
- `DELETE` → 204; grant status revoked; refresh tokens revoked; access-token jti denylisted (we implement the SHOULD as MUST); repeat DELETE → 404.
- Token responses include `grant_id` when an action was supplied; never in authorization responses.
- Metadata: `grant_management_actions_supported: ["query","revoke","create","merge","replace"]`, `grant_management_endpoint`, `grant_management_action_required`.
- Grant revocation emits an audit event and a domain event consumed by SSF (E12_08).

**Depends on:** E07_04, E08_08, E08_06

### E07_06 — User-facing grants dashboard (list & revoke standing consents)

*feature · P2 · labels: area:consent, area:web, differentiator:agents*

**Spec:** Grant Management ID1 §3 (dashboards use case); OIDC Core §3.1.2.4; FAPI 2.0 SP §7 (privacy).

Account page listing active grants per client/agent with scopes, RAR summaries, resources, last use, delegation chains issued from the grant; one-click revoke with the same semantics as E07_05.

**Acceptance tests**

- Lists only the signed-in user's grants; revoke requires CSRF + re-auth when tenant policy says so.
- Revoke cascades exactly like the API; audit event; page works without JS.
- Agent grants show the agent owner and last token exchange.

**Depends on:** E07_02, E06_08

## E08 — Token endpoint, token formats & sender-constraining  (P0, epic)

Token endpoint framework, authorization_code grant, JWT access tokens (RFC 9068), ID tokens, refresh tokens without rotation (FAPI 2.0), DPoP (mandatory), optional mTLS-bound tokens, client_credentials, fuzz/conformance.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E08_01 | Token endpoint framework & client-authentication dispatch | feature | P0 | E03_02, E01_04 |
| E08_02 | authorization_code grant (PKCE, redirect_uri, DPoP-key binding, replay) | feature | P0 | E08_01, E05_04, E05_03, E08_03, E08_04, E08_06 |
| E08_03 | JWT access token profile (RFC 9068, `at+jwt`, always audience- and sender-bound) | feature | P0 | E02_01, E07_02 |
| E08_04 | ID Token issuance (claims, nonce, auth_time, acr/amr, sid, at_hash, pairwise sub) | feature | P0 | E02_01, E09_04 |
| E08_05 | Refresh tokens: opaque, grant-bound, no rotation (FAPI 2.0), revocable | feature | P0 | E08_02, E07_03 |
| E08_06 | DPoP (RFC 9449): proof validation, jkt binding, nonce, `dpop_jkt` in PAR, metadata | feature | P0 | E02_04, E08_01, E02_06 |
| E08_07 | Certificate-bound access tokens (RFC 8705 §3) [flag: mtls] | feature | P2 | E03_03, E08_03 |
| E08_08 | client_credentials grant (service & agent tokens, sender-constrained, audience-bound) | feature | P1 | E08_01, E08_06, E05_07 |
| E08_09 | Token endpoint fuzz targets & FAPI 2.0 conformance sweep | chore | P1 | E08_02, E08_05, E01_08 |

### E08_01 — Token endpoint framework & client-authentication dispatch

*feature · P0 · labels: area:token, spec:rfc6749, spec:oidc-core, status:final*

**Spec:** RFC 6749 §3.2 (token endpoint: POST, TLS, client auth), §3.2.1, §4.1.3, §5.1 (success: `Cache-Control: no-store`, `Pragma: no-cache`), §5.2 (errors invalid_request, invalid_client (401 + WWW-Authenticate when header auth attempted), invalid_grant, unauthorized_client, unsupported_grant_type, invalid_scope); OIDC Core §3.1.3 (token endpoint), §3.1.3.4 (token error response); RFC 6750 §3.

One handler that authenticates the client (E03_02/E03_03), validates the DPoP proof when present (E08_06), parses `grant_type` and dispatches to grant handlers enabled by feature flags and the client's `grant_types`.

**Acceptance tests**

- Non-POST or non-`application/x-www-form-urlencoded` → 400 `invalid_request`; duplicate parameter → `invalid_request` (RFC 6749 §3.2: 'Request and response parameters MUST NOT be included more than once').
- Grant type not enabled for the client → `unauthorized_client`; unknown → `unsupported_grant_type`.
- Every success response has `Cache-Control: no-store` and `Pragma: no-cache`; JSON errors with `error`, optional `error_description` (ASCII-only), never stack traces.
- Parsing is total (never panics) — fuzz target `token_form`; property test that unknown parameters are ignored.

**Depends on:** E03_02, E01_04

### E08_02 — authorization_code grant (PKCE, redirect_uri, DPoP-key binding, replay)

*feature · P0 · labels: area:token, spec:rfc6749, spec:oidc-core, spec:rfc7636, spec:rfc9449, status:final*

**Spec:** RFC 6749 §4.1.3 (grant_type=authorization_code, code, redirect_uri REQUIRED if included in the authorization request, client_id), §4.1.4; OIDC Core §3.1.3.1 (token request), §3.1.3.2 (validation: authenticate client, code issued to this client, code not used, redirect_uri identical), §3.1.3.3 (successful response: access_token, token_type, refresh_token, expires_in, id_token); RFC 7636 §4.6; RFC 9449 §10 ('Authorization Code Binding to DPoP Key': `dpop_jkt` must match the proof key at the token endpoint); RFC 8707 §2.2; FAPI 2.0 SP §5.3.2.1 item 12, §5.3.2.2 item 9.

Redeem a code for tokens. All bindings recorded at issuance (E05_04) are checked here.

**Acceptance tests**

- Code unknown/expired/other client → `invalid_grant`; `redirect_uri` not byte-identical to the PAR value → `invalid_grant`.
- PKCE verifier mismatch → `invalid_grant`; code bound to `dpop_jkt` and proof thumbprint differs or proof absent → `invalid_grant`; code issued without `dpop_jkt` still requires a DPoP proof (all ATs sender-constrained).
- Second use → `invalid_grant` and revocation of the tokens from the first use (E05_04).
- Response: `access_token` (E08_03), `token_type: "DPoP"` (or `Bearer` only for mTLS-bound tokens), `expires_in`, `id_token` when `openid` scope (E08_04), `refresh_token` per E08_05, `scope` when it differs from the request, `authorization_details` when RAR, `grant_id` when Grant Management.
- FAPI2 conformance token-endpoint tests pass.

**Depends on:** E08_01, E05_04, E05_03, E08_03, E08_04, E08_06

### E08_03 — JWT access token profile (RFC 9068, `at+jwt`, always audience- and sender-bound)

*feature · P0 · labels: area:token, spec:rfc9068, spec:rfc9449, spec:rfc8693, spec:fapi2-sp, status:final*

**Spec:** RFC 9068 §2.1 (header `typ: at+jwt`), §2.2 (claims iss, exp, aud, sub, client_id, iat, jti REQUIRED), §2.2.1 (auth_time, acr, amr), §2.2.3 (scope, groups/roles/entitlements), §4 (validation rules for RS — informs tests), §5 (security: aud restriction, no sensitive data); RFC 9449 §6.1 (`cnf.jkt`); RFC 8705 §3 (`cnf.x5t#S256`); RFC 8693 §4.1 (`act`); RFC 9396 §8.1 (`authorization_details`); FAPI 2.0 SP §5.3.2.1 item 4 (only sender-constrained access tokens), item 14 (least privilege), §6.1 (short-lived access tokens), §5.4.1.

Signed (EdDSA default) self-contained access tokens; opaque reference tokens are out of scope (KISS). Lifetime default 300 s, tenant/resource cap 900 s.

**Acceptance tests**

- Header `{alg, kid, typ: "at+jwt"}`; claims `iss`, `sub` (user sub or `client_id` for client_credentials), `aud` (non-empty; resource identifiers), `client_id`, `iat`, `exp`, `jti` (≥128 bits), `scope`, `cnf` (`jkt` or `x5t#S256` — REQUIRED, a token without `cnf` cannot be built), optional `auth_time`/`acr`/`amr`, `authorization_details`, `act`, `grant_id` (private claim, tenant option).
- `exp - iat` ≤ 900 s enforced by the builder; ID-token-only claims (nonce, at_hash) never appear; no PII beyond `sub` unless resource policy opts in.
- Serialised token ≤ 4 KiB by default (guard); property test on builder invariants.
- Verification helper for resource servers (`asterius-rs` crate or docs) implements RFC 9068 §4 and DPoP §7 checks — used by UserInfo (E09_03) and introspection (E09_01).

**Depends on:** E02_01, E07_02

### E08_04 — ID Token issuance (claims, nonce, auth_time, acr/amr, sid, at_hash, pairwise sub)

*feature · P0 · labels: area:token, spec:oidc-core, status:final*

**Spec:** OIDC Core §2 (ID Token claims: iss, sub, aud, exp, iat REQUIRED; auth_time, nonce, acr, amr, azp), §3.1.3.6 (ID Token from token endpoint; at_hash OPTIONAL in code flow), §3.1.3.7 (validation rules the client applies — drive our tests), §5.4/§5.5 (claims in the ID Token via scopes/`claims`), §10.1 (signing; `alg` per `id_token_signed_response_alg`; `none` forbidden here), §15.1 (mandatory to implement), §8.1 (pairwise sub); Back-Channel Logout §2.3 (remembering logged-in RPs) and §2.4 (`sid` in ID Token and Logout Token).

Built after grant/claims resolution (E09_04). Signed with the client's `id_token_signed_response_alg` (default EdDSA). Explicit `typ: JWT` header.

**Acceptance tests**

- Claims: `iss` = tenant issuer, `sub` (public/pairwise per client), `aud` = client_id string, `exp` (default 300 s), `iat`, `auth_time` (always), `nonce` echoed byte-exact when supplied, `acr`, `amr`, `azp` = client_id, `sid`, `at_hash` (present for code flow as a defensive extra), plus requested claims.
- Signature alg ∈ allow-list; `none` and HS* impossible; `kid` present; verifies against JWKS in a test using an independent JWT library.
- Refresh-token-issued ID tokens carry the same `sub`/`auth_time` (Core §12.2) and no `nonce` unless original.
- Conformance `oidcc` ID-token checks (as run inside the FAPI2 plan) pass.

**Depends on:** E02_01, E09_04

### E08_05 — Refresh tokens: opaque, grant-bound, no rotation (FAPI 2.0), revocable

*feature · P0 · labels: area:token, spec:rfc6749, spec:oidc-core, spec:rfc9449, spec:fapi2-sp, status:final*

**Spec:** RFC 6749 §1.5, §6 (refresh request: grant_type=refresh_token, refresh_token, scope ⊆ original), §10.4; OIDC Core §12.1–12.3 (refresh: ID Token MAY be returned; `sub` MUST match; new nonce not required); FAPI 2.0 SP §5.3.2.1 item 9 ('shall not use refresh token rotation except in extraordinary circumstances'), Note 1, §6.1 (long-lived grants → short ATs + RTs); RFC 9449 §5 (refresh tokens for public clients bound to DPoP key; confidential clients: new AT bound to the proof key presented); RFC 9700 §4.14 (refresh token protection: sender-constrained or rotation — we use client authentication + optional key binding).

Opaque ≥256-bit refresh tokens stored as SHA-256 digests with grant, client, scopes, absolute and idle expiry. No rotation by default; a time-boxed rotation mode exists only for migrations (FAPI Note 1) and offers the old token for retry within a grace window.

**Acceptance tests**

- Refresh request requires client authentication and a DPoP proof; the new access token's `cnf.jkt` is the presented proof key; tenant option `bind_refresh_to_dpop_key` rejects a different key (`invalid_grant`).
- Requested `scope` ⊄ granted → `invalid_scope`; narrowing allowed; `openid` present → new ID token with same `sub` and `auth_time`.
- Same refresh token value returned unchanged (no rotation) by default; migration mode issues a new token and accepts the old one for `grace_seconds` (test both).
- Revoked grant/session-linked policy → `invalid_grant`; absolute lifetime and idle lifetime enforced; audit events on refresh.
- FAPI2 conformance refresh-token tests pass.

**Depends on:** E08_02, E07_03

### E08_06 — DPoP (RFC 9449): proof validation, jkt binding, nonce, `dpop_jkt` in PAR, metadata

*feature · P0 · labels: area:token, spec:rfc9449, spec:fapi2-sp, status:final*

**Spec:** RFC 9449 §4.1 (`DPoP` header), §4.2 (proof JWT: typ dpop+jwt, alg asymmetric ≠ none, jwk public key; claims jti, htm, htu, iat, nonce, ath), §4.3 (checking: exactly one header; parse; typ; alg; signature with jwk; jti replay; htm/htu match; iat window; nonce), §5 (token request: `token_type: DPoP`; error `invalid_dpop_proof`), §6.1 (`cnf.jkt` = JWK thumbprint RFC 7638), §8 (AS-provided nonce: `use_dpop_nonce` 400 + `DPoP-Nonce` header), §10.1 (`dpop_jkt` authorization request parameter), §10.2 (in PAR), §11 (`dpop_signing_alg_values_supported`), §12 (`dpop_bound_access_tokens`), §13 (security: htu normalisation, replay); FAPI 2.0 SP §5.3.2.1 items 4–5 (sender-constrained via DPoP), 10 (nonce MAY), 12 (must support code binding to DPoP key), 13 (skew).

Proof validation middleware for token, PAR (dpop_jkt correlation), UserInfo, introspection (optional), grant-management, SSF-management and AuthZEN endpoints. Replay store in PostgreSQL keyed by (tenant, jkt, jti) with TTL = iat window.

**Acceptance tests**

- Two `DPoP` headers → `invalid_dpop_proof`/`invalid_request`; missing `typ`/wrong `typ`, `alg` outside {ES256, EdDSA, PS256}, symmetric alg, `jwk` containing private members → `invalid_dpop_proof`.
- `htm` must equal the request method; `htu` compared after normalising scheme/host case and stripping query/fragment; mismatch → `invalid_dpop_proof`.
- `iat` outside [now−300 s, now+10 s] → reject (window configurable ≤ 60 s future); `jti` replay → reject.
- Tenant `dpop_nonce=required`: missing/stale nonce → 400 `use_dpop_nonce` + fresh `DPoP-Nonce`; nonces are HMAC-derived, valid 5 min, no storage.
- `dpop_jkt` accepted in PAR and stored on the code; token request proof key must match (E08_02).
- Issued tokens: `token_type: "DPoP"`, `cnf.jkt` = RFC 7638 thumbprint; metadata `dpop_signing_alg_values_supported`.
- Fuzz target `dpop_proof`; FAPI2 conformance DPoP tests pass; test vectors from RFC 9449 §4.2 reproduced.

**Depends on:** E02_04, E08_01, E02_06

### E08_07 — Certificate-bound access tokens (RFC 8705 §3) [flag: mtls]

*feature · P2 · labels: area:token, spec:rfc8705, spec:fapi2-sp, status:final, flag:mtls*

**Spec:** RFC 8705 §3 (mutual-TLS certificate-bound access tokens), §3.1 (`cnf` `x5t#S256`), §3.2 (introspection), §3.3 (AS metadata `tls_client_certificate_bound_access_tokens`), §3.4 (client metadata `tls_client_certificate_bound_access_tokens`), §5 (`mtls_endpoint_aliases`); FAPI 2.0 SP §5.3.2.1 item 5.

When the client is registered with `tls_client_certificate_bound_access_tokens: true` and presents a certificate at the token endpoint, bind the access token to it instead of DPoP.

**Acceptance tests**

- `cnf: {"x5t#S256": <thumbprint>}` in AT; `token_type: Bearer`; introspection exposes `cnf`.
- UserInfo/introspection verify the presented certificate thumbprint against `cnf` (E09_03 hook).
- A token request that presents both a client certificate for binding and a DPoP proof is ambiguous → `invalid_request` (documented; a client registers exactly one binding method).
- Flag off → metadata omits `tls_client_certificate_bound_access_tokens`.

**Depends on:** E03_03, E08_03

### E08_08 — client_credentials grant (service & agent tokens, sender-constrained, audience-bound)

*feature · P1 · labels: area:token, spec:rfc6749, spec:rfc8707, spec:rfc9449, status:final, differentiator:agents*

**Spec:** RFC 6749 §4.4 (client credentials grant; §4.4.3 refresh token SHOULD NOT be included); RFC 8707 §2.2; RFC 9449 §5; FAPI 2.0 SP §5.3.2.1 items 4, 14; RFC 9068 §2.2 (`sub` = client_id for client-only tokens).

Used by resource servers, admin automation, SSF receivers, AuthZEN PEPs and AI agents acting on their own behalf.

**Acceptance tests**

- Only clients with `client_credentials` in `grant_types`; scope ⊆ client's allowed scopes else `invalid_scope`; `resource` required or defaults (E05_07) else `invalid_target`.
- DPoP proof (or mTLS) required → `invalid_request`/`invalid_dpop_proof` otherwise; AT has `sub` = `client_id`, `cnf`, `aud`.
- No refresh token; a synthetic grant row (client-only) is created for audit/revocation.
- Audit event includes agent profile fields when the client is an agent (E11_01).

**Depends on:** E08_01, E08_06, E05_07

### E08_09 — Token endpoint fuzz targets & FAPI 2.0 conformance sweep

*chore · P1 · labels: area:token, area:conformance*

**Spec:** Project DoD; FAPI 2.0 SP conformance plan.

Ensure the parser-coverage gate is satisfied for the token endpoint family and run the FAPI2 plan end to end.

**Acceptance tests**

- Fuzz targets: `token_form`, `client_assertion`, `dpop_proof`, `pkce` run 10 min nightly without findings.
- FAPI2 SP plan: token endpoint, PKCE, DPoP, refresh, client-auth sections all green.

**Depends on:** E08_02, E08_05, E01_08

## E09 — Introspection, revocation, UserInfo & claims resolution  (P1, epic)

RFC 7662 introspection restricted to authorized callers, RFC 7009 revocation with grant semantics, DPoP-protected UserInfo, and the scope/claims resolution service used by ID tokens and UserInfo.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E09_01 | Token introspection endpoint (RFC 7662) for registered resource servers | feature | P1 | E08_03, E03_02 |
| E09_02 | Token revocation endpoint (RFC 7009) with grant-aware semantics | feature | P1 | E08_05, E03_02 |
| E09_03 | UserInfo endpoint (DPoP-bound access tokens, JSON or signed JWT) | feature | P1 | E08_03, E08_06, E09_04 |
| E09_04 | Claims resolution service (scopes → claims, `claims` parameter, placement, i18n) | feature | P1 | E06_06 |

### E09_01 — Token introspection endpoint (RFC 7662) for registered resource servers

*feature · P1 · labels: area:token, spec:rfc7662, spec:rfc9449, status:final*

**Spec:** RFC 7662 §2.1 (POST `token`, `token_type_hint`; caller MUST be authorized), §2.2 (response: `active` REQUIRED; scope, client_id, username, token_type, exp, iat, nbf, sub, aud, iss, jti), §2.3 (errors; unauthorized → 401), §4 (security: only authorized protected resources; token scanning), §2.2 note (`active:false` for any token the caller may not learn about); RFC 9449 §6.2 (`cnf` in introspection); RFC 8693 §4 (act/scope/client_id in introspection).

Callers authenticate with private_key_jwt/mTLS and must be registered as a resource server (or the client that owns the token). JWT access tokens are verified locally and checked against the jti denylist and grant status.

**Acceptance tests**

- Caller not a resource server for the token's `aud` and not the token's client → `active:false` (not an error), constant response time.
- Active response includes `scope`, `client_id`, `sub`, `aud`, `iss`, `exp`, `iat`, `jti`, `token_type`, `cnf`, `authorization_details`, `act`, `grant_id` (private).
- Revoked (grant, jti denylist) or expired → `active:false`; refresh tokens introspectable only by their client.
- Rate limited per caller; audit event on every call with outcome; `introspection_endpoint_auth_methods_supported` published.

**Depends on:** E08_03, E03_02

### E09_02 — Token revocation endpoint (RFC 7009) with grant-aware semantics

*feature · P1 · labels: area:token, spec:rfc7009, status:final*

**Spec:** RFC 7009 §2.1 (POST `token`, `token_type_hint`; client authentication; the AS MUST NOT return an error if the token is invalid), §2.2 (200 on success; 'the client MUST NOT be able to revoke a token issued to another client' → treat as invalid), §2.2.1 (`unsupported_token_type`); RFC 6749 §10.4; Grant Management ID1 §6.5 Note (token revocation need not revoke the underlying grant).

Revoke a refresh token (and, by tenant policy, all access tokens of its grant) or a single access token (jti denylist until exp). The grant itself stays intact unless policy says otherwise (allows re-connect without consent).

**Acceptance tests**

- Refresh token of the authenticated client → revoked, related access tokens denylisted (policy default on); token of another client or unknown → 200 with no action.
- Access token → `jti` denylisted until `exp`; introspection reflects it immediately.
- Unknown `token_type_hint` value → ignore hint (RFC 7009 §2.1) and still succeed; malformed request → 400 `invalid_request`.
- Audit event; `revocation_endpoint_auth_methods_supported` published.

**Depends on:** E08_05, E03_02

### E09_03 — UserInfo endpoint (DPoP-bound access tokens, JSON or signed JWT)

*feature · P1 · labels: area:userinfo, spec:oidc-core, spec:rfc6750, spec:rfc9449, spec:fapi2-sp, status:final*

**Spec:** OIDC Core §5.3.1 (GET/POST with access token; `openid` scope), §5.3.2 (response: `sub` REQUIRED and MUST match; JSON `application/json` or signed/encrypted JWT `application/jwt` per `userinfo_signed_response_alg`, with `iss`/`aud` in JWT form), §5.3.3 (errors per RFC 6750: `invalid_token` 401, `insufficient_scope` 403), §5.3.4, §5.4 (scope → claims), §5.5 (claims parameter), §5.2 (language tags); RFC 6750 §3 (`WWW-Authenticate: Bearer` … error attributes); RFC 9449 §7.1 (`Authorization: DPoP` + proof with `ath`), §7.2 (RS nonce optional); FAPI 2.0 SP §5.3.4 (RS: accept tokens in header only; never in query; verify validity, revocation, sender-constraint).

The IdP's own resource server; reuses the RS verification helper (E08_03).

**Acceptance tests**

- `Authorization: DPoP <at>` + valid proof with `ath` = SHA-256(at) → 200; Bearer scheme accepted only for mTLS-bound tokens with matching certificate; token in query string → 400/401 and never processed.
- Missing/invalid token → 401 `WWW-Authenticate: DPoP error="invalid_token"` (and `Bearer` challenge listed); scope without `openid` → 403 `insufficient_scope`.
- `sub` always present and equal to the ID token's `sub` for that client (pairwise aware); claims limited to granted scopes/claims from the grant, not the current user state beyond what was consented.
- `userinfo_signed_response_alg` set → `application/jwt` with `iss`, `aud`; alg from allow-list; `userinfo_signing_alg_values_supported` published.
- Revoked/denylisted tokens → `invalid_token`; conformance UserInfo tests pass.

**Depends on:** E08_03, E08_06, E09_04

### E09_04 — Claims resolution service (scopes → claims, `claims` parameter, placement, i18n)

*feature · P1 · labels: area:userinfo, spec:oidc-core, spec:oidc-discovery, status:final*

**Spec:** OIDC Core §5.1 (standard claims), §5.2 (claims languages and scripts: `#` language tag suffix; `claims_locales`), §5.4 (scope values profile/email/address/phone/offline_access), §5.5 (`claims` request parameter: `userinfo` and `id_token` members; `essential`, `value`, `values`; 'MUST NOT return claims the user did not consent to'; unknown claims ignored), §5.5.1 (individual claims requests), §5.5.1.1 (acr), §5.6.1 (normal claims); Discovery §3 (`claims_supported`, `claims_parameter_supported`, `claims_locales_supported`).

Pure function from (grant, user claims store, request `claims`, `claims_locales`) to (id_token claims, userinfo claims). Tenant-configurable scope→claim mapping with OIDC defaults.

**Acceptance tests**

- `profile`/`email`/`address`/`phone` map to the Core §5.4 claim sets; unknown scopes ignored (or `invalid_scope` when tenant is strict).
- `claims` parameter: `essential:true` claims that are unavailable do not fail the request (Core §5.5.1) except `acr` handling (E06_07); `value`/`values` honoured for `acr` only unless tenant policy extends.
- Claims never exceed the consented set (test: grant with `email` only never yields `name`).
- Language-tagged claims returned per `claims_locales` order with untagged fallback; `claims_supported` generated from the mapping.
- Property test: output claims ⊆ (consented ∪ {sub}); JSON canonical shape.

**Depends on:** E06_06

## E10 — Logout & session lifecycle  (P1, epic)

RP-Initiated Logout, Back-Channel Logout (Final specs), admin/user session revocation with propagation, and an ADR that Session Management/Front-Channel Logout are not in v1.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E10_01 | RP-Initiated Logout (`end_session_endpoint`) | feature | P1 | E06_02, E08_04 |
| E10_02 | Back-Channel Logout (Logout Token `logout+jwt`, delivery via outbox) | feature | P1 | E06_02, E02_01, E12_09 |
| E10_03 | Session revocation by admin/user with propagation (back-channel logout + CAEP) | feature | P1 | E10_02, E14_01 |
| E10_04 | Decision: no Session Management (check_session_iframe) and no Front-Channel Logout in v1 | decision | P3 | E01_09 |

### E10_01 — RP-Initiated Logout (`end_session_endpoint`)

*feature · P1 · labels: area:logout, spec:oidc-rp-initiated-logout, status:final*

**Spec:** OpenID Connect RP-Initiated Logout 1.0 (Final, 2022-09) §2 (parameters id_token_hint, logout_hint, client_id, post_logout_redirect_uri, ui_locales, state; OP asks the End-User whether to log out when the request cannot be verified), §2.1 (`end_session_endpoint` metadata), §3 (redirection: 'MUST NOT perform post-logout redirection' without id_token_hint unless other means confirm legitimacy, and only when `post_logout_redirect_uri` exactly matches a registered value; redirection happens after RPs are notified), §3.1 (client metadata `post_logout_redirect_uris`), §4 (validation and error handling: id_token_hint signature/iss/aud; expired ID Tokens accepted as hints).

GET/POST endpoint; terminates the OP session, triggers back-channel logout (E10_02) for participating clients, then redirects or shows a logged-out page.

**Acceptance tests**

- Valid `id_token_hint` (our signature incl. retired keys, `iss`, `aud` contains client; `exp` ignored) identifies the client; `client_id` if present must match; mismatch → confirmation page without RP branding.
- `post_logout_redirect_uri` is honoured only when the RP is identified (id_token_hint, or client_id confirmed by tenant policy) and the value exactly matches a registered `post_logout_redirect_uris` entry (§3); otherwise the neutral logged-out page is shown; `state` echoed only on redirect.
- No `id_token_hint` → confirmation page ('Log out of <tenant>?') before any session change (spec MUST for unidentified RP).
- Session terminated, cookie cleared, back-channel logout notifications sent before the post-logout redirect (§3); 303 redirect; audit + CAEP `session-revoked`.
- `end_session_endpoint` in metadata; conformance `oidcc-rp-initiated-logout` style checks pass where compatible.

**Depends on:** E06_02, E08_04

### E10_02 — Back-Channel Logout (Logout Token `logout+jwt`, delivery via outbox)

*feature · P1 · labels: area:logout, spec:oidc-backchannel-logout, status:final*

**Spec:** OpenID Connect Back-Channel Logout 1.0 incorporating errata set 1 (Final, 2023-12) §2.1 (OP metadata `backchannel_logout_supported`, `backchannel_logout_session_supported`), §2.2 (client metadata `backchannel_logout_uri`, `backchannel_logout_session_required`), §2.3 (remembering logged-in RPs), §2.4 (Logout Token: `iss`, `sub` and/or `sid`, `aud`, `iat`, `exp`, `jti`, `events` = {"http://schemas.openid.net/event/backchannel-logout": {}}; `typ` `logout+jwt`; MUST NOT contain `nonce`), §2.5 (request: POST `logout_token` form param; retransmit only on potentially recoverable errors, with delay), §2.6 (RP validation steps 1–11 — drive tests), §2.7 (RP actions), §2.8 (response: 200/204 success, 400 on invalid token), §4.1 (cross-JWT confusion → explicit typ).

On session termination, for each participating client with `backchannel_logout_uri`, enqueue a Logout Token signed with the client's ID-token alg and POST it with retries.

**Acceptance tests**

- Logout Token contains `iss`, `aud`=client_id, `iat`, `exp` (≤ 2 min), `jti`, `events`, `sid` and `sub` (or only `sid` when `backchannel_logout_session_required` and pairwise privacy policy says so), `typ: logout+jwt`, and never `nonce` (schema test).
- Delivery: POST `application/x-www-form-urlencoded` `logout_token=…`, timeout 5 s, TLS verify, no redirects followed, retries with backoff for 5xx/timeouts, give up after N with audit.
- Refresh tokens bound to the session (tenant policy `revoke_refresh_on_logout`) revoked.
- Metadata flags true; a test RP (in the test suite) validates the token per §2.6.
- Conformance back-channel logout tests pass where compatible.

**Depends on:** E06_02, E02_01, E12_09

### E10_03 — Session revocation by admin/user with propagation (back-channel logout + CAEP)

*feature · P1 · labels: area:logout, area:sessions*

**Spec:** Back-Channel Logout §2.5; CAEP 1.0 §3.1 (session-revoked); product requirement (continuous access).

Admin API / console and account page can revoke one, many or all sessions of a user; propagation reuses E10_02 and E12_08.

**Acceptance tests**

- Revoking N sessions produces N back-channel logout deliveries per participating client and N CAEP `session-revoked` events (or one complex-subject event per session).
- Revocation reason recorded (`initiating_entity`: admin|user|policy|system) and surfaced in CAEP `reason_admin`.
- Idempotent; audit events.

**Depends on:** E10_02, E14_01

### E10_04 — Decision: no Session Management (check_session_iframe) and no Front-Channel Logout in v1

*decision · P3 · labels: adr, area:logout, spec:oidc-session, spec:oidc-frontchannel-logout*

**Spec:** OpenID Connect Session Management 1.0 (iframe + postMessage; depends on third-party cookies); OpenID Connect Front-Channel Logout 1.0 (iframes rendered in the OP page).

Both mechanisms require iframes/JavaScript and third-party cookies that browsers now block, and conflict with the strict CSP / no-JS baseline. Back-channel logout + CAEP session-revoked cover the need. Recommendation: not planned; `frontchannel_logout_supported` absent; ADR documents how to add later if a customer needs it.

**Acceptance tests**

- ADR merged; metadata omits `check_session_iframe` and `frontchannel_logout_supported`.

**Depends on:** E01_09

## E11 — AI-agent-native authorization  (P2, epic)

Agent client profile, RFC 8693 token exchange with delegation chains, device flow and CIBA (poll/ping) for human-in-the-loop approval, approvals inbox, MCP compatibility profile for confidential clients, per-agent audit trail, pre-issuance policy hook.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E11_01 | Agent client profile & policy (owner, key, allowed grants/audiences/RAR types, delegation limits) | feature | P2 | E03_01, E03_06 |
| E11_02 | Token Exchange (RFC 8693) with delegation chains (`act`), narrowing-only | feature | P2 | E08_01, E08_06, E08_03, E11_01 |
| E11_03 | Device Authorization Grant (RFC 8628) for confidential agents/devices | feature | P2 | E08_01, E08_06, E06_01, E07_01 |
| E11_04 | CIBA backchannel authentication endpoint (poll/ping only) | feature | P2 | E11_07, E03_02, E06_06 |
| E11_05 | CIBA token delivery: poll & ping (`urn:openid:params:grant-type:ciba`) | feature | P2 | E11_04, E08_01, E08_06, E12_09 |
| E11_06 | Approvals inbox: human-in-the-loop approval UX for CIBA, device flow and agent step-ups | feature | P2 | E11_04, E11_03, E06_04 |
| E11_07 | CIBA & device-flow metadata and client-registration validation | feature | P2 | E03_01, E04_03 |
| E11_08 | MCP authorization compatibility profile (confidential MCP clients & MCP resource servers) | feature | P2 | E04_01, E04_02, E05_07, E03_04, E03_08 |
| E11_09 | Per-agent audit trail & query API (delegation chains end-to-end) | feature | P2 | E01_11, E11_02 |
| E11_10 | Pre-issuance policy port (AuthZEN-backed decisions before minting agent tokens) | feature | P3 | E13_01, E11_01 |

### E11_01 — Agent client profile & policy (owner, key, allowed grants/audiences/RAR types, delegation limits)

*feature · P2 · labels: area:agents, area:clients, differentiator:agents*

**Spec:** RFC 7591 §2 (client metadata + extension fields); FAPI 2.0 SP §6.6 (client impersonating resource owner: client_id must not look like a subject identifier); RFC 8693 §5 (security considerations for delegation).

`client_kind = agent` with owner (user or org), mandatory `private_key_jwt` + `jwks`, allowed grant types ⊆ {client_credentials, token-exchange, device_code, ciba}, allowed audiences and scopes, allowed RAR types, `max_delegation_depth`, token TTL caps, and human-approval requirements per scope/RAR type. A DCR policy preset (E03_06) creates agents with these constraints.

**Acceptance tests**

- Agent registration without `jwks`/`jwks_uri` or with a redirect-based grant type not allowed by the preset → `invalid_client_metadata`.
- Agent `client_id` format is random and distinct from user `sub` format (test asserts no overlap in format).
- Every issuance for an agent carries `agent_owner`, `agent_id` in the audit event (E11_09).
- Policy stored as data, validated by schema, editable in console (E14_05).

**Depends on:** E03_01, E03_06

### E11_02 — Token Exchange (RFC 8693) with delegation chains (`act`), narrowing-only

*feature · P2 · labels: area:agents, area:token, spec:rfc8693, status:final, differentiator:agents, flag:token_exchange*

**Spec:** RFC 8693 §2.1 (request: grant_type urn:ietf:params:oauth:grant-type:token-exchange, resource, audience, scope, requested_token_type, subject_token, subject_token_type REQUIRED, actor_token, actor_token_type), §2.2.1 (response: access_token, issued_token_type REQUIRED, token_type, expires_in, scope, refresh_token), §2.2.2 (error: invalid_request/invalid_grant; invalid_target for unacceptable resource/audience), §3 (token type identifiers), §4.1 (`act` claim; nested chains; most recent actor outermost), §4.4 (`may_act`), §5 (security: delegation vs impersonation policy), §6 (privacy).

Agents obtain a token to act *for* a user (delegation, `act` chain) or, when policy explicitly allows, *as* a user (impersonation, no `act`). Subject tokens: our access tokens or ID tokens; actor token optional (defaults to the authenticated client). Every exchange narrows: scope ⊆ subject scope ∩ actor allowed; aud ⊆ allowed; TTL ≤ subject remaining.

**Acceptance tests**

- `subject_token_type` ∈ {urn:ietf:params:oauth:token-type:access_token, …:id_token, …:jwt}; token must be issued by us, unexpired, unrevoked, and (for access tokens) sender-constrained to the presented DPoP key or explicitly marked exchangeable by policy; otherwise `invalid_grant`.
- Delegation default: issued AT contains `act: {client_id: <agent>, act?: <previous chain>}`; chain depth > `max_delegation_depth` → `invalid_request`; impersonation only when client policy `impersonation=true`.
- `may_act` in the subject token, when present, must authorize the actor (`invalid_grant` otherwise).
- Requested `scope`/`audience`/`resource` that widen the subject token → `invalid_scope`/`invalid_target`; `requested_token_type` other than access_token → `invalid_request` (v1).
- Response: `issued_token_type`, `token_type: DPoP`, `expires_in`, `scope`; no refresh token in v1.
- Audit event records the full chain; introspection exposes `act`; fuzz target `token_exchange_form`.

**Depends on:** E08_01, E08_06, E08_03, E11_01

### E11_03 — Device Authorization Grant (RFC 8628) for confidential agents/devices

*feature · P2 · labels: area:agents, area:token, spec:rfc8628, status:final, differentiator:agents, flag:device_flow*

**Spec:** RFC 8628 §3.1 (device authorization request: client_id/auth, scope), §3.2 (response: device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval), §3.3 (user interaction; §3.3.1 non-textual), §3.4 (token request grant_type urn:ietf:params:oauth:grant-type:device_code), §3.5 (errors authorization_pending, slow_down (+5 s), access_denied, expired_token), §4 (`device_authorization_endpoint`), §5.1 (user code brute forcing: entropy + rate limiting), §5.2 (device code brute forcing), §5.3 (remote phishing: show client identity, warn), §5.4 (session spying), §6.1 (user code recommendations: case-insensitive, unambiguous alphabet, e.g. 8 chars ≈ 34.5 bits with base-20 alphabet); FAPI 2.0 SP §5.3.2.1 item 3 (confidential clients only → client authentication required at the device authorization endpoint; documented deviation from typical public-client usage).

For CLI agents/headless devices. Approval happens in the approvals inbox (E11_06) after passkey authentication.

**Acceptance tests**

- Device authorization endpoint requires client authentication (private_key_jwt/mTLS); response `device_code` ≥ 128 bits (stored hashed), `user_code` 8 chars from `BCDFGHJKLMNPQRSTVWXZ` formatted `XXXX-XXXX`, `expires_in` ≤ 600, `interval` = 5, `verification_uri_complete` with the code.
- Token endpoint polling: faster than `interval` → `slow_down` and interval += 5 for that device_code; pending → `authorization_pending`; expired → `expired_token`; denied → `access_denied`; wrong client → `invalid_grant`; DPoP proof required and AT bound to it.
- Verification page: SSR, no JS needed, shows client name + scopes/RAR + phishing warning, rate-limits user_code attempts (≤ 5 per IP per 10 min, code invalidated after 10 failures); approval requires an authenticated session at the required acr.
- Single redemption of `device_code`; grant created on approval; audit + agent fields.
- Metadata `device_authorization_endpoint` and grant type only when flag on.

**Depends on:** E08_01, E08_06, E06_01, E07_01

### E11_04 — CIBA backchannel authentication endpoint (poll/ping only)

*feature · P2 · labels: area:agents, area:authn, spec:oidc-ciba, status:final, differentiator:agents, flag:ciba*

**Spec:** OpenID Connect CIBA Core 1.0 (Final, 2021-09-01) §7 (endpoint MUST use TLS), §7.1 (authentication request: client auth per registered method — for JWT client assertions the OP 'MUST accept its Issuer Identifier, Token Endpoint URL, or Backchannel Authentication Endpoint URL' as aud; parameters scope (MUST contain openid), client_notification_token (REQUIRED for ping/push; ≤1024 chars; ≥128 bits), acr_values, login_hint_token, id_token_hint, login_hint, binding_message, user_code, requested_expiry; exactly one hint REQUIRED), §7.1.1 (signed authentication request: all params in JWT; aud = issuer, iss = client_id, exp, iat, nbf, jti; no params outside), §7.1.2 (user code), §7.2 (validation steps 1–6; ignore unrecognised parameters), §7.3 (ack: auth_req_id ≥128 bits, charset A-Za-z0-9.-_; expires_in; interval for poll/ping), §13 (errors: invalid_request, invalid_scope, expired_login_hint_token, unknown_user_id, unauthorized_client, missing_user_code, invalid_user_code, invalid_binding_message; 401 invalid_client; 403 access_denied); FAPI-CIBA profile (Final) — push mode not permitted.

`POST /t/{tenant}/bc-authorize`. Creates a pending authentication request that surfaces in the user's approvals inbox / notification channel.

**Acceptance tests**

- Client without CIBA grant type or with `backchannel_token_delivery_mode=push` → `unauthorized_client` (push rejected at registration too).
- Zero or more than one hint → `invalid_request`; `login_hint` resolves to a user (email/username policy) else `unknown_user_id`; `id_token_hint` verified (our signature, aud contains client; expired accepted within grace) and its `sub` resolved; `login_hint_token` accepted only when signed by a configured issuer (§14) else `invalid_request`.
- `scope` must contain `openid` → else `invalid_scope`; `binding_message` ≤ 64 chars printable ASCII/Unicode letters+digits+spaces per tenant policy → else `invalid_binding_message`; `user_code` policy: required for user when enabled → `missing_user_code`/`invalid_user_code`.
- Ping mode requires `client_notification_token` (≤1024 chars, stored hashed) → else `invalid_request`.
- Signed requests: `request` JWT validated per §7.1.1 with alg = registered `backchannel_authentication_request_signing_alg`; any authentication parameter outside the JWT → `invalid_request`.
- 200 `{auth_req_id (≥128 bits, charset), expires_in (≤ requested_expiry, ≤ tenant max 300), interval}`; RAR/Grant Management params accepted (E05_06, E07_04).
- Client-assertion `aud` accepts the three §7.1 values at this endpoint only (E03_02 note); fuzz target `ciba_form`.

**Depends on:** E11_07, E03_02, E06_06

### E11_05 — CIBA token delivery: poll & ping (`urn:openid:params:grant-type:ciba`)

*feature · P2 · labels: area:agents, area:token, spec:oidc-ciba, status:final, flag:ciba*

**Spec:** CIBA Core §10 (single registered delivery mode), §10.1 (token request: grant_type ciba, auth_req_id; 'MUST check whether the auth_req_id was issued to this Client'; polling not more frequent than `interval`; long polling optional; 503 + Retry-After under load), §10.1.1 (successful response per OIDC Core §3.1.3.3; auth_req_id no longer valid after redemption), §10.2 (ping callback: POST JSON {auth_req_id} with `Authorization: Bearer <client_notification_token>`; client SHOULD answer 204; OP MUST NOT follow redirects), §11 (errors authorization_pending, slow_down (+5 s), expired_token, access_denied; invalid_grant when auth_req_id invalid/other client; invalid_request when polling too fast; unauthorized_client for push clients).

Poll: token endpoint grant handler. Ping: outbox job posts the callback after the user decides, then the client polls once.

**Acceptance tests**

- `auth_req_id` unknown/other client → `invalid_grant`; pending → `authorization_pending`; polled faster than interval → `slow_down` (interval += 5) and after repeated abuse `invalid_request` (client must stop); expired → `expired_token`; denied → `access_denied`.
- Approved → tokens per E08_02 shape (ID token, DPoP-bound AT, refresh token only with `offline_access` consent); `auth_req_id` single redemption.
- Ping callback: JSON body `{auth_req_id}`, bearer = client_notification_token, timeout 5 s, TLS verify, no redirects, 2xx accepted, failures retried with backoff then audited; sent after success and after denial (§10.2: 'after a successful or failed end-user authentication'), not on expiry.
- DPoP proof required at token endpoint; audit events with agent fields.

**Depends on:** E11_04, E08_01, E08_06, E12_09

### E11_06 — Approvals inbox: human-in-the-loop approval UX for CIBA, device flow and agent step-ups

*feature · P2 · labels: area:agents, area:web, spec:oidc-ciba, spec:rfc8628, status:final, differentiator:agents*

**Spec:** CIBA Core §8 (OP identifies the user, authenticates on the authentication device, 'MUST obtain an authorization decision as described in Section 3.1.2.4 of OpenID Core'), §7.1 (binding_message displayed on both devices), §14 (security: login_hint_token signed); RFC 8628 §3.3, §5.3 (show client identity, warn).

SSR page `/account/approvals` listing pending requests (CIBA, device, agent scope elevation) with client/agent identity, binding_message or user_code, scopes/RAR/resources, expiry countdown (no JS required), Approve/Deny. Notification port (email/push adapters) informs the user.

**Acceptance tests**

- Approve requires a fresh passkey authentication (≤ 120 s) at the acr demanded by the request; otherwise step-up first.
- `binding_message` rendered prominently and escaped; user_code entry page for device flow shares this inbox.
- Approve/Deny are CSRF-protected POSTs; result feeds E11_05/E11_03 state machines; audit events.
- Expired requests disappear; a request cannot be approved twice.

**Depends on:** E11_04, E11_03, E06_04

### E11_07 — CIBA & device-flow metadata and client-registration validation

*feature · P2 · labels: area:agents, area:discovery, spec:oidc-ciba, spec:rfc8628, status:final, flag:ciba, flag:device_flow*

**Spec:** CIBA Core §4 (OP metadata: backchannel_token_delivery_modes_supported REQUIRED, backchannel_authentication_endpoint REQUIRED, backchannel_authentication_request_signing_alg_values_supported, backchannel_user_code_parameter_supported; grant type in grant_types_supported; client metadata: backchannel_token_delivery_mode REQUIRED, backchannel_client_notification_endpoint REQUIRED (https) for ping/push, backchannel_authentication_request_signing_alg, backchannel_user_code_parameter; pairwise + poll/ping requires jwks_uri/sector_identifier_uri); RFC 8628 §4 (`device_authorization_endpoint`).

Wire the capability registry and the client validator for both flows.

**Acceptance tests**

- Metadata (flags on): `backchannel_token_delivery_modes_supported: ["poll","ping"]`, endpoint URL, signing algs, `backchannel_user_code_parameter_supported`, grant types include CIBA and device_code; `device_authorization_endpoint`.
- Client validation: CIBA grant requires `backchannel_token_delivery_mode` ∈ {poll, ping}; ping requires https `backchannel_client_notification_endpoint`; `push` → `invalid_client_metadata`; pairwise + CIBA requires `jwks_uri` listed in `sector_identifier_uri` (or `jwks_uri` host as sector).
- Flags off → nothing advertised and grant types rejected at registration.

**Depends on:** E03_01, E04_03

### E11_08 — MCP authorization compatibility profile (confidential MCP clients & MCP resource servers)

*feature · P2 · labels: area:agents, spec:mcp, spec:rfc8414, spec:rfc8707, spec:rfc9728, differentiator:agents*

**Spec:** MCP Authorization (2025-11-25): AS MUST provide RFC 8414 or OIDC Discovery (clients try path-inserted RFC 8414, path-inserted OIDC, path-appended OIDC); OIDC discovery MUST include `code_challenge_methods_supported`; AS MUST validate exact redirect URIs; clients MUST send `resource` (RFC 8707) in authorization and token requests; AS SHOULD issue short-lived ATs; MCP servers MUST implement RFC 9728 with `authorization_servers` and validate `aud`; DCR MAY; CIMD SHOULD (IETF draft → track per E03_08).

Make a FAPI-compliant Asterius tenant usable by MCP clients that are confidential (DCR with `jwks` → private_key_jwt, PAR, PKCE S256, DPoP) and document the resource-server side.

**Acceptance tests**

- End-to-end test with an MCP client library configured for confidential mode: discovery at all three URL forms → DCR (policy preset `mcp-confidential`) → PAR → code → DPoP token with `aud` = MCP server canonical URI → introspection/JWT validation sample passes.
- `scopes_supported` present; `resource` mismatch → `invalid_target`; canonical URI comparison rules from MCP spec tested (trailing slash, uppercase host).
- Docs: 'MCP servers with Asterius' — RFC 9728 document example (`authorization_servers`, `scopes_supported`, `bearer_methods_supported`), `WWW-Authenticate` 401 example with `resource_metadata`, RFC 9068 + DPoP validation checklist, `insufficient_scope` step-up example.
- `client_id_metadata_document_supported` absent; ADR E03_08 referenced in docs.

**Depends on:** E04_01, E04_02, E05_07, E03_04, E03_08

### E11_09 — Per-agent audit trail & query API (delegation chains end-to-end)

*feature · P2 · labels: area:agents, area:audit, differentiator:agents*

**Spec:** RFC 8693 §4.1 (act chain semantics); FAPI 2.0 SP §6.8 item 4 (credential linking); product requirement.

Extend E01_11 events with `agent_id`, `agent_owner`, `act_chain`, `grant_id`, `authorization_details` summary, `resource`, `approval_id` (CIBA/device). Query API with filters and NDJSON export; console explorer (E14_08).

**Acceptance tests**

- For a chain user → agent A → agent B, the query 'everything done under user U' returns issuance, exchange and introspection events for A and B with the chain intact.
- Filters: agent, owner, user, grant, time range, event type; pagination; export ≤ 100k rows streaming.
- Retention per tenant; PII minimised (hashed IP/UA).

**Depends on:** E01_11, E11_02

### E11_10 — Pre-issuance policy port (AuthZEN-backed decisions before minting agent tokens)

*feature · P3 · labels: area:agents, area:authzen, differentiator:agents*

**Spec:** Authorization API 1.0 §6 (evaluation request shape); RFC 6749 §5.2 (`access_denied`, `invalid_scope`).

`IssuancePolicy` port consulted for agent clients: subject = agent (+ owner), action = `obtain_token`/`exchange_token`, resource = {audience, scope, authorization_details}, context = {grant, chain depth}. Default adapter = internal PDP (E13); decisions cached briefly; deny → `access_denied` with audit.

**Acceptance tests**

- Policy deny blocks issuance for client_credentials, token exchange, device and CIBA grants for agents; allow path adds ≤ 5 ms p95 with the in-process PDP.
- PDP unavailable → fail closed for agents (configurable), audited.
- Decision reason captured in audit (`reason_admin`).

**Depends on:** E13_01, E11_01

## E12 — Continuous access: Shared Signals Framework / CAEP transmitter  (P2, epic)

SSF 1.0 / CAEP 1.0 / RISC 1.0 (all Final, Sept 2025) transmitter: configuration metadata, SET profile, stream management, push and poll delivery, verification/stream-updated events, CAEP/RISC emitters fed by domain events through a transactional outbox.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E12_01 | SSF Transmitter Configuration Metadata (`/.well-known/ssf-configuration`) | feature | P2 | E01_10, E02_02, E04_03 |
| E12_02 | SET issuance profile (SSF §4): explicit typing, subjects, single event, txn | feature | P2 | E02_01 |
| E12_03 | Stream Configuration endpoint (create/read/update/replace/delete) | feature | P2 | E12_01, E08_08 |
| E12_04 | Stream Status & Subjects endpoints (add/remove, matching rules) | feature | P2 | E12_03 |
| E12_05 | Verification event & Stream Updated event | feature | P2 | E12_04, E12_02 |
| E12_06 | Push delivery (RFC 8935) via outbox worker | feature | P2 | E12_02, E12_09, E12_03 |
| E12_07 | Poll delivery (RFC 8936) endpoint with acknowledgement | feature | P2 | E12_02, E12_09, E12_03 |
| E12_08 | CAEP/RISC event emitters (session-revoked, credential-change, assurance-level-change, account-disabled/enabled) | feature | P2 | E12_02, E12_06, E12_07, E06_02 |
| E12_09 | Transactional outbox & delivery worker (no Redis) | task | P2 | E01_03 |

### E12_01 — SSF Transmitter Configuration Metadata (`/.well-known/ssf-configuration`)

*feature · P2 · labels: area:ssf, spec:openid-ssf, status:final, flag:ssf*

**Spec:** SSF 1.0 §7.1 (metadata: spec_version, issuer REQUIRED (https, no query/fragment, identical to SET `iss`), jwks_uri (REQUIRED when signing; https), delivery_methods_supported, configuration_endpoint, status_endpoint, add_subject_endpoint, remove_subject_endpoint, verification_endpoint (all https), critical_subject_members, authorization_schemes [{spec_urn}], default_subjects ALL|NONE), §7.2 (well-known path inserted between host and path; application/json), §7.2.3 (200 + JSON), §7.2.4 (validation: issuer identical).

Per-tenant transmitter identity = tenant issuer; JWKS shared with the OP (SET signing keys may be the same purpose or a dedicated one — decide in E02_03).

**Acceptance tests**

- `GET /.well-known/ssf-configuration/t/{tenant}` (and host form) returns JSON with `spec_version: "1_0"`, `issuer` = tenant issuer, `jwks_uri`, `delivery_methods_supported: ["urn:ietf:rfc:8935","urn:ietf:rfc:8936"]`, all five management endpoints, `authorization_schemes: [{"spec_urn":"urn:ietf:rfc:6749"}]`, `default_subjects: "NONE"`.
- All URLs https; flag off → 404 and no metadata.
- Golden-file test; issuer validation test (metadata issuer equals fetch URL base).

**Depends on:** E01_10, E02_02, E04_03

### E12_02 — SET issuance profile (SSF §4): explicit typing, subjects, single event, txn

*feature · P2 · labels: area:ssf, spec:openid-ssf, spec:rfc8417, spec:rfc9493, status:final, flag:ssf*

**Spec:** SSF 1.0 §3.1 (top-level `sub_id` MUST describe the primary subject; existing CAEP/RISC events MAY also use `subject` inside the event, but `sub_id` MUST still be present), §3.2–3.3 (simple and complex subjects: user, device, session, application, tenant, org_unit, group), §3.4–3.5 (RFC 9493 formats + jwt_id, saml_assertion_id, ip-addresses), §4.1.1 (`typ: secevent+jwt` MUST), §4.1.2 (`sub` claim MUST NOT be present), §4.1.6 (`iss` MUST match stream `iss`), §4.1.7 (`exp` MUST NOT be used), §4.1.8 (`aud`), §4.1.9 (`txn` SHOULD; unique per underlying event), §4.2.1 (`events` SHOULD contain only one event); RFC 8417 §2.

`SetBuilder` enforcing the profile and signing with the tenant key (EdDSA/ES256).

**Acceptance tests**

- Builder cannot produce a SET with `sub` or `exp`, without `typ: secevent+jwt`, without `sub_id`, or with two different event types (compile-time API + unit tests).
- `iss` = tenant issuer; `aud` = stream audience; `jti` ≥ 128 bits; `iat`; `txn` set and shared across SETs from the same cause.
- Subjects: `iss_sub` (using the pairwise `sub` the receiver knows when the receiver client is pairwise), `email`, `opaque`, complex {user, session, device, tenant}.
- Independent JWT library verifies produced SETs against the JWKS; property tests on builder invariants.

**Depends on:** E02_01

### E12_03 — Stream Configuration endpoint (create/read/update/replace/delete)

*feature · P2 · labels: area:ssf, spec:openid-ssf, status:final, flag:ssf*

**Spec:** SSF 1.0 §8 (management API MUST use standard HTTP auth; authorization MUST associate a receiver with stream ids/aud), §8.1.1 (stream configuration: stream_id, iss, aud (immutable), events_supported, events_requested, events_delivered (⊆ supported ∩ requested; receiver relies on it), delivery {method, endpoint_url, authorization_header}, min_verification_interval, description, inactivity_timeout), §8.1.1.1 (POST → 201; 409 when multiple streams unsupported; default delivery poll with transmitter-supplied endpoint_url; 400 unsupported method), §8.1.1.2 (GET with/without stream_id → object or list; `Cache-Control: no-store`), §8.1.1.3 (PATCH: stream_id required; only receiver-supplied properties change; transmitter-supplied must match), §8.1.1.4 (PUT: full receiver-supplied set; missing = delete), §8.1.1.5 (DELETE → 204); error tables (400/401/403/404).

Receivers are registered clients holding a DPoP-bound client_credentials token with scope `ssf.manage` and `aud` = SSF management resource. One stream per receiver per audience by default (409 otherwise) — tenant option for multiple.

**Acceptance tests**

- POST without `delivery` → poll stream with transmitter-generated `endpoint_url`; push requires https `endpoint_url`; unsupported method → 400.
- Response objects contain all §8.1.1 fields; `events_delivered` = supported ∩ requested; unknown requested events ignored.
- PATCH/PUT semantics per spec (tests: transmitter-supplied field with wrong value → 400; missing receiver field in PUT → deleted; PATCH missing → unchanged).
- GET without stream_id lists the caller's streams (possibly `[]`); foreign stream_id → 404.
- DELETE → 204 and pending events dropped; audit events for all changes.

**Depends on:** E12_01, E08_08

### E12_04 — Stream Status & Subjects endpoints (add/remove, matching rules)

*feature · P2 · labels: area:ssf, spec:openid-ssf, status:final, flag:ssf*

**Spec:** SSF 1.0 §8.1.2 (status enabled|paused|disabled; paused MUST NOT transmit and SHOULD hold, ordering per subject; disabled drops), §8.1.2.1 (GET status → {stream_id, status, reason}), §8.1.2.2 (POST status → 200 or 202 when undecided), §8.1.3 (subjects), §8.1.3.1 (subject matching: simple = identical; complex = each member undefined on either side or identical), §8.1.3.2 (add subject: POST {stream_id, subject, verified} → 200; MAY silently ignore; 404/403/429), §8.1.3.3 (remove subject → 204), §9.1 (subject probing: prefer 200/204 even when unknown), §9.3 (tolerate events after removal).

Status transitions and subject membership per stream; `default_subjects: NONE` means only added subjects receive events (E12_01).

**Acceptance tests**

- Status POST changes state; `paused` holds events in a bounded per-stream queue with per-subject ordering; `disabled` drops; re-enable flushes held events.
- Add subject returns 200 for unknown subjects (no probing leak) but records nothing; remove returns 204 similarly.
- Matching tests from §8.1.3.1 examples (less restrictive, more restrictive, mismatch) pass.
- 429 with `Retry-After` when a receiver exceeds add/remove rate limits.

**Depends on:** E12_03

### E12_05 — Verification event & Stream Updated event

*feature · P2 · labels: area:ssf, spec:openid-ssf, status:final, flag:ssf*

**Spec:** SSF 1.0 §8.1.4 (verification: event type https://schemas.openid.net/secevent/ssf/event-type/verification; `state` echoed; `sub_id` MUST be opaque = stream_id), §8.1.4.2 (POST verification endpoint {stream_id, state} → 204; 429 under `min_verification_interval`; asynchronous transmission allowed), §8.1.5 (stream-updated: type …/stream-updated with `status`, `reason`; MUST be sent before pausing/disabling and upon re-enabling; `sub_id` opaque stream_id).

Both events bypass `events_requested` filtering (spec allows) and go through the normal outbox delivery.

**Acceptance tests**

- Verification request → 204, SET queued with the exact `state`, `sub_id: {format: opaque, id: <stream_id>}`; second request within `min_verification_interval` → 429.
- Transmitter-initiated pause/disable emits stream-updated *before* the state change takes effect on delivery; re-enable emits it again.
- Receiver test harness validates both SETs per §8.1.4/§8.1.5 examples.

**Depends on:** E12_04, E12_02

### E12_06 — Push delivery (RFC 8935) via outbox worker

*feature · P2 · labels: area:ssf, spec:rfc8935, spec:openid-ssf, status:final, flag:ssf*

**Spec:** RFC 8935 §2.1 (POST SET with `Content-Type: application/secevent+jwt`, `Accept: application/json`), §2.2 (success 202; SETs MUST be transmitted one at a time), §2.3 (failure: 400 with JSON `err`/`description`; `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`, `authentication_failed`, `access_denied`), §2.4 (retries for 5xx/timeouts; do not retry on 4xx except 429/503); SSF 1.0 §6.1.1 (push: `endpoint_url` receiver-supplied; `authorization_header` MUST be sent with every request when provided).

Outbox worker (E12_09) delivers each SET individually, in order per subject, with exponential backoff and a dead-letter state visible in the console.

**Acceptance tests**

- Request has `Content-Type: application/secevent+jwt`, body = compact SET, `Authorization` = configured header; TLS verify; no redirects; timeout 10 s.
- 202 → delivered; 400 with `err` → recorded, no retry (except `invalid_key` triggers a JWKS refresh hint in audit); 429/503/5xx/timeouts → retry with backoff up to a bounded budget then dead-letter + stream status `paused` with reason.
- Ordering test: two events for the same subject are delivered in generation order even with retries.
- Metrics per stream: delivered, failed, queue depth.

**Depends on:** E12_02, E12_09, E12_03

### E12_07 — Poll delivery (RFC 8936) endpoint with acknowledgement

*feature · P2 · labels: area:ssf, spec:rfc8936, spec:openid-ssf, status:final, flag:ssf*

**Spec:** RFC 8936 §2.1–2.2 (poll request JSON: `maxEvents`, `returnImmediately`, `ack` [jti…], `setErrs`), §2.3 (response: `sets` {jti: SET}, `moreAvailable`), §2.4 (acknowledgement removes SETs; unacknowledged SETs are redelivered; error reporting via `setErrs`; long polling when `returnImmediately` is false — subsection numbers from memory, verify); SSF 1.0 §6.1.2 (poll `endpoint_url` transmitter-supplied, unique per stream per receiver); §7.1.1 (authorization_schemes SHOULD protect the polling endpoint).

Per-stream poll endpoint protected with the receiver's DPoP-bound access token.

**Acceptance tests**

- Unacked SETs are returned again on the next poll; `ack` removes them; `setErrs` recorded in audit and the SET is not redelivered (policy).
- `maxEvents` honoured (cap 100); `moreAvailable` correct; `returnImmediately:false` waits ≤ 30 s for a new event then returns empty.
- Wrong stream/receiver → 404/403; token without `ssf.poll` scope → 403 `insufficient_scope`.
- Interoperability test against a reference receiver implementation (test-suite RP).

**Depends on:** E12_02, E12_09, E12_03

### E12_08 — CAEP/RISC event emitters (session-revoked, credential-change, assurance-level-change, account-disabled/enabled)

*feature · P2 · labels: area:ssf, spec:openid-caep, spec:openid-risc, status:final, flag:ssf*

**Spec:** CAEP 1.0 (Final) §2 (optional event claims common to all events: `event_timestamp` (seconds since epoch), `initiating_entity` admin|user|policy|system, `reason_admin`, `reason_user` — localized objects), §3.1 (session-revoked: no event-specific claims; complex subject {user, session, device, tenant} applies to matching sessions), §3.3 (credential-change: `credential_type` (password|pin|x509|fido2-platform|fido2-roaming|fido-u2f|verifiable-credential|phone-voice|phone-sms|app), `change_type` create|revoke|update|delete, `friendly_name`, `x509_issuer`, `x509_serial`, `fido2_aaguid`), §3.4 (assurance-level-change: `namespace`, `current_level`, `previous_level`, `change_direction` increase|decrease); RISC 1.0 (Final) account-disabled (`reason` hijacking|bulk-account), account-enabled; SSF 1.0 §3.1.1 (existing CAEP/RISC events MAY carry `subject` inside the event but `sub_id` MUST be present). Section numbers per the Final markdown structure — re-check against the published HTML while implementing.

Domain events (logout, admin/user session revoke, passkey add/remove/rename, password set/change/reset, step-up, account disable/enable — grant revocation has no CAEP event type and stays audit-only) map to SETs, filtered by stream subjects/events_requested, and enqueued.

**Acceptance tests**

- Each emitter produces a SET matching the CAEP/RISC JSON schemas (golden tests per event type) with `event_timestamp` (OPTIONAL in CAEP 1.0 §2 — we always include it, seconds since epoch) and `sub_id`.
- Session revocation → `session-revoked` with complex subject {user: iss_sub, session: opaque sid}; passkey creation → `credential-change` {credential_type: fido2-platform|fido2-roaming, change_type: create, fido2_aaguid}.
- Step-up from password to passkey → `assurance-level-change` with tenant namespace and levels; admin disable → RISC `account-disabled`.
- Events are only queued for streams whose `events_requested` includes the type and whose subjects match (E12_04); `txn` shared across SETs from one cause.
- SSF conformance/interoperability checks with the OpenID SSF test tooling pass for implemented events (where available).

**Depends on:** E12_02, E12_06, E12_07, E06_02

### E12_09 — Transactional outbox & delivery worker (no Redis)

*task · P2 · labels: area:ssf, area:foundation*

**Spec:** Product architecture decision (single binary, one PostgreSQL, no Redis until measured need).

`outbox` table written in the same transaction as the domain change; worker claims rows with `SELECT … FOR UPDATE SKIP LOCKED`, delivers (SSF push, back-channel logout, CIBA ping, notifications), records attempts, applies backoff and dead-lettering. Per-key ordering (stream+subject, client+session).

**Acceptance tests**

- Crash between DB commit and delivery never loses an event (test kills worker mid-delivery; event delivered after restart; receiver sees at-least-once with same `jti`).
- Ordering per key preserved under concurrency (property test with N workers).
- Backoff schedule and max attempts configurable; dead-letter visible via admin API; metrics.
- Throughput ≥ 500 deliveries/s on reference hardware without Redis.

**Depends on:** E01_03

## E13 — AuthZEN Policy Decision Point (Authorization API 1.0)  (P2, epic)

Authorization API 1.0 (Final, 2026-01-12) PDP: access evaluation and evaluations endpoints, PDP metadata, a policy-engine port with a built-in declarative engine over IdP data (users, groups, grants, RAR), optional search APIs.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E13_01 | Access Evaluation endpoint (`POST /access/v1/evaluation`) | feature | P2 | E13_04, E08_08 |
| E13_02 | Access Evaluations (boxcar) endpoint with `evaluations_semantic` options | feature | P2 | E13_01 |
| E13_03 | PDP metadata (`/.well-known/authzen-configuration`) | feature | P2 | E13_01, E04_03 |
| E13_04 | PolicyEngine port + built-in declarative engine over IdP data | feature | P2 | E06_06, E07_02, E13_05 |
| E13_05 | Decision: policy language for the built-in PDP (declarative rules vs Cedar vs external OPA) | decision | P2 | E01_09 |
| E13_06 | Search APIs (subject/resource/action) with pagination [optional] | feature | P3 | E13_04 |

### E13_01 — Access Evaluation endpoint (`POST /access/v1/evaluation`)

*feature · P2 · labels: area:authzen, spec:openid-authzen, status:final, flag:authzen*

**Spec:** Authorization API 1.0 §5 (information model: Subject {type, id REQUIRED, properties}, Resource {type, id, properties}, Action {name REQUIRED, properties}, Context, Decision {decision boolean REQUIRED, context}), §6.1 (request: subject, action, resource REQUIRED; context OPTIONAL), §6.2 (response = Decision), §10.1 (HTTPS JSON binding: POST, `Content-Type: application/json`, 200 + JSON; default path /access/v1/evaluation), §10.1.1 (JSON serialisation: missing required → 400; ignore unknown fields; no ordering assumptions), §10.1.2 (errors 400/401/403/500 — a deny is 200 {decision:false}), §10.1.3 (`X-Request-ID` echoed when present), §11.1–11.2 (TLS; authenticate the PEP), §11.5 (I-JSON, omit nulls), §11.7 (DoS: payload limits, rate limiting).

PEPs authenticate with a DPoP-bound access token (scope `authzen.evaluate`, `aud` = PDP identifier). Decisions come from the `PolicyEngine` port (E13_04). Fail closed.

**Acceptance tests**

- Request missing `subject.id`, `resource.type`, or `action.name` → 400 with error string; unknown members ignored; nested payload > 64 KiB or depth > 16 → 400.
- Deny → 200 `{"decision": false, "context": {...}}`; engine error/timeout → 200 `{decision:false, context:{error:{status:500,...}}}` and audit (fail closed); unauthenticated → 401 with `WWW-Authenticate`.
- `X-Request-ID` from the request is echoed on the response; absent → generated.
- Every decision audited with subject/action/resource summary (no full properties) and latency; p95 ≤ 5 ms for the built-in engine.
- Fuzz target `authzen_request`; AuthZEN interop test suite (openid.github.io/authzen todo/interop) passes for evaluation.

**Depends on:** E13_04, E08_08

### E13_02 — Access Evaluations (boxcar) endpoint with `evaluations_semantic` options

*feature · P2 · labels: area:authzen, spec:openid-authzen, status:final, flag:authzen*

**Spec:** Authorization API 1.0 §7.1 (`evaluations` array; top-level subject/action/resource/context as defaults; each item overrides; required entities must come from item or default), §7.1.1 (default values), §7.1.2.1 (`options.evaluations_semantic`: execute_all (default) | deny_on_first_deny | permit_on_first_permit), §7.2 (response `evaluations` array in request order; per-item errors as decision:false with context.error), §10.1 (default path /access/v1/evaluations).

Same engine, N decisions per request with short-circuit semantics.

**Acceptance tests**

- Table-driven tests for all three semantics using the §7.1.2.1 examples (including the truncated arrays for short-circuit modes).
- Missing required entity after default merge → 400 for the whole request; per-item engine failure → item `decision:false` with `context.error`.
- Array size cap (default 100) → 400 beyond; items evaluated concurrently for execute_all.

**Depends on:** E13_01

### E13_03 — PDP metadata (`/.well-known/authzen-configuration`)

*feature · P2 · labels: area:authzen, spec:openid-authzen, status:final, flag:authzen*

**Spec:** Authorization API 1.0 §9.1.1 (endpoint parameters: policy_decision_point REQUIRED (https, no query/fragment), access_evaluation_endpoint REQUIRED, access_evaluations_endpoint, search_* OPTIONAL), §9.1.2 (`capabilities` URNs), §9.1.3 (`signed_metadata` OPTIONAL), §9.2 (well-known URI inserted between host and path; multi-tenant example), §9.2.2 (200, application/json; omit empty parameters; ignore unknown), §9.2.3 (validation: policy_decision_point identical to the identifier used).

Per-tenant PDP identifier = tenant issuer + `/authzen` (or the issuer itself — decide in implementation, keep identical in `aud`).

**Acceptance tests**

- Document lists exactly the implemented endpoints; `policy_decision_point` equals the identifier the well-known URL was derived from (test).
- Search endpoints appear only when E13_06 is enabled; `signed_metadata` optional behind a flag using tenant signing keys.
- Route/metadata parity test (E04_03) extended to AuthZEN endpoints.

**Depends on:** E13_01, E04_03

### E13_04 — PolicyEngine port + built-in declarative engine over IdP data

*feature · P2 · labels: area:authzen, differentiator:authzen*

**Spec:** Authorization API 1.0 §5 (information model), §5.5.1 (decision context: reasons, obligations, step-up hints e.g. `acr_values`); NIST SP 800-162 (ABAC — informational).

`PolicyEngine::evaluate(tenant, Subject, Action, Resource, Context) -> Decision`. Built-in engine: tenant rules as data (JSON/YAML, schema-validated) over attributes the IdP owns — user attributes/groups/roles, client/agent profile, active grants (scopes, RAR, resources), session acr — plus PEP-supplied properties. Deterministic, total, explainable.

**Acceptance tests**

- Rule language supports: match on subject/resource `type`, attribute equality/set membership, group/role membership, 'subject holds an active grant for resource R with authorization_details type T and action A', acr ≥ level; explicit deny wins; default deny.
- Decision `context` can carry `reason_admin`, `reason_user` and a step-up hint `acr_values` (§5.5.1 examples) — used by E11_10.
- Property test: evaluation never panics on random inputs and is deterministic; golden tests for the rule catalogue.
- No tenant-supplied code; rules edited via admin API/console (E14_09).

**Depends on:** E06_06, E07_02, E13_05

### E13_05 — Decision: policy language for the built-in PDP (declarative rules vs Cedar vs external OPA)

*decision · P2 · labels: adr, area:authzen*

**Spec:** Authorization API 1.0 §2 ('policy language, architecture, and state management aspects of a PDP are beyond the scope').

Options: (a) small declarative rule model (JSON/YAML) tailored to IdP data — simplest, explainable, no new language; (b) embed Cedar (`cedar-policy` crate) behind the port — expressive, well-analysed, adds a policy language to learn; (c) delegate to external OPA — new runtime dependency, contradicts single-binary. Recommendation: (a) for v1 with the port shaped so (b) is a drop-in adapter; revisit when customers need cross-resource policies.

**Acceptance tests**

- ADR merged; port signature reviewed for Cedar compatibility (entities/attributes shape).

**Depends on:** E01_09

### E13_06 — Search APIs (subject/resource/action) with pagination [optional]

*feature · P3 · labels: area:authzen, spec:openid-authzen, status:final, flag:authzen*

**Spec:** Authorization API 1.0 §8 (search: omit the id of the entity being searched; results SHOULD evaluate to permit), §8.2 (pagination: `page.token`/`limit`; response `page.next_token` REQUIRED when paginated, empty string at end; identical parameters between pages), §8.3 (response: `results` REQUIRED, `page`, `context`), §8.4–8.6 (subject/resource/action search requests; default paths /access/v1/search/{subject,resource,action}).

Only for the built-in engine (finite entity sets: users, grants, resources).

**Acceptance tests**

- Each search returns only entities of the searched type; every returned entity evaluates to `decision:true` in a follow-up evaluation (property test on seeded data).
- Pagination tokens opaque and bound to the query; changed parameters mid-pagination → 400.
- Metadata advertises `search_*_endpoint` only when enabled.

**Depends on:** E13_04

## E14 — Admin API & admin console  (P1, epic)

OpenAPI-described admin API (same-origin session for the console, DPoP client_credentials for automation), React + TypeScript + Vite console served by the binary under strict CSP, screens for tenants, clients/DCR policy, users/sessions/grants, keys, SSF streams & audit explorer, AuthZEN policies.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E14_01 | Admin API foundation (`/admin/api/v1`): auth modes, RBAC, audit, OpenAPI | feature | P1 | E06_02, E08_08, E01_11 |
| E14_02 | Decision: admin console as a first-party same-origin app (not an OAuth public client) | decision | P1 | E01_09 |
| E14_03 | Console scaffold (React + TypeScript + Vite) served by the binary under strict CSP | feature | P1 | E14_01, E14_02, E15_03 |
| E14_04 | Console: tenant settings (feature flags, lifetimes, session & ACR policy, rate limits, theming) | feature | P1 | E14_03 |
| E14_05 | Console: clients, agents & DCR policy | feature | P1 | E14_03 |
| E14_06 | Console: users, credentials, sessions & grants | feature | P1 | E14_03, E10_03 |
| E14_07 | Console: signing keys (list, rotate, retire, JWKS preview) | feature | P1 | E14_03, E02_03 |
| E14_08 | Console: SSF streams, delivery status & audit/agent-trail explorer | feature | P2 | E14_03, E12_03, E11_09 |
| E14_09 | Console: AuthZEN policy editor with test bench | feature | P3 | E14_03, E13_04 |

### E14_01 — Admin API foundation (`/admin/api/v1`): auth modes, RBAC, audit, OpenAPI

*feature · P1 · labels: area:admin, area:api*

**Spec:** RFC 6749 §4.4 (client_credentials for automation); RFC 9449 §7 (DPoP at the API); OWASP ASVS V4 (access control), V13 (API).

Two auth modes: (1) console — same-origin IdP session cookie + CSRF header + admin role; (2) automation — DPoP-bound access token with `admin.*` scopes from an admin client. RBAC roles: tenant-admin, security-auditor (read-only), user-support (users/sessions only). Every mutation audited with actor.

**Acceptance tests**

- Every route declares required role/scope; a table-driven test enumerates all routes and asserts 401/403 for missing/insufficient auth.
- CSRF: mutations from the console require `X-CSRF-Token` matching the session; token-based calls skip CSRF but require DPoP.
- OpenAPI 3.1 document generated from code and served at `/admin/api/v1/openapi.json`; contract tests run against it.
- Pagination (cursor), idempotency keys on POST, consistent error envelope, rate limits.

**Depends on:** E06_02, E08_08, E01_11

### E14_02 — Decision: admin console as a first-party same-origin app (not an OAuth public client)

*decision · P1 · labels: adr, area:admin*

**Spec:** FAPI 2.0 SP §5.3.2.1 item 3 (confidential clients only) — a browser SPA cannot be a FAPI 2.0 client; RFC 9700 §4 (browser-based app risks).

Options: (a) console authenticates with the IdP's own session cookie (same origin), calls `/admin/api` with CSRF protection; (b) console as OIDC public client with DPoP — violates baseline; (c) separate BFF service — new component. Recommendation (a): no tokens in the browser, CSP strict, no third-party origins; the console is just another server-rendered-entry SPA of the IdP.

**Acceptance tests**

- ADR merged; E14_03 implements (a); threat-model rows for CSRF/XSS on the console added.

**Depends on:** E01_09

### E14_03 — Console scaffold (React + TypeScript + Vite) served by the binary under strict CSP

*feature · P1 · labels: area:admin, area:console*

**Spec:** CSP Level 3 (`strict-dynamic`, nonces/hashes); FAPI 2.0 SP §5.2.3.

Vite build embedded in the binary (`include_dir`/rust-embed) under `/admin/`, hashed immutable assets, index rendered server-side to inject the CSP nonce; no inline scripts/styles; no external fonts/CDNs; role-aware navigation; Playwright e2e smoke.

**Acceptance tests**

- All console responses carry the same CSP as E15_03 (script-src nonce + strict-dynamic); zero CSP violations in e2e run (console listener).
- Login redirects to the IdP login page and back; unauthenticated API calls → 401 handled with re-login.
- Bundle has no third-party network calls (test intercepts all requests).
- Accessibility lint (axe) passes on main screens.

**Depends on:** E14_01, E14_02, E15_03

### E14_04 — Console: tenant settings (feature flags, lifetimes, session & ACR policy, rate limits, theming)

*feature · P1 · labels: area:admin, area:console*

**Spec:** OIDC Discovery §3 (settings that surface in metadata); product config model (E01_02).

Forms for issuer info (read-only), feature flags, token/code/session lifetimes (with FAPI caps enforced server-side), ACR policy editor, rate limits, theming tokens (E15_01) with live preview.

**Acceptance tests**

- Attempt to set code lifetime > 60 s or AT lifetime > cap is rejected by the API with a message citing FAPI 2.0 SP §5.3.2.2 item 11.
- Changing a flag updates discovery metadata immediately (cache invalidation) — e2e test.
- All changes audited with before/after diff (no secrets).

**Depends on:** E14_03

### E14_05 — Console: clients, agents & DCR policy

*feature · P1 · labels: area:admin, area:console, differentiator:agents*

**Spec:** RFC 7591 §2; RFC 7592; E03_06 policy model; E11_01 agent profile.

Client list/search, create/edit with the same validator as DCR (E03_01), JWKS upload / jwks_uri, redirect URIs, grant types, RAR types, resources; agent profile editor; initial-access-token issuance with policy and quota; DCR policy editor with dry-run against a sample registration.

**Acceptance tests**

- Console cannot create a client that DCR would reject (shared validator; e2e negative tests).
- Initial access tokens shown once, stored hashed; quota and expiry visible.
- Policy dry-run returns the failing rule id for a sample document.

**Depends on:** E14_03

### E14_06 — Console: users, credentials, sessions & grants

*feature · P1 · labels: area:admin, area:console*

**Spec:** OIDC Core §5.1 (claims editing); Back-Channel Logout §2.5; CAEP 1.0 §3.1.

User search/create/disable, claims editing with verification flags, credential management (remove passkey, force password reset), session list with revoke (triggers E10_03), grants list with revoke (E07_05 semantics).

**Acceptance tests**

- Disabling a user revokes sessions, emits RISC `account-disabled` and back-channel logout — e2e verifies receiver stubs.
- Support role can view/revoke sessions but not edit claims (RBAC test).
- Bulk import CSV/JSON with validation report (no passwords in import).

**Depends on:** E14_03, E10_03

### E14_07 — Console: signing keys (list, rotate, retire, JWKS preview)

*feature · P1 · labels: area:admin, area:console, area:keys*

**Spec:** OIDC Core §10.1.1; FAPI 2.0 SP §6.8.

Key inventory per purpose/alg with states; rotate now; set rotation schedule; JWKS preview; never shows private material.

**Acceptance tests**

- Rotation from the console produces a new active `kid` and keeps the previous one published (e2e); private keys never leave the server (API schema test).

**Depends on:** E14_03, E02_03

### E14_08 — Console: SSF streams, delivery status & audit/agent-trail explorer

*feature · P2 · labels: area:admin, area:console, area:ssf, area:audit, differentiator:agents*

**Spec:** SSF 1.0 §8 (stream state); E11_09 query API.

Stream list with status/reason, queue depth, dead letters (retry/drop), trigger verification; audit explorer with filters and delegation-chain visualisation; export.

**Acceptance tests**

- Operator can pause/enable a stream (emits stream-updated) and requeue a dead-lettered SET.
- Chain view renders user → agent A → agent B from `act` data for a seeded scenario.
- Export downloads NDJSON respecting RBAC.

**Depends on:** E14_03, E12_03, E11_09

### E14_09 — Console: AuthZEN policy editor with test bench

*feature · P3 · labels: area:admin, area:console, area:authzen*

**Spec:** Authorization API 1.0 §6 (evaluation request shape for the test bench).

Edit tenant rules (E13_04) with schema validation and a 'try a request' panel that calls the evaluation endpoint.

**Acceptance tests**

- Invalid rule documents are rejected with line/path errors; test bench shows decision + context; changes audited.

**Depends on:** E14_03, E13_04

## E15 — Theming, templates & browser security  (P1, epic)

Tenant theming through design tokens only, a constrained askama template set, strict nonce-based CSP and security headers, progressive-enhancement test suite, i18n.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E15_01 | Design-token model & tenant theming (no tenant HTML/CSS/JS) | feature | P2 | E15_02 |
| E15_02 | Constrained template set (login, register, consent, error, device, approvals, logout, account, reset) | feature | P1 | E06_01 |
| E15_03 | Strict CSP (nonce + strict-dynamic) & security headers on every HTML response | feature | P0 | E01_04 |
| E15_04 | Progressive-enhancement test suite (JS disabled and enabled) | chore | P1 | E15_02, E05_05, E11_03 |
| E15_05 | i18n message bundles & `ui_locales` handling | feature | P2 | E15_02 |

### E15_01 — Design-token model & tenant theming (no tenant HTML/CSS/JS)

*feature · P2 · labels: area:web, area:theming*

**Spec:** Product rule: customization without a JS foothold; CSP `style-src` nonce; OWASP file upload cheat sheet (logo).

Token schema: palette (with contrast validation), font stack from the self-hosted set, radius/spacing scale, logo (PNG/JPEG/WebP ≤ 200 KiB, re-encoded server-side; SVG rejected), favicon, product name, support links (https only). Rendered as CSS custom properties in a nonce'd `<style>` block.

**Acceptance tests**

- Schema-validated JSON; invalid colors/fonts/URLs rejected with field paths; contrast below WCAG AA for text/background rejected (or warned, tenant override with audit).
- Uploaded image is decoded and re-encoded (strips metadata/scripts); SVG upload → 415.
- Theme changes never introduce inline `style=` attributes or external origins (CSP test remains green).
- Preview in console (E14_04).

**Depends on:** E15_02

### E15_02 — Constrained template set (login, register, consent, error, device, approvals, logout, account, reset)

*feature · P1 · labels: area:web, area:templates*

**Spec:** OIDC Core §3.1.2.3–3.1.2.4; RFC 8628 §3.3; CIBA §8; product rule (templates fixed, tenants change tokens and strings only); WCAG 2.2 AA.

askama compile-time templates with a shared layout; tenant customization limited to tokens (E15_01) and message bundles (E15_05). Snapshot-tested.

**Acceptance tests**

- Templates: login (passkey-first, password fallback), registration + email verification, consent, error, device verification, approvals inbox, logout confirm/done, account (passkeys, sessions, grants, password), password reset; each has a snapshot test in en and fr.
- No template accepts tenant-provided markup; all variables autoescaped; a lint test fails on `|safe` with request data.
- Forms have labels, error summaries, focus management; axe checks pass in CI.

**Depends on:** E06_01

### E15_03 — Strict CSP (nonce + strict-dynamic) & security headers on every HTML response

*feature · P0 · labels: area:web, area:security, spec:fapi2-sp, status:final*

**Spec:** FAPI 2.0 SP §5.2.3 (browser endpoints: HSTS, no CORS on authorization endpoint); RFC 9700 §4 (clickjacking, referrer leakage); CSP Level 3; RFC 6797 (HSTS).

Middleware sets per-response nonce and headers: `Content-Security-Policy: default-src 'none'; script-src 'nonce-{n}' 'strict-dynamic'; style-src 'nonce-{n}'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self' {redirect-origin-when-form_post}; frame-ancestors 'none'; base-uri 'none'; object-src 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`, `Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)`, `Cache-Control: no-store` on interaction pages.

**Acceptance tests**

- Integration test iterates every HTML route and asserts the header set; nonce differs per response and matches the one in the page.
- form_post page's `form-action` includes exactly the redirect_uri origin (E05_05).
- No `unsafe-inline`/`unsafe-eval` anywhere (grep test); CSP report-only endpoint optional for staging.
- Playwright run reports zero CSP violations across the no-JS and JS suites.

**Depends on:** E01_04

### E15_04 — Progressive-enhancement test suite (JS disabled and enabled)

*chore · P1 · labels: area:web, area:ci*

**Spec:** Product rule: pages must work without JavaScript and support response_mode=form_post.

Playwright suites: (1) JS disabled — password login → consent → form_post continue button → RP receives code; device verification; logout; account pages. (2) JS enabled — passkeys via virtual authenticator, form_post auto-submit, conditional UI.

**Acceptance tests**

- Both suites run in CI against a seeded tenant; failures block merge.
- A page that only works with JS (other than the passkey ceremony) fails the no-JS suite by design (documented allowlist).

**Depends on:** E15_02, E05_05, E11_03

### E15_05 — i18n message bundles & `ui_locales` handling

*feature · P2 · labels: area:web, spec:oidc-core, status:final*

**Spec:** OIDC Core §3.1.2.1 (`ui_locales`: preferred languages in order; OP MUST NOT error if unsupported), §5.2 (`claims_locales`); Discovery §3 (`ui_locales_supported`).

Fluent (or ICU) bundles en + fr, tenant string overrides validated against the bundle keys (no markup), locale negotiation from `ui_locales` → Accept-Language → tenant default.

**Acceptance tests**

- `ui_locales=fr-CA fr en` renders French; unsupported values ignored without error; `ui_locales_supported` published.
- Tenant overrides cannot introduce HTML (escaped) and unknown keys are rejected.
- Snapshot tests per locale for the template set.

**Depends on:** E15_02

## E16 — Security hardening, conformance & release  (P1, epic)

FAPI 2.0 conformance in CI, OIDC-core conformance strategy decision, rate limiting and abuse controls, secrets/data hygiene, fuzz/static-analysis gates, threat-model completion and security review, packaging/deployment docs, performance baseline.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E16_01 | FAPI 2.0 Security Profile conformance suite green in CI (release gate) | task | P1 | E01_08, E08_09, E05_05, E09_03 |
| E16_02 | Decision: OIDC Core certification profile vs PAR-only baseline (conformance_mode) | decision | P2 | E16_01 |
| E16_03 | Rate limiting & abuse controls across endpoints | feature | P1 | E01_04 |
| E16_04 | Secrets & data hygiene: retention jobs, log redaction proof, PII minimisation, backups doc | task | P1 | E01_05 |
| E16_05 | Fuzz-coverage gate, nightly fuzzing, cargo-geiger/deny/audit gates | chore | P1 | E01_07 |
| E16_06 | Threat model completion & external security review readiness | task | P1 | E01_09, E11_02, E11_06, E12_08 |
| E16_07 | Release packaging & deployment docs (single binary, container, compose, Helm minimal) | task | P1 | E01_03, E01_04 |
| E16_08 | Performance baseline & DB index review | task | P2 | E08_02, E12_06 |

### E16_01 — FAPI 2.0 Security Profile conformance suite green in CI (release gate)

*task · P1 · labels: area:conformance, spec:fapi2-sp, status:final*

**Spec:** FAPI 2.0 Security Profile (Final); OIDF conformance plan `fapi2-security-profile-final` variants: client_auth_type=private_key_jwt, sender_constrain=dpop, fapi_profile=plain_fapi, openid=openid_connect (+ mtls variant when flag on).

Run the full plan nightly and on release branches; publish report; track waivers explicitly (none expected).

**Acceptance tests**

- 100% pass on the DPoP/private_key_jwt variant; mTLS variant passes when `mtls` enabled.
- Release workflow refuses to tag when the latest report has failures or is older than 24 h.
- Certification submission checklist documented (`docs/certification.md`).

**Depends on:** E01_08, E08_09, E05_05, E09_03

### E16_02 — Decision: OIDC Core certification profile vs PAR-only baseline (conformance_mode)

*decision · P2 · labels: adr, area:conformance*

**Spec:** OIDF OpenID Provider certification plans (Basic OP, Config OP, Dynamic OP, Form Post, Logout profiles) send non-PAR authorization requests; FAPI 2.0 SP §5.3.2.2 item 3 requires rejecting them.

Options: (a) certify FAPI 2.0 only (+ logout profiles where compatible); (b) add a tenant-scoped `conformance_mode` that accepts non-PAR requests solely for certification runs, clearly non-FAPI; (c) skip OIDC certification. Recommendation: (a) now, (b) only if a customer requires the OP marks; never enable (b) on a FAPI tenant.

**Acceptance tests**

- ADR merged; if (b) chosen, readiness reports `fapi_compliant=false` for that tenant and the mode cannot be enabled together with agent features.

**Depends on:** E16_01

### E16_03 — Rate limiting & abuse controls across endpoints

*feature · P1 · labels: area:security*

**Spec:** RFC 8628 §5.1–5.2 (brute force on user/device codes); CIBA §11 (over-polling → invalid_request); RFC 9126 §7.1 (request_uri guessing); RFC 7591 §5 (registration abuse); RFC 6749 §10.x; Authorization API 1.0 §11.7 (DoS).

In-process token buckets (per instance; documented) keyed by (tenant, endpoint, client|ip|user) with 429 + `Retry-After`; polling grants get `slow_down`; login/registration/reset get silent throttling (E06_09).

**Acceptance tests**

- Limits configurable per tenant; defaults documented; exceeding → 429 with `Retry-After`, audited once per window (no log flood).
- PAR/token/introspection/revocation/registration/backchannel/device endpoints covered by a table-driven test.
- Metrics for throttled requests per endpoint.

**Depends on:** E01_04

### E16_04 — Secrets & data hygiene: retention jobs, log redaction proof, PII minimisation, backups doc

*task · P1 · labels: area:security, area:ops*

**Spec:** RFC 9700 §4.2–4.3 (credential leakage); FAPI 2.0 SP §7 (privacy: data minimisation, data leak from AS); GDPR data minimisation (informational).

Scheduled cleanup of codes, PAR requests, interactions, expired sessions, jti denylist, outbox, replay caches; audit PII hashing; log redaction regression test; backup/restore runbook covering KEK handling.

**Acceptance tests**

- Retention job removes expired rows for every ephemeral table (test seeds and verifies) and is safe to run concurrently.
- Redaction test (E01_05) extended to admin API and worker logs.
- Runbook: backup, restore, KEK rotation with re-encryption of signing keys.

**Depends on:** E01_05

### E16_05 — Fuzz-coverage gate, nightly fuzzing, cargo-geiger/deny/audit gates

*chore · P1 · labels: area:security, area:ci*

**Spec:** Project DoD (fuzz target for every parser; no new unsafe).

Finalize the coverage gate (E01_07) across all parser modules added by the protocol epics; nightly 10-minute runs per target with corpus persistence; `cargo geiger` zero unsafe in workspace crates; `cargo deny`/`cargo audit` gates.

**Acceptance tests**

- Every parser/validator module in the workspace has a fuzz target (gate passes) — list committed in `docs/fuzzing.md`.
- Nightly job uploads corpus artifacts and crash reports; a crash opens an issue automatically.
- `cargo geiger` reports 0 unsafe expressions in first-party crates.

**Depends on:** E01_07

### E16_06 — Threat model completion & external security review readiness

*task · P1 · labels: area:security, area:docs*

**Spec:** FAPI 2.0 Attacker Model (A1–A5); FAPI 2.0 SP §6 (DPoP proof replay, stolen token injection/'Cuckoo's token', authorization request leak → CSRF, browser swapping, client impersonating resource owner, key compromise); MCP Authorization security considerations (confused deputy, token passthrough, localhost redirect risks).

Complete `docs/threat-model.md` with agent-specific threats: prompt-injected agent requesting broader scope, delegation-chain abuse, replay of agent DPoP proofs, approval fatigue in CIBA/device flows, MCP confused deputy. Each threat links to controls and beads. Add SECURITY.md and a coordinated-disclosure policy.

**Acceptance tests**

- Every FAPI attacker capability and every listed SP §6 consideration has a row with control + test reference.
- Agent threats documented with mitigations (narrowing-only exchange, depth limits, approval freshness, audience binding).
- SECURITY.md published; review checklist ready for an external audit.

**Depends on:** E01_09, E11_02, E11_06, E12_08

### E16_07 — Release packaging & deployment docs (single binary, container, compose, Helm minimal)

*task · P1 · labels: area:release, area:ops*

**Spec:** Product decision: single binary + one PostgreSQL; FAPI 2.0 SP §5.2 (TLS deployment guidance).

Reproducible release builds (musl/static where feasible), distroless image, migrations-on-start with advisory lock, example compose (PG + Asterius + conformance), minimal Helm chart, config reference generated from the config schema, TLS/HSTS/reverse-proxy guide, upgrade & rotation runbooks.

**Acceptance tests**

- `docker compose up` gives a working tenant with seeded admin and passes a smoke test script.
- Image runs as non-root, read-only FS, no shell; SBOM published with the release.
- Config reference lists every key with type/default; secrets sources documented.

**Depends on:** E01_03, E01_04

### E16_08 — Performance baseline & DB index review

*task · P2 · labels: area:ops, area:performance*

**Spec:** FAPI 2.0 SP §6.1 (short access tokens increase AS load — size lifetimes with data).

Load scripts (k6/oha) for token endpoint (private_key_jwt + DPoP), PAR+authorize+token flow, introspection, SSF delivery; EXPLAIN review of hot queries; connection-pool sizing guidance.

**Acceptance tests**

- Published numbers on reference hardware (e.g., 4 vCPU/8 GiB + PG): token endpoint p95 latency and throughput; no query without an index on hot paths.
- No N+1 queries in code flow (query counter test).

**Depends on:** E08_02, E12_06

## E17 — Track, don't implement (post-v1 and working drafts)  (P4, epic)

Specifications and features deliberately kept out of v1: working drafts (never build v1 scope on them), out-of-scope protocols, and post-v1 candidates. One bead per item so status changes are visible; all P4.

| Key | Story | Type | P | Depends on |
|---|---|---|---|---|
| E17_01 | Track: FAPI 2.0 Message Signing (JAR + JARM + HTTP message signatures) | task | P4 | — |
| E17_02 | Track: Client ID Metadata Documents (IETF draft) for MCP clients | task | P4 | E03_08 |
| E17_03 | Track: Identity Assertion Authorization Grant / Cross-App Access for enterprise agents | task | P4 | — |
| E17_04 | Track: OpenID Federation 1.0 (Final) — out of v1 scope by product decision | task | P4 | — |
| E17_05 | Track: Identity Assurance (IDA) verified claims — out of v1 scope; claims model must stay compatible | task | P4 | — |
| E17_06 | Track: OID4VCI / OID4VP (verifiable credentials) — out of v1 scope | task | P4 | — |
| E17_07 | Track: Native SSO for mobile apps (draft) | task | P4 | — |
| E17_08 | Track: Provider Commands, IPSIE profiles, Enterprise Extensions (drafts) | task | P4 | — |
| E17_09 | Track: Ephemeral Subject Identifier, Key Binding, Advanced Syntax for Claims, Claims Aggregation (drafts) | task | P4 | — |
| E17_10 | Track: CAEP Interoperability Profile (Implementer's Draft) & SSF receiver role | task | P4 | E12_08 |
| E17_11 | Track: OAuth 2.1 (draft) and RFC 7523bis (draft) alignment notes | task | P4 | — |
| E17_12 | Post-v1 candidates: SCIM 2.0 provisioning, TOTP second factor, SAML (nice-to-have), LDAP | task | P4 | — |

### E17_01 — Track: FAPI 2.0 Message Signing (JAR + JARM + HTTP message signatures)

*task · P4 · labels: track, spec:fapi2-message-signing, status:impl-draft*

**Spec:** FAPI 2.0 Message Signing draft-02 (Implementer's Draft; 'not an OIDF International Standard'); JARM (Final, errata set 1) §2 (JWT response document: iss, aud, exp ≤10 min, plus response params), §4 (response modes query.jwt/fragment.jwt/form_post.jwt/jwt).

Non-repudiation profile on top of FAPI 2.0 SP. E05_09 (JAR in PAR) is the only prerequisite worth keeping optional in v1. Re-evaluate when Message Signing reaches Final.

**Acceptance tests**

- Bead updated with the spec status at each release; no code beyond E05_09.

**Depends on:** —

### E17_02 — Track: Client ID Metadata Documents (IETF draft) for MCP clients

*task · P4 · labels: track, spec:mcp, status:draft*

**Spec:** draft-ietf-oauth-client-id-metadata-document-00 (IETF working draft); MCP Authorization 2025-11-25 (AS SHOULD support; `client_id_metadata_document_supported`).

Would let MCP clients use an https URL as `client_id`; requires SSRF-hardened fetching and a trust policy; only meaningful together with a public-client decision (E03_08).

**Acceptance tests**

- Revisit when the draft is in WGLC/RFC and E03_08 is revisited.

**Depends on:** E03_08

### E17_03 — Track: Identity Assertion Authorization Grant / Cross-App Access for enterprise agents

*task · P4 · labels: track, spec:ietf-identity-assertion-authz-grant, status:draft*

**Spec:** draft-ietf-oauth-identity-assertion-authz-grant (IETF working draft; builds on RFC 8693 + RFC 7523); MCP 'enterprise-managed authorization' extension.

IdP-brokered token issuance for third-party apps/agents inside an enterprise. Our RFC 8693 implementation (E11_02) is the foundation.

**Acceptance tests**

- Revisit at IETF WGLC.

**Depends on:** —

### E17_04 — Track: OpenID Federation 1.0 (Final) — out of v1 scope by product decision

*task · P4 · labels: track, spec:openid-federation, status:final*

**Spec:** OpenID Federation 1.0 (Final) — trust chains, entity statements, automatic registration.

Keep client/key models compatible (entity id = https URL, JWKS by reference). No implementation in v1.

**Acceptance tests**

- Data-model compatibility note maintained in ADR log.

**Depends on:** —

### E17_05 — Track: Identity Assurance (IDA) verified claims — out of v1 scope; claims model must stay compatible

*task · P4 · labels: track, spec:openid-ida, status:final*

**Spec:** OpenID Connect for Identity Assurance 1.0 (Final) — `verified_claims` structure.

E06_06 stores per-claim source/verification metadata so `verified_claims` can be projected later.

**Acceptance tests**

- Schema compatibility test kept in E06_06.

**Depends on:** —

### E17_06 — Track: OID4VCI / OID4VP (verifiable credentials) — out of v1 scope

*task · P4 · labels: track, spec:oid4vc, status:final*

**Spec:** OpenID for Verifiable Credential Issuance 1.0 / Verifiable Presentations 1.0 (Final), HAIP.

No implementation; issuer-agnostic claims model is the only hook.

**Acceptance tests**

- None (tracking only).

**Depends on:** —

### E17_07 — Track: Native SSO for mobile apps (draft)

*task · P4 · labels: track, spec:openid-native-sso, status:draft*

**Spec:** OpenID Connect Native SSO for Mobile Apps 1.0 (draft) — device_secret + token exchange.

Track; token exchange (E11_02) would host it.

**Acceptance tests**

- Revisit if it reaches Implementer's Draft/Final.

**Depends on:** —

### E17_08 — Track: Provider Commands, IPSIE profiles, Enterprise Extensions (drafts)

*task · P4 · labels: track, spec:openid-provider-commands, spec:ipsie, status:draft*

**Spec:** OpenID Provider Commands 1.0 (draft); IPSIE Common Requirements / SL1 profile (drafts); Enterprise Extensions (draft).

Align where free (IPSIE SL1 ≈ OIDC + SSF/CAEP which we have); no dedicated implementation.

**Acceptance tests**

- Gap list vs IPSIE SL1 maintained in docs once IPSIE is an Implementer's Draft.

**Depends on:** —

### E17_09 — Track: Ephemeral Subject Identifier, Key Binding, Advanced Syntax for Claims, Claims Aggregation (drafts)

*task · P4 · labels: track, status:draft*

**Spec:** OpenID Connect drafts: Ephemeral Subject Identifier, Key Binding, Advanced Syntax for Claims, Claims Aggregation.

Keep `sub` generation and claims model pluggable; nothing else.

**Acceptance tests**

- None (tracking only).

**Depends on:** —

### E17_10 — Track: CAEP Interoperability Profile (Implementer's Draft) & SSF receiver role

*task · P4 · labels: track, spec:openid-caep-interop, status:impl-draft*

**Spec:** CAEP Interoperability Profile 1.0 (Implementer's Draft); SSF 1.0 receiver responsibilities (§3.6 receiver subject processing, §8).

Post-v1: consume upstream signals (e.g., revoke sessions on `credential-compromise` from an upstream IdP); align event set with the interop profile.

**Acceptance tests**

- Re-evaluate after v1; receiver design note referencing outbox and SET verification.

**Depends on:** E12_08

### E17_11 — Track: OAuth 2.1 (draft) and RFC 7523bis (draft) alignment notes

*task · P4 · labels: track, spec:oauth-2.1, spec:rfc7523bis, status:draft*

**Spec:** draft-ietf-oauth-v2-1 (consolidates BCP: PKCE, exact redirect URIs, no implicit/ROPC); draft-ietf-oauth-rfc7523bis (client assertion `aud` MUST be the issuer identifier; no token endpoint URL).

FAPI 2.0 already implies both; our private_key_jwt `aud` rule (E03_02) matches 7523bis. Track for wording changes only.

**Acceptance tests**

- Bead notes updated when either becomes an RFC.

**Depends on:** —

### E17_12 — Post-v1 candidates: SCIM 2.0 provisioning, TOTP second factor, SAML (nice-to-have), LDAP

*task · P4 · labels: track, post-v1*

**Spec:** RFC 7643/7644 (SCIM 2.0); RFC 6238 (TOTP); SAML 2.0 (never in v1; XML-based); LDAP (out of scope).

Common asks explicitly deferred. SCIM is the most likely first addition (fits the user/claims model). SAML/LDAP remain out of scope unless a product decision re-opens them.

**Acceptance tests**

- Product owner reviews this bead at each release planning.

**Depends on:** —

