# Asterius IdP

**An open-source OpenID Connect / OAuth 2.0 identity provider, written in Rust, with the FAPI 2.0 Security Profile as its only mode — built for people *and* AI agents.**

> **Status: pre-alpha.** Architecture, security baseline and the full v1 backlog are defined; implementation is starting. Nothing here is production-ready yet. See [Roadmap](#roadmap).

## Why another IdP?

Most identity providers treat high security as an optional profile and AI agents as an afterthought. Asterius flips both:

- **FAPI 2.0 is the baseline, not a mode.** No implicit flow, no ROPC, no public clients, PAR-only authorization requests, PKCE S256, sender-constrained (DPoP) access tokens, exact redirect-URI matching, `private_key_jwt` client authentication, short-lived audience-bound tokens, explicit `typ` on every JWT.
- **Agent-native authorization.** RFC 8693 token exchange with delegation chains (`act`), Rich Authorization Requests (RFC 9396), device flow and CIBA for human-in-the-loop approval, dynamic client registration with policy, MCP compatibility for confidential clients, and a per-agent audit trail.
- **Continuous access, not one-time login.** A Shared Signals Framework / CAEP transmitter (session revoked, credential change, assurance-level change), an AuthZEN 1.0 policy decision point for action-level decisions, and Grant Management for revocable standing consents.
- **Customization without a JavaScript foothold.** Login, consent and error pages are server-rendered, work without JavaScript, support `response_mode=form_post`, and are themed through design tokens only — tenants never supply scripts or markup. Strict nonce-based CSP everywhere.

## Architecture

- **Modular monolith, single binary, one PostgreSQL.** No microservices, no Redis (transactional outbox instead). Ports & adapters around protocol and key-management code so crypto and storage can be swapped without touching protocol logic.
- **Backend:** Rust — `axum`, `tokio`, `sqlx`/PostgreSQL, `rustls`, `aws-lc-rs`/`ring`, `josekit`, `argon2`, `webauthn-rs`.
- **Admin console:** React + TypeScript + Vite, served by the same binary as a first-party same-origin app (it is *not* an OAuth public client).
- **End-user pages:** `askama` templates, progressive enhancement, no-JS baseline.
- **Signing:** EdDSA (Ed25519) by default, ES256 for compatibility, PS256 as the RSA option. Passwords: Argon2id. **Passkeys are the primary human credential.**

```
crates/
  asterius-domain/     entities, ids, ports (Clock, KeyStore, Signer, repositories, Outbox …)
  asterius-oidc/       protocol logic — pure functions, no I/O, no framework types
  asterius-jose/       key management port + JOSE adapter, algorithm allow-list
  asterius-store-pg/   sqlx adapters, migrations
  asterius-web/        server-rendered pages, CSP, interaction engine
  asterius-admin-api/  OpenAPI-described admin API
  asterius-server/     axum wiring, single `asterius` binary
```

**The rule: protocol code talks to the outside world only through ports.**
`asterius-domain` declares a trait for every outside dependency; `asterius-oidc`
decides what the protocol requires and never performs I/O. Adapters
(`asterius-store-pg`, `asterius-jose`, `asterius-server`) implement those traits
and are chosen once, in the composition root. Consequences:

- a protocol rule is tested against the normative text without a database, a
  TLS listener or a runtime — which is what keeps the test suite fast enough to
  run on every edit;
- the storage engine and the crypto provider can be swapped without touching a
  line of protocol logic;
- `scripts/check-layering.sh` fails CI if `asterius-domain` or `asterius-oidc`
  can reach `sqlx`, `axum`, `tokio`, `hyper`, `reqwest` or `askama` — directly
  *or transitively*.

Every crate root carries `#![forbid(unsafe_code)]`, enforced by the same script.
Cross-cutting lints (clippy pedantic, `rust_2018_idioms`) are declared once in
the workspace manifest and inherited with `[lints] workspace = true`.

## Standards

| Area | Specification | Status |
|---|---|---|
| Security baseline | FAPI 2.0 Security Profile & Attacker Model | Final |
| Core | OpenID Connect Core / Discovery / Dynamic Registration; OAuth 2.0 (RFC 6749/6750), PAR (RFC 9126), PKCE (RFC 7636), DPoP (RFC 9449), JWT access tokens (RFC 9068), `iss` response parameter (RFC 9207), resource indicators (RFC 8707), introspection (RFC 7662), revocation (RFC 7009), AS metadata (RFC 8414), DCR (RFC 7591/7592), mTLS (RFC 8705, optional) | Final / RFC |
| Logout | RP-Initiated Logout, Back-Channel Logout | Final |
| Agents | Token Exchange (RFC 8693), Rich Authorization Requests (RFC 9396), Device Authorization Grant (RFC 8628), CIBA Core 1.0 (poll/ping), MCP Authorization (confidential clients) | Final / RFC |
| Continuous access | Shared Signals Framework 1.0, CAEP 1.0, RISC 1.0 | Final |
| Authorization decisions | AuthZEN Authorization API 1.0 | Final |
| Consent lifecycle | Grant Management for OAuth 2.0 | Implementer's Draft — behind a feature flag |
| Tracked, not implemented | FAPI 2.0 Message Signing, Client ID Metadata Documents, Identity Assertion Authorization Grant, Native SSO, Provider Commands, IPSIE | Drafts |

**Deliberately out of scope for v1:** SAML, LDAP, verifiable credentials (OID4VCI/VP), OpenID Federation, Identity Assurance. The claims model is issuer-agnostic so these can be added later without a schema rewrite.

## Security posture

- Threat model derived from the FAPI 2.0 Attacker Model (A1–A5) plus agent-specific threats (delegation-chain abuse, confused-deputy MCP servers, approval fatigue). Every control links to a spec clause and a test.
- No refresh-token rotation (FAPI 2.0 SP §5.3.2.1), authorization codes ≤ 60 s, single-use codes with replay revocation, `jti` replay protection for client assertions and DPoP proofs.
- `#![forbid(unsafe_code)]` in every crate; constant-time comparison for every secret; opaque credentials stored only as hashes; private keys encrypted at rest.
- Definition of done for any protocol task: conformance-suite or spec-derived test passes, a fuzz target exists for every new parser/validator, the threat-model note is updated, no new `unsafe` — and generated crypto/parsing code is never "done" until a human has read the RFC.
- Target certification: OpenID FAPI 2.0 Security Profile (conformance suite runs in CI).

## Roadmap

The v1 backlog is tracked in [Beads](https://github.com/steveyegge/beads) for agent work and in GitHub Issues for the public roadmap. It is organised as 17 epics / 130 stories, one story per spec section or endpoint, each with acceptance tests derived from the normative text:

| Epic | Scope |
|---|---|
| E01–E04 | Foundation, key management & JOSE, clients & registration, discovery |
| E05–E09 | PAR & authorization endpoint, authentication & sessions (passkeys), consent & grants, token endpoint & DPoP, introspection/revocation/UserInfo |
| E10 | Logout & session lifecycle |
| E11 | AI-agent-native authorization (token exchange, device flow, CIBA, approvals inbox, MCP profile, per-agent audit) |
| E12 | Shared Signals / CAEP transmitter |
| E13 | AuthZEN policy decision point |
| E14–E16 | Admin API & console, theming & templates, hardening, conformance & release |
| E17 | Tracked specifications (not implemented) |

See [`docs/BACKLOG.md`](docs/BACKLOG.md) for the full breakdown and `scripts/beads-import.sh` to load it into a Beads repo (`bd init --prefix ast && ./scripts/beads-import.sh`, then `bd ready`).

## Getting started

Not yet — there is no runnable release. When there is, the goal is:

```sh
docker compose up          # PostgreSQL + Asterius + seeded tenant
open https://localhost:8443/t/demo/.well-known/openid-configuration
```

## Contributing

Contributions are welcome once the foundation epics land. Until then, the most useful help is reviewing the backlog against the specs and opening issues where a MUST is missing or misread.

Ground rules:

- Protocol behaviour follows the spec text; where a common implementation disagrees, we follow the spec and document the interop risk.
- Pull requests are small and reviewable; every parser gets a fuzz target; every security-relevant change updates `docs/threat-model.md`.
- Anything that weakens the FAPI 2.0 baseline, adds unjustified complexity, or re-introduces an out-of-scope protocol will be pushed back on — with a compliant alternative.

Language: English for code, identifiers, commits and ADRs. Issues and discussions in English or French.

## License

TBD (Apache-2.0 intended). Until a `LICENSE` file is committed, all rights reserved.
