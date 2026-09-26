# IPSIE SL1 OpenID Provider readiness

This is an OP-role gap matrix, not an IPSIE conformance statement. The
[SL1 OpenID Connect draft](https://openid.github.io/ipsie-openid-sl1/draft-openid-ipsie-sl1-profile.html)
(2 September 2025) incorporates the
[Common Requirements draft](https://openid.github.io/ipsie-common-requirements-profile/draft-ipsie-common-requirements-profile.html)
(20 August 2025). Both `latest` pages were checked on 26 September 2026. Both
Internet-Draft snapshots have expired, and neither page is an Implementer's
Draft. Clauses and interpretation may change. No metadata or console control
claims an IPSIE profile today.

“Implemented” below means the named code path has the stated behavior, not
that deployment or interoperability evidence has been collected. Relying-party
requirements are excluded unless they constrain something this OP offers.

## SL1 §3.2.1: OP obligations

| Draft obligation | Current OP path and result |
|---|---|
| Discovery metadata | Implemented by `crates/oidc/src/metadata.rs` and `crates/server/src/http/protocol.rs`. Metadata is tenant-specific. |
| Reject resource-owner password grant | Implemented by the token endpoint's grant-type dispatch; no password grant handler. |
| Support public clients | Implemented in `crates/domain/src/entities/client.rs` and client authentication. Tenant administration must explicitly select the `public` client compliance profile; dynamic registration uses FAPI. A deployment must verify this registration path before claiming this row. |
| No open redirector; preregistered, exact redirect URI | Implemented in client registration and `crates/oidc/src/authorize.rs`. Native loopback-port variation is allowed by the general product and is a separate SL1 conflict below. |
| Client assertion `aud` is the issuer string only | Implemented by client authentication validation; recheck all accepted assertion methods when defining an IPSIE profile. |
| Authorization code lifetime at most 60 seconds | `crates/domain/src/entities/tenant_settings.rs` caps the configured lifetime at 60 seconds; the authorization path uses that tenant value. |
| Preregister clients; no unauthenticated dynamic registration | Default registration policy is closed in `crates/server/src/http/register.rs`, but tenant configuration can enable other policies. An SL1 deployment must keep registration closed or protected and audit every registration channel. This is not an enforced IPSIE profile invariant. |
| Access tokens used by the RP only for identity claims at the OP | General clients can request resource-server audiences. No SL1 client boundary constrains audiences and scopes to UserInfo. Open gap. |
| Sender-constrained access tokens with DPoP | This is a SHOULD in the OP subsection. Public clients require DPoP-bound access tokens; refresh redemption now requires their original DPoP key even when tenant optional pinning is off for confidential clients (`crates/server/src/http/refresh.rs`). Other client profiles may use different sender constraints. |
| ID-token `aud` is one string | `crates/oidc/src/tokens/id_token.rs` emits the registered client ID as a single JSON string. |
| ID-token `auth_time` | The builder always emits the actual authentication time. Session and grant snapshot logic in `crates/server/src/http/issuance.rs` preserves it across refresh. |
| ID-token `acr` and `amr` | ACR is assigned from the tenant's ladder and revalidated against recorded methods; unsupported essential ACR requests fail. ID-token AMR uses only IANA entries backed by the recorded ceremony: `pwd`, `otp`, `pop` for a verified WebAuthn signature, and `user` after verified user presence. The internal existing-session marker is omitted, and historical `swk` rows are read as key possession without asserting software storage. No SL1 profile currently requires a configured ACR and AMR release for every issuance; voluntary `acr_values` retain OIDC Core behavior. Open profile gap. |
| ID-token integer `session_expiry` | Not server-emitted. Migration 0128 archives historical user claims under this name (including language-tagged variants) before `ClaimName::SERVER_ISSUED` reserves it; the old value is never used as an RP deadline. Browser session expiry is not automatically an RP session expiry, and offline refresh can outlive a browser session. A distinct RP session policy and issuer path are still open gaps. |

## SL1 §3.2.1: authorization-code obligations

| Draft obligation | Current OP path and result |
|---|---|
| `response_type=code`, PKCE S256, one-use codes | Implemented by `crates/oidc/src/authorize.rs` and code redemption. |
| Exact registered redirect URI; no HTTP callback | Ordinary HTTPS URIs use exact registration matching. An operator can list client IDs in the tenant's `ipsie_https_only_client` setting: admin create/update, dynamic registration, client ID metadata discovery, and registration-management PUT reject non-HTTPS callbacks for selected IDs. PAR and direct authorization also reject every non-HTTPS callback, including native HTTP loopback, while ordinary clients retain native support. Configuration load validates list shape and duplicates. Existing registrations may still contain HTTP URIs until updated, but cannot start new authorizations while selected; a request or interaction already stored before this setting is enabled can still complete. Other profile controls are still open. |
| Authorization response `iss` | Emitted by the authorization response path (RFC 9207). |
| No credential-bearing 307 redirect; prefer 303 | Browser redirect helper in `crates/server/src/http/redirect.rs` uses 303. |
| `nonce` values through 64 characters | `crates/oidc/src/authorize.rs` accepts up to 256 bytes and the ID-token builder echoes the value. |
| `max_age` reauthentication | Authorization decision uses session `authenticated_at`; stale authentication requires an active step-up. |

## Common Requirements §§3.2–3.4: OP-relevant obligations

| Draft obligation | Current OP path and result |
|---|---|
| TLS 1.2+, BCP 195 ciphers, HSTS, DNSSEC SHOULD, certificate verification | Deployment controls. The app's HTTPS issuer and transport assumptions do not prove the edge proxy's TLS settings, certificate checks, preload status or DNSSEC. Collect deployment evidence; do not claim these from code alone. |
| No CORS on authorization endpoint | The server has no CORS layer (`crates/server/src/http/server.rs`). Recheck the deployment proxy. |
| RFC 8725, allowed JWT algorithms, key sizes, no `none`, 128-bit credential entropy | JOSE and credential code constrain these values for their respective paths. A profile audit must enumerate every JWT type and key-import path; the current matrix is not that audit. |
| Minimize account-attribute disclosure | Claims resolution and grant/consent paths narrow ordinary releases. An enterprise deployment still has to configure scopes, audiences and claims providers for minimum disclosure. |
| Offer pairwise subject identifiers | Pairwise client sectors exist in `crates/domain/src/entities/user.rs`; public-client registration uses its own sector behavior. Availability for each RP needs registration evidence. |
| Offer encrypted back-channel assertions | Signed ID tokens and JWT UserInfo exist; nested JWE response encryption, RP encryption-key registration and associated metadata do not. Open gap. |
| Encrypt front-channel assertions | Current authorization-code response contains no identity assertion; a future JARM or other front-channel assertion must be assessed separately. This is not evidence for a claim of universal front-channel encryption. |
| Alternative/break-glass authentication rules | The draft places these on *applications* (RPs). They are not OP implementation obligations, though an OP deployment may impose its own operational controls. |
| Security-control program | Common §3.1 explicitly labels its text non-normative. Operator documentation and independent evidence would still be needed before any assurance claim. |

The Common Requirements draft's RP-only account-linking and cross-tenant
subject-keying instructions do not become OP requirements. Likewise, the
SL1 draft's third-party-initiated-login and DPoP-nonce RP requirements are not
proof of OP support. No conformance suite has been run for this profile.

## Adjacent drafts

[Provider Commands](https://openid.net/specs/openid-provider-commands-1_0.html)
is separate from SSF/CAEP. This OP can send signed invalidate/delete Account
Commands to an RP's explicitly registered HTTPS command endpoint when a
supported account lifecycle action occurs. Delivery uses a durable intent,
fresh token signing, guarded transport and outcome audit. This does not make
this deployment an RP command receiver, establish IPSIE SL1 conformance, or
provide interoperability evidence against an independent RP.

[OpenID Connect Enterprise Extensions](https://openid.net/specs/openid-connect-enterprise-extensions-1_0.html)
defines `session_expiry`, `tenant`, `aud_sub` and request hints. The tenant-per-
issuer model is not automatically that draft's `tenant` claim, and a local
subject mapping is not RP-owned `aud_sub`. None is advertised as Enterprise
Extensions support. `session_expiry` must come from explicit OP policy rather
than a user claim or an unexamined browser-session timestamp.

## Before claiming SL1 support

Pin an approved revision, define a complete tenant/client profile boundary,
enforce identity-only token audiences for those clients, make
registration policy non-bypassable, issue truthful mandatory ID-token claims,
implement back-channel JWE, collect TLS/operator evidence, and run the
relevant OpenID interoperability and conformance plans. Until those gaps are
closed, this matrix remains a readiness record only.
