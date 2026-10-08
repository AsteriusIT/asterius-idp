# IPSIE SL1 OpenID Provider readiness

This is an OP-role gap matrix, not an IPSIE conformance statement. The
[SL1 OpenID Connect draft](https://openid.github.io/ipsie-openid-sl1/draft-openid-ipsie-sl1-profile.html)
now publishes the 29 September 2026 revision, expiring 2 April 2027. Its source
repository HEAD checked on 8 October 2026 is
`4130f7418c2944b150d585c8d4f26e4a11d7023e`; the fetched HTML SHA-256 is
`21fafe24fdeffb29384cf1f7432b4404c65c0ec1cc68d9c8280ce838af0ceacf`.
The [Common Requirements draft](https://openid.github.io/ipsie-common-requirements-profile/draft-ipsie-common-requirements-profile.html)
still publishes 20 August 2025, expired 21 February 2026; fetched HTML SHA-256 is
`5de8852b00e9c64b9a5a82bd97f478b3a71bfa80f1544aedc77bf980eab0a91f`.
The user approved adopting the 29 September 2026 SL1 revision on 8 October 2026.
The Common Requirements pin remains the referenced draft baseline. No metadata
or console control claims IPSIE; deployment and independent evidence must still
satisfy the matrix before such a claim.

The adopted SL1 §3.2.1 adds these profile obligations:

| Obligation in 29 September 2026 revision | Candidate gap |
| --- | --- |
| `session_expiry` at least `iat + 300` | Selected clients require an explicit 300–86400 second policy. Configuration rejects shorter or absent deadlines, and issuance independently refuses them. |
| Satisfy one requested `acr_values` class or return an error | Selected-profile PAR persists requested ACR classes as an essential claim, intersecting any existing essential constraint. Authorization, authentication and consent then require a matching attainable class; contradictions fail before persistence. |
| Support a class requiring at least two distinct factors | Authorization and issuance require an attainable class with distinct factors: password plus possession, or a user-verified passkey. Actual deployment and RP checks remain necessary. |

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
| Preregister clients; no unauthenticated dynamic registration | Default registration policy is closed in `crates/server/src/http/register.rs`, but tenant configuration can enable other policies for ordinary clients. A client listed in `ipsie_identity_only_client` cannot be created by dynamic registration (the ID is server-minted), materialized from a self-hosted CIMD URL, or replaced through RFC 7592 client-managed PUT. Provision and replace it through the authenticated tenant-admin API; keep a selected ID in the operator list across updates. A CIMD client selected after earlier materialization cannot use that route and must be reprovisioned through protected administration with a new server-minted ID. Registration-access-token GET and DELETE remain available to a client that already holds that credential; revoke legacy credentials and review existing rows during rollout. The general tenant registration setting remains an operator responsibility, and this guard does not establish full SL1 conformance. |
| Access tokens used by the RP only for identity claims at the OP | General clients can request resource-server audiences. An operator may list candidates in `ipsie_identity_only_client`, independently of the HTTPS callback list. For those clients, registration writes require authorization-code and optional refresh grants, `openid` plus only `profile`, `email`, `address`, `phone`, or `offline_access` scopes, no authorization details or agent profile, and exactly the tenant issuer in the client resource allow-list. PAR/direct authorization reject external resources and nonidentity requests; token dispatch refuses other grants, and code/refresh issuance rejects any resolved audience other than the issuer. The tenant issuer must be registered as a resource server and assigned to the client; missing setup fails closed. UserInfo accepts this issuer-audienced access token. Access tokens minted before this setting was enabled remain valid until expiration or revocation. This constrains what the OP issues; the OP cannot establish where an RP actually presents the token. No IPSIE conformance claim. |
| Sender-constrained access tokens with DPoP | This is a SHOULD in the OP subsection. Public clients require DPoP-bound access tokens; refresh redemption now requires their original DPoP key even when tenant optional pinning is off for confidential clients (`crates/server/src/http/refresh.rs`). Other client profiles may use different sender constraints. |
| ID-token `aud` is one string | `crates/oidc/src/tokens/id_token.rs` emits the registered client ID as a single JSON string. |
| ID-token `auth_time` | The builder always emits the actual authentication time. Session and grant snapshot logic in `crates/server/src/http/issuance.rs` preserves it across refresh. |
| ID-token `acr` and `amr` | ACR is assigned from the tenant's ladder and revalidated against recorded methods; unsupported essential ACR requests fail. ID-token AMR uses only IANA entries backed by the recorded ceremony: `pwd`, `otp`, `pop` for a verified WebAuthn signature, and `user` after WebAuthn user verification. The internal existing-session marker is omitted, and historical `swk` rows are read as key possession without asserting software storage. For clients listed in `ipsie_identity_only_client`, code and refresh ID-token issuance now fails closed unless the current ladder validates the recorded ACR and policy releases at least one evidence-backed IANA AMR value. The operator must configure an attainable ACR ladder with AMR release enabled and must reauthenticate clients with old or insufficient grant evidence. Ordinary OIDC clients retain optional claim behavior. This is a bounded candidate control, not full SL1 support. |
| ID-token integer `session_expiry` | An operator may configure `[[tenant.ipsie_rp_session]]` with `client_id` and `lifetime_seconds` (300–86400) for a client also listed in `ipsie_identity_only_client`. Code-flow and refresh ID tokens for that client carry a server-issued integer Unix deadline equal to this ID token's `iat` plus the policy duration. A refreshed ID token therefore renews the RP session deadline; its `auth_time` still reports the original authentication. Unlisted clients omit the claim. The deadline is independent of OP browser session expiry and user claims. Migration 0128 archived historical user claims of this name, which cannot supply the server-issued value. This is a bounded claim issuer. Shorter durations and missing selected-client policies are rejected. This does not establish full IPSIE SL1 conformance. |

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
| Offer encrypted back-channel assertions | An RP may register `id_token_encrypted_response_alg`/`enc` and `userinfo_encrypted_response_alg`/`enc` as the fixed pair RSA-OAEP-256/A256GCM. UserInfo encryption requires a registered signing algorithm. The RP must register an inline public JWKS with exactly one eligible `use=enc` RSA key; the server refuses private material, ambiguous keys, unsupported values, explicit null and incomplete pairs. The client row stores both opt-ins atomically; readback revalidates the JWKS. Code/refresh ID-token issuance and UserInfo sign first, then wrap the signed JWT as RFC 7516 compact JWE with `cty=JWT`; an encryption error fails issuance without a plaintext fallback. Registration responses echo the selected pair, and Discovery lists the supported algorithms. Key rotation requires replacing the registered key set; simultaneous eligible encryption keys are refused until a future explicit key-selection policy exists. Native Keycloak 26.7.4 encrypted ID-token and signed UserInfo interoperability passed on 8 October 2026, including a separately selected-client deployment; see the pinned evidence below. Formal profile conformance evidence remains uncollected. This offering alone does not establish IPSIE SL1 conformance. |
| Encrypt front-channel assertions | Selected identity clients accept code responses only via query or form_post and cannot overlap the unencrypted Message Signing JARM profile. The code response contains no identity assertion. Ordinary clients retain their separately configured response modes. |
| Alternative/break-glass authentication rules | The draft places these on *applications* (RPs). They are not OP implementation obligations, though an OP deployment may impose its own operational controls. |
| Security-control program | Common §3.1 explicitly labels its text non-normative. Operator documentation and independent evidence would still be needed before any assurance claim. |

The Common Requirements draft's RP-only account-linking and cross-tenant
subject-keying instructions do not become OP requirements. Likewise, the
SL1 draft's third-party-initiated-login and DPoP-nonce RP requirements are not
proof of OP support. No conformance suite has been run for this profile.

## Independent selected deployment evidence, 2026-10-08

The [selected RP harness](../scripts/integrations/ipsie_selected_browser.mjs)
passed 19 checks on a separate owned tenant/database configured with the HTTPS
and identity-only client lists, a 300-second RP policy, issuer-only identity
resource and the default attainable ACR ladder. The
[sanitized result](integrations/evidence/ipsie-selected-rp-2026-10-08.json)
pins source `0b4c7a4a4486fb981ac18dac39b9a8431065accc` and the exact binary hash.
Native Keycloak 26.7.4 requested password ACR through its owned broker and
completed its real downstream RP callback after decrypting the nested ES256 ID
token and signed UserInfo as RSA-OAEP-256/A256GCM JWE.

A second independent RP phase replaced only that owned client's encryption
public key with an ephemeral RSA key, preserving Basic authentication and all
profile controls. Native Node crypto decrypted the real response and verified
the nested ES256 signature against Asterius JWKS. The original JSON
`session_expiry` and `iat` were integers with a difference of 300 seconds;
issuer, audience and nonce matched the request. The signed token reported
`acr=urn:asterius:acr:pwd` and `amr=["pwd"]`, without inventing MFA. Discovery
advertised the attainable user-verified passkey class. An unsupported selected
ACR returned `unmet_authentication_requirements` and no authorization code.
Signed encrypted UserInfo used the same subject as the ID token. The original
native Keycloak encryption JWKS was restored and verified after the run.

The [portable fixture helper](../scripts/integrations/ipsie_selected_fixture.py)
accepts private output-manifest and public encryption-JWKS paths plus the
approved Keycloak issuer. It reuses the owned product fixture and existing
runtime/database environment variables. Its preconfigured selected client is
fixture setup, not evidence of protected registration. The browser harness
requires private mode-0600 input keys `manifest`, `keycloakPrivate`,
`keycloakIssuer`, `publicRelay`, `relayMetrics` and `evidence`; set the installed
Playwright module and owned PostgreSQL container as for the OIDC adversarial
harness. Native broker credentials, codes, tokens and private encryption keys
remain private; the temporary RP private key stays in memory.

The [selected TLS probe](integrations/evidence/ipsie-selected-tls-2026-10-08.json)
on the same source revision refused TLS 1.0/1.1, accepted TLS 1.2/1.3 with
ECDHE/AES-GCM, and observed a one-year HSTS header with `includeSubDomains` and
`preload`. Discovery returned no CORS allow-origin header. The browser accepts
the disposable local self-signed certificate; native peer back-channel and
relay backend certificate validation remain active. This probe does not prove
production DNSSEC, certificate deployment or HSTS preload registration.

This proves selected-client password behavior and independent RP consumption
on the controlled deployment. It does not claim a hardware MFA ceremony,
production edge readiness, formal IPSIE certification, or conformance to every
row above. The separate ordinary-OIDC JWE evidence is linked from
[identity brokering](identity-brokering.md); it does not prove the selected
profile boundary by itself.

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
make
registration policy non-bypassable, issue truthful mandatory ID-token claims,
validate back-channel JWE against an independent RP, collect TLS/operator evidence, and run the
relevant OpenID interoperability and conformance plans. Until those gaps are
closed, this matrix remains a readiness record only.
