# IPSIE and OpenID enterprise draft readiness

This is a tracking note, not a conformance statement. It records the seams and
known gaps that are cheap to preserve while the specifications are working
documents. It must be re-audited clause by clause when the IPSIE Common
Requirements and SL1 profile become OpenID Implementer's Drafts; until then,
changes in either draft do not create v1 product requirements.

Status was checked against OpenID Foundation publications on 2026-09-19.

## Maturity checkpoint

| Work | Revision checked | Status and consequence |
|---|---|---|
| [IPSIE Common Requirements](https://openid.github.io/ipsie-common-requirements-profile/draft-ipsie-common-requirements-profile.html) | `latest`, published 2025-08-20 | Working document predating an Implementer's Draft. It still contains editorial removal notes and an unfinished security section, and its Internet-Draft snapshot has expired. Keep the matrix below provisional. |
| [IPSIE SL1 OpenID Connect Profile](https://openid.github.io/ipsie-openid-sl1/draft-openid-ipsie-sl1-profile.html) | `latest`, published 2025-09-02 | Working document predating an Implementer's Draft whose Internet-Draft snapshot has expired. It incorporates the Common Requirements by reference. Do not claim SL1 support. |
| [OpenID Provider Commands 1.0](https://openid.net/specs/openid-provider-commands-1_0.html) | draft 02, 2025-09-25 | Working draft. No command endpoint, command token, callback, synchronous account operation or streaming tenant operation is implemented. |
| [OpenID Connect Enterprise Extensions 1.0](https://openid.net/specs/openid-connect-enterprise-extensions-1_0.html) | draft 01, 2025-09-25 | Working draft defining optional `session_expiry`, `tenant` and `aud_sub` ID-token claims and `domain_hint`/`tenant` request hints. None is advertised or emitted as an Enterprise Extensions feature. |

The trigger for turning this note into a maintained compliance gap list is an
OpenID Implementer's Draft of both IPSIE documents. Finalization of Provider
Commands or Enterprise Extensions is a separate trigger and does not by itself
authorize implementation.

## Provisional IPSIE gap map

The unit of comparison is Asterius acting as an OpenID Provider. Requirements
placed only on relying parties are outside the product role. “Aligned” means an
existing invariant happens to agree with the current draft; it does not mean
the project has passed an IPSIE conformance suite.

| Current draft area | Asterius today | Disposition |
|---|---|---|
| Common Requirements: TLS, HSTS, no CORS on the authorization endpoint, BCP 195, RFC 9525 | The FAPI baseline already owns these transport rules. | Aligned without IPSIE-specific code. Preserve the common HTTP/TLS path. |
| Common Requirements: RFC 8725; PS256, ES256 or Ed25519; key-size floors; no `none`; 128-bit credentials | The JOSE allow-list and credential types are FAPI invariants. | Aligned without IPSIE-specific code. |
| Common Requirements: minimize disclosed attributes and offer pairwise subject identifiers | Claims are consent/grant bounded, and clients may register for pairwise subjects. | Aligned in shape; a future audit must verify every disclosure path against the stabilized wording. |
| Common Requirements: offer encryption for back-channel assertions | ID tokens and JWT UserInfo responses are signed, but JWE response encryption is not implemented. | Gap. Do not add JWE solely for this draft. Revisit at Implementer's Draft together with key registration, algorithm metadata and nested-JWT rules. |
| Common Requirements: front-channel assertions must be encrypted | The only supported authorization response carries a short-lived code, not an identity assertion. | Not applicable to the current code-only flow. Reassess if a front-channel assertion response is ever added. |
| Common Requirements: security-control program, break-glass handling and provisioning-driven disablement | These include operator and relying-party obligations, not only protocol behavior. Asterius has no IPSIE deployment profile that evaluates them. | Operational/profile gap. They need certification evidence and deployment guidance, not a hidden protocol flag. |
| SL1: discovery, no ROPC/open redirector, exact preregistered redirects, issuer-only assertion audience, code lifetime at most 60 seconds | These are existing OIDC/FAPI invariants. Authorization responses include RFC 9207 `iss`. | Aligned without a separate mode. |
| SL1: no `http` redirect URI | The FAPI baseline permits RFC 8252 loopback `http` redirects for native clients. | Profile gap. An SL1 profile would have to refuse that otherwise-valid registration without changing the FAPI baseline. |
| SL1: authorization code only, PKCE `S256`, one-use codes, 303 rather than 307, `nonce` through 64 characters, and `max_age` | The authorization path enforces these rules. | Aligned without IPSIE-specific code. |
| SL1: public clients | ADR-0002 and ADR-0012 deliberately allow confidential clients only. | Intentional incompatibility. Supporting SL1 requires a new tenant-scoped profile and ADR; it must not weaken the FAPI profile globally. |
| SL1: clients preregistered and no unauthenticated dynamic registration | Asterius can require pre-registration or protected registration, but registration policy is deployment configurable. | Profile gap. A future SL1 mode must make the closed/protected policy mandatory. |
| SL1: access tokens used only to retrieve identity claims at the OP | Asterius also issues audience-bound tokens for registered resource servers and administration protocols. | Profile gap. A future SL1 client/profile boundary must constrain token audiences without narrowing the general product. |
| SL1: DPoP sender constraint | The FAPI path already binds access tokens to DPoP; server-provided nonces are feature gated. The current SL1 text makes DPoP optional for the OP. | Stronger default, but a future profile must decide whether its RP-facing metadata promises nonce support. |
| SL1: ID-token `aud` is one string; `acr`, `amr`, `auth_time` and `session_expiry` are always present | `aud` is one string and `auth_time` is always present. `acr` and `amr` are omitted when no authentication policy/method value exists; `session_expiry` is absent. | Gap. Stabilized semantics are needed for a default `acr`, method registry mapping and RP-session expiry before changing token claims. |

## Adjacent drafts and compatibility seams

Provider Commands is not SSF or CAEP. The existing SSF transmitter delivers
asynchronous security-event tokens; it does not give an OP authority to invoke
synchronous account lifecycle, migration or audit procedures at an RP. Reuse
of signing keys, the outbox or subject mapping may be considered in a future
design, but no current endpoint or metadata may be described as Provider
Commands support.

Enterprise Extensions draft 01 currently gives the `session_expiry` claim a
direct relationship to the SL1 gap above. The other draft members must remain
unclaimed: Asterius's tenant-per-issuer model is not automatically the draft's
`tenant` claim, `login_hint` is not `domain_hint`, and a local subject mapping
is not the RP-owned `aud_sub`. The claims model is extensible enough to add
server-issued claims later, but those reserved claims require explicit issuer
logic and must never be copied from the user claim bag.

## Re-audit checklist

At the Implementer's-Draft trigger:

1. Pin the approved versions and replace this grouped snapshot with a
   clause-by-clause matrix for the OP role and the Common Requirements.
2. Separate code behavior, deployment obligations and relying-party-only
   requirements; attach tests or operational evidence to every applicable
   normative clause.
3. Resolve the public-client conflict and the access-token audience boundary
   through an ADR before adding a profile switch.
4. Design JWE response encryption and mandatory ID-token claims from the
   stabilized Enterprise Extensions dependency.
5. Run the relevant OpenID conformance plan before making any IPSIE readiness
   or support claim.
