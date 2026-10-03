# Architecture decision records

One file per decision, numbered in the order they were taken. A record is
immutable once merged: a decision that is later reversed gets a *new* record
that supersedes the old one, and the old one gains a `Superseded by` line. The
log is the answer to "why is it like this?" six months from now.

Copy [`0000-template.md`](0000-template.md) to start one.

| # | Decision | Status |
|---|---|---|
| [0001](0001-modular-monolith.md) | Modular monolith, single binary, one PostgreSQL | Accepted |
| [0002](0002-fapi-2-0-as-the-only-mode.md) | FAPI 2.0 is the baseline, not a mode | Superseded by 0014 |
| [0003](0003-signing-algorithm-set.md) | Signing algorithms: EdDSA, ES256, PS256; RS256 is non-FAPI | Accepted |
| [0004](0004-jose-on-aws-lc-rs.md) | JOSE is built on aws-lc-rs, not on a JOSE library | Accepted |
| [0005](0005-exact-redirect-uri-matching.md) | Redirect URIs match exactly against the registered set, including under PAR | Accepted |
| [0006](0006-outbound-fetches-of-client-supplied-urls.md) | How this server dereferences a URL a client chose | Accepted |
| [0007](0007-webauthn-without-webauthn-rs.md) | WebAuthn relying-party verification is written here, not taken from webauthn-rs | Accepted |
| [0008](0008-the-pairwise-salt-is-not-cached.md) | The pairwise salt is decrypted per mint and not cached | Accepted |
| [0009](0009-the-admin-console-is-a-first-party-same-origin-app.md) | The admin console is a first-party same-origin app, not an OAuth client | Accepted |
| [0010](0010-deployment-admins-live-in-a-reserved-tenant.md) | Deployment admins are users of a reserved tenant | Accepted |
| [0011](0011-a-declarative-rule-model-for-the-built-in-pdp.md) | The built-in PDP evaluates declarative rules, not a policy language | Accepted |
| [0012](0012-mcp-clients-remain-confidential.md) | Public OAuth clients are an explicit tenant exception; CIMD is not implemented | Accepted |
| [0013](0013-openid-federation-remains-out-of-v1.md) | OpenID Federation remains out of v1 without narrowing the client model | Accepted |
| [0014](0014-explicitly-gated-standard-oidc-clients.md) | Standard OIDC clients are explicit tenant and application opt-ins | Accepted |
| [0015](0015-certify-the-fapi-profile-only.md) | Certify the FAPI profile only; do not add a conformance mode | Accepted |
| [0016](0016-ciba-assertion-audience.md) | Keep the CIBA assertion audience profile scoped to CIBA | Accepted |
| [0017](0017-id-jag-draft-profile.md) | Explicit enterprise approval for ID-JAG issuance | Provisional |
| [0018](0018-oid4vp-verifier-profile.md) | Narrow OID4VP verifier profile | Provisional |
| [0019](0019-caep-interop-algorithm-boundary.md) | Keep CAEP Draft 01 outside the supported SSF receiver profile | Accepted |

The modern IDP decisions use descriptive filenames to avoid concurrent numbering:

| Decision | Status |
| --- | --- |
| [Kubernetes human access](kubernetes-human-access.md) | Approved design; controlled signature interoperability verified |
| [External workload trust](external-workload-trust.md) | Approved design; runtime and direct secretless bootstrap tracked separately |
| [Declarative management v1](declarative-management-contract.md) | Accepted architecture; runtime tracked in ast-dd1y.3.2 |
| [Trusted conditional access](trusted-conditional-access-context.md) | Decided; enforcement tracked separately |
| [Managed device posture](managed-device-posture-source.md) | Decided relay and PKI model; runtime tracked in ast-dd1y.4.5 |
| [Temporary entitlement activation](temporary-entitlement-activation.md) | Decided; implementation tracked separately |
| [Task-bound agent grants](task-bound-agent-grants.md) | Accepted; enforcement tracked in ast-dd1y.8.2 and ast-dd1y.8.3 |
