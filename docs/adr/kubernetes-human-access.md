# Kubernetes human access uses a confidential browser-login broker

- **Status:** Proposed; implementation and human normative review outstanding
- **Date:** 2026-10-03
- **Bead:** ast-dd1y.1.1
- **Refines:** [ADR-0014](0014-explicitly-gated-standard-oidc-clients.md)
- **Preserves:** [ADR-0003](0003-signing-algorithm-set.md)

## Context and source evidence

Kubernetes authenticates an OIDC ID token as a bearer credential. It does not
enforce DPoP, consult OAuth revocation, or continuously resolve group membership.
The intended cluster audience must therefore be isolated from application and
administration audiences, and expiry must bound stale identity information.

The ticket's premise that Asterius only supports confidential clients and HTTPS
callbacks is stale. `crates/domain/src/entities/client.rs` implements the gated
`Public` profile, PKCE, DPoP and native HTTP loopback redirects with port
variation; [ADR-0012](0012-mcp-clients-remain-confidential.md) describes that
exception. ADR-0014 remains the confidential OIDC opt-in. Neither exception
changes the defaults of existing FAPI applications.

`crates/oidc/src/tokens/id_token.rs` currently issues a single client-ID `aud`,
defaults ID-token lifetime to five minutes, and emits managed groups as
`group_ids`. `crates/server/src/http/issuance.rs` uses the registered
`id_token_signed_response_alg` and fails when no matching tenant key exists.
It does not issue an arbitrary cluster audience separate from the client ID.

## Chosen contract

Use an operator-run confidential login broker and a kubectl exec helper as
components of one relying party. Register **one confidential OIDC client per
cluster and tenant**, explicitly selecting `compliance_profile=oidc` only on a
tenant with `allow_non_fapi_clients=true`. This distributed relying party is a
Kubernetes compatibility integration; do not label its bearer cluster access as
FAPI conformant. FAPI registrations, PAR enforcement and sender constraints
remain unchanged.

The broker owns the client authentication key, DPoP key, authorization state and
OAuth refresh tokens. The helper never contains a client secret, an OP refresh
token or the broker's private keys. Broker credentials are provisioned through
the existing confidential-client registration path, protected by the operator's
secret store, and rotated individually. Use `private_key_jwt`, S256 PKCE and
DPoP-bound OAuth access/refresh tokens; do not select the existing OIDC Bearer
exemption. The broker uses PAR and verifies the exact issuer, signature,
algorithm, audience, nonce and PKCE transaction binding before releasing an ID
token. DPoP protects the broker's OAuth token use; it cannot protect the ID token
at the Kubernetes API boundary.

Browser flow:

1. The helper creates a per-login ephemeral proof key and starts a bounded
   transaction at the pinned HTTPS broker, identifying an operator-registered
   cluster. The broker chooses the issuer, client and callback from its own
   allow-list; request input cannot choose an issuer or token endpoint.
2. The helper opens the system browser at a broker URL carrying only a random,
   short-lived transaction reference. The broker creates independent random
   OAuth state, nonce and verifier, stores them server side, pushes the request
   and redirects to Asterius. No token or reusable credential enters a URL.
3. Asterius returns the code to the preregistered **exact HTTPS broker callback**.
   The broker validates the browser transaction, exchanges the one-use code and
   verifies the ID token. It displays the cluster and account and requires an
   explicit browser confirmation to bind the CLI transaction. A transaction
   expires after five minutes and can complete only once.
4. The helper polls over HTTPS using its proof key and a separate random secret
   never included in the browser URL. The broker returns the verified ID token
   and a broker session handle bound to the helper key. A copied transaction
   reference alone cannot claim the result. Responses are `no-store`.
5. The helper emits `client.authentication.k8s.io/v1` `ExecCredential` JSON with
   `status.token` and `status.expirationTimestamp` derived from verified `exp`.
   It checks kubeconfig's pinned cluster/issuer/broker association before login;
   kubeconfig contains the helper invocation, not a token or private key.

This rendezvous is a broker API, **not RFC 8628 device authorization**. Headless
users may open the same confirmation URL on another trusted device; the broker
must show what cluster and CLI transaction they are authorizing. There is no
new device grant, localhost OAuth callback or public-client exception in this
decision. A full RFC 8628 implementation needs a separate reviewed contract.

## Claims, cluster configuration and signing

| Field | Contract |
|---|---|
| `iss` | Exact HTTPS tenant issuer, pinned in broker and API server |
| `aud` | Single client-ID string unique to this cluster/tenant |
| `sub` | Stable server-issued subject; never email or display name |
| `iat`, `exp` | Existing five-minute ID-token lifetime; broker rejects longer tokens |
| `nonce` | Bound to the browser authorization transaction |
| `group_ids` | Existing bounded server-managed stable group identifiers, explicitly released for this client; absent means no groups |
| `auth_time`, `acr`, `amr` | Existing validated authentication evidence; no invented MFA claim |
| `sid` | Existing optional OP session identifier; not a Kubernetes revocation mechanism |
| JOSE | `alg=ES256`, provisioned P-256 tenant signing key and matching `kid` in public JWKS |

Do not mint a multi-cluster audience, use admin access tokens, or make email the
authorization identity. Apply a distinct nonempty username prefix such as
`asterius:<tenant>:<cluster>:` and a group prefix such as
`asterius:<tenant>:<cluster>:group:`. Group names from external identity
providers are not Kubernetes grants; explicit managed-group membership and
client release policy control them. Kubernetes RoleBindings remain operator
managed. Prefixes prevent collision with `system:` identities.

For a single-issuer cluster use these API-server flags, replacing placeholders
with operator-reviewed literals (these are deployment requirements, not a claim
that the local cluster has been reconfigured):

```text
--oidc-issuer-url=https://auth.example/t/team
--oidc-client-id=<unique-cluster-client-id>
--oidc-signing-algs=ES256
--oidc-username-claim=sub
--oidc-username-prefix=asterius:team:cluster-a:
--oidc-groups-claim=group_ids
--oidc-groups-prefix=asterius:team:cluster-a:group:
--oidc-ca-file=<trusted-issuer-ca-bundle>
```

The CA path is required for a private CA; public CA deployments may use the
API server's system trust store. Do not disable certificate verification.
Discovery and JWKS must be reachable from the API server over trusted HTTPS.
For multiple issuers use a reviewed `AuthenticationConfiguration` instead of
mixing it with OIDC flags. Its algorithm behavior must be verified separately;
the `--oidc-signing-algs` choice here is for the legacy flag authenticator.
During signing-key rotation retain the previous public key for outstanding
five-minute ID tokens plus clock tolerance and observed JWKS propagation.

## Refresh, local storage and revocation

The broker rotates refresh tokens on the existing OP refresh path and keeps
them encrypted server side. Refresh must recheck the tenant/client enablement,
user status, session and current managed-group release policy. Never replay a
previous refresh credential after a failed or ambiguous rotation; reconcile
through the existing rotation semantics or require a fresh browser login.
Broker session handles expire within eight hours, with a fifteen-minute idle
limit, and cannot extend the OP session or override refresh rejection. Every
refresh request proves possession of the helper key. The broker serializes
refresh per session, checks returned issuer/audience/signature/expiry and
releases only the new ID token. A cached group set must not be reused.

Store the helper private key and broker handle in the OS credential store,
partitioned by issuer, cluster and account. If secure storage is unavailable,
use an in-memory session and require login after exit; no plaintext fallback.
The short-lived ID token may be cached in memory until an expiry margin of
thirty seconds. Never write credentials into kubeconfig, stdout logs,
telemetry, shell arguments or browser storage. Only ExecCredential output
contains the token on stdout; diagnostics go to stderr without credentials.
Logout erases local state, invalidates the broker session and revokes the
server-side OAuth grant where supported. Browser logout and OP back-channel
logout also terminate associated broker sessions.

An already issued ID token can still authenticate to native Kubernetes until
expiry. OP logout, group removal, user disablement and refresh revocation block
future issuance; they do not revoke the presented JWT. Native authentication
does not call Asterius introspection or process CAEP/SSF revocation events.
Removing RoleBindings can remove authorization immediately according to
Kubernetes propagation; emergency signing-key removal affects many users and
has JWKS-cache delay. Neither promises per-user instant token revocation.
Clusters needing that guarantee require a separately reviewed online
authenticator or access proxy with defined cache/availability semantics.

## Threat model and alternatives

| Threat/boundary | Required control and residual risk |
|---|---|
| CLI/browser account substitution | Independent OAuth state/nonce/PKCE; one-use transaction; account and cluster confirmation; key-bound result collection. Phishing a user into confirming an attacker's transaction remains a social risk. |
| Callback interception or open redirect | Exact operator-owned HTTPS callback, broker server-side code exchange; no helper-supplied callback or post-login redirect. |
| Broker session or token theft | OS key store, proof-key-bound handles, encrypted server-side refresh tokens, no-store responses, redaction. A stolen bearer ID token remains usable until `exp`. |
| Broker compromise | Broker can act as its cluster clients; isolate credentials and sessions per cluster, narrow network egress and audit issuance. This is a new high-trust service. |
| Cross-cluster/confused deputy | Distinct client audience, pinned issuer and cluster mapping; no caller-selected issuer/discovery URL or arbitrary audience. |
| Stale groups and user disablement | Re-evaluate on refresh, five-minute ID-token bound, operator-managed RBAC; no instant JWT revocation claim. |
| Refresh replay/concurrency | Existing rotation/reuse rejection and serialized broker refresh; invalidate compromised sessions and require reauthentication. |
| Malicious kubeconfig | Treat exec configuration as executable input; operator-approved helper and cluster mapping, no automatic arbitrary broker enrollment. |

The existing public native profile is a viable future alternative if a helper
implements its required DPoP flow, code-key binding and secure rotated refresh
storage. It avoids a broker but expands the managed endpoint credential
surface and needs independent CLI interoperability evidence; an arbitrary
stock kubectl OIDC helper cannot be assumed compatible. Individually
provisioned confidential CLI keys add enrollment and rotation burden. An
embedded shared client secret has no defensible confidentiality and is
rejected. The chosen broker trades a new service boundary for central refresh
handling and unchanged FAPI defaults.

## Evidence and release gates

On 2026-10-03 the local target `kind-asterius-local` reported Kubernetes
`v1.35.0`, commit `66452049f3d692768c39c797b21b793dce80314e`.
Read-only inspection of the running API-server command showed **no OIDC or
authentication-config flags**. Running that installed binary's `--help` via
`crictl exec` listed ES256 among its permitted `--oidc-signing-algs`; its default
is RS256. The version-pinned Kubernetes source also includes ES256 in the
authenticator allow-list. This validates the algorithm/configuration choice,
not successful authentication or interoperability with Asterius.

The selected configuration must still be exercised on a disposable configured
API server with actual Asterius ES256 ID tokens: authorized access, wrong
issuer/audience, expired/forged token, disallowed algorithm, absent groups,
cross-cluster use, signing rotation and disablement/refresh behavior. The
broker and helper described here are contracts, not implemented components.
`ast-dd1y.1.1` remains open until signing interoperability and human review of
the relevant normative text are recorded. Dependent work must not infer
approval from a proposed ADR or mark the integration supported.

## Normative and implementation references

- [Kubernetes authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens): ID-token authentication, claims, configuration and revocation limitations.
- [Kubernetes v1.35.0 OIDC authenticator](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go): algorithm allow-list and verifier configuration.
- [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation): ID-token validation and refresh requirements.
- [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252): external browser and native redirect alternatives.
- [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628): separate device grant and its phishing considerations.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449): DPoP proof and token binding; Kubernetes bearer use does not implement this resource-server protocol.
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700): authorization-code defenses and refresh-token protection.

These sources were checked for this proposed contract; this does not substitute
for the repository's required human normative review or an external interop run.
