# Kubernetes workload exchange

The approved [external workload contract](adr/external-workload-trust.md) is now
implemented on the existing token endpoint for enabled Kubernetes trust records.
Enable the deployment and tenant Token Exchange capability, register an
independent confidential client for the RFC 8693 grant with DPoP binding, register
its permitted resource servers and configure the tenant [workload trust](workload-trusts.md).

The projected JWT goes in `subject_token`, with
`subject_token_type=urn:ietf:params:oauth:token-type:jwt`. Client authentication
remains a separate `private_key_jwt` or mTLS operation. Kubernetes tokens cannot
be used as client assertions. A `private_key_jwt` client uses a registered FAPI
signing key; this recipe stores no OAuth client secret, but it still needs that
independent client key. DPoP possession alone does not authenticate the client.

Requests specify exactly one `resource` or equivalent `audience`, optionally
narrow `scope`, and present a fresh DPoP proof. No actor token, impersonation,
refresh token or ID token is supported. Issuer hints select an existing trust;
local-issuer JWTs stay on the local verification path without an external
fallback. The separate [GitHub profile](github-actions-workload-exchange.md)
shares issuance limits while enforcing its own workflow claims.

The response carries a DPoP-bound access token whose `sub` is the pinned
`workload:` principal and whose `act` names the independently authenticated
client. Output scopes intersect trust, client, agent policy and resource scope
ceilings. Resource widening fails. Output TTL is the minimum of the assertion
remaining lifetime, tenant/client ceiling and 300 seconds. The output always
carries a grant identifier so revocation and descendants remain traceable.

Assertion consumption, the grant, source provenance and issuance audit commit
in one transaction. The transaction locks and rechecks the current trust,
client allowlist, provider, principal, permissions, enabled state and revision.
A duplicate assertion cannot issue a second grant, even after trust deletion and
recreation. Signing occurs after the commit; if signing fails the assertion is
spent and the caller requests a fresh assertion. Consumed digests are retained
until expiry; workload grants follow bounded machine-grant retention after
expiry and preserve source provenance until their own deletion.

## Actions through RFC 9396

When an API needs actions beyond scopes, register the explicit tenant type
`urn:asterius:workload-actions`, using
[the sample schema](../examples/kubernetes/workload-exchange/actions-schema.json),
and add the type to the client's registered `authorization_details_types`.
Requests carry the existing `authorization_details` parameter, for example:

```json
[{"type":"urn:asterius:workload-actions","actions":["read"],"locations":["https://inventory.example/"]}]
```

The existing bounded RFC 9396 parser and tenant/client schema registry validate
the request. Each action must exactly match a configured trust action, and the
single location must equal the chosen permitted resource. Other types, extra
fields, empty or wider actions, unregistered client types and other locations
fail. The token and stored grant carry only these accepted details. Omitting
the parameter grants no actions. Resource servers must enforce actions as well
as issuer, audience, scopes and DPoP; an API that ignores this claim must not
rely on it for authorization.

## Projection and fresh assertions

The sample [pod manifest](../examples/kubernetes/workload-exchange/pod.yaml)
shows a trust-specific workload projection and a separate Kubernetes API
projection. Replace the image, issuer, client ID, audience, resource and key
mount with operator-controlled values; pin the ServiceAccount UID in the trust.
Neither this document nor the sample deploys anything.

One-use semantics require a new TokenRequest assertion for every mint. Merely
reading a projected workload file again can return the already-consumed token.
Kubelet rotation of a 600-second projected token can also occur after the local
300-second assertion-freshness window. The sample therefore grants explicit
named `serviceaccounts/token` creation authority and requests a fresh
600-second, pod-bound assertion per mint. This Kubernetes permission needs
operator review; it does not arise from OAuth client authentication.

The [Node client](../examples/kubernetes/workload-exchange/client.mjs) rereads the
Kubernetes API credential file on every TokenRequest, so kubelet symlink rotation
is respected. It binds the TokenRequest to the current pod name and UID, sends
independent ES256 client authentication and an ephemeral ES256 DPoP proof, and
calls the permitted API with an access-token-hash-bound DPoP proof. Nonce
challenges use a new client-authentication jti and fresh subject assertion.
Older issuers can return identical compact assertions for requests within one
second. The client detects an immediate duplicate digest and waits across the
next second before requesting again, with a bounded retry count. Server-side
one-use enforcement remains authoritative across processes.
TLS certificate checks and redirect refusal apply throughout; the client never
logs tokens or credentials. It is a reusable `apiCall()` module plus a one-call
CLI; production retry/backoff policy remains the application's responsibility.

## Pod deletion and verification

The approved profile uses offline pinned-key validation, without TokenReview.
Require pod-bound UID claims and reject assertions older than 300 seconds;
output lifetime never exceeds 300 seconds. A stolen unconsumed assertion issued
before deletion can therefore remain usable for at most 600 seconds from its
issuance, with up to the approved 30-second future clock skew. Trust disable
prevents the next mint and the transaction fence prevents a stale verification
from committing after disable. Already minted JWTs remain valid until expiry
unless the resource checks grant revocation. Removing a pod is not immediate
offline token revocation.

Controlled signed RSA TokenRequest-shaped fixtures traverse the real token
endpoint with independent client authentication and DPoP. They cover exact
cluster/namespace/ServiceAccount/UID/audience binding, expiry and stale tokens,
one-use replay, output scope/TTL/sender binding, fresh assertion reuse after a
rejected widening request and trust disable. This fixture is ignored locally
and reserved for CI with `DATABASE_URL`. The client test independently verifies real ES256
signatures and checks credential rotation, fresh TokenRequests and nonce
handling without network access:

```sh
node --test examples/kubernetes/workload-exchange/client.test.mjs
```

The separate [acceptance runner](../examples/kubernetes/workload-exchange/acceptance.mjs)
uses real Kubernetes TokenRequests, a running Asterius binary and a loopback TLS
resource server that verifies signatures, audience, scopes, actions and DPoP
proofs. It passed against disposable kind Kubernetes v1.35 on 2026-10-03: API
HTTP 200, output TTL 300 seconds, fresh assertion rotation, and denial of replay,
cluster issuer, namespace, ServiceAccount name/UID, audience, scope, resource,
action and client-authentication widening. A fresh assertion issued before pod
deletion was accepted within the documented offline bound, and disabling the
trust refused an unused fresh assertion. Each successful exchange had persisted
grant provenance. No production cluster or deployment was involved.

To repeat this controlled test, create a disposable `kind-asterius-dd1y<N>`
context and isolated `ast_dd1y<N>` database, start the current binary on localhost
with Token Exchange enabled and tenant `workload`, and create namespace
`workload-exchange-<N>` with ServiceAccount `inventory` and a pod of the same name
using that account. Supply `ACCEPTANCE_KUBECONFIG`, `ACCEPTANCE_CONTEXT`,
`ACCEPTANCE_DATABASE_URL`, `ACCEPTANCE_NAMESPACE`, `ACCEPTANCE_ISSUER`,
`ACCEPTANCE_CERTIFICATE`, `ACCEPTANCE_TLS_KEY` and `NODE_EXTRA_CA_CERTS`, then run
`node examples/kubernetes/workload-exchange/acceptance.mjs`. The loopback API
needs port 9450. The runner seeds test registrations, creates and cleans its
additional namespace/account fixtures, deletes the primary test pod, disables
its test trust, and optionally writes a credential-free `ACCEPTANCE_EVIDENCE`
JSON file. Its context/database/namespace guards refuse ordinary environments.

The standalone [OpenAPI profile](kubernetes-workload-exchange.openapi.json)
describes this form contract. The JWT issuer-routing parser and JWT/JWKS
validators share the `workload_token` fuzz target.
