# Optional online Kubernetes authentication — candidate

This adapter remains pending normative review and real acceptance. Do not enable
it from these instructions before delivery approval. The default Kubernetes
profile continues to use the separately documented offline broker flow.
See [the proposed contract](../adr/kubernetes-online-authentication.md) for the
trust boundary and the distinction between measured and source-derived bounds.

## Registration and opt-in

Keep the human client confidential OIDC, public subject, web application,
ES256-signed unencrypted ID tokens, managed group claim, one broker callback,
PAR/PKCE, private-key JWT, DPoP, `authorization_code`, `refresh_token` and `openid`.
Use a separate active non-agent FAPI reviewer with private-key JWT, DPoP,
**only** `client_credentials`, and `admin.kubernetes_reviews:read`. It requests the
exact tenant issuer plus `/admin/api/v1` as its resource. Neither registration
may be an agent-task client. Temporary Kubernetes RBAC and online mode cannot
be enabled together for the same human client.

An authorized tenant console administrator reads
`GET /t/<tenant>/admin/api/v1/clients/<human-client>/kubernetes/online`, then sends
`PUT` to that same path with the usual console CSRF proof and a body such as:

```json
{"reviewer_client_id":"cluster-reviewer","expected_revision":null,"enabled":true}
```

`expected_revision: null` creates a missing profile; replacing a profile requires
its returned UUID. A stale UUID conflicts. Each change creates a new revision
and invalidates old token bindings. Relevant human/reviewer metadata changes
terminally disable the profile; restoring metadata does not revive bindings.
Re-enable explicitly with the current revision and obtain newly issued tokens.
An offline token minted before opt-in cannot be enrolled through TokenReview.

## Authenticated adapter

Build `./cmd/asterius-token-review` from `providers/terraform`. Store the reviewer
ES256 PKCS8 key in an operator-owned secret file; register its public JWK and
`kid` on the reviewer. Use separate server TLS and API-server client certificates,
with a dedicated API-server client CA and the exact approved client SPKI pin:

```sh
openssl x509 -in apiserver-client.pem -pubkey -noout | \
  openssl pkey -pubin -outform DER | openssl dgst -sha256

asterius-token-review \
  -listen 0.0.0.0:9448 \
  -issuer https://id.example/t/example \
  -human-client cluster-human -reviewer-client cluster-reviewer \
  -reviewer-key /run/secrets/reviewer-key.pem -reviewer-kid reviewer-1 \
  -server-cert /run/secrets/adapter-cert.pem \
  -server-key /run/secrets/adapter-key.pem \
  -apiserver-ca /run/secrets/apiserver-client-ca.pem \
  -apiserver-spki-sha256 <lowercase-64-hex-SPKI-digest> \
  -identity-prefix asterius:example:cluster-1:
```

Use `-issuer-ca` when Asterius has a private issuer CA. The identity prefix must
match this tenant and the selected Kubernetes profile's cluster ID. Never print
reviewer keys, token requests or full TokenReview bodies in operational logs.
The listener verifies TLS client certificates and the exact SPKI; it does not
trust forwarded identity headers. Do not terminate this authentication at an
unauthenticated HTTP proxy.

## API-server replacement configuration

Mount this kubeconfig in each API server. Files must be readable only by its
operator/process. The API-server certificate belongs to the dedicated adapter
client CA and must have the configured SPKI; the adapter serving certificate
must match `review.example` and its verified server CA.

```yaml
apiVersion: v1
kind: Config
clusters:
- name: asterius-review
  cluster:
    server: https://review.example:9448/review
    certificate-authority: /etc/kubernetes/review-server-ca.pem
users:
- name: api-server
  user:
    client-certificate: /etc/kubernetes/review-client.pem
    client-key: /etc/kubernetes/review-client-key.pem
contexts:
- name: asterius-review
  context:
    cluster: asterius-review
    user: api-server
current-context: asterius-review
```

Configure the supported Kubernetes 1.35 target with:

```text
--authentication-token-webhook-config-file=/etc/kubernetes/review-kubeconfig
--authentication-token-webhook-version=v1
--authentication-token-webhook-cache-ttl=0s
--api-audiences=cluster-human
```

Remove the equivalent `--oidc-*` or structured JWT authenticator for this exact
issuer/client. Keeping it provides an offline path around online revocation.
Other service-account and certificate authentication remains independently
configured. Preserve any required existing API audiences explicitly and validate
that unrelated workload tokens gain no human identity on this route.

Continue the broker flow to obtain the human ID token and configure its bearer
credential for `kubectl`. Kubernetes does not prove human DPoP possession;
upstream broker DPoP does not change that property. RBAC still authorizes every
request after authentication. Existing offline username/group prefixes remain,
with groups narrowed against current allow-list and directory membership.

## Availability, revocation and operation

There is no positive identity cache in Asterius or the adapter. Each adapter
review has a three-second total deadline and accepts one in-flight review per
instance; excess requests and failures grant no identity. Size multiple identical
instances for uncached peak traffic. Use end-to-end TLS passthrough and identical
route pins, dedicated credentials and primary-database-backed Asterius replicas.
Do not route state reads to an asynchronously lagging database replica.

Kubernetes 1.35 retains a global ten-second successful authentication cache even
with the inner webhook TTL at zero. Its detached upstream lookup/transport can
run for thirty seconds. The conservative contract is therefore **40 seconds
plus measured scheduling/transport margin**, not immediate revocation and not
three seconds. This is a source-derived bound; healthy-network observations
cannot establish the delayed-transport worst case. Cached identities may survive
an outage within this bound. Uncached requests fail closed if the adapter,
reviewer authentication, Asterius or primary database is unavailable.

Monitor aggregate request counts, refusal/error rates, capacity and latency
without recording credentials. Review reads do not heartbeat sessions. Account,
exact original grant, session, profile or reviewer withdrawal must deny the next
fresh review; another active grant for the same account cannot repair it.
Session cookie rotation must preserve the exact original public session lineage.
Certificate/key renewal must be coordinated: the current adapter accepts one
API-server SPKI pin, so overlapping distinct client keys requires separately
pinned instances/routes and an explicit control-plane rollout. Do not widen to
any certificate signed by the CA to avoid coordinating renewal.

Required acceptance includes real code and refresh issuance, exact-grant
revocation with another grant alive, session rotation/refresh/logout, group
narrowing, wrong route/audience/reviewer/certificate, expiry, all-adapter and
primary-database outage, complete-route timeout, concurrent changes, and delayed
transport using the actual Kubernetes cache settings. Record the source commit,
binary digest, settings, measured times and unrun cases. No production readiness
or completed acceptance is implied by this candidate guide.
