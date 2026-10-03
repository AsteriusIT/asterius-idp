# Kubernetes human access onboarding

The approved [broker contract](adr/kubernetes-human-access.md) uses a distinct
confidential OIDC application per tenant and cluster. Cluster profiles provide
authentication/RBAC configuration and narrow managed group release; they do not
implement the browser login broker or kubectl helper themselves.

Enable the tenant's non-FAPI client permission explicitly, then register a web
OIDC application with one exact HTTPS broker callback, `private_key_jwt`,
`authorization_code` and `refresh_token`, `openid`, ES256 ID-token signing,
DPoP-bound tokens and `managed_groups_claim=true`. Provision the tenant's ES256
signing key and the broker's public authentication JWK before onboarding.
Existing FAPI applications retain their security profile.

The client configuration tab contains **Kubernetes access**. Choose a unique
DNS-label cluster identifier, an example RBAC namespace and the exact stable
managed-group UUIDs this cluster may receive. Empty means no groups. Selecting
more than 100 groups, duplicates, unknown groups or groups belonging to another
tenant is refused. The cluster identifier is immutable after creation: another
cluster requires another registered application/client ID. Namespace and group
selection can be replaced using the saved optimistic-concurrency revision.

The administrative API uses the same route authorization and CSRF protections
as the rest of the client screen:

```text
GET /admin/api/v1/clients/{client_id}/kubernetes   admin.clients:read
PUT /admin/api/v1/clients/{client_id}/kubernetes   admin.clients:write
```

Creation uses revision zero; a replacement uses the revision last read:

```json
{
  "cluster_id": "cluster-a",
  "namespace": "team-a",
  "group_ids": ["00000000-0000-0000-0000-000000000001"],
  "revision": 0
}
```

The response displays issuer, registered client audience, subject type,
algorithm, stable claim names, mandatory safe username/group prefixes, legacy
API-server flags, an `AuthenticationConfiguration` and namespace-scoped `view`
RoleBindings. GET also displays public signing keys and whether current
registration remains compatible. No private key or broker secret is exported.
Unknown/cross-tenant client IDs return not found; group policy belongs to the
server and cannot be selected through dynamic client metadata or token claims.

Use either generated structured authentication or legacy flags, never both.
JSON is valid YAML. The structured example targets Kubernetes 1.35 and its
stable `apiserver.config.k8s.io/v1` configuration, enforces a single audience
and at most five-minute ID-token lifetime, and rejects reserved `system:`
identities. Legacy flags explicitly pin ES256. Structured authentication
accepts Kubernetes' supported algorithms, while this Asterius client issues
ES256 only. For a private issuer CA, populate `issuer.certificateAuthority`
with its PEM bundle or add `--oidc-ca-file` to legacy flags. Never disable TLS
verification; discovery and JWKS must be reachable from the API server.

Review RBAC examples before applying. They grant read-only `view` in the chosen
namespace to selected stable group identifiers, never `cluster-admin` or
`system:masters`. A user's memberships are intersected with this client's
allow-list on ID-token issuance and UserInfo, including refresh issuance.
Group omission produces an identity without group authority. Other applications
retain their existing managed-group opt-in behavior. A profile whose client
registration is later downgraded fails closed at managed-group release.

Subject identity comes from the existing server subject resolver and remains
stable according to the registered public/pairwise subject type; email,
display names and custom group claims do not control Kubernetes identities.
Issuer/client audiences and safe prefixes distinguish clusters. Removing a
group, disabling a user/client or logging out prevents future issuance through
existing checks, but an already issued offline JWT remains usable until expiry.

## Controlled verification

The example in [examples/kubernetes-authentication.json](examples/kubernetes-authentication.json)
is asserted against the onboarding generator by a focused Rust test. The
standalone verifier uses the exact Kubernetes v1.35.0 authentication library,
strictly parses the generated configuration, compiles its CEL and checks real
ES256 signatures produced by Asterius's JOSE provider. Synthetic identities and
ephemeral keys stay local; no live cluster or Asterius deployment is mutated.

```bash
SQLX_OFFLINE=true cargo run --quiet -p asterius-jose --example kubernetes_fixture > /tmp/asterius-kubernetes-fixtures.json
cd scripts/kubernetes-interop
go run . ../../docs/examples/kubernetes-authentication.json /tmp/asterius-kubernetes-fixtures.json
```

The verifier checks user/group mapping, absent groups, Cluster A tokens rejected
by Cluster B, wrong issuer/audience, expired or forged tokens, unsupported
algorithm, excess lifetime and multiple audiences. This is controlled verifier
interoperability; it does not verify live discovery/JWKS, ingress, browser
authentication, the future broker/helper or production cluster configuration.
The PostgreSQL persistence test is marked slow and remains CI-only.

Configuration fields follow the official
[Kubernetes v1.35 authentication reference](https://v1-35.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/).
