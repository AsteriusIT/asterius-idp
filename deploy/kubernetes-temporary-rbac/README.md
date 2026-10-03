# Temporary Kubernetes access controller

The candidate contract is [the temporary RBAC ADR](../../docs/adr/kubernetes-temporary-rbac.md).
Enable a production profile only after its normative review. The controller updates
one precreated RoleBinding; it has no role catalogue, eligibility or approval command.

1. Register a confidential public-subject OIDC cluster client with ES256,
   private_key_jwt, DPoP, managed_groups_claim and roles_in_id_token enabled.
   Keep one HTTPS callback and code/refresh grants. Configure its Kubernetes profile.
2. The entitlement owner configures the exact resource, permission set and role,
   independent approvers and bounded eligibility through the temporary lifecycle.
   Register a separate same-tenant controller client for private_key_jwt/DPoP
   client credentials, `admin.app_roles:read`, and the tenant admin API resource.
3. The owner PUTs `/temporary-entitlements/{id}/kubernetes-binding` through their
   authenticated Console session with CSRF. Supply `controller_client_id`,
   `enabled` and explicit `expected_revision` (null creates; UUID replaces).
   GET returns `binding` and the exact `authentication_configuration` example.
   One enabled entitlement mapping is permitted per cluster client.
4. Review and install the structured authentication example, including the issuer
   CA. Legacy OIDC flags cannot implement the private JIT username selector.
   Pin the returned mapping revision and profile revision in the controller config.
5. Independently review the fixed Role in `rbac.example.yaml`, its namespace,
   resources/names and verbs. Precreate the empty dedicated binding and the
   restricted controller ServiceAccount. Existing baseline bindings stay separate.
   Read the dedicated binding's UID into the config; never infer or replace it.

Build from the repository root:

```sh
docker build -f deploy/kubernetes-temporary-rbac/Dockerfile -t asterius-jit-rbac:reviewed .
```

Alternatively build `providers/terraform/cmd/asterius-jit-rbac` and invoke the
binary with one closed JSON configuration file. A representative configuration is:

```json
{
  "Controller": {
    "Tenant": "acme",
    "ControllerClient": "incident-controller",
    "ClusterClient": "incident-cluster",
    "Cluster": "incident",
    "Namespace": "incident",
    "EntitlementID": "00000000-0000-0000-0000-000000000001",
    "BindingRevision": "00000000-0000-0000-0000-000000000002",
    "RoleBindingName": "asterius-temporary-secret-read",
    "RoleBindingUID": "00000000-0000-0000-0000-000000000003",
    "RoleName": "approved-secret-read",
    "ProfileRevision": 1,
    "Interval": 1000000000
  },
  "Issuer": "https://issuer.example/t/acme",
  "KeyFile": "/credentials/client.pem",
  "KeyID": "registered-client-key-id",
  "CAFile": "/credentials/issuer-ca.pem",
  "KubernetesURL": "https://kubernetes.default.svc",
  "KubernetesTokenFile": "/var/run/secrets/kubernetes.io/serviceaccount/token",
  "KubernetesCAFile": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
}
```

Replace every example identity/UUID with the reviewed registered value. Interval
is a Go duration in nanoseconds (the example is one second); the accepted range is
100ms–2s. Mount the client key read-only from a Secret, issuer CA and config read-only,
and use the restricted projected ServiceAccount credential. The API credential is
proof bound; the controller's DPoP key is independent of its client assertion key.
The config is at most 64KiB, rejects unknown/trailing fields, and contains no raw token.

Successful approval requires fresh independent account authentication. The broker
requests exactly the approved registered resource permissions; extra resource
permissions cannot accompany this temporary identity. ID tokens without current
private provenance keep the baseline username. A separately standing role never
becomes JIT provenance. Group-based baseline bindings still apply; existing User
bindings can be used with their ordinary credentials.

Monitor reconciliation refusals and the dedicated binding's resourceVersion.
Read/apply timeouts and bad projections clear only dedicated subjects. Shutdown
attempts a bounded clear. A crash may leave the native binding in place; the old
JIT JWT has a signed expiry no later than its activation deadline, and a new ordinary
JWT cannot match its username. Kubernetes v1.35 caches successful token authentication
for ten seconds; a cached expired credential may remain accepted for that additional
window. Verify this finite cache ceiling and clock skew in the reviewed server profile. During outages revocation has this bounded offline
residual, while healthy revocation is measured through actual old-token access loss.
All JWT readers and API servers need synchronized clocks.

A mapping, configuration or profile change invalidates the old username generation.
Install the new reviewed authentication configuration and matching controller pins
together. Unknown generations select the baseline identity; they do not reactivate
old namespace bindings. An unexpected binding UID/roleRef refuses reconciliation;
repair and review the independent Role ceiling before adopting new pins.

For disposable acceptance, supply a verified current server binary and run
`bash scripts/kubernetes-temporary-rbac-acceptance.sh`. It creates only its own
local database, listener 9469 and kind cluster `asterius-dd1y53`, then cleans them.
It never uses the ambient Kubernetes context. Positive credentials come from real
Asterius code/refresh issuance with explicitly seeded fixture assurance; malformed
signed verifier negatives use only that disposable realm's known development KEK.
This fixture does not claim a new WebAuthn ceremony or production deployment.
