# External workload trust administration

Workload trusts validate external Kubernetes TokenRequest and GitHub Actions
assertions independently of browser identity providers and confidential OAuth
client authentication. Enabled Kubernetes trusts support [the workload exchange profile](kubernetes-workload-exchange.md) when the Token Exchange capability is enabled. Existing
FAPI client authentication and sender constraints remain mandatory for the
subsequent exchange implementation. The approved contract is
[external-workload-trust.md](adr/external-workload-trust.md).

The tenant admin API provides `GET /workload-trusts` and
`GET`, `PUT`, `DELETE /workload-trusts/{trust_id}`. Reads require
`admin.workload_trusts:read`; mutations require `admin.workload_trusts:write`.
The authenticated management principal determines the tenant; a request body
cannot choose another tenant. Deployment-wide administration remains subject
to the existing explicit tenant delegation rules.

A PUT body contains `expected_version` and `config`. Use null for create and the
current metadata version for replace, including enable, disable and key
rotation. DELETE takes `{ "expected_version": 123 }`. Concurrent or stale
mutations fail with a conflict. Every successful mutation and its audit record
commit together. Recreating a deleted name receives a new monotonically
increasing version; prior replay records remain valid until their expiry.

Example initially disabled Kubernetes configuration:

```json
{
  "expected_version": null,
  "config": {
    "issuer": "https://cluster.example",
    "audience": "urn:asterius:workload:acme:inventory",
    "subject": "system:serviceaccount:apps:inventory",
    "provider": "kubernetes",
    "principal": "workload:inventory",
    "clients": ["inventory-client"],
    "scopes": ["inventory:read"],
    "resources": ["https://inventory.example/"],
    "actions": ["read"],
    "required_claims": {
      "/kubernetes.io/namespace": "apps",
      "/kubernetes.io/serviceaccount/name": "inventory",
      "/kubernetes.io/serviceaccount/uid": "immutable-service-account-uid"
    },
    "algorithms": ["RS256"],
    "keys": { "kind": "remote", "uri": "https://cluster.example/openid/v1/jwks" }
  }
}
```

The audience must be `urn:asterius:workload:{tenant}:{trust_id}`; configure the
TokenRequest or GitHub audience accordingly. Trust names are lowercase ASCII,
up to 63 characters. Each tenant has at most 64 trusts. Nonhuman principals use
`workload:` plus a bounded name. Grants cannot acquire `openid` or
`offline_access`. Permissions are explicit ceilings for later exchange.

Kubernetes configurations pin namespace, service-account name and UID, and the
verifier additionally requires a pod-bound UID. GitHub configurations pin exact
subject, numeric repository and owner IDs, environment, ref, event, workflow
reference and SHA. Pull-request and pull-request-target events are rejected;
reusable workflows require both job workflow reference and SHA. Match fields
are JSON pointers to exact string values, never patterns.

Keys are either inline public JWKS or an operator-pinned HTTPS JWKS URI. All
private JWK members are rejected. Reads expose only public key fingerprints and
key source type; they never return keys, raw assertions or signature bytes.
Remote configuration is checked through the existing SSRF guard; enabling a
remote trust fetches and validates its JWKS before committing. Verification
uses a 60-second, version-specific, singleflight cache and limits refreshes to
once per 30 seconds. Unexpired known keys survive a failed unknown-key refresh;
expired keys never receive an outage extension. Changing inline keys or
disabling a trust takes effect on the next authoritative lookup.

The verifier accepts only RS256, PS256, ES256 and EdDSA under the configured
algorithm set. JWTs are bounded to 8 KiB and claims to 4 KiB, with duplicate
members, excessive nesting and key injection headers rejected. The exact
issuer, audience, subject, provider claims and allowed authenticated client are
verified before returning a principal. Assertions must be issued within 300
seconds, with at most 30 seconds of future clock skew and no expiration grace.
Kubernetes assertion duration is at most 3600 seconds; GitHub at most 600.

`ExternalWorkloads::new(registry, guarded_fetcher, audit)` implements the domain
`workload::Verifier`. Its result is validation evidence, not an issued grant.
Future exchange must call `store_pg::workload::consume_on_connection` within
the transaction creating the child grant. That function locks the authoritative
trust row, rechecks enabled status and version, and inserts the tenant/trust
SHA-256 assertion consumption once. Rollback also rolls back consumption. The
exchange worker must perform permission intersection and impose the output
lifetime ceiling. The bounded tenant retention sweep removes replay marks only after
expiration, and retains operator trust configuration until explicit removal.

Parser fuzz coverage is `workload_token`; focused signature and cache tests
cover all accepted algorithms, ambiguity, tenant/client mismatch, rotation,
disable and outage behavior. The ignored database test runs in an isolated
schema and verifies tenant fencing, audit counts, rollback and deletion/replay
behavior. CI runs ignored database tests with `DATABASE_URL` configured.
