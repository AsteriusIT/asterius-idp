# Declarative management API v1

The management API writes live identity configuration through the same validators
and PostgreSQL tables as ordinary administration. Its contract is
[the declarative management ADR](adr/declarative-management-contract.md).

Every path is under the issuing tenant's `/admin/api/v1/declarative/v1` base.
Authenticate with the existing client-credentials admin token and DPoP proof.
Browser session cookies are refused. Every operation requires
`admin.session:read` **and** the addressed kind's read scope. Mutation additionally
requires its write scope. The OpenAPI `x-kind-scopes` table documents these gates;
the registry's static session scope alone grants no resource authority.

| Kind | Immutable import identity | Read/write scope prefix | Desired spec |
| --- | --- | --- | --- |
| `tenant` | Tenant ID | `admin.tenants` | `tenant_id`, `issuer`, `display_name`, `default_resource`, optional `custom_host`, `options` using the existing tenant settings schema. Identity/routing fields cannot change; label/options can. |
| `application` | Generated client ID | `admin.clients` | Public FAPI registration metadata plus `resources`. Confidential public-key registration only; agents and non-FAPI clients are excluded. Read excludes server timestamps, client ID and status. |
| `resource` | Exact audience URL | `admin.resource_servers` | `identifier`, `scopes` (null or array), `default_token_lifetime_seconds`, `introspection_clients`. |
| `group` | Generated UUID | `admin.groups` | `name`, `display_name`. Rename preserves UUID. |
| `membership` | Group UUID + existing user UUID | `admin.memberships` | `group_id`, `user_id`, naming same-tenant existing resources. |
| `policy` | Literal `policy` under the tenant | `admin.policies` | Entire existing RuleSet JSON, preserving ordered rules. |

Create a tenant through an existing reserved-tenant issuer with deployment reach
and tenant read/write scopes. `spec.tenant_id` names the target new tenant.
Tenant, default resource, pairwise salt, wrapped active signing keys and rotation
schedules commit with management ownership/logical identity in one transaction.
Tenant deletion is refused; use retain/release. Application removal reuses
registration deprovisioning and token cutoff: the registration row is removed,
previously issued credentials/tokens are withdrawn, and the management identity
remains as a tombstone. It is not a tenant or audit-history deletion.

## Requests and canonical reads

Create uses `POST /resources`:

```json
{
  "kind": "resource",
  "external_key": "provider-instance/api-audience",
  "deletion_protection": true,
  "spec": {
    "identifier": "https://api.example/",
    "scopes": ["read"],
    "default_token_lifetime_seconds": 300,
    "introspection_clients": []
  }
}
```

The response contains `contract_version: 1`, portable `id`, `kind`, canonical
`spec`, strong `revision`, server-derived `owner`, durable builder `origin` and
`deletion_protection`. The HTTP ETag is the quoted revision. Responses use
`Cache-Control: no-store`. Body size is limited to 64 KiB. Unknown outer fields
and unknown kind-specific desired fields are refused.

Import ID is unpadded base64url UTF-8 JSON `[tenant, kind, identity]`, or
`[tenant, "membership", group_uuid, user_uuid]`. UUIDs must use canonical
lowercase hyphenated spelling; exact audience URLs are preserved. Import/read is
`GET /resources/{id}`. It never adopts the resource. Identity tenants must match
the routed tenant, including for deployment credentials.

`GET /resources?kind=resource&external_key=...` resolves the authenticated owner's
logical creation identity after a lost create response. This is an exact-key
lookup, not a general inventory/list endpoint; use ordinary paginated inventories
for discovery. Unknown/duplicate query fields are refused.

Canonicalize with `POST /resources/{id}/plan`, a `{ "spec": ... }` body and the
current `If-Match` ETag. Planning returns canonical spec, whether it changed,
revision and owner-conflict status, and writes nothing. Application planning
reuses the current registration policy, active signing-key check and outbound
sector verifier. Apply uses `PUT /resources/{id}` with canonical `spec`, explicit
`deletion_protection` and the same `If-Match`. A plan grants no write permission.
After a stale revision, refresh and replan; never implicitly claim or force a
write. `null` resource scopes permit all granted scopes; `[]` permits none.

## Ownership, drift and retries

Ownership is the verified automation issuer tenant plus client ID. Separate
controllers need separate credentials; configuration cannot impersonate another
owner by sending an owner string. Configuration addresses and Kubernetes UIDs
belong in the nonsecret `external_key`, not in authentication headers.

`POST /resources/{id}/adopt` explicitly claims an unowned resource at its current
ETag. Existing managed builder origins, SCIM and LDAP ownership refuse adoption;
reference-only flow links remain valid. `POST /resources/{id}/release` retains
live state and releases ownership. Builder-origin records are never removed by
these operations. There is no implicit managed-builder-origin handoff.

Console edits remain available through ordinary endpoints and appear as drift.
Every supported runtime writer increments a durable management generation;
changing a value and changing it back does not restore the original ETag.
Parent group generations participate in membership ETags. All controller claims,
resource writes and builder managed-origin inserts serialize on the same database
identity locks; database deadlock/availability errors fail closed and can be
retried after refresh, without partial transaction effects.

Create persists normalized desired spec, initial delete-protection, controller
owner, external key, actual live ID and resource incarnation together. Repeating
the same create intent returns that resource; changing its intent returns 409.
The ordinary admin API's 24-hour `Idempotency-Key` replay guard is not used here.
Retries remain deterministic after its retention window.

Deletion protection defaults on. Disable it in a separate conditional PUT, then
DELETE with the returned ETag. Group deletion refuses members and application-role
grants; dependent foreign keys refuse unsafe client deletion. Ordinary destructive
endpoints also honor active controller protection. A deleted resource retains its
logical identity and incarnation; reusing the old logical creation key fails.
Creating a new incarnation requires a new external key and the prior owner's
credential, or an explicit release of its tombstone. Ordinary writers cannot
silently recreate controller-owned tombstones. Durable deletion receipts make an
old delete retry succeed without touching a later incarnation at the same natural
identity. There is no whole-stack transaction: retain each completed identity and
refresh after partial stack failure.

## Credentials and errors

Private keys remain in local files or external Secret stores. Only public JWKS or
JWKS URI enters application specs. Generated reusable client secrets and private
JWK members are refused. No read, plan, import, audit or error returns key material
or registration credentials. Policy literals and other public configuration are
retained in state/manifests; those documents are not Secret stores.

| Status | Stable code | Required response |
| --- | --- | --- |
| 400 | `invalid_request` | Fix schema/identity; errors do not echo supplied values. |
| 403 | `forbidden` | Supply both registry and kind scopes with the correct tenant reach. |
| 404 | `not_found` | Refresh import/live identity; do not adopt by name. |
| 409 | `owner_conflict`, `logical_key_conflict`, `delete_protected`, `dependency_conflict` | Explicitly resolve the ownership, intent, protection or dependency. |
| 412 | `revision_conflict` | Refresh and replan. |
| 428 | `precondition_required` | Send the exact strong ETag in `If-Match`. |
| 503 | `unavailable` | Retry after refresh; the database transaction committed nothing on failure. |

The focused parser/auth/canonicalization tests run locally through targeted
verification. Slow live PostgreSQL tests are ignored locally and run in CI,
including six-kind live writes/retry/import and signing-key rollback checks.
