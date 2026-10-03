# Declarative management v1: exclusive controllers and conditional writes

- **Status:** Accepted architecture; implementation tracked separately
- **Date:** 2026-10-03
- **Bead:** ast-dd1y.3.1
- **Deciders:** Epic implementation orchestrator under the user's request

## Context and verified inventory

Terraform/OpenTofu and Kubernetes must refresh and import real identities, detect
console changes, and refuse to fight the builder or another controller. The
[builder contract](../architecture-builder.md) already distinguishes durable
managed origin from references; deleting a diagram node preserves its live object.

The current route catalogue is `crates/admin-api/src/lib.rs`; renderers and
validators live in the corresponding admin modules. Paths below are relative to
`/t/{tenant}/admin/api/v1` (the tenant's issuer plus `/admin/api/v1`).

| Existing resource | Existing operations and identity | Verified limitation |
| --- | --- | --- |
| Tenant | List/create `/tenants`, read `/tenants/{tenant_id}`, settings read/replace, status replace. Tenant ID is a stable string. | Creation and status require deployment authority; there is no tenant delete route. Settings lack a universal revision contract. |
| Application/client | List/create `/clients`, read/replace `/clients/{client_id}`, dedicated `/resources` replace. Server generates opaque client IDs. | Full registration replacement and resources are separate writes; no universal conditional controller ownership. Credential generation is unsuitable for IaC state. |
| Resource server | List `/resource-servers`; read/upsert/delete `/resource-servers/{identifier}`. Exact absolute audience URL, percent-encoded as one segment. | Upsert cannot distinguish create from overwrite; no universal concurrency token. |
| Group | List/create `/groups`; read/replace/delete `/groups/{group_id}`. UUID identity, tenant-unique name. | Group metadata already uses revisions; SCIM owns some groups. Other kinds do not share this contract. |
| Membership | List `/groups/{group_id}/members`; idempotent PUT/DELETE `/groups/{group_id}/members/{user_id}`. Same-tenant existing users only. | Membership changes increment and lock the group revision but do not accept the controller's expected revision. |
| Policy | Read/replace/delete singleton `/policies`; history and trial endpoints. | Entire parsed rule set is the write unit; no controller ownership or universal concurrency token. |
| App roles | Shared and client-owned role catalogues and group/user assignments. | Separate from administrative roles; excluded from v1 IaC resources. Builder continues to support them. |

Automation already checks client-credentials `sub == client_id`, token issuer,
admin audience, DPoP binding/replay and revocation (`crates/server/src/admin.rs`).
`auth.rs` refuses Bearer and mixed cookie/token credentials. RBAC already has
resource-specific scopes, and tenant or deployment reach. This decision adds no
OAuth grant, algorithm, compliance-profile relaxation or new token verifier.

`flow_resource_links` (migration 0144) enforces one managed origin per resource,
including pending links; references can coexist. Existing builder apply performs
conditional updates and uses an exact preview digest. Ordinary POST idempotency
currently consumes a caller-scoped key for 24 hours and returns 409 on reuse;
it does not recover a generated ID or prove that the first write succeeded.

## Decision

Add an additive **declarative/v1** API over existing domain validators and stores.
Use an exclusive controller owner, atomic conditional writes and a durable logical
creation key. Keep the ordinary console API available; console edits remain
possible and visible as drift. Do not turn builder drafts into the IaC wire format.

### First supported resources and import

| Declarative kind | Immutable live identity | Desired configuration / deletion |
| --- | --- | --- |
| `tenant` | Tenant ID | Create with deployment authority; edit existing allowed settings. Delete is **retain/release only** in v1; never simulate delete by disabling a tenant. Status remains a separate deployment operation. |
| `application` | Client ID | Confidential FAPI registration using public JWKS or JWKS URI, plus allowed resource/scopes policy. No generated secret or private key. Delete uses explicit existing client retirement semantics, documented as retirement rather than physical erasure. |
| `resource` | Exact audience URL | Supported scopes, token lifetime, introspection clients. Delete withdraws the audience from future issuance. |
| `group` | Group UUID | Name/display name only. Renaming preserves UUID. Delete refuses while direct members or managed dependants exist. SCIM-owned groups cannot be adopted. |
| `membership` | Group UUID + user UUID | One direct membership edge, not a full user or membership-set replacement. Delete removes that edge. |
| `policy` | Tenant ID + literal `policy` | Entire RuleSet document, including its version. Delete restores the existing deny-all/no-policy behavior. No per-rule controller. |

Import IDs are a JSON array encoded as unpadded base64url UTF-8: `[tenant, kind,
identity]`, and `[tenant, "membership", group_uuid, user_uuid]` for membership.
This avoids ambiguous URL delimiters. IDs are case-sensitive domain identities;
reject invalid shapes, unknown versions/kinds and cross-tenant identity lookups.
Import performs a read and never claims ownership. An explicit adoption is needed
before the first managed write. Data sources always remain read-only.

Tenant creation uses its chosen tenant ID as the logical key. Other creates carry
`external_key`, a nonsecret stable configuration identity (provider instance plus
resource address, or Kubernetes cluster/namespace/CR UID). Persist the mapping to
the generated live ID in the resource transaction. Never infer adoption from a
matching display name, audience or external key owned by somebody else.

### Concrete wire contract

Use `/declarative/v1/resources` under the existing admin base path:

- `GET /resources/{import_id}` returns `{contract_version:1, id, kind, spec,
  revision, owner, origin, deletion_protection}` and a strong `ETag`.
- `GET /resources?kind=...&external_key=...` resolves a caller's logical creation
  key; paginated inventory uses opaque cursors and requires the kind's read scope.
- `POST /resources` creates `{kind, external_key, spec, deletion_protection}`.
  The authenticated owner is established server-side, never trusted from JSON.
- `PUT /resources/{import_id}` replaces `spec`, requires `If-Match` and the same
  owner, and returns the complete canonical document and new ETag.
- `POST /resources/{import_id}/adopt` and `/release` require `If-Match`, resource
  write authority, and explicit adoption/release intent. Adoption requires no
  current controller, no managed builder origin and no SCIM owner.
- `DELETE /resources/{import_id}` requires `If-Match`, the same owner, and
  protection already disabled by a separate conditional update. `tenant` rejects
  delete; clients report retirement; retained resources use `/release`.
- `POST /resources/{import_id}/plan` accepts the proposed spec and expected
  revision, validates/canonicalizes, and returns secret-free change/conflict
  details. Planning persists nothing and grants no apply authority.

A strong revision covers canonical managed spec, owner and delete-protection;
implementation may use a monotonic counter or collision-resistant digest with an
atomic row comparison. Membership also binds the parent group revision, so
parent deletion or membership edits invalidate its plan. Read the object,
provenance and ownership consistently in one database transaction. Do not hash
or render private credential material. Include ordinary console and builder
mutations in revision changes; a facade-only revision unrelated to the live
object is insufficient.

Missing precondition returns 428, stale precondition 412, ownership/dependency
conflict 409, invalid schema 400, denied scope 403, absent identity 404. Errors
carry stable machine codes (`revision_conflict`, `owner_conflict`,
`delete_protected`, `dependency_conflict`) and nonsecret identities only. A client
must refresh/replan after 412; retries must never silently adopt or overwrite.

Create uniqueness is `(tenant, kind, authenticated_owner, external_key)`. Same key
and canonical spec returns the existing ID/document; changed spec returns 409.
Creation, logical mapping, ownership and initial canonical spec commit together.
A failed transaction claims nothing. Retrying after a lost response reads that
mapping and cannot create a duplicate. Tombstones preserve mapping after delete:
reusing a deleted logical key returns 409, while retrying that exact deletion
returns success without touching a later resource. Replacement with a new logical
key is explicit. Existing 24-hour POST replay guard is not this persistence layer.

Each replace/delete/claim compares revision and ownership under the same database
lock/transaction as the resource write. A repeated replacement whose canonical
spec already matches the requested outcome may return success for the same owner;
otherwise stale revision remains 412. No database transaction spans a stack.
Clients record each completed ID and refresh before retrying failed operations;
no whole-stack success is claimed after a partial apply.

### Ownership, console drift and builder provenance

Owner is a server-derived automation issuer + client ID, with a bounded nonsecret
controller instance identifier bound to that credential. Use separate credentials
for independent Terraform states or operator installations. The owner string is
identity metadata, never an authorization capability or a replacement for scopes.
Terraform and the operator cannot claim the same object concurrently. Membership
has its own edge ownership; managing group metadata does not confer ownership of
all memberships or users.

Keep the builder origin permanently available in `origin`; do not rewrite or
remove `flow_resource_links` when adopting or releasing an object. A `managed`
link, even detached/pending, refuses adoption. `reference` links do not. Builder
create/apply and declarative claims must serialize against a shared ownership
check; a controller-managed object may only be referenced by a flow. Builder
managed-origin uniqueness alone is insufficient to enforce this across tools.
Transfer from a builder requires a separately explicit, audited managed-link
release operation; until implemented it is refused. Provider/SSF builder work
`ast-q0af.6` remains independent.

Ordinary console edits remain authorized by current scopes and are audited. They
change the same canonical revision and produce drift. A controller reports drift
and does not blindly retry with the refreshed revision; an explicit apply or
configured operator drift policy determines reconciliation. Ordinary destructive
routes must enforce active controller deletion protection. A privileged recovery
release is explicit and audited; possession of ordinary write scope does not
silently take over another automation owner.

### Canonicalization and secret boundaries

Reuse current domain parsers, not a second metadata policy. Sort/deduplicate set
fields (scope values, granted resources and membership identities) while preserving
ordered policy rules. Preserve meaningful absent/null/empty differences, including
resource `scopes: null` versus `[]`. Emit actual server defaults in canonical reads;
IaC state excludes timestamps, ETags, ownership and computed-only metadata from
its desired spec. Do not normalize exact redirect URIs or audience URLs beyond
existing domain parsing. Unknown desired fields are rejected. Freeze schemas in
OpenAPI with explicit required/optional fields and payload bounds.

Only public JWKS/JWKS URI enters an application spec. Authentication private keys
stay in a local file or same-namespace Kubernetes Secret; configuration stores the
reference, never the contents. No generated reusable client secret is returned by
this surface. Public key JSON rejects private JWK members through existing domain
validation. No secrets in plan, read, import, error, audit or external-key fields;
never fetch arbitrary secret-reference URLs on the server. V1 has no credential
rotation resource. Providers must state that policy literals and public metadata
are retained in state and Kubernetes manifests: this is not secret storage.

### Service authorization

Use existing client credentials with private-key JWT and DPoP; bind the access
token audience to the issuing tenant's issuer plus `/admin/api/v1`. Request fresh
DPoP proofs per method/URL and implement the existing nonce/replay behavior. No
cookie credentials or CSRF bypass for service automation; mixed credentials fail.
Tenant-issued tokens may administer only their tenant. Reserved-tenant tokens
carry deployment reach in current code; use them only for tenant creation/status,
never as the default operator credential.

Read/plan/import require the respective `admin.tenants:read`, `admin.clients:read`,
`admin.resource_servers:read`, `admin.groups:read`, `admin.memberships:read` or
`admin.policies:read`. Mutation/adopt/release additionally require the matching
`:write` scope. Applications changing authorized resources still require the
client write scope. Membership lookup must not grant user enumeration. Tenant
create requires deployment reach and `admin.tenants:write`; tenant settings use
current tenant reach. No wildcard/admin role scope is introduced.

## Alternatives and consequences

Shared mutable administration with CAS alone detects races but permits perpetual
controller fights; rejected. Immutable snapshots complicate every existing
mutable admin resource and import; rejected. Reusing builder graphs couples IaC
to layout revisions and unsupported/context-only nodes and inherits partial apply
without stable independent ownership; rejected. Exclusive owners plus CAS keeps
stable import and explicit handoff while preserving intentional console edits.

`ast-dd1y.3.2` implements the additive routes, durable mappings/tombstones, canonical
consistent reads, ownership atomicity and all-writer revision/delete guards; it
must update OpenAPI, the management threat model and parser fuzz targets.
`ast-dd1y.3.3` adds the provider and representative import/second-plan tests.
`ast-dd1y.3.4`/`.3.5` define and implement namespaced CRDs over this same contract.
No dependent component may advertise a kind whose atomic runtime adapter is absent.

Verification must cover lost-create responses, replay after failed transactions,
stale writes, competing owner adoption, console drift, builder managed/reference
origins, SCIM conflicts, protected delete, membership-parent races, tenant isolation,
private-key rejection and redacted errors/plans. This decision changes management
semantics, not protocol or crypto conformance; no new normative claim is made.
