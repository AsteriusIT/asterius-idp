# Outbound SCIM candidate

This isolated implementation awaits human review of
[the proposed contract](../adr/outbound-scim-contract.md) and the first real
source-to-target interoperability acceptance. It is not a delivered generic
SCIM, Entra or SaaS connector. No shared instance is enabled by this preparation.

The candidate target is another explicitly configured Asterius tenant with
current FAPI private_key_jwt client credentials, DPoP, versioned SCIM writes and
the exact reserved-incarnation protection capability. Source and target issuers
must differ. The source operator configures an `outbound_scim_credential` entry
under its own tenant: `reference`, `generation`, `target_issuer`, `target_client`,
`key_file`, `kid`, `algorithm`. The key file is an absolute private regular file,
at most 16 KiB and readable only by its owner. Register the corresponding public
key on the target client, with `admin.scim:read admin.scim:write` and the exact
`<target-issuer>/admin/api/v1` resource. Private bytes are never supplied through
the administration API, database or console. The registry admits 100 complete
source/destination credential contexts process-wide; knowing a reference from a
different source tenant grants no use of that context.

A same-realm tenant administrator uses **Applications → Outbound provisioning**
with `admin.outbound_scim:read` / `admin.outbound_scim:write`. Writes use the
existing fresh administration ceremony and CSRF protection. Create a paused
connector from an approved credential, run authenticated destination preview,
then enable within its five-minute validity window. Every configuration change
invalidates that preview. Pause before rotating to another configured generation
for the same pinned destination issuer/client; preview again before resuming.
Pause stops subsequent dispatch admissions and retains ownership evidence; an
already transmitted request may still finish remotely.

Select explicit local Users and Groups. Each connector holds at most 100 current
User and 100 current Group assignments, including pending deprovisioning, with at
most 100 selected active direct User members per Group. Group members require
selected User assignments and mappings first. A bounded reconcile command queues
25 assignments and returns the next cursor. Refresh displays pending, paused,
waiting dependencies, conflict and dead-letter states. Dry run authenticates and
reads the current owned target; it neither mutates SCIM nor stores a mapping.
No local authentication material, built-in role or application role is exported.

Unselect disables an owned User or empties its Group, retaining the object and
mapping. This does not free a current assignment slot. Explicit archive verifies
safe absence for a never-created object or conditionally fences an already
inactive/empty owned target before retiring the incarnation. Historical mapping
and approval evidence remains. Source tenant deletion is refused until every
current assignment has been safely retired; generic cascade cannot deprovision.

Separately enable reviewed deletion policy while paused and preview before
resuming. A confirmed delete addresses only the saved owned UUID and exact
reviewed ETag of an already disabled User or empty Group. An admitted ambiguous
DELETE retries that UUID;404 records its same-resource receipt. Archive a
completed delete receipt to retire it without another remote request. A normal
mapped404 is a conflict. Explicit recreate either verifies that saved UUID is
absent or fences an already inactive/empty old object, retains its history, and
atomically creates a fresh generation and alias. It cannot replace an active old
object, borrow a protected inbound-SCIM source, or delete a replacement UUID.

Lifecycle approvals last five minutes. A changed context or ETag is a visible
refusal, not a reason to remove ownership checks. A lost archive PUT response
may require reconciliation, inspection of the new saved version and a fresh
approval. Renewed deletion approval carries prior admission only for the exact
same generation and UUID. The latest 25 lifecycle receipts remain visible per
assignment, including completed, superseded and fixed refusal codes.

The target retains reserved outbound incarnation externalIds across deletion
and identity changes, so late collection POSTs cannot revive them. Fresh explicit
generations use different IDs; ordinary SCIM externalIds retain their normal
behavior. Retention is bounded at 10,000 keys per target tenant/client/kind and
never expires automatically. Capacity refuses further reserved retirement and
needs an explicit operator lifecycle; no cleanup job discards these fences.
Whole target tenant teardown removes its credentials and retention history and
is outside connector recovery. Do not restore an old issuer/client authority
context as though it were an ordinary retry.

`scripts/outbound-scim-schema-smoke.py --container <owned-test-db-container>`
creates and removes its own schema-cloned database. It checks source producers,
coalescing, bounds, tenant cleanup, reserved late-create fences and actual
concurrent delete/create serialization. It copies no source accounts/secrets.
This SQL smoke does not prove OAuth/DPoP interoperability. The real acceptance
matrix is `scripts/outbound-scim/acceptance-matrix.json`; it remains unexecuted
until the owned first-target fixture and targeted final verification are run.
