# UUID client ID cutover

Migration `0173_uuid_client_ids.sql` changes server-assigned legacy application
IDs to UUIDs. Existing UUIDs and HTTPS Client ID Metadata Document identities stay
unchanged. Client secrets and registration metadata stay with the application;
external configuration must send its new ID. Old IDs are not authentication aliases.
The migration is a breaking, explicitly approved terminal cutover, not a routine
rolling upgrade. No live database cutover is implied by this preparation.

## Preserved history and fresh authority

Immutable task approvals, entitlement definitions and requests, Kubernetes binding
identities, captured authorization parameters, managed-device proofs, audit events,
idempotent replies and creation requests retain their original identifiers and
snapshots. The migration uses existing guarded transitions to revoke tasks,
eligibilities and activations, invalidate pending approval requests, disable
entitlement/Kubernetes definitions, and detach mutable client references. Approved
requests retain their decisions. Affected grants and all their descendants are
revoked, including descendants whose recipient already has a UUID or HTTPS ID.
Parent approval revisions and actor chains remain original; changing client lookup
identities rotates authority generations without inventing a new approval receipt.
Task refresh credentials are revoked before their mutable lookups move. Captured
PAR, code, CIBA, device and presentation transactions are expired where affected.

Mutable tenant-scoped client lookups record their original identifier in an
immutable `*_before_uuid_cutover` column. Grants also record their previous authority
revision and changed subject. Those columns and `client_id_migrations` are evidence,
not protocol lookup sources. New rows cannot invent this history. Declarative
ownership and captured initial creation specifications are preserved. Only current
configuration JSON is rewritten; historical proofs, requests and replies are not.
No existing immutable trigger is disabled or relaxed.

After migration, recreate disabled definitions and obtain fresh approvals under
UUID identities. Reconfigure OAuth/OIDC clients, resource integrations, Kubernetes
helpers and automation using the operator-only mapping:

```sql
select tenant_id, old_client_id, new_client_id, migrated_at
from client_id_migrations order by tenant_id, old_client_id;
```

Already issued signed credentials retain their claims and external expiry/cache
limits. Integrations must arrange expiry or revocation appropriate to those tokens;
the database migration cannot alter a signed credential already held externally.

## Rehearsal and checksum adoption

Restore a backup into an isolated database. Record the exact deployed binary/source
revision and all SQLx migration checksums. Run the read-only inventory with that
database's intended schema search path and review every reported reference:

```sh
PGOPTIONS='-c asterius.client_uuid_terminal_cutover=approved' \
  psql -X --set=ON_ERROR_STOP=1 --file=scripts/sql/client-id-uuid-preflight.sql "$RESTORED_DATABASE_URL"
sha384sum crates/store-pg/migrations/0173_uuid_client_ids.sql
python3 scripts/client-id-uuid-rehearsal.py --restored-database-url "$RESTORED_DATABASE_URL"
```

The preflight requires schema 0172 or newer and prints metadata/counts, not secrets.
Approval makes the inventory usable; it does not replace reviewing actual restored
data. The Python probe creates and removes only its random owned schema, applies
migrations through 0172, then exercises populated terminal fixtures: unapproved
rejection, approved rollback, successful commit, preserved history, revoked authority,
UUID/HTTPS preservation and immutable tamper rejection. It is a fixture regression;
add the same rollback/commit and application checks to the actual restored backup.

This corrected prerelease migration is intended for a database whose recorded
migrations stop before 0173. If `_sqlx_migrations` already records an older 0173
checksum, SQLx must reject it. **Do not edit its checksum or rerun 0173 over that
schema.** Preserve that database and its exact source. The supported adoption path
requires a verified pre-0173 backup restored into a replacement database, replay or
reconciliation of subsequent writes under a separately reviewed plan, and the
corrected migration there. If no suitable backup exists, obtain a database-specific
repair plan; historical snapshots cannot be reconstructed by changing checksums.

## Deployment and rollback

1. Verify backups and rehearse restore, the terminal transitions, references and
   application flows on actual copied data. Export the identifier mapping securely.
2. Quiesce all writers and stop every replica. Retain the old database and matching
   old application configuration as one rollback unit.
3. Start the exact reviewed migrator with
   `PGOPTIONS='-c asterius.client_uuid_terminal_cutover=approved'`. SQLx reads
   `PGOPTIONS` when constructing its PostgreSQL connection. Missing approval fails
   before any legacy-ID transition; empty fresh databases need no approval flag.
4. Apply the mapping to dependent application configurations, recreate definitions
   and obtain fresh approvals. Confirm no old-ID aliases remain and exercise each
   affected authorization and client credentials flow before reopening traffic.
5. Remove the temporary approval option from runtime environments. Retain backups
   until deployment checks, reconciliation and external configuration updates finish.

A transaction rollback preserves the original state. After commit, rollback means
restoring the whole matched database/configuration unit while quiesced and accounting
for subsequent writes. Never mix legacy-ID and UUID-ID replicas or selectively
restore approval rows. This runbook prepares a cutover; operator approval of the
specific database, restored evidence and deployment window is still required.
