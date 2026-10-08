# UUID client ID cutover

Migration `0173_uuid_client_ids.sql` changes every server-assigned application
client ID to a bare UUID. The value an application sends as `client_id` changes;
its client secret, registration metadata, and database relationships stay with
the application. HTTPS client IDs used for Client ID Metadata Documents remain
URLs because the URL is their protocol identity.

This is a breaking deployment. Back up PostgreSQL and arrange to update each
dependent application's `client_id` at the same cutover. Existing client IDs
are not accepted as aliases. Clients with an old ID will fail authentication
until reconfigured. Tokens already issued with an old client ID retain their
signed claims; plan for their expiry or revocation according to the integration.

After the migration, read the durable mapping as a deployment operator:

```sql
select tenant_id, old_client_id, new_client_id, migrated_at
from client_id_migrations
order by tenant_id, old_client_id;
```

Update OAuth/OIDC clients, resource server integrations, Kubernetes helpers,
automation, and any external configuration that stores a client ID. The
mapping is operational evidence, not an OAuth lookup table. Do not expose it
as an authentication fallback.

For a check after cutover, compare `clients.client_id` to the mapping and
confirm each new ID is present. Then exercise one authorization flow and one
client credentials flow for the integrations that use them. Keep the database
backup until those checks and the external configuration updates are complete.

## Existing-data preflight

Migration 0173 is not yet safe for every populated database. Its generic text
reference rewrite conflicts with immutable agent approvals, temporary entitlement
bindings and requests, and temporary Kubernetes binding identities. Grant client
changes also rotate authority revisions; a child pinned to the old parent revision
must obtain fresh authorization. Audit snapshots, captured requests, approvals and
idempotent replies retain the identifier true when they were recorded.

First restore a backup into an isolated database and run the read-only inventory
with the deployment's schema search path:

```sh
psql -X --set=ON_ERROR_STOP=1 --file=scripts/sql/client-id-uuid-preflight.sql "$RESTORED_DATABASE_URL"
sha384sum crates/store-pg/migrations/0173_uuid_client_ids.sql
```

The inventory prints recorded SQLx checksums, foreign keys, triggers and every
client-named/array/JSON column, then refuses known incompatible populated history.
A successful inventory is a preliminary screen: it does not replace a populated
rollback probe, reference-by-reference review or a restore rehearsal. Run it on a
database migrated through 0172 or newer; earlier schemas require a separate upgrade
review. The query prints metadata and counts, not private keys or credentials.

Do not update `_sqlx_migrations` to silence a changed checksum. Record the exact
previous binary/source revision and checksum, verify a restorable backup, and
review an explicit adoption plan for that exact database. Stop all replicas before
cutover and keep them stopped until the migration and application configurations
agree. Never mix a legacy-ID replica with a UUID-ID replica.

For affected immutable history, obtain approval for a terminal cutover: preserve
old request/approval identities, revoke their live authority, detach mutable client
references through the existing guarded transitions, and recreate definitions and
fresh approvals under UUID identities. Changes to frozen bindings or historic
snapshots, trigger disabling, old-ID authentication aliases and invented parent
approval revisions are not valid shortcuts. Existing signed credentials keep their
original claims and external expiry/cache limits. Do not attempt the populated
cutover until its terminal transitions and rollback evidence are implemented and
reviewed.
