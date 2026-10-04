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
