-- One durable create intent per configured transmitter. The row commits
-- before the remote POST, so a crash after remote 201 cannot cause an
-- automatic second POST on retry. Reconciliation uses the authenticated SSF
-- configuration list and deletes this row only in the transaction that
-- records the exact validated stream.
-- Keep established stream identities as tombstones when a local peer client
-- is removed too. Otherwise re-registering the same issuer could create a
-- second remote stream after the original local row cascaded away.
alter table ssf_receiver_upstream_streams
    drop constraint ssf_receiver_upstream_streams_tenant_id_peer_client_id_fkey;

create table ssf_receiver_upstream_setup_intents (
    tenant_id text not null,
    peer_client_id text not null,
    issuer text not null,
    jwks_uri text not null,
    configuration_endpoint text not null,
    status_endpoint text not null,
    audience text not null,
    events_requested text[] not null,
    delivery_method text not null,
    started_at timestamptz not null,
    primary key (tenant_id, peer_client_id),
    -- No FK to clients: deleting and re-registering the local peer must not
    -- erase the tombstone for a remote POST whose outcome is still unknown.
    check (length(issuer) between 1 and 2048),
    check (length(jwks_uri) between 1 and 2048),
    check (length(configuration_endpoint) between 1 and 2048),
    check (length(status_endpoint) between 1 and 2048),
    check (length(audience) between 1 and 2048),
    check (cardinality(events_requested) between 1 and 16),
    check (delivery_method = 'urn:ietf:rfc:8936')
);
