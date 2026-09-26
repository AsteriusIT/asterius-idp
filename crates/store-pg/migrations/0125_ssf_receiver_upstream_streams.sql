-- Receiver-side state for streams explicitly established at a configured
-- transmitter. This table contains no upstream OAuth access token or secret.
-- A peer registration can have at most one active upstream stream in this
-- deployment; replacement requires an explicit delete and fresh setup.
create table ssf_receiver_upstream_streams (
    tenant_id text not null,
    peer_client_id text not null,
    issuer text not null,
    jwks_uri text not null,
    configuration_endpoint text not null,
    status_endpoint text not null,
    stream_id text not null,
    delivery_method text not null,
    poll_endpoint text,
    audience text not null,
    events_requested text[] not null,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    last_polled_at timestamptz,
    primary key (tenant_id, peer_client_id),
    foreign key (tenant_id, peer_client_id)
        references clients (tenant_id, client_id) on delete cascade,
    check (length(issuer) between 1 and 2048),
    check (length(jwks_uri) between 1 and 2048),
    check (length(configuration_endpoint) between 1 and 2048),
    check (length(status_endpoint) between 1 and 2048),
    check (length(stream_id) between 1 and 255),
    check (delivery_method in ('urn:ietf:rfc:8935', 'urn:ietf:rfc:8936')),
    check ((delivery_method = 'urn:ietf:rfc:8936') = (poll_endpoint is not null)),
    check (length(audience) between 1 and 2048),
    check (cardinality(events_requested) between 1 and 16)
);
