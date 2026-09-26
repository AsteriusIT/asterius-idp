-- Explicit tenant-scoped SAML SP trust. No browser SSO route is enabled by
-- these rows. A future verifier must add request-signing policy before use.
create table saml_sp_trusts (
    tenant_id text not null references tenants (tenant_id) on delete cascade,
    entity_id text not null,
    acs_url text not null,
    created_at timestamptz not null default now(),
    primary key (tenant_id, entity_id),
    check (length(entity_id) between 1 and 1024),
    check (length(acs_url) between 1 and 2048)
);

-- A request ID is reserved once for its SP and tenant. Keep tombstones when
-- trust is removed or replaced; no FK to the mutable SP row. The expiry is
-- informational until a retention sweep exists, so an old ID stays refused.
create table saml_authn_request_replays (
    tenant_id text not null references tenants (tenant_id) on delete cascade,
    sp_entity_id text not null,
    request_id_hash bytea not null,
    reserved_at timestamptz not null default now(),
    expires_at timestamptz not null,
    primary key (tenant_id, sp_entity_id, request_id_hash),
    check (length(request_id_hash) = 32),
    check (expires_at > reserved_at)
);

create index saml_authn_request_replays_expiry
    on saml_authn_request_replays (tenant_id, expires_at);
