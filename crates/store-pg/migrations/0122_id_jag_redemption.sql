-- ID-JAG subject resolution is an explicit tenant/issuer binding. No email,
-- username or untrusted sub_id lookup can create a local account identity.
create table id_jag_subject_bindings (
    tenant_id text not null,
    issuer text not null,
    upstream_subject text not null,
    user_id uuid not null,
    created_at timestamptz not null default now(),
    primary key (tenant_id, issuer, upstream_subject),
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    check (length(issuer) between 1 and 2048),
    check (length(upstream_subject) between 1 and 512)
);

create index id_jag_subject_bindings_by_user
    on id_jag_subject_bindings (tenant_id, user_id);

-- Consent is distinct from operator trust and subject mapping. There is no
-- automatic writer: a future authenticated owner flow must record it before
-- redemption can pass the SQL authorization predicate.
create table id_jag_consents (
    tenant_id text not null,
    user_id uuid not null,
    issuer text not null,
    actor_client_id text not null,
    client_id text not null,
    resource text not null,
    scopes text[] not null,
    granted_at timestamptz not null,
    expires_at timestamptz not null,
    revoked_at timestamptz,
    primary key (tenant_id, user_id, issuer, actor_client_id, client_id, resource),
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade,
    check (length(issuer) between 1 and 2048),
    check (length(actor_client_id) between 1 and 512),
    check (length(resource) between 1 and 2048),
    check (cardinality(scopes) between 1 and 32),
    check (expires_at > granted_at)
);

-- One use per issuer-scoped jti. The hash bounds index size and avoids storing
-- arbitrary token identifiers. No foreign key to clients: the issuer is an
-- externally trusted identity, not necessarily a local OAuth client.
create table id_jag_replays (
    tenant_id text not null,
    issuer text not null,
    jti_hash bytea not null,
    user_id uuid not null,
    expires_at timestamptz not null,
    redeemed_at timestamptz not null default now(),
    primary key (tenant_id, issuer, jti_hash),
    -- Keep the replay tombstone even if a user is deleted during the ID-JAG's
    -- short lifetime. A new binding must not make the same jti usable again.
    check (length(jti_hash) = 32)
);

create index id_jag_replays_expiry on id_jag_replays (tenant_id, expires_at);
