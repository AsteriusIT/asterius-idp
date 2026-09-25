-- Inbound SET subject bindings are explicit per trusted peer. There is no
-- email/username fallback: only a mapping an operator established can name a
-- local account. Accepted event IDs are retained through token expiry so
-- retries and replay attempts stay idempotent across replicas and restarts.
create table ssf_receiver_subject_mappings (
    tenant_id text not null,
    peer_client_id text not null,
    subject_key text not null,
    user_id uuid not null,
    created_at timestamptz not null default now(),
    primary key (tenant_id, peer_client_id, subject_key),
    foreign key (tenant_id, peer_client_id)
        references clients (tenant_id, client_id) on delete cascade,
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    check (length(subject_key) between 1 and 4096)
);

create index ssf_receiver_subjects_by_user
    on ssf_receiver_subject_mappings (tenant_id, user_id);

create table ssf_receiver_events (
    tenant_id text not null,
    peer_client_id text not null,
    jti text not null,
    replay_until timestamptz not null,
    user_id uuid not null,
    event_type text not null,
    processed_at timestamptz not null default now(),
    primary key (tenant_id, peer_client_id, jti),
    foreign key (tenant_id, peer_client_id)
        references clients (tenant_id, client_id) on delete cascade,
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    check (length(jti) between 1 and 255),
    check (event_type in ('session-revoked', 'account-disabled'))
);

create index ssf_receiver_events_expiry on ssf_receiver_events (replay_until);
