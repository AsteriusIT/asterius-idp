-- Candidate online authentication state. No bearer JWT is retained.
create table kubernetes_online_profiles (
    tenant_id text not null,
    client_id text not null,
    reviewer_client_id text not null,
    revision uuid not null default gen_random_uuid(),
    enabled boolean not null default false,
    primary key (tenant_id, client_id),
    check (client_id <> reviewer_client_id),
    foreign key (tenant_id, client_id)
        references kubernetes_profiles (tenant_id, client_id) on delete cascade,
    foreign key (tenant_id, reviewer_client_id)
        references clients (tenant_id, client_id) on delete cascade
);

-- Every administrative update invalidates previously issued bindings, including
-- disable/re-enable and reviewer replacement. No caller supplies the new revision.
create function kubernetes_online_revision() returns trigger language plpgsql as $$
begin
    new.revision := gen_random_uuid();
    return new;
end
$$;
create trigger kubernetes_online_revision before update on kubernetes_online_profiles
    for each row execute function kubernetes_online_revision();

create table kubernetes_online_tokens (
    tenant_id text not null,
    token_digest bytea not null check (octet_length(token_digest) = 32),
    client_id text not null,
    grant_id uuid not null,
    user_id uuid not null,
    public_sid text not null,
    subject text not null check (octet_length(subject) between 1 and 2048),
    profile_revision uuid not null,
    cluster_profile_revision bigint not null check (cluster_profile_revision > 0),
    reviewer_client_id text not null,
    issued_at timestamptz not null,
    expires_at timestamptz not null,
    primary key (tenant_id, token_digest),
    check (expires_at > issued_at and expires_at <= issued_at + interval '300 seconds'),
    foreign key (tenant_id, client_id)
        references kubernetes_online_profiles (tenant_id, client_id) on delete cascade,
    foreign key (tenant_id, grant_id)
        references grants (tenant_id, grant_id) on delete cascade,
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    foreign key (tenant_id, public_sid)
        references sessions (tenant_id, public_sid) on delete cascade,
    foreign key (tenant_id, reviewer_client_id)
        references clients (tenant_id, client_id) on delete cascade
);
create index kubernetes_online_tokens_expiry on kubernetes_online_tokens (expires_at);
