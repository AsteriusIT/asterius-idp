-- TOTP material is always wrapped by the deployment KEK. There is one
-- credential per user and tenant; pending enrollment expires automatically
-- and is never returned by repository reads.
create table totp_credentials (
    tenant_id text not null,
    user_id uuid not null,
    ciphertext bytea not null,
    nonce bytea not null,
    kek_id text not null,
    state text not null check (state in ('pending', 'active')),
    created_at timestamptz not null,
    expires_at timestamptz not null,
    activated_at timestamptz,
    failed_attempts smallint not null default 0 check (failed_attempts between 0 and 5),
    primary key (tenant_id, user_id),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade,
    check (expires_at > created_at),
    check ((state = 'pending' and activated_at is null) or
           (state = 'active' and activated_at is not null))
);

create index totp_credentials_by_expiry
    on totp_credentials (expires_at)
    where state = 'pending';
