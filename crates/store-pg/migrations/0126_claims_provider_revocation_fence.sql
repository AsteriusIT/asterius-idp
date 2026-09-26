-- A user revoke fences a callback that already consumed its one-use state.
-- New authorization attempts started after the revoke remain valid.
alter table claims_provider_oauth_pending
    add column created_at timestamptz not null default now();

-- Pre-upgrade attempts carry only the old instance's clock and cannot be
-- ordered safely against a database-time revoke. They are single-use and
-- expire in ten minutes; require these users to start setup again.
delete from claims_provider_oauth_pending;

create table claims_provider_oauth_revocations (
    tenant_id text not null,
    user_id uuid not null,
    provider_issuer text not null,
    revoked_at timestamptz not null,
    primary key (tenant_id,user_id,provider_issuer),
    foreign key (tenant_id,user_id) references users (tenant_id,user_id) on delete cascade,
    check (length(provider_issuer) between 1 and 2048)
);

create index claims_provider_oauth_revocations_expiry
    on claims_provider_oauth_revocations (revoked_at);
