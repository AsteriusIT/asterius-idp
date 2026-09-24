-- Pending self-service email changes are separate from mailbox verification.
-- The old address remains authoritative until a one-use token is confirmed.
create table email_change_requests (
    tenant_id text not null,
    token_hash text not null,
    user_id uuid not null,
    old_address text not null,
    old_verified boolean not null,
    new_address text not null,
    issued_at timestamptz not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    consumed_reason text check (consumed_reason in ('spent', 'superseded', 'conflict')),
    primary key (tenant_id, token_hash),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade,
    constraint email_change_expiry_after_issue check (expires_at > issued_at),
    constraint email_change_consumption_reason
        check ((consumed_at is null) = (consumed_reason is null))
);

create index email_changes_by_user on email_change_requests (tenant_id, user_id, expires_at);
create index email_changes_by_expiry on email_change_requests (expires_at);
