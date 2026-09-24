-- A mailbox link is an invitation to create exactly one account in this
-- tenant. Only the digest is persisted; the bearer token lives in the mail.
create table invitations (
    tenant_id text not null references tenants (tenant_id) on delete cascade,
    invitation_id uuid not null,
    email text not null,
    username text not null,
    token_hash text not null,
    invited_by text not null,
    role text,
    group_ids uuid[] not null default '{}',
    created_at timestamptz not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    revoked_at timestamptz,
    primary key (tenant_id, invitation_id),
    unique (tenant_id, token_hash),
    check (role is null or role in ('tenant_admin', 'user_support', 'security_auditor')),
    check (expires_at > created_at)
);

-- Issuing or resending retires an earlier link for the same address.
create unique index invitations_live_email
    on invitations (tenant_id, lower(email))
    where consumed_at is null and revoked_at is null;

create unique index invitations_live_username
    on invitations (tenant_id, username)
    where consumed_at is null and revoked_at is null;

create index invitations_by_created
    on invitations (tenant_id, created_at desc, invitation_id);
