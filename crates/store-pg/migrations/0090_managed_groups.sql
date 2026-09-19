-- Additive only: legacy users.claims.groups remains the policy authority until
-- the explicit ast-6uqw.12 cutover. Never infer memberships from claims, rewrite
-- names, or rewrite claims from this catalogue. See docs/groups-migration.md.
create table managed_groups (
    tenant_id text not null references tenants (tenant_id) on delete cascade,
    group_id uuid not null,
    name text collate "C" not null
        check (name ~ '^[a-z0-9][a-z0-9._:-]{0,63}$'),
    display_name text not null
        check (octet_length(display_name) between 1 and 200)
        -- Match the parser's Unicode whitespace, C0/C1 and bidi exclusions.
        check (display_name !~ U&'[\0001-\001F\007F-\009F\061C\200E\200F\202A-\202E\2066-\2069]')
        check (display_name !~ U&'^[\0009-\000D\0020\0085\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]|[\0009-\000D\0020\0085\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]$'),
    revision bigint not null default 1 check (revision > 0),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    primary key (tenant_id, group_id),
    unique (tenant_id, name)
);

create table group_memberships (
    tenant_id text not null,
    group_id uuid not null,
    user_id uuid not null,
    created_at timestamptz not null,
    primary key (tenant_id, group_id, user_id),
    foreign key (tenant_id, group_id)
        references managed_groups (tenant_id, group_id) on delete cascade,
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade
);

-- Direct memberships only. This index also supports user-deletion cascades.
create index group_memberships_by_user
    on group_memberships (tenant_id, user_id, group_id);
