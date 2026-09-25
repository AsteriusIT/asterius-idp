-- A monotonic version changes on every account write, including an admin
-- console edit. SCIM If-Match therefore detects edits made outside SCIM too.
alter table users add column scim_revision bigint not null default 1
    check (scim_revision > 0);

create function bump_user_scim_revision() returns trigger language plpgsql as $$
begin
    new.scim_revision := old.scim_revision + 1;
    return new;
end;
$$;

create trigger users_bump_scim_revision before update on users
    for each row execute function bump_user_scim_revision();

-- externalId is controlled by the provisioning client. The same account can
-- be known by distinct external identifiers to distinct clients, while a
-- client cannot assign one identifier to two accounts in a tenant.
create table scim_user_external_ids (
    tenant_id text not null,
    client_id text not null,
    user_id uuid not null,
    external_id text,
    deleted_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (tenant_id, client_id, user_id),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id)
        on delete cascade,
    check (external_id is null or length(external_id) between 1 and 256)
);

create unique index scim_user_external_id_unique
    on scim_user_external_ids (tenant_id, client_id, external_id)
    where external_id is not null and deleted_at is null;

create trigger scim_user_external_ids_set_updated_at
    before update on scim_user_external_ids
    for each row execute function set_updated_at();
