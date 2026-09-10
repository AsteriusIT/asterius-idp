-- Application roles: what a tenant delegates to its own applications
-- (`ast-095`).
--
-- Distinct from `user_roles`, which is authority over *this server* and whose
-- vocabulary is a two-value check constraint decided at compile time. What is
-- added here is the opposite kind of thing: a name a tenant invents, copied
-- into an access token, and interpreted by a resource server this deployment
-- never sees. The two must not share a table, or a role created through the
-- admin API would be one `insert` away from being read as `deployment_admin`.
--
-- # Four tables, not one with a nullable `client_id`
--
-- The obvious alternative is a single `application_roles (tenant_id,
-- client_id, name)` with `client_id` null for a tenant-wide role. It is
-- rejected here for one reason that is about correctness rather than taste:
-- in Postgres a unique constraint treats NULLs as *distinct*, so
-- `unique (tenant_id, client_id, name)` would happily admit two tenant roles
-- both called `auditor`. `nulls not distinct` (PG 15+) fixes that, at the
-- price of raising this schema's floor and of a natural key that is partly
-- absent — every foreign key from the assignment table would then have to
-- carry the same nullable column and the same subtlety.
--
-- Four tables make each key total: `(tenant_id, name)` for a tenant role and
-- `(tenant_id, client_id, name)` for a client role, both of them referenced by
-- a matching assignment table. The cost is one extra join at read time, paid
-- once per token issuance by an index-only scan.
--
-- # Deleting a role that somebody holds is refused, not cascaded
--
-- `on delete restrict` on both assignment tables. `ast-095` asked for a
-- decision between "removing a role removes it from everybody" and "removing a
-- role is refused while it is held", and this is the second.
--
-- A cascade would be one API call that silently withdraws authority from an
-- unbounded number of people, recorded as a single audit event that names none
-- of them. Somebody investigating "why did four hundred users lose access on
-- Tuesday" would find one line. A refusal makes the administrator revoke the
-- assignments first, so each withdrawal is its own audited act, and it is the
-- reversible direction: a role deleted by accident cannot be un-deleted with
-- its assignment list intact.
--
-- The admin API renders the refusal as `409 Conflict`; see the OpenAPI
-- document for `roles.tenant.delete` and `roles.client.delete`.
--
-- # The alphabet is checked twice on purpose
--
-- `asterius_domain::RoleName::parse` is the parser (and is fuzzed). The check
-- constraint below is the same rule stated where a hand-written `insert` or a
-- future second adapter also has to obey it — a role name is copied verbatim
-- into a JWT, so "no whitespace, no uppercase, no control character" must be a
-- fact about the stored data and not about the code path that happened to
-- write it.

-- ---------------------------------------------------------------------------
-- Catalogues
-- ---------------------------------------------------------------------------

-- The tenant's shared vocabulary: every application of the tenant sees these
-- in the `roles` claim.
create table tenant_roles (
    tenant_id   text        not null
                references tenants (tenant_id) on delete cascade,
    name        text        not null
                check (name ~ '^[a-z0-9][a-z0-9._:-]{0,63}$'),
    description text        check (length(description) <= 200),
    created_at  timestamptz not null default now(),

    primary key (tenant_id, name)
);

-- One client's own vocabulary, issued under
-- `resource_access.<client_id>.roles`. Two clients may both define `admin`
-- without either of them widening the other.
create table client_roles (
    tenant_id   text        not null,
    client_id   text        not null,
    name        text        not null
                check (name ~ '^[a-z0-9][a-z0-9._:-]{0,63}$'),
    description text        check (length(description) <= 200),
    created_at  timestamptz not null default now(),

    primary key (tenant_id, client_id, name),
    -- The pair, never the id alone: a role cannot belong to a client of
    -- another tenant, and deleting a client takes its catalogue with it. The
    -- catalogue is meaningless without the client — nothing can be assigned it
    -- and no token can carry it — so this is the one cascade here.
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade
);

-- ---------------------------------------------------------------------------
-- Assignments
-- ---------------------------------------------------------------------------

create table user_tenant_roles (
    tenant_id  text        not null,
    user_id    uuid        not null,
    name       text        not null,
    granted_at timestamptz not null default now(),

    primary key (tenant_id, user_id, name),
    -- Deleting the account takes its assignments; deleting the role does not.
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    foreign key (tenant_id, name)
        references tenant_roles (tenant_id, name) on delete restrict
);

create table user_client_roles (
    tenant_id  text        not null,
    client_id  text        not null,
    user_id    uuid        not null,
    name       text        not null,
    granted_at timestamptz not null default now(),

    primary key (tenant_id, client_id, user_id, name),
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    foreign key (tenant_id, client_id, name)
        references client_roles (tenant_id, client_id, name) on delete restrict
);

-- "Who holds this role?", which is the question an administrator asks before
-- deleting one and the question the `409` above sends them to. Without it the
-- answer is a scan of every assignment in the tenant.
create index user_tenant_roles_by_role on user_tenant_roles (tenant_id, name);
create index user_client_roles_by_role on user_client_roles (tenant_id, client_id, name);

-- The read on the token path: everything one account holds, in one index scan
-- per table. It is on the hot path of every access token issued to a user, so
-- it is an index and not a hope about row counts.
create index user_client_roles_by_user on user_client_roles (tenant_id, user_id);
