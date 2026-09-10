-- Two restricted administrative roles (`ast-3t8`).
--
-- ADR-0010 keeps authority readable in the data: a role is a value of a closed
-- set, named in `asterius_domain::Role`, and the schema states the same set in
-- a check constraint. Adding a role is therefore a migration — deliberately,
-- because it is a decision about what somebody may do to other people's
-- accounts and not a configuration item.
--
--  * `user_support` reads accounts and acts on their sessions and grants. It
--    cannot write to the account itself: ending a session somebody is stuck in
--    is support work, editing the claims that describe them is not.
--  * `security_auditor` reads and writes nothing at all, so that reviewing a
--    deployment does not require the authority to change it.
--
-- Both are tenant-scoped, which is why the deployment-scope constraint below is
-- untouched: it still names `deployment_admin` and only `deployment_admin`, and
-- a restricted role in the reserved tenant is a restricted role over the
-- reserved tenant and nothing wider.
--
-- The check is replaced rather than widened in place because Postgres has no
-- "alter check": the baseline's inline check carries the generated name
-- `user_roles_role_check`, and what replaces it is named, so the next migration
-- to touch it does not have to know how the name was generated.
alter table user_roles
    drop constraint user_roles_role_check;

alter table user_roles
    add constraint user_roles_role_is_known
        check (role in (
            'tenant_admin',
            'deployment_admin',
            'user_support',
            'security_auditor'
        ));
