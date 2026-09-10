-- Fixture data for the browser sweep. Development values only.
--
-- Applied by `scripts/browser-tests.sh` *after* the server has started, because
-- the server upserts its configured tenants at boot and that upsert overwrites
-- `custom_host`.
--
-- Idempotent: the script is expected to be run repeatedly against a database
-- somebody keeps around between runs.
--
-- Variables are supplied with `psql -v`; nothing here is interpolated by a
-- shell.

\set ON_ERROR_STOP on

-- --------------------------------------------------------------------------
-- The tenant answers to a hostname, not only to a path.
--
-- Not cosmetic. `/authorize` redirects to `/interaction/{id}` and both pages
-- post to `/interaction/{id}` — root-relative, with no tenant prefix — so a
-- tenant reachable only at `/t/{id}/…` loses its tenant on the second hop and
-- the browser gets a 404 (`crates/server/src/tenancy.rs`: a path with no tenant
-- is resolved by host, and `by_host` is indexed on `custom_host` alone). The
-- flow this sweep exists to walk therefore only completes for a host-routed
-- tenant, and there is no configuration key for `custom_host` yet — hence this
-- statement. See the note in `e2e/README.md`.
-- --------------------------------------------------------------------------
update tenants set custom_host = :'host' where tenant_id = :'tenant';

-- --------------------------------------------------------------------------
-- One user, with one password.
--
-- The identifiers are constants so that a re-run updates the same rows rather
-- than accumulating a directory of sweep users.
-- --------------------------------------------------------------------------
insert into users (tenant_id, user_id, username, email, email_verified, status)
values (
    :'tenant',
    '3f1d5c2a-0000-4000-8000-000000000001'::uuid,
    :'username',
    :'username',
    true,
    'active'
)
on conflict (tenant_id, user_id) do update
set username = excluded.username,
    status   = 'active';

-- The Argon2id hash of the password in `e2e/src/environment.ts`, at the
-- parameters `Argon2Parameters::default()` names (m=19456, t=2, p=1 — OWASP's
-- minimum, which `crates/domain/src/entities/password.rs` enforces as a floor).
--
-- A constant rather than a value computed at seed time: computing it would put
-- an Argon2 implementation in this harness, and the only thing that would test
-- is the harness. The salt is fixed for the same reason a fixture is fixed.
-- This is a throwaway credential for a throwaway database and belongs nowhere
-- else.
insert into credentials (tenant_id, credential_id, user_id, kind, password_hash, label)
values (
    :'tenant',
    '3f1d5c2a-0000-4000-8000-000000000002'::uuid,
    '3f1d5c2a-0000-4000-8000-000000000001'::uuid,
    'password',
    :'hash',
    'browser sweep'
)
on conflict (tenant_id, credential_id) do update
set password_hash = excluded.password_hash,
    disabled_at   = null;

-- --------------------------------------------------------------------------
-- One role, so the console shell has something to draw.
--
-- `ast-xka`: since `ast-wr4` the entry document is served only to a session,
-- and the shell the browser then renders is role-driven — with no role the
-- navigation is empty and the accessibility sweep would be run over a screen
-- no administrator ever sees. `tenant_admin` is the smaller of the two roles
-- `crates/domain/src/entities/role.rs` knows, and it reaches every tenant
-- destination in `console/src/navigation.ts` without granting anything
-- deployment-wide.
--
-- `tenant_is_reserved` is read from the tenant rather than asserted: the
-- foreign key on `(tenant_id, tenant_is_reserved)` is what refuses a
-- deployment-scoped role outside the reserved tenant, and a literal here would
-- be a second place to be wrong about which tenant this is.
-- --------------------------------------------------------------------------
insert into user_roles (tenant_id, user_id, role, tenant_is_reserved)
select :'tenant',
       '3f1d5c2a-0000-4000-8000-000000000001'::uuid,
       'tenant_admin',
       tenants.is_reserved
from tenants
where tenants.tenant_id = :'tenant'
on conflict (tenant_id, user_id, role) do nothing;
