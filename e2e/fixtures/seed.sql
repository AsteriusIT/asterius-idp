-- Fixture data for the browser sweep. Development values only.
--
-- Applied by `scripts/browser-tests.sh` after the server has started, because
-- the rows below reference tenants the server upserts at boot.
--
-- Idempotent: the script is expected to be run repeatedly against a database
-- somebody keeps around between runs.
--
-- Variables are supplied with `psql -v`; nothing here is interpolated by a
-- shell.

\set ON_ERROR_STOP on

-- --------------------------------------------------------------------------
-- One user, with one password.
--
-- The identifiers are constants so that a re-run updates the same rows rather
-- than accumulating a directory of sweep users.
-- --------------------------------------------------------------------------
--
-- The claim bag carries `preferred_username` (OIDC Core §5.1). It is there
-- because `claims_supported` advertises it (`ast-2vk.8`), and a document that
-- advertises a claim the fixture user does not have is what made the
-- conformance suite report a missing identity claim in `ast-8p1`. It is a
-- *display* name and deliberately not the login identifier: the two differ
-- here so that a test asserting one cannot pass by reading the other.
insert into users (tenant_id, user_id, username, email, email_verified, status, claims)
values (
    :'tenant',
    '3f1d5c2a-0000-4000-8000-000000000001'::uuid,
    :'username',
    :'username',
    true,
    'active',
    '{"preferred_username": {"value": "Sweep User", "source": "local"}}'::jsonb
)
on conflict (tenant_id, user_id) do update
set username = excluded.username,
    claims   = excluded.claims,
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
