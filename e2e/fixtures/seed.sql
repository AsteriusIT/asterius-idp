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
