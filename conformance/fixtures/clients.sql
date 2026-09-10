-- The two clients the OIDF FAPI2 Security Profile plan drives. Development
-- values only, for a database that is destroyed at the end of the run.
--
-- Applied by `scripts/conformance.sh` after Asterius has started, for the
-- reason `e2e/fixtures/seed.sql` records: the rows below reference a tenant the
-- server upserts at boot.
--
-- Idempotent, and parameterised with `psql -v`; nothing here is interpolated by
-- a shell.
--
-- Why two clients. The plan needs a second one for the tests that prove a
-- token, an authorization code or a `redirect_uri` issued to one client is
-- refused for another — `fapi2-security-profile-final-attempt-client-2-*`.
-- With one client those modules cannot run, and a plan that cannot run half of
-- its negative tests is the "green because it tested nothing" failure this
-- harness exists to avoid.
--
-- Both authenticate with `private_key_jwt` and both take DPoP-bound tokens:
-- that pair is the plan variant this harness runs, and it is the only pair the
-- server supports today (`features.mtls` is off, and the discovery document
-- announces `private_key_jwt` alone).

\set ON_ERROR_STOP on

-- --------------------------------------------------------------------------
-- Client 1 and client 2.
--
-- `redirect_uris` holds the suite's callback for the test alias, byte for byte,
-- and the same callback with the two dummy query parameters the suite appends
-- for its second client. ADR-0005: this server matches redirect URIs exactly,
-- so a URI that differs by a query string is a rejected authorization request
-- and a whole plan that fails for a reason that is not a finding — which is
-- exactly what the first run of this harness did, at
-- `CheckPAREndpointResponse201WithNoError`, until the second URI was added.
-- Both clients register both, because which of the two a module uses is the
-- module's business and not something to re-derive here.
--
-- The JWKS are the public halves of the keys in
-- `conformance/plans/fapi2-sp-final.json`. They are throwaway P-256 keys,
-- generated once and committed on purpose: the suite has to sign its client
-- assertions with the private half, and a key generated per run would have to
-- be written into both this table and that configuration by something. They
-- belong to nothing else and grant nothing anywhere else.
-- --------------------------------------------------------------------------
insert into clients (
    tenant_id, client_id, client_name, token_endpoint_auth_method,
    redirect_uris, grant_types, response_types, scopes,
    jwks, dpop_bound_access_tokens
)
values (
    :'tenant',
    'conformance-client-1',
    'OIDF conformance client 1',
    'private_key_jwt',
    array[:'redirect_uri', :'redirect_uri_with_query'],
    array['authorization_code', 'refresh_token'],
    array['code'],
    array['openid', 'profile', 'email', 'offline_access'],
    :'jwks1'::jsonb,
    true
), (
    :'tenant',
    'conformance-client-2',
    'OIDF conformance client 2',
    'private_key_jwt',
    array[:'redirect_uri', :'redirect_uri_with_query'],
    array['authorization_code', 'refresh_token'],
    array['code'],
    array['openid', 'profile', 'email', 'offline_access'],
    :'jwks2'::jsonb,
    true
)
on conflict (tenant_id, client_id) do update
set redirect_uris = excluded.redirect_uris,
    grant_types   = excluded.grant_types,
    scopes        = excluded.scopes,
    jwks          = excluded.jwks,
    status        = 'active';
