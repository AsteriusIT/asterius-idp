-- Seeds what the load scripts need: three clients that sign with the key
-- gen-keys.sh produced, and one person with a password.
--
--     psql "$DATABASE_URL" -v tenant=load -v issuer=https://localhost:9443/t/load \
--          -v jwks="$(cat scripts/load/client.jwks.json)" -f scripts/load/seed.sql
--
-- Idempotent: re-running it re-asserts the same rows. Written as SQL rather
-- than through the admin API because the admin API's own cost is not what is
-- being measured, and because a load stack is disposable — this file must
-- never run against a database that holds anyone's account.
--
-- The person's password is the deployment admin's: the hash is copied from
-- the account `[admin]` seeded at boot, so the operator who exported
-- ASTERIUS_ADMIN_PASSWORD already holds the one credential the scripts need,
-- and no second secret has to travel. That is acceptable on a stack whose
-- only purpose is to be measured and thrown away, and on nothing else.

\set ON_ERROR_STOP on

-- The browser-flow client: authorization_code with PKCE, DPoP-bound tokens,
-- private_key_jwt. The registration mirrors what a relying party would push
-- through RFC 7591, minus the parts the load scripts never touch.
insert into clients (
    tenant_id, client_id, client_name, token_endpoint_auth_method,
    redirect_uris, grant_types, response_types, scopes, jwks
) values (
    :'tenant', 'load-client', 'Load: browser flow', 'private_key_jwt',
    '{https://rp.example/cb}', '{authorization_code,refresh_token}', '{code}',
    '{openid,offline_access}', :'jwks'::jsonb
)
on conflict (tenant_id, client_id) do update set
    redirect_uris = excluded.redirect_uris,
    grant_types = excluded.grant_types,
    response_types = excluded.response_types,
    scopes = excluded.scopes,
    jwks = excluded.jwks,
    status = 'active';

-- The machine client: client_credentials only, no redirect URI, no response
-- type (RFC 7591 §2.1's table). Its tokens are audienced at the tenant's
-- default resource, which is what a service client's ordinarily are.
insert into clients (
    tenant_id, client_id, client_name, token_endpoint_auth_method,
    redirect_uris, grant_types, response_types, scopes, jwks
) values (
    :'tenant', 'load-machine', 'Load: machine client', 'private_key_jwt',
    '{}', '{client_credentials}', '{}',
    '{load.read}', :'jwks'::jsonb
)
on conflict (tenant_id, client_id) do update set
    grant_types = excluded.grant_types,
    response_types = excluded.response_types,
    scopes = excluded.scopes,
    resources = '{}',
    jwks = excluded.jwks,
    status = 'active';

-- The SSF receiver (SSF 1.0 §8): a second machine client, because a receiver
-- asks for tokens audienced at the transmitter's own endpoints and a client
-- may only ask for what its allow-list names (RFC 8707 §2; `issuance.rs`).
-- Its own client so that `load-machine` above keeps the plain shape the
-- token-endpoint numbers are about.
insert into clients (
    tenant_id, client_id, client_name, token_endpoint_auth_method,
    redirect_uris, grant_types, response_types, scopes, resources, jwks
) values (
    :'tenant', 'load-receiver', 'Load: SSF receiver', 'private_key_jwt',
    '{}', '{client_credentials}', '{}',
    '{ssf.manage,ssf.poll}',
    array[:'issuer' || '/ssf/streams', :'issuer' || '/ssf/poll'],
    :'jwks'::jsonb
)
on conflict (tenant_id, client_id) do update set
    grant_types = excluded.grant_types,
    response_types = excluded.response_types,
    scopes = excluded.scopes,
    resources = excluded.resources,
    jwks = excluded.jwks,
    status = 'active';

-- The person. A fixed uuid so the row is the same across runs.
insert into users (tenant_id, user_id, username, status)
values (:'tenant', '6c0ad000-0000-4000-8000-000000000001', 'load-user', 'active')
on conflict (tenant_id, user_id) do update set username = excluded.username, status = 'active';

-- Their password: the deployment admin's hash, verbatim. Argon2id parameters
-- travel inside the PHC string, so the copy verifies exactly as the original.
insert into credentials (tenant_id, credential_id, user_id, kind, password_hash)
select :'tenant', '6c0ad000-0000-4000-8000-000000000002',
       '6c0ad000-0000-4000-8000-000000000001', 'password', c.password_hash
from credentials c
join users u on u.tenant_id = c.tenant_id and u.user_id = c.user_id
where u.tenant_id = 'admin' and u.username = 'admin' and c.kind = 'password'
on conflict (tenant_id, credential_id) do update set
    password_hash = excluded.password_hash,
    disabled_at = null;

select client_id, grant_types, scopes, resources from clients where tenant_id = :'tenant' order by client_id;
select username, (select count(*) from credentials c where c.tenant_id = u.tenant_id and c.user_id = u.user_id) as credentials
from users u where tenant_id = :'tenant';
