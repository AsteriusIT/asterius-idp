-- Volume for the EXPLAIN review: enough rows in every table the hot paths
-- touch that the planner has something to choose between. On an empty table
-- PostgreSQL sequentially scans everything and reports it as the cheapest
-- plan, which is true and tells you nothing; the question the review asks
-- is what the plan becomes once the table has grown.
--
--     psql "$DATABASE_URL" -v n=50000 -f scripts/load/explain-seed.sql
--
-- Throwaway database only: this fills a tenant `explain` with synthetic rows
-- (digests are SHA-256 of a counter, keys are placeholders) and the review's
-- write statements are rolled back by explain-queries.sql, so the seed can be
-- reused. `n` rows per growing table; the reference tables (tenants, clients,
-- signing keys, resource servers) stay the size they are in a real
-- deployment, which is small.

\set ON_ERROR_STOP on
\if :{?n}
\else
  \set n 50000
\endif

set client_min_messages = warning;

insert into tenants (tenant_id, issuer, display_name, default_resource)
values ('explain', 'https://explain.example/t/explain', 'Explain', 'https://explain.example/t/explain')
on conflict (tenant_id) do nothing;

insert into clients (
    tenant_id, client_id, client_name, token_endpoint_auth_method,
    redirect_uris, grant_types, response_types, scopes, jwks, backchannel_logout_uri
) values (
    'explain', 'rp', 'Relying party', 'private_key_jwt',
    '{https://rp.example/cb}', '{authorization_code,refresh_token,client_credentials}',
    '{code}', '{openid,offline_access}', '{"keys":[]}', 'https://rp.example/backchannel-logout'
)
on conflict (tenant_id, client_id) do nothing;

insert into resource_servers (tenant_id, identifier, scopes)
values ('explain', 'https://api.example/', '{read,write}')
on conflict (tenant_id, identifier) do nothing;

-- Three keys, as a tenant mid-rotation holds: one active, one retiring, one
-- pending. The material is a placeholder that satisfies the constraints
-- (distinct `x`, a ciphertext longer than a tag, a nonce per key).
insert into signing_keys (tenant_id, kid, alg, purpose, public_jwk, private_key_ciphertext, private_key_nonce, kek_id, state, created_at, activated_at, retiring_at)
select 'explain', 'explain-' || s.state, 'ES256', 'sig',
       jsonb_build_object('kty', 'EC', 'crv', 'P-256', 'use', 'sig', 'x', 'explain-x-' || s.state, 'y', 'explain-y-' || s.state),
       decode(repeat('ab', 40), 'hex'), substr(decode(md5('nonce-' || s.state), 'hex'), 1, 12), 'kek-explain',
       s.state,
       now() - interval '1 day',
       case when s.state = 'pending' then null else now() - interval '1 day' end,
       case when s.state = 'retiring' then now() - interval '1 hour' else null end
from (values ('active'), ('retiring'), ('pending')) as s(state)
on conflict (tenant_id, kid) do nothing;

-- A deterministic uuid per counter, so the tables can reference each other.
create or replace function pg_temp.explain_uuid(prefix text, i bigint) returns uuid
language sql immutable as $$
    select (substr(md5(prefix || i), 1, 8) || '-' || substr(md5(prefix || i), 9, 4) || '-4'
            || substr(md5(prefix || i), 14, 3) || '-8' || substr(md5(prefix || i), 18, 3) || '-'
            || substr(md5(prefix || i), 21, 12))::uuid
$$;

insert into users (tenant_id, user_id, username, email, status)
select 'explain', pg_temp.explain_uuid('user', i), 'user-' || i, 'user-' || i || '@example.test', 'active'
from generate_series(1, :n) as i
on conflict (tenant_id, user_id) do nothing;

insert into credentials (tenant_id, credential_id, user_id, kind, password_hash)
select 'explain', pg_temp.explain_uuid('password', i), pg_temp.explain_uuid('user', i), 'password',
       '$argon2id$v=19$m=19456,t=2,p=1$ZXhwbGFpbi1zYWx0$ZXhwbGFpbi1ub3QtYS1yZWFsLWhhc2g'
from generate_series(1, :n) as i
on conflict (tenant_id, credential_id) do nothing;

insert into credentials (tenant_id, credential_id, user_id, kind, passkey_credential_id, passkey_public_key, passkey_rp_id, passkey_sign_count)
select 'explain', pg_temp.explain_uuid('passkey', i), pg_temp.explain_uuid('user', i), 'passkey',
       sha256(('passkey-' || i)::bytea), decode(repeat('cd', 77), 'hex'), 'explain.example', i
from generate_series(1, :n) as i
on conflict (tenant_id, credential_id) do nothing;

insert into subject_identifiers (tenant_id, user_id, sector_identifier, subject)
select 'explain', pg_temp.explain_uuid('user', i), '', 'sub-' || i
from generate_series(1, :n) as i
on conflict (tenant_id, user_id, sector_identifier) do nothing;

insert into sessions (tenant_id, session_id, public_sid, user_id, created_at, authenticated_at, last_seen_at, expires_at, idle_expires_at, amr)
select 'explain', 'session-' || i, 'sid-' || i, pg_temp.explain_uuid('user', i),
       now() - (i % 720) * interval '1 hour', now() - (i % 720) * interval '1 hour', now(),
       now() + interval '12 hours' - (i % 720) * interval '1 hour', now() + interval '1 hour', '{pwd}'
from generate_series(1, :n) as i
on conflict (tenant_id, session_id) do nothing;

insert into session_clients (tenant_id, session_id, client_id)
select 'explain', 'session-' || i, 'rp' from generate_series(1, :n) as i
on conflict (tenant_id, session_id, client_id) do nothing;

-- Half the pushed requests have been turned into interactions.
insert into auth_requests (tenant_id, request_uri_hash, client_id, parameters, interaction_id_hash, pushed_at, expires_at, consumed_at)
select 'explain', sha256(('request-' || i)::bytea), 'rp', '{"scope":"openid"}'::jsonb,
       case when i % 2 = 0 then sha256(('interaction-' || i)::bytea) end,
       now() - (i % 600) * interval '1 second',
       now() + interval '10 minutes' - (i % 600) * interval '1 second',
       case when i % 10 = 0 then now() end
from generate_series(1, :n) as i
on conflict (tenant_id, request_uri_hash) do nothing;

-- Grants over a month, one in a hundred never claimed (a consent whose code
-- was never redeemed), one in fifty revoked.
insert into grants (tenant_id, grant_id, client_id, user_id, subject, scopes, session_id, authenticated_at, created_at, updated_at, claimed_at, revoked_at, revocation_reason)
select 'explain', pg_temp.explain_uuid('grant', i), 'rp', pg_temp.explain_uuid('user', i), 'sub-' || i, '{openid,offline_access}',
       'session-' || i, now() - (i % 30) * interval '1 day',
       now() - (i % 30) * interval '1 day', now() - (i % 30) * interval '1 day',
       case when i % 100 = 0 then null else now() - (i % 30) * interval '1 day' end,
       case when i % 50 = 0 then now() - interval '1 day' end,
       case when i % 50 = 0 then 'user' end
from generate_series(1, :n) as i
on conflict (tenant_id, grant_id) do nothing;

insert into authorization_codes (tenant_id, code_hash, client_id, grant_id, code_challenge, redirect_uri, issued_at, expires_at, consumed_at)
select 'explain', sha256(('code-' || i)::bytea), 'rp', pg_temp.explain_uuid('grant', i),
       'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'https://rp.example/cb',
       now() - (i % 60) * interval '1 second', now() + interval '1 minute' - (i % 60) * interval '1 second',
       case when i % 3 = 0 then now() end
from generate_series(1, :n) as i
on conflict (tenant_id, code_hash) do nothing;

insert into refresh_tokens (tenant_id, token_hash, grant_id, client_id, scopes, dpop_jkt, issued_at, absolute_expires_at, idle_expires_at)
select 'explain', sha256(('refresh-' || i)::bytea), pg_temp.explain_uuid('grant', i), 'rp', '{openid,offline_access}',
       'jkt-' || i, now() - (i % 30) * interval '1 day',
       now() + interval '30 days' - (i % 30) * interval '1 day', now() + interval '14 days' - (i % 30) * interval '1 day'
from generate_series(1, :n) as i
on conflict (tenant_id, token_hash) do nothing;

insert into jti_replay (tenant_id, purpose, subject, jti_hash, expires_at)
select 'explain', case when i % 2 = 0 then 'client_assertion' else 'dpop_proof' end, 'rp',
       sha256(('jti-' || i)::bytea), now() + interval '5 minutes' - (i % 300) * interval '1 second'
from generate_series(1, :n) as i
on conflict do nothing;

-- A thousand addresses, each with a window per minute going back.
insert into rate_limits (tenant_id, bucket, window_start, counter, expires_at)
select 'explain', 'token:address:' || (i % 1000), date_trunc('minute', now()) - (i / 1000) * interval '1 minute',
       1 + (i % 50), date_trunc('minute', now()) + interval '2 minutes' - (i / 1000) * interval '1 minute'
from generate_series(1, :n) as i
on conflict do nothing;

insert into access_token_denylist (tenant_id, jti, grant_id, revoked_at, expires_at)
select 'explain', 'at-' || i, pg_temp.explain_uuid('grant', i), now(), now() + interval '5 minutes'
from generate_series(1, :n) as i
on conflict do nothing;

insert into access_token_cutoffs (tenant_id, principal_kind, principal_id, revoked_before, expires_at)
select 'explain', 'grant', pg_temp.explain_uuid('grant', i)::text, now(), now() + interval '5 minutes'
from generate_series(1, :n / 10) as i
on conflict do nothing;

insert into ssf_streams (tenant_id, stream_id, client_id, audience, delivery_method)
values ('explain', 'stream-explain', 'rp', '{https://rp.example}', 'urn:ietf:rfc:8936')
on conflict (tenant_id, stream_id) do nothing;

-- An outbox as a healthy deployment carries one: almost everything delivered
-- and waiting for retention, a few hundred pending, a handful failed.
insert into outbox (tenant_id, kind, destination, payload, status, attempts, created_at, available_at, delivered_at, ordering_key)
select 'explain',
       case when i % 2 = 0 then 'ssf.set' else 'logout.backchannel' end,
       case when i % 2 = 0 then 'stream-explain' else 'https://rp.example/backchannel-logout' end,
       '{"jti":"explain"}'::jsonb,
       case when i % 100 = 0 then 'pending' when i % 250 = 0 then 'failed' when i % 500 = 0 then 'abandoned' else 'delivered' end,
       case when i % 250 = 0 then 3 else 1 end,
       now() - (i % 720) * interval '1 hour', now() - (i % 720) * interval '1 hour',
       case when i % 100 = 0 or i % 250 = 0 or i % 500 = 0 then null else now() - (i % 720) * interval '1 hour' end,
       case when i % 2 = 1 then 'rp:session-' || (i % 100) end
from generate_series(1, :n) as i;

insert into ssf_poll_queue (tenant_id, stream_id, jti, set_jws, queued_at)
select 'explain', 'stream-explain', 'set-' || i, 'eyJhbGciOiJFUzI1NiJ9.explain.sig', now() - (i % 3600) * interval '1 second'
from generate_series(1, :n) as i
on conflict do nothing;

-- Recovery tokens for a tenth of the people, most of them long expired and
-- waiting for the sweep.
insert into recovery_tokens (tenant_id, token_hash, user_id, issued_at, expires_at)
select 'explain', sha256(('recovery-' || i)::bytea), pg_temp.explain_uuid('user', i),
       now() - (i % 720) * interval '1 hour', now() + interval '1 hour' - (i % 720) * interval '1 hour'
from generate_series(1, :n / 10) as i
on conflict (tenant_id, token_hash) do nothing;

insert into audit_events (tenant_id, occurred_at, event_type, outcome, actor, subject, client_id, grant_id, detail, previous_hash, event_hash)
select 'explain', now() - (i % 720) * interval '1 hour', 'token.issued', 'success',
       jsonb_build_object('kind', 'client', 'id', 'rp'), 'sub-' || i, 'rp', pg_temp.explain_uuid('grant', i), '{}'::jsonb,
       sha256(('event-' || (i - 1))::bytea), sha256(('event-' || i)::bytea)
from generate_series(1, :n) as i
on conflict do nothing;

analyze;

select relname as "table", n_live_tup as rows
from pg_stat_user_tables
where relname in ('users', 'sessions', 'auth_requests', 'grants', 'authorization_codes', 'refresh_tokens',
                  'jti_replay', 'rate_limits', 'access_token_denylist', 'outbox', 'ssf_poll_queue', 'audit_events',
                  'recovery_tokens')
order by relname;
