-- The hot statements, as `.sqlx/` records them, with `EXPLAIN (ANALYZE,
-- BUFFERS)` and literal parameters against the `explain` tenant that
-- explain-seed.sql filled. explain.sh runs this and reports every sequential
-- scan on a table that grows; read the plans themselves for the rest.
--
-- The whole file is one transaction that is rolled back, so the writes leave
-- the seed as they found it and the file can be run again.
--
-- Grouped by the path that runs them, in the order that path runs them (the
-- order the query-budget test in crates/server/tests/end_to_end.rs prints).

\set ON_ERROR_STOP on
\set t '''explain'''
\pset pager off
set client_min_messages = warning;

-- The same deterministic uuid the seed used, so a parameter names a row.
create or replace function pg_temp.explain_uuid(prefix text, i bigint) returns uuid
language sql immutable as $$
    select (substr(md5(prefix || i), 1, 8) || '-' || substr(md5(prefix || i), 9, 4) || '-4'
            || substr(md5(prefix || i), 14, 3) || '-8' || substr(md5(prefix || i), 18, 3) || '-'
            || substr(md5(prefix || i), 21, 12))::uuid
$$;

begin;

\echo '#### every request: tenant resolution, throttling, replay guards'
explain (analyze, buffers) select tenant_id, issuer, custom_host, display_name, default_resource, status, settings, created_at, updated_at from tenants where issuer = 'https://explain.example/t/explain';
explain (analyze, buffers) select tenant_id, issuer, custom_host, display_name, default_resource, status, settings, created_at, updated_at from tenants where tenant_id = :t;
explain (analyze, buffers) select settings from tenants where tenant_id = :t;
explain (analyze, buffers) select counter from rate_limits where tenant_id = :t and bucket = 'token:address:7' and window_start = date_trunc('minute', now());
explain (analyze, buffers) insert into rate_limits (tenant_id, bucket, window_start, counter, expires_at) values (:t, 'token:address:7', date_trunc('minute', now()), 1, now() + interval '2 minutes') on conflict (tenant_id, bucket, window_start) do update set counter = rate_limits.counter + 1 returning counter;
explain (analyze, buffers) insert into jti_replay (tenant_id, purpose, subject, jti_hash, expires_at) values (:t, 'client_assertion', 'rp', sha256('fresh'::bytea), now() + interval '5 minutes') on conflict (tenant_id, purpose, subject, jti_hash) do nothing;
explain (analyze, buffers) select client_id, client_name, token_endpoint_auth_method, redirect_uris, grant_types, response_types, scopes, resources, jwks, jwks_uri, status from clients where tenant_id = :t and client_id = 'rp';

\echo '#### PAR (RFC 9126) and /authorize'
explain (analyze, buffers) insert into auth_requests (tenant_id, request_uri_hash, client_id, parameters, pushed_at, expires_at) values (:t, sha256('fresh-request'::bytea), 'rp', '{}'::jsonb, now(), now() + interval '10 minutes');
explain (analyze, buffers) select client_id, parameters, pushed_at, expires_at from auth_requests where tenant_id = :t and request_uri_hash = sha256('request-1001'::bytea) and consumed_at is null and expires_at > now();
explain (analyze, buffers) update auth_requests set interaction_id_hash = sha256('fresh-interaction'::bytea) where tenant_id = :t and request_uri_hash = sha256('request-1001'::bytea) and interaction_id_hash is null and consumed_at is null and expires_at > now();

\echo '#### the interaction: login page, password, passkey, session'
explain (analyze, buffers) select client_id, parameters, interaction_state, session_id, expires_at from auth_requests where tenant_id = :t and interaction_id_hash = sha256('interaction-1000'::bytea) and consumed_at is null and expires_at > now();
explain (analyze, buffers) update auth_requests set interaction_state = '{"stage":"consent"}'::jsonb, session_id = coalesce('session-1000', session_id) where tenant_id = :t and interaction_id_hash = sha256('interaction-1000'::bytea) and consumed_at is null and expires_at > now();
explain (analyze, buffers) select u.user_id, c.password_hash, u.status, c.disabled_at from users u join credentials c on c.tenant_id = u.tenant_id and c.user_id = u.user_id where u.tenant_id = :t and u.username = 'user-1000' and c.kind = 'password';
explain (analyze, buffers) select credential_id, user_id, passkey_public_key, passkey_sign_count, passkey_rp_id from credentials where tenant_id = :t and kind = 'passkey' and passkey_credential_id = sha256('passkey-1000'::bytea) and disabled_at is null;
explain (analyze, buffers) select user_id, username, email, email_verified, status, claims, created_at, updated_at from users where tenant_id = :t and user_id = pg_temp.explain_uuid('user', 1000);
explain (analyze, buffers) insert into sessions (tenant_id, session_id, public_sid, user_id, created_at, authenticated_at, last_seen_at, expires_at, idle_expires_at, acr, amr) values (:t, 'fresh-session', 'fresh-sid', pg_temp.explain_uuid('user', 1000), now(), now(), now(), now() + interval '12 hours', now() + interval '1 hour', null, '{pwd}');
explain (analyze, buffers) select session_id, public_sid, user_id, created_at, authenticated_at, last_seen_at, expires_at, idle_expires_at, acr, amr, revoked_at, revocation_reason from sessions where tenant_id = :t and session_id = 'session-1000';
explain (analyze, buffers) update sessions set last_seen_at = now(), idle_expires_at = now() + interval '1 hour' where tenant_id = :t and session_id = 'session-1000' and revoked_at is null and expires_at > now() and idle_expires_at > now();
explain (analyze, buffers) select session_id from sessions where tenant_id = :t and public_sid = 'sid-1000';
explain (analyze, buffers) select session_id from sessions where tenant_id = :t and user_id = pg_temp.explain_uuid('user', 1000) and revoked_at is null and expires_at > now() order by created_at desc;

\echo '#### consent: subject, earlier grants, the grant and the code'
explain (analyze, buffers) select salt_ciphertext, salt_nonce, kek_id from tenant_pairwise_salts where tenant_id = :t;
explain (analyze, buffers) select 1 from retired_subject_identifiers where tenant_id = :t and subject = 'sub-1000';
explain (analyze, buffers) select subject from subject_identifiers where tenant_id = :t and user_id = pg_temp.explain_uuid('user', 1000) and sector_identifier = '';
explain (analyze, buffers) select grant_id, client_id, user_id, subject, scopes, claims, claims_locales, authorization_details, resources, actor_chain, parent_grant_id, session_id, authenticated_at, acr, amr, created_at, updated_at, expires_at, claimed_at, revoked_at, revocation_reason from grants where tenant_id = :t and subject = 'sub-1000' order by created_at desc, grant_id;
explain (analyze, buffers) insert into grants (tenant_id, grant_id, client_id, user_id, subject, scopes, claims, claims_locales, authorization_details, resources, actor_chain, parent_grant_id, session_id, authenticated_at, acr, amr, created_at, updated_at, expires_at, claimed_at) values (:t, gen_random_uuid(), 'rp', pg_temp.explain_uuid('user', 1000), 'sub-1000', '{openid}', '{}', '{}', '[]', '{}', '[]', null, 'session-1000', now(), null, '{pwd}', now(), now(), null, null);
explain (analyze, buffers) insert into authorization_codes (tenant_id, code_hash, client_id, grant_id, code_challenge, redirect_uri, nonce, dpop_jkt, issued_at, expires_at, grant_management_action) values (:t, sha256('fresh-code'::bytea), 'rp', pg_temp.explain_uuid('grant', 1000), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'https://rp.example/cb', null, null, now(), now() + interval '1 minute', null);
explain (analyze, buffers) update auth_requests set consumed_at = now() where tenant_id = :t and request_uri_hash = sha256('request-1001'::bytea) and consumed_at is null and expires_at > now() returning client_id, parameters, pushed_at, expires_at;

\echo '#### the audit trail (every state change)'
explain (analyze, buffers) select event_hash from audit_events where tenant_id = :t order by event_id desc limit 1;
explain (analyze, buffers) insert into audit_events (tenant_id, occurred_at, event_type, outcome, actor, actor_chain, subject, client_id, session_id, grant_id, request_id, detail, previous_hash, event_hash) values (:t, now(), 'token.issued', 'success', '{"kind":"client","id":"rp"}', '[]', 'sub-1000', 'rp', null, null, null, '{}', sha256('event-0'::bytea), sha256('fresh-event'::bytea));

\echo '#### token: code redemption, refresh, client_credentials'
explain (analyze, buffers) update authorization_codes set consumed_at = now() where tenant_id = :t and code_hash = sha256('code-1001'::bytea) and consumed_at is null and expires_at > now() returning client_id, grant_id, code_challenge, redirect_uri, nonce, dpop_jkt, expires_at, grant_management_action;
explain (analyze, buffers) select grant_id, client_id, user_id, subject, scopes, claims, claims_locales, authorization_details, resources, actor_chain, parent_grant_id, session_id, authenticated_at, acr, amr, created_at, updated_at, expires_at, claimed_at, revoked_at, revocation_reason from grants where tenant_id = :t and grant_id = pg_temp.explain_uuid('grant', 1001);
explain (analyze, buffers) update grants set claimed_at = coalesce(claimed_at, now()) where tenant_id = :t and grant_id = pg_temp.explain_uuid('grant', 1001) and revoked_at is null and (expires_at is null or expires_at > now()) returning grant_id;
explain (analyze, buffers) insert into session_clients (tenant_id, session_id, client_id, first_seen_at, last_seen_at) values (:t, 'session-1001', 'rp', now(), now()) on conflict (tenant_id, session_id, client_id) do update set last_seen_at = excluded.last_seen_at;
explain (analyze, buffers) select identifier, scopes, token_lifetime_seconds from resource_servers where tenant_id = :t order by identifier;
explain (analyze, buffers) select name from user_tenant_roles where tenant_id = :t and user_id = pg_temp.explain_uuid('user', 1001) order by name;
explain (analyze, buffers) select client_id, name from user_client_roles where tenant_id = :t and user_id = pg_temp.explain_uuid('user', 1001) order by client_id, name;
explain (analyze, buffers) select kid, private_key_ciphertext, private_key_nonce, kek_id from signing_keys where tenant_id = :t and purpose = 'sig' and alg = 'ES256' and state = 'active';
explain (analyze, buffers) select kid, alg, purpose, state, public_jwk, created_at from signing_keys where tenant_id = :t and state in ('pending', 'active', 'retiring') order by case state when 'active' then 0 when 'pending' then 1 else 2 end, created_at desc, kid;
explain (analyze, buffers) insert into refresh_tokens (tenant_id, token_hash, grant_id, client_id, scopes, dpop_jkt, cert_thumbprint, issued_at, absolute_expires_at, idle_expires_at) values (:t, sha256('fresh-refresh'::bytea), pg_temp.explain_uuid('grant', 1001), 'rp', '{openid}', 'jkt', null, now(), now() + interval '30 days', now() + interval '14 days');
explain (analyze, buffers) update refresh_tokens set last_used_at = now(), idle_expires_at = case when (now() + interval '14 days')::timestamptz is null then null else least(now() + interval '14 days', absolute_expires_at) end where tenant_id = :t and token_hash = sha256('refresh-1002'::bytea) and revoked_at is null and absolute_expires_at > now() and (idle_expires_at is null or idle_expires_at > now()) and (superseded_at is null or superseded_at > now()) returning grant_id, client_id, scopes, dpop_jkt, cert_thumbprint, issued_at, absolute_expires_at, superseded_at;
explain (analyze, buffers) update refresh_tokens set revoked_at = now() where tenant_id = :t and grant_id = pg_temp.explain_uuid('grant', 1003) and revoked_at is null;

\echo '#### presenting an access token (UserInfo, SSF, Grant Management)'
explain (analyze, buffers) select exists (select 1 from access_token_denylist where tenant_id = :t and jti = 'at-1000');
explain (analyze, buffers) select max(revoked_before) from access_token_cutoffs where tenant_id = :t and ((principal_kind = 'client' and principal_id = 'rp') or (principal_kind = 'grant' and principal_id = pg_temp.explain_uuid('grant', 1000)::text));

\echo '#### logout: the sessions of a person, the grants of a session'
explain (analyze, buffers) update sessions set revoked_at = coalesce(revoked_at, now()), revocation_reason = coalesce(revocation_reason, 'logout') where tenant_id = :t and user_id = pg_temp.explain_uuid('user', 1004) and revoked_at is null;
explain (analyze, buffers) update refresh_tokens r set revoked_at = now() from grants g where r.tenant_id = :t and g.tenant_id = r.tenant_id and g.grant_id = r.grant_id and g.session_id = 'session-1004' and r.revoked_at is null returning r.grant_id;
explain (analyze, buffers) select client_id, first_seen_at, last_seen_at from session_clients where tenant_id = :t and session_id = 'session-1004' order by first_seen_at;

\echo '#### the outbox worker (back-channel logout, SSF push, notifications)'
explain (analyze, buffers) insert into outbox (tenant_id, kind, destination, payload, ordering_key, created_at, available_at, max_attempts) values (:t, 'ssf.set', 'stream-explain', '{}', null, now(), now(), coalesce(null, 10)) returning outbox_id;
explain (analyze, buffers) with due as ( select c.tenant_id, c.outbox_id from outbox c where c.available_at <= now() and (c.status in ('pending', 'failed') or (c.status = 'claimed' and c.claim_expires_at <= now())) and c.attempts < c.max_attempts and (c.ordering_key is null or not exists ( select 1 from outbox e where e.tenant_id = c.tenant_id and e.ordering_key = c.ordering_key and e.outbox_id < c.outbox_id and e.status in ('pending', 'failed', 'claimed'))) order by c.available_at, c.outbox_id limit 16 for update skip locked ) update outbox o set status = 'claimed', claimed_by = 'explain-worker', claim_expires_at = now() + interval '60 seconds', attempts = o.attempts + 1 from due where o.tenant_id = due.tenant_id and o.outbox_id = due.outbox_id returning o.tenant_id, o.outbox_id;
explain (analyze, buffers) update outbox set status = 'delivered', delivered_at = now(), last_error = null, claimed_by = null, claim_expires_at = null where tenant_id = :t and outbox_id = 100;
explain (analyze, buffers) select count(*) from outbox where status in ('pending', 'failed', 'claimed');
explain (analyze, buffers) select s.status, s.status_reason, s.delivered_count, s.failed_count, (select count(*) from outbox o where o.tenant_id = s.tenant_id and o.kind = 'ssf.set' and o.destination = s.stream_id and o.status in ('pending', 'failed', 'claimed')) as queued from ssf_streams s where s.tenant_id = :t and s.client_id = 'rp' and s.stream_id = 'stream-explain';
explain (analyze, buffers) select kind, destination, payload, created_at from outbox where tenant_id = :t and kind like 'notification.%' and delivered_at is null order by outbox_id asc;

\echo '#### SSF poll delivery (RFC 8936)'
explain (analyze, buffers) select stream_id, audience, events_requested, delivery_method, delivery_endpoint_url, description, inactivity_timeout_seconds, status from ssf_streams where tenant_id = :t and client_id = 'rp' and stream_id = 'stream-explain';
explain (analyze, buffers) insert into ssf_poll_queue (tenant_id, stream_id, jti, set_jws, queued_at) values (:t, 'stream-explain', 'fresh-set', 'eyJ', now()) on conflict (tenant_id, stream_id, jti) do nothing;
explain (analyze, buffers) with taken as ( select jti from ssf_poll_queue where tenant_id = :t and stream_id = 'stream-explain' order by queued_at, jti limit 64 ) update ssf_poll_queue queued set deliveries = queued.deliveries + 1, delivered_at = now() from taken where queued.tenant_id = :t and queued.stream_id = 'stream-explain' and queued.jti = taken.jti returning queued.jti, queued.set_jws, queued.queued_at;
explain (analyze, buffers) delete from ssf_poll_queue where tenant_id = :t and stream_id = 'stream-explain' and jti = any('{set-1,set-2,set-3}'::text[]);
explain (analyze, buffers) select count(*) from ssf_poll_queue where tenant_id = :t and stream_id = 'stream-explain';

\echo '#### retention sweeps (once per tenant per period, over whole tables)'
explain (analyze, buffers) delete from auth_requests where tenant_id = :t and expires_at <= now() - interval '1 hour';
explain (analyze, buffers) delete from authorization_codes where tenant_id = :t and expires_at <= now() - interval '1 hour';
explain (analyze, buffers) delete from jti_replay where tenant_id = :t and expires_at <= now() - interval '1 hour';
explain (analyze, buffers) delete from rate_limits where tenant_id = :t and expires_at <= now() - interval '1 hour';
explain (analyze, buffers) delete from sessions where tenant_id = :t and expires_at <= now() - interval '1 hour';
explain (analyze, buffers) delete from recovery_tokens where tenant_id = :t and expires_at <= now() - interval '1 hour';
explain (analyze, buffers) delete from grants where tenant_id = :t and created_at < now() - interval '1 day' and claimed_at is null and revoked_at is null;

\echo '#### the console: one person''s grants and sessions'
explain (analyze, buffers) select grant_id, client_id, user_id, subject, scopes, claims, claims_locales, authorization_details, resources, actor_chain, parent_grant_id, session_id, authenticated_at, acr, amr, created_at, updated_at, expires_at, claimed_at, revoked_at, revocation_reason from grants where tenant_id = :t and user_id = pg_temp.explain_uuid('user', 1000) order by created_at desc, grant_id;
explain (analyze, buffers) select public_sid, created_at, authenticated_at, last_seen_at, expires_at, acr, amr, revoked_at, revocation_reason from sessions where tenant_id = :t and user_id = pg_temp.explain_uuid('user', 1000) order by created_at desc;

rollback;
