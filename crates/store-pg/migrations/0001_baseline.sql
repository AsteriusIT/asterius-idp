-- Baseline schema.
--
-- Three rules run through every table here.
--
-- 1. **Every tenant-scoped table carries `tenant_id`, and it is the first
--    column of the primary key and of every composite index.** A query that
--    forgets the tenant does not merely return the wrong rows, it returns
--    another customer's rows, so the physical layout is arranged to make the
--    tenant predicate the cheapest thing a query can do.
--
-- 2. **Opaque credentials are stored as SHA-256 digests and nothing else.**
--    Authorization codes, refresh tokens, device codes, `auth_req_id` values
--    and registration access tokens are ≥128-bit random strings (FAPI 2.0 SP
--    §5.4.1), so a digest is enough to look one up and a database leak yields
--    nothing usable. RFC 6749 §10.3 requires this for codes and tokens.
--    Columns holding such a digest are named `*_hash`; columns holding
--    encrypted material are named `*_ciphertext`. A schema test enforces the
--    convention, so a plaintext credential column cannot be added quietly.
--
-- 3. **Deletion cascades from the tenant.** Removing a tenant removes its
--    data, in one statement, with no orphan rows left behind to leak.

-- ---------------------------------------------------------------------------
-- Shared helpers
-- ---------------------------------------------------------------------------

create function set_updated_at() returns trigger language plpgsql as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

-- ---------------------------------------------------------------------------
-- Tenants
-- ---------------------------------------------------------------------------

create table tenants (
    tenant_id      text        primary key,
    -- Canonical issuer, normalised by asterius_domain::Issuer before it gets
    -- here. Unique across the whole deployment: two tenants answering to one
    -- issuer would make `iss` ambiguous.
    issuer         text        not null unique,
    -- Optional vanity host. When set, requests arriving on this host resolve to
    -- this tenant without the /t/{tenant} path prefix.
    custom_host    text        unique,
    display_name   text        not null,
    status         text        not null default 'active'
                               check (status in ('active', 'disabled')),
    -- Per-tenant policy: lifetimes, ACR rules, rate limits, theming tokens.
    settings       jsonb       not null default '{}'::jsonb,
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now()
);

create trigger tenants_set_updated_at before update on tenants
    for each row execute function set_updated_at();

-- ---------------------------------------------------------------------------
-- Clients
-- ---------------------------------------------------------------------------

create table clients (
    tenant_id                      text        not null
                                   references tenants (tenant_id) on delete cascade,
    client_id                      text        not null,
    client_name                    text        not null,
    -- FAPI 2.0 has no public clients (ADR-0002). The check exists so that a
    -- future migration adding one has to argue with the schema first.
    client_type                    text        not null default 'confidential'
                                   check (client_type = 'confidential'),
    token_endpoint_auth_method     text        not null
                                   check (token_endpoint_auth_method in (
                                       'private_key_jwt',
                                       'tls_client_auth',
                                       'self_signed_tls_client_auth')),
    -- Exact-match only: no wildcards, no prefixes (FAPI 2.0 SP §5.3.2.1).
    redirect_uris                  text[]      not null default '{}',
    grant_types                    text[]      not null default '{}',
    response_types                 text[]      not null default '{code}',
    scopes                         text[]      not null default '{}',
    resources                      text[]      not null default '{}',
    -- Exactly one key source, by ADR-0002's "no ambiguity" rule: an inline JWKS
    -- or a URI to fetch, never both and never neither.
    jwks                           jsonb,
    jwks_uri                       text,
    id_token_signed_response_alg   text        not null default 'EdDSA'
                                   check (id_token_signed_response_alg in
                                          ('EdDSA', 'ES256', 'PS256')),
    -- OIDC Registration §2 and OIDC Core §8. `subject_type` decides whether a
    -- client sees a shared `sub` or one derived per sector.
    application_type               text        not null default 'web'
                                   check (application_type in ('web', 'native')),
    subject_type                   text        not null default 'public'
                                   check (subject_type in ('public', 'pairwise')),
    sector_identifier_uri          text,
    -- Optional signing algorithms, from the same allow-list as everything else
    -- (ADR-0003). Null means the client registered none.
    request_object_signing_alg     text
                                   check (request_object_signing_alg in
                                          ('EdDSA', 'ES256', 'PS256')),
    backchannel_authentication_request_signing_alg text
                                   check (backchannel_authentication_request_signing_alg in
                                          ('EdDSA', 'ES256', 'PS256')),
    -- What this client's access tokens are bound to. FAPI 2.0 forbids a bearer
    -- token, so the pair (false, false) is refused here as well as in the
    -- parser: a row that says "bound to nothing" must not be expressible.
    dpop_bound_access_tokens       boolean     not null default true,
    tls_client_certificate_bound_access_tokens boolean not null default false,
    -- RFC 9396 §9.2: the `authorization_details` types this client may use.
    authorization_details_types    text[]      not null default '{}',
    -- FAPI 2.0 SP §5.2.2.1.1.
    use_mtls_endpoint_aliases      boolean     not null default false,
    -- Agent clients (E11). `agent_owner_sub` is the principal the agent acts
    -- for; it is what makes a delegation chain attributable.
    is_agent                       boolean     not null default false,
    agent_owner_sub                text,
    agent_policy                   jsonb       not null default '{}'::jsonb,
    -- RFC 7592 registration access token, digest only.
    registration_access_token_hash bytea,
    software_statement             jsonb,
    status                         text        not null default 'active'
                                   check (status in ('active', 'disabled')),
    created_at                     timestamptz not null default now(),
    updated_at                     timestamptz not null default now(),

    primary key (tenant_id, client_id),
    constraint clients_exactly_one_key_source
        check ((jwks is null) <> (jwks_uri is null)),
    constraint clients_agent_has_owner
        check (not is_agent or agent_owner_sub is not null),
    -- FAPI 2.0 SP §5.3.2.1: access tokens are always sender-constrained. A
    -- client bound to neither would be issued bearer tokens, so the row cannot
    -- exist.
    constraint clients_tokens_are_sender_constrained
        check (dpop_bound_access_tokens or tls_client_certificate_bound_access_tokens),
    -- OIDC Core §8.1: a sector identifier only means anything for a pairwise
    -- subject.
    constraint clients_sector_identifier_needs_pairwise
        check (sector_identifier_uri is null or subject_type = 'pairwise')
);

create trigger clients_set_updated_at before update on clients
    for each row execute function set_updated_at();

create index clients_by_agent_owner on clients (tenant_id, agent_owner_sub)
    where is_agent;

-- Client keys resolved from `jwks_uri`, cached with an expiry so that a key
-- rotation at the client is picked up without a fetch on every request.
create table client_keys (
    tenant_id  text        not null,
    client_id  text        not null,
    kid        text        not null,
    jwk        jsonb       not null,
    alg        text,
    key_use    text,
    fetched_at timestamptz not null default now(),
    expires_at timestamptz not null,

    primary key (tenant_id, client_id, kid),
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade
);

-- ---------------------------------------------------------------------------
-- Users, subjects and credentials
-- ---------------------------------------------------------------------------

create table users (
    tenant_id      text        not null
                   references tenants (tenant_id) on delete cascade,
    user_id        uuid        not null,
    username       text        not null,
    email          text,
    email_verified boolean     not null default false,
    status         text        not null default 'active'
                   check (status in ('active', 'disabled', 'locked')),
    -- Issuer-agnostic claim bag. Keeping claims out of columns is what lets
    -- Identity Assurance and verifiable credentials be added later without a
    -- schema rewrite (ast-s36.5, ast-s36.6).
    claims         jsonb       not null default '{}'::jsonb,
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),

    primary key (tenant_id, user_id),
    unique (tenant_id, username)
);

create trigger users_set_updated_at before update on users
    for each row execute function set_updated_at();

create unique index users_by_email on users (tenant_id, lower(email))
    where email is not null;

-- `sub` as seen by one sector. A public subject uses the sentinel sector '',
-- so both subject types live in one table and `sub` is unique per tenant
-- either way.
create table subject_identifiers (
    tenant_id         text        not null,
    user_id           uuid        not null,
    sector_identifier text        not null default '',
    subject           text        not null,
    created_at        timestamptz not null default now(),

    primary key (tenant_id, user_id, sector_identifier),
    unique (tenant_id, subject),
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade
);

create table credentials (
    tenant_id             text        not null,
    credential_id         uuid        not null,
    user_id               uuid        not null,
    kind                  text        not null
                          check (kind in ('password', 'passkey', 'recovery_code')),
    -- Argon2id PHC string. Named `_hash` like every other credential column.
    password_hash         text,
    -- WebAuthn material. The credential id and public key are not secrets —
    -- they are handed to the browser on every authentication — so they are
    -- stored as they are used.
    passkey_credential_id bytea,
    passkey_public_key    bytea,
    passkey_sign_count    bigint      not null default 0,
    passkey_aaguid        uuid,
    passkey_transports    text[],
    passkey_backup_state  boolean,
    label                 text,
    recovery_code_hash    bytea,
    created_at            timestamptz not null default now(),
    last_used_at          timestamptz,
    disabled_at           timestamptz,

    primary key (tenant_id, credential_id),
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    constraint credentials_material_matches_kind check (
        case kind
            when 'password'      then password_hash is not null
            when 'passkey'       then passkey_credential_id is not null
                                      and passkey_public_key is not null
            when 'recovery_code' then recovery_code_hash is not null
        end
    )
);

create index credentials_by_user on credentials (tenant_id, user_id, kind);

create unique index credentials_by_passkey_id
    on credentials (tenant_id, passkey_credential_id)
    where passkey_credential_id is not null;

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

create table sessions (
    tenant_id             text        not null,
    session_id            text        not null,
    user_id               uuid        not null,
    created_at            timestamptz not null default now(),
    -- `auth_time` as it will appear in the ID Token.
    authenticated_at      timestamptz not null,
    last_seen_at          timestamptz not null default now(),
    expires_at            timestamptz not null,
    idle_expires_at       timestamptz not null,
    acr                   text,
    amr                   text[]      not null default '{}',
    -- PII minimisation: enough to spot a session moving between devices,
    -- not enough to reconstruct where a user was.
    user_agent_hash       bytea,
    ip_hash               bytea,
    revoked_at            timestamptz,
    revocation_reason     text,

    primary key (tenant_id, session_id),
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade
);

create index sessions_by_user on sessions (tenant_id, user_id)
    where revoked_at is null;
create index sessions_expiring on sessions (expires_at);

-- Which clients took part in a session. Back-channel logout needs this list.
create table session_clients (
    tenant_id      text        not null,
    session_id     text        not null,
    client_id      text        not null,
    first_seen_at  timestamptz not null default now(),
    last_seen_at   timestamptz not null default now(),

    primary key (tenant_id, session_id, client_id),
    foreign key (tenant_id, session_id)
        references sessions (tenant_id, session_id) on delete cascade
);

-- ---------------------------------------------------------------------------
-- Authorization: pushed requests, codes, grants
-- ---------------------------------------------------------------------------

-- A pushed authorization request (RFC 9126) and the interaction state that
-- accumulates against it while the user logs in and consents.
create table auth_requests (
    tenant_id         text        not null,
    -- The `request_uri` is a bearer-ish credential handed back to the client,
    -- so only its digest is stored.
    request_uri_hash  bytea       not null,
    client_id         text        not null,
    -- The pushed parameters, exactly as validated.
    parameters        jsonb       not null,
    dpop_jkt          text,
    -- Login and consent progress; replaced as the interaction advances.
    interaction_state jsonb       not null default '{}'::jsonb,
    session_id        text,
    pushed_at         timestamptz not null default now(),
    expires_at        timestamptz not null,
    consumed_at       timestamptz,

    primary key (tenant_id, request_uri_hash),
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade
);

create index auth_requests_expiring on auth_requests (expires_at);

-- A grant is the revocable unit of authority. Every token traces back to one,
-- which is what makes revocation a single row update rather than a hunt.
create table grants (
    tenant_id             text        not null,
    grant_id              uuid        not null,
    client_id             text        not null,
    user_id               uuid,
    subject               text,
    scopes                text[]      not null default '{}',
    claims                jsonb       not null default '{}'::jsonb,
    authorization_details jsonb       not null default '[]'::jsonb,
    resources             text[]      not null default '{}',
    -- RFC 8693 `act` chain, innermost actor last. Present only for tokens
    -- obtained through token exchange.
    actor_chain           jsonb       not null default '[]'::jsonb,
    -- The grant this one was narrowed from, for exchanged tokens.
    parent_grant_id       uuid,
    session_id            text,
    created_at            timestamptz not null default now(),
    updated_at            timestamptz not null default now(),
    expires_at            timestamptz,
    revoked_at            timestamptz,
    revocation_reason     text,

    primary key (tenant_id, grant_id),
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade,
    foreign key (tenant_id, parent_grant_id)
        references grants (tenant_id, grant_id) on delete cascade
);

create trigger grants_set_updated_at before update on grants
    for each row execute function set_updated_at();

create index grants_by_subject on grants (tenant_id, subject)
    where revoked_at is null;
create index grants_by_client on grants (tenant_id, client_id)
    where revoked_at is null;
create index grants_by_session on grants (tenant_id, session_id)
    where session_id is not null and revoked_at is null;

create table authorization_codes (
    tenant_id             text        not null,
    code_hash             bytea       not null,
    client_id             text        not null,
    grant_id              uuid        not null,
    -- PKCE: the challenge is public, the verifier never reaches the database.
    code_challenge        text        not null,
    code_challenge_method text        not null default 'S256'
                          check (code_challenge_method = 'S256'),
    redirect_uri          text        not null,
    nonce                 text,
    dpop_jkt              text,
    issued_at             timestamptz not null default now(),
    -- FAPI 2.0 SP §5.4.1: at most 60 seconds. Enforced in code; recorded here
    -- so that a stored row can be audited against the rule.
    expires_at            timestamptz not null,
    -- Set on first redemption. A second redemption finds it set and revokes
    -- the whole grant (RFC 6749 §10.5).
    consumed_at           timestamptz,

    primary key (tenant_id, code_hash),
    foreign key (tenant_id, grant_id)
        references grants (tenant_id, grant_id) on delete cascade,
    constraint authorization_codes_max_lifetime
        check (expires_at <= issued_at + interval '60 seconds')
);

create index authorization_codes_expiring on authorization_codes (expires_at);

-- ---------------------------------------------------------------------------
-- Tokens
-- ---------------------------------------------------------------------------

create table refresh_tokens (
    tenant_id    text        not null,
    token_hash   bytea       not null,
    grant_id     uuid        not null,
    client_id    text        not null,
    -- Sender constraint, one of the two. FAPI 2.0 forbids bearer refresh
    -- tokens, so exactly one of these is always present.
    dpop_jkt     text,
    cert_thumbprint bytea,
    issued_at    timestamptz not null default now(),
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz,

    primary key (tenant_id, token_hash),
    foreign key (tenant_id, grant_id)
        references grants (tenant_id, grant_id) on delete cascade,
    constraint refresh_tokens_are_sender_constrained
        check ((dpop_jkt is null) <> (cert_thumbprint is null))
);

create index refresh_tokens_by_grant on refresh_tokens (tenant_id, grant_id);
create index refresh_tokens_expiring on refresh_tokens (expires_at)
    where expires_at is not null;

-- Denylist for JWT access tokens revoked before their own expiry. Rows are
-- pruned once `expires_at` passes, because after that the token fails on `exp`
-- and the row stops earning its keep.
create table access_token_denylist (
    tenant_id  text        not null,
    jti        text        not null,
    grant_id   uuid,
    revoked_at timestamptz not null default now(),
    expires_at timestamptz not null,

    primary key (tenant_id, jti)
);

create index access_token_denylist_expiring on access_token_denylist (expires_at);

-- Single-use enforcement for `jti` values in client assertions and DPoP
-- proofs. Keyed by digest because the `jti` is chosen by the client and can be
-- arbitrarily long.
create table jti_replay (
    tenant_id  text        not null,
    purpose    text        not null
               check (purpose in ('client_assertion', 'dpop_proof')),
    jti_hash   bytea       not null,
    client_id  text,
    seen_at    timestamptz not null default now(),
    expires_at timestamptz not null,

    primary key (tenant_id, purpose, jti_hash)
);

create index jti_replay_expiring on jti_replay (expires_at);

-- ---------------------------------------------------------------------------
-- Signing keys
-- ---------------------------------------------------------------------------

-- A key's life is `pending -> active -> retiring -> retired`, and it is a
-- sequence rather than a swap because of OIDC Core §10.1.1: keys are rolled
-- over "by periodically adding new keys to the JWK Set", the signer "can begin
-- using a new key at its discretion and signals the change to the verifier
-- using the kid value", and the JWK Set "SHOULD retain recently decommissioned
-- signing keys for a reasonable period of time to facilitate a smooth
-- transition".
--
-- So: a key is published before it ever signs (`pending`, for long enough that
-- a verifier's cached copy has turned over, which is why no verifier should
-- ever meet an unfamiliar `kid`), and it stays published after it stops
-- (`retiring`, for at least the lifetime of the longest token it signed).
-- `retired` is the only state that is gone from the JWKS, and the row survives
-- so its `kid` is never handed out twice.
create table signing_keys (
    tenant_id              text        not null
                           references tenants (tenant_id) on delete cascade,
    -- The RFC 7638 thumbprint of the public key: identity, not a label. The
    -- same key material always produces the same `kid`, so the primary key
    -- below is what makes "this key exists once, for one purpose" true rather
    -- than merely intended.
    kid                    text        not null,
    alg                    text        not null
                           check (alg in ('EdDSA', 'ES256', 'PS256')),
    -- The JWK `use` value (RFC 7517 §4.2). FAPI 2.0 SP §6.8 item 2: "single
    -- purpose keys are recommended. For example, it is not recomended to use
    -- the same key for signing and encryption." A P-256 or RSA key pair is
    -- usable for both operations, so the separation has to be recorded and
    -- enforced — it is not implied by the key type.
    purpose                text        not null default 'sig'
                           check (purpose in ('sig', 'enc')),
    public_jwk             jsonb       not null,
    -- Private key, encrypted with a key-encryption key held outside the
    -- database (KMS or a file). Never a `_hash`: it has to come back out.
    -- Bound to this row's tenant, kid, purpose and algorithm as AEAD
    -- additional authenticated data, so moving the bytes to another row makes
    -- them undecryptable rather than useful. See asterius_jose::kek.
    private_key_ciphertext bytea       not null,
    private_key_nonce      bytea       not null,
    kek_id                 text        not null,
    state                  text        not null default 'pending'
                           check (state in ('pending', 'active', 'retiring', 'retired')),
    created_at             timestamptz not null default now(),
    -- When it started signing, when it stopped signing, and when it left the
    -- JWKS. `retiring_at` is what the grace period is measured from, so it is
    -- a column and not an inference from `created_at`.
    activated_at           timestamptz,
    retiring_at            timestamptz,
    retired_at             timestamptz,

    primary key (tenant_id, kid),
    -- A published key announces its own purpose. Storing it twice looks
    -- redundant until a row is edited: if these could disagree, a key could be
    -- served to the world as `use: enc` while the signer still treated it as a
    -- signing key.
    constraint signing_keys_jwk_use_matches_purpose
        check (public_jwk ->> 'use' = purpose),
    -- 96 bits, the IV length NIST SP 800-38D §5.2.1.1 recommends restricting
    -- support to, and the only length aws-lc-rs will produce here.
    constraint signing_keys_nonce_is_96_bits
        check (length(private_key_nonce) = 12),
    -- Ciphertext plus a 16-byte GCM tag: a row shorter than that is truncated,
    -- and a row exactly that long carries no key at all.
    constraint signing_keys_ciphertext_carries_a_tag
        check (length(private_key_ciphertext) > 16),
    -- The timestamps are the audit trail of the state machine, so a state that
    -- does not match them is a row nobody can reason about afterwards.
    constraint signing_keys_timestamps_follow_the_state check (
        case state
            when 'pending'  then activated_at is null
                                 and retiring_at is null and retired_at is null
            when 'active'   then activated_at is not null
                                 and retiring_at is null and retired_at is null
            when 'retiring' then activated_at is not null
                                 and retiring_at is not null and retired_at is null
            -- A key can be retired straight out of `pending` when it is
            -- destroyed before it ever signs, so only the final stamp is
            -- required here.
            when 'retired'  then retired_at is not null
        end
    )
);

-- At most one active key per purpose and algorithm per tenant: "which key
-- signs this" must have exactly one answer, and two concurrent rotations
-- racing to promote must have one of them fail rather than both succeed.
create unique index signing_keys_one_active_per_alg
    on signing_keys (tenant_id, purpose, alg)
    where state = 'active';

-- And at most one pending key, so a rotation triggered twice before the
-- propagation period elapses does not leave a queue of unused keys behind.
create unique index signing_keys_one_pending_per_alg
    on signing_keys (tenant_id, purpose, alg)
    where state = 'pending';

-- The JWKS query: every published key for a tenant.
create index signing_keys_published
    on signing_keys (tenant_id, purpose, state)
    where state in ('pending', 'active', 'retiring');

-- A nonce may be used once per key-encryption key. AES-GCM loses both
-- confidentiality and authenticity if a nonce repeats under one key
-- (NIST SP 800-38D §8), and the nonces here come from an RBG rather than a
-- counter — so the uniqueness the standard requires is asserted here instead
-- of assumed. Not tenant-scoped, deliberately: a KEK spans tenants, so the
-- constraint has to as well.
create unique index signing_keys_nonce_never_repeats
    on signing_keys (kek_id, private_key_nonce);

-- Key material appears in exactly one row, anywhere. Two rows sharing a public
-- key are either the same key registered for both purposes — the reuse
-- FAPI 2.0 SP §6.8 item 2 warns about — or one tenant's key installed in
-- another tenant's JWKS. The `kid` is a thumbprint, so the primary key already
-- catches this whenever the `kid` was computed honestly; this catches it when
-- it was not.
create unique index signing_keys_material_is_used_once
    on signing_keys (
        coalesce(public_jwk ->> 'x', ''),
        coalesce(public_jwk ->> 'y', ''),
        coalesce(public_jwk ->> 'n', '')
    );

-- Per-tenant rotation policy. FAPI 2.0 SP §6.8 item 1: "automated regular key
-- rotation is recommended, as it reduces the time window in which a
-- compromised key can be used."
--
-- Periods are seconds and not `interval` because an interval of one month has
-- no fixed length, and "how long does a decommissioned key stay verifiable"
-- is not a question that may have a different answer in February.
create table key_rotation_schedules (
    tenant_id                  text        not null
                               references tenants (tenant_id) on delete cascade,
    purpose                    text        not null default 'sig'
                               check (purpose in ('sig', 'enc')),
    -- How often a new key is created. 90 days by default.
    rotation_period_seconds    bigint      not null default 7776000,
    -- How long a new key sits in the JWKS before it is allowed to sign, so
    -- that verifiers have refreshed their cached JWK Set first (OIDC Core
    -- §10.1.1). 15 minutes by default; it should exceed the `max-age` the
    -- jwks_uri response advertises.
    propagation_period_seconds bigint      not null default 900,
    -- How long a key stays published after it stops signing. Must exceed the
    -- longest lifetime of any token signed with it, or a token still inside
    -- its own `exp` stops verifying. 7 days by default, which is far beyond
    -- the access-token lifetimes this profile issues.
    grace_period_seconds       bigint      not null default 604800,
    last_rotated_at            timestamptz,
    created_at                 timestamptz not null default now(),
    updated_at                 timestamptz not null default now(),

    primary key (tenant_id, purpose),
    -- A schedule that never rotates is not a schedule; a year is already
    -- longer than item 1 has in mind.
    constraint key_rotation_schedules_rotation_period_is_sane
        check (rotation_period_seconds between 3600 and 31536000),
    -- Zero propagation would mean signing with a key no verifier has had the
    -- chance to fetch, which is the failure the OIDC Core §10.1.1 procedure
    -- exists to avoid.
    constraint key_rotation_schedules_propagation_is_positive
        check (propagation_period_seconds > 0
               and propagation_period_seconds < rotation_period_seconds),
    constraint key_rotation_schedules_grace_is_positive
        check (grace_period_seconds > 0 and grace_period_seconds <= 31536000)
);

create trigger key_rotation_schedules_set_updated_at before update on key_rotation_schedules
    for each row execute function set_updated_at();

-- ---------------------------------------------------------------------------
-- Audit
-- ---------------------------------------------------------------------------

create table audit_events (
    event_id    bigint      generated always as identity,
    tenant_id   text        not null,
    occurred_at timestamptz not null default now(),
    event_type  text        not null,
    outcome     text        not null check (outcome in ('success', 'failure')),
    -- {"type": "user" | "client" | "agent" | "admin" | "system", "id": "..."}
    actor       jsonb       not null,
    -- The delegation chain in force, so an agent action is attributable to the
    -- human at the root of it.
    actor_chain jsonb       not null default '[]'::jsonb,
    subject     text,
    client_id   text,
    session_id  text,
    grant_id    uuid,
    request_id  text,
    detail      jsonb       not null default '{}'::jsonb,
    -- Tamper evidence. Each record hashes its predecessor together with its own
    -- canonical encoding, so altering one record invalidates every record after
    -- it. See asterius_domain::audit::chain for the encoding and for what this
    -- does and does not defend against.
    previous_hash bytea     not null,
    event_hash    bytea     not null,

    primary key (tenant_id, event_id),
    constraint audit_events_hashes_are_sha256
        check (length(previous_hash) = 32 and length(event_hash) = 32)
);

-- The chain is per tenant, and a hash may appear once.
create unique index audit_events_hash_unique on audit_events (tenant_id, event_hash);

create index audit_events_recent on audit_events (tenant_id, occurred_at desc);
create index audit_events_by_actor on audit_events (tenant_id, (actor ->> 'id'), occurred_at desc);
create index audit_events_by_grant on audit_events (tenant_id, grant_id)
    where grant_id is not null;

-- Append-only, enforced where it cannot be forgotten. An audit trail that the
-- application can rewrite is not evidence.
--
-- UPDATE is refused unconditionally: there is no legitimate reason to change a
-- record that has already been written, and the hash chain would not survive it
-- anyway.
--
-- DELETE is refused too, except for the retention job, which announces itself
-- by setting `asterius.retention` for the duration of its transaction. That is
-- an escape hatch and it is deliberately a narrow one: it makes deletion an
-- explicit, greppable act rather than something any query can do by accident or
-- through a reused code path. It is not a defence against an attacker who
-- already has arbitrary SQL access — such an attacker can drop the trigger. It
-- defends against the application rewriting its own history.
create function audit_events_are_append_only() returns trigger language plpgsql as $$
begin
    if tg_op = 'DELETE'
       and coalesce(current_setting('asterius.retention', true), 'off') = 'on'
    then
        return null;
    end if;

    raise exception 'audit_events is append-only (attempted %)', tg_op
        using errcode = 'restrict_violation',
              hint = 'retention must set asterius.retention = ''on'' for the transaction';
end;
$$;

create trigger audit_events_no_update before update on audit_events
    for each statement execute function audit_events_are_append_only();
create trigger audit_events_no_delete before delete on audit_events
    for each statement execute function audit_events_are_append_only();

-- ---------------------------------------------------------------------------
-- Transactional outbox
-- ---------------------------------------------------------------------------

-- Back-channel logout tokens and SSF events are written here in the same
-- transaction as the state change they describe, so there is no window in
-- which a session is revoked but the notification was lost. This is what
-- replaces a message broker (ADR-0001).
create table outbox (
    tenant_id    text        not null,
    outbox_id    bigint      generated always as identity,
    kind         text        not null,
    destination  text        not null,
    payload      jsonb       not null,
    status       text        not null default 'pending'
                 check (status in ('pending', 'delivered', 'failed', 'abandoned')),
    attempts     integer     not null default 0,
    max_attempts integer     not null default 10,
    created_at   timestamptz not null default now(),
    available_at timestamptz not null default now(),
    delivered_at timestamptz,
    last_error   text,

    primary key (tenant_id, outbox_id)
);

-- The worker's only query: the oldest due row, per tenant.
create index outbox_due on outbox (available_at, outbox_id)
    where status in ('pending', 'failed');
create index outbox_by_tenant on outbox (tenant_id, created_at desc);

-- ---------------------------------------------------------------------------
-- Rate limits
-- ---------------------------------------------------------------------------

-- Fixed windows, in the same database as everything else. A separate cache
-- tier would be faster and would also be a second thing to operate, back up
-- and reason about during an incident (ADR-0001).
create table rate_limits (
    tenant_id    text        not null,
    bucket       text        not null,
    window_start timestamptz not null,
    counter      integer     not null default 0,
    expires_at   timestamptz not null,

    primary key (tenant_id, bucket, window_start)
);

create index rate_limits_expiring on rate_limits (expires_at);
