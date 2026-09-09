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
    -- The `aud` an access token carries when the grant it came from named no
    -- resource of its own (RFC 9068 §3, RFC 8707 §2). https and no fragment,
    -- the same shape RFC 8707 §2 requires of a `resource` parameter, so a
    -- value that could never be a legitimate audience cannot be stored and
    -- then discovered at the moment a token is signed.
    default_resource text      not null
                               check (default_resource ~ '^https://[^#]*$'),
    status         text        not null default 'active'
                               check (status in ('active', 'disabled')),
    -- Whether this is the deployment's reserved tenant (ADR-0010). A
    -- deployment admin is a user of it, and a deployment-scoped role may only
    -- be granted inside it — see `user_roles`. Everything else about the row is
    -- an ordinary tenant: it has an issuer, it is served by the same code, and
    -- it is discoverable by anyone who can list tenants, deliberately.
    is_reserved    boolean     not null default false,
    -- Per-tenant policy: lifetimes, ACR rules, rate limits, theming tokens.
    settings       jsonb       not null default '{}'::jsonb,
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),

    -- Redundant against the primary key, and present because a composite
    -- foreign key needs a unique constraint to point at: it is what lets
    -- `user_roles` reference `(tenant_id, is_reserved)` and so refuse a
    -- deployment-scoped role outside the reserved tenant without a trigger.
    constraint tenants_id_and_reservation unique (tenant_id, is_reserved)
);

create trigger tenants_set_updated_at before update on tenants
    for each row execute function set_updated_at();

-- One deployment, one reserved tenant. Two would make "where does deployment
-- authority live" a question with two answers, which is the thing ADR-0010
-- rejects the no-reserved-tenant alternative for.
create unique index tenants_only_one_is_reserved on tenants (is_reserved)
    where is_reserved;

-- The reserved tenant cannot be deleted (ADR-0010).
--
-- Enforced here rather than in the application because the cascade is the
-- danger: `users` is `on delete cascade` from `tenants`, so deleting the
-- reserved tenant would remove every deployment admin in one statement — a
-- routine operation taking away the ability to administer the deployment. Like
-- the audit trail's append-only trigger, this is not a defence against somebody
-- with arbitrary SQL, who can drop it; it is a defence against the application,
-- an operator with `psql`, and a future migration.
create function tenants_reserved_is_never_deleted() returns trigger language plpgsql as $$
begin
    raise exception 'the reserved tenant % cannot be deleted', old.tenant_id
        using errcode = 'restrict_violation',
              hint = 'deployment admins are users of this tenant (ADR-0010) and would '
                     'be removed by the cascade; clear tenants.is_reserved first, which '
                     'is refused while a deployment-scoped role exists';
end;
$$;

create trigger tenants_reserved_no_delete before delete on tenants
    for each row when (old.is_reserved)
    execute function tenants_reserved_is_never_deleted();

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
    -- OIDC RP-Initiated Logout 1.0 §3.1. Matched byte for byte by §3, with no
    -- exception at all — not even the loopback port `redirect_uris` allows a
    -- native client to vary.
    post_logout_redirect_uris      text[]      not null default '{}',
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

-- Resolves a registration access token by its digest, within one tenant.
--
-- The only lookup in the schema that goes from a credential to its row rather
-- than from an identifier to it, and it exists for one caller: RFC 7592
-- §2.1/§2.2/§2.3 say a registration access token presented for a client that
-- does not exist "SHOULD be immediately revoked", and revoking it means finding
-- whichever client holds that digest. Without this index that is a sequential
-- scan of every client in the deployment, driven by an unauthenticated request
-- — so the index is not a performance nicety, it is what makes honouring the
-- SHOULD safe at all (`ast-m9c.11`).
--
-- Partial, on `not null`, because a client that was created through the admin
-- API has no registration access token and would otherwise put a null in the
-- index for nothing. Not unique: two clients holding the same digest is a
-- CSPRNG failure, and a unique index would turn it into a write error at
-- registration time instead of leaving the revocation to null both rows.
create index clients_by_registration_access_token
    on clients (tenant_id, registration_access_token_hash)
    where registration_access_token_hash is not null;

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

-- The per-tenant salt every pairwise `sub` is derived under (OIDC Core §8.1).
--
-- **Why this is key material and not configuration.** §8.1 requires that a
-- pairwise Subject Identifier "MUST NOT be reversible by any party other than
-- the OpenID Provider". The other two inputs to the derivation are not secret:
-- the sector identifier is a public host name, and the local account id is a
-- UUID sitting in `users` one join away. The salt is the only thing standing
-- between somebody holding a dump and re-deriving — or confirming — every `sub`
-- in the tenant, which is the entire property pairwise subjects exist to
-- provide. So it is sealed exactly as a signing key is: `*_ciphertext` under a
-- key-encryption key held outside the database, bound to its tenant as AEAD
-- additional authenticated data, with the `kek_id` recorded so a KEK rotation
-- is a `WHERE` clause. See asterius_jose::kek, and `signing_keys` above for the
-- pattern this follows.
--
-- **Why its own table.** A salt is written once per tenant and never again, and
-- a table that refuses `UPDATE` is the only place that statement can be made in
-- a language an operator with `psql` cannot argue with. `tenants` is updated
-- whenever a display name or a settings blob changes, so the salt could not
-- live there without a column-level trigger that has to keep being right
-- forever. Here the trigger is unconditional.
--
-- **Why rotation is not offered.** Every derived `sub` is stored in
-- `subject_identifiers` and read back from there, so a new salt would not move
-- an identifier already issued — it would only mean the same user in the same
-- sector derives differently if that row were ever lost. OIDC Core §8: a
-- Subject Identifier is "a locally unique and never reassigned identifier
-- within the Issuer for the End-User". Recovering from a leaked salt is a
-- reissue of every identifier in the tenant — a relying-party migration — and
-- not a rotation.
create table tenant_pairwise_salts (
    tenant_id       text        primary key
                    references tenants (tenant_id) on delete cascade,
    salt_ciphertext bytea       not null,
    salt_nonce      bytea       not null,
    kek_id          text        not null,
    created_at      timestamptz not null default now(),

    -- 96 bits, the IV length NIST SP 800-38D §5.2.1.1 recommends restricting
    -- support to, and the only length aws-lc-rs will produce here.
    constraint tenant_pairwise_salts_nonce_is_96_bits
        check (length(salt_nonce) = 12),
    -- A salt is exactly 256 bits, so its envelope is exactly that plus a
    -- 16-byte GCM tag. Unlike a private key the plaintext length is fixed, so
    -- this can be an equality rather than a lower bound: a row of any other
    -- size did not come from sealing a salt.
    constraint tenant_pairwise_salts_ciphertext_is_a_sealed_salt
        check (length(salt_ciphertext) = 48)
);

-- A nonce may be used once per key-encryption key, for the reason given on
-- `signing_keys_nonce_never_repeats`: AES-GCM loses confidentiality *and*
-- authenticity if one repeats under one key (NIST SP 800-38D §8). Not tenant
-- scoped, because a KEK spans tenants.
--
-- This covers salt against salt. It cannot cover salt against signing key —
-- PostgreSQL has no cross-table unique constraint — so the residual risk is a
-- nonce collision between the two tables under one KEK. With 96 random bits and
-- one sealing per tenant per lifetime for salts, that is the birthday bound on
-- a handful of draws; the index exists to catch a broken RBG, not to make the
-- arithmetic work.
create unique index tenant_pairwise_salts_nonce_never_repeats
    on tenant_pairwise_salts (kek_id, salt_nonce);

-- Write once. Rotation is refused here rather than merely not implemented, so
-- that "the salt is generated once" is a property of the database and not a
-- convention in the adapter above it. Like the audit trail's append-only
-- trigger, this is not a defence against an attacker with arbitrary SQL — they
-- can drop it — it is a defence against the application, an operator, or a
-- future migration quietly reassigning every subject identifier in a tenant.
--
-- `DELETE` is allowed, because the cascade from `tenants` is a delete: a tenant
-- that no longer exists takes its salt with it, along with every `sub` derived
-- under it.
create function tenant_pairwise_salts_are_written_once() returns trigger language plpgsql as $$
begin
    raise exception 'a tenant pairwise salt is never updated'
        using errcode = 'restrict_violation',
              hint = 'every sub already derived under this salt is stored and never '
                     'reassigned (OIDC Core section 8); recovering from a leak means '
                     'reissuing every identifier, which is a relying-party migration';
end;
$$;

create trigger tenant_pairwise_salts_no_update before update on tenant_pairwise_salts
    for each statement execute function tenant_pairwise_salts_are_written_once();

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
    -- The two backup flags of WebAuthn L3 section 6.1.3, kept apart because
    -- they answer different questions: `eligible` is a property of the
    -- credential that never changes, `state` is where it is right now. A
    -- single-device credential that can never be backed up is the one a
    -- recovery policy has to care about, and only `eligible` says so.
    passkey_backup_eligible boolean,
    passkey_backup_state  boolean,
    -- The RP ID the credential was scoped to, recorded rather than assumed: a
    -- tenant that later moves host must not silently start verifying old
    -- credentials against a new relying party.
    passkey_rp_id         text,
    -- Whether the UV bit was set at registration. A passkey registered without
    -- user verification is one factor, and a step-up policy (ast-2vk.7) needs
    -- to know which it is holding.
    passkey_user_verified boolean,
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
                                      and passkey_rp_id is not null
            when 'recovery_code' then recovery_code_hash is not null
        end
    )
);

create index credentials_by_user on credentials (tenant_id, user_id, kind);

create unique index credentials_by_passkey_id
    on credentials (tenant_id, passkey_credential_id)
    where passkey_credential_id is not null;

-- What a user is allowed to administer (ADR-0010).
--
-- Authority is a role on a user, and a role's scope is either the tenant the
-- user belongs to or the whole deployment. The scope is not a column an admin
-- API could get wrong: it is a property of the role name, spelled out in
-- asterius_domain::Role, so `deployment_admin` is the only value this schema
-- has to reason about.
--
-- **A deployment-scoped role cannot be granted outside the reserved tenant**,
-- and that is enforced declaratively rather than by a trigger or by the code
-- above. `tenant_is_reserved` is a copy of `tenants.is_reserved` that the
-- composite foreign key below forces to be the truth for this tenant — the pair
-- has to exist in `tenants` — and the check then refuses the combination
-- "deployment admin, ordinary tenant". `on update cascade` keeps the copy
-- honest if the flag ever moves: flipping `is_reserved` off cascades into these
-- rows, where the check rejects the update while a deployment-scoped role still
-- exists. Without this, an ordinary tenant would become implicitly privileged
-- and the authority would stop being readable from the data.
create table user_roles (
    tenant_id          text        not null,
    user_id            uuid        not null,
    role               text        not null
                       check (role in ('tenant_admin', 'deployment_admin')),
    -- Denormalised on purpose; see above. Not an assertion the writer makes:
    -- the foreign key makes it one the database checks.
    tenant_is_reserved boolean     not null,
    granted_at         timestamptz not null default now(),

    primary key (tenant_id, user_id, role),
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    foreign key (tenant_id, tenant_is_reserved)
        references tenants (tenant_id, is_reserved)
        on update cascade on delete cascade,
    constraint user_roles_deployment_scope_needs_the_reserved_tenant
        check (role <> 'deployment_admin' or tenant_is_reserved)
);

-- "Who administers this deployment?" answered by an index lookup rather than by
-- a scan over every role in every tenant.
create index user_roles_by_role on user_roles (tenant_id, role);

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

create table sessions (
    tenant_id             text        not null,
    session_id            text        not null,
    -- The `sid` claim (OIDC Back-Channel Logout 1.0 §2.4). Deliberately not
    -- `session_id`: that column is the lookup key and it is *rewritten* on
    -- every rotation, while a relying party's `sid` has to survive one — a
    -- rotation is a new cookie for the same login, not a new session.
    public_sid            text        not null,
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
    -- Back-channel logout arrives carrying a `sid` and nothing else, so this
    -- is the index that resolves it — and unique, because two sessions
    -- answering to one `sid` would make that lookup ambiguous.
    unique (tenant_id, public_sid),
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

-- One outstanding passkey enrolment per session (WebAuthn L3 section 7.1).
--
-- The challenge lives here rather than in `auth_requests.interaction_state`
-- because enrolment is not part of an authorization: a signed-in user reaches
-- it with no pushed request behind them. The session is what it is bound to,
-- and the foreign key is that binding — a challenge cannot outlive, or be
-- moved to, another session, and signing out deletes it by cascade.
--
-- Single use is `spend_challenge`, one `update ... returning` that nulls the
-- column it read. Comparing a challenge is not consuming it, which is the half
-- of step 8 that `asterius_webauthn` documents as the caller's.
create table passkey_enrolments (
    tenant_id   text        not null,
    -- The session's lookup digest, so this table holds no id a browser sent.
    session_id  text        not null,
    -- SHA-256 of the synchroniser token this page was rendered with. The
    -- ceremony is two fetches, and neither is a form, so the token cannot come
    -- from one.
    csrf_digest text        not null,
    -- Null between renderings and after a spend: a row with no challenge is a
    -- page that has been shown and a ceremony that has not started.
    challenge   bytea,
    expires_at  timestamptz not null,
    created_at  timestamptz not null default now(),

    primary key (tenant_id, session_id),
    foreign key (tenant_id, session_id)
        references sessions (tenant_id, session_id) on delete cascade,
    -- WebAuthn L3 section 13.4.3. Enforced here as well as in the type,
    -- because a short challenge that reached the table would be a replayable
    -- one and the table is the last place to say no.
    constraint passkey_enrolments_challenge_is_long_enough
        check (challenge is null or octet_length(challenge) >= 16)
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
    -- The browser's handle on this request, distinct from `request_uri_hash`,
    -- which is the client's. Two parties, two credentials, neither derivable
    -- from the other: a client that could compute this could drive the user's
    -- interaction. Digest only, like the request_uri — it is a bearer value
    -- and a leaked row must not yield a usable one.
    interaction_id_hash bytea unique,
    session_id        text,
    -- The outstanding passkey authentication challenge (WebAuthn L3 section
    -- 7.2), and when it stops being one.
    --
    -- Here rather than in a table of its own, and *not* in `passkey_enrolments`
    -- beside the registration challenge, because the two are bound to
    -- different things. Enrolment happens inside a session; authentication is
    -- what produces one, so at the moment this column is written there is no
    -- session to hang it on. What does exist is the interaction — the browser
    -- holds its id, this row holds the digest — which is the same binding the
    -- synchroniser token in `interaction_state` already has.
    --
    -- Single use is the same statement shape `spend_challenge` uses: one
    -- `update ... from (select ...) returning previous.column`, so two racing
    -- finishes cannot both come away with bytes. Null between renderings and
    -- after a spend.
    passkey_challenge bytea,
    passkey_challenge_expires_at timestamptz,
    pushed_at         timestamptz not null default now(),
    expires_at        timestamptz not null,
    consumed_at       timestamptz,

    primary key (tenant_id, request_uri_hash),
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade,
    -- WebAuthn L3 section 13.4.3, enforced here as well as in the type for the
    -- same reason `passkey_enrolments` does it: a short challenge that reached
    -- the table would be a replayable one.
    constraint auth_requests_passkey_challenge_is_long_enough
        check (passkey_challenge is null or octet_length(passkey_challenge) >= 16),
    -- A challenge with no deadline would be one that never expires, which is
    -- the failure mode the TTL exists to prevent.
    constraint auth_requests_passkey_challenge_has_a_deadline
        check ((passkey_challenge is null) = (passkey_challenge_expires_at is null))
);

create index auth_requests_expiring on auth_requests (expires_at);

create index auth_requests_by_interaction
    on auth_requests (tenant_id, interaction_id_hash)
    where interaction_id_hash is not null;

-- A grant is the revocable unit of authority. Every token traces back to one,
-- which is what makes revocation a single row update rather than a hunt.
create table grants (
    tenant_id             text        not null,
    grant_id              uuid        not null,
    client_id             text        not null,
    user_id               uuid,
    -- Null means "no resource owner", which RFC 9068 §2.2 answers by putting
    -- the client_id in `sub`. Empty means nothing at all, and would be minted
    -- into a token as a subject every other empty subject compares equal to.
    subject               text        check (subject <> ''),
    scopes                text[]      not null default '{}',
    -- The OIDC Core §5.5 `claims` request this authorization covers, as the
    -- parser accepted it and not as the client wrote it: `ClaimsRequest` is
    -- serialised canonically here, so a member this server declines to
    -- understand never reaches the row that records what a person agreed to.
    claims                jsonb       not null default '{}'::jsonb,
    -- OIDC Core §5.2 `claims_locales`, most preferred first. Ordered, so an
    -- array and not a set: "ordered by preference" is the whole parameter.
    -- A column rather than a member of `claims` because it is not part of the
    -- §5.5 request object, and a reader parsing that column as one would have
    -- to know to skip it.
    claims_locales        text[]      not null default '{}',
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
    -- Grant Management ID1 §5.6: a grant is active "when associated tokens have
    -- been successfully claimed by the client", and one that was never claimed
    -- "should be deleted by the AS after a reasonable timeout". This is the
    -- stamp that says which, written by whatever mints the first credential.
    --
    -- It is a column and not a derivation because the one credential that
    -- leaves no trace is the interesting one: a bare access token is a
    -- stateless JWT (RFC 9068), and the authorization code it came from is
    -- gone within 60 seconds (FAPI 2.0 SP §5.3.2.1 item 11). A grant whose
    -- credential is such a token has nothing pointing at it, so a derivation
    -- reads it as abandoned and the sweep below deletes the only row that
    -- could ever have revoked that token.
    --
    -- Deliberately not a `status` column: `expired` is a fact about the clock,
    -- and a stored status is wrong from the instant `expires_at` passes until
    -- a sweep gets to it. See `Grant::status`.
    claimed_at            timestamptz,
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
    -- FAPI 2.0 SP §5.3.2.1 item 11, "shall issue authorization codes with a
    -- maximum lifetime of 60 seconds". Enforced in code; recorded here
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

-- Opaque, never stored in the clear: the column holds the SHA-256 of the value
-- handed to the client, the same treatment `clients.registration_access_token_hash`
-- and the pairwise salt get. A database dump is then a list of digests rather
-- than a list of live credentials (RFC 6749 §10.4, RFC 9700 §4.14).
--
-- The primary key is `(tenant_id, token_hash)`, which is also the only lookup
-- this table has: redemption reads one row by both halves of that key, so there
-- is no predicate here that could degrade into a scan of the tenant.
create table refresh_tokens (
    tenant_id    text        not null,
    token_hash   bytea       not null,
    grant_id     uuid        not null,
    client_id    text        not null,
    -- The scopes this token may be refreshed for (RFC 6749 §6: "the scope of
    -- the access request … MUST NOT include any scope not originally granted").
    -- Recorded per token rather than read from the grant, because a token may
    -- have been issued for a narrowed set and must not widen back to the
    -- grant's on a later refresh.
    scopes       text[]      not null default '{}',
    -- Sender constraint, one of the two. FAPI 2.0 forbids bearer refresh
    -- tokens, so exactly one of these is always present.
    dpop_jkt     text,
    cert_thumbprint bytea,
    issued_at    timestamptz not null default now(),
    -- The two expiries are two different rules and are deliberately two
    -- columns. The absolute one is fixed at issuance and never moves: it is
    -- the only deadline an attacker holding the token cannot push out by
    -- using it. The idle one is rewritten on every successful refresh and
    -- answers "is this integration still in use". Collapsing them into one
    -- column would mean whichever rule wrote last is the rule that applies.
    absolute_expires_at timestamptz not null,
    idle_expires_at     timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    -- Set only under the migration rotation mode (FAPI 2.0 SP §5.3.2.1 item 9,
    -- Note 1), when a refresh issued a replacement. The superseded token stays
    -- acceptable for the tenant's grace window so that a client which lost the
    -- response can retry, and then stops.
    superseded_at timestamptz,

    primary key (tenant_id, token_hash),
    foreign key (tenant_id, grant_id)
        references grants (tenant_id, grant_id) on delete cascade,
    constraint refresh_tokens_are_sender_constrained
        check ((dpop_jkt is null) <> (cert_thumbprint is null)),
    -- The idle deadline is a floor under the absolute one, never past it: a
    -- row where it were later would describe a token whose idle rule can never
    -- fire, which is a policy nobody wrote.
    constraint refresh_tokens_idle_within_absolute
        check (idle_expires_at is null or idle_expires_at <= absolute_expires_at)
);

create index refresh_tokens_by_grant on refresh_tokens (tenant_id, grant_id);
create index refresh_tokens_expiring on refresh_tokens (absolute_expires_at);

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
--
-- `subject` is who chose the value: the `client_id` for a client assertion,
-- the key thumbprint for a DPoP proof. It is part of the key because RFC 7523
-- §3 item 7 scopes `jti` uniqueness to the *issuer* of the assertion, which is
-- the client. A key of (tenant, purpose, jti_hash) alone would put every
-- client in one namespace, so a registered client could burn likely `jti`
-- values -- "1", "2", a guessable UUID -- and deny service to the others.
create table jti_replay (
    tenant_id  text        not null,
    purpose    text        not null
               check (purpose in ('client_assertion', 'dpop_proof')),
    subject    text        not null,
    jti_hash   bytea       not null,
    seen_at    timestamptz not null default now(),
    expires_at timestamptz not null,

    primary key (tenant_id, purpose, subject, jti_hash)
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
    -- Per algorithm, not per tenant. A tenant holds one active key of each
    -- algorithm it advertises (ADR-0003 fixes the set at three), and
    -- `last_rotated_at` is what decides whether the next one is due. Shared
    -- across algorithms it would mean rotating EdDSA suppresses the ES256 and
    -- PS256 rotations that were due at the same time — and, on a tenant with
    -- no keys at all, that only the first algorithm ever gets one.
    alg                        text        not null default 'EdDSA'
                               check (alg in ('EdDSA', 'ES256', 'PS256')),
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

    primary key (tenant_id, purpose, alg),
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
