-- The device authorization grant (RFC 8628), `ast-lh3.3`.
--
-- One table. A device authorization is a single row that four different actors
-- move through three states, and splitting it would put the state machine in
-- application code where two of those actors race:
--
--   * the device, which creates the row (§3.1) and then polls it (§3.4);
--   * the person at a browser, who finds it by `user_code` and approves or
--     refuses it (§3.3);
--   * the token endpoint, which spends it exactly once;
--   * retention, which deletes it once it can no longer be spent.
--
-- Neither code is stored in the clear. `device_code_hash` and `user_code_hash`
-- are SHA-256 digests, the treatment `authorization_codes.code_hash` and
-- `refresh_tokens.token_hash` already get: a dump of this table is a list of
-- digests rather than a list of codes somebody could type into the
-- verification page of a flow that is still pending (RFC 6749 §10.4,
-- RFC 9700 §4.14). The user code is normalised before it is hashed — upper
-- case, no separator (RFC 8628 §6.1) — so the case-insensitivity lives in one
-- Rust function and not in a `lower()` here that a later index would have to
-- match.
create table device_codes (
    tenant_id             text        not null,
    -- What the device presents at the token endpoint. 256 bits, digested.
    device_code_hash      bytea       not null,
    -- What the person types on the verification page. ~34.5 bits (§6.1),
    -- digested. Unique within the tenant, because two live authorizations
    -- sharing a user code would be an approval landing on whichever the
    -- lookup happened to find.
    user_code_hash        bytea       not null,
    client_id             text        not null,
    -- What the device asked for (§3.1), already narrowed to the client's
    -- registration. The approval is for *these*, so they are recorded when the
    -- request arrives rather than re-read from anywhere later.
    scopes                text[]      not null default '{}',
    authorization_details jsonb       not null default '[]'::jsonb,
    issued_at             timestamptz not null default now(),
    -- §3.2's `expires_in`. Ten minutes at most: a pending authorization is a
    -- user code on a screen, and §5.1's guessing budget grows with every
    -- second one stays live.
    expires_at            timestamptz not null,
    -- §3.2's `interval`, in seconds, as it currently stands *for this
    -- authorization*. §3.5 raises it by five each time the device polls too
    -- fast, so the value is per-row and not a constant: a client that has
    -- already obeyed one `slow_down` must not be told to slow down again at
    -- the rate it was just asked to use.
    poll_interval_seconds integer     not null,
    -- When the device last polled, which is the only thing "too fast" can be
    -- measured against. Null until the first poll, so the first one is never
    -- `slow_down`.
    last_polled_at        timestamptz,
    -- The state machine. `pending` is what §3.5 answers `authorization_pending`
    -- for; `approved` is redeemable exactly once; `denied` is §3.5's
    -- `access_denied` and is terminal. Expiry is *not* a state — it is the
    -- clock against `expires_at`, so there is no sweep that has to run for
    -- `expired_token` to be the honest answer.
    status                text        not null default 'pending'
                          check (status in ('pending', 'approved', 'denied')),
    -- Who approved it, and the authorization their approval created. Both null
    -- while pending, both set together at approval: a row with a grant and no
    -- user, or the reverse, is an approval this server could not explain.
    user_id               uuid,
    grant_id              uuid,
    approved_at           timestamptz,
    -- Set by the one statement that spends the row. RFC 8628 §3.4 refers to
    -- RFC 6749 §4.1.3, and a device code is redeemable once for the same
    -- reason an authorization code is: a second redemption means either the
    -- client is broken or somebody else has the code.
    redeemed_at           timestamptz,
    -- §5.1. Failed confirmations against *this* authorization, counted so that
    -- the row can be taken out of the guessing space before the space is
    -- exhausted. The per-address limit (`rate_limits`) is the other half and
    -- the one that bounds a sweep across many codes; this one bounds an
    -- attacker who has found one.
    failed_attempts       integer     not null default 0
                          check (failed_attempts >= 0),

    primary key (tenant_id, device_code_hash),
    unique (tenant_id, user_code_hash),
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade,
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    foreign key (tenant_id, grant_id)
        references grants (tenant_id, grant_id) on delete set null,
    -- RFC 8628 §3.2 leaves `expires_in` to the server; `ast-lh3.3` caps it at
    -- ten minutes, and the schema says so too, so a row that violated the cap
    -- could not be written even if the issuing code were wrong.
    constraint device_codes_max_lifetime
        check (expires_at <= issued_at + interval '600 seconds'),
    -- §3.5's default interval is 5 seconds and `slow_down` only ever raises
    -- it. A row below it would be this server advertising a rate it then
    -- punishes a client for using.
    constraint device_codes_interval_floor
        check (poll_interval_seconds >= 5),
    -- An approval is a user, a grant and a stamp, or it is none of them.
    constraint device_codes_approval_is_whole
        check ((status = 'approved') = (user_id is not null and approved_at is not null)),
    -- Nothing that was never approved can have been spent.
    constraint device_codes_only_approved_are_redeemed
        check (redeemed_at is null or status = 'approved')
);

-- The two lookups that are not by primary key. The verification page finds a
-- row by `user_code_hash` alone within the tenant, which the unique constraint
-- above already indexes; retention deletes by `expires_at`, which this covers.
create index device_codes_expiring on device_codes (tenant_id, expires_at);
