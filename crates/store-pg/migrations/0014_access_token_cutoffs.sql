-- ast-m9c.13 — withdrawing access tokens this server does not hold.
--
-- RFC 7592 §2.3 asks a deprovisioning to "immediately invalidate ... currently
-- active access tokens", and RFC 7009 §2.1 asks the revocation of a refresh
-- token to "also invalidate all access tokens based on the same authorization
-- grant". Neither is answerable from `access_token_denylist` alone: that table
-- is keyed by `jti`, and this deployment has no inventory of the `jti` values
-- it has signed — RFC 9068 access tokens are stateless by design, which is the
-- trade FAPI 2.0 SP §6.8 item 3 buys.
--
-- So the withdrawal is a *mark* rather than a list: one row says "every access
-- token this principal was issued before this instant is no longer good", and
-- the read compares it against the token's own `iat`. It costs one row per
-- withdrawal instead of one row per token, and it does not grow with traffic.
--
-- There is deliberately no foreign key to `clients` or to `grants`. The whole
-- point of the client mark is that it outlives the client row: RFC 7592 §2.3
-- is a real delete, and a cascading mark would be erased by the very act it
-- records.
create table access_token_cutoffs (
    tenant_id      text        not null,
    -- What the mark is about: a `client_id`, or a `grant_id` rendered as text.
    -- One table rather than two, because it is one question asked of two
    -- principals, and two tables would be two reads on the resource path.
    principal_kind text        not null
                   check (principal_kind in ('client', 'grant')),
    principal_id   text        not null,
    -- Tokens with an `iat` strictly before this instant are refused.
    revoked_before timestamptz not null,
    -- The mark stops doing work once every token it could refuse has expired
    -- on its own `exp`. An access token's lifetime is capped at fifteen
    -- minutes (`asterius_domain::entities::tenant_settings::MAX_ACCESS_TOKEN_LIFETIME`),
    -- so the writer sets this to the cutoff plus that cap and retention sweeps
    -- it afterwards.
    expires_at     timestamptz not null,

    primary key (tenant_id, principal_kind, principal_id)
);

create index access_token_cutoffs_expiring on access_token_cutoffs (expires_at);
