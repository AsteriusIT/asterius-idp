-- A failed `jwks_uri` fetch, remembered across replicas and restarts
-- (`ast-mxc.8`).
--
-- `client_keys` holds what a fetch *produced*, keyed by `(tenant_id,
-- client_id, kid)`. A failed fetch produces no key and therefore no `kid`, so
-- there was no row in this schema able to say "this URL was tried at T and it
-- failed". The negative cache in `asterius_jose::ClientKeyCache` was
-- consequently in memory and per process: with N replicas an unreachable
-- third-party `jwks_uri` is fetched N times per backoff window instead of once,
-- and a restart forgets the outage entirely.
--
-- ADR-0001 expects more than one replica and ADR-0006 makes the treatment of a
-- client-supplied URL a *policy*. A policy whose rate is multiplied by the
-- number of processes that happen to be running is not a policy, and the party
-- paying for the difference is the third party at the far end of a URL a client
-- chose. This table is where the decision becomes shared.
--
-- A migration of its own rather than an edit to the baseline, for the reason
-- 0002 gives: editing a baseline changes a checksum sqlx refuses to run against
-- a database that already applied it.

create table client_key_fetches (
    tenant_id       text        not null,
    client_id       text        not null,
    -- SHA-256 of the `jwks_uri`, not the URL.
    --
    -- Two reasons, and either alone would be enough. The URL is a
    -- client-supplied string that may carry a query parameter the client
    -- considers a secret — `asterius_server::outbound` refuses to put one in a
    -- log line for exactly that reason, and a table is a log line that keeps —
    -- and it is unbounded, while a btree index entry is not. A digest is
    -- fixed-width and only ever compared for equality, which is all this key is
    -- for. Same reasoning as `jti_replay.jti_hash`.
    jwks_uri_hash   bytea       not null check (octet_length(jwks_uri_hash) = 32),
    last_attempt_at timestamptz not null,
    -- Why it failed, for an operator reading the table. Never the response
    -- body: that is bytes chosen by whoever is at the end of the URL, and this
    -- is not the place to store an arbitrary quantity of them. The bound is
    -- enforced here rather than trusted to the adapter, because a constraint is
    -- what makes it true of every writer.
    last_error      text        not null check (length(last_error) <= 200),
    -- Before this instant, no replica fetches this URL for this client. The
    -- window is a duration the process applies, but what is stored is the
    -- instant: two replicas with different configuration still agree on a
    -- deadline, and a replica that starts after the failure honours what is
    -- left of it rather than starting a window of its own.
    next_attempt_at timestamptz not null,

    primary key (tenant_id, client_id, jwks_uri_hash),
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade
);

comment on table client_key_fetches is
    'Negative cache for client JWK Set fetches, shared by every replica. '
    'One row per (tenant, client, jwks_uri) that failed; removed when a fetch '
    'for that URL succeeds, and swept once next_attempt_at has passed.';
