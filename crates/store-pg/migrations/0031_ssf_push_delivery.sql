-- Push delivery: the receiver's credential, and a stream that can be stopped
-- (RFC 8935, ast-0ju.6).
--
-- `0025_ssf_streams.sql` said what this migration owes:
--
-- > `delivery.authorization_header` (RFC 8935 §2.2) is deliberately absent. It
-- > is a credential the receiver hands the transmitter, and every credential
-- > this schema keeps is either a `*_hash` or a `*_ciphertext` re-sealed by the
-- > KEK rotation sweep. [...] `ast-0ju.6` adds the sealed column and the rewrap
-- > arm together when push delivery lands.
--
-- Both are here, and the arm is in `asterius_store_pg::rewrap`. A digest is not
-- an option the way it is for a client secret: SSF 1.0 §6.1.1 obliges the
-- transmitter to *present* this value on every request, so it has to be
-- recoverable, which leaves sealing under the tenant's KEK — the same envelope
-- as `signing_keys.private_key_ciphertext` and `tenant_pairwise_salts`, with
-- the stream bound in as additional authenticated data so that a ciphertext
-- moved to another stream's row stops decrypting instead of being presented to
-- somebody else's endpoint.
--
-- # Why a stream has a status now
--
-- SSF 1.0 §8.1.2 already defines one — `enabled`, `paused`, `disabled` — and
-- push delivery is what first needs to *write* it. RFC 8935 §2.4 bounds the
-- retries of one SET; it says nothing about the tenth SET in a row that a
-- receiver has refused, and a transmitter that keeps queueing for an endpoint
-- that has been answering 400 for a day is generating dead letters rather than
-- signals. So a delivery that exhausts its budget pauses the stream and writes
-- why, which is the state the console shows and the state a receiver reads
-- back. `paused` is deliberately not `disabled`: §8.1.2 makes paused a state
-- the transmitter may leave, and the events go on being queued.
--
-- # Why the counters are columns and not a metric
--
-- `crates/server/src/observability/metrics.rs` keeps every label in a closed
-- set the server owns, because a label a caller can choose is a way to exhaust
-- the metric store — and a stream identifier is chosen by whoever creates a
-- stream. "Delivered and failed *per stream*" is still a thing an operator
-- needs, so it is two counters on the row, read by the management API beside
-- the queue depth. The Prometheus counters stay per-family.

alter table ssf_streams
    -- The receiver's `authorization_header`, sealed. All three columns move
    -- together: a ciphertext without its nonce or without the `kek_id` that
    -- opened it is not recoverable, and a row holding one of the three is a
    -- row a rewrap sweep cannot reason about.
    add column authorization_header_ciphertext bytea,
    add column authorization_header_nonce      bytea,
    add column authorization_header_kek_id     text,
    -- §8.1.2's status. `enabled` for every row that exists today, which is what
    -- they have been doing.
    add column status text not null default 'enabled'
        check (status in ('enabled', 'paused', 'disabled')),
    -- Why it is not enabled, in this server's own words — never a receiver's
    -- response body, which `asterius_ssf::push` reduces to a code first.
    add column status_reason text,
    add column status_changed_at timestamptz,
    -- Per-stream delivery counts. Monotonic, never reset by a delivery: an
    -- operator comparing them is asking "is this receiver taking anything at
    -- all", and a counter that a good delivery cleared would answer yes on the
    -- strength of one.
    add column delivered_count bigint not null default 0,
    add column failed_count    bigint not null default 0,
    -- Either the whole envelope is there or none of it is.
    add constraint ssf_streams_authorization_header_is_whole
        check (num_nonnulls(authorization_header_ciphertext,
                            authorization_header_nonce,
                            authorization_header_kek_id) in (0, 3)),
    -- A credential is for a push endpoint. A poll stream storing one would be
    -- a secret nothing ever presents, kept for as long as the stream lives.
    add constraint ssf_streams_only_push_is_authorized
        check (authorization_header_ciphertext is null
               or delivery_method = 'urn:ietf:rfc:8935');

-- The rewrap sweep reads every sealed row of a KEK generation it is retiring,
-- and `kek_id` is the predicate it selects on. Partial, because the rows
-- without a credential — every poll stream — are not work it has.
create index ssf_streams_sealed_authorization
    on ssf_streams (authorization_header_kek_id)
    where authorization_header_ciphertext is not null;

-- The delivery worker's read: one stream by identifier, without a receiver.
-- It is the primary key already, so this is not an index but a note about why
-- `PgSsfStreams::for_delivery` exists at all: the worker holds an outbox row
-- whose `destination` is a `stream_id`, and no client_id — the receiver is
-- whoever the stream says it is. Every *management* statement keeps the
-- receiver in its `WHERE` clause, as §8 requires; delivery is the one path
-- where the stream is the authority, because it is the stream that was
-- configured.
