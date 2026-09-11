-- What a CIBA Core 1.0 §10.2 ping notification needs, sealed (`ast-lh3.5`).
--
-- `0026_ciba_requests.sql` stored the `auth_req_id` and the
-- `client_notification_token` as digests, which is the right shape for a
-- value this server only ever *compares*. The ping callback does not compare
-- either: it *presents* both. §10.2 has the OP post `{"auth_req_id": …}` to
-- the client's notification endpoint with the `client_notification_token` as
-- the bearer, minutes after the request was accepted and on a worker that has
-- nothing but the row. A digest cannot be posted, so in ping mode the two
-- values are kept in a form the worker can open — and that form is the one
-- every other recoverable secret here takes: sealed under the tenant's KEK,
-- bound to this row, with the three columns of the envelope moving together.
--
-- Sealed rather than stored beside the digests in the clear, for the reason
-- `ssf_streams.authorization_header_ciphertext` gives: the notification token
-- is a bearer credential at a URL the client registered, and the `auth_req_id`
-- is a bearer credential at *this server's* token endpoint. A dump of this
-- table is a list of pending approvals; it must not also be a list of things
-- somebody could redeem once the approvals land. Bound to the row (the AEAD's
-- additional data names the tenant and the `auth_req_id` digest) so that a
-- ciphertext copied over another request's row stops opening rather than
-- notifying one client of another client's approval.
--
-- The digest columns stay. `auth_req_id_hash` is the primary key and the value
-- the token endpoint looks up; `client_notification_token_hash` keeps the
-- constraint that a poll row holds no notification credential at all.
alter table ciba_requests
    add column ping_ciphertext bytea,
    add column ping_nonce      bytea,
    add column ping_kek_id     text;

-- A ping row accepted before this migration holds a digest and nothing the
-- worker could post. It could never be notified, and its client is polling
-- anyway (§10.2 clients "MUST" still fetch from the token endpoint); it is
-- removed rather than left to violate the constraint below. A CIBA request
-- lives five minutes at most, so this is at most five minutes of pending
-- approvals on a deployment that was mid-flight during the upgrade.
delete from ciba_requests where delivery_mode = 'ping' and ping_ciphertext is null;

-- All three columns of the envelope, or none: a ciphertext without its nonce
-- or without the `kek_id` that sealed it cannot be opened, and cannot be
-- re-sealed by the rotation sweep either.
alter table ciba_requests
    add constraint ciba_requests_ping_envelope_is_whole
        check (num_nonnulls(ping_ciphertext, ping_nonce, ping_kek_id) in (0, 3)),
    -- §7.1: sealed exactly when there is a notification to send. A ping row
    -- without one is a row the worker cannot act on; a poll row with one is a
    -- credential nothing presents.
    add constraint ciba_requests_ping_envelope_needs_ping
        check ((ping_ciphertext is null) = (delivery_mode <> 'ping'));

-- The rewrap sweep (`asterius rewrap-kek`) reads every sealed row of a KEK
-- generation it is retiring, and `kek_id` is the predicate it selects on.
-- Partial, because poll rows have nothing sealed.
create index ciba_requests_sealed_ping
    on ciba_requests (ping_kek_id)
    where ping_ciphertext is not null;
