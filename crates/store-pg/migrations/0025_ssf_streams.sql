-- SSF stream configuration (ast-0ju.3).
--
-- One row per stream: SSF 1.0 §8.1.1's object, minus the members that are
-- constants of the deployment. `iss`, `events_supported` and
-- `min_verification_interval` are *not* columns — they are rendered from the
-- tenant's issuer and from `asterius_ssf::stream`, so a stored row cannot
-- carry a stale copy of the issuer a receiver validates every SET against.
--
-- The poll endpoint is not a column either, for the same reason: for poll
-- delivery §8.1.1 makes `endpoint_url` transmitter-supplied, so it is derived
-- from the issuer at render time and `delivery_endpoint_url` is null. Only a
-- push endpoint — the receiver's own URL — is stored.
--
-- `delivery.authorization_header` (RFC 8935 §2.2) is deliberately absent.
-- It is a credential the receiver hands the transmitter, and every credential
-- this schema keeps is either a `*_hash` or a `*_ciphertext` re-sealed by the
-- KEK rotation sweep (`asterius_store_pg::rewrap`). A column outside that
-- sweep would be a secret a rotation silently strands, so the endpoint refuses
-- the member instead of storing it in the clear; `ast-0ju.6` adds the sealed
-- column and the rewrap arm together when push delivery lands.

create table ssf_streams (
    tenant_id                  text        not null
                               references tenants (tenant_id) on delete cascade,
    -- §8.1.1's `stream_id`: 128 bits of entropy from the transmitter, never a
    -- value a receiver chose (`asterius_ssf::stream::StreamId`).
    stream_id                  text        not null,
    -- The receiver. §8 makes authorization "an association between a receiver
    -- and the streams it may manage", and this column is that association:
    -- every read in the management API is `where tenant_id = $1 and client_id
    -- = $2`, so another receiver's stream is not a row this endpoint can
    -- reach — it does not have to be recognised and refused.
    client_id                  text        not null,
    -- §8.1.1's `aud`, immutable after creation. Stored sorted, because the
    -- order of an audience carries no meaning and the uniqueness rule below
    -- compares whole arrays: two requests naming the same two audiences in
    -- different orders are one stream, not two.
    audience                   text[]      not null
                               check (cardinality(audience) between 1 and 8),
    -- §8.1.1's `events_requested`, as the receiver asked for it — including
    -- types this transmitter cannot yet emit, so that a type gaining an
    -- emitter starts being delivered without the receiver asking again.
    -- `events_delivered` is not stored: it is the intersection with what the
    -- build supports, computed at render time, and a stored copy would go
    -- stale the moment an emitter lands.
    events_requested           text[]      not null default '{}'
                               check (cardinality(events_requested) <= 64),
    -- §8.1.1's `delivery.method`. The two methods SSF 1.0 defines and no
    -- third: an unrecognised URN is a 400 at the endpoint, and the check keeps
    -- that true of anything else that ever writes here.
    delivery_method            text        not null
                               check (delivery_method in (
                                   'urn:ietf:rfc:8935',
                                   'urn:ietf:rfc:8936')),
    -- The receiver's push endpoint (RFC 8935 §2.2), or null for a poll stream.
    delivery_endpoint_url      text,
    description                text,
    inactivity_timeout_seconds integer     check (inactivity_timeout_seconds > 0),
    created_at                 timestamptz not null default now(),
    updated_at                 timestamptz not null default now(),

    primary key (tenant_id, stream_id),
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade,
    -- A push stream has a URL and a poll stream has none. Without this a row
    -- could say "push" and name nowhere, which is a stream whose events have
    -- no destination and no error.
    constraint ssf_streams_push_has_an_endpoint
        check ((delivery_method = 'urn:ietf:rfc:8935') = (delivery_endpoint_url is not null))
);

-- One stream per receiver per audience (§8.1.1.1's 409).
--
-- A unique index rather than a count taken by the handler: two concurrent
-- `POST`s would both read "no stream yet" and both insert, and the 409 exists
-- precisely so a receiver knows which of its streams a SET belongs to.
--
-- A tenant that wants several streams per audience is a setting this build
-- does not have; adding it means dropping this index and enforcing the default
-- per tenant, which is a migration of its own and not a column here.
create unique index ssf_streams_one_per_audience
    on ssf_streams (tenant_id, client_id, audience);

create trigger ssf_streams_set_updated_at before update on ssf_streams
    for each row execute function set_updated_at();

-- The management API lists a receiver's streams (§8.1.1.2, `GET` with no
-- `stream_id`), which is this index; the single-stream read is the primary
-- key.
create index ssf_streams_by_receiver on ssf_streams (tenant_id, client_id);

-- §8.1.1.5: "the transmitter MUST NOT deliver any events for a deleted
-- stream". A SET that is already queued has to be dropped with the stream, so
-- the outbox rows that carry one name the stream they belong to.
--
-- `kind = 'ssf.set'` and `destination = <stream_id>` is that naming. The
-- delivery stories (`ast-0ju.6` push, `ast-0ju.7` poll) queue under it and
-- `PgSsfStreams::delete` abandons whatever is still owed, in the same
-- transaction that removes the stream. This partial index is what makes that
-- statement a lookup rather than a scan of the tenant's whole outbox.
create index outbox_ssf_pending on outbox (tenant_id, destination)
    where kind = 'ssf.set' and status in ('pending', 'failed', 'claimed');
