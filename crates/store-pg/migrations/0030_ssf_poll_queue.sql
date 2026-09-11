-- SETs waiting for a receiver to poll for them (RFC 8936, ast-0ju.7).
--
-- # Why this is not the outbox
--
-- `0025_ssf_streams.sql` reserved `outbox.kind = 'ssf.set'` for the delivery
-- stories, and that is the right home for *push* (RFC 8935, ast-0ju.6): the
-- outbox is a queue of work this server owes and a worker performs. Poll
-- delivery is the other shape. Nobody here performs it: the receiver comes and
-- asks, decides for itself whether it processed the SET, and says so in the
-- *next* request (RFC 8936 §2.4). Three of the outbox's properties are wrong
-- for that, each of them in a way that loses signals:
--
-- * a claim lease means a SET a receiver was handed is invisible until the
--   lease lapses, where §2.4 requires that an unacknowledged SET be handed
--   over again on the next poll;
-- * an attempt budget dead-letters a SET after ten polls, so a receiver that
--   is slow to acknowledge silently stops being told things;
-- * `OutboxWorker` claims every row whose kind it can read and abandons the
--   ones no deliverer answers for, which is exactly what would happen to a
--   poll row today.
--
-- So a poll queue is its own table, with the receiver's acknowledgement as the
-- only thing that removes a row. Push delivery keeps the outbox and keeps
-- `PgSsfStreams::delete`'s abandonment of it.
--
-- # What removes a row
--
-- Three things, and nothing else.
--
-- 1. The receiver acknowledged it (§2.4). It has the SET; holding a copy after
--    that is retaining a subject identifier for no purpose.
-- 2. The receiver reported an error for it in `setErrs` (§2.4). The row goes
--    and the audit trail keeps the report, including the receiver's own error
--    code: redelivering a SET a receiver has already refused is a loop, and
--    which SET it refused and why is a thing an operator must be able to read
--    afterwards. That is this deployment's policy where §2.4 leaves the
--    transmitter a choice, and `docs/threat-model.md` records it.
-- 3. The stream was deleted (SSF 1.0 §8.1.1.5: "the transmitter MUST NOT
--    deliver any events for a deleted stream"). That is the foreign key's
--    `on delete cascade` below rather than a statement someone has to
--    remember to write beside the delete.

create table ssf_poll_queue (
    tenant_id    text        not null,
    -- The stream this SET belongs to. Also the address it is polled at: SSF
    -- 1.0 §6.1.2 makes the polling URL unique per stream and per receiver, so
    -- the stream identifier in the URL is what selects these rows.
    stream_id    text        not null,
    -- RFC 8417 §2's `jti`, and §2.3's member name in the poll response. The
    -- primary key, so a SET queued twice for one stream is one row: a
    -- transmitter that delivered a duplicate would be asking a receiver to
    -- deduplicate work this table can avoid creating.
    jti          text        not null,
    -- The compact serialisation, exactly as it was signed. Not the claims: a
    -- SET is a signed object and re-rendering it here would produce bytes
    -- whose signature does not check out.
    set_jws      text        not null,
    queued_at    timestamptz not null default now(),
    -- When this SET was last handed to a poll, and how many times. Neither
    -- gates delivery — §2.4 redelivers until acknowledged — but "we have
    -- handed this to the receiver forty times and it has never acknowledged
    -- it" is the shape of a receiver that cannot verify our SETs, and an
    -- operator can only see it if it is written down.
    delivered_at timestamptz,
    deliveries   integer     not null default 0,

    primary key (tenant_id, stream_id, jti),
    foreign key (tenant_id, stream_id)
        references ssf_streams (tenant_id, stream_id) on delete cascade
);

-- The poll itself: the oldest SETs of one stream, first in first out, so a
-- receiver reading with `maxEvents` sees its backlog in the order the events
-- happened rather than in whatever order the table hands them back.
create index ssf_poll_queue_by_stream
    on ssf_poll_queue (tenant_id, stream_id, queued_at, jti);
