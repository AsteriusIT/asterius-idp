-- Outbox delivery: claims, attempts and per-key ordering (ast-0ju.9).
--
-- `0001_baseline.sql` created the `outbox` table and said what it was for:
-- rows written in the same transaction as the state change they describe, so
-- that no notification is lost between the commit and the delivery. What it
-- did not have was anything that *delivers* them. This migration adds the
-- three things a worker needs and nothing else.
--
-- 1. A **claim**. `status = 'claimed'` plus `claim_expires_at` is a lease: the
--    worker takes the row, commits the claim, then delivers. A process that
--    dies between the two has left a claimed row whose lease expires, and the
--    next worker takes it again. That is at-least-once by construction — the
--    only alternative, deleting or acking before delivering, is at-most-once
--    and loses a back-channel logout every time a pod is evicted.
--
-- 2. An **ordering key**. Two events about the same (stream, subject) or the
--    same (client, session) have to reach the receiver in the order they
--    happened, or a "session revoked" can arrive before the "session started"
--    it invalidates. `ordering_key` is null for rows where order does not
--    matter — a recovery e-mail has nothing to be ordered against — and the
--    claim query refuses to take a keyed row while an earlier row with the
--    same key is still owed.
--
-- 3. An **attempt trail**. `outbox.attempts` is a counter, which answers "how
--    many" and never "what went wrong the third time". A dead-lettered row is
--    read during an incident, and a counter is not enough to act on.

alter table outbox
    -- Null means unordered: this row may be delivered concurrently with any
    -- other. Non-null groups rows that must go out oldest-first.
    add column ordering_key     text,
    -- Which worker holds the claim, for a log line during an incident. A
    -- process-scoped random name, never anything about the row's subject.
    add column claimed_by       text,
    -- When the claim lapses. Null unless `status = 'claimed'`.
    add column claim_expires_at timestamptz;

-- `claimed` is a fourth in-flight state. It is deliberately *not* terminal and
-- deliberately not swept by retention: a claimed row is still work owed.
alter table outbox drop constraint outbox_status_check;
alter table outbox add constraint outbox_status_check
    check (status in ('pending', 'claimed', 'delivered', 'failed', 'abandoned'));

-- A claim lease that outlives its worker must be reclaimable, so the index the
-- worker scans has to include `claimed` rows.
drop index outbox_due;
create index outbox_due on outbox (available_at, outbox_id)
    where status in ('pending', 'failed', 'claimed');

-- The ordering check: "is there an earlier row with this key still owed". It
-- runs once per candidate row, so it gets its own index rather than sharing
-- `outbox_due`, whose leading column is a timestamp.
create index outbox_ordering on outbox (tenant_id, ordering_key, outbox_id)
    where ordering_key is not null
      and status in ('pending', 'failed', 'claimed');

-- One row per delivery attempt.
--
-- `on delete cascade` from `outbox` is what keeps this out of the retention
-- policy's way: the parent row is swept on the stated schedule and its trail
-- goes with it, so there is no second cutoff to keep in step with the first.
create table outbox_attempts (
    tenant_id    text        not null,
    outbox_id    bigint      not null,
    -- 1 for the first. Part of the key, so a retried ack cannot double-count.
    attempt      integer     not null,
    attempted_at timestamptz not null default now(),
    -- What the deliverer reported. `journalled` is the honest outcome for a
    -- deliverer that recorded the event inside this process rather than
    -- sending it anywhere; see `asterius_server::outbox::Delivered`.
    outcome      text        not null
                 check (outcome in ('delivered', 'journalled', 'retry', 'abandoned')),
    -- The deliverer's own words, already trimmed of anything a payload
    -- carried. Never the payload, never the destination: a dead-lettered
    -- recovery message's payload is a live reset link, and this table is read
    -- by an operator through the admin API.
    detail       text,

    primary key (tenant_id, outbox_id, attempt),
    foreign key (tenant_id, outbox_id) references outbox (tenant_id, outbox_id)
        on delete cascade
);

-- The dead-letter screen reads the newest attempt of each abandoned row.
create index outbox_attempts_recent on outbox_attempts (tenant_id, attempted_at desc);
