-- Subject membership per stream (SSF 1.0 §8.1.3), ast-0ju.4.
--
-- §8.1.2's status is not here: `0031_ssf_push_delivery.sql` added the column
-- when push delivery first needed to *write* it, and this story is the one
-- that lets a receiver read and change it. One column, because two would be
-- two answers to "is this stream delivering".
--
-- The subjects a stream carries events about (§8.1.3).
--
-- # Why every row is explicit
--
-- §7.1's `default_subjects` for this transmitter is `NONE`
-- (`asterius_ssf::metadata`), so a stream carries events about the subjects a
-- receiver added and about nobody else. That makes this table the whole
-- answer to "may this receiver hear about this person": an empty table for a
-- stream is a stream that delivers nothing, which is the safe state to be in
-- by default and the only one that cannot leak a subject identifier a receiver
-- was never given.
--
-- # The key is canonical, not the bytes the receiver sent
--
-- `subject_key` is `asterius_ssf::Subject::key`: the parsed identifier
-- rendered back to JSON with its members in one order. Two spellings of one
-- subject — members reordered, a member the format does not define, different
-- whitespace — are therefore one row, so §8.1.3.3's remove finds what
-- §8.1.3.2's add wrote. Storing the receiver's bytes instead would leave a
-- membership a receiver believes it removed, which is events about a person
-- continuing to reach somebody who asked to stop hearing about them.
--
-- `subject` keeps the parsed object, because §8.1.3.1's matching is not string
-- equality: a complex subject matches one whose members are undefined on
-- either side, and that comparison needs the members rather than the key.

create table ssf_stream_subjects (
    tenant_id   text        not null,
    stream_id   text        not null,
    -- The canonical form, and the primary key: adding a subject twice is one
    -- row, which is what makes §8.1.3.2 idempotent rather than a counter.
    subject_key text        not null check (length(subject_key) <= 4096),
    -- The same identifier, parsed, for §8.1.3.1's matching.
    subject     jsonb       not null,
    -- §8.1.3.2's `verified`, as the receiver asserted it. Recorded and never
    -- relied on: what a receiver may hear about is decided by the matching
    -- rules against this tenant's own events, never by a boolean the caller
    -- set. Kept because an operator investigating a subscription wants to know
    -- what the receiver claimed when it made it.
    verified    boolean,
    added_at    timestamptz not null default now(),

    primary key (tenant_id, stream_id, subject_key),
    -- §8.1.1.5: a deleted stream carries nothing, including its membership.
    -- The cascade is what stops a deleted stream's subject identifiers from
    -- outliving the stream they described.
    foreign key (tenant_id, stream_id)
        references ssf_streams (tenant_id, stream_id) on delete cascade
);

-- The read that matters: every subject of one stream, which is what an emitter
-- walks to decide whether an event reaches a receiver (§8.1.3.1). Matching is
-- not an equality the index could answer, so the index is on the stream and
-- the comparison is in Rust.
create index ssf_stream_subjects_by_stream
    on ssf_stream_subjects (tenant_id, stream_id);
