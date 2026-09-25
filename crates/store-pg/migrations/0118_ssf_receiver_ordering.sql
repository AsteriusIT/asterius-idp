-- Persist ordering and processing outcome for verified receiver events. The
-- per-user ordering query is serialized by locking the corresponding subject
-- mapping row before reading the maximum timestamp.
alter table ssf_receiver_events
    add column event_timestamp timestamptz,
    add column outcome text not null default 'applied';

update ssf_receiver_events set event_timestamp = processed_at;
alter table ssf_receiver_events alter column event_timestamp set not null;

alter table ssf_receiver_events
    drop constraint ssf_receiver_events_event_type_check,
    add constraint ssf_receiver_events_event_type_check
        check (event_type in (
            'session-revoked', 'account-disabled',
            'credential-compromised', 'credential-observed'
        )),
    add constraint ssf_receiver_events_outcome_check
        check (outcome in ('applied', 'stale'));

create index ssf_receiver_events_subject_order
    on ssf_receiver_events (tenant_id, user_id, event_timestamp desc);
