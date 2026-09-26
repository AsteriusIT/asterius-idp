-- A remote DELETE may succeed even when the receiver loses the response.
-- Keep the exact stream pinned and stop polling until authenticated readback
-- proves it absent. This also prevents setup from creating a second stream.
alter table ssf_receiver_upstream_streams
    add column deletion_started_at timestamptz;
