-- Event ordering outlives bounded JTI replay tombstones. One row per exact
-- tenant/peer/canonical subject binding keeps storage bounded by mappings.
-- Rebinding a mapping to another user resets its ordering state on the next
-- accepted event; deleting the mapping cascades this row away.
create table ssf_receiver_subject_order (
    tenant_id text not null,
    peer_client_id text not null,
    subject_key text not null,
    user_id uuid not null,
    latest_event_timestamp timestamptz not null,
    primary key (tenant_id, peer_client_id, subject_key),
    foreign key (tenant_id, peer_client_id, subject_key)
        references ssf_receiver_subject_mappings
            (tenant_id, peer_client_id, subject_key) on delete cascade
);

-- Historical replay rows do not name their subject_key. Conservatively seed
-- each current mapping for a tenant/peer/user with the group's maximum event
-- timestamp. This can suppress an older legitimate event on another alias
-- during upgrade, but prevents an old event from reapplying after replay
-- tombstones are swept. New events are ordered by exact mapping thereafter.
insert into ssf_receiver_subject_order
    (tenant_id, peer_client_id, subject_key, user_id, latest_event_timestamp)
select b.tenant_id, b.peer_client_id, b.subject_key, b.user_id,
       max(e.event_timestamp)
  from ssf_receiver_subject_mappings b
  join ssf_receiver_events e
    on e.tenant_id = b.tenant_id
   and e.peer_client_id = b.peer_client_id
   and e.user_id = b.user_id
 group by b.tenant_id, b.peer_client_id, b.subject_key, b.user_id;
