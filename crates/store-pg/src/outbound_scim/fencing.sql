-- Prepared supplied-connection command shapes, not registered runtime queries.
-- Caller obtains connector/assignment locks in this order before checking lease.
-- No network request is allowed while this transaction remains open.
select revision, credential_generation, enabled, target_issuer, target_client
from outbound_scim_connectors
where tenant_id=$1 and connector_id=$2 for update;

select generation, desired_revision, target_id, retired_at
from outbound_scim_assignments
where tenant_id=$1 and assignment_id=$3 for update;

-- A delayed worker must not write a mapping or terminal evidence for a later
-- claimed attempt. Capture clock_timestamp() after all authority locks settle.
select claim_expires_at
from outbox
where tenant_id=$1 and outbox_id=$4 and attempts=$5 and status='claimed'
for share;

-- A separate clock statement is essential: evaluating time inside the locking
-- SELECT can happen before an asynchronous row-lock wait. The adapter compares
-- both the saved lease and the prepared delivery deadline with this DB time.
select clock_timestamp() as observed_at;

-- Persist an initially recovered UUID only for the same incarnation/principal.
-- A concurrent source change preserves that UUID but keeps its latest work dirty.
update outbound_scim_assignments
set target_id=$6, observed_etag=$7, observed_at=clock_timestamp(),
    delivered_revision=case when desired_revision=$8 then $8 else delivered_revision end,
    dirty=desired_revision<>$8,
    state=case when desired_revision=$8 then 'applied' else 'pending' end,
    failure_code=null
where tenant_id=$1 and assignment_id=$3 and generation=$9
  and retired_at is null and (target_id is null or target_id=$6)
returning assignment_id;
