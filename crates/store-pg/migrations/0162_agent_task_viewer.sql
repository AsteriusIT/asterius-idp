-- Keyset task listing and recorded Task-specific audit correlation. These
-- indexes do not turn historical audit claims into authorization state.
create index agent_tasks_by_agent on agent_tasks(tenant_id,initiating_client_id,task_id);
create index audit_events_task_reference on audit_events(tenant_id,(detail ->> 'task_id'),event_id desc)
    where detail ? 'task_id';
