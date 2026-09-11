-- Per-agent audit trail: the indexes the query API reads through (`ast-lh3.9`).
--
-- No new column. The trail already holds everything the per-agent view needs
-- — the agent and its owner in `actor`, the RFC 8693 §4.1 `act` chain in
-- `actor_chain`, the FAPI 2.0 SP §6.8 item 4 link in `grant_id` — and a column
-- added here would either duplicate one of them or, worse, change what the
-- hash chain covers (`asterius_domain::audit::chain::canonical_bytes`) and
-- turn every record written before it into a tampering report. What was
-- missing is a way to *find* a record by those fields without scanning a
-- tenant's whole trail, which is what an incident review of a compromised
-- agent (threat-model T-A4) does first.
--
-- Every index leads with `tenant_id` and ends with `event_id desc`, because
-- the query pages newest first by keyset on `event_id`: a filtered page is one
-- range scan from wherever the previous page stopped, whatever the filter.

-- "Everything agent A did, for whoever": the actor is an agent with this id.
-- Partial, because the plain-client and user records that make up most of
-- the trail would never be found through it.
create index audit_events_by_agent on audit_events (tenant_id, (actor ->> 'id'), event_id desc)
    where actor ->> 'type' = 'agent';

-- "Everything done for user U by an agent": the owner the actor names.
create index audit_events_by_owner on audit_events (tenant_id, (actor ->> 'on_behalf_of'), event_id desc)
    where actor ->> 'type' = 'agent';

-- "Everything done under user U": the subject, for the half of the question
-- the owner index does not answer (an exchange by B is *about* U and *for* B's
-- owner).
create index audit_events_by_subject on audit_events (tenant_id, subject, event_id desc)
    where subject is not null;

-- "Everything of one type in a window": the console's first filter.
create index audit_events_by_type on audit_events (tenant_id, event_type, event_id desc);

-- "Everything agent A took part in", including exchanges it did not perform:
-- containment on the chain (`actor_chain @> '[{"id": "c.a"}]'`), which
-- `jsonb_path_ops` answers from the index. The chain is a list of small
-- objects and never grows past `max_delegation_depth`, so the index stays a
-- fraction of the table.
create index audit_events_by_chain on audit_events using gin (actor_chain jsonb_path_ops);
