-- Preserve the specification that last reached every resource. Older flows
-- can be backfilled only when their draft still is the applied revision.
alter table architecture_flows add column applied_graph jsonb;
update architecture_flows set applied_graph = graph
where applied_revision = revision and applied_revision is not null;
