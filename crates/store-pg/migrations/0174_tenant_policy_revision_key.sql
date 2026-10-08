-- Preserve the global publication sequence while indexing authority by tenant.
-- No foreign key references revision IDs; readers already qualify by tenant.
alter table tenant_policy_revisions drop constraint tenant_policy_revisions_pkey;
alter table tenant_policy_revisions add primary key (tenant_id, id);
