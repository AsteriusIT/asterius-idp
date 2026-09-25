-- Persist the last accepted moving factor so concurrent and subsequent
-- challenges cannot reuse a valid TOTP in the same time step.
alter table totp_credentials
    add column last_used_step bigint not null default -1
        check (last_used_step >= -1);
