-- RP-owned endpoint, pinned with the rest of its validated registration.
-- Existing clients do not receive lifecycle commands by default.
alter table clients add column command_endpoint text;

alter table clients add constraint clients_command_endpoint_https
    check (command_endpoint is null or
           (length(command_endpoint) between 1 and 2048 and
            command_endpoint like 'https://%'));

-- A grant may expire and be swept long before an RP deletes its local account.
-- Retain the exact OIDC subject known by each RP until the user or client is
-- removed. Public and pairwise subjects are stable; ephemeral subjects are
-- deliberately ineligible for Provider Commands registration.
create table provider_command_subjects (
    tenant_id text not null,
    user_id uuid not null,
    client_id text not null,
    subject text not null check (length(subject) between 1 and 255),
    first_claimed_at timestamptz not null,
    primary key (tenant_id, user_id, client_id, subject),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade,
    foreign key (tenant_id, client_id) references clients (tenant_id, client_id) on delete cascade
);

insert into provider_command_subjects
    (tenant_id, user_id, client_id, subject, first_claimed_at)
select g.tenant_id, g.user_id, g.client_id, g.subject, min(g.claimed_at)
from grants g join clients c
  on c.tenant_id = g.tenant_id and c.client_id = g.client_id
where g.user_id is not null and g.subject is not null
  and g.claimed_at is not null and 'openid' = any(g.scopes)
  and c.subject_type <> 'ephemeral'
group by g.tenant_id, g.user_id, g.client_id, g.subject;

create function record_provider_command_subject() returns trigger language plpgsql as $$
begin
    if new.user_id is not null and new.subject is not null
       and new.claimed_at is not null and 'openid' = any(new.scopes)
       and exists (select 1 from clients c
                   where c.tenant_id = new.tenant_id and c.client_id = new.client_id
                     and c.subject_type <> 'ephemeral') then
        insert into provider_command_subjects
            (tenant_id, user_id, client_id, subject, first_claimed_at)
        values (new.tenant_id, new.user_id, new.client_id, new.subject, new.claimed_at)
        on conflict do nothing;
    end if;
    return new;
end;
$$;

create trigger grants_record_provider_command_subject
after insert or update of claimed_at on grants
for each row execute function record_provider_command_subject();
