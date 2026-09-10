-- Agent clients get an owner that is a *row*, not a string (`ast-lh3.1`).
--
-- The baseline shipped `agent_owner_sub`, a free-text subject identifier, as a
-- placeholder for this story. It is replaced rather than kept, for two reasons
-- and one consequence.
--
--  * A `sub` is not an identity here. A pairwise subject identifier means
--    something only to the client that received it (OIDC Core §8.1), so an
--    owner named that way is a different owner depending on who is reading —
--    and a public `sub` is the account UUID with a second spelling.
--  * Nothing ever wrote it. The column has no reader and no writer in the
--    codebase, so there is no data to migrate and no compatibility to keep.
--
-- The consequence is that an owner is now referential: `users` decides whether
-- an agent has one, and a deleted account cannot leave an agent behind that
-- still acts on nobody's behalf.
alter table clients
    drop constraint clients_agent_has_owner;

drop index clients_by_agent_owner;

alter table clients
    drop column agent_owner_sub;

alter table clients
    add column agent_owner_user_id uuid;

-- The owner is a user of the *same* tenant: the pair, never the id alone, so
-- that a client in one tenant cannot be owned by an account in another.
--
-- `on delete set null` on the one column rather than on the whole key (PG 15+),
-- because `tenant_id` is the client's own and is not null. Deleting the owner
-- therefore leaves the client row standing — it has an audit history, a
-- registration access token and possibly live grants, and cascading it away
-- would destroy the evidence of what the agent did — and hands it to the
-- trigger below.
alter table clients
    add constraint clients_agent_owner_is_a_user
        foreign key (tenant_id, agent_owner_user_id)
        references users (tenant_id, user_id)
        on delete set null (agent_owner_user_id);

-- An agent has an owner or it is disabled. There is no third state.
--
-- `status` is part of the check so that the trigger below has somewhere to put
-- an agent whose owner has gone: without it, `on delete set null` would produce
-- a row this constraint refuses and the *user's* deletion would fail, which is
-- the wrong end to push back on.
alter table clients
    add constraint clients_agent_has_an_owner_or_is_disabled
        check (not is_agent
               or agent_owner_user_id is not null
               or status = 'disabled');

-- An agent whose owner is gone stops being an agent that works.
--
-- `before update`, so the disabling is part of the same row version the
-- constraint above then sees; and in the database rather than in the domain
-- because the event is a `delete from users`, which the domain never observes.
-- Deliberately one-way: restoring the account does not re-enable the agent, and
-- it should not — somebody has to look at what the agent did in the meantime.
create or replace function disable_ownerless_agent() returns trigger as $$
begin
    if new.is_agent and new.agent_owner_user_id is null then
        new.status := 'disabled';
    end if;
    return new;
end;
$$ language plpgsql;

create trigger clients_disable_ownerless_agent before update on clients
    for each row execute function disable_ownerless_agent();

-- An owner's fleet, which is what both the console screen (`ast-f7m`) and a
-- deprovisioning run ask for: "everything acting for this person".
create index clients_by_agent_owner on clients (tenant_id, agent_owner_user_id)
    where is_agent;
