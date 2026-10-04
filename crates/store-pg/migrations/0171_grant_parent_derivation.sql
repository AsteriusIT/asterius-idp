-- Private generations distinguish permission/authentication changes even within
-- one transaction timestamp. Bookkeeping updated_at is deliberately unsuitable.
alter table grants add column authority_revision uuid not null default gen_random_uuid();
alter table grants add column parent_authority_revision uuid;
alter table grants add constraint grant_authority_revision_not_nil
    check (authority_revision <> '00000000-0000-0000-0000-000000000000'::uuid);
alter table grants add constraint grant_parent_revision_has_parent
    check (parent_authority_revision is null or parent_grant_id is not null);

-- Do not backfill children from current parent generations: that invents the
-- historical derivation receipt. Legacy derived grants require reauthorization
-- before new issuance; existing offline credentials retain their expiry bounds.
create function protect_grant_authority_revision() returns trigger
language plpgsql as $$
declare
    attested_lookup_move boolean := false;
begin
    if new.parent_authority_revision is distinct from old.parent_authority_revision then
        raise exception 'grant parent derivation is immutable' using errcode = '23514';
    end if;
    if new.session_id is distinct from old.session_id
       and (new.user_id,new.authenticated_at,new.acr,new.amr)
           is not distinct from (old.user_id,old.authenticated_at,old.acr,old.amr) then
        -- The same exact stable public session may rotate a private lookup
        -- digest without replacing frozen authentication or derived authority.
        -- This matches the original-source attestation used by migration0170.
        select exists (
            select 1 from grant_session_lineage l join sessions s
              on s.tenant_id=l.tenant_id and s.public_sid=l.public_sid and s.user_id=l.user_id
            where l.tenant_id=new.tenant_id and l.grant_id=new.grant_id
              and l.user_id=new.user_id and l.lookup_digest=old.session_id
              and s.session_id=new.session_id and s.revoked_at is null
              and s.expires_at>clock_timestamp() and s.idle_expires_at>clock_timestamp()
        ) into attested_lookup_move;
    end if;
    if (new.client_id,new.user_id,new.subject,new.scopes,new.claims,new.claims_locales,
        new.authorization_details,new.resources,new.actor_chain,new.parent_grant_id,
        new.authenticated_at,new.acr,new.amr)
       is distinct from
       (old.client_id,old.user_id,old.subject,old.scopes,old.claims,old.claims_locales,
        old.authorization_details,old.resources,old.actor_chain,old.parent_grant_id,
        old.authenticated_at,old.acr,old.amr)
       or (new.session_id is distinct from old.session_id and not attested_lookup_move) then
        new.authority_revision := gen_random_uuid();
    elsif new.authority_revision is distinct from old.authority_revision then
        raise exception 'grant authority generation is server owned' using errcode = '23514';
    end if;
    return new;
end;
$$;
create trigger grants_protect_authority_revision before update on grants
    for each row execute function protect_grant_authority_revision();
