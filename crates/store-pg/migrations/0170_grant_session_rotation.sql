-- Private exact-session lineage permits cookie fixation defence to move grant
-- lookup references without refreshing the original assurance clock. No raw
-- cookie is retained or released; lookup_digest is the existing SHA256 lookup.
create table grant_session_lineage (
    tenant_id text not null,
    grant_id uuid not null,
    user_id uuid not null,
    public_sid text not null,
    lookup_digest text not null,
    primary key(tenant_id,grant_id),
    foreign key(tenant_id,grant_id) references grants on delete cascade,
    foreign key(tenant_id,public_sid) references sessions(tenant_id,public_sid) on delete cascade
);

-- Backfill only currently provable exact tuples, never infer from another
-- session for this user or invent lineage for already orphaned old digests.
insert into grant_session_lineage(tenant_id,grant_id,user_id,public_sid,lookup_digest)
select g.tenant_id,g.grant_id,g.user_id,s.public_sid,s.session_id
  from grants g join sessions s on s.tenant_id=g.tenant_id and s.session_id=g.session_id
   and s.user_id=g.user_id and s.authenticated_at=g.authenticated_at
   and s.acr is not distinct from g.acr and s.amr=g.amr;

create or replace function capture_grant_assurance_proof() returns trigger language plpgsql as $$
begin
    if tg_op = 'UPDATE' and (new.session_id,new.user_id,new.authenticated_at,new.acr,new.amr)
        is not distinct from (old.session_id,old.user_id,old.authenticated_at,old.acr,old.amr) then
        return new;
    end if;
    -- Only a previously attested exact stable session can justify moving a
    -- lookup digest without replacing the grant's original proof. Another
    -- same-user session or a caller's arbitrary reassignment cannot qualify.
    if tg_op = 'UPDATE' and new.session_id is distinct from old.session_id
       and (new.user_id,new.authenticated_at,new.acr,new.amr)
           is not distinct from (old.user_id,old.authenticated_at,old.acr,old.amr)
       and exists (
           select 1 from grant_session_lineage l join sessions s
             on s.tenant_id=l.tenant_id and s.public_sid=l.public_sid and s.user_id=l.user_id
           where l.tenant_id=new.tenant_id and l.grant_id=new.grant_id
             and l.user_id=new.user_id and l.lookup_digest=old.session_id
             and s.session_id=new.session_id and s.revoked_at is null
             and s.expires_at>clock_timestamp() and s.idle_expires_at>clock_timestamp()
       ) then
        update grant_session_lineage set lookup_digest=new.session_id
            where tenant_id=new.tenant_id and grant_id=new.grant_id;
        return new;
    end if;
    if tg_op = 'UPDATE' and new.session_id is distinct from old.session_id
       and (new.user_id,new.authenticated_at,new.acr,new.amr)
           is not distinct from (old.user_id,old.authenticated_at,old.acr,old.amr) then
        -- A failed lineage check is not a fresh authentication, even if another
        -- session happens to carry the same authentication tuple.
        delete from grant_session_lineage where tenant_id=new.tenant_id and grant_id=new.grant_id;
        delete from grant_assurance_proofs where tenant_id=new.tenant_id and grant_id=new.grant_id;
        return new;
    end if;
    delete from grant_session_lineage where tenant_id=new.tenant_id and grant_id=new.grant_id;
    delete from grant_assurance_proofs where tenant_id = new.tenant_id and grant_id = new.grant_id;
    insert into grant_assurance_proofs
        (tenant_id,grant_id,authenticated_at,acr,amr,assurance_authenticated_at,assurance_policy_revision,assurance_methods)
    select new.tenant_id,new.grant_id,new.authenticated_at,new.acr,new.amr,
           p.assurance_authenticated_at,p.assurance_policy_revision,p.assurance_methods
      from sessions s join session_assurance_proofs p using(tenant_id,session_id)
     where s.tenant_id = new.tenant_id and s.session_id = new.session_id
       and s.user_id = new.user_id and s.authenticated_at = new.authenticated_at
       and s.acr is not distinct from new.acr and s.amr = new.amr
       and p.acr is not distinct from s.acr
       and p.assurance_authenticated_at <= s.authenticated_at;
    if not found and new.parent_grant_id is not null then
        insert into grant_assurance_proofs
            (tenant_id,grant_id,authenticated_at,acr,amr,assurance_authenticated_at,assurance_policy_revision,assurance_methods)
        select new.tenant_id,new.grant_id,new.authenticated_at,new.acr,new.amr,
               p.assurance_authenticated_at,p.assurance_policy_revision,p.assurance_methods
          from grants g join grant_assurance_proofs p using(tenant_id,grant_id)
         where g.tenant_id = new.tenant_id and g.grant_id = new.parent_grant_id
           and g.user_id = new.user_id and g.authenticated_at = new.authenticated_at
           and g.acr is not distinct from new.acr and g.amr = new.amr
           and p.authenticated_at = g.authenticated_at
           and p.acr is not distinct from g.acr and p.amr = g.amr;
    end if;
    -- Capture lineage only from the original exact verified source tuple.
    insert into grant_session_lineage(tenant_id,grant_id,user_id,public_sid,lookup_digest)
    select new.tenant_id,new.grant_id,new.user_id,s.public_sid,s.session_id
      from sessions s where s.tenant_id=new.tenant_id and s.session_id=new.session_id
       and s.user_id=new.user_id and s.authenticated_at=new.authenticated_at
       and s.acr is not distinct from new.acr and s.amr=new.amr;
    return new;
end $$;
