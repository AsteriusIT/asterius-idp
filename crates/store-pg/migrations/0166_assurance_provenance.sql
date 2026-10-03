-- auth_time may advance when only one part of a cumulative session is proved.
-- Keep the age and meaning of class evidence separately. Existing sessions and
-- grants receive no inferred provenance from their historical AMR.
create table session_assurance_proofs (
    tenant_id text not null,
    session_id text not null,
    acr text,
    assurance_authenticated_at timestamptz not null,
    assurance_policy_revision text not null check (assurance_policy_revision ~ '^[0-9a-f]{64}$'),
    assurance_methods text[] not null check (cardinality(assurance_methods) between 1 and 16),
    primary key (tenant_id, session_id),
    foreign key (tenant_id, session_id) references sessions on update cascade on delete cascade
);
create table grant_assurance_proofs (
    tenant_id text not null,
    grant_id uuid not null,
    authenticated_at timestamptz not null,
    acr text,
    amr text[] not null,
    assurance_authenticated_at timestamptz not null check (assurance_authenticated_at <= authenticated_at),
    assurance_policy_revision text not null check (assurance_policy_revision ~ '^[0-9a-f]{64}$'),
    assurance_methods text[] not null check (cardinality(assurance_methods) between 1 and 16),
    primary key (tenant_id, grant_id),
    foreign key (tenant_id, grant_id) references grants on delete cascade
);

-- Capture only the exact verified source tuple in the same grant transaction.
-- Retained proof survives session cleanup; refresh cannot replace its clock.
create function capture_grant_assurance_proof() returns trigger language plpgsql as $$
begin
    if tg_op = 'UPDATE' and (new.session_id,new.user_id,new.authenticated_at,new.acr,new.amr)
        is not distinct from (old.session_id,old.user_id,old.authenticated_at,old.acr,old.amr) then
        return new;
    end if;
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
    return new;
end $$;
create trigger grants_capture_assurance_proof after insert or update of session_id,user_id,authenticated_at,acr,amr on grants
    for each row execute function capture_grant_assurance_proof();
