-- Client classification is administrative authority, never DCR metadata.
create table conditional_client_settings (
    tenant_id text not null,
    client_id text not null,
    sensitivity text check (sensitivity in ('standard', 'sensitive', 'critical')),
    revision uuid not null,
    primary key (tenant_id, client_id),
    foreign key (tenant_id, client_id) references clients(tenant_id, client_id) on delete cascade
);

-- Every policy writer, including declarative automation, must reference actual
-- registered clients. Row locks prevent concurrent delete during publication.
create function validate_conditional_policy_clients() returns trigger language plpgsql as $$
declare
    requested_client text;
    requested_remedy text;
    acr_document jsonb;
begin
    for requested_client in
        select distinct jsonb_array_elements_text(scope->'clients')
        from jsonb_array_elements(coalesce(new.document->'conditional_scopes', '[]'::jsonb)) scope
        order by 1
    loop
        perform 1 from clients where tenant_id = new.tenant_id and client_id = requested_client for key share;
        if not found then
            raise exception 'conditional scope references an unregistered client' using errcode = '23514';
        end if;
    end loop;
    select settings->'options'->'acr_policy' into acr_document from tenants where tenant_id=new.tenant_id;
    -- Missing/null settings use AcrPolicy::default(), including legacy rows.
    -- Explicit custom ladders never inherit these aliases.
    if acr_document is null or acr_document = 'null'::jsonb then
        acr_document := '{"levels":[{"value":"urn:asterius:acr:pwd"},{"value":"phr"},{"value":"urn:asterius:acr:passkey"},{"value":"urn:asterius:acr:passkey-uv"}]}'::jsonb;
    end if;
    for requested_remedy in
        select distinct scope->>'assurance_remedy'
        from jsonb_array_elements(coalesce(new.document->'conditional_scopes', '[]'::jsonb)) scope
        where scope->>'assurance_remedy' is not null
    loop
        if not exists(select 1 from jsonb_array_elements(coalesce(acr_document->'levels','[]'::jsonb)) level where level->>'value'=requested_remedy) then
            raise exception 'conditional remedy references an unsupported assurance level' using errcode='23514';
        end if;
    end loop;
    return new;
end;
$$;
create trigger conditional_policy_clients before insert or update of document on tenant_policies
for each row execute function validate_conditional_policy_clients();

-- All policy publication paths, including declarative ownership and deletion,
-- share a tenant fence with final issuance. A reader holding FOR SHARE sees
-- either the complete old publication before its signature or the new one.
create function fence_tenant_policy_publication() returns trigger language plpgsql as $$
begin
    perform 1 from tenants where tenant_id = coalesce(new.tenant_id, old.tenant_id) for no key update;
    if tg_op = 'DELETE' then return old; end if;
    return new;
end;
$$;
create trigger a_conditional_policy_publication_fence before insert or update or delete on tenant_policies
for each row execute function fence_tenant_policy_publication();
