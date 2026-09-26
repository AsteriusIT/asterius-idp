-- JARM §3 and FAPI Message Signing §5.3.3 client registration metadata.
alter table clients
    add column authorization_signed_response_alg text
        check (authorization_signed_response_alg in ('EdDSA', 'ES256', 'PS256')),
    add column response_modes text[]
        check (response_modes is null or
               (cardinality(response_modes) between 1 and 5 and
                array_position(response_modes, null) is null and
                response_modes <@ array['query', 'form_post', 'query.jwt', 'jwt', 'form_post.jwt']::text[]));

-- The existing CIMD immutability trigger predates these columns.
create function reject_cimd_fapi_metadata_change() returns trigger language plpgsql as $$
begin
    if old.client_id like 'https://%' and old.compliance_profile = 'public' and (
        new.authorization_signed_response_alg is distinct from old.authorization_signed_response_alg or
        new.response_modes is distinct from old.response_modes
    ) then
        raise exception 'CIMD client registration is immutable';
    end if;
    return new;
end;
$$;

create trigger clients_reject_cimd_fapi_metadata_change
    before update on clients
    for each row execute function reject_cimd_fapi_metadata_change();
