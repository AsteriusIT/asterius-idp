-- A rotated lookup digest still identifies the same public session and RP
-- participants. Preserve logout lineage while invalidating pending ceremonies.
alter table session_clients drop constraint session_clients_tenant_id_session_id_fkey;
alter table session_clients add foreign key (tenant_id,session_id)
    references sessions(tenant_id,session_id) on update cascade on delete cascade;

create function invalidate_enrolment_on_session_rotation() returns trigger language plpgsql as $$
begin
    if new.session_id is distinct from old.session_id then
        delete from passkey_enrolments where tenant_id=old.tenant_id and session_id=old.session_id;
    end if;
    return new;
end $$;
create trigger session_rotation_invalidates_enrolment before update of session_id on sessions
    for each row execute function invalidate_enrolment_on_session_rotation();
