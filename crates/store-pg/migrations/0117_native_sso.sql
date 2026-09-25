-- OpenID Native SSO draft-07: opaque, random device credentials are stored
-- only by digest and bound to one user, source client, and live session.
create table native_sso_secrets (
    tenant_id text not null,
    secret_digest bytea not null,
    source_client_id text not null,
    source_grant_id uuid not null,
    user_id uuid not null,
    public_sid text not null,
    expires_at timestamptz not null,
    revoked_at timestamptz,
    created_at timestamptz not null default now(),
    primary key (tenant_id, secret_digest),
    foreign key (tenant_id, source_client_id)
        references clients (tenant_id, client_id) on delete cascade,
    foreign key (tenant_id, source_grant_id)
        references grants (tenant_id, grant_id) on delete cascade,
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    foreign key (tenant_id, public_sid)
        references sessions (tenant_id, public_sid) on delete cascade
);

create index native_sso_secrets_by_session
    on native_sso_secrets (tenant_id, public_sid)
    where revoked_at is null;

-- Derived grants are linked by the same stable sid; the originating grant's
-- session_id may rotate but public_sid never does.
create table native_sso_derivations (
    tenant_id text not null,
    grant_id uuid not null,
    public_sid text not null,
    source_grant_id uuid not null,
    created_at timestamptz not null default now(),
    primary key (tenant_id, grant_id),
    foreign key (tenant_id, grant_id)
        references grants (tenant_id, grant_id) on delete cascade,
    foreign key (tenant_id, source_grant_id)
        references grants (tenant_id, grant_id) on delete cascade,
    foreign key (tenant_id, public_sid)
        references sessions (tenant_id, public_sid) on delete cascade
);

create index native_sso_derivations_by_session
    on native_sso_derivations (tenant_id, public_sid);

-- Every session revocation path (browser logout, account sessions, password
-- reset, administrative withdrawal) reaches this trigger. The withdrawal is
-- in the same transaction as the session state change, independent of the
-- generic offline_access logout setting.
create function native_sso_withdraw_session() returns trigger language plpgsql as $$
begin
    update native_sso_secrets n
       set revoked_at = coalesce(n.revoked_at, now())
     where n.tenant_id = old.tenant_id and n.public_sid = old.public_sid;
    update refresh_tokens r
       set revoked_at = coalesce(r.revoked_at, now())
      from native_sso_derivations d
     where d.tenant_id = old.tenant_id and d.public_sid = old.public_sid
       and r.tenant_id = d.tenant_id and r.grant_id = d.grant_id;
    insert into access_token_cutoffs
        (tenant_id, principal_kind, principal_id, revoked_before, expires_at)
    select d.tenant_id, 'grant', d.grant_id::text, now(), now() + interval '15 minutes'
      from native_sso_derivations d
     where d.tenant_id = old.tenant_id and d.public_sid = old.public_sid
    on conflict (tenant_id, principal_kind, principal_id) do update
        set revoked_before = greatest(access_token_cutoffs.revoked_before, excluded.revoked_before),
            expires_at = greatest(access_token_cutoffs.expires_at, excluded.expires_at);
    update grants g
       set revoked_at = coalesce(g.revoked_at, now()),
           revocation_reason = coalesce(g.revocation_reason, 'session_ended')
      from native_sso_derivations d
     where d.tenant_id = old.tenant_id and d.public_sid = old.public_sid
       and g.tenant_id = d.tenant_id and g.grant_id = d.grant_id;
    if TG_OP = 'DELETE' then
        return old;
    end if;
    return new;
end;
$$;

create trigger native_sso_session_revoked
    after update of revoked_at on sessions
    for each row when (old.revoked_at is null and new.revoked_at is not null)
    execute function native_sso_withdraw_session();

create trigger native_sso_session_deleted
    before delete on sessions
    for each row execute function native_sso_withdraw_session();

-- A source grant can be withdrawn without ending the browser session.
create function native_sso_withdraw_source_grant() returns trigger language plpgsql as $$
begin
    update native_sso_secrets n
       set revoked_at = coalesce(n.revoked_at, now())
     where n.tenant_id = new.tenant_id and n.source_grant_id = new.grant_id;
    update refresh_tokens r
       set revoked_at = coalesce(r.revoked_at, now())
      from native_sso_derivations d
     where d.tenant_id = new.tenant_id and d.source_grant_id = new.grant_id
       and r.tenant_id = d.tenant_id and r.grant_id = d.grant_id;
    insert into access_token_cutoffs
        (tenant_id, principal_kind, principal_id, revoked_before, expires_at)
    select d.tenant_id, 'grant', d.grant_id::text, now(), now() + interval '15 minutes'
      from native_sso_derivations d
     where d.tenant_id = new.tenant_id and d.source_grant_id = new.grant_id
    on conflict (tenant_id, principal_kind, principal_id) do update
        set revoked_before = greatest(access_token_cutoffs.revoked_before, excluded.revoked_before),
            expires_at = greatest(access_token_cutoffs.expires_at, excluded.expires_at);
    update grants g
       set revoked_at = coalesce(g.revoked_at, now()),
           revocation_reason = coalesce(g.revocation_reason, 'session_ended')
      from native_sso_derivations d
     where d.tenant_id = new.tenant_id and d.source_grant_id = new.grant_id
       and g.tenant_id = d.tenant_id and g.grant_id = d.grant_id;
    return new;
end;
$$;

create trigger native_sso_source_grant_revoked
    after update of revoked_at on grants
    for each row when (old.revoked_at is null and new.revoked_at is not null)
    execute function native_sso_withdraw_source_grant();

-- RFC 7009 withdrawal of the source refresh token also ends the SSO link,
-- even though the source authorization grant itself may remain active.
create trigger native_sso_source_refresh_revoked
    after update of revoked_at on refresh_tokens
    for each row when (old.revoked_at is null and new.revoked_at is not null)
    execute function native_sso_withdraw_source_grant();
