-- OpenID Connect Enterprise Extensions defines session_expiry as an OP-issued
-- RP session deadline. Older tenants could store this name as a user claim.
-- Preserve every legacy value for operator-led review while making all user
-- rows readable after ClaimName reserves the namespace. The archive follows
-- account deletion so a deleted user's old attributes are not retained.
create table legacy_session_expiry_claims (
    tenant_id text not null,
    user_id uuid not null,
    claim_name text not null,
    claim_value jsonb not null,
    archived_at timestamptz not null default now(),
    primary key (tenant_id, user_id, claim_name),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade
);

-- Copy and removal must observe one stable set of users. A concurrent claim
-- write during this migration would otherwise escape the archive and make
-- its user row unreadable by the new domain parser.
lock table users in access exclusive mode;

insert into legacy_session_expiry_claims (tenant_id, user_id, claim_name, claim_value)
select users.tenant_id, users.user_id, claim.key, claim.value
from users
cross join lateral jsonb_each(users.claims) as claim(key, value)
where claim.key = 'session_expiry' or claim.key like 'session\_expiry#%' escape '\';

update users
set claims = coalesce((
    select jsonb_object_agg(claim.key, claim.value)
    from jsonb_each(users.claims) as claim(key, value)
    where claim.key <> 'session_expiry'
      and claim.key not like 'session\_expiry#%' escape '\'
), '{}'::jsonb)
where claims ? 'session_expiry'
   or exists (
       select 1 from jsonb_object_keys(users.claims) as name
       where name like 'session\_expiry#%' escape '\'
   );
