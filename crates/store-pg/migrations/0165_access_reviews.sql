-- Standing-access review snapshots never confer new access.
-- A new row generation detects deletion/recreation even when logical keys match.
alter table group_memberships add column governance_generation uuid not null default gen_random_uuid();
alter table user_tenant_roles add column governance_generation uuid not null default gen_random_uuid();
alter table user_client_roles add column governance_generation uuid not null default gen_random_uuid();
alter table group_tenant_roles add column governance_generation uuid not null default gen_random_uuid();
alter table group_client_roles add column governance_generation uuid not null default gen_random_uuid();

create function governance_assignment_generation() returns trigger language plpgsql as $$
begin
    -- Ordinary writers cannot carry an old review's generation across an edit.
    new.governance_generation := gen_random_uuid();
    return new;
end
$$;
create trigger governance_membership_generation before insert or update on group_memberships
for each row execute function governance_assignment_generation();
create trigger governance_user_tenant_generation before insert or update on user_tenant_roles
for each row execute function governance_assignment_generation();
create trigger governance_user_client_generation before insert or update on user_client_roles
for each row execute function governance_assignment_generation();
create trigger governance_group_tenant_generation before insert or update on group_tenant_roles
for each row execute function governance_assignment_generation();
create trigger governance_group_client_generation before insert or update on group_client_roles
for each row execute function governance_assignment_generation();

create table governance_ownerships (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    ownership_id uuid not null,
    target_kind text not null check(target_kind in ('membership','user_tenant_role','user_client_role','group_tenant_role','group_client_role')),
    target_keys jsonb not null check(jsonb_typeof(target_keys)='array' and jsonb_array_length(target_keys) between 2 and 3),
    owner_user_id uuid,
    reviewers uuid[] not null check(cardinality(reviewers) between 1 and 20 and array_position(reviewers,null) is null),
    revision uuid not null default gen_random_uuid(),
    enabled boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key(tenant_id,ownership_id),
    unique(tenant_id,target_kind,target_keys),
    foreign key(tenant_id,owner_user_id) references users(tenant_id,user_id) on delete set null(owner_user_id)
);

-- FK-driven owner deletion also invalidates every pending snapshot.
create function governance_ownership_revision() returns trigger language plpgsql as $$
begin
    new.revision := gen_random_uuid();
    new.updated_at := transaction_timestamp();
    return new;
end
$$;
create trigger governance_ownership_revision before update on governance_ownerships
for each row execute function governance_ownership_revision();

create table governance_reviews (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    review_id uuid not null,
    created_by uuid not null,
    created_at timestamptz not null default now(),
    due_at timestamptz not null check(due_at > created_at),
    completed_at timestamptz,
    cancelled_at timestamptz,
    primary key(tenant_id,review_id),
    check(completed_at is null or cancelled_at is null)
);

create table governance_review_items (
    tenant_id text not null,
    review_id uuid not null,
    item_id uuid not null,
    ownership_id uuid not null,
    ownership_revision uuid not null,
    target_kind text not null,
    target_keys jsonb not null,
    assignment_generation uuid not null,
    assigned_reviewer uuid not null,
    snapshot jsonb not null check(jsonb_typeof(snapshot)='object'),
    decision text check(decision in ('retain','remove')),
    decided_by uuid,
    decided_at timestamptz,
    reason text check(length(reason) between 1 and 1000),
    apply_status text not null default 'pending' check(apply_status in ('pending','retained','removed','absent','conflict','protected')),
    applied_by uuid,
    applied_at timestamptz,
    primary key(tenant_id,review_id,item_id),
    unique(tenant_id,review_id,ownership_id),
    foreign key(tenant_id,review_id) references governance_reviews(tenant_id,review_id) on delete cascade,
    -- Historical references intentionally survive target/config/user deletion.
    check((decision is null and decided_by is null and decided_at is null and reason is null)
       or (decision is not null and decided_by is not null and decided_at is not null and reason is not null)),
    check((apply_status='pending' and applied_by is null and applied_at is null)
       or (apply_status<>'pending' and applied_by is not null and applied_at is not null))
);
create index governance_reviews_due on governance_reviews(tenant_id,due_at,review_id);
create index governance_items_reviewer on governance_review_items(tenant_id,assigned_reviewer,review_id,item_id);
