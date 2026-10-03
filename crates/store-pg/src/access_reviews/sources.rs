//! Standing provenance is selected by a closed domain enum, never SQL from a request.

use asterius_domain::access_reviews::Target;
use asterius_domain::{DomainError, TenantId, UserId};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::error::to_domain_error;

/// Locks current administrative authority until the governance transaction commits.
pub(super) async fn active_admin(
    connection: &mut PgConnection,
    tenant: &TenantId,
    user: UserId,
) -> Result<(), DomainError> {
    let held: Option<Uuid> = sqlx::query_scalar(
        "select u.user_id from users u join user_roles r using(tenant_id,user_id)
         where u.tenant_id=$1 and u.user_id=$2 and u.status='active' and r.role='tenant_admin'
         for share of u,r",
    )
    .bind(tenant.as_str())
    .bind(user.as_uuid())
    .fetch_optional(connection)
    .await
    .map_err(to_domain_error)?;
    if held.is_none() {
        return Err(DomainError::Conflict("current active tenant administrator is required".into()));
    }
    Ok(())
}

pub(super) fn group(target: &Target) -> Option<Uuid> {
    match target {
        Target::Membership { group_id, .. }
        | Target::GroupTenantRole { group_id, .. }
        | Target::GroupClientRole { group_id, .. } => Some(*group_id),
        Target::UserTenantRole { .. } | Target::UserClientRole { .. } => None,
    }
}

/// Shared declarative lock order protects parent ownership and absent-row writers.
pub(super) async fn lock(
    connection: &mut PgConnection,
    tenant: &TenantId,
    target: &Target,
) -> Result<Option<Uuid>, DomainError> {
    target.validate()?;
    if let Some(group) = group(target) {
        sqlx::query("select declarative_lock($1,'group',$2)")
            .bind(tenant.as_str()).bind(json!([group])).execute(&mut *connection)
            .await.map_err(to_domain_error)?;
        let present: Option<Uuid> = sqlx::query_scalar(
            "select group_id from managed_groups where tenant_id=$1 and group_id=$2 for update",
        ).bind(tenant.as_str()).bind(group).fetch_optional(&mut *connection)
            .await.map_err(to_domain_error)?;
        if present.is_none() { return Ok(None); }
    }
    if matches!(target, Target::Membership { .. }) {
        sqlx::query("select declarative_lock($1,'membership',$2)")
            .bind(tenant.as_str()).bind(json!(target.keys())).execute(&mut *connection)
            .await.map_err(to_domain_error)?;
    }
    // Every statement is literal and every value is bound; the key shape cannot
    // be replaced by a caller-selected relation, predicate or column.
    let row = match target {
        Target::Membership { group_id, user_id } => sqlx::query_scalar(
            "select governance_generation from group_memberships where tenant_id=$1 and group_id=$2 and user_id=$3 for update",
        ).bind(tenant.as_str()).bind(group_id).bind(user_id).fetch_optional(connection).await,
        Target::UserTenantRole { user_id, name } => sqlx::query_scalar(
            "select governance_generation from user_tenant_roles where tenant_id=$1 and user_id=$2 and name=$3 for update",
        ).bind(tenant.as_str()).bind(user_id).bind(name).fetch_optional(connection).await,
        Target::UserClientRole { user_id, client_id, name } => sqlx::query_scalar(
            "select governance_generation from user_client_roles where tenant_id=$1 and user_id=$2 and client_id=$3 and name=$4 for update",
        ).bind(tenant.as_str()).bind(user_id).bind(client_id).bind(name).fetch_optional(connection).await,
        Target::GroupTenantRole { group_id, name } => sqlx::query_scalar(
            "select governance_generation from group_tenant_roles where tenant_id=$1 and group_id=$2 and name=$3 for update",
        ).bind(tenant.as_str()).bind(group_id).bind(name).fetch_optional(connection).await,
        Target::GroupClientRole { group_id, client_id, name } => sqlx::query_scalar(
            "select governance_generation from group_client_roles where tenant_id=$1 and group_id=$2 and client_id=$3 and name=$4 for update",
        ).bind(tenant.as_str()).bind(group_id).bind(client_id).bind(name).fetch_optional(connection).await,
    };
    row.map_err(to_domain_error)
}

/// Protection is rechecked under the same parent advisory lock used to claim it.
pub(super) async fn protected(
    connection: &mut PgConnection,
    tenant: &TenantId,
    target: &Target,
) -> Result<bool, DomainError> {
    let Some(group) = group(target) else { return Ok(false); };
    let protected: bool = sqlx::query_scalar(
        "select exists(select 1 from scim_group_owners where tenant_id=$1 and group_id=$2)
         or exists(select 1 from flow_resource_links where tenant_id=$1 and resource_kind='group'
                   and resource_id=$2::text and relation='managed')
         or exists(select 1 from declarative_owners where tenant_id=$1 and kind='group'
                   and keys=jsonb_build_array($2::text) and owner is not null)
         or ($4::boolean and exists(select 1 from declarative_owners where tenant_id=$1 and kind='membership'
                   and keys=$3 and owner is not null))",
    ).bind(tenant.as_str()).bind(group).bind(json!(target.keys()))
        .bind(matches!(target,Target::Membership { .. }))
        .fetch_one(connection).await.map_err(to_domain_error)?;
    Ok(protected)
}

/// All standing sources remain separate so the review cannot imply union-wide revocation.
pub(super) async fn standing_for_user(
    connection: &mut PgConnection,
    tenant: &TenantId,
    user: Uuid,
) -> Result<Vec<Value>, DomainError> {
    let rows = sqlx::query(
        "select null::text client_id,name,null::uuid group_id from user_tenant_roles where tenant_id=$1 and user_id=$2
         union all select client_id,name,null::uuid from user_client_roles where tenant_id=$1 and user_id=$2
         union all select null::text,r.name,r.group_id from group_memberships m
           join group_tenant_roles r using(tenant_id,group_id) where m.tenant_id=$1 and m.user_id=$2
         union all select r.client_id,r.name,r.group_id from group_memberships m
           join group_client_roles r using(tenant_id,group_id) where m.tenant_id=$1 and m.user_id=$2
         order by client_id nulls first,name,group_id nulls first limit 501",
    ).bind(tenant.as_str()).bind(user).fetch_all(connection).await.map_err(to_domain_error)?;
    if rows.len() > 500 {
        return Err(DomainError::Conflict("effective provenance exceeds the bounded review snapshot".into()));
    }
    rows.into_iter().map(|row| {
        let client: Option<String> = row.try_get("client_id").map_err(to_domain_error)?;
        let name: String = row.try_get("name").map_err(to_domain_error)?;
        let group: Option<Uuid> = row.try_get("group_id").map_err(to_domain_error)?;
        Ok(json!({"client_id":client,"name":name,"group_id":group}))
    }).collect()
}

/// Calls existing lifecycle commands and leaves unrelated effective sources intact.
pub(super) async fn withdraw(
    connection: &mut PgConnection,
    tenant: &TenantId,
    target: &Target,
    now: time::OffsetDateTime,
) -> Result<bool, DomainError> {
    use asterius_domain::{ClientId, GroupId, RoleName, RoleOwner};
    use crate::{PgApplicationRoles, PgGroups};
    let parse = |name: &str| RoleName::parse(name)
        .map_err(|error| DomainError::invalid("name", error.to_string()));
    match target {
        Target::Membership { group_id, user_id } => PgGroups::remove_member_on(
            connection, tenant, GroupId::from_uuid(*group_id), UserId::new(*user_id), now,
        ).await,
        Target::UserTenantRole { user_id, name } => PgApplicationRoles::withdraw_on(
            connection, tenant, UserId::new(*user_id), &RoleOwner::Tenant, &parse(name)?,
        ).await,
        Target::UserClientRole { user_id, client_id, name } => PgApplicationRoles::withdraw_on(
            connection, tenant, UserId::new(*user_id), &RoleOwner::Client(ClientId::new(client_id)), &parse(name)?,
        ).await,
        Target::GroupTenantRole { group_id, name } => PgApplicationRoles::withdraw_group_on(
            connection, tenant, GroupId::from_uuid(*group_id), &RoleOwner::Tenant, &parse(name)?,
        ).await,
        Target::GroupClientRole { group_id, client_id, name } => PgApplicationRoles::withdraw_group_on(
            connection, tenant, GroupId::from_uuid(*group_id), &RoleOwner::Client(ClientId::new(client_id)), &parse(name)?,
        ).await,
    }
}

/// Any concurrent group membership edit invalidates a group-role review too:
/// otherwise removing its unchanged role row would also affect a new member.
pub(super) async fn context_fingerprint(
    connection: &mut PgConnection,
    tenant: &TenantId,
    target: &Target,
) -> Result<Value, DomainError> {
    let group_state: Option<Value> = if let Some(group) = group(target) {
        sqlx::query_scalar(
            "select jsonb_build_object('group_revision',g.revision,'incarnation',d.incarnation,'provenance_revision',d.revision)
             from managed_groups g left join declarative_owners d on d.tenant_id=g.tenant_id
               and d.kind='group' and d.keys=jsonb_build_array(g.group_id::text)
             where g.tenant_id=$1 and g.group_id=$2",
        ).bind(tenant.as_str()).bind(group).fetch_optional(&mut *connection).await.map_err(to_domain_error)?
    } else { None };
    let catalogue: Option<Value> = match target {
        Target::Membership { .. } => None,
        Target::UserTenantRole { name, .. } | Target::GroupTenantRole { name, .. } => sqlx::query_scalar(
            "select jsonb_build_object('name',name,'description',description,'created_at',created_at) from tenant_roles where tenant_id=$1 and name=$2 for share",
        ).bind(tenant.as_str()).bind(name).fetch_optional(&mut *connection).await.map_err(to_domain_error)?,
        Target::UserClientRole { client_id, name, .. } | Target::GroupClientRole { client_id, name, .. } => sqlx::query_scalar(
            "select jsonb_build_object('name',r.name,'description',r.description,'created_at',r.created_at,'client_status',c.status)
             from client_roles r join clients c using(tenant_id,client_id) where r.tenant_id=$1 and r.client_id=$2 and r.name=$3 for share of r,c",
        ).bind(tenant.as_str()).bind(client_id).bind(name).fetch_optional(&mut *connection).await.map_err(to_domain_error)?,
    };
    let account_state:Value=match target {
        Target::Membership {user_id,..}|Target::UserTenantRole {user_id,..}|Target::UserClientRole {user_id,..}=>
            sqlx::query_scalar("select jsonb_build_object('status',status,'updated_at',updated_at) from users where tenant_id=$1 and user_id=$2 for share")
                .bind(tenant.as_str()).bind(user_id).fetch_one(&mut *connection).await.map_err(to_domain_error)?,
        Target::GroupTenantRole {group_id,..}|Target::GroupClientRole {group_id,..}=>{
            let rows:Vec<Value>=sqlx::query_scalar("select jsonb_build_object('user_id',u.user_id,'status',u.status,'updated_at',u.updated_at) from users u join group_memberships m using(tenant_id,user_id) where m.tenant_id=$1 and m.group_id=$2 order by u.user_id limit 101 for share of u")
                .bind(tenant.as_str()).bind(group_id).fetch_all(&mut *connection).await.map_err(to_domain_error)?;
            if rows.len()>100 {return Err(DomainError::Conflict("group exceeds the bounded hundred-user review snapshot".into()));}
            json!(rows)
        }
    };
    Ok(json!({"group":group_state,"catalogue":catalogue,"accounts":account_state}))
}
