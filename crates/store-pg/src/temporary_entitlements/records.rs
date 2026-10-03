use super::*;
pub(super) const ENTITLEMENT: &str = "select (to_jsonb(e) - array['tenant_id','owner_reference','client_reference','role_reference','resource_reference']) || jsonb_build_object('created_at',floor(extract(epoch from e.created_at))::bigint,'approver_user_ids',coalesce((select jsonb_agg(a.user_id order by a.user_id) from temporary_entitlement_approvers a where a.tenant_id=e.tenant_id and a.entitlement_id=e.entitlement_id),'[]'::jsonb)) from temporary_entitlements e";
pub(super) const ELIGIBILITY: &str = "select (to_jsonb(e) - 'tenant_id') || jsonb_build_object('not_before',floor(extract(epoch from e.not_before))::bigint,'expires_at',floor(extract(epoch from e.expires_at))::bigint,'revoked_at',floor(extract(epoch from e.revoked_at))::bigint) from temporary_entitlement_eligibility e";
pub(super) const REQUEST: &str = "select (to_jsonb(e) - array['tenant_id','decision_key']) || jsonb_build_object('created_at',floor(extract(epoch from e.created_at))::bigint,'deadline',floor(extract(epoch from e.deadline))::bigint,'decided_at',floor(extract(epoch from e.decided_at))::bigint) from temporary_entitlement_requests e";
pub(super) const ACTIVATION: &str = "select (to_jsonb(e) - 'tenant_id') || jsonb_build_object('status',case when e.revoked_at is not null then 'revoked' when e.expires_at<=clock_timestamp() then 'expired' when not exists(select 1 from temporary_entitlement_requests request join temporary_entitlements config on config.tenant_id=request.tenant_id and config.entitlement_id=request.entitlement_id join temporary_entitlement_eligibility el on el.tenant_id=request.tenant_id and el.eligibility_id=request.eligibility_id join users subject on subject.tenant_id=e.tenant_id and subject.user_id=e.user_id join users owner on owner.tenant_id=config.tenant_id and owner.user_id=config.owner_reference join clients client on client.tenant_id=config.tenant_id and client.client_id=config.client_reference join resource_servers resource on resource.tenant_id=config.tenant_id and resource.identifier=config.resource_reference where request.tenant_id=e.tenant_id and request.request_id=e.request_id and request.status='approved' and config.enabled and config.role_reference is not null and config.revision=request.policy_revision and el.revision=request.eligibility_revision and el.revoked_at is null and el.not_before<=clock_timestamp() and el.expires_at>clock_timestamp() and subject.status='active' and owner.status='active' and client.status='active' and not client.is_agent and (resource.scopes is null or config.permissions<@resource.scopes)) then 'invalidated' else 'active' end,'activated_at',floor(extract(epoch from e.activated_at))::bigint,'expires_at',floor(extract(epoch from e.expires_at))::bigint,'revoked_at',floor(extract(epoch from e.revoked_at))::bigint,'expiry_recorded_at',floor(extract(epoch from e.expiry_recorded_at))::bigint) from temporary_entitlement_activations e";
pub(super) async fn entitlement(
    tx: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
) -> Result<Entitlement, DomainError> {
    let sql = format!("{ENTITLEMENT} where e.tenant_id=$1 and e.entitlement_id=$2");
    let row: Option<(serde_json::Value,)> = sqlx::query_as(&sql)
        .bind(tenant.as_str())
        .bind(id)
        .fetch_optional(tx)
        .await
        .map_err(to_domain_error)?;
    decode(row.ok_or(DomainError::NotFound)?.0)
}
pub(super) async fn request(
    tx: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
) -> Result<EntitlementRequest, DomainError> {
    let sql = format!("{REQUEST} where e.tenant_id=$1 and e.request_id=$2");
    let row: Option<(serde_json::Value,)> = sqlx::query_as(&sql)
        .bind(tenant.as_str())
        .bind(id)
        .fetch_optional(tx)
        .await
        .map_err(to_domain_error)?;
    decode(row.ok_or(DomainError::NotFound)?.0)
}
pub(super) async fn activation(
    tx: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
) -> Result<Activation, DomainError> {
    let sql = format!("{ACTIVATION} where e.tenant_id=$1 and e.activation_id=$2");
    let row: Option<(serde_json::Value,)> = sqlx::query_as(&sql)
        .bind(tenant.as_str())
        .bind(id)
        .fetch_optional(tx)
        .await
        .map_err(to_domain_error)?;
    decode(row.ok_or(DomainError::NotFound)?.0)
}
pub(super) async fn owner(
    tx: &mut PgConnection,
    tenant: &TenantId,
    user: &UserId,
    id: Uuid,
) -> Result<Entitlement, DomainError> {
    let configuration = entitlement(tx, tenant, id).await?;
    let active: Option<(Uuid,)> = sqlx::query_as(
        "select user_id from users where tenant_id=$1 and user_id=$2 and status='active' for share",
    )
    .bind(tenant.as_str())
    .bind(user.as_uuid())
    .fetch_optional(tx)
    .await
    .map_err(to_domain_error)?;
    if configuration.configuration.owner_user_id != *user.as_uuid() || active.is_none() {
        return Err(DomainError::NotFound);
    }
    Ok(configuration)
}
