use super::records::{ELIGIBILITY, ENTITLEMENT, entitlement, owner};
use super::{
    DomainError, Eligibility, EligibilityChange, Entitlement, EntitlementConfiguration,
    OffsetDateTime, PgConnection, PgTemporaryEntitlements, TenantId, UserId, Uuid, audit,
    current_acr, decode, to_domain_error,
};

impl PgTemporaryEntitlements {
    pub(super) async fn list_configurations(
        &self,
        tenant: &TenantId,
        actor: &UserId,
    ) -> Result<Vec<Entitlement>, DomainError> {
        let sql = format!(
            "{ENTITLEMENT} where e.tenant_id=$1 and e.owner_user_id=$2 order by e.created_at desc,e.entitlement_id limit 100"
        );
        let rows: Vec<(serde_json::Value,)> = sqlx::query_as(&sql)
            .bind(tenant.as_str())
            .bind(actor.as_uuid())
            .fetch_all(&self.pool)
            .await
            .map_err(to_domain_error)?;
        rows.into_iter().map(|r| decode(r.0)).collect()
    }
    pub(super) async fn save_configuration(
        &self,
        tenant: &TenantId,
        actor: &UserId,
        id: Option<Uuid>,
        expected: Option<Uuid>,
        c: EntitlementConfiguration,
    ) -> Result<Entitlement, DomainError> {
        c.validate()?;
        if c.owner_user_id != *actor.as_uuid() {
            return Err(DomainError::NotFound);
        }
        if id.is_some() != expected.is_some() {
            return Err(DomainError::invalid(
                "expected_revision",
                "required exactly for existing configuration",
            ));
        }
        let (mut tx, now) = self.begin(tenant).await?;
        let acr = current_acr(&mut tx, tenant).await?;
        if !acr.can_produce(&c.requester_acr) || !acr.can_produce(&c.approver_acr) {
            return Err(DomainError::invalid(
                "acr",
                "unknown tenant assurance requirement",
            ));
        }
        validate_catalogue(&mut tx, tenant, &c).await?;
        let entitlement_id = id.unwrap_or_else(Uuid::new_v4);
        if let Some(expected) = expected {
            let old = owner(&mut tx, tenant, actor, entitlement_id).await?;
            if old.revision != expected {
                return Err(DomainError::Conflict("entitlement revision changed".into()));
            }
            let oldc = &old.configuration;
            if oldc.client_id != c.client_id
                || oldc.resource != c.resource
                || oldc.role_name != c.role_name
                || oldc.permissions != c.permissions
            {
                return Err(DomainError::invalid(
                    "configuration",
                    "catalogue binding is immutable",
                ));
            }
            sqlx::query("update temporary_entitlements set editor_user_id=$3,requester_acr=$4,approver_acr=$5,max_duration_seconds=$6,max_eligibility_seconds=$7,enabled=$8 where tenant_id=$1 and entitlement_id=$2")
                .bind(tenant.as_str()).bind(entitlement_id).bind(actor.as_uuid()).bind(&c.requester_acr).bind(&c.approver_acr).bind(c.max_duration_seconds).bind(c.max_eligibility_seconds).bind(c.enabled).execute(&mut *tx).await.map_err(to_domain_error)?;
            sqlx::query("delete from temporary_entitlement_approvers where tenant_id=$1 and entitlement_id=$2").bind(tenant.as_str()).bind(entitlement_id).execute(&mut *tx).await.map_err(to_domain_error)?;
        } else {
            sqlx::query("insert into temporary_entitlements(tenant_id,entitlement_id,client_id,resource,role_name,permissions,owner_user_id,owner_reference,client_reference,role_reference,resource_reference,editor_user_id,requester_acr,approver_acr,max_duration_seconds,max_eligibility_seconds,enabled,created_at) values($1,$2,$3,$4,$5,$6,$7,$7,$3,$5,$4,$7,$8,$9,$10,$11,$12,$13)")
                .bind(tenant.as_str()).bind(entitlement_id).bind(&c.client_id).bind(&c.resource).bind(&c.role_name).bind(&c.permissions).bind(actor.as_uuid()).bind(&c.requester_acr).bind(&c.approver_acr).bind(c.max_duration_seconds).bind(c.max_eligibility_seconds).bind(c.enabled).bind(now).execute(&mut *tx).await.map_err(to_domain_error)?;
        }
        for approver in &c.approver_user_ids {
            sqlx::query("insert into temporary_entitlement_approvers(tenant_id,entitlement_id,user_id) values($1,$2,$3)").bind(tenant.as_str()).bind(entitlement_id).bind(approver).execute(&mut *tx).await.map_err(to_domain_error)?;
        }
        audit(
            &mut tx,
            tenant,
            Some(actor),
            "configured",
            entitlement_id,
            now,
        )
        .await?;
        let result = entitlement(&mut tx, tenant, entitlement_id).await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    pub(super) async fn eligibility_list(
        &self,
        tenant: &TenantId,
        actor: &UserId,
        id: Uuid,
    ) -> Result<Vec<Eligibility>, DomainError> {
        let (mut tx, _) = self.begin(tenant).await?;
        owner(&mut tx, tenant, actor, id).await?;
        let sql = format!(
            "{ELIGIBILITY} where e.tenant_id=$1 and e.entitlement_id=$2 order by e.expires_at desc,e.eligibility_id limit 100"
        );
        let rows: Vec<(serde_json::Value,)> = sqlx::query_as(&sql)
            .bind(tenant.as_str())
            .bind(id)
            .fetch_all(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        rows.into_iter().map(|r| decode(r.0)).collect()
    }
    pub(super) async fn eligibility_set(
        &self,
        tenant: &TenantId,
        actor: &UserId,
        id: Uuid,
        c: EligibilityChange,
    ) -> Result<Eligibility, DomainError> {
        let (mut tx, now) = self.begin(tenant).await?;
        let config = owner(&mut tx, tenant, actor, id).await?;
        let start = OffsetDateTime::from_unix_timestamp(c.not_before)
            .map_err(|e| DomainError::invalid("not_before", e.to_string()))?;
        let end = OffsetDateTime::from_unix_timestamp(c.expires_at)
            .map_err(|e| DomainError::invalid("expires_at", e.to_string()))?;
        if end <= now
            || end <= start
            || end - start
                > time::Duration::seconds(i64::from(config.configuration.max_eligibility_seconds))
            || end - now
                > time::Duration::seconds(i64::from(config.configuration.max_eligibility_seconds))
        {
            return Err(DomainError::invalid(
                "eligibility",
                "invalid or excessive interval",
            ));
        }
        let user:Option<(Uuid,)>=sqlx::query_as("select user_id from users where tenant_id=$1 and user_id=$2 and status='active' for share").bind(tenant.as_str()).bind(c.user_id).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if user.is_none() {
            return Err(DomainError::NotFound);
        }
        let existing:Option<(Uuid,Uuid)>=sqlx::query_as("select eligibility_id,revision from temporary_entitlement_eligibility where tenant_id=$1 and entitlement_id=$2 and user_id=$3 and revoked_at is null for update").bind(tenant.as_str()).bind(id).bind(c.user_id).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        let eligibility_id = match (existing, c.expected_revision) {
            (Some((eligibility_id, revision)), Some(expected)) if revision == expected => {
                sqlx::query("update temporary_entitlement_eligibility set editor_user_id=$3,not_before=$4,expires_at=$5 where tenant_id=$1 and eligibility_id=$2").bind(tenant.as_str()).bind(eligibility_id).bind(actor.as_uuid()).bind(start).bind(end).execute(&mut *tx).await.map_err(to_domain_error)?;
                eligibility_id
            }
            (None, None) => {
                let eligibility_id = Uuid::new_v4();
                sqlx::query("insert into temporary_entitlement_eligibility(tenant_id,eligibility_id,entitlement_id,user_id,editor_user_id,not_before,expires_at) values($1,$2,$3,$4,$5,$6,$7)").bind(tenant.as_str()).bind(eligibility_id).bind(id).bind(c.user_id).bind(actor.as_uuid()).bind(start).bind(end).execute(&mut *tx).await.map_err(to_domain_error)?;
                eligibility_id
            }
            _ => return Err(DomainError::Conflict("eligibility revision changed".into())),
        };
        audit(
            &mut tx,
            tenant,
            Some(actor),
            "eligibility_saved",
            eligibility_id,
            now,
        )
        .await?;
        let sql = format!("{ELIGIBILITY} where e.tenant_id=$1 and e.eligibility_id=$2");
        let (value,): (serde_json::Value,) = sqlx::query_as(&sql)
            .bind(tenant.as_str())
            .bind(eligibility_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        decode(value)
    }
    pub(super) async fn eligibility_remove(
        &self,
        tenant: &TenantId,
        actor: &UserId,
        id: Uuid,
        eligibility_id: Uuid,
        expected: Uuid,
    ) -> Result<(), DomainError> {
        let (mut tx, now) = self.begin(tenant).await?;
        owner(&mut tx, tenant, actor, id).await?;
        let changed=sqlx::query("update temporary_entitlement_eligibility set revoked_at=$5,editor_user_id=$6 where tenant_id=$1 and entitlement_id=$2 and eligibility_id=$3 and revision=$4 and revoked_at is null")
            .bind(tenant.as_str()).bind(id).bind(eligibility_id).bind(expected).bind(now).bind(actor.as_uuid()).execute(&mut *tx).await.map_err(to_domain_error)?.rows_affected();
        if changed != 1 {
            return Err(DomainError::Conflict("eligibility revision changed".into()));
        }
        audit(
            &mut tx,
            tenant,
            Some(actor),
            "eligibility_removed",
            eligibility_id,
            now,
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(())
    }
}
async fn validate_catalogue(
    tx: &mut PgConnection,
    tenant: &TenantId,
    c: &EntitlementConfiguration,
) -> Result<(), DomainError> {
    let users:Vec<(Uuid,)>=sqlx::query_as("select user_id from users where tenant_id=$1 and user_id=any($2) and status='active' for share")
        .bind(tenant.as_str()).bind(c.approver_user_ids.iter().copied().chain(std::iter::once(c.owner_user_id)).collect::<Vec<_>>()).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
    if !c
        .approver_user_ids
        .iter()
        .chain(std::iter::once(&c.owner_user_id))
        .all(|id| users.iter().any(|r| &r.0 == id))
    {
        return Err(DomainError::NotFound);
    }
    let client:Option<(String,)>=sqlx::query_as("select client_id from clients where tenant_id=$1 and client_id=$2 and status='active' and not is_agent for share").bind(tenant.as_str()).bind(&c.client_id).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
    let role: Option<(String,)> = sqlx::query_as(
        "select name from client_roles where tenant_id=$1 and client_id=$2 and name=$3 for share",
    )
    .bind(tenant.as_str())
    .bind(&c.client_id)
    .bind(&c.role_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(to_domain_error)?;
    let resource: Option<(Option<Vec<String>>,)> = sqlx::query_as(
        "select scopes from resource_servers where tenant_id=$1 and identifier=$2 for share",
    )
    .bind(tenant.as_str())
    .bind(&c.resource)
    .fetch_optional(tx)
    .await
    .map_err(to_domain_error)?;
    if client.is_none()
        || role.is_none()
        || !resource.is_some_and(|r| {
            r.0.is_none_or(|allowed| c.permissions.iter().all(|s| allowed.contains(s)))
        })
    {
        return Err(DomainError::invalid(
            "catalogue",
            "current client, role and resource permissions required",
        ));
    }
    Ok(())
}
