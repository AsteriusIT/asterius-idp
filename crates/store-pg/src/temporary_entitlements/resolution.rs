use super::*;
use asterius_domain::{ClientId, Grant, RoleName};
impl PgTemporaryEntitlements {
    pub(super) async fn resolve(
        &self,
        tenant: &TenantId,
        grant: &Grant,
    ) -> Result<TemporaryRoleSnapshot, DomainError> {
        // A read must coexist with the signer's outer SHARE publication fence;
        // requesting a writer fence here would deadlock that composition.
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let anchor: Option<(String,)> = sqlx::query_as(
            "select tenant_id from tenants where tenant_id=$1 and status='active' for share",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if anchor.is_none() {
            return Err(DomainError::NotFound);
        }
        let (now,): (OffsetDateTime,) = sqlx::query_as("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let mut snapshot = TemporaryRoleSnapshot {
            observed_at: now,
            roles: Vec::new(),
        };
        if grant.tenant != *tenant
            || grant.resources.len() != 1
            || !grant.actor_chain.is_empty()
            || grant.task.is_some()
            || grant.parent.is_some()
            || !grant.status(now).may_issue()
        {
            return Ok(snapshot);
        }
        let (Some(user), Some(auth)) = (&grant.user, &grant.authentication) else {
            return Ok(snapshot);
        };
        let Some(proved_at) = auth.assurance_authenticated_at else {
            return Ok(snapshot);
        };
        let age = now - proved_at;
        if age.is_negative() || age > time::Duration::seconds(120) {
            return Ok(snapshot);
        }
        let resource =
            grant.resources.iter().next().ok_or_else(|| {
                DomainError::invalid("resources", "exactly one resource required")
            })?;
        let permissions: Vec<_> = grant.scopes.iter().cloned().collect();
        let rows:Vec<(Uuid,Uuid,String,String,OffsetDateTime,String,Uuid,Uuid,Vec<String>)> = sqlx::query_as("select a.activation_id,e.entitlement_id,e.client_id,e.role_name,a.expires_at,e.requester_acr,e.revision,el.revision,e.permissions from temporary_entitlement_activations a join temporary_entitlement_requests r on r.tenant_id=a.tenant_id and r.request_id=a.request_id join temporary_entitlements e on e.tenant_id=r.tenant_id and e.entitlement_id=r.entitlement_id join temporary_entitlement_eligibility el on el.tenant_id=r.tenant_id and el.eligibility_id=r.eligibility_id join users u on u.tenant_id=a.tenant_id and u.user_id=a.user_id join users o on o.tenant_id=e.tenant_id and o.user_id=e.owner_reference join clients c on c.tenant_id=e.tenant_id and c.client_id=e.client_reference join client_roles role on role.tenant_id=e.tenant_id and role.client_id=e.client_reference and role.name=e.role_reference join resource_servers rs on rs.tenant_id=e.tenant_id and rs.identifier=e.resource_reference where a.tenant_id=$1 and a.user_id=$2 and e.client_id=$3 and e.resource=$4 and e.permissions<@$5 and e.enabled and e.revision=r.policy_revision and el.revision=r.eligibility_revision and el.user_id=a.user_id and el.revoked_at is null and el.not_before<=$6 and el.expires_at>$6 and a.revoked_at is null and a.activated_at<=$6 and a.expires_at>$6 and r.status='approved' and u.status='active' and o.status='active' and c.status='active' and not c.is_agent and (rs.scopes is null or e.permissions<@rs.scopes) order by a.expires_at,a.activation_id limit 100")
            .bind(tenant.as_str()).bind(user.as_uuid()).bind(grant.client.as_str()).bind(resource).bind(&permissions).bind(now).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
        let acr = current_acr(&mut tx, tenant).await?;
        if auth.assurance_policy_revision.as_deref()
            != Some(asterius_domain::sha256_hex(acr.to_json().to_string().as_bytes()).as_str())
        {
            return Ok(snapshot);
        }
        // Stored ACR labels do not supply methods; the original grant proof is
        // checked against today's tenant ladder on every privileged issuance.
        if !auth.acr.as_ref().is_some_and(|claimed| {
            acr.level(claimed)
                .is_some_and(|level| level.is_met_by(&auth.assurance_methods))
        }) {
            return Ok(snapshot);
        }
        for (
            activation_id,
            entitlement_id,
            client,
            role,
            expires_at,
            required,
            policy_revision,
            eligibility_revision,
            permissions,
        ) in rows
        {
            if assurance_current(
                &acr,
                &required,
                AssuranceProof {
                    at: auth.assurance_authenticated_at,
                    revision: auth.assurance_policy_revision.as_deref(),
                    methods: &auth.assurance_methods,
                },
                now,
            ) {
                snapshot.roles.push(ActiveTemporaryRole {
                    activation_id,
                    entitlement_id,
                    client: ClientId::new(client),
                    resource: resource.clone(),
                    permissions,
                    policy_revision,
                    eligibility_revision,
                    role: RoleName::parse(&role)
                        .map_err(|e| DomainError::invalid("role_name", e.to_string()))?,
                    expires_at,
                });
            }
        }
        tx.commit().await.map_err(to_domain_error)?;
        Ok(snapshot)
    }
}

impl PgTemporaryEntitlements {
    /// Read current lifecycle provenance inside the caller's transaction.
    /// Keeps the same tenant publication fence as review/apply; never constructs
    /// HeldRoles and never infers grant scopes or authentication from history.
    pub async fn provenance_for_user_on(
        connection: &mut PgConnection,
        tenant: &TenantId,
        user: &UserId,
    ) -> Result<TemporaryEntitlementProvenanceSnapshot, DomainError> {
        let anchor: Option<(String,)> = sqlx::query_as(
            "select tenant_id from tenants where tenant_id=$1 and status='active' for share",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        if anchor.is_none() {
            return Err(DomainError::NotFound);
        }
        let (observed_at,): (OffsetDateTime,) = sqlx::query_as("select clock_timestamp()")
            .fetch_one(&mut *connection)
            .await
            .map_err(to_domain_error)?;
        Self::provenance_for_user_at_on(connection, tenant, user, observed_at).await
    }
    /// Uses the caller's single database clock snapshot, never a browser or
    /// process-local timestamp. This read-only result is not an authority port.
    pub async fn provenance_for_user_at_on(
        connection: &mut PgConnection,
        tenant: &TenantId,
        user: &UserId,
        observed_at: OffsetDateTime,
    ) -> Result<TemporaryEntitlementProvenanceSnapshot, DomainError> {
        let anchor: Option<(String,)> = sqlx::query_as(
            "select tenant_id from tenants where tenant_id=$1 and status='active' for share",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        if anchor.is_none() {
            return Err(DomainError::NotFound);
        }
        let rows:Vec<(Uuid,Uuid,Uuid,String,String,String,Vec<String>,Uuid,Uuid,OffsetDateTime)>=sqlx::query_as("select a.activation_id,e.entitlement_id,r.request_id,e.client_id,e.resource,e.role_name,e.permissions,e.revision,el.revision,a.expires_at from temporary_entitlement_activations a join temporary_entitlement_requests r on r.tenant_id=a.tenant_id and r.request_id=a.request_id join temporary_entitlements e on e.tenant_id=r.tenant_id and e.entitlement_id=r.entitlement_id join temporary_entitlement_eligibility el on el.tenant_id=r.tenant_id and el.eligibility_id=r.eligibility_id join users u on u.tenant_id=a.tenant_id and u.user_id=a.user_id join users o on o.tenant_id=e.tenant_id and o.user_id=e.owner_reference join clients c on c.tenant_id=e.tenant_id and c.client_id=e.client_reference join client_roles role on role.tenant_id=e.tenant_id and role.client_id=e.client_reference and role.name=e.role_reference join resource_servers rs on rs.tenant_id=e.tenant_id and rs.identifier=e.resource_reference where a.tenant_id=$1 and a.user_id=$2 and e.enabled and e.revision=r.policy_revision and el.revision=r.eligibility_revision and el.user_id=a.user_id and el.revoked_at is null and el.not_before<=$3 and el.expires_at>$3 and a.revoked_at is null and a.activated_at<=$3 and a.expires_at>$3 and r.status='approved' and u.status='active' and o.status='active' and c.status='active' and not c.is_agent and (rs.scopes is null or e.permissions<@rs.scopes) order by a.expires_at,a.activation_id limit 101")
            .bind(tenant.as_str()).bind(user.as_uuid()).bind(observed_at).fetch_all(connection).await.map_err(to_domain_error)?;
        if rows.len() > 100 {
            return Err(DomainError::Conflict(
                "temporary provenance exceeds the complete snapshot bound".into(),
            ));
        }
        let entries = rows
            .into_iter()
            .map(
                |(
                    activation_id,
                    entitlement_id,
                    request_id,
                    client,
                    resource,
                    role_name,
                    permissions,
                    policy_revision,
                    eligibility_revision,
                    expires_at,
                )| TemporaryEntitlementProvenance {
                    activation_id,
                    entitlement_id,
                    request_id,
                    client,
                    resource,
                    role_name,
                    permissions,
                    policy_revision,
                    eligibility_revision,
                    expires_at,
                },
            )
            .collect();
        Ok(TemporaryEntitlementProvenanceSnapshot {
            observed_at,
            entries,
        })
    }
}
