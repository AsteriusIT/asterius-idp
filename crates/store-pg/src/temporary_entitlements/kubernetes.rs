use super::{PgTemporaryEntitlements, audit, decode, records, to_domain_error};
use asterius_domain::temporary_kubernetes::{
    KubernetesAccessProjection, KubernetesActiveSubject, KubernetesBindingChange,
    KubernetesEntitlementBinding, TemporaryKubernetes,
};
use asterius_domain::{ClientId, DomainError, TenantId, UserId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

const BINDING: &str = "select to_jsonb(b)-array['tenant_id','controller_reference','cluster_client_reference'] || jsonb_build_object('cluster',b.cluster_id) - 'cluster_id' from temporary_kubernetes_bindings b where b.tenant_id=$1 and b.entitlement_id=$2";
async fn binding(
    connection: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
) -> Result<Option<KubernetesEntitlementBinding>, DomainError> {
    let row: Option<(serde_json::Value,)> = sqlx::query_as(BINDING)
        .bind(tenant.as_str())
        .bind(id)
        .fetch_optional(connection)
        .await
        .map_err(to_domain_error)?;
    row.map(|row| decode(row.0)).transpose()
}
#[async_trait::async_trait]
impl TemporaryKubernetes for PgTemporaryEntitlements {
    async fn binding(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        id: Uuid,
    ) -> Result<Option<KubernetesEntitlementBinding>, DomainError> {
        let (mut tx, _) = self.begin(tenant).await?;
        records::owner(&mut tx, tenant, owner, id).await?;
        binding(&mut tx, tenant, id).await
    }
    async fn replace_binding(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        id: Uuid,
        change: KubernetesBindingChange,
    ) -> Result<KubernetesEntitlementBinding, DomainError> {
        change.validate()?;
        let (mut tx, now) = self.begin(tenant).await?;
        let entitlement = records::owner(&mut tx, tenant, owner, id).await?;
        let controller: Option<(String,)> = sqlx::query_as("select client_id from clients where tenant_id=$1 and client_id=$2 and status='active' and not is_agent and token_endpoint_auth_method='private_key_jwt' and dpop_bound_access_tokens and 'client_credentials'=any(grant_types) for share")
            .bind(tenant.as_str()).bind(&change.controller_client_id).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if controller.is_none() {
            return Err(DomainError::NotFound);
        }
        let profile: Option<(String,String,i64)> = sqlx::query_as("select p.cluster_id,p.namespace,p.revision from kubernetes_profiles p join clients c on c.tenant_id=p.tenant_id and c.client_id=p.client_id where p.tenant_id=$1 and p.client_id=$2 and c.status='active' and not c.is_agent and c.subject_type='public' and c.compliance_profile='oidc' and c.managed_groups_claim and c.roles_in_id_token and 'authorization_code'=any(c.grant_types) and 'refresh_token'=any(c.grant_types) and 'openid'=any(c.scopes) and cardinality(c.redirect_uris)=1 and c.application_type='web' and c.token_endpoint_auth_method='private_key_jwt' and c.dpop_bound_access_tokens and c.id_token_signed_response_alg='ES256' for share of p,c")
            .bind(tenant.as_str()).bind(&entitlement.configuration.client_id).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        let (cluster, namespace, profile_revision) = profile.ok_or_else(|| {
            DomainError::invalid(
                "kubernetes",
                "one current public-subject confidential cluster profile required",
            )
        })?;
        let previous = binding(&mut tx, tenant, id).await?;
        match (&previous, change.expected_revision) {
            (None, None) => {}
            (Some(previous), Some(expected))
                if previous.revision == expected
                    && previous.controller_client_id == change.controller_client_id => {}
            _ => {
                return Err(DomainError::Conflict(
                    "Kubernetes binding revision or immutable controller changed".into(),
                ));
            }
        }
        sqlx::query("insert into temporary_kubernetes_bindings(tenant_id,entitlement_id,controller_client_id,controller_reference,cluster_client_id,cluster_client_reference,cluster_id,namespace,profile_revision,enabled) values($1,$2,$3,$3,$4,$4,$5,$6,$7,$8) on conflict(tenant_id,entitlement_id) do update set controller_reference=excluded.controller_reference,cluster_client_reference=excluded.cluster_client_reference,namespace=excluded.namespace,profile_revision=excluded.profile_revision,enabled=excluded.enabled")
            .bind(tenant.as_str()).bind(id).bind(&change.controller_client_id).bind(&entitlement.configuration.client_id).bind(cluster).bind(namespace).bind(profile_revision).bind(change.enabled).execute(&mut *tx).await.map_err(to_domain_error)?;
        audit(&mut tx, tenant, Some(owner), "kubernetes_binding", id, now).await?;
        let result = binding(&mut tx, tenant, id)
            .await?
            .ok_or(DomainError::NotFound)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    async fn project(
        &self,
        tenant: &TenantId,
        controller: &ClientId,
        id: Uuid,
    ) -> Result<KubernetesAccessProjection, DomainError> {
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
        let (observed_at,): (OffsetDateTime,) = sqlx::query_as("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let mut current = binding(&mut tx, tenant, id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if current.controller_client_id != controller.as_str() {
            return Err(DomainError::NotFound);
        }
        let eligible: Option<(Uuid,)> = sqlx::query_as("select b.entitlement_id from temporary_kubernetes_bindings b join clients controller on controller.tenant_id=b.tenant_id and controller.client_id=b.controller_reference where b.tenant_id=$1 and b.entitlement_id=$2 and controller.status='active' and not controller.is_agent and controller.token_endpoint_auth_method='private_key_jwt' and controller.dpop_bound_access_tokens and 'client_credentials'=any(controller.grant_types)")
            .bind(tenant.as_str()).bind(id).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if eligible.is_none() {
            return Err(DomainError::NotFound);
        }
        let entitlement = records::entitlement(&mut tx, tenant, id).await?;
        let profile: Option<(i64,)> = sqlx::query_as("select p.revision from kubernetes_profiles p join clients c on c.tenant_id=p.tenant_id and c.client_id=p.client_id where p.tenant_id=$1 and p.client_id=$2 and p.cluster_id=$3 and p.namespace=$4 and p.revision=$5 and c.status='active' and not c.is_agent and c.subject_type='public' and c.compliance_profile='oidc' and c.managed_groups_claim and c.roles_in_id_token and 'authorization_code'=any(c.grant_types) and 'refresh_token'=any(c.grant_types) and 'openid'=any(c.scopes) and cardinality(c.redirect_uris)=1 and c.token_endpoint_auth_method='private_key_jwt' and c.dpop_bound_access_tokens and c.id_token_signed_response_alg='ES256'")
            .bind(tenant.as_str()).bind(&current.cluster_client_id).bind(&current.cluster).bind(&current.namespace).bind(current.profile_revision).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        current.enabled &= profile.is_some() && entitlement.configuration.enabled;
        let subjects = if current.enabled {
            active_subjects(&mut tx, tenant, id, &current, observed_at).await?
        } else {
            Vec::new()
        };
        tx.commit().await.map_err(to_domain_error)?;
        Ok(KubernetesAccessProjection {
            binding: current,
            entitlement_revision: entitlement.revision,
            observed_at,
            subjects,
        })
    }
}
async fn active_subjects(
    connection: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
    current: &KubernetesEntitlementBinding,
    now: OffsetDateTime,
) -> Result<Vec<KubernetesActiveSubject>, DomainError> {
    let rows: Vec<(Uuid,String,OffsetDateTime)> = sqlx::query_as("select a.activation_id,s.subject,a.expires_at from temporary_entitlement_activations a join temporary_entitlement_requests r on r.tenant_id=a.tenant_id and r.request_id=a.request_id join temporary_entitlements e on e.tenant_id=a.tenant_id and e.entitlement_id=a.entitlement_id join temporary_entitlement_eligibility el on el.tenant_id=r.tenant_id and el.eligibility_id=r.eligibility_id join users u on u.tenant_id=a.tenant_id and u.user_id=a.user_id join users owner on owner.tenant_id=e.tenant_id and owner.user_id=e.owner_reference join client_roles role on role.tenant_id=e.tenant_id and role.client_id=e.client_reference and role.name=e.role_reference join resource_servers rs on rs.tenant_id=e.tenant_id and rs.identifier=e.resource_reference join subject_identifiers s on s.tenant_id=a.tenant_id and s.user_id=a.user_id and s.sector_identifier='' where a.tenant_id=$1 and a.entitlement_id=$2 and e.enabled and e.revision=r.policy_revision and r.status='approved' and r.requester_user_id=a.user_id and el.revision=r.eligibility_revision and el.user_id=a.user_id and el.revoked_at is null and el.not_before<=$3 and el.expires_at>$3 and a.revoked_at is null and a.activated_at<=$3 and a.expires_at>$3 and u.status='active' and owner.status='active' and (rs.scopes is null or e.permissions<@rs.scopes) order by a.expires_at,a.activation_id limit 101")
        .bind(tenant.as_str()).bind(id).bind(now).fetch_all(connection).await.map_err(to_domain_error)?;
    if rows.len() > 100 {
        return Err(DomainError::Conflict(
            "complete Kubernetes projection exceeds 100 subjects".into(),
        ));
    }
    let prefix = format!("asterius-jit:{}:", current.revision);
    Ok(rows
        .into_iter()
        .map(
            |(activation_id, subject, expires_at)| KubernetesActiveSubject {
                activation_id,
                username: format!("{prefix}{subject}"),
                expires_at,
            },
        )
        .collect())
}

impl PgTemporaryEntitlements {
    /// Resolve private ID provenance using only the caller's fenced signing connection.
    /// Standing overlaps are excluded by the supplied exact-grant temporary deadlines.
    pub async fn kubernetes_identity_for_grant_on(
        connection: &mut PgConnection,
        tenant: &TenantId,
        grant: &asterius_domain::Grant,
        held: &asterius_domain::HeldRoles,
    ) -> Result<Option<asterius_domain::temporary_kubernetes::KubernetesJitIdentity>, DomainError> {
        let snapshot = Self::resolve_for_grant_on(connection, tenant, grant).await?;
        let mut identity = None;
        for role in snapshot.roles {
            let Some(deadline) = held.temporary_deadlines.get(&grant.client)
                .and_then(|roles| roles.get(&role.role)) else { continue; };
            if !held.role_current_at(&grant.client, &role.role, snapshot.observed_at) { continue; }
            let mapped: Option<(Uuid, String, String, i64)> = sqlx::query_as(
                "select b.revision,b.cluster_id,b.namespace,b.profile_revision from temporary_kubernetes_bindings b join kubernetes_profiles p on p.tenant_id=b.tenant_id and p.client_id=b.cluster_client_reference and p.cluster_id=b.cluster_id and p.namespace=b.namespace and p.revision=b.profile_revision join clients c on c.tenant_id=p.tenant_id and c.client_id=p.client_id join clients controller on controller.tenant_id=b.tenant_id and controller.client_id=b.controller_reference where b.tenant_id=$1 and b.entitlement_id=$2 and b.cluster_client_id=$3 and b.enabled and c.status='active' and not c.is_agent and c.subject_type='public' and c.compliance_profile='oidc' and c.managed_groups_claim and c.roles_in_id_token and 'authorization_code'=any(c.grant_types) and 'refresh_token'=any(c.grant_types) and 'openid'=any(c.scopes) and cardinality(c.redirect_uris)=1 and c.compliance_profile='oidc' and c.application_type='web' and c.token_endpoint_auth_method='private_key_jwt' and c.id_token_signed_response_alg='ES256' and c.dpop_bound_access_tokens and c.managed_groups_claim and c.roles_in_id_token and 'authorization_code'=any(c.grant_types) and 'refresh_token'=any(c.grant_types) and 'openid'=any(c.scopes) and cardinality(c.redirect_uris)=1 and controller.status='active' and not controller.is_agent and controller.token_endpoint_auth_method='private_key_jwt' and controller.dpop_bound_access_tokens and 'client_credentials'=any(controller.grant_types)"
            ).bind(tenant.as_str()).bind(role.entitlement_id).bind(grant.client.as_str())
                .fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
            let Some((revision, cluster, namespace, profile_revision)) = mapped else { continue; };
            let expires_at = role.expires_at.min(*deadline).unix_timestamp();
            if expires_at <= snapshot.observed_at.unix_timestamp() { continue; }
            let candidate = asterius_domain::temporary_kubernetes::KubernetesJitIdentity {
                binding_revision: revision, entitlement_id: role.entitlement_id,
                client_id: grant.client.as_str().to_owned(), resource: role.resource,
                permissions: role.permissions, role: role.role.as_str().to_owned(),
                cluster, namespace, profile_revision, expires_at,
            };
            candidate.validate()?;
            if identity.as_ref().is_some_and(|current: &asterius_domain::temporary_kubernetes::KubernetesJitIdentity|
                current.binding_revision != candidate.binding_revision) {
                return Err(DomainError::Conflict("ambiguous temporary Kubernetes identity".into()));
            }
            // Multiple activations for the same entitlement never extend an earlier
            // independently resolved temporary-role deadline.
            identity = Some(candidate);
        }
        Ok(identity)
    }
}
