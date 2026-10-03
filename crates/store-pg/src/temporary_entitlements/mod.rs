//! Authoritative-clock lifecycle transitions and live role resolution.
mod configuration;
mod lifecycle;
mod records;
mod resolution;
use crate::error::to_domain_error;
use asterius_domain::temporary_entitlements::*;
use asterius_domain::{
    Actor, AuditEvent, AuthenticationMethod, Detail, DomainError, EventType, Outcome, TenantId,
    TenantSettings, UserId,
};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PgTemporaryEntitlements {
    pool: PgPool,
}
impl PgTemporaryEntitlements {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    // Always lock the publication fence before rows to keep writer/signer order.
    async fn begin(
        &self,
        tenant: &TenantId,
    ) -> Result<(Transaction<'_, Postgres>, OffsetDateTime), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let exists: Option<(String,)> = sqlx::query_as("select tenant_id from tenants where tenant_id=$1 and status='active' for no key update")
            .bind(tenant.as_str()).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if exists.is_none() {
            return Err(DomainError::NotFound);
        }
        let (now,): (OffsetDateTime,) = sqlx::query_as("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        Ok((tx, now))
    }
}
async fn audit(
    tx: &mut PgConnection,
    tenant: &TenantId,
    actor: Option<&UserId>,
    operation: &str,
    id: Uuid,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    let context: Option<(serde_json::Value,)> = sqlx::query_as("select to_jsonb(r) from temporary_entitlement_requests r where r.tenant_id=$1 and r.request_id=$2 union all select to_jsonb(r) || jsonb_build_object('activation_id',a.activation_id,'activation_expires_at',a.expires_at,'revocation_reason',a.revocation_reason) from temporary_entitlement_requests r join temporary_entitlement_activations a on a.tenant_id=r.tenant_id and a.request_id=r.request_id where a.tenant_id=$1 and a.activation_id=$2 union all select to_jsonb(e) from temporary_entitlements e where e.tenant_id=$1 and e.entitlement_id=$2 union all select to_jsonb(el) from temporary_entitlement_eligibility el where el.tenant_id=$1 and el.eligibility_id=$2 limit 1")
        .bind(tenant.as_str()).bind(id).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
    let mut detail = Detail::new()
        .text("operation", format!("temporary_entitlement.{operation}"))
        .text("reference", id.to_string());
    if let Some((context,)) = context {
        detail = detail.credential("authority_snapshot", context.to_string());
        for key in [
            "policy_revision",
            "eligibility_revision",
            "revision",
            "eligibility_id",
            "requester_acr",
            "approver_acr",
        ] {
            if let Some(value) = context.get(key).and_then(serde_json::Value::as_str) {
                detail = detail.text(key, value);
            }
        }
        for key in ["reason", "revocation_reason"] {
            if let Some(reason) = context.get(key).and_then(serde_json::Value::as_str) {
                detail = detail.pii(key, reason);
            }
        }
    }
    let event = AuditEvent::new(
        tenant.clone(),
        EventType::ADMIN_CHANGED,
        Outcome::Success,
        actor.map_or(Actor::System, |user| {
            Actor::User(user.as_uuid().to_string())
        }),
        now,
    )
    .detail(detail);
    crate::audit::append(tx, event).await
}
async fn current_acr(
    tx: &mut PgConnection,
    tenant: &TenantId,
) -> Result<asterius_domain::AcrPolicy, DomainError> {
    let (settings,): (serde_json::Value,) =
        sqlx::query_as("select settings from tenants where tenant_id=$1")
            .bind(tenant.as_str())
            .fetch_one(tx)
            .await
            .map_err(to_domain_error)?;
    let settings = TenantSettings::from_json(settings.get("options"))
        .map_err(|e| DomainError::invalid("tenant.options", e.to_string()))?;
    Ok(settings.acr_policy().clone())
}
type SessionProofRow = (Option<OffsetDateTime>, Option<String>, Option<Vec<String>>);
async fn session(
    tx: &mut PgConnection,
    tenant: &TenantId,
    actor: &SessionActor,
    required: Option<&str>,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    let row: Option<SessionProofRow> = sqlx::query_as("select proof.assurance_authenticated_at,proof.assurance_policy_revision,proof.assurance_methods from sessions s left join session_assurance_proofs proof on proof.tenant_id=s.tenant_id and proof.session_id=s.session_id and proof.acr is not distinct from s.acr and proof.assurance_authenticated_at<=s.authenticated_at join users u on u.tenant_id=s.tenant_id and u.user_id=s.user_id where s.tenant_id=$1 and s.session_id=$2 and s.user_id=$3 and s.revoked_at is null and s.expires_at>$4 and s.idle_expires_at>$4 and u.status='active' for share of s,u")
        .bind(tenant.as_str()).bind(&actor.session_digest).bind(actor.user.as_uuid()).bind(now).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
    let (authenticated_at, revision, methods) = row.ok_or(DomainError::NotFound)?;
    if let Some(required) = required {
        let authenticated_at = authenticated_at.ok_or_else(|| {
            DomainError::invalid("authentication", "independent assurance proof is missing")
        })?;
        let methods = methods.ok_or_else(|| {
            DomainError::invalid("authentication", "independent proof methods missing")
        })?;
        let methods: Vec<_> = methods
            .iter()
            .map(|s| AuthenticationMethod::parse(s))
            .collect::<Option<_>>()
            .ok_or_else(|| {
                DomainError::invalid("authentication", "unknown authentication evidence")
            })?;
        let acr = current_acr(tx, tenant).await?;
        if !assurance_current(
            &acr,
            required,
            AssuranceProof {
                at: Some(authenticated_at),
                revision: revision.as_deref(),
                methods: &methods,
            },
            now,
        ) {
            return Err(DomainError::invalid(
                "authentication",
                "fresh required assurance must be proved",
            ));
        }
    }
    Ok(())
}
async fn replay(
    tx: &mut PgConnection,
    tenant: &TenantId,
    actor: &UserId,
    operation: &str,
    key: Uuid,
    payload: &serde_json::Value,
) -> Result<Option<serde_json::Value>, DomainError> {
    let row: Option<(serde_json::Value,serde_json::Value)> = sqlx::query_as("select payload,response from temporary_entitlement_replays where tenant_id=$1 and actor_user_id=$2 and operation=$3 and idempotency_key=$4")
        .bind(tenant.as_str()).bind(actor.as_uuid()).bind(operation).bind(key).fetch_optional(tx).await.map_err(to_domain_error)?;
    match row {
        Some((stored, response)) if &stored == payload => Ok(Some(response)),
        Some(_) => Err(DomainError::Conflict(
            "idempotency key already used for different command".into(),
        )),
        None => Ok(None),
    }
}
async fn remember(
    tx: &mut PgConnection,
    tenant: &TenantId,
    actor: &UserId,
    operation: &str,
    key: Uuid,
    payload: &serde_json::Value,
    response: &serde_json::Value,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    sqlx::query("insert into temporary_entitlement_replays(tenant_id,actor_user_id,operation,idempotency_key,payload,response,created_at) values($1,$2,$3,$4,$5,$6,$7)")
        .bind(tenant.as_str()).bind(actor.as_uuid()).bind(operation).bind(key).bind(payload).bind(response).bind(now).execute(tx).await.map_err(to_domain_error)?;
    Ok(())
}
fn encode<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, DomainError> {
    serde_json::to_value(value).map_err(|e| DomainError::Storage(Box::new(e)))
}
fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, DomainError> {
    serde_json::from_value(value).map_err(|e| DomainError::Storage(Box::new(e)))
}

#[async_trait::async_trait]
impl TemporaryEntitlements for PgTemporaryEntitlements {
    async fn list(&self, t: &TenantId, a: &UserId) -> Result<Vec<Entitlement>, DomainError> {
        self.list_configurations(t, a).await
    }
    async fn get(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        entitlement: Uuid,
    ) -> Result<Entitlement, DomainError> {
        let (mut tx, _) = self.begin(tenant).await?;
        records::owner(&mut tx, tenant, owner, entitlement).await
    }
    async fn configure(
        &self,
        t: &TenantId,
        a: &UserId,
        id: Option<Uuid>,
        expected: Option<Uuid>,
        c: EntitlementConfiguration,
    ) -> Result<Entitlement, DomainError> {
        self.save_configuration(t, a, id, expected, c).await
    }
    async fn eligibilities(
        &self,
        t: &TenantId,
        a: &UserId,
        id: Uuid,
    ) -> Result<Vec<Eligibility>, DomainError> {
        self.eligibility_list(t, a, id).await
    }
    async fn set_eligibility(
        &self,
        t: &TenantId,
        a: &UserId,
        id: Uuid,
        c: EligibilityChange,
    ) -> Result<Eligibility, DomainError> {
        self.eligibility_set(t, a, id, c).await
    }
    async fn remove_eligibility(
        &self,
        t: &TenantId,
        a: &UserId,
        id: Uuid,
        el: Uuid,
        expected: Uuid,
    ) -> Result<(), DomainError> {
        self.eligibility_remove(t, a, id, el, expected).await
    }
    async fn owner_requests(
        &self,
        t: &TenantId,
        a: &UserId,
        id: Uuid,
    ) -> Result<Vec<EntitlementRequest>, DomainError> {
        self.owner_records(t, a, id, records::REQUEST).await
    }
    async fn owner_activations(
        &self,
        t: &TenantId,
        a: &UserId,
        id: Uuid,
    ) -> Result<Vec<Activation>, DomainError> {
        self.owner_records(t, a, id, records::ACTIVATION).await
    }
    async fn owner_revoke(
        &self,
        t: &TenantId,
        a: &UserId,
        id: Uuid,
        c: RevokeActivation,
    ) -> Result<Activation, DomainError> {
        self.revocation(t, a, None, Some(id), c).await
    }
    async fn account(
        &self,
        t: &TenantId,
        a: &SessionActor,
    ) -> Result<AccountEntitlements, DomainError> {
        self.account_records(t, a).await
    }
    async fn request(
        &self,
        t: &TenantId,
        a: &SessionActor,
        c: RequestActivation,
    ) -> Result<EntitlementRequest, DomainError> {
        self.submit(t, a, c).await
    }
    async fn decide(
        &self,
        t: &TenantId,
        a: &SessionActor,
        c: DecideRequest,
    ) -> Result<EntitlementRequest, DomainError> {
        self.decision(t, a, c).await
    }
    async fn cancel(
        &self,
        t: &TenantId,
        a: &SessionActor,
        c: CancelRequest,
    ) -> Result<EntitlementRequest, DomainError> {
        self.cancellation(t, a, c).await
    }
    async fn revoke(
        &self,
        t: &TenantId,
        a: &SessionActor,
        c: RevokeActivation,
    ) -> Result<Activation, DomainError> {
        self.revocation(t, &a.user, Some(a), None, c).await
    }
    async fn resolve_for_grant(
        &self,
        t: &TenantId,
        g: &asterius_domain::Grant,
    ) -> Result<TemporaryRoleSnapshot, DomainError> {
        self.resolve(t, g).await
    }
    async fn reconcile_expired(&self, t: &TenantId, limit: u16) -> Result<u64, DomainError> {
        self.expiry(t, limit).await
    }
}
