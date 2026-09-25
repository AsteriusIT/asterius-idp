//! Tenant-scoped storage for explicit Identity Assurance verification records.

use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::ports::TenantScoped;
use asterius_domain::{DomainError, Issuer, TenantId, UserId, VerifiedClaims};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::to_domain_error;

/// A verified bundle with its revocable storage identifier.
#[derive(Debug, Clone)]
pub struct StoredVerifiedClaims {
    /// Stable identifier for revocation and audit.
    pub id: Uuid,
    /// Validated IDA record.
    pub bundle: VerifiedClaims,
}

/// Isolated repository for IDA records; ordinary claims cannot be promoted by
/// merely changing their source or `verified_at` timestamp.
#[derive(Debug, Clone)]
pub struct PgVerifiedClaims {
    pool: PgPool,
    tenant: TenantId,
}

impl PgVerifiedClaims {
    pub(crate) fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Store one trusted verification record for a user in this tenant.
    /// Maximum 32 live bundles per user. The lock on the user row serializes
    /// concurrent inserts and prevents a race with account removal.
    ///
    /// # Errors
    /// Returns storage errors, `NotFound` for a missing user, or an invalid
    /// input error when the per-user bound is reached.
    pub async fn insert(
        &self,
        user: UserId,
        bundle: &VerifiedClaims,
        actor: &str,
        now: OffsetDateTime,
    ) -> Result<Uuid, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let present: Option<Uuid> = sqlx::query_scalar(
            "select user_id from users where tenant_id = $1 and user_id = $2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if present.is_none() {
            return Err(DomainError::NotFound);
        }
        let live: i64 = sqlx::query_scalar(
            "select count(*) from verified_claim_bundles where tenant_id = $1 and user_id = $2 and revoked_at is null",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if live >= 32 {
            return Err(DomainError::invalid(
                "verified_claims",
                "maximum live bundles reached",
            ));
        }
        let claims = serde_json::to_value(bundle.claims())
            .map_err(|error| DomainError::invalid("verified_claims", error.to_string()))?;
        let id = Uuid::new_v4();
        sqlx::query(
            "insert into verified_claim_bundles
             (tenant_id, user_id, bundle_id, trust_framework, verifier_issuer, verified_at, claims)
             values ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .bind(id)
        .bind(bundle.verification().trust_framework())
        .bind(bundle.verification().verifier())
        .bind(bundle.verification().time())
        .bind(claims)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        crate::audit::append(
            &mut *tx,
            AuditEvent::new(
                self.tenant.clone(),
                EventType::USER_CLAIMS_CHANGED,
                Outcome::Success,
                Actor::Admin(actor.to_owned()),
                now,
            )
            .subject(user.as_uuid().to_string())
            .detail(
                Detail::new()
                    .label("operation", "ida.bundle.create")
                    .text("bundle_id", id.to_string())
                    .text("trust_framework", bundle.verification().trust_framework()),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(id)
    }

    /// Read live records through the domain validator before any release.
    ///
    /// # Errors
    /// Returns a storage or validation error for a malformed row.
    pub async fn by_user(&self, user: UserId) -> Result<Vec<StoredVerifiedClaims>, DomainError> {
        let rows = sqlx::query_as::<_, Row>(
            "select bundle_id, trust_framework, verifier_issuer, verified_at, claims
             from verified_claim_bundles
             where tenant_id = $1 and user_id = $2 and revoked_at is null
             order by created_at desc, bundle_id limit 33",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        if rows.len() > 32 {
            return Err(DomainError::invalid(
                "verified_claims",
                "too many live bundles",
            ));
        }
        rows.into_iter().map(Row::validated).collect()
    }

    /// Revoke a record owned by this tenant and user. Repeated revocations
    /// return false, preserving an idempotent administration surface.
    ///
    /// # Errors
    /// Returns a storage error when the update fails.
    pub async fn revoke(
        &self,
        user: UserId,
        id: Uuid,
        actor: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let changed = sqlx::query(
            "update verified_claim_bundles set revoked_at = $4
             where tenant_id = $1 and user_id = $2 and bundle_id = $3 and revoked_at is null",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if changed.rows_affected() == 1 {
            crate::audit::append(
                &mut *tx,
                AuditEvent::new(
                    self.tenant.clone(),
                    EventType::USER_CLAIMS_CHANGED,
                    Outcome::Success,
                    Actor::Admin(actor.to_owned()),
                    now,
                )
                .subject(user.as_uuid().to_string())
                .detail(
                    Detail::new()
                        .label("operation", "ida.bundle.revoke")
                        .text("bundle_id", id.to_string()),
                ),
            )
            .await?;
        }
        tx.commit().await.map_err(to_domain_error)?;
        Ok(changed.rows_affected() == 1)
    }
}

impl TenantScoped for PgVerifiedClaims {
    fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}

#[derive(sqlx::FromRow)]
struct Row {
    bundle_id: Uuid,
    trust_framework: String,
    verifier_issuer: String,
    verified_at: OffsetDateTime,
    claims: serde_json::Value,
}

impl Row {
    fn validated(self) -> Result<StoredVerifiedClaims, DomainError> {
        let issuer = Issuer::parse(&self.verifier_issuer)
            .map_err(|error| DomainError::invalid("verifier_issuer", error.to_string()))?;
        let bundle = VerifiedClaims::from_storage(
            &self.trust_framework,
            &issuer,
            self.verified_at,
            &self.claims,
        )
        .map_err(|error| DomainError::invalid("verified_claims", error.to_string()))?;
        Ok(StoredVerifiedClaims {
            id: self.bundle_id,
            bundle,
        })
    }
}
