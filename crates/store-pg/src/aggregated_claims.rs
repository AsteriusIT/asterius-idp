//! Tenant-scoped retention of verified Claims Provider signed UserInfo.
//!
//! Only [`VerifiedClaimSet`] can be inserted. Verification and an end user's
//! provider/RP consent happen before this repository is called; the upcoming
//! connection flow owns those decisions. Rows remain short-lived and can be
//! revoked independently of the local user's own attributes.

use crate::error::to_domain_error;
use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::{DomainError, TenantId, UserId};
use asterius_jose::claims_aggregation::VerifiedClaimSet;
use sqlx::PgPool;
use time::OffsetDateTime;

/// The signed claim source a user still has connected to this tenant.
#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct StoredClaimSource {
    /// Pinned Claims Provider issuer.
    pub provider_issuer: String,
    /// Subject established by the user's provider connection.
    pub provider_subject: String,
    /// Signed UserInfo JWT, intact for later RP verification.
    pub signed_userinfo: String,
    /// Names carried in that signed JWT.
    pub claim_names: Vec<String>,
    /// JWT expiry, also the maximum retention deadline.
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for StoredClaimSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredClaimSource")
            .field("provider_issuer", &self.provider_issuer)
            .field("claim_names", &self.claim_names)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Signed claim sets belonging to one tenant.
#[derive(Debug, Clone)]
pub struct PgAggregatedClaims {
    pool: PgPool,
    tenant: TenantId,
}

impl PgAggregatedClaims {
    pub(crate) fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Retain one verified signed response for a user and pinned provider.
    /// At most four unexpired providers may be connected for one user. A
    /// provider-subject change cannot silently replace an existing connection.
    ///
    /// # Errors
    /// Refuses a missing user, subject switch, expired JWT or provider limit;
    /// returns storage errors if the transaction cannot complete.
    pub async fn replace(
        &self,
        user: UserId,
        verified: &VerifiedClaimSet,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let provider_issuer = verified.issuer();
        let provider_subject = verified.subject();
        if verified.expires_at() <= now
            || provider_issuer.is_empty()
            || provider_issuer.len() > 2048
            || provider_subject.is_empty()
            || provider_subject.len() > 256
        {
            return Err(DomainError::invalid(
                "aggregated_claims",
                "provider or signed claim set is invalid",
            ));
        }
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let present: Option<uuid::Uuid> = sqlx::query_scalar(
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
        let count: i64 = sqlx::query_scalar(
            "select count(*) from aggregated_claim_sources
             where tenant_id = $1 and user_id = $2 and provider_issuer <> $3
               and revoked_at is null and expires_at > $4",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .bind(provider_issuer)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if count >= 4 {
            return Err(DomainError::invalid(
                "aggregated_claims",
                "maximum connected providers reached",
            ));
        }
        let names: Vec<String> = verified.names().iter().cloned().collect();
        let written = sqlx::query(
            "insert into aggregated_claim_sources
             (tenant_id, user_id, provider_issuer, provider_subject, signed_userinfo,
              claim_names, expires_at, stored_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8)
             on conflict (tenant_id, user_id, provider_issuer) do update set
                 signed_userinfo = excluded.signed_userinfo,
                 claim_names = excluded.claim_names,
                 expires_at = excluded.expires_at,
                 stored_at = excluded.stored_at,
                 revoked_at = null
             where aggregated_claim_sources.provider_subject = excluded.provider_subject",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .bind(provider_issuer)
        .bind(provider_subject)
        .bind(verified.jwt())
        .bind(&names)
        .bind(verified.expires_at())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if written.rows_affected() != 1 {
            return Err(DomainError::invalid(
                "aggregated_claims",
                "provider subject changed",
            ));
        }
        crate::audit::append(
            &mut tx,
            AuditEvent::new(
                self.tenant.clone(),
                EventType::USER_CLAIMS_CHANGED,
                Outcome::Success,
                Actor::User(user.to_string()),
                now,
            )
            .subject(user.to_string())
            .detail(
                Detail::new()
                    .label("operation", "claims_provider.store")
                    .text("provider_issuer", provider_issuer),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    /// Read no more than four live, unrevoked signed sources for a user.
    ///
    /// # Errors
    /// Returns storage failures or refuses rows beyond the configured bound.
    pub async fn by_user(
        &self,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<StoredClaimSource>, DomainError> {
        let rows = sqlx::query_as::<_, StoredClaimSource>(
            "select provider_issuer, provider_subject, signed_userinfo, claim_names, expires_at
             from aggregated_claim_sources
             where tenant_id = $1 and user_id = $2 and revoked_at is null and expires_at > $3
             order by provider_issuer limit 5",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        if rows.len() > 4 {
            return Err(DomainError::invalid(
                "aggregated_claims",
                "too many live providers",
            ));
        }
        Ok(rows)
    }

    /// Revoke one provider connection and its cached signed claims.
    ///
    /// # Errors
    /// Returns a storage failure if the update cannot complete.
    pub async fn revoke(
        &self,
        user: UserId,
        provider_issuer: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let changed = sqlx::query(
            "update aggregated_claim_sources set revoked_at = $4
             where tenant_id = $1 and user_id = $2 and provider_issuer = $3
               and revoked_at is null",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .bind(provider_issuer)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if changed.rows_affected() == 1 {
            crate::audit::append(
                &mut tx,
                AuditEvent::new(
                    self.tenant.clone(),
                    EventType::USER_CLAIMS_CHANGED,
                    Outcome::Success,
                    Actor::User(user.to_string()),
                    now,
                )
                .subject(user.to_string())
                .detail(
                    Detail::new()
                        .label("operation", "claims_provider.revoke")
                        .text("provider_issuer", provider_issuer),
                ),
            )
            .await?;
        }
        tx.commit().await.map_err(to_domain_error)?;
        Ok(changed.rows_affected() == 1)
    }
}
