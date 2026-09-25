//! Tenant-scoped identity bindings and atomic, replay-safe inbound SET effects.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, SessionRevocation, TenantId};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// A lifecycle action the configured peer is permitted to request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverAction {
    /// Revoke all active sessions belonging to the mapped user.
    SessionRevoked,
    /// Disable the mapped account and revoke its active sessions.
    AccountDisabled,
}

impl ReceiverAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SessionRevoked => "session-revoked",
            Self::AccountDisabled => "account-disabled",
        }
    }
}

/// Outcome of processing one valid inbound SET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverOutcome {
    /// The subject's local action was applied and recorded.
    Applied,
    /// This peer's `jti` was already processed; no action was repeated.
    Duplicate,
}

/// The durable receiver store for one tenant.
#[derive(Clone)]
pub struct PgSsfReceiver {
    pool: PgPool,
    tenant: TenantId,
}

impl std::fmt::Debug for PgSsfReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSsfReceiver")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgSsfReceiver {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Adds or replaces an operator-provisioned binding from one peer subject
    /// to one local account. `subject_key` must be the canonical output of
    /// `asterius_ssf::Subject::key`; raw email or username matching is not used.
    pub async fn bind_subject(
        &self,
        peer_client_id: &str,
        subject_key: &str,
        user_id: Uuid,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "insert into ssf_receiver_subject_mappings
                (tenant_id, peer_client_id, subject_key, user_id)
             values ($1, $2, $3, $4)
             on conflict (tenant_id, peer_client_id, subject_key)
             do update set user_id = excluded.user_id",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(subject_key)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    /// Removes one exact subject-to-user binding, returning false when it is
    /// absent or now names a different local user.
    pub async fn remove_subject(
        &self,
        peer_client_id: &str,
        subject_key: &str,
        user_id: Uuid,
    ) -> Result<bool, DomainError> {
        let result = sqlx::query(
            "delete from ssf_receiver_subject_mappings
             where tenant_id = $1 and peer_client_id = $2 and subject_key = $3 and user_id = $4",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(subject_key)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() > 0)
    }

    /// Atomically resolves an explicitly bound subject, claims the peer's
    /// `jti`, and applies its authorized lifecycle action. A failed identity
    /// lookup rolls back; a duplicate returns successfully without repeating
    /// the effect.
    pub async fn process(
        &self,
        peer_client_id: &str,
        subject_key: &str,
        jti: &str,
        replay_until: OffsetDateTime,
        action: ReceiverAction,
        now: OffsetDateTime,
    ) -> Result<ReceiverOutcome, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let duplicate: bool = sqlx::query_scalar(
            "select exists(
                 select 1 from ssf_receiver_events
                  where tenant_id = $1 and peer_client_id = $2 and jti = $3
             )",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(jti)
        .fetch_one(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if duplicate {
            transaction.rollback().await.map_err(to_domain_error)?;
            return Ok(ReceiverOutcome::Duplicate);
        }
        let user_id: Option<Uuid> = sqlx::query_scalar(
            "select user_id from ssf_receiver_subject_mappings
             where tenant_id = $1 and peer_client_id = $2 and subject_key = $3
             for share",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(subject_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        let Some(user_id) = user_id else {
            return Err(DomainError::invalid(
                "sub_id",
                "the event subject is not configured for this peer",
            ));
        };
        let inserted = sqlx::query(
            "insert into ssf_receiver_events
                (tenant_id, peer_client_id, jti, replay_until, user_id, event_type, processed_at)
             values ($1, $2, $3, $4, $5, $6, $7)
             on conflict (tenant_id, peer_client_id, jti) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(jti)
        .bind(replay_until)
        .bind(user_id)
        .bind(action.as_str())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        if inserted == 0 {
            transaction.rollback().await.map_err(to_domain_error)?;
            return Ok(ReceiverOutcome::Duplicate);
        }

        match action {
            ReceiverAction::SessionRevoked => {
                revoke_sessions(&mut transaction, &self.tenant, user_id, now).await?;
            }
            ReceiverAction::AccountDisabled => {
                sqlx::query(
                    "update users set status = 'disabled', updated_at = $3
                     where tenant_id = $1 and user_id = $2 and status = 'active'",
                )
                .bind(self.tenant.as_str())
                .bind(user_id)
                .bind(now)
                .execute(&mut *transaction)
                .await
                .map_err(to_domain_error)?;
                revoke_sessions(&mut transaction, &self.tenant, user_id, now).await?;
            }
        }
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(ReceiverOutcome::Applied)
    }
}

async fn revoke_sessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &TenantId,
    user_id: Uuid,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    sqlx::query(
        "update sessions
         set revoked_at = coalesce(revoked_at, $3),
             revocation_reason = coalesce(revocation_reason, $4)
         where tenant_id = $1 and user_id = $2 and revoked_at is null",
    )
    .bind(tenant.as_str())
    .bind(user_id)
    .bind(now)
    .bind(SessionRevocation::Administrative.as_str())
    .execute(&mut **transaction)
    .await
    .map_err(to_domain_error)?;
    Ok(())
}
