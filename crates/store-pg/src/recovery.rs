//! Account recovery tokens, over PostgreSQL.
//!
//! Three statements, and the shape of each is the security property:
//!
//! * `issue` writes the new token and consumes the user's earlier ones in one
//!   transaction, so a mailbox never holds two live links;
//! * `spend` is a single `update ... returning`, so two requests racing one
//!   link produce exactly one reset;
//! * `invalidate_for_user` is the hook every credential change calls.
//!
//! None of them ever selects a token by anything but its digest, and no column
//! holds a token. See `asterius_domain::entities::recovery`.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, IssuedRecovery, RecoveryTokenStore, TenantId, UserId};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// Why a token stopped being usable. The stored spellings of
/// `recovery_tokens.consumed_reason`.
mod reason {
    /// It was presented and a new credential was set.
    pub const SPENT: &str = "spent";
    /// A newer link was issued for the same account.
    pub const SUPERSEDED: &str = "superseded";
    /// The account's credentials changed by some other route.
    pub const CREDENTIAL_CHANGE: &str = "credential_change";
}

/// [`RecoveryTokenStore`] for one tenant.
#[derive(Clone)]
pub struct PgRecoveryTokens {
    pool: PgPool,
    tenant: TenantId,
}

impl std::fmt::Debug for PgRecoveryTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgRecoveryTokens")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgRecoveryTokens {
    /// Binds a pool to one tenant.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Drops rows whose tokens expired before `before`.
    ///
    /// An expired token is refused by `spend` regardless, so these rows
    /// protect nothing and only cost space. Per tenant rather than one
    /// unqualified delete, for the reason `PgReplayGuard::purge_expired`
    /// gives: every statement over a tenant-scoped table names `tenant_id`.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the delete fails.
    pub async fn purge_expired(&self, before: OffsetDateTime) -> Result<u64, DomainError> {
        let result = sqlx::query!(
            "delete from recovery_tokens where tenant_id = $1 and expires_at <= $2",
            self.tenant.as_str(),
            before,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }
}

#[async_trait::async_trait]
impl RecoveryTokenStore for PgRecoveryTokens {
    async fn issue(&self, issued: &IssuedRecovery) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;

        // Earlier links for this account stop working the moment a new one is
        // drawn. In the same transaction as the insert: a crash between the
        // two would otherwise leave the old ones live, which is the state this
        // is here to prevent.
        sqlx::query!(
            "update recovery_tokens
                set consumed_at = $3, consumed_reason = $4
              where tenant_id = $1 and user_id = $2 and consumed_at is null",
            self.tenant.as_str(),
            issued.user.as_uuid(),
            issued.issued_at,
            reason::SUPERSEDED,
        )
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;

        sqlx::query!(
            "insert into recovery_tokens
                 (tenant_id, token_hash, user_id, issued_at, expires_at)
             values ($1, $2, $3, $4, $5)",
            self.tenant.as_str(),
            issued.token_digest,
            issued.user.as_uuid(),
            issued.issued_at,
            issued.expires_at,
        )
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;

        tx.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    async fn spend(
        &self,
        digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<UserId>, DomainError> {
        // One statement. The `consumed_at is null` and `expires_at > now`
        // predicates are inside the `update`, so the row is claimed by
        // whichever request wins and the loser updates nothing and is told
        // nothing.
        let row = sqlx::query!(
            "update recovery_tokens
                set consumed_at = $3, consumed_reason = $4
              where tenant_id = $1
                and token_hash = $2
                and consumed_at is null
                and expires_at > $3
          returning user_id",
            self.tenant.as_str(),
            digest,
            now,
            reason::SPENT,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(row.map(|row| UserId::new(row.user_id)))
    }

    async fn peek(&self, digest: &str, now: OffsetDateTime) -> Result<Option<UserId>, DomainError> {
        // The same predicates `spend` applies, and no write. See the port: the
        // handler that renders is not the handler that decides.
        let row = sqlx::query!(
            "select user_id from recovery_tokens
              where tenant_id = $1
                and token_hash = $2
                and consumed_at is null
                and expires_at > $3",
            self.tenant.as_str(),
            digest,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(row.map(|row| UserId::new(row.user_id)))
    }

    async fn invalidate_for_user(
        &self,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let result = sqlx::query!(
            "update recovery_tokens
                set consumed_at = $3, consumed_reason = $4
              where tenant_id = $1 and user_id = $2 and consumed_at is null",
            self.tenant.as_str(),
            user.as_uuid(),
            now,
            reason::CREDENTIAL_CHANGE,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }
}
