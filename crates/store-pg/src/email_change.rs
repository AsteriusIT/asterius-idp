//! Tenant-scoped, single-use requests to replace an account's email address.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId, UserId};
use sqlx::PgPool;
use time::OffsetDateTime;

/// The confirmed change, returned without a token or message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedEmailChange {
    /// The account that changed.
    pub user: UserId,
    /// The prior address. It receives a security notice only when verified.
    pub old_address: String,
    /// Whether the prior address was verified.
    pub old_verified: bool,
    /// The newly verified address.
    pub new_address: String,
}

/// Pending email changes for one tenant.
#[derive(Clone)]
pub struct PgEmailChangeRequests {
    pool: PgPool,
    tenant: TenantId,
}

impl std::fmt::Debug for PgEmailChangeRequests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgEmailChangeRequests")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgEmailChangeRequests {
    /// Bind the repository to one tenant.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Replace any earlier pending request. `false` means the address is
    /// already held by this account or another account in this tenant.
    /// The caller supplies only a digest; plaintext never reaches this table.
    ///
    /// # Errors
    /// Returns a storage error if the transaction fails.
    pub async fn issue(
        &self,
        user: UserId,
        new_address: &str,
        digest: &str,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let current: Option<(Option<String>, bool)> = sqlx::query_as(
            "select email, email_verified from users
             where tenant_id = $1 and user_id = $2 and status = 'active'
             for update",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let Some((Some(old_address), old_verified)) = current else {
            return Ok(false);
        };
        if old_address.eq_ignore_ascii_case(new_address) {
            return Ok(false);
        }
        let in_use: bool = sqlx::query_scalar(
            "select exists(select 1 from users where tenant_id = $1 and lower(email) = lower($2))",
        )
        .bind(self.tenant.as_str())
        .bind(new_address)
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if in_use {
            return Ok(false);
        }

        sqlx::query(
            "update email_change_requests
             set consumed_at = $3, consumed_reason = 'superseded'
             where tenant_id = $1 and user_id = $2 and consumed_at is null",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "insert into email_change_requests
             (tenant_id, token_hash, user_id, old_address, old_verified,
              new_address, issued_at, expires_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(self.tenant.as_str())
        .bind(digest)
        .bind(user.as_uuid())
        .bind(old_address)
        .bind(old_verified)
        .bind(new_address)
        .bind(now)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(true)
    }

    /// Consume one confirmation and move the email in the same transaction.
    /// The old address and token must still match, and no other account may
    /// own the new address. A spent, expired, or superseded token returns None.
    ///
    /// # Errors
    /// Returns a storage error if the transaction fails.
    pub async fn confirm(
        &self,
        digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<ConfirmedEmailChange>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let row: Option<(uuid::Uuid, String, bool, String)> = sqlx::query_as(
            "select user_id, old_address, old_verified, new_address
             from email_change_requests
             where tenant_id = $1 and token_hash = $2 and consumed_at is null
               and expires_at > $3
             for update",
        )
        .bind(self.tenant.as_str())
        .bind(digest)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let Some((user_id, old_address, old_verified, new_address)) = row else {
            return Ok(None);
        };
        // Two accounts may request the same currently free address. Serialize
        // their confirmations by (tenant, case-folded address), then the
        // predicate below sees whichever claim committed first. A hash
        // collision only causes extra waiting; the unique index remains the
        // final authority.
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext(lower($2)))")
            .bind(self.tenant.as_str())
            .bind(&new_address)
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let updated = sqlx::query(
            "update users set email = $4, email_verified = true
             where tenant_id = $1 and user_id = $2 and lower(email) = lower($3)
               and status = 'active'
               and not exists (
                   select 1 from users other
                   where other.tenant_id = $1 and other.user_id <> $2
                     and lower(other.email) = lower($4)
               )",
        )
        .bind(self.tenant.as_str())
        .bind(user_id)
        .bind(&old_address)
        .bind(&new_address)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let changed = updated.rows_affected() == 1;
        sqlx::query(
            "update email_change_requests set consumed_at = $3,
                    consumed_reason = $4
             where tenant_id = $1 and token_hash = $2",
        )
        .bind(self.tenant.as_str())
        .bind(digest)
        .bind(now)
        .bind(if changed { "spent" } else { "conflict" })
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if changed {
            sqlx::query(
                "update email_verification_tokens
                 set consumed_at = $3, consumed_reason = 'address_change'
                 where tenant_id = $1 and user_id = $2 and consumed_at is null",
            )
            .bind(self.tenant.as_str())
            .bind(user_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
            if old_verified {
                sqlx::query(
                    "insert into outbox (tenant_id, kind, destination, payload, created_at)
                     values ($1, 'notification.email_change_notice', $2, '{}'::jsonb, $3)",
                )
                .bind(self.tenant.as_str())
                .bind(&old_address)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(to_domain_error)?;
            }
        }
        tx.commit().await.map_err(to_domain_error)?;
        Ok(changed.then_some(ConfirmedEmailChange {
            user: UserId::new(user_id),
            old_address,
            old_verified,
            new_address,
        }))
    }
}
