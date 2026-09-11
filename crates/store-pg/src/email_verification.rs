//! Email-verification tokens, over PostgreSQL.
//!
//! Three statements, shaped exactly like `crate::recovery`'s and against a
//! different table for the reason `0027_email_verification.sql` gives:
//!
//! * `issue` writes the new token and supersedes the user's earlier ones in
//!   one transaction, so a mailbox never holds two live links and an old
//!   address can never be confirmed after a new one was asked for;
//! * `spend` is a single `update … returning`, so two requests racing one link
//!   produce exactly one confirmation;
//! * `invalidate_for_user` is the hook an address change calls.
//!
//! None of them ever selects a token by anything but its digest, and no column
//! holds a token. See `asterius_domain::entities::email_verification`.

use crate::error::to_domain_error;
use asterius_domain::{
    DomainError, EmailVerificationStore, IssuedEmailVerification, TenantId, UserId, VerifiedAddress,
};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// Why a token stopped being usable. The stored spellings of
/// `email_verification_tokens.consumed_reason`.
mod reason {
    /// It was followed and the address was confirmed.
    pub const SPENT: &str = "spent";
    /// A newer link was issued for the same account.
    pub const SUPERSEDED: &str = "superseded";
    /// The account's address changed by some other route.
    pub const ADDRESS_CHANGE: &str = "address_change";
}

/// [`EmailVerificationStore`] for one tenant.
#[derive(Clone)]
pub struct PgEmailVerificationTokens {
    pool: PgPool,
    tenant: TenantId,
}

impl std::fmt::Debug for PgEmailVerificationTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgEmailVerificationTokens")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgEmailVerificationTokens {
    /// Binds a pool to one tenant.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Drops rows whose tokens expired before `before`.
    ///
    /// An expired token is refused by `spend` regardless, so these rows
    /// protect nothing and cost an address sitting in a table. Per tenant
    /// rather than one unqualified delete, like every other statement over a
    /// tenant-scoped table here.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the delete fails.
    pub async fn purge_expired(&self, before: OffsetDateTime) -> Result<u64, DomainError> {
        let result = sqlx::query!(
            "delete from email_verification_tokens where tenant_id = $1 and expires_at <= $2",
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
impl EmailVerificationStore for PgEmailVerificationTokens {
    async fn issue(&self, issued: &IssuedEmailVerification) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;

        // Earlier links for this account stop working the moment a new one is
        // drawn. In the same transaction as the insert: a crash between the
        // two would leave a link proving an address the account may no longer
        // hold, which is the state the address column exists to prevent.
        sqlx::query!(
            "update email_verification_tokens
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
            "insert into email_verification_tokens
                 (tenant_id, token_hash, user_id, address, issued_at, expires_at)
             values ($1, $2, $3, $4, $5, $6)",
            self.tenant.as_str(),
            issued.token_digest,
            issued.user.as_uuid(),
            issued.address,
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
    ) -> Result<Option<VerifiedAddress>, DomainError> {
        // One statement. The `consumed_at is null` and `expires_at > now`
        // predicates are inside the `update`, so the row is claimed by
        // whichever request wins and the loser updates nothing and is told
        // nothing.
        let row = sqlx::query!(
            "update email_verification_tokens
                set consumed_at = $3, consumed_reason = $4
              where tenant_id = $1
                and token_hash = $2
                and consumed_at is null
                and expires_at > $3
          returning user_id, address",
            self.tenant.as_str(),
            digest,
            now,
            reason::SPENT,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(row.map(|row| VerifiedAddress {
            user: UserId::new(row.user_id),
            address: row.address,
        }))
    }

    async fn invalidate_for_user(
        &self,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let result = sqlx::query!(
            "update email_verification_tokens
                set consumed_at = $3, consumed_reason = $4
              where tenant_id = $1 and user_id = $2 and consumed_at is null",
            self.tenant.as_str(),
            user.as_uuid(),
            now,
            reason::ADDRESS_CHANGE,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }
}
