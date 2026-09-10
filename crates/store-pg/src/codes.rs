//! Authorization codes, over PostgreSQL.
//!
//! Two statements carry the security. Issuance is a plain insert. Redemption is
//! one `update … where consumed_at is null … returning`, so the check and the
//! spend are the same statement and two concurrent redemptions cannot both win.
//!
//! # Replay revokes the grant
//!
//! RFC 6749 §10.5: if a code is presented twice, the authorization server
//! "SHOULD revoke all tokens previously issued based on that authorization
//! code". This does, and it is not optional here — a second presentation means
//! either the client is broken or somebody else has the code, and the second
//! reading is the one worth designing for. FAPI 2.0 SP §5.3.2.2 item 9 requires
//! rejecting the replay; §6.8's credential-linking item is why the tokens go
//! too.
//!
//! The revocation is deliberately blunt. A code that is replayed cannot be told
//! apart from a code that was stolen and replayed, so the safe reading is
//! applied to both: everything derived from that authorization stops working,
//! and the legitimate client has to start again. That is a worse experience
//! than a retry and a much better one than an attacker holding live tokens.

use crate::error::to_domain_error;
use asterius_domain::{CodeBinding, DomainError, GrantId, RevocationReason, TenantId};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// What happened when a code was presented.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Redemption {
    /// The code was live, and is now spent.
    Redeemed(Box<CodeBinding>),
    /// No such code in this tenant, or it has expired.
    ///
    /// One variant for both: which it was is a fact for the log, and a client
    /// that could tell them apart could probe for live codes.
    NotFound,
    /// Presented a second time. The grant behind it has been revoked.
    Replayed,
}

/// Authorization codes for one tenant.
#[derive(Debug, Clone)]
pub struct PgCodeRepository {
    pool: PgPool,
    tenant: TenantId,
}

impl PgCodeRepository {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    fn digest_bytes(digest: &str) -> Result<Vec<u8>, DomainError> {
        hex::decode(digest).map_err(|e| DomainError::invalid("code", e.to_string()))
    }

    /// Stores a freshly issued code.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the digest exists, which at 256 bits means
    /// a broken generator. [`DomainError::Storage`] otherwise.
    pub async fn issue(
        &self,
        digest: &str,
        binding: &CodeBinding,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let digest = Self::digest_bytes(digest)?;
        sqlx::query!(
            "insert into authorization_codes
                 (tenant_id, code_hash, client_id, grant_id, code_challenge,
                  redirect_uri, nonce, dpop_jkt, issued_at, expires_at,
                  grant_management_action)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            self.tenant.as_str(),
            digest,
            binding.client_id,
            crate::grants::uuid(&binding.grant_id)?,
            binding.code_challenge,
            binding.redirect_uri,
            binding.nonce.as_deref(),
            binding.dpop_jkt.as_deref(),
            now,
            binding.expires_at,
            binding.grant_management_action.as_deref(),
        )
        .execute(&self.pool)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("authorization code already exists".to_owned())
            }
            _ => to_domain_error(error),
        })?;
        Ok(())
    }

    /// Spends a code, or reports why it could not be spent.
    ///
    /// On a replay this **revokes the grant** before returning, so the caller
    /// cannot forget to — the whole point of RFC 6749 §10.5 is that the
    /// revocation is not optional, and a caller that had to remember it is a
    /// caller that will not.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Never treat
    /// that as [`Redemption::NotFound`]: an unavailable database is not
    /// permission to reject a legitimate redemption *or* to accept a replay.
    pub async fn redeem(
        &self,
        digest: &str,
        now: OffsetDateTime,
    ) -> Result<Redemption, DomainError> {
        let digest = Self::digest_bytes(digest)?;

        // The spend. `consumed_at is null` in the predicate is what makes this
        // single-use: a second concurrent redemption matches no row.
        let spent = sqlx::query!(
            "update authorization_codes
                set consumed_at = $3
              where tenant_id = $1
                and code_hash = $2
                and consumed_at is null
                and expires_at > $3
             returning client_id, grant_id, code_challenge, redirect_uri,
                       nonce, dpop_jkt, expires_at, grant_management_action",
            self.tenant.as_str(),
            digest,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if let Some(row) = spent {
            return Ok(Redemption::Redeemed(Box::new(CodeBinding {
                client_id: row.client_id,
                grant_id: GrantId::new(row.grant_id.to_string()),
                code_challenge: row.code_challenge,
                redirect_uri: row.redirect_uri,
                nonce: row.nonce,
                dpop_jkt: row.dpop_jkt,
                grant_management_action: row.grant_management_action,
                expires_at: row.expires_at,
            })));
        }

        // Nothing was spent. Either it never existed, it has expired, or it was
        // already used — and only the last of those is an incident.
        let existing = sqlx::query!(
            "select grant_id, consumed_at from authorization_codes
              where tenant_id = $1 and code_hash = $2",
            self.tenant.as_str(),
            digest,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        match existing {
            Some(row) if row.consumed_at.is_some() => {
                // RFC 6749 §10.5. Everything derived from this authorization
                // stops working, because a replay and a theft look identical
                // from here.
                tracing::warn!(
                    tenant = %self.tenant,
                    "an authorization code was presented twice; revoking its grant"
                );
                self.revoke_grant(row.grant_id, now).await?;
                Ok(Redemption::Replayed)
            }
            _ => Ok(Redemption::NotFound),
        }
    }

    /// Marks a grant revoked because a code drawn on it was replayed.
    async fn revoke_grant(
        &self,
        grant: uuid::Uuid,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        // `coalesce` so an already-revoked grant keeps its first reason, and so
        // a second replay of the same code is idempotent rather than rewriting
        // history.
        sqlx::query!(
            "update grants
                set revoked_at = coalesce(revoked_at, $3),
                    revocation_reason = coalesce(revocation_reason, $4)
              where tenant_id = $1 and grant_id = $2",
            self.tenant.as_str(),
            grant,
            now,
            RevocationReason::CodeReplayed.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        // Refresh tokens drawn on the grant go too. An access token already
        // issued is bounded by its own expiry and by the grant's `revoked_at`,
        // which introspection consults.
        sqlx::query!(
            "update refresh_tokens
                set revoked_at = coalesce(revoked_at, $3)
              where tenant_id = $1 and grant_id = $2",
            self.tenant.as_str(),
            grant,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    /// Drops this tenant's spent and expired codes.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the delete fails.
    pub async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64, DomainError> {
        let result = sqlx::query!(
            "delete from authorization_codes where tenant_id = $1 and expires_at <= $2",
            self.tenant.as_str(),
            now
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }
}

/// The issuing half of the port pair. Redemption is deliberately not reachable
/// through a trait the authorization endpoint holds — see
/// [`asterius_domain::CodeIssuer`].
#[async_trait::async_trait]
impl asterius_domain::CodeIssuer for PgCodeRepository {
    async fn issue(
        &self,
        digest: &str,
        binding: &CodeBinding,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Self::issue(self, digest, binding, now).await
    }
}
