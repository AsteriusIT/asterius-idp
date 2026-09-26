//! Single-use, session-bound Claims Provider OAuth setup transactions.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId};
use asterius_jose::{Kek, KeyBinding, RowSecret, WrappedKey};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroize;

/// A consumed setup request. The verifier is held only long enough to redeem
/// the authorization code and is never returned to the browser.
pub struct CpPending {
    pub user_id: Uuid,
    pub provider_issuer: String,
    pub provider_nonce: String,
    pub code_verifier: String,
}

impl Drop for CpPending {
    fn drop(&mut self) {
        self.code_verifier.zeroize();
    }
}

impl std::fmt::Debug for CpPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CpPending")
            .field("user_id", &self.user_id)
            .field("provider_issuer", &self.provider_issuer)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct PgCpOAuth {
    pool: PgPool,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
}

impl std::fmt::Debug for PgCpOAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PgCpOAuth")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgCpOAuth {
    #[must_use]
    pub fn new(pool: PgPool, tenant: TenantId, kek: Arc<dyn Kek>) -> Self {
        Self { pool, tenant, kek }
    }

    /// Persist a ten-minute setup attempt before sending the browser to CP.
    pub async fn begin(
        &self,
        state_hash: &str,
        user_id: Uuid,
        session_digest: &str,
        provider_issuer: &str,
        provider_nonce: &str,
        code_verifier: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if state_hash.len() != 64
            || session_digest.len() != 64
            || provider_issuer.len() > 2048
            || provider_issuer.is_empty()
            || !(32..=128).contains(&provider_nonce.len())
            || !(43..=128).contains(&code_verifier.len())
        {
            return Err(DomainError::invalid(
                "claims_provider.oauth",
                "pending request is invalid",
            ));
        }
        let wrapped = self
            .kek
            .wrap(
                KeyBinding::row_secret(&self.tenant, RowSecret::ClaimsProviderPkce, state_hash),
                code_verifier.as_bytes(),
            )
            .await
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query(
            "delete from claims_provider_oauth_pending
             where tenant_id = $1 and (expires_at <= now() or (user_id = $2 and provider_issuer = $3))",
        )
        .bind(self.tenant.as_str()).bind(user_id).bind(provider_issuer)
        .execute(&mut *tx).await.map_err(to_domain_error)?;
        sqlx::query(
            "insert into claims_provider_oauth_pending
             (tenant_id, state_hash, user_id, session_digest, provider_issuer,
              provider_nonce, verifier_ciphertext, verifier_nonce, verifier_kek_id, expires_at)
             values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(self.tenant.as_str())
        .bind(state_hash)
        .bind(user_id)
        .bind(session_digest)
        .bind(provider_issuer)
        .bind(provider_nonce)
        .bind(wrapped.ciphertext())
        .bind(wrapped.nonce())
        .bind(wrapped.kek_id())
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    /// Consume one state token only for the browser session that began it.
    /// Failed token exchange cannot replay the code against this transaction.
    pub async fn consume(
        &self,
        state_hash: &str,
        session_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<CpPending>, DomainError> {
        let row = sqlx::query(
            "delete from claims_provider_oauth_pending
             where tenant_id = $1 and state_hash = $2 and session_digest = $3 and expires_at > $4
             returning user_id, provider_issuer, provider_nonce,
                       verifier_ciphertext, verifier_nonce, verifier_kek_id",
        )
        .bind(self.tenant.as_str())
        .bind(state_hash)
        .bind(session_digest)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let wrapped = WrappedKey::from_parts(
            row.try_get::<String, _>("verifier_kek_id")
                .map_err(to_domain_error)?,
            row.try_get("verifier_nonce").map_err(to_domain_error)?,
            row.try_get("verifier_ciphertext")
                .map_err(to_domain_error)?,
        )
        .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let plaintext = self
            .kek
            .unwrap(
                KeyBinding::row_secret(&self.tenant, RowSecret::ClaimsProviderPkce, state_hash),
                &wrapped,
            )
            .await
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let code_verifier = String::from_utf8(plaintext.to_vec()).map_err(|_| {
            DomainError::invalid("claims_provider.oauth", "stored verifier is invalid")
        })?;
        Ok(Some(CpPending {
            user_id: row.try_get("user_id").map_err(to_domain_error)?,
            provider_issuer: row.try_get("provider_issuer").map_err(to_domain_error)?,
            provider_nonce: row.try_get("provider_nonce").map_err(to_domain_error)?,
            code_verifier,
        }))
    }
}
