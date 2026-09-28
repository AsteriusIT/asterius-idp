//! Single-use upstream OIDC browser transactions bound to interaction digests.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId};
use asterius_jose::{Kek, KeyBinding, RowSecret, WrappedKey};
use sqlx::{PgPool, Row as _};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

pub const LIFETIME: Duration = Duration::minutes(5);

#[derive(Clone)]
pub struct NewOidcPending<'a> {
    pub state_digest: &'a str,
    pub interaction_digest: &'a str,
    pub provider_id: &'a str,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub token_endpoint: &'a str,
    pub jwks_uri: &'a str,
    pub nonce_digest: &'a str,
    pub code_verifier: &'a str,
}

impl std::fmt::Debug for NewOidcPending<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewOidcPending")
            .field("provider_id", &self.provider_id)
            .finish_non_exhaustive()
    }
}

pub struct ConsumedOidcPending {
    pub issuer: String,
    pub client_id: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub nonce_digest: String,
    pub code_verifier: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for ConsumedOidcPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsumedOidcPending")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct PgOidcUpstreamPending {
    pool: PgPool,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
}

impl PgOidcUpstreamPending {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId, kek: Arc<dyn Kek>) -> Self {
        Self { pool, tenant, kek }
    }

    /// Replaces any outstanding attempt for this interaction. The browser must
    /// still present the interaction cookie when the callback consumes state.
    pub async fn begin(
        &self,
        input: &NewOidcPending<'_>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let wrapped = self
            .kek
            .wrap(
                KeyBinding::row_secret(
                    &self.tenant,
                    RowSecret::OidcUpstreamPkce,
                    input.state_digest,
                ),
                input.code_verifier.as_bytes(),
            )
            .await
            .map_err(storage_error)?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query(
            "delete from oidc_upstream_pending where tenant_id = $1 and interaction_digest = $2",
        )
        .bind(self.tenant.as_str())
        .bind(input.interaction_digest)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "insert into oidc_upstream_pending
            (tenant_id, state_digest, interaction_digest, provider_id, issuer, client_id,
             token_endpoint, jwks_uri, nonce_digest, verifier_ciphertext, verifier_nonce,
             kek_id, expires_at)
            values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(self.tenant.as_str())
        .bind(input.state_digest)
        .bind(input.interaction_digest)
        .bind(input.provider_id)
        .bind(input.issuer)
        .bind(input.client_id)
        .bind(input.token_endpoint)
        .bind(input.jwks_uri)
        .bind(input.nonce_digest)
        .bind(wrapped.ciphertext())
        .bind(wrapped.nonce())
        .bind(wrapped.kek_id())
        .bind(now + LIFETIME)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)
    }

    /// Consumes state atomically before any outbound token request. Replayed,
    /// expired or wrong-browser callbacks all return None.
    pub async fn consume(
        &self,
        state_digest: &str,
        interaction_digest: &str,
        provider_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<ConsumedOidcPending>, DomainError> {
        let row = sqlx::query(
            "delete from oidc_upstream_pending
            where tenant_id = $1 and state_digest = $2 and interaction_digest = $3
              and provider_id = $4 and expires_at > $5
            returning issuer, client_id, token_endpoint, jwks_uri, nonce_digest,
                      verifier_ciphertext, verifier_nonce, kek_id",
        )
        .bind(self.tenant.as_str())
        .bind(state_digest)
        .bind(interaction_digest)
        .bind(provider_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let Some(row) = row else { return Ok(None) };
        let wrapped = WrappedKey::from_parts(
            row.try_get::<String, _>("kek_id")
                .map_err(to_domain_error)?,
            row.try_get("verifier_nonce").map_err(to_domain_error)?,
            row.try_get("verifier_ciphertext")
                .map_err(to_domain_error)?,
        )
        .map_err(storage_error)?;
        let code_verifier = self
            .kek
            .unwrap(
                KeyBinding::row_secret(&self.tenant, RowSecret::OidcUpstreamPkce, state_digest),
                &wrapped,
            )
            .await
            .map_err(storage_error)?;
        Ok(Some(ConsumedOidcPending {
            issuer: row.try_get("issuer").map_err(to_domain_error)?,
            client_id: row.try_get("client_id").map_err(to_domain_error)?,
            token_endpoint: row.try_get("token_endpoint").map_err(to_domain_error)?,
            jwks_uri: row.try_get("jwks_uri").map_err(to_domain_error)?,
            nonce_digest: row.try_get("nonce_digest").map_err(to_domain_error)?,
            code_verifier,
        }))
    }
}

fn storage_error(error: impl std::error::Error + Send + Sync + 'static) -> DomainError {
    DomainError::Storage(Box::new(error))
}
