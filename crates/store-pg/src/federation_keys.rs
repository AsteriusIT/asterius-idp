//! KEK-wrapped, tenant-scoped Federation signing key lifecycle.
use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId, keys::SigningAlgorithm};
use asterius_jose::{Kek, KeyBinding, RowSecret, SigningKey, WrappedKey, thumbprint};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

const PROPAGATION: Duration = Duration::minutes(6);
const RETIREMENT: Duration = Duration::minutes(10);

#[derive(Debug, Clone)]
pub struct PgFederationKeys {
    pool: PgPool,
    kek: Arc<dyn Kek>,
}

#[derive(Debug)]
pub struct FederationKeySnapshot {
    pub active: SigningKey,
    pub kid: asterius_domain::Kid,
    pub jwks: Vec<Value>,
}

impl PgFederationKeys {
    #[must_use]
    pub const fn new(pool: PgPool, kek: Arc<dyn Kek>) -> Self {
        Self { pool, kek }
    }

    pub async fn has_key(&self, tenant: &TenantId) -> Result<bool, DomainError> {
        sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from federation_signing_keys where tenant_id = $1)",
        )
        .bind(tenant.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)
    }

    /// Import a legacy key or generate a new one exactly once. A serialised
    /// tenant lock makes concurrent first boots converge on one active key.
    pub async fn initialize(
        &self,
        tenant: &TenantId,
        legacy: Option<&[u8]>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('federation-keys'))")
            .bind(tenant.as_str())
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let exists: bool = sqlx::query_scalar(
            "select exists(select 1 from federation_signing_keys where tenant_id = $1)",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if exists {
            tx.commit().await.map_err(to_domain_error)?;
            return Ok(());
        }
        let key = match legacy {
            Some(bytes) => SigningKey::from_pkcs8(SigningAlgorithm::EdDsa, bytes),
            None => SigningKey::generate(SigningAlgorithm::EdDsa),
        }
        .map_err(storage)?;
        self.insert(&mut tx, tenant, &key, "active", now).await?;
        tx.commit().await.map_err(to_domain_error)
    }

    /// Publish a successor before it signs. Repeated requests keep the same
    /// pending key and therefore cannot continually delay propagation.
    pub async fn stage(
        &self,
        tenant: &TenantId,
        now: OffsetDateTime,
    ) -> Result<String, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('federation-keys'))")
            .bind(tenant.as_str())
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let pending: Option<String> = sqlx::query_scalar(
            "select kid from federation_signing_keys where tenant_id = $1 and state = 'pending'",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if let Some(kid) = pending {
            tx.commit().await.map_err(to_domain_error)?;
            return Ok(kid);
        }
        let active: bool = sqlx::query_scalar("select exists(select 1 from federation_signing_keys where tenant_id = $1 and state = 'active')")
            .bind(tenant.as_str()).fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        if !active {
            return Err(DomainError::Conflict(
                "Federation key has no active predecessor".to_owned(),
            ));
        }
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).map_err(storage)?;
        let kid = self.insert(&mut tx, tenant, &key, "pending", now).await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(kid)
    }

    /// Promote only after propagation; retain prior public keys past JWT expiry.
    pub async fn sweep(&self, tenant: &TenantId, now: OffsetDateTime) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('federation-keys'))")
            .bind(tenant.as_str())
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let pending: Option<String> = sqlx::query_scalar("select kid from federation_signing_keys where tenant_id = $1 and state = 'pending' and created_at <= $2")
            .bind(tenant.as_str()).bind(now - PROPAGATION).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if let Some(kid) = pending {
            sqlx::query("update federation_signing_keys set state = 'retiring', retired_at = $2 where tenant_id = $1 and state = 'active'")
                .bind(tenant.as_str()).bind(now).execute(&mut *tx).await.map_err(to_domain_error)?;
            sqlx::query("update federation_signing_keys set state = 'active', activated_at = $3 where tenant_id = $1 and kid = $2 and state = 'pending'")
                .bind(tenant.as_str()).bind(kid).bind(now).execute(&mut *tx).await.map_err(to_domain_error)?;
        }
        sqlx::query("update federation_signing_keys set state = 'retired' where tenant_id = $1 and state = 'retiring' and retired_at <= $2")
            .bind(tenant.as_str()).bind(now - RETIREMENT).execute(&mut *tx).await.map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)
    }

    pub async fn snapshot(&self, tenant: &TenantId) -> Result<FederationKeySnapshot, DomainError> {
        let rows = sqlx::query("select kid, public_jwk, ciphertext, nonce, kek_id, state from federation_signing_keys where tenant_id = $1 and state in ('pending', 'active', 'retiring') order by created_at")
            .bind(tenant.as_str()).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        let mut active = None;
        let mut jwks = Vec::new();
        for row in rows {
            let kid: String = row.try_get("kid").map_err(to_domain_error)?;
            let jwk: Value = row.try_get("public_jwk").map_err(to_domain_error)?;
            if row.try_get::<String, _>("state").map_err(to_domain_error)? == "active" {
                let wrapped = WrappedKey::from_parts(
                    row.try_get::<String, _>("kek_id")
                        .map_err(to_domain_error)?,
                    row.try_get("nonce").map_err(to_domain_error)?,
                    row.try_get("ciphertext").map_err(to_domain_error)?,
                )
                .map_err(storage)?;
                let bytes = self
                    .kek
                    .unwrap(
                        KeyBinding::row_secret(tenant, RowSecret::FederationSigningKey, &kid),
                        &wrapped,
                    )
                    .await
                    .map_err(storage)?;
                let key =
                    SigningKey::from_pkcs8(SigningAlgorithm::EdDsa, &bytes).map_err(storage)?;
                let derived = key.public_jwk().map_err(storage)?;
                if thumbprint(&derived).map_err(storage)?.as_str() != kid
                    || thumbprint(&jwk).map_err(storage)?.as_str() != kid
                {
                    return Err(DomainError::Conflict(
                        "Federation private and public keys differ".to_owned(),
                    ));
                }
                active = Some((key, thumbprint(&jwk).map_err(storage)?));
            }
            jwks.push(jwk);
        }
        let (active, kid) = active.ok_or_else(|| {
            DomainError::Conflict("Federation key has no active signer".to_owned())
        })?;
        Ok(FederationKeySnapshot { active, kid, jwks })
    }

    async fn insert(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: &TenantId,
        key: &SigningKey,
        state: &str,
        now: OffsetDateTime,
    ) -> Result<String, DomainError> {
        let mut jwk = key.public_jwk().map_err(storage)?;
        let kid = thumbprint(&jwk).map_err(storage)?.as_str().to_owned();
        jwk["kid"] = serde_json::json!(kid);
        jwk["use"] = serde_json::json!("sig");
        let wrapped = self
            .kek
            .wrap(
                KeyBinding::row_secret(tenant, RowSecret::FederationSigningKey, &kid),
                key.pkcs8(),
            )
            .await
            .map_err(storage)?;
        sqlx::query("insert into federation_signing_keys (tenant_id, kid, public_jwk, ciphertext, nonce, kek_id, state, created_at, activated_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(tenant.as_str()).bind(&kid).bind(jwk).bind(wrapped.ciphertext()).bind(wrapped.nonce()).bind(wrapped.kek_id()).bind(state).bind(now).bind((state == "active").then_some(now))
            .execute(&mut **tx).await.map_err(to_domain_error)?;
        Ok(kid)
    }
}

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> DomainError {
    DomainError::Storage(Box::new(error))
}
