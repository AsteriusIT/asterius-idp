//! Tenant-scoped upstream OIDC registrations and encrypted credentials.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId};
use asterius_jose::{Kek, KeyBinding, RowSecret, WrappedKey};
use sqlx::{PgPool, Row as _};
use std::sync::Arc;
use time::OffsetDateTime;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct OidcProvider {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    pub username_claim: Option<String>,
    pub enabled: bool,
    pub allow_registration: bool,
    pub created_at: OffsetDateTime,
}

/// Secret material is internal only; its `Debug` output is deliberately empty.
pub struct OidcProviderCredential {
    pub provider: OidcProvider,
    pub client_secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for OidcProviderCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcProviderCredential")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct PgOidcProviders {
    pool: PgPool,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
}

type StoredEnvelope = (Vec<u8>, Vec<u8>, String, String, String);

impl PgOidcProviders {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId, kek: Arc<dyn Kek>) -> Self {
        Self { pool, tenant, kek }
    }

    pub async fn list(&self) -> Result<Vec<OidcProvider>, DomainError> {
        let rows = sqlx::query(
            "select provider_id, display_name, issuer, authorization_endpoint,
                       token_endpoint, jwks_uri, client_id, username_claim, enabled, allow_registration, created_at
                  from oidc_identity_providers where tenant_id = $1 order by provider_id",
        )
        .bind(self.tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        rows.iter().map(provider_from_row).collect()
    }

    pub async fn find(&self, id: &str) -> Result<Option<OidcProviderCredential>, DomainError> {
        let row = sqlx::query(
            "select provider_id, display_name, issuer, authorization_endpoint,
                       token_endpoint, jwks_uri, client_id, username_claim, enabled, allow_registration, created_at,
                       client_secret_ciphertext, client_secret_nonce, kek_id
                  from oidc_identity_providers where tenant_id = $1 and provider_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let Some(row) = row else { return Ok(None) };
        let provider = provider_from_row(&row)?;
        let wrapped = WrappedKey::from_parts(
            row.try_get::<String, _>("kek_id")
                .map_err(to_domain_error)?,
            row.try_get("client_secret_nonce")
                .map_err(to_domain_error)?,
            row.try_get("client_secret_ciphertext")
                .map_err(to_domain_error)?,
        )
        .map_err(storage_error)?;
        let client_secret = self
            .kek
            .unwrap(
                KeyBinding::row_secret(&self.tenant, RowSecret::OidcProviderClientSecret, id),
                &wrapped,
            )
            .await
            .map_err(storage_error)?;
        Ok(Some(OidcProviderCredential {
            provider,
            client_secret,
        }))
    }

    /// Upsert one fully validated discovery snapshot. A missing secret is
    /// accepted only when the row exists; it leaves the old envelope untouched.
    pub async fn put(
        &self,
        provider: &OidcProvider,
        secret: Option<&[u8]>,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('oidc-provider'))")
            .bind(self.tenant.as_str())
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let previous: Option<StoredEnvelope> = sqlx::query_as(
            "select client_secret_ciphertext, client_secret_nonce, kek_id, issuer, client_id
               from oidc_identity_providers where tenant_id = $1 and provider_id = $2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(&provider.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let previous_issuer = previous.as_ref().map(|(_, _, _, issuer, _)| issuer.clone());
        let (ciphertext, nonce, kek_id) = if let Some(secret) = secret {
            let wrapped = self
                .kek
                .wrap(
                    KeyBinding::row_secret(
                        &self.tenant,
                        RowSecret::OidcProviderClientSecret,
                        &provider.id,
                    ),
                    secret,
                )
                .await
                .map_err(storage_error)?;
            (
                wrapped.ciphertext().to_vec(),
                wrapped.nonce().to_vec(),
                wrapped.kek_id().to_owned(),
            )
        } else {
            let (ciphertext, nonce, kek_id, issuer, client_id) = previous
                .ok_or_else(|| DomainError::invalid("oidc_provider", "client secret required"))?;
            if issuer != provider.issuer || client_id != provider.client_id {
                return Err(DomainError::invalid(
                    "oidc_provider",
                    "client secret required when issuer or client ID changes",
                ));
            }
            (ciphertext, nonce, kek_id)
        };
        if previous_issuer
            .as_ref()
            .is_some_and(|issuer| issuer != &provider.issuer)
        {
            let bound: bool = sqlx::query_scalar(
                "select exists(select 1 from oidc_identity_bindings
                 where tenant_id = $1 and provider_id = $2)",
            )
            .bind(self.tenant.as_str())
            .bind(&provider.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
            if bound {
                return Err(DomainError::invalid(
                    "oidc_provider",
                    "unlink identities before changing issuer",
                ));
            }
        }
        sqlx::query(
            "insert into oidc_identity_providers
                 (tenant_id, provider_id, display_name, issuer, authorization_endpoint,
                  token_endpoint, jwks_uri, client_id, client_secret_ciphertext,
                  client_secret_nonce, kek_id, enabled, allow_registration, username_claim)
               values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
               on conflict (tenant_id, provider_id) do update set
                 display_name = excluded.display_name, issuer = excluded.issuer,
                 authorization_endpoint = excluded.authorization_endpoint,
                 token_endpoint = excluded.token_endpoint, jwks_uri = excluded.jwks_uri,
                 client_id = excluded.client_id,
                 client_secret_ciphertext = excluded.client_secret_ciphertext,
                 client_secret_nonce = excluded.client_secret_nonce, kek_id = excluded.kek_id,
                 enabled = excluded.enabled,
                 allow_registration = excluded.allow_registration,
                 username_claim = excluded.username_claim, updated_at = now()",
        )
        .bind(self.tenant.as_str())
        .bind(&provider.id)
        .bind(&provider.name)
        .bind(&provider.issuer)
        .bind(&provider.authorization_endpoint)
        .bind(&provider.token_endpoint)
        .bind(&provider.jwks_uri)
        .bind(&provider.client_id)
        .bind(ciphertext)
        .bind(nonce)
        .bind(kek_id)
        .bind(provider.enabled)
        .bind(provider.allow_registration)
        .bind(&provider.username_claim)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)
    }

    pub async fn delete(&self, id: &str) -> Result<bool, DomainError> {
        let result = sqlx::query(
            "delete from oidc_identity_providers where tenant_id = $1 and provider_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }
}

fn provider_from_row(row: &sqlx::postgres::PgRow) -> Result<OidcProvider, DomainError> {
    Ok(OidcProvider {
        id: row.try_get("provider_id").map_err(to_domain_error)?,
        name: row.try_get("display_name").map_err(to_domain_error)?,
        issuer: row.try_get("issuer").map_err(to_domain_error)?,
        authorization_endpoint: row
            .try_get("authorization_endpoint")
            .map_err(to_domain_error)?,
        token_endpoint: row.try_get("token_endpoint").map_err(to_domain_error)?,
        jwks_uri: row.try_get("jwks_uri").map_err(to_domain_error)?,
        client_id: row.try_get("client_id").map_err(to_domain_error)?,
        username_claim: row.try_get("username_claim").map_err(to_domain_error)?,
        enabled: row.try_get("enabled").map_err(to_domain_error)?,
        allow_registration: row.try_get("allow_registration").map_err(to_domain_error)?,
        created_at: row.try_get("created_at").map_err(to_domain_error)?,
    })
}

fn storage_error(error: impl std::error::Error + Send + Sync + 'static) -> DomainError {
    DomainError::invalid("oidc_provider", error.to_string())
}
