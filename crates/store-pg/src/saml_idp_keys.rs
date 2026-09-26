//! Tenant-scoped custody of the dedicated SAML `IdP` RSA signing key.
//!
//! The operator validates the certificate/key pair before provisioning. Only
//! the public certificate is stored in the clear. The private PKCS#8 DER is
//! wrapped with the deployment KEK under tenant and certificate-fingerprint
//! AAD, so moving either half of a row invalidates unwrapping. A tenant may
//! stage one pending successor, activate it while retaining the former active
//! certificate, and retire the old certificate only by an explicit command.
//! One pending or retiring successor is allowed at a time. Retirement erases
//! private material, retaining only the public certificate for audit history.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId};
use asterius_jose::{Kek, KeyBinding, RowSecret, WrappedKey};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row as _};
use std::sync::Arc;
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Public details that may be shown to a tenant administrator.
#[derive(Debug, Clone)]
pub struct SamlIdpKeySummary {
    pub certificate_sha256: String,
    pub certificate_der: Vec<u8>,
    pub state: String,
    pub created_at: OffsetDateTime,
}

/// Decrypted material for an internal signer. Debug output omits the key.
pub struct SamlIdpKeyMaterial {
    pub certificate_der: Vec<u8>,
    pub private_key_pkcs8: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SamlIdpKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamlIdpKeyMaterial")
            .field("certificate_len", &self.certificate_der.len())
            .finish_non_exhaustive()
    }
}

/// A repository that cannot query a different tenant without construction of
/// a different `TenantScope`.
#[derive(Debug, Clone)]
pub struct PgSamlIdpKeys {
    pool: PgPool,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
}

impl PgSamlIdpKeys {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId, kek: Arc<dyn Kek>) -> Self {
        Self { pool, tenant, kek }
    }

    /// Provisions the first key active, or one successor pending. A duplicate
    /// certificate or existing pending successor returns false. The caller
    /// must validate certificate structure, strength and pair match first.
    pub async fn provision(
        &self,
        certificate_der: &[u8],
        private_key_pkcs8: &[u8],
    ) -> Result<bool, DomainError> {
        if !(256..=16_384).contains(&certificate_der.len())
            || !(256..=16_384).contains(&private_key_pkcs8.len())
        {
            return Err(DomainError::invalid(
                "saml.idp_key",
                "invalid key material length",
            ));
        }
        let fingerprint = Sha256::digest(certificate_der);
        let fingerprint_hex = hex::encode(fingerprint);
        let wrapped = self
            .kek
            .wrap(
                KeyBinding::row_secret(
                    &self.tenant,
                    RowSecret::SamlIdpSigningKey,
                    &fingerprint_hex,
                ),
                private_key_pkcs8,
            )
            .await
            .map_err(storage_error)?;
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('saml-idp-key'))")
            .bind(self.tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(to_domain_error)?;
        let overlap: bool = sqlx::query_scalar(
            "select exists(select 1 from saml_idp_signing_keys
                            where tenant_id = $1 and state in ('pending', 'retiring'))",
        )
        .bind(self.tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if overlap {
            return Ok(false);
        }
        let active: bool = sqlx::query_scalar(
            "select exists(select 1 from saml_idp_signing_keys
                            where tenant_id = $1 and state = 'active')",
        )
        .bind(self.tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        let state = if active { "pending" } else { "active" };
        let result = sqlx::query(
            "insert into saml_idp_signing_keys
                 (tenant_id, certificate_der, certificate_sha256,
                  private_key_ciphertext, private_key_nonce, kek_id, state, activated_at)
             values ($1, $2, $3, $4, $5, $6, $7,
                     case when $7 = 'active' then now() else null end)
             on conflict (tenant_id, certificate_sha256) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(certificate_der)
        .bind(fingerprint.as_slice())
        .bind(wrapped.ciphertext())
        .bind(wrapped.nonce())
        .bind(wrapped.kek_id())
        .bind(state)
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Public certificate history for operator inspection. Current keys sort
    /// first; recent retired keys follow, capped at 100. No private material
    /// is opened or returned.
    pub async fn list(&self) -> Result<Vec<SamlIdpKeySummary>, DomainError> {
        let rows = sqlx::query(
            "select certificate_der, certificate_sha256, state, created_at
               from saml_idp_signing_keys
              where tenant_id = $1
              order by case state when 'active' then 0 when 'pending' then 1
                                  when 'retiring' then 2 else 3 end,
                       created_at desc, certificate_sha256
              limit 100",
        )
        .bind(self.tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        rows.into_iter()
            .map(|row| {
                let certificate_der: Vec<u8> =
                    row.try_get("certificate_der").map_err(to_domain_error)?;
                let fingerprint: Vec<u8> =
                    row.try_get("certificate_sha256").map_err(to_domain_error)?;
                if Sha256::digest(&certificate_der).as_slice() != fingerprint {
                    return Err(DomainError::invalid(
                        "saml.idp_key",
                        "stored certificate fingerprint mismatch",
                    ));
                }
                Ok(SamlIdpKeySummary {
                    certificate_sha256: hex::encode(fingerprint),
                    certificate_der,
                    state: row.try_get("state").map_err(to_domain_error)?,
                    created_at: row.try_get("created_at").map_err(to_domain_error)?,
                })
            })
            .collect()
    }

    /// Public certificates eligible for live metadata publication. Retired
    /// keys are omitted. At most two rows are
    /// returned because another key cannot be staged during retirement.
    pub async fn published(&self) -> Result<Vec<SamlIdpKeySummary>, DomainError> {
        Ok(self
            .list()
            .await?
            .into_iter()
            .filter(|key| key.state != "retired")
            .collect())
    }

    /// Atomically promotes exactly the named pending certificate. The former
    /// active certificate becomes retiring and stays available for metadata
    /// overlap until an operator separately calls `retire`.
    pub async fn activate(&self, certificate_sha256: &str) -> Result<bool, DomainError> {
        let fingerprint = parse_fingerprint(certificate_sha256)?;
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('saml-idp-key'))")
            .bind(self.tenant.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(to_domain_error)?;
        let pending: bool = sqlx::query_scalar(
            "select exists(select 1 from saml_idp_signing_keys
                            where tenant_id = $1 and certificate_sha256 = $2 and state = 'pending')",
        )
        .bind(self.tenant.as_str())
        .bind(fingerprint.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if !pending {
            return Ok(false);
        }
        let retiring: bool = sqlx::query_scalar(
            "select exists(select 1 from saml_idp_signing_keys
                            where tenant_id = $1 and state = 'retiring')",
        )
        .bind(self.tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if retiring {
            return Ok(false);
        }
        sqlx::query(
            "update saml_idp_signing_keys
                set state = 'retiring', retiring_at = now()
              where tenant_id = $1 and state = 'active'",
        )
        .bind(self.tenant.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        let changed = sqlx::query(
            "update saml_idp_signing_keys
                set state = 'active', activated_at = now()
              where tenant_id = $1 and certificate_sha256 = $2 and state = 'pending'",
        )
        .bind(self.tenant.as_str())
        .bind(fingerprint.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Explicitly stops publishing one former active certificate after at
    /// least ten minutes. The operator confirms SP rollover at the API edge.
    /// Private ciphertext and its envelope are erased; public audit material
    /// stays. Active and pending certificates cannot be retired here.
    pub async fn retire(&self, certificate_sha256: &str) -> Result<bool, DomainError> {
        let fingerprint = parse_fingerprint(certificate_sha256)?;
        let changed = sqlx::query(
            "update saml_idp_signing_keys
                set state = 'retired', retired_at = now(),
                    private_key_ciphertext = null, private_key_nonce = null, kek_id = null
              where tenant_id = $1 and certificate_sha256 = $2 and state = 'retiring'
                and retiring_at <= now() - interval '10 minutes'",
        )
        .bind(self.tenant.as_str())
        .bind(fingerprint.as_slice())
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Loads the sealed private key only for an internal signer. The row's
    /// public certificate fingerprint is verified before deriving AAD.
    pub async fn load_for_signing(&self) -> Result<Option<SamlIdpKeyMaterial>, DomainError> {
        let row = sqlx::query(
            "select certificate_der, certificate_sha256,
                    private_key_ciphertext, private_key_nonce, kek_id
               from saml_idp_signing_keys where tenant_id = $1 and state = 'active'",
        )
        .bind(self.tenant.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let Some(row) = row else { return Ok(None) };
        let certificate_der: Vec<u8> = row.try_get("certificate_der").map_err(to_domain_error)?;
        let fingerprint: Vec<u8> = row.try_get("certificate_sha256").map_err(to_domain_error)?;
        if Sha256::digest(&certificate_der).as_slice() != fingerprint {
            return Err(DomainError::invalid(
                "saml.idp_key",
                "stored certificate fingerprint mismatch",
            ));
        }
        let fingerprint_hex = hex::encode(fingerprint);
        let wrapped = WrappedKey::from_parts(
            row.try_get::<String, _>("kek_id")
                .map_err(to_domain_error)?,
            row.try_get("private_key_nonce").map_err(to_domain_error)?,
            row.try_get("private_key_ciphertext")
                .map_err(to_domain_error)?,
        )
        .map_err(storage_error)?;
        let private_key_pkcs8 = self
            .kek
            .unwrap(
                KeyBinding::row_secret(
                    &self.tenant,
                    RowSecret::SamlIdpSigningKey,
                    &fingerprint_hex,
                ),
                &wrapped,
            )
            .await
            .map_err(storage_error)?;
        Ok(Some(SamlIdpKeyMaterial {
            certificate_der,
            private_key_pkcs8,
        }))
    }
}

fn storage_error(error: impl std::error::Error + Send + Sync + 'static) -> DomainError {
    DomainError::Storage(Box::new(error))
}

fn parse_fingerprint(value: &str) -> Result<Vec<u8>, DomainError> {
    let decoded = hex::decode(value)
        .map_err(|_| DomainError::invalid("saml.idp_key", "invalid certificate fingerprint"))?;
    if decoded.len() != 32 || value.len() != 64 {
        return Err(DomainError::invalid(
            "saml.idp_key",
            "invalid certificate fingerprint",
        ));
    }
    Ok(decoded)
}
