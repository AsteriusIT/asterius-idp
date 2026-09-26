//! Tenant-scoped custody of the dedicated SAML IdP RSA signing key.
//!
//! The operator validates the certificate/key pair before provisioning. Only
//! the public certificate is stored in the clear. The private PKCS#8 DER is
//! wrapped with the deployment KEK under tenant and certificate-fingerprint
//! AAD, so moving either half of a row invalidates unwrapping. There is one
//! immutable row per tenant; rotation will require a separate overlap design.

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

    /// Inserts only when this tenant has no SAML IdP key. The caller must
    /// validate certificate structure, key strength and key/cert match first.
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
        let result = sqlx::query(
            "insert into saml_idp_signing_keys
                 (tenant_id, certificate_der, certificate_sha256,
                  private_key_ciphertext, private_key_nonce, kek_id)
             values ($1, $2, $3, $4, $5, $6)
             on conflict (tenant_id) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(certificate_der)
        .bind(fingerprint.as_slice())
        .bind(wrapped.ciphertext())
        .bind(wrapped.nonce())
        .bind(wrapped.kek_id())
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Public certificate and fingerprint only; does not open the KEK.
    pub async fn summary(&self) -> Result<Option<SamlIdpKeySummary>, DomainError> {
        let row = sqlx::query(
            "select certificate_der, certificate_sha256, created_at
               from saml_idp_signing_keys where tenant_id = $1",
        )
        .bind(self.tenant.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(|row| {
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
                created_at: row.try_get("created_at").map_err(to_domain_error)?,
            })
        })
        .transpose()
    }

    /// Loads the sealed private key only for an internal signer. The row's
    /// public certificate fingerprint is verified before deriving AAD.
    pub async fn load_for_signing(&self) -> Result<Option<SamlIdpKeyMaterial>, DomainError> {
        let row = sqlx::query(
            "select certificate_der, certificate_sha256,
                    private_key_ciphertext, private_key_nonce, kek_id
               from saml_idp_signing_keys where tenant_id = $1",
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
