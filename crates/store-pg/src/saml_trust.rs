//! Tenant-scoped SAML SP trust and durable AuthnRequest ID reservations.
//!
//! Provisioning does not enable browser SSO. A later handler must validate
//! destination, time, signature policy and response issuance before using
//! these records. No inbound XML or caller-provided ACS is written here.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use url::Url;

/// One explicitly provisioned SP. Metadata and assertion recipients must
/// always use this exact ACS URL, never an AuthnRequest supplied endpoint.
#[derive(Debug, Clone)]
pub struct SamlSp {
    pub entity_id: String,
    pub acs_url: String,
    /// Explicit operator exception; false is the database default.
    pub allow_unsigned_requests: bool,
    /// Operator-pinned RSA public key DER for HTTP-Redirect signatures.
    pub redirect_signing_public_key_der: Option<Vec<u8>>,
    pub created_at: OffsetDateTime,
}

/// PostgreSQL handle with the routed tenant fixed before any query.
#[derive(Debug, Clone)]
pub struct PgSamlTrust {
    pool: PgPool,
    tenant: TenantId,
}

impl PgSamlTrust {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Inserts one exact trust entry. A duplicate entity ID returns false;
    /// changing an ACS requires an explicit removal and a separate insert.
    pub async fn provision(
        &self,
        entity_id: &str,
        acs_url: &str,
        allow_unsigned_requests: bool,
        redirect_signing_public_key_der: Option<&[u8]>,
    ) -> Result<bool, DomainError> {
        validate(entity_id, acs_url)?;
        let result = sqlx::query(
            "insert into saml_sp_trusts
                 (tenant_id, entity_id, acs_url, allow_unsigned_requests, redirect_signing_public_key_der)
             values ($1, $2, $3, $4, $5)
             on conflict (tenant_id, entity_id) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(entity_id)
        .bind(acs_url)
        .bind(allow_unsigned_requests)
        .bind(redirect_signing_public_key_der)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Lists only this tenant's exact SP trust entries.
    pub async fn list(&self) -> Result<Vec<SamlSp>, DomainError> {
        let rows: Vec<(String, String, bool, Option<Vec<u8>>, OffsetDateTime)> = sqlx::query_as(
            "select entity_id, acs_url, allow_unsigned_requests,
                    redirect_signing_public_key_der, created_at
               from saml_sp_trusts where tenant_id = $1 order by entity_id",
        )
        .bind(self.tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    entity_id,
                    acs_url,
                    allow_unsigned_requests,
                    redirect_signing_public_key_der,
                    created_at,
                )| SamlSp {
                    entity_id,
                    acs_url,
                    allow_unsigned_requests,
                    redirect_signing_public_key_der,
                    created_at,
                },
            )
            .collect())
    }

    /// Resolves only an exact entity ID in this tenant.
    pub async fn find(&self, entity_id: &str) -> Result<Option<SamlSp>, DomainError> {
        let row: Option<(String, String, bool, Option<Vec<u8>>, OffsetDateTime)> = sqlx::query_as(
            "select entity_id, acs_url, allow_unsigned_requests,
                    redirect_signing_public_key_der, created_at
               from saml_sp_trusts where tenant_id = $1 and entity_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(row.map(
            |(
                entity_id,
                acs_url,
                allow_unsigned_requests,
                redirect_signing_public_key_der,
                created_at,
            )| SamlSp {
                entity_id,
                acs_url,
                allow_unsigned_requests,
                redirect_signing_public_key_der,
                created_at,
            },
        ))
    }

    /// Removes one exact SP trust. Replay tombstones survive this operation.
    pub async fn remove(&self, entity_id: &str) -> Result<bool, DomainError> {
        let result =
            sqlx::query("delete from saml_sp_trusts where tenant_id = $1 and entity_id = $2")
                .bind(self.tenant.as_str())
                .bind(entity_id)
                .execute(&self.pool)
                .await
                .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Reserves an AuthnRequest ID once for an existing SP. The primary key
    /// makes concurrent attempts across replicas atomic. A missing SP and a
    /// replay both return false; a caller must not issue on either outcome.
    /// The ACS and unsigned policy are checked again in the insertion
    /// statement, so a trust change between a read and this reservation
    /// cannot silently substitute another recipient.
    /// Tombstones survive SP replacement and currently have no TTL cleanup.
    pub async fn reserve_unsigned_request(
        &self,
        entity_id: &str,
        expected_acs: &str,
        request_id: &str,
    ) -> Result<bool, DomainError> {
        validate_request_id(entity_id, request_id)?;
        let id_hash: [u8; 32] = Sha256::digest(request_id.as_bytes()).into();
        let result = sqlx::query(
            "insert into saml_authn_request_replays
                 (tenant_id, sp_entity_id, request_id_hash, expires_at)
             select tenant_id, entity_id, $3, now() + interval '10 minutes'
               from saml_sp_trusts
              where tenant_id = $1 and entity_id = $2
                and acs_url = $4 and allow_unsigned_requests = true
              on conflict (tenant_id, sp_entity_id, request_id_hash) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(entity_id)
        .bind(id_hash.as_slice())
        .bind(expected_acs)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Reserves a verified HTTP-Redirect request only while its exact ACS and
    /// public key remain pinned. The signature is checked by the server before
    /// this call; this adapter never accepts caller XML or a dynamic key URL.
    pub async fn reserve_signed_request(
        &self,
        entity_id: &str,
        expected_acs: &str,
        expected_key_der: &[u8],
        request_id: &str,
    ) -> Result<bool, DomainError> {
        validate_request_id(entity_id, request_id)?;
        let id_hash: [u8; 32] = Sha256::digest(request_id.as_bytes()).into();
        let result = sqlx::query(
            "insert into saml_authn_request_replays
                 (tenant_id, sp_entity_id, request_id_hash, expires_at)
             select tenant_id, entity_id, $3, now() + interval '10 minutes'
               from saml_sp_trusts
              where tenant_id = $1 and entity_id = $2
                and acs_url = $4 and redirect_signing_public_key_der = $5
              on conflict (tenant_id, sp_entity_id, request_id_hash) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(entity_id)
        .bind(id_hash.as_slice())
        .bind(expected_acs)
        .bind(expected_key_der)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }
}

fn validate_request_id(entity_id: &str, request_id: &str) -> Result<(), DomainError> {
    if entity_id.is_empty()
        || entity_id.len() > 1024
        || request_id.len() > 128
        || !request_id.starts_with('_')
        || !request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(DomainError::invalid(
            "saml.request_id",
            "invalid request identifier",
        ));
    }
    Ok(())
}

fn validate(entity_id: &str, acs_url: &str) -> Result<(), DomainError> {
    if entity_id.is_empty()
        || entity_id.len() > 1024
        || entity_id.chars().any(char::is_control)
        || acs_url.len() > 2048
    {
        return Err(DomainError::invalid("saml.sp", "invalid SP trust"));
    }
    let url =
        Url::parse(acs_url).map_err(|_| DomainError::invalid("saml.sp", "invalid SP trust"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || acs_url.chars().any(char::is_control)
    {
        return Err(DomainError::invalid("saml.sp", "invalid SP trust"));
    }
    Ok(())
}
