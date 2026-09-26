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
    pub async fn provision(&self, entity_id: &str, acs_url: &str) -> Result<bool, DomainError> {
        validate(entity_id, acs_url)?;
        let result = sqlx::query(
            "insert into saml_sp_trusts (tenant_id, entity_id, acs_url)
             values ($1, $2, $3)
             on conflict (tenant_id, entity_id) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(entity_id)
        .bind(acs_url)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Lists only this tenant's exact SP trust entries.
    pub async fn list(&self) -> Result<Vec<SamlSp>, DomainError> {
        let rows: Vec<(String, String, OffsetDateTime)> = sqlx::query_as(
            "select entity_id, acs_url, created_at
               from saml_sp_trusts where tenant_id = $1 order by entity_id",
        )
        .bind(self.tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(rows
            .into_iter()
            .map(|(entity_id, acs_url, created_at)| SamlSp {
                entity_id,
                acs_url,
                created_at,
            })
            .collect())
    }

    /// Resolves only an exact entity ID in this tenant.
    pub async fn find(&self, entity_id: &str) -> Result<Option<SamlSp>, DomainError> {
        let row: Option<(String, String, OffsetDateTime)> = sqlx::query_as(
            "select entity_id, acs_url, created_at
               from saml_sp_trusts where tenant_id = $1 and entity_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(row.map(|(entity_id, acs_url, created_at)| SamlSp {
            entity_id,
            acs_url,
            created_at,
        }))
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
    /// Tombstones survive SP replacement and currently have no TTL cleanup.
    pub async fn reserve_request(
        &self,
        entity_id: &str,
        request_id: &str,
    ) -> Result<bool, DomainError> {
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
        let id_hash: [u8; 32] = Sha256::digest(request_id.as_bytes()).into();
        let result = sqlx::query(
            "insert into saml_authn_request_replays
                 (tenant_id, sp_entity_id, request_id_hash, expires_at)
             select tenant_id, entity_id, $3, now() + interval '10 minutes'
               from saml_sp_trusts
              where tenant_id = $1 and entity_id = $2
              on conflict (tenant_id, sp_entity_id, request_id_hash) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(entity_id)
        .bind(id_hash.as_slice())
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }
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
