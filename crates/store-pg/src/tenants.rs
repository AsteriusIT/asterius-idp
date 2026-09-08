//! The tenant repository.

use crate::error::to_domain_error;
use asterius_domain::ports::TenantRepository;
use asterius_domain::{DomainError, Issuer, Tenant, TenantId, TenantStatus};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// `TenantRepository` over PostgreSQL.
#[derive(Debug, Clone)]
pub struct PgTenantRepository {
    pool: PgPool,
}

impl PgTenantRepository {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// One row of `tenants`, before it becomes an entity.
struct Row {
    tenant_id: String,
    issuer: String,
    custom_host: Option<String>,
    display_name: String,
    status: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Row {
    /// Converts a row into an entity, re-validating what the schema cannot
    /// express.
    ///
    /// The issuer is parsed again on the way out even though it was
    /// canonicalised on the way in. Rows get edited by hand during incidents,
    /// and an issuer that is no longer canonical would silently produce `iss`
    /// claims that clients reject by string comparison — better to fail loudly
    /// here than to mint tokens nobody accepts.
    fn into_entity(self) -> Result<Tenant, DomainError> {
        let issuer = Issuer::parse(&self.issuer)
            .map_err(|e| DomainError::invalid("issuer", e.to_string()))?;
        let status = match self.status.as_str() {
            "active" => TenantStatus::Active,
            "disabled" => TenantStatus::Disabled,
            other => return Err(DomainError::invalid("status", format!("unknown: {other}"))),
        };
        Ok(Tenant {
            id: TenantId::new(self.tenant_id),
            issuer,
            custom_host: self.custom_host,
            display_name: self.display_name,
            status,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[async_trait::async_trait]
impl TenantRepository for PgTenantRepository {
    async fn find_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, DomainError> {
        let row = sqlx::query_as!(
            Row,
            "select tenant_id, issuer, custom_host, display_name, status, created_at, updated_at
             from tenants
             where tenant_id = $1",
            id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(Row::into_entity).transpose()
    }

    async fn find_by_issuer(&self, issuer: &Issuer) -> Result<Option<Tenant>, DomainError> {
        let row = sqlx::query_as!(
            Row,
            "select tenant_id, issuer, custom_host, display_name, status, created_at, updated_at
             from tenants
             where issuer = $1",
            issuer.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(Row::into_entity).transpose()
    }

    async fn find_by_host(&self, host: &str) -> Result<Option<Tenant>, DomainError> {
        let row = sqlx::query_as!(
            Row,
            "select tenant_id, issuer, custom_host, display_name, status, created_at, updated_at
             from tenants
             where custom_host = $1",
            host
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(Row::into_entity).transpose()
    }

    async fn list(&self) -> Result<Vec<Tenant>, DomainError> {
        sqlx::query_as!(
            Row,
            "select tenant_id, issuer, custom_host, display_name, status, created_at, updated_at
             from tenants
             order by tenant_id"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?
        .into_iter()
        .map(Row::into_entity)
        .collect()
    }

    async fn upsert(&self, tenant: &Tenant) -> Result<(), DomainError> {
        sqlx::query!(
            "insert into tenants (tenant_id, issuer, custom_host, display_name, status)
             values ($1, $2, $3, $4, $5)
             on conflict (tenant_id) do update
             set issuer = excluded.issuer,
                 custom_host = excluded.custom_host,
                 display_name = excluded.display_name,
                 status = excluded.status",
            tenant.id.as_str(),
            tenant.issuer.as_str(),
            tenant.custom_host.as_deref(),
            tenant.display_name,
            tenant.status.as_str()
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(to_domain_error)
    }

    async fn delete(&self, id: &TenantId) -> Result<(), DomainError> {
        let result = sqlx::query!("delete from tenants where tenant_id = $1", id.as_str())
            .execute(&self.pool)
            .await
            .map_err(to_domain_error)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }
}
