//! The tenant repository.
//!
//! Creating a tenant does two things, and they commit together: it writes the
//! `tenants` row, and it gives the tenant the pairwise salt every `sub` it will
//! ever issue is derived under. The salt needs a key-encryption key, which is
//! why this repository holds one — see [`crate::salts`] for why the salt is key
//! material and why it is written exactly once.

use crate::error::to_domain_error;
use crate::salts;
use asterius_domain::ports::TenantRepository;
use asterius_domain::{DomainError, Issuer, RefreshPolicy, Tenant, TenantId, TenantStatus};
use asterius_jose::Kek;
use sqlx::postgres::PgPool;
use std::sync::Arc;
use time::OffsetDateTime;

/// `TenantRepository` over PostgreSQL.
#[derive(Clone)]
pub struct PgTenantRepository {
    pool: PgPool,
    kek: Arc<dyn Kek>,
}

impl std::fmt::Debug for PgTenantRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The KEK's id is derived from the material and reveals nothing about
        // it, and it is the one field an operator debugging "cannot decrypt"
        // wants to see.
        f.debug_struct("PgTenantRepository")
            .field("kek", &self.kek.id())
            .finish_non_exhaustive()
    }
}

impl PgTenantRepository {
    /// Wraps a pool and the key-encryption key a new tenant's salt is sealed
    /// under.
    #[must_use]
    pub const fn new(pool: PgPool, kek: Arc<dyn Kek>) -> Self {
        Self { pool, kek }
    }
}

/// One row of `tenants`, before it becomes an entity.
struct Row {
    tenant_id: String,
    issuer: String,
    custom_host: Option<String>,
    display_name: String,
    default_resource: String,
    status: String,
    /// Per-tenant policy. Only `refresh` is read today; the column is the one
    /// place a tenant's policy lives, so a reader takes the whole document and
    /// picks the member it understands.
    settings: serde_json::Value,
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
        // A stored refresh policy that no longer parses fails the read rather
        // than falling back to the defaults, for the reason the issuer above
        // is re-parsed: a tenant whose `bind_to_dpop_key` quietly reverted to
        // this file's idea of a default is a security setting an operator
        // believes is in force and is not.
        let refresh = RefreshPolicy::from_json(self.settings.get("refresh"))
            .map_err(|e| DomainError::invalid("settings.refresh", e.to_string()))?;
        Ok(Tenant {
            id: TenantId::new(self.tenant_id),
            refresh,
            issuer,
            custom_host: self.custom_host,
            display_name: self.display_name,
            default_resource: self.default_resource,
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
            "select tenant_id, issuer, custom_host, display_name, default_resource, status,
                    settings, created_at, updated_at
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
            "select tenant_id, issuer, custom_host, display_name, default_resource, status,
                    settings, created_at, updated_at
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
            "select tenant_id, issuer, custom_host, display_name, default_resource, status,
                    settings, created_at, updated_at
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
            "select tenant_id, issuer, custom_host, display_name, default_resource, status,
                    settings, created_at, updated_at
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

    /// Creates or updates a tenant, and gives a new one its pairwise salt.
    ///
    /// One transaction, because a tenant that exists without a salt cannot mint
    /// a subject identifier and therefore cannot issue an `id_token` — a state
    /// that would be created by a crash between two statements and would look,
    /// from the outside, like a tenant that simply does not work. The salt
    /// write is an insert that yields to whatever is already there, so updating
    /// a tenant never disturbs the salt it was created with.
    async fn upsert(&self, tenant: &Tenant) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        // `settings` is merged rather than replaced: `refresh` is the only
        // member this server understands today, and an upsert that wrote the
        // whole document would silently drop whatever a later story — or an
        // operator — put beside it. `||` on `jsonb` is a shallow merge, which
        // is what is wanted here: the `refresh` member is replaced whole,
        // because a policy read half from the file and half from the row is
        // not a policy anybody wrote.
        sqlx::query!(
            "insert into tenants
                 (tenant_id, issuer, custom_host, display_name, default_resource, status,
                  settings)
             values ($1, $2, $3, $4, $5, $6, jsonb_build_object('refresh', $7::jsonb))
             on conflict (tenant_id) do update
             set issuer = excluded.issuer,
                 custom_host = excluded.custom_host,
                 display_name = excluded.display_name,
                 default_resource = excluded.default_resource,
                 status = excluded.status,
                 settings = tenants.settings || excluded.settings",
            tenant.id.as_str(),
            tenant.issuer.as_str(),
            tenant.custom_host.as_deref(),
            tenant.display_name,
            tenant.default_resource,
            tenant.status.as_str(),
            tenant.refresh.to_json(),
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        salts::ensure(&mut *transaction, &tenant.id, self.kek.as_ref()).await?;

        transaction.commit().await.map_err(to_domain_error)
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
