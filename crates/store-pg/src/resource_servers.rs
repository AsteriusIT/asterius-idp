//! One tenant's registered resource servers, over `PostgreSQL` (RFC 8707).
//!
//! # These are runtime queries, not `query!`
//!
//! The same trade [`crate::tenant_settings`] states, and for the same reason:
//! `sqlx::query!` checks a statement against a live database at compile time
//! and records the result in `.sqlx/`, so a statement added with it cannot be
//! compiled without a migrated database to hand. The statements here are a
//! single-table read and a single-row upsert over a table this crate owns
//! outright, and what compile-time checking would catch is caught by the
//! database tests in `crates/store-pg/tests/database.rs`.

use crate::error::to_domain_error;
use asterius_domain::ports::ResourceServerRepository;
use asterius_domain::{DomainError, ResourceIdentifier, ResourceServer, TenantId};
use sqlx::Row as _;
use sqlx::postgres::PgPool;
use time::Duration;

/// [`ResourceServerRepository`] over `PostgreSQL`, scoped to one tenant.
#[derive(Debug, Clone)]
pub struct PgResourceServers {
    pool: PgPool,
    tenant: TenantId,
}

impl PgResourceServers {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Registers a resource server, or replaces the one already registered
    /// under this identifier.
    ///
    /// The administrative API for this is `ast-gxh.7`'s follow-up; until it
    /// exists an operator registers a resource server with SQL, and this is
    /// what provisioning and the tests use so that the shape of the row is
    /// decided in one place rather than in every caller's `insert`.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails, which includes the
    /// schema's own refusal of an identifier that is not an absolute,
    /// fragment-free URI.
    pub async fn register(&self, server: &ResourceServer) -> Result<(), DomainError> {
        let scopes: Option<Vec<String>> = server
            .scopes
            .as_ref()
            .map(|scopes| scopes.iter().cloned().collect());
        let lifetime: Option<i32> = server
            .default_token_lifetime
            .and_then(|d| i32::try_from(d.whole_seconds()).ok())
            .filter(|seconds| *seconds > 0);

        sqlx::query(
            "insert into resource_servers
                 (tenant_id, identifier, scopes, token_lifetime_seconds)
             values ($1, $2, $3, $4)
             on conflict (tenant_id, identifier) do update
             set scopes = excluded.scopes,
                 token_lifetime_seconds = excluded.token_lifetime_seconds",
        )
        .bind(self.tenant.as_str())
        .bind(server.identifier.as_str())
        .bind(scopes)
        .bind(lifetime)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    /// Withdraws a resource server.
    ///
    /// Returns whether a row was there to withdraw. A withdrawn identifier
    /// stops being a legal `resource` immediately; tokens already minted for
    /// it keep their `aud`, because a token is a statement about the moment it
    /// was issued.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the delete fails.
    pub async fn withdraw(&self, identifier: &str) -> Result<bool, DomainError> {
        let affected =
            sqlx::query("delete from resource_servers where tenant_id = $1 and identifier = $2")
                .bind(self.tenant.as_str())
                .bind(identifier)
                .execute(&self.pool)
                .await
                .map_err(to_domain_error)?
                .rows_affected();
        Ok(affected > 0)
    }
}

#[async_trait::async_trait]
impl ResourceServerRepository for PgResourceServers {
    async fn list(&self) -> Result<Vec<ResourceServer>, DomainError> {
        let rows = sqlx::query(
            "select identifier, scopes, token_lifetime_seconds
               from resource_servers
              where tenant_id = $1
              order by identifier",
        )
        .bind(self.tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let mut servers = Vec::with_capacity(rows.len());
        for row in rows {
            let identifier: String = row.try_get("identifier").map_err(to_domain_error)?;
            let scopes: Option<Vec<String>> = row.try_get("scopes").map_err(to_domain_error)?;
            let lifetime: Option<i32> = row
                .try_get("token_lifetime_seconds")
                .map_err(to_domain_error)?;
            // A stored row that is not a resource indicator fails the read
            // rather than being skipped: an audience this server would refuse
            // to issue is an audience it must not quietly stop offering
            // either, and the difference between the two is what an operator
            // would spend an afternoon on.
            let identifier = ResourceIdentifier::parse(&identifier).map_err(|_| {
                DomainError::invalid(
                    "resource_servers.identifier",
                    "a registered resource server is not a resource indicator",
                )
            })?;
            servers.push(ResourceServer {
                identifier,
                scopes: scopes.map(|scopes| scopes.into_iter().collect()),
                default_token_lifetime: lifetime.map(|s| Duration::seconds(i64::from(s))),
            });
        }
        Ok(servers)
    }
}
