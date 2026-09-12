//! One tenant's registered resource servers, over `PostgreSQL` (RFC 8707).
//!
//! # Checked against the schema, not just against the tests
//!
//! Every statement here is `sqlx::query!`, so the column list and the bind
//! types are checked against a migrated database at compile time and recorded
//! in `.sqlx/`. That matters more than usual for `scopes`: it is the one
//! `text[]` this crate binds, and a mismatch between it and `Option<Vec<..>>`
//! is the kind of error a runtime `query` only reports once a tenant has a
//! resource server registered.

use crate::error::to_domain_error;
use asterius_domain::ports::ResourceServerRepository;
use asterius_domain::{DomainError, ResourceIdentifier, ResourceServer, TenantId};
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

        let introspectors: Vec<String> = server
            .introspection_clients
            .iter()
            .map(|client| client.as_str().to_owned())
            .collect();

        sqlx::query!(
            "insert into resource_servers
                 (tenant_id, identifier, scopes, token_lifetime_seconds,
                  introspection_clients)
             values ($1, $2, $3, $4, $5)
             on conflict (tenant_id, identifier) do update
             set scopes = excluded.scopes,
                 token_lifetime_seconds = excluded.token_lifetime_seconds,
                 introspection_clients = excluded.introspection_clients",
            self.tenant.as_str(),
            server.identifier.as_str(),
            scopes.as_deref(),
            lifetime,
            &introspectors
        )
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
        let affected = sqlx::query!(
            "delete from resource_servers where tenant_id = $1 and identifier = $2",
            self.tenant.as_str(),
            identifier
        )
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
        let rows = sqlx::query!(
            "select identifier, scopes, token_lifetime_seconds, introspection_clients
               from resource_servers
              where tenant_id = $1
              order by identifier",
            self.tenant.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let mut servers = Vec::with_capacity(rows.len());
        for row in rows {
            let identifier = row.identifier;
            let scopes = row.scopes;
            let lifetime = row.token_lifetime_seconds;
            let introspectors = row.introspection_clients;
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
                // The column is `not null default '{}'`, so this is the empty
                // set for every row registered before RFC 7662 introspection
                // existed here — which is the posture that lets nobody but a
                // token's own client introspect it.
                introspection_clients: introspectors
                    .into_iter()
                    .map(asterius_domain::ClientId::new)
                    .collect(),
            });
        }
        Ok(servers)
    }
}
