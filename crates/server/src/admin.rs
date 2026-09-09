//! Wiring the admin API to this deployment.
//!
//! `asterius-admin-api` reaches everything through one port,
//! [`asterius_admin_api::AdminBackend`], because it may not depend on `sqlx`
//! (`scripts/check-layering.sh`). This is the implementation, and it is
//! deliberately thin: every method either opens a tenant scope on the store or
//! hands back a handle the composition root already built.
//!
//! # The tenant repository is passed in, not constructed here
//!
//! [`Deployment::tenants`] is an `Arc<dyn TenantRepository>` given to
//! [`Deployment::new`] by `main`, which is holding `ProvisionedTenants` — the
//! decorator that makes writing a tenant and provisioning its signing keys one
//! step (`ast-qa3`). Building a `PgTenantRepository` here instead would be
//! quietly correct-looking and would create tenants with no active key, which
//! then refuse every client registration. The field type is the port for that
//! reason: this module *cannot* reach the bare adapter, because it is never
//! handed one.

use asterius_admin_api::{AdminBackend, ClientAddress};
use asterius_domain::ports::TenantRepository;
use asterius_domain::{
    AuditSink, DomainError, RateLimitStore, ReplayGuard, Role, Session, SessionRepository as _,
    TenantId, UserId,
};
use asterius_store_pg::{PgAuditSink, PgRateLimitStore, PgReplayGuard, PgRoleRepository, Store};
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

use crate::tenancy::TenantDirectory;

/// This deployment, as the admin API sees it.
#[derive(Clone)]
pub struct Deployment {
    store: Store,
    tenants: Arc<dyn TenantRepository>,
    directory: TenantDirectory,
}

impl std::fmt::Debug for Deployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deployment").finish_non_exhaustive()
    }
}

impl Deployment {
    /// Binds the admin API to the handles the composition root already holds.
    ///
    /// `tenants` must be the process's `dyn TenantRepository` — the
    /// `ProvisionedTenants` one — and not a repository built here. See the
    /// module documentation for what goes wrong otherwise.
    #[must_use]
    pub const fn new(
        store: Store,
        tenants: Arc<dyn TenantRepository>,
        directory: TenantDirectory,
    ) -> Self {
        Self {
            store,
            tenants,
            directory,
        }
    }
}

#[async_trait::async_trait]
impl AdminBackend for Deployment {
    async fn session(
        &self,
        tenant: &TenantId,
        id_digest: &str,
    ) -> Result<Option<Session>, DomainError> {
        self.store
            .scope(tenant.clone())
            .sessions()
            .find(id_digest)
            .await
    }

    async fn roles(&self, tenant: &TenantId, user: UserId) -> Result<Vec<Role>, DomainError> {
        let roles = PgRoleRepository::new(self.store.pool().clone(), tenant.clone())
            .roles_of(user)
            .await?;
        Ok(roles.into_iter().map(|granted| granted.role).collect())
    }

    fn tenants(&self) -> Arc<dyn TenantRepository> {
        Arc::clone(&self.tenants)
    }

    fn audit(&self) -> Arc<dyn AuditSink> {
        Arc::new(PgAuditSink::new(self.store.pool().clone()))
    }

    fn rate_limits(&self) -> Arc<dyn RateLimitStore> {
        Arc::new(PgRateLimitStore::new(self.store.pool().clone()))
    }

    fn replay(&self) -> Arc<dyn ReplayGuard> {
        Arc::new(PgReplayGuard::new(self.store.pool().clone()))
    }

    fn tenant_directory_changed(&self) {
        self.directory.invalidate();
    }
}

/// Copies the resolved client address into the extension the admin API reads.
///
/// Two types for one value, because the *resolution* — socket peer plus the
/// trusted proxy set, never a header at face value — belongs to this crate and
/// the admin API may not depend on it. This layer is where they meet, and it
/// is a copy rather than a second resolution so that the two can never
/// disagree about which address a request came from.
///
/// A request whose address was never resolved gets `None`, which the limiter
/// admits: refusing every request from a deployment whose proxy configuration
/// is wrong would turn a misconfiguration into an outage of the surface an
/// operator would use to fix it.
pub async fn client_address_layer(mut request: Request, next: Next) -> Response {
    let resolved = request
        .extensions()
        .get::<crate::http::forwarded::ClientAddr>()
        .map(|client| client.ip);
    request.extensions_mut().insert(ClientAddress(resolved));
    next.run(request).await
}
