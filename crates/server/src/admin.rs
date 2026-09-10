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

use asterius_admin_api::clients::RegistrationGate;
use asterius_admin_api::{AdminBackend, ClientAddress};
use asterius_domain::keys::KeyAdministration;
use asterius_domain::ports::PasskeyRepository as _;
use asterius_domain::ports::{
    ClientAdministration, JwksFetcher, TenantRepository, TenantSettingsRepository,
};
use asterius_domain::{
    AuditSink, Capabilities, Client, ClientId, ClientMetadataError, ClientRegistration,
    DomainError, PasskeyEnrolment, RateLimitStore, ReplayGuard, Role, Session,
    SessionRepository as _, TenantId, UserId,
};

use crate::http::register::RegistrationPolicy;
use crate::outbound::sector;
use asterius_store_pg::{
    PgAuditSink, PgRateLimitStore, PgReplayGuard, PgRoleRepository, PgTenantSettings, Store,
};
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

use crate::tenancy::TenantDirectory;
use crate::tenant_settings::SettingsDirectory;

/// This deployment, as the admin API sees it.
#[derive(Clone)]
pub struct Deployment {
    store: Store,
    tenants: Arc<dyn TenantRepository>,
    keys: Arc<dyn KeyAdministration>,
    directory: TenantDirectory,
    settings: SettingsDirectory,
    capabilities: Capabilities,
    registration: RegistrationPolicy,
    outbound: Arc<dyn JwksFetcher>,
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
    ///
    /// `keys` is the process's `TenantKeyStore`, for a sharper version of the
    /// same reason: it holds the key-encryption key this deployment was started
    /// with, and a repository assembled here would seal a rotated key under
    /// whatever KEK this module could reach. The failure would be a key that
    /// does not decrypt on the next boot — after the rotation, on somebody
    /// else's shift.
    ///
    /// `outbound` must be the process's one [`JwksFetcher`] for the reason
    /// ADR-0006 gives: it is the only object in this deployment allowed to
    /// dereference a URL somebody else wrote, and the console registering a
    /// client is one of the two callers that has to.
    ///
    /// Takes one struct rather than eight arguments, so that a caller cannot
    /// transpose two handles of the same type — `Arc<dyn TenantRepository>` and
    /// `Arc<dyn JwksFetcher>` are different, but a future seventh and eighth
    /// may not be.
    #[must_use]
    pub fn new(parts: DeploymentParts) -> Self {
        Self {
            store: parts.store,
            tenants: parts.tenants,
            keys: parts.keys,
            directory: parts.directory,
            settings: parts.settings,
            capabilities: parts.capabilities,
            registration: parts.registration,
            outbound: parts.outbound,
        }
    }
}

/// What [`Deployment::new`] needs, named rather than ordered.
pub struct DeploymentParts {
    /// The connection pool every tenant scope is opened on.
    pub store: Store,
    /// The process's `dyn TenantRepository`, which is `ProvisionedTenants`.
    pub tenants: Arc<dyn TenantRepository>,
    /// The process's `TenantKeyStore`, holding this deployment's KEK.
    pub keys: Arc<dyn KeyAdministration>,
    /// The routing snapshot, invalidated when a tenant is written.
    pub directory: TenantDirectory,
    /// The settings cache, invalidated when a flag changes.
    pub settings: SettingsDirectory,
    /// What this build offers, as the protocol endpoints see it. The same
    /// value, so that the console and `POST /register` validate a registration
    /// document against the same set.
    pub capabilities: Capabilities,
    /// Who dynamic client registration admits.
    pub registration: RegistrationPolicy,
    /// ADR-0006's single outbound path.
    pub outbound: Arc<dyn JwksFetcher>,
}

impl std::fmt::Debug for DeploymentParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeploymentParts").finish_non_exhaustive()
    }
}

/// This deployment's clients, as the admin API's port sees them.
///
/// A type of its own rather than three more methods on [`Deployment`], because
/// the admin API takes a `dyn ClientAdministration` handle: the object behind
/// it is what a handler can reach, and this one can reach a tenant's clients
/// and the outbound fetcher and nothing else.
#[derive(Clone)]
struct DeploymentClients {
    store: Store,
    capabilities: Capabilities,
    outbound: Arc<dyn JwksFetcher>,
}

impl std::fmt::Debug for DeploymentClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeploymentClients").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl ClientAdministration for DeploymentClients {
    async fn list(&self, tenant: &TenantId) -> Result<Vec<Client>, DomainError> {
        self.store
            .scope(tenant.clone())
            .clients(self.capabilities)
            .list()
            .await
    }

    async fn find(
        &self,
        tenant: &TenantId,
        client_id: &ClientId,
    ) -> Result<Option<Client>, DomainError> {
        self.store
            .scope(tenant.clone())
            .clients(self.capabilities)
            .find(client_id)
            .await
    }

    async fn create(&self, client: &Client) -> Result<Client, DomainError> {
        let clients = self
            .store
            .scope(client.tenant.clone())
            .clients(self.capabilities);

        // `upsert` is a create-or-replace, and creation must never be a
        // replacement: it would retire a live client's keys and redirect URIs
        // on a repeated call. The identifier was drawn from 128 bits a
        // moment ago, so this reads as a guard against a bug rather than
        // against a collision — and it is a guard the caller cannot forget,
        // because it is on this side of the port.
        if clients.find(&client.id).await?.is_some() {
            return Err(DomainError::Conflict(
                "a client already exists under this client_id".to_owned(),
            ));
        }
        clients.upsert(client).await?;

        // Read back rather than returned: RFC 7591 §3.2.1's "all registered
        // metadata about this client" is what the row holds after defaults and
        // triggers, not what went in.
        clients.find(&client.id).await?.ok_or(DomainError::NotFound)
    }

    async fn replace(&self, client: &Client) -> Result<Client, DomainError> {
        self.store
            .scope(client.tenant.clone())
            .clients(self.capabilities)
            .replace(client)
            .await
    }

    async fn verify_sector(
        &self,
        registration: &ClientRegistration,
    ) -> Result<(), ClientMetadataError> {
        // The same call `POST /register` makes, through the same adapter: the
        // console cannot register a client whose sector dynamic registration
        // would have refused, because there is one implementation of the check.
        sector::verify(self.outbound.as_ref(), registration).await
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

    async fn end_session(
        &self,
        tenant: &TenantId,
        id_digest: &str,
        reason: asterius_domain::entities::session::SessionRevocation,
        now: time::OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.store
            .scope(tenant.clone())
            .sessions()
            .revoke(id_digest, reason, now)
            .await
    }

    async fn roles(&self, tenant: &TenantId, user: UserId) -> Result<Vec<Role>, DomainError> {
        let roles = PgRoleRepository::new(self.store.pool().clone(), tenant.clone())
            .roles_of(user)
            .await?;
        Ok(roles.into_iter().map(|granted| granted.role).collect())
    }

    /// Whether this user has an enabled passkey (`ast-895`).
    ///
    /// `credential_ids` is the read `excludeCredentials` already uses, and it
    /// filters `disabled_at is null` — which is the behaviour this rule wants
    /// and not a coincidence to be relied on quietly: a passkey blocked for a
    /// counter regression cannot be presented, so counting it would leave the
    /// admin holding a credential the server refuses.
    async fn passkey_enrolment(
        &self,
        tenant: &TenantId,
        user: UserId,
    ) -> Result<PasskeyEnrolment, DomainError> {
        let credentials = self
            .store
            .scope(tenant.clone())
            .passkeys()
            .credential_ids(&user)
            .await?;

        Ok(if credentials.is_empty() {
            PasskeyEnrolment::None
        } else {
            PasskeyEnrolment::Enrolled
        })
    }

    fn tenants(&self) -> Arc<dyn TenantRepository> {
        Arc::clone(&self.tenants)
    }

    fn tenant_settings(&self) -> Arc<dyn TenantSettingsRepository> {
        Arc::new(PgTenantSettings::new(self.store.pool().clone()))
    }

    fn keys(&self) -> Arc<dyn KeyAdministration> {
        Arc::clone(&self.keys)
    }

    fn clients(&self) -> Arc<dyn ClientAdministration> {
        Arc::new(DeploymentClients {
            store: self.store.clone(),
            capabilities: self.capabilities,
            outbound: Arc::clone(&self.outbound),
        })
    }

    fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    fn registration_gate(&self) -> RegistrationGate {
        RegistrationGate {
            // The label the policy already carries into the audit trail, so a
            // console and a trail cannot describe one deployment differently.
            mode: self.registration.as_str(),
            configured_tokens: match &self.registration {
                RegistrationPolicy::Gated(tokens) => tokens.len(),
                // Not "how many strings are in the file": a closed or open
                // endpoint honours no initial access token at all, whatever the
                // configuration happens to hold beside it.
                RegistrationPolicy::Closed | RegistrationPolicy::Open => 0,
            },
        }
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
        // The settings cache too, and in the same call: a feature flag is
        // published in the discovery document, so an administrator who has
        // just switched one off will look there to check.
        self.settings.invalidate();
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
