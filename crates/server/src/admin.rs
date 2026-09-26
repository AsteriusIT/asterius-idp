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
use asterius_admin_api::{
    AdminBackend, AdminTokens, ClientAddress, PresentedToken, TokenPrincipal,
};
use asterius_domain::MailSender as _;
use asterius_domain::keys::{KeyAdministration, KeyStore};
use asterius_domain::ports::PasskeyRepository as _;
use asterius_domain::ports::RecoveryTokenStore as _;
use asterius_domain::ports::{
    ClientAdministration, ClientUrlFetcher, TenantRepository, TenantSettingsRepository,
};
use asterius_domain::{
    AuditSink, Capabilities, Client, ClientId, ClientMetadataError, ClientRegistration,
    ClientSecretUpdate, DomainError, GrantId, PasskeyEnrolment, RateLimitStore, ReplayGuard, Role,
    Session, SessionRepository as _, Tenant, TenantId, UserId,
};

use crate::http::register::RegistrationPolicy;
use crate::outbound::sector;
use asterius_store_pg::{
    PgAuditSink, PgRateLimitStore, PgReplayGuard, PgRoleRepository, PgTenantSettings, Store,
};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

use crate::tenancy::TenantDirectory;
use crate::tenant_settings::SettingsDirectory;
use crate::themes::ThemeDirectory;

/// Resolves the access tokens used by non-browser admin API clients.
///
/// Token verification is deliberately composed from the same access-token and
/// DPoP primitives as UserInfo and the other protected resources. The only
/// policy added here is specific to the admin API: its audience, its
/// `client_credentials` subject shape, and whether the issuer is the routed
/// tenant or the reserved tenant that may issue deployment-wide authority.
#[derive(Clone)]
pub struct AutomationTokens {
    status: Arc<dyn AutomationTokenStatus>,
    keys: Arc<dyn KeyStore>,
    dpop: Arc<crate::http::dpop::DpopEndpoint>,
    directory: TenantDirectory,
    reserved_tenant: Option<TenantId>,
}

impl std::fmt::Debug for AutomationTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutomationTokens")
            .field("reserved_tenant", &self.reserved_tenant)
            .finish_non_exhaustive()
    }
}

impl AutomationTokens {
    /// Uses the process's existing key, DPoP, tenant-directory and token-status
    /// handles. No verifier or replay cache is constructed per request.
    #[must_use]
    pub fn new(
        store: Store,
        keys: Arc<dyn KeyStore>,
        dpop: Arc<crate::http::dpop::DpopEndpoint>,
        directory: TenantDirectory,
        reserved_tenant: Option<TenantId>,
    ) -> Self {
        Self {
            status: Arc::new(PgAutomationTokenStatus { store }),
            keys,
            dpop,
            directory,
            reserved_tenant,
        }
    }

    async fn issuers(&self, routed: &Tenant) -> Result<Vec<Tenant>, DomainError> {
        let mut issuers = vec![routed.clone()];
        if let Some(reserved) = self
            .reserved_tenant
            .as_ref()
            .filter(|reserved| *reserved != &routed.id)
        {
            let tenant = self.directory.by_id(reserved).await?.ok_or_else(|| {
                DomainError::invalid(
                    "admin.tenant",
                    "the configured reserved tenant is not in the tenant directory",
                )
            })?;
            issuers.push((*tenant).clone());
        }
        Ok(issuers)
    }

    async fn verify(
        &self,
        routed: &Tenant,
        token: &str,
        now: time::OffsetDateTime,
    ) -> Result<Option<(asterius_jose::verify::Verified, Tenant)>, DomainError> {
        let mut unavailable = None;
        for issuer in self.issuers(routed).await? {
            let audience = format!(
                "{}{}",
                issuer.issuer.as_str(),
                asterius_admin_api::BASE_PATH
            );
            match crate::http::access_token::verify_for_audience(
                &issuer,
                self.keys.as_ref(),
                token,
                &audience,
                now,
            )
            .await
            {
                Ok(verified) => return Ok(Some((verified, issuer))),
                Err(crate::http::access_token::Rejected::Token(error)) => {
                    tracing::debug!(%error, "an admin API access token did not verify");
                }
                Err(crate::http::access_token::Rejected::Unavailable(error)) => {
                    unavailable = Some(error);
                }
            }
        }
        match unavailable {
            Some(error) => Err(error),
            None => Ok(None),
        }
    }

    async fn sender_constrained(
        &self,
        routed: &Tenant,
        presented: &PresentedToken<'_>,
        verified: &asterius_jose::verify::Verified,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let path = presented
            .url
            .strip_prefix(routed.issuer.as_str())
            .filter(|path| path.starts_with(asterius_admin_api::BASE_PATH));
        let Some(path) = path else {
            return Ok(false);
        };
        let Ok(method) = Method::from_bytes(presented.method.as_bytes()) else {
            return Ok(false);
        };
        let Ok(proof) = HeaderValue::from_str(presented.proof) else {
            return Ok(false);
        };
        let mut headers = HeaderMap::new();
        headers.insert(crate::http::dpop::HEADER, proof);

        crate::http::access_token::check_sender_constraint(
            &crate::http::access_token::Presented {
                tenant: routed,
                dpop: self.dpop.as_ref(),
                target: crate::http::dpop::ProofTarget::at_path(path),
                certificate: None,
                method: &method,
                headers: &headers,
                presented: asterius_oidc::userinfo::Presentation::Dpop(presented.token),
                now,
            },
            verified,
        )
        .await
        .map(|()| true)
        .or_else(|failure| match failure {
            crate::http::access_token::NotBound::Dpop(refusal)
                if refusal.status() == StatusCode::SERVICE_UNAVAILABLE =>
            {
                Err(DomainError::Storage(Box::new(std::io::Error::other(
                    "the DPoP replay store is unavailable",
                ))))
            }
            crate::http::access_token::NotBound::Refused
            | crate::http::access_token::NotBound::Dpop(_) => Ok(false),
        })
    }
}

#[async_trait::async_trait]
impl AdminTokens for AutomationTokens {
    async fn resolve(
        &self,
        routed: &Tenant,
        presented: &PresentedToken<'_>,
    ) -> Result<Option<TokenPrincipal>, DomainError> {
        let now = time::OffsetDateTime::now_utc();
        let Some((verified, issuer)) = self.verify(routed, presented.token, now).await? else {
            return Ok(None);
        };

        if !self
            .sender_constrained(routed, presented, &verified, now)
            .await?
        {
            return Ok(None);
        }

        let Some(jti) = verified.claim_str("jti") else {
            return Ok(None);
        };
        let Some(client) = verified.claim_str("client_id") else {
            return Ok(None);
        };
        // Automation is a client-credentials mode. A user-delegated token may
        // carry the same scope names but its `sub` is a person, and accepting
        // it here would turn a browser authorization into service authority.
        if verified.claim_str("sub") != Some(client) {
            return Ok(None);
        }

        if self.status.is_denylisted(&issuer.id, jti).await? {
            return Ok(None);
        }
        let client_id = ClientId::new(client.to_owned());
        let grant_id = verified
            .claim_str("grant_id")
            .map(|id| GrantId::new(id.to_owned()));
        let cutoff = self
            .status
            .revoked_before(&issuer.id, &client_id, grant_id.as_ref())
            .await?;
        if crate::http::access_token::withdrawn(&verified, cutoff) {
            return Ok(None);
        }

        let scopes = verified
            .claim_str("scope")
            .unwrap_or_default()
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect();
        let tenant = if self.reserved_tenant.as_ref() == Some(&issuer.id) {
            None
        } else {
            Some(issuer.id)
        };
        Ok(Some(TokenPrincipal {
            subject: client.to_owned(),
            tenant,
            scopes,
        }))
    }
}

#[async_trait::async_trait]
trait AutomationTokenStatus: std::fmt::Debug + Send + Sync {
    async fn is_denylisted(&self, tenant: &TenantId, jti: &str) -> Result<bool, DomainError>;

    async fn revoked_before(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        grant: Option<&GrantId>,
    ) -> Result<Option<time::OffsetDateTime>, DomainError>;
}

#[derive(Debug)]
struct PgAutomationTokenStatus {
    store: Store,
}

#[async_trait::async_trait]
impl AutomationTokenStatus for PgAutomationTokenStatus {
    async fn is_denylisted(&self, tenant: &TenantId, jti: &str) -> Result<bool, DomainError> {
        self.store
            .scope(tenant.clone())
            .grants()
            .is_denylisted(jti)
            .await
    }

    async fn revoked_before(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        grant: Option<&GrantId>,
    ) -> Result<Option<time::OffsetDateTime>, DomainError> {
        self.store
            .scope(tenant.clone())
            .grants()
            .revoked_before(client, grant)
            .await
    }
}

/// This deployment, as the admin API sees it.
#[derive(Clone)]
pub struct Deployment {
    rate_limit_policy: Option<(
        asterius_domain::LoginLimits,
        asterius_domain::EndpointLimits,
    )>,
    store: Store,
    tenants: Arc<dyn TenantRepository>,
    keys: Arc<dyn KeyAdministration>,
    directory: TenantDirectory,
    settings: SettingsDirectory,
    themes: ThemeDirectory,
    capabilities: Capabilities,
    registration: RegistrationPolicy,
    outbound: Arc<dyn ClientUrlFetcher>,
    outbox: Arc<dyn asterius_domain::outbox::DeadLetterQuery>,
    dead_letters: Arc<dyn asterius_domain::outbox::DeadLetterOperations>,
    kek: Arc<dyn asterius_jose::Kek>,
    signer: Arc<dyn asterius_domain::keys::Signer>,
    queue: Option<Arc<dyn asterius_domain::outbox::OutboxQueue>>,
    argon2: asterius_domain::Argon2Parameters,
    issuance: Option<Arc<crate::http::agent_issuance::IssuanceGuard>>,
    id_jag_trusts: Arc<crate::id_jag_trust::IdJagTrusts>,
}

impl std::fmt::Debug for Deployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deployment").finish_non_exhaustive()
    }
}

impl Deployment {
    /// Publishes the same ceilings enforced by the protocol and sign-in limiters.
    #[must_use]
    pub const fn with_rate_limit_policy(
        mut self,
        login: asterius_domain::LoginLimits,
        endpoints: asterius_domain::EndpointLimits,
    ) -> Self {
        self.rate_limit_policy = Some((login, endpoints));
        self
    }

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
    /// `outbound` must be the process's one [`ClientUrlFetcher`] for the reason
    /// ADR-0006 gives: it is the only object in this deployment allowed to
    /// dereference a URL somebody else wrote, and the console registering a
    /// client is one of the two callers that has to.
    ///
    /// Takes one struct rather than eight arguments, so that a caller cannot
    /// transpose two handles of the same type — `Arc<dyn TenantRepository>` and
    /// `Arc<dyn ClientUrlFetcher>` are different, but a future seventh and eighth
    /// may not be.
    #[must_use]
    pub fn new(parts: DeploymentParts) -> Self {
        Self {
            rate_limit_policy: None,
            store: parts.store,
            tenants: parts.tenants,
            keys: parts.keys,
            directory: parts.directory,
            settings: parts.settings,
            themes: parts.themes,
            capabilities: parts.capabilities,
            registration: parts.registration,
            outbound: parts.outbound,
            outbox: parts.outbox,
            dead_letters: parts.dead_letters,
            kek: parts.kek,
            signer: parts.signer,
            queue: parts.queue,
            argon2: parts.argon2,
            issuance: parts.issuance,
            id_jag_trusts: parts.id_jag_trusts,
        }
    }
}

/// What [`Deployment::new`] needs, named rather than ordered.
pub struct DeploymentParts {
    /// The connection pool every tenant scope is opened on.
    pub store: Store,
    /// Startup-validated upstream issuer/actor pins for ID-JAG mappings.
    pub id_jag_trusts: Arc<crate::id_jag_trust::IdJagTrusts>,
    /// The process's `dyn TenantRepository`, which is `ProvisionedTenants`.
    pub tenants: Arc<dyn TenantRepository>,
    /// The process's `TenantKeyStore`, holding this deployment's KEK.
    pub keys: Arc<dyn KeyAdministration>,
    /// The routing snapshot, invalidated when a tenant is written.
    pub directory: TenantDirectory,
    /// The settings cache, invalidated when a flag changes.
    pub settings: SettingsDirectory,
    /// Shared cache and repository for tenant branding.
    pub themes: ThemeDirectory,
    /// What this build offers, as the protocol endpoints see it. The same
    /// value, so that the console and `POST /register` validate a registration
    /// document against the same set.
    pub capabilities: Capabilities,
    /// Who dynamic client registration admits.
    pub registration: RegistrationPolicy,
    /// ADR-0006's single outbound path.
    pub outbound: Arc<dyn ClientUrlFetcher>,
    /// The process's `PgOutbox`, read-only, for the dead-letter screen.
    pub outbox: Arc<dyn asterius_domain::outbox::DeadLetterQuery>,
    /// The same `PgOutbox` as the operator's retry and drop (`ast-f7m.8`).
    ///
    /// The same object as `outbox` and `queue`, handed over as a third
    /// port for the reason those two are two: the admin API keeps the
    /// read-only view and the mutations on separate handles, and this is
    /// the one behind `admin.outbox:write`.
    pub dead_letters: Arc<dyn asterius_domain::outbox::DeadLetterOperations>,
    /// The key-encryption key the tenants' pairwise salts are sealed under.
    ///
    /// The process's, for the reason `keys` is the process's: a `sub` derived
    /// under a salt this module unsealed with a different KEK would be a
    /// different `sub`, and the logout token carrying it would name a person
    /// no relying party recognises.
    pub kek: Arc<dyn asterius_jose::Kek>,
    /// The signer the back-channel logout tokens are minted with — the same
    /// one the end-session endpoint uses, so a relying party resolves the key
    /// from the tenant's published JWKS either way.
    pub signer: Arc<dyn asterius_domain::keys::Signer>,
    /// The process's `PgOutbox` as a *queue*, for the logout tokens an
    /// administrative revocation sends (`ast-f7m.6`).
    ///
    /// Separate from `outbox` above, which is the read-only dead-letter view:
    /// one handle that could both read the backlog and write a delivery would
    /// give the dead-letter screen the authority to make this server POST to a
    /// URL, which is precisely what that port's documentation says it must not
    /// have.
    pub queue: Option<Arc<dyn asterius_domain::outbox::OutboxQueue>>,
    /// The cost an administratively created password is hashed at: the
    /// deployment's, so a console-created account is not cheaper to crack than
    /// one created at the recovery form.
    pub argon2: asterius_domain::Argon2Parameters,
    /// The protocol endpoints' issuance decision cache (`ast-lh3.10`).
    ///
    /// The *same* handle `ClientEndpoints` holds, so that an administrator who
    /// rewrites a tenant's policy empties the decisions the token endpoint is
    /// about to reuse. A second guard here would be a cache nobody
    /// invalidates. `None` where this deployment has no policy decision point.
    pub issuance: Option<Arc<crate::http::agent_issuance::IssuanceGuard>>,
}

impl std::fmt::Debug for DeploymentParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeploymentParts").finish_non_exhaustive()
    }
}

/// This deployment's SSF streams, as the admin API's port sees them
/// (`ast-f7m.8`).
///
/// A type of its own for the reason [`DeploymentClients`] is one: the
/// object behind the handle is what a handler can reach, and this one can
/// read and re-status a tenant's streams and sign a verification event, and
/// nothing else. The verification goes through the same
/// [`crate::ssf::SsfTransmitter`] the emitters use — same signer, same
/// queues — so the SET a receiver gets is signed by a key in the tenant's
/// published JWKS and delivered by the worker that delivers everything else.
/// The policy test bench's decision path (`ast-f7m.9`): the PDP, asked by
/// somebody who is not enforcing anything.
///
/// A type of its own for the reason [`DeploymentSsf`] is one — the handle is
/// what a handler can reach, and this one can resolve a subject's facts and
/// read a policy document, and nothing else. It cannot write a policy: the
/// admin route that does holds a separate handle over
/// [`asterius_domain::ports::PolicyStore`].
#[derive(Clone)]
struct DeploymentPolicyTrial {
    settings: crate::tenant_settings::SettingsDirectory,
    store: Store,
    kek: Arc<dyn asterius_jose::Kek>,
}

impl std::fmt::Debug for DeploymentPolicyTrial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeploymentPolicyTrial")
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl asterius_admin_api::backend::PolicyTrial for DeploymentPolicyTrial {
    /// What this tenant's stored rules decide about one request.
    ///
    /// Everything that makes the answer trustworthy lives in
    /// [`crate::http::access_evaluation::decide_without_enforcing`], which is
    /// the same code path the AuthZEN endpoints take once a PEP's credential
    /// has been checked: the facts are read here, never taken from the body,
    /// and the ladder is the deployment's.
    async fn decide(
        &self,
        tenant: &TenantId,
        request: &asterius_domain::policy::EvaluationRequest,
    ) -> Result<asterius_domain::policy::Decision, DomainError> {
        let engine = asterius_domain::policy::DeclarativeEngine::new(Arc::new(
            asterius_store_pg::PgPolicies::new(self.store.pool().clone()),
        ));
        let subjects =
            crate::http::protocol::StoredSubjects::of(&self.store, Arc::clone(&self.kek), tenant);
        crate::http::access_evaluation::decide_without_enforcing(
            &engine,
            &subjects,
            self.settings.for_tenant(tenant).await?.acr_policy(),
            tenant,
            request,
            time::OffsetDateTime::now_utc(),
        )
        .await
    }
}

#[derive(Debug, Clone)]
struct DeploymentIdJagBindings {
    store: Store,
    trusts: Arc<crate::id_jag_trust::IdJagTrusts>,
}

#[async_trait::async_trait]
impl asterius_admin_api::id_jag::IdJagBindings for DeploymentIdJagBindings {
    async fn bind(
        &self,
        tenant: &TenantId,
        binding: &asterius_admin_api::id_jag::SubjectBinding,
    ) -> Result<(), DomainError> {
        if !self
            .trusts
            .supports_issuer(tenant.as_str(), binding.issuer.as_str())
        {
            return Err(DomainError::NotFound);
        }
        self.store
            .scope(tenant.clone())
            .id_jag_redemption()
            .bind_subject(binding.issuer.as_str(), &binding.subject, binding.user)
            .await
    }

    async fn remove(
        &self,
        tenant: &TenantId,
        binding: &asterius_admin_api::id_jag::SubjectBinding,
    ) -> Result<bool, DomainError> {
        if !self
            .trusts
            .supports_issuer(tenant.as_str(), binding.issuer.as_str())
        {
            return Err(DomainError::NotFound);
        }
        self.store
            .scope(tenant.clone())
            .id_jag_redemption()
            .remove_subject(binding.issuer.as_str(), &binding.subject, binding.user)
            .await
    }
}

#[derive(Clone)]
struct DeploymentSsf {
    store: Store,
    tenants: Arc<dyn TenantRepository>,
    /// The process's signer: the same key the emitters sign with, so the
    /// verification SET verifies against the published JWKS.
    keys: Arc<dyn asterius_domain::keys::Signer>,
    kek: Arc<dyn asterius_jose::Kek>,
    capabilities: Capabilities,
}

impl std::fmt::Debug for DeploymentSsf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeploymentSsf").finish_non_exhaustive()
    }
}

impl DeploymentSsf {
    async fn receiver_peer(&self, tenant: &TenantId, peer: &ClientId) -> Result<(), DomainError> {
        let clients = self.store.scope(tenant.clone()).clients(self.capabilities);
        let Some(client) = clients.find(peer).await? else {
            return Err(DomainError::NotFound);
        };
        if !client.is_active()
            || !client
                .registration
                .scopes
                .contains(crate::http::ssf_receiver::RECEIVE_SCOPE)
        {
            return Err(DomainError::NotFound);
        }
        asterius_domain::Issuer::parse(peer.as_str()).map_err(|_| {
            DomainError::invalid("peer_client_id", "issuer must be an absolute URL")
        })?;
        Ok(())
    }

    /// Queues §8.1.5's stream-updated event on one stream, or says in the log
    /// why it could not.
    ///
    /// Never fails the caller: see [`SsfAdministration::set_status`] for why
    /// a status change outlives an announcement that could not be made.
    async fn announce(
        &self,
        tenant: &TenantId,
        subscription: &asterius_store_pg::Subscription,
        status: asterius_ssf::stream::StreamStatus,
        reason: Option<&str>,
        now: time::OffsetDateTime,
    ) {
        let Ok(Some(tenant_entity)) = self.tenants.find_by_id(tenant).await else {
            tracing::error!(tenant = %tenant, "cannot read a tenant to announce a stream update");
            return;
        };
        let scope = self.store.scope(tenant.clone());
        let clients = scope.clients(self.capabilities);
        let users = scope.users(Arc::clone(&self.kek));
        let queues = crate::outbox::PgSsfQueues::new(
            self.store.clone(),
            tenant.clone(),
            Arc::clone(&self.kek),
        );
        let transmitter = crate::ssf::SsfTransmitter {
            tenant,
            issuer: &tenant_entity.issuer,
            queues: &queues,
            clients: &clients,
            subjects: &users,
            signer: self.keys.as_ref(),
        };
        if let Err(error) = transmitter
            .announce_status(subscription, status, reason, now)
            .await
        {
            tracing::error!(
                %error,
                tenant = %tenant,
                stream = subscription.stream_id.as_str(),
                "a stream status change was not announced to its receiver",
            );
        }
    }
}

#[async_trait::async_trait]
impl asterius_admin_api::ssf::SsfAdministration for DeploymentSsf {
    async fn streams(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<asterius_admin_api::ssf::StreamSummary>, DomainError> {
        let overview = self
            .store
            .scope(tenant.clone())
            .ssf_streams(Arc::clone(&self.kek))
            .overview()
            .await?;
        Ok(overview
            .into_iter()
            .map(|stream| asterius_admin_api::ssf::StreamSummary {
                stream_id: stream.stream_id,
                receiver: stream.receiver,
                delivery_method: match stream.delivery {
                    asterius_store_pg::DeliveryMethod::Poll => asterius_ssf::stream::DELIVERY_POLL,
                    asterius_store_pg::DeliveryMethod::Push => asterius_ssf::stream::DELIVERY_PUSH,
                },
                events_requested: stream.events_requested,
                description: stream.description,
                created_at: stream.created_at,
                status: stream.stats.status,
                reason: stream.stats.reason,
                status_changed_at: stream.status_changed_at,
                delivered: stream.stats.delivered,
                failed: stream.stats.failed,
                queue_depth: stream.stats.queue_depth,
            })
            .collect())
    }

    async fn bind_receiver_subject(
        &self,
        tenant: &TenantId,
        peer: &ClientId,
        subject_key: &str,
        user: uuid::Uuid,
    ) -> Result<(), DomainError> {
        self.receiver_peer(tenant, peer).await?;
        let scope = self.store.scope(tenant.clone());
        if scope
            .users(Arc::clone(&self.kek))
            .find(UserId::new(user))
            .await?
            .is_none()
        {
            return Err(DomainError::NotFound);
        }
        scope
            .ssf_receiver()
            .bind_subject(peer.as_str(), subject_key, user)
            .await
    }

    async fn remove_receiver_subject(
        &self,
        tenant: &TenantId,
        peer: &ClientId,
        subject_key: &str,
        user: uuid::Uuid,
    ) -> Result<bool, DomainError> {
        self.receiver_peer(tenant, peer).await?;
        self.store
            .scope(tenant.clone())
            .ssf_receiver()
            .remove_subject(peer.as_str(), subject_key, user)
            .await
    }

    /// An operator's pause or re-enable, announced to the receiver as SSF 1.0
    /// §8.1.5 requires (`ast-0ju.5`).
    ///
    /// The order is the specification's and is the whole point of this
    /// method:
    ///
    /// > The Transmitter MUST send this event to the Receiver before the
    /// > stream is paused or disabled, and upon the stream being re-enabled.
    ///
    /// So a **pause** announces first and writes second — the SET is enqueued
    /// while the stream still accepts events, and the queue then holds it as
    /// §8.1.2 says a paused stream holds what it is handed, delivering it when
    /// the stream is enabled again. A **re-enable** writes first and announces
    /// second, so that the announcement leaves immediately rather than joining
    /// the backlog behind the very pause it ends.
    ///
    /// An announcement that cannot be queued is logged and does not stop the
    /// status change. An operator pausing a stream is usually pausing it
    /// *because* the receiver is unreachable, and a transmitter that refused
    /// to stop delivering until it had told the receiver it was stopping would
    /// be stuck exactly when stopping matters.
    async fn set_status(
        &self,
        tenant: &TenantId,
        stream: &asterius_ssf::stream::StreamId,
        status: asterius_ssf::stream::StreamStatus,
        reason: Option<&str>,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let scope = self.store.scope(tenant.clone());
        let streams = scope.ssf_streams(Arc::clone(&self.kek));
        // Read before the write, because a stream that is not there is not one
        // to announce and the console's 404 depends on the same answer.
        let Some(subscription) = streams.subscription(stream).await? else {
            return Ok(false);
        };

        let announce_first = !matches!(status, asterius_ssf::stream::StreamStatus::Enabled);
        if announce_first {
            self.announce(tenant, &subscription, status, reason, now)
                .await;
        }
        let changed = streams.set_status(stream, status, reason, now).await?;
        if changed && !announce_first {
            self.announce(tenant, &subscription, status, reason, now)
                .await;
        }
        Ok(changed)
    }

    async fn verify(
        &self,
        tenant: &TenantId,
        stream: &asterius_ssf::stream::StreamId,
        state: Option<&asterius_ssf::VerificationState>,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let scope = self.store.scope(tenant.clone());
        let Some(subscription) = scope
            .ssf_streams(Arc::clone(&self.kek))
            .subscription(stream)
            .await?
        else {
            return Ok(false);
        };
        let tenant_entity = self
            .tenants
            .find_by_id(tenant)
            .await?
            .ok_or(DomainError::NotFound)?;
        let clients = scope.clients(self.capabilities);
        let users = scope.users(Arc::clone(&self.kek));
        let queues = crate::outbox::PgSsfQueues::new(
            self.store.clone(),
            tenant.clone(),
            Arc::clone(&self.kek),
        );
        let transmitter = crate::ssf::SsfTransmitter {
            tenant,
            issuer: &tenant_entity.issuer,
            queues: &queues,
            clients: &clients,
            subjects: &users,
            signer: self.keys.as_ref(),
        };
        transmitter.verify(&subscription, state, now).await?;
        Ok(true)
    }
}

/// This deployment's clients, as the admin API's port sees them.
///
/// A type of its own rather than three more methods on [`Deployment`], because
/// the admin API takes a `dyn ClientAdministration` handle: the object behind
/// it is what a handler can reach, and this one can reach a tenant's clients
/// and the outbound fetcher and nothing else.
fn public_jwks_metadata_valid(set: &serde_json::Value) -> bool {
    let Some(keys) = set.get("keys").and_then(serde_json::Value::as_array) else {
        return false;
    };
    if keys.is_empty() {
        return false;
    }
    let mut kids = std::collections::BTreeSet::new();
    keys.iter().all(|key| {
        let kid = key.get("kid").and_then(serde_json::Value::as_str);
        let kty = key.get("kty").and_then(serde_json::Value::as_str);
        kid.is_some_and(|kid| !kid.is_empty() && kids.insert(kid.to_owned()))
            && kty.is_some_and(|kty| !kty.is_empty())
            && ["d", "p", "q", "dp", "dq", "qi", "k", "oth"]
                .iter()
                .all(|member| key.get(member).is_none())
    })
}

async fn issuer_health_checks(
    outbound: &dyn ClientUrlFetcher,
    issuer: &str,
) -> (
    serde_json::Value,
    serde_json::Value,
    Option<serde_json::Value>,
) {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let discovery = outbound
        .fetch(&discovery_url)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let discovery_matches = discovery
        .as_ref()
        .and_then(|document| document.get("issuer"))
        .and_then(serde_json::Value::as_str)
        == Some(issuer);
    let discovery_check = serde_json::json!({
        "name": "discovery_issuer",
        "status": if discovery_matches { "pass" } else { "fail" },
        "message": if discovery_matches {
            "The discovery document is reachable and its issuer exactly matches this tenant. Configure the client with this issuer and its discovery URL."
        } else {
            "The discovery document could not be fetched or its issuer did not exactly match this tenant. Check the public issuer URL, reverse-proxy routing, TLS, and discovery response."
        }
    });
    let jwks_uri = discovery
        .as_ref()
        .and_then(|document| document.get("jwks_uri"))
        .and_then(serde_json::Value::as_str);
    let jwks = match jwks_uri {
        Some(uri) => outbound
            .fetch(uri)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok()),
        None => None,
    };
    let keys_valid = jwks.as_ref().is_some_and(public_jwks_metadata_valid);
    let jwks_check = serde_json::json!({
        "name": "issuer_jwks",
        "status": if keys_valid { "pass" } else { "fail" },
        "message": if keys_valid {
            "The JWKS URI advertised by discovery is reachable and publishes public keys with unique IDs and key types."
        } else {
            "The JWKS URI advertised by discovery could not be fetched or has invalid public key metadata. Check discovery's jwks_uri and publish a valid public JWK Set."
        }
    });
    (discovery_check, jwks_check, discovery)
}

fn registration_health_checks(
    registration: &asterius_domain::ClientRegistration,
    discovery: Option<&serde_json::Value>,
) -> Vec<serde_json::Value> {
    let mut checks = vec![serde_json::json!({
        "name": "callbacks",
        "status": if registration.redirect_uris.is_empty() { "fail" } else { "pass" },
        "message": if registration.redirect_uris.is_empty() {
            "Register at least one exact callback URL allowed for this application type and make the application use the same URL."
        } else {
            "At least one callback is registered. Use the exact registered URL, including path and case; web callbacks use HTTPS and native loopback callbacks may use HTTP."
        }
    })];
    let auth_method = registration.token_endpoint_auth_method;
    let auth_supported = discovery
        .and_then(|document| document.get("token_endpoint_auth_methods_supported"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|methods| {
            methods
                .iter()
                .any(|method| method.as_str() == Some(auth_method.as_str()))
        });
    let auth_message = if auth_supported {
        match auth_method {
            asterius_domain::TokenEndpointAuthMethod::None => {
                "The client is public and uses PKCE S256 with DPoP-bound tokens instead of a client credential."
            }
            asterius_domain::TokenEndpointAuthMethod::PrivateKeyJwt => {
                "The client uses private_key_jwt. Confirm its signing key is available to the application and its public key is published."
            }
            asterius_domain::TokenEndpointAuthMethod::TlsClientAuth => {
                "The client uses tls_client_auth. Confirm the client certificate chains to this deployment's configured trust anchor."
            }
            asterius_domain::TokenEndpointAuthMethod::SelfSignedTlsClientAuth => {
                "The client uses self_signed_tls_client_auth. Confirm the certificate thumbprint matches the registered public key."
            }
            asterius_domain::TokenEndpointAuthMethod::ClientSecretBasic => {
                "This OIDC compatibility profile uses client_secret_basic. Keep the server-issued secret private and use the configured basic-auth method."
            }
        }
    } else {
        "The registered authentication method is not advertised by discovery. Choose a method from token_endpoint_auth_methods_supported and update the client."
    };
    checks.push(serde_json::json!({
        "name": "client_authentication",
        "status": if auth_supported { "pass" } else { "fail" },
        "message": auth_message,
    }));
    let dpop = registration.token_binding.is_dpop_bound();
    let mtls = registration.token_binding.is_certificate_bound();
    let dpop_supported = discovery
        .and_then(|document| document.get("dpop_signing_alg_values_supported"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|algorithms| !algorithms.is_empty());
    let mtls_supported = discovery
        .and_then(|document| document.get("tls_client_certificate_bound_access_tokens"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    let bearer_supported = registration.token_binding.is_bearer()
        && registration.compliance_profile == asterius_domain::ClientComplianceProfile::Oidc;
    let binding_supported =
        (dpop && dpop_supported) || (mtls && mtls_supported) || bearer_supported;
    let binding_message = if dpop && dpop_supported {
        "Access tokens are bound to DPoP. Discovery advertises supported proof algorithms; send a fresh proof for each protected request."
    } else if mtls && mtls_supported {
        "Access tokens are certificate bound. Discovery advertises mTLS-bound tokens; present the same trusted client certificate when using them."
    } else if bearer_supported {
        "This explicitly selected standard OIDC client uses bearer tokens. Prefer DPoP or mTLS where the client supports sender constraints."
    } else if dpop {
        "Discovery does not advertise DPoP proof algorithms. Check tenant protocol capability and DPoP configuration."
    } else if mtls {
        "Discovery does not advertise certificate-bound access tokens. Enable and configure mTLS for the tenant."
    } else {
        "This registration has no supported sender constraint. Select DPoP or mTLS for FAPI."
    };
    checks.push(serde_json::json!({
        "name": "sender_constraint",
        "status": if binding_supported { "pass" } else { "fail" },
        "message": binding_message,
    }));
    checks
}

async fn client_jwks_health_check(
    outbound: &dyn ClientUrlFetcher,
    registration: &asterius_domain::ClientRegistration,
) -> serde_json::Value {
    let jwks = match &registration.jwks {
        asterius_domain::JwksSource::Uri(uri) => outbound
            .fetch(uri)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok()),
        asterius_domain::JwksSource::Inline(value) => Some(value.clone()),
        asterius_domain::JwksSource::None => None,
    };
    let auth_method = registration.token_endpoint_auth_method;
    let client_jwks_required = matches!(
        auth_method,
        asterius_domain::TokenEndpointAuthMethod::PrivateKeyJwt
            | asterius_domain::TokenEndpointAuthMethod::SelfSignedTlsClientAuth
    ) || registration.request_object_signing_alg.is_some();
    let keys_valid = match &registration.jwks {
        asterius_domain::JwksSource::None => !client_jwks_required,
        _ => jwks.as_ref().is_some_and(public_jwks_metadata_valid),
    };
    let message = if matches!(registration.jwks, asterius_domain::JwksSource::None) {
        "No client JWK Set is needed for this registered authentication method."
    } else if keys_valid {
        "The registered public key set is reachable and has unique key IDs and key types without private key members."
    } else if matches!(registration.jwks, asterius_domain::JwksSource::Uri(_)) {
        "The registered public key URL could not be fetched or did not return a usable public JWK Set. Publish HTTPS JSON with unique kid and kty values; private key members must stay private."
    } else {
        "The registered public JWK Set is missing or unusable. Provide public keys with unique kid and kty values; keep private key members out of the registration."
    };
    serde_json::json!({
        "name": "public_jwks",
        "status": if keys_valid { "pass" } else { "fail" },
        "message": message,
    })
}

#[cfg(test)]
mod integration_health_tests {
    use super::public_jwks_metadata_valid;
    use serde_json::json;

    #[test]
    fn jwks_health_requires_nonempty_public_keys_with_unique_kids_and_types() {
        assert!(public_jwks_metadata_valid(&json!({"keys": [
            {"kty": "EC", "kid": "one", "crv": "P-256", "x": "x", "y": "y"},
            {"kty": "RSA", "kid": "two", "n": "n", "e": "AQAB"}
        ]})));
        assert!(!public_jwks_metadata_valid(&json!({"keys": []})));
        assert!(!public_jwks_metadata_valid(&json!({"keys": [
            {"kty": "EC", "kid": "same"}, {"kty": "RSA", "kid": "same"}
        ]})));
        assert!(!public_jwks_metadata_valid(&json!({"keys": [
            {"kty": "EC", "kid": "private", "d": "secret"}
        ]})));
    }
}

#[derive(Clone)]
struct DeploymentClients {
    store: Store,
    capabilities: Capabilities,
    outbound: Arc<dyn ClientUrlFetcher>,
    id_jag_trusts: Arc<crate::id_jag_trust::IdJagTrusts>,
}

impl std::fmt::Debug for DeploymentClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeploymentClients").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl ClientAdministration for DeploymentClients {
    fn id_jag_pinned(&self, tenant: &TenantId, client_id: &ClientId) -> bool {
        self.id_jag_trusts
            .supports_client(tenant.as_str(), client_id.as_str())
    }

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

    async fn integration_health(
        &self,
        tenant: &TenantId,
        client_id: &ClientId,
        issuer: &str,
    ) -> Result<serde_json::Value, DomainError> {
        let client = self
            .find(tenant, client_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        let (discovery_check, issuer_jwks_check, discovery) =
            issuer_health_checks(self.outbound.as_ref(), issuer).await;
        let mut checks = vec![discovery_check, issuer_jwks_check];
        checks.extend(registration_health_checks(
            &client.registration,
            discovery.as_ref(),
        ));
        checks.push(client_jwks_health_check(self.outbound.as_ref(), &client.registration).await);
        Ok(serde_json::json!({ "checks": checks }))
    }

    async fn create(
        &self,
        client: &Client,
        client_secret_digest: Option<&[u8; 32]>,
    ) -> Result<Client, DomainError> {
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
        clients
            .upsert_with_secret(client, client_secret_digest)
            .await?;

        // Read back rather than returned: RFC 7591 §3.2.1's "all registered
        // metadata about this client" is what the row holds after defaults and
        // triggers, not what went in.
        clients.find(&client.id).await?.ok_or(DomainError::NotFound)
    }

    async fn replace(
        &self,
        client: &Client,
        client_secret: ClientSecretUpdate,
    ) -> Result<Client, DomainError> {
        self.store
            .scope(client.tenant.clone())
            .clients(self.capabilities)
            .replace_with_secret(client, client_secret)
            .await
    }

    async fn replace_resources(
        &self,
        tenant: &TenantId,
        client_id: &ClientId,
        resources: &std::collections::BTreeSet<String>,
    ) -> Result<Client, DomainError> {
        self.store
            .scope(tenant.clone())
            .clients(self.capabilities)
            .replace_resources(client_id, resources)
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

/// This deployment's accounts, as the admin API's port sees them
/// (`ast-f7m.6`).
///
/// A type of its own rather than a dozen more methods on [`Deployment`],
/// because the admin API takes a `dyn UserAdministration` handle: the object
/// behind it is what a handler can reach, and this one can reach a tenant's
/// accounts, its sessions, its grants, its credentials and the back-channel
/// notifier — and nothing else.
///
/// # Why the ordering lives here
///
/// Disabling an account is three effects, and the order is load-bearing:
///
/// ```text
///   mark the account  →  revoke its sessions  →  notify the relying parties
/// ```
///
/// A relying party told that a session ended while the account can still sign
/// in has been told something this server cannot stand behind, and a session
/// revoked before the account is marked is a person who can start a fresh one
/// a moment later. Putting the three in the API layer would make the ordering
/// a property of a handler somebody may rewrite; putting them here makes it a
/// property of the one implementation both the console and any future caller
/// go through.
#[derive(Clone)]
struct DeploymentUsers {
    store: Store,
    tenants: Arc<dyn TenantRepository>,
    kek: Arc<dyn asterius_jose::Kek>,
    keys: Arc<dyn asterius_domain::keys::Signer>,
    capabilities: Capabilities,
    argon2: asterius_domain::Argon2Parameters,
    /// Where a back-channel logout token is queued (§2.5), or `None` in a
    /// deployment with no outbox wired — which notifies nobody and says so.
    queue: Option<Arc<dyn asterius_domain::outbox::OutboxQueue>>,
}

impl std::fmt::Debug for DeploymentUsers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeploymentUsers").finish_non_exhaustive()
    }
}

impl DeploymentUsers {
    /// Ends every live session of an account and notifies the relying parties
    /// that took part in each.
    ///
    /// The revocation comes first and the notification second, for the reason
    /// `crate::http::logout` gives: a relying party told that a session ended
    /// whose credentials still work is a client that can mint a fresh access
    /// token a second later.
    ///
    /// Every failure below the first is logged and degrades: an account that
    /// has been disabled must not come back because one relying party's
    /// registration would not load.
    ///
    /// # One signal per session, not one per cause (`ast-o4u.3`)
    ///
    /// Each session ended here produces its own CAEP `session-revoked` (§3.1),
    /// whose complex subject names `{user, session}`: a receiver holding three
    /// of this person's sessions has to be told which of them to drop, and an
    /// event about the user alone would either say nothing or say "all of
    /// them". That is the same shape as the back-channel logout tokens beside
    /// it — one per session, per participating client — and it is why the
    /// public `sid` is read back before the revocation rather than after.
    ///
    /// The list is [`live_digests_for_user`], so a session already revoked is
    /// not in it: terminating twice ends nothing the second time, and emits
    /// nothing.
    ///
    /// [`live_digests_for_user`]: asterius_store_pg::PgSessionRepository::live_digests_for_user
    async fn terminate_sessions(
        &self,
        tenant: &TenantId,
        user: UserId,
        reason: asterius_domain::SessionRevocation,
        by: crate::ssf::RevokedBy,
        now: time::OffsetDateTime,
    ) -> Result<asterius_domain::Terminated, DomainError> {
        let scope = self.store.scope(tenant.clone());
        let sessions = scope.sessions();
        let digests = sessions.live_digests_for_user(*user.as_uuid(), now).await?;

        let mut terminated = asterius_domain::Terminated::default();
        for digest in digests {
            // Read before revoking: the `sid` a receiver knows this session by
            // is what the event's subject carries, and a row read back after a
            // failed revocation would name a session that is still live.
            let public_sid = match sessions.find(&digest).await {
                Ok(Some(session)) => session.public_sid,
                Ok(None) => continue,
                Err(error) => {
                    tracing::error!(%error, tenant = %tenant, "cannot read a session to revoke it");
                    continue;
                }
            };
            if let Err(error) = sessions.revoke(&digest, reason, now).await {
                tracing::error!(%error, tenant = %tenant, "cannot revoke a session administratively");
                continue;
            }
            terminated.sessions_revoked += 1;
            terminated.logout_tokens_queued += self.notify_participants(tenant, &digest, now).await;
            self.emit_signal(
                tenant,
                &crate::ssf::Cause::SessionRevoked {
                    user,
                    sid: public_sid,
                    by,
                    // English: nobody negotiated a language with this server —
                    // an operator acting on somebody else's account did.
                    locale: asterius_domain::Locale::default(),
                },
                now,
            )
            .await;
        }
        Ok(terminated)
    }

    /// Queues one logout token per participating relying party of the session
    /// `digest` names, through the same [`crate::backchannel::Notifier`] the
    /// end-session endpoint uses.
    ///
    /// Returns zero rather than failing for every reason short of "the session
    /// is gone": it is called after a revocation that has already happened.
    async fn notify_participants(
        &self,
        tenant: &TenantId,
        digest: &str,
        now: time::OffsetDateTime,
    ) -> usize {
        let scope = self.store.scope(tenant.clone());
        let sessions = scope.sessions();

        let Ok(Some(session)) = sessions.find(digest).await else {
            tracing::error!(tenant = %tenant, "a revoked session could not be read back");
            return 0;
        };
        let participants = match sessions.participants(digest).await {
            Ok(participants) => participants,
            Err(error) => {
                tracing::error!(%error, "cannot read the participants of an ended session");
                return 0;
            }
        };
        if participants.is_empty() {
            return 0;
        }
        let Ok(Some(tenant_entity)) = self.tenants.find_by_id(tenant).await else {
            tracing::error!(tenant = %tenant, "cannot read the tenant an ended session belongs to");
            return 0;
        };

        let clients = scope.clients(self.capabilities);
        let users = scope.users(Arc::clone(&self.kek));
        let notifier = crate::backchannel::Notifier {
            tenant: &tenant_entity,
            clients: &clients,
            subjects: &users,
            signer: self.keys.as_ref(),
            outbox: self.queue.as_deref(),
        };
        notifier.notify(&session, &participants, now).await
    }

    /// Emits the CAEP or RISC Security Event Tokens one administrative effect
    /// produces, to every stream that subscribed (`ast-0ju.8`).
    ///
    /// Best-effort and after the effect, the same order and the same reasoning
    /// as [`Self::notify_participants`]: the account is already disabled, and a
    /// receiver that could not be told must not undo that. A tenant that cannot
    /// be read is logged and nothing is emitted.
    async fn emit_signal(
        &self,
        tenant: &TenantId,
        cause: &crate::ssf::Cause,
        now: time::OffsetDateTime,
    ) {
        let Ok(Some(tenant_entity)) = self.tenants.find_by_id(tenant).await else {
            tracing::error!(tenant = %tenant, "cannot read a tenant to emit a security event");
            return;
        };
        let scope = self.store.scope(tenant.clone());
        let clients = scope.clients(self.capabilities);
        let users = scope.users(Arc::clone(&self.kek));
        let queues = crate::outbox::PgSsfQueues::new(
            self.store.clone(),
            tenant.clone(),
            Arc::clone(&self.kek),
        );
        let transmitter = crate::ssf::SsfTransmitter {
            tenant,
            issuer: &tenant_entity.issuer,
            queues: &queues,
            clients: &clients,
            subjects: &users,
            signer: self.keys.as_ref(),
        };
        transmitter.emit(cause, now).await;
    }
}

#[async_trait::async_trait]
impl asterius_domain::UserAdministration for DeploymentUsers {
    async fn scim_replace_profile(
        &self,
        replacement: asterius_domain::ScimProfileReplacement,
    ) -> Result<asterius_domain::ScimUserState, DomainError> {
        let now = time::OffsetDateTime::now_utc();
        let scope = self.store.scope(replacement.tenant.clone());
        let users = scope.users(Arc::clone(&self.kek));
        let previous = users
            .scim_find(&replacement.client, replacement.user)
            .await?
            .ok_or(DomainError::NotFound)?;
        let (state, sessions) = users.scim_replace_profile(&replacement).await?;
        for (digest, public_sid) in sessions {
            self.notify_participants(&replacement.tenant, &digest, now)
                .await;
            self.emit_signal(
                &replacement.tenant,
                &crate::ssf::Cause::SessionRevoked {
                    user: replacement.user,
                    sid: public_sid,
                    by: crate::ssf::RevokedBy::AccountDisabled,
                    locale: asterius_domain::Locale::default(),
                },
                now,
            )
            .await;
        }
        if previous.user.status == state.user.status {
            return Ok(state);
        }
        if state.user.status == asterius_domain::UserStatus::Active {
            self.emit_signal(
                &replacement.tenant,
                &crate::ssf::Cause::AccountEnabled {
                    user: replacement.user,
                    initiator: asterius_ssf::caep::InitiatingEntity::Admin,
                },
                now,
            )
            .await;
        } else {
            self.emit_signal(
                &replacement.tenant,
                &crate::ssf::Cause::AccountDisabled {
                    user: replacement.user,
                    reason: None,
                    initiator: asterius_ssf::caep::InitiatingEntity::Admin,
                },
                now,
            )
            .await;
        }
        Ok(state)
    }

    async fn scim_page(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        offset: u32,
        limit: u16,
    ) -> Result<(u64, Vec<asterius_domain::ScimUserState>), DomainError> {
        self.store
            .scope(tenant.clone())
            .users(Arc::clone(&self.kek))
            .scim_page(client, offset, limit)
            .await
    }

    async fn scim_find(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        id: UserId,
    ) -> Result<Option<asterius_domain::ScimUserState>, DomainError> {
        self.store
            .scope(tenant.clone())
            .users(Arc::clone(&self.kek))
            .scim_find(client, id)
            .await
    }

    async fn scim_create(
        &self,
        client: &ClientId,
        user: asterius_domain::User,
        external_id: Option<&str>,
    ) -> Result<asterius_domain::ScimUserState, DomainError> {
        self.store
            .scope(user.tenant.clone())
            .users(Arc::clone(&self.kek))
            .scim_create(client, &user, external_id)
            .await
    }

    async fn find_by_username(
        &self,
        tenant: &TenantId,
        username: &str,
    ) -> Result<Option<asterius_domain::User>, DomainError> {
        self.store
            .scope(tenant.clone())
            .users(Arc::clone(&self.kek))
            .find_by_username(username)
            .await
    }

    async fn page(
        &self,
        tenant: &TenantId,
        offset: u32,
        limit: u16,
    ) -> Result<(u64, Vec<asterius_domain::User>), DomainError> {
        self.store
            .scope(tenant.clone())
            .users(Arc::clone(&self.kek))
            .page(offset, limit)
            .await
    }

    async fn search(
        &self,
        tenant: &TenantId,
        term: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<asterius_domain::User>, DomainError> {
        self.store
            .scope(tenant.clone())
            .users(Arc::clone(&self.kek))
            .search(term, after, i64::try_from(limit).unwrap_or(i64::MAX))
            .await
    }

    async fn find(
        &self,
        tenant: &TenantId,
        id: UserId,
    ) -> Result<Option<asterius_domain::User>, DomainError> {
        self.store
            .scope(tenant.clone())
            .users(Arc::clone(&self.kek))
            .find(id)
            .await
    }

    async fn create(
        &self,
        account: asterius_domain::NewAccount,
    ) -> Result<asterius_domain::User, DomainError> {
        let scope = self.store.scope(account.user.tenant.clone());
        let users = scope.users(Arc::clone(&self.kek));

        // `upsert` is a create-or-replace, and a creation must never be a
        // replacement: it would hand an administrator somebody else's account
        // under a username they typed. The same guard `DeploymentClients` puts
        // in front of a client registration, and for the same reason.
        if users
            .find_by_username(&account.user.username)
            .await?
            .is_some()
        {
            return Err(DomainError::Conflict(
                "an account already exists under this username".to_owned(),
            ));
        }
        users.upsert(&account.user).await?;

        if let Some(password) = account.password {
            let verifier = asterius_store_pg::PgPasswordVerifier::new(
                self.store.pool().clone(),
                account.user.tenant.clone(),
                self.argon2,
            )?;
            // The *normalised* form, which is what
            // `AcceptedPassword::expose` holds and what NIST SP 800-63B
            // §5.1.1.2 requires be hashed.
            verifier
                .set_password(*account.user.id.as_uuid(), password.expose())
                .await?;
        }

        // Read back rather than returned: the row after defaults and triggers
        // is what an administrator is shown.
        users
            .find(account.user.id)
            .await?
            .ok_or(DomainError::NotFound)
    }

    async fn set_status(
        &self,
        tenant: &TenantId,
        id: UserId,
        status: asterius_domain::UserStatus,
        now: time::OffsetDateTime,
    ) -> Result<asterius_domain::Terminated, DomainError> {
        let scope = self.store.scope(tenant.clone());
        let users = scope.users(Arc::clone(&self.kek));
        let mut held = users.find(id).await?.ok_or(DomainError::NotFound)?;
        held.status = status;
        held.updated_at = now;
        // First: an account marked disabled cannot start a new session while
        // the old ones are being ended.
        users.upsert(&held).await?;

        if status != asterius_domain::UserStatus::Disabled {
            // RISC `account-enabled`: nothing was terminated, but a receiver
            // that heard the account was disabled must hear it is back.
            self.emit_signal(
                tenant,
                &crate::ssf::Cause::AccountEnabled {
                    user: id,
                    initiator: asterius_ssf::caep::InitiatingEntity::Admin,
                },
                now,
            )
            .await;
            return Ok(asterius_domain::Terminated::default());
        }
        let terminated = self
            .terminate_sessions(
                tenant,
                id,
                asterius_domain::SessionRevocation::AccountClosed,
                crate::ssf::RevokedBy::AccountDisabled,
                now,
            )
            .await?;
        // RISC `account-disabled`, on top of the per-session CAEP
        // `session-revoked` each ended session produced above: the two answer
        // different questions. A receiver acts on the first by refusing the
        // account altogether and on the second by dropping one session, and a
        // receiver subscribed to only one of the two event types must still
        // hear the half it asked for.
        self.emit_signal(
            tenant,
            &crate::ssf::Cause::AccountDisabled {
                user: id,
                reason: None,
                initiator: asterius_ssf::caep::InitiatingEntity::Admin,
            },
            now,
        )
        .await;
        Ok(terminated)
    }

    async fn save(
        &self,
        user: &asterius_domain::User,
    ) -> Result<asterius_domain::User, DomainError> {
        let users = self
            .store
            .scope(user.tenant.clone())
            .users(Arc::clone(&self.kek));
        users.upsert(user).await?;
        users.find(user.id).await?.ok_or(DomainError::NotFound)
    }

    async fn sessions(
        &self,
        tenant: &TenantId,
        user: UserId,
    ) -> Result<Vec<asterius_domain::SessionSummary>, DomainError> {
        self.store
            .scope(tenant.clone())
            .sessions()
            .summaries_for_user(*user.as_uuid())
            .await
    }

    async fn revoke_session(
        &self,
        tenant: &TenantId,
        public_sid: &str,
        now: time::OffsetDateTime,
    ) -> Result<asterius_domain::Terminated, DomainError> {
        let scope = self.store.scope(tenant.clone());
        let sessions = scope.sessions();
        // The `sid` is resolved to the digest here and nowhere above: the
        // admin API never holds one, which is the whole point of the port's
        // shape.
        let digest = sessions
            .digest_of_sid(public_sid)
            .await?
            .ok_or(DomainError::NotFound)?;

        let held = sessions.find(&digest).await?.ok_or(DomainError::NotFound)?;
        // Idempotence (`ast-o4u.3`): a session ends once. A second press of
        // the button in the console — or a retried request — finds a row that
        // is already revoked or expired, and answers "nothing was ended"
        // rather than queueing a second set of logout tokens and a second
        // `session-revoked`. A receiver that deduplicates by `jti` would still
        // see two transactions, and an auditor counting SETs would see one
        // session ended twice.
        if !held.status(now).is_usable() {
            return Ok(asterius_domain::Terminated::default());
        }
        sessions
            .revoke(
                &digest,
                asterius_domain::SessionRevocation::Administrative,
                now,
            )
            .await?;
        // CAEP §3.1: the session named by its public `sid`, which this path
        // has in hand.
        self.emit_signal(
            tenant,
            &crate::ssf::Cause::SessionRevoked {
                user: asterius_domain::UserId::new(held.user),
                sid: public_sid.to_owned(),
                by: crate::ssf::RevokedBy::Administrator,
                locale: asterius_domain::Locale::default(),
            },
            now,
        )
        .await;
        Ok(asterius_domain::Terminated {
            sessions_revoked: 1,
            logout_tokens_queued: self.notify_participants(tenant, &digest, now).await,
        })
    }

    async fn grants(
        &self,
        tenant: &TenantId,
        user: UserId,
    ) -> Result<Vec<asterius_domain::Grant>, DomainError> {
        self.store
            .scope(tenant.clone())
            .grants()
            .list_for_user(&user)
            .await
    }

    async fn revoke_grant(
        &self,
        tenant: &TenantId,
        grant: &asterius_domain::GrantId,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError> {
        // Grant Management ID1 §6.5 through the same transaction the
        // client-facing `DELETE /grants/{grant_id}` uses: the refresh tokens
        // are marked, the access-token cutoff is written (`ast-m9c.13`) and
        // the grant is stamped last.
        //
        // No live access tokens are named, for the reason
        // `ClientEndpoints::revoke` gives: this caller holds none of the
        // grant's tokens, and what withdraws them is the cutoff.
        match self
            .store
            .scope(tenant.clone())
            .grants()
            .revoke(
                grant,
                asterius_domain::RevocationReason::AdminRevoked,
                &[],
                now,
            )
            .await
        {
            Ok(_) => Ok(true),
            // What a second `DELETE` finds, and what an id this tenant never
            // held finds. Not an error: both are "there is nothing to
            // withdraw".
            Err(DomainError::NotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    async fn credentials(
        &self,
        tenant: &TenantId,
        user: UserId,
    ) -> Result<asterius_domain::CredentialSummary, DomainError> {
        let scope = self.store.scope(tenant.clone());
        let verifier = asterius_store_pg::PgPasswordVerifier::new(
            self.store.pool().clone(),
            tenant.clone(),
            self.argon2,
        )?;
        Ok(asterius_domain::CredentialSummary {
            password: verifier.has_password(*user.as_uuid()).await?,
            passkeys: scope.passkeys().summaries_for_user(&user).await?,
        })
    }

    async fn remove_passkey(
        &self,
        tenant: &TenantId,
        user: UserId,
        credential: uuid::Uuid,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let removed = self
            .store
            .scope(tenant.clone())
            .passkeys()
            .disable_for_user(&user, credential, now)
            .await?;
        let Some(removed) = removed else {
            return Ok(false);
        };

        // CAEP §3.3: a credential was deleted. `fido2-platform` or
        // `fido2-roaming` from what WebAuthn recorded, the friendly name where
        // the user gave one — no key material, which a receiver has no use for
        // and this server never puts on the wire.
        let mut change = asterius_ssf::caep::CredentialChange::new(
            asterius_ssf::caep::CredentialType::fido2(None, removed.backup_eligible),
            asterius_ssf::caep::ChangeType::Delete,
        );
        if let Some(aaguid) = removed.aaguid {
            change = change.fido2_aaguid(aaguid);
        }
        if let Some(label) = removed.label.as_deref()
            && let Ok(named) = change.clone().friendly_name(label)
        {
            change = named;
        }
        self.emit_signal(
            tenant,
            &crate::ssf::Cause::CredentialChange {
                user,
                change,
                initiator: asterius_ssf::caep::InitiatingEntity::Admin,
            },
            now,
        )
        .await;
        Ok(true)
    }

    async fn force_password_reset(
        &self,
        tenant: &TenantId,
        user: UserId,
        now: time::OffsetDateTime,
    ) -> Result<asterius_domain::PasswordReset, DomainError> {
        let scope = self.store.scope(tenant.clone());
        let held = scope
            .users(Arc::clone(&self.kek))
            .find(user)
            .await?
            .ok_or(DomainError::NotFound)?;

        let verifier = asterius_store_pg::PgPasswordVerifier::new(
            self.store.pool().clone(),
            tenant.clone(),
            self.argon2,
        )?;
        let has_password = verifier.has_password(*user.as_uuid()).await?;
        if !has_password && !scope.passkeys().summaries_for_user(&user).await?.is_empty() {
            // Administrative authority does not turn mailbox control into a
            // user-verified passkey. Leave credentials and sessions untouched.
            PgAuditSink::new(self.store.pool().clone())
                .record(
                    asterius_domain::audit::AuditEvent::new(
                        tenant.clone(),
                        asterius_domain::audit::EventType::RECOVERY_REFUSED,
                        asterius_domain::audit::Outcome::Failure,
                        asterius_domain::audit::Actor::System,
                        now,
                    )
                    .subject(user.as_uuid().to_string())
                    .detail(
                        asterius_domain::audit::Detail::new()
                            .label("reason", "passkey_only_admin_reset"),
                    ),
                )
                .await?;
            if held.email_verified
                && let Some(address) = held.email.clone()
                && let Err(error) = scope
                    .mail()
                    .send(&asterius_domain::Notification::recovery_refused(address))
                    .await
            {
                tracing::error!(%error, tenant = %tenant, "cannot hand off an administrative recovery refusal notice");
            }
            return Err(DomainError::Conflict(
                "Passkey-only accounts require administrator-assisted identity verification and passkey re-enrolment; password reset is unavailable".to_owned(),
            ));
        }
        let password_invalidated = verifier.invalidate(*user.as_uuid(), now).await?;

        // Every outstanding recovery link goes with the credential, for the
        // reason `crate::http::recovery` gives: a link quietly requested
        // before the change must not survive it.
        scope
            .recovery_tokens()
            .invalidate_for_user(user, now)
            .await?;

        let recovery_sent = self.send_recovery(tenant, &held, now).await;

        // A forced reset ends the sessions, and `CredentialChange` is what
        // that revocation means: every session predating the change is stale.
        // Whoever is signed in on the old password is signed out by the same
        // call that took it away.
        let terminated = self
            .terminate_sessions(
                tenant,
                user,
                asterius_domain::SessionRevocation::CredentialChange,
                crate::ssf::RevokedBy::PasswordReset,
                now,
            )
            .await?;

        // CAEP §3.3: the password was changed. `update` and not `revoke`: a
        // forced reset replaces the password rather than removing the factor.
        self.emit_signal(
            tenant,
            &crate::ssf::Cause::CredentialChange {
                user,
                change: asterius_ssf::caep::CredentialChange::new(
                    asterius_ssf::caep::CredentialType::Password,
                    asterius_ssf::caep::ChangeType::Update,
                ),
                initiator: asterius_ssf::caep::InitiatingEntity::Admin,
            },
            now,
        )
        .await;

        Ok(asterius_domain::PasswordReset {
            password_invalidated,
            recovery_sent,
            terminated,
        })
    }

    async fn reset_totp(
        &self,
        tenant: &TenantId,
        user: UserId,
        now: time::OffsetDateTime,
    ) -> Result<asterius_domain::TotpReset, DomainError> {
        let scope = self.store.scope(tenant.clone());
        scope
            .users(Arc::clone(&self.kek))
            .find(user)
            .await?
            .ok_or(DomainError::NotFound)?;

        let reset = scope
            .totp_credentials(Arc::clone(&self.kek))
            .reset_with_sessions(*user.as_uuid(), now)
            .await?;
        let mut terminated = asterius_domain::Terminated::default();
        for session in reset.sessions {
            terminated.sessions_revoked += 1;
            terminated.logout_tokens_queued +=
                self.notify_participants(tenant, &session.digest, now).await;
            self.emit_signal(
                tenant,
                &crate::ssf::Cause::SessionRevoked {
                    user,
                    sid: session.public_sid,
                    by: crate::ssf::RevokedBy::Administrator,
                    locale: asterius_domain::Locale::default(),
                },
                now,
            )
            .await;
        }
        if reset.factor_removed {
            self.emit_signal(
                tenant,
                &crate::ssf::Cause::CredentialChange {
                    user,
                    change: asterius_ssf::caep::CredentialChange::new(
                        asterius_ssf::caep::CredentialType::App,
                        asterius_ssf::caep::ChangeType::Delete,
                    ),
                    initiator: asterius_ssf::caep::InitiatingEntity::Admin,
                },
                now,
            )
            .await;
        }
        Ok(asterius_domain::TotpReset {
            factor_removed: reset.factor_removed,
            terminated,
        })
    }
}

impl DeploymentUsers {
    /// Draws a recovery token and hands the message to the notification port.
    ///
    /// The same shape as `crate::http::recovery`'s own: a 256-bit single-use
    /// token, stored as a digest, in a link built from the tenant's issuer.
    /// An account with no address gets nothing and reports `false` — there is
    /// nowhere to send a link, and inventing one would be worse.
    ///
    /// Failures are logged and reported as `false` rather than failing the
    /// reset: the password is already gone by the time this runs, and an
    /// administrator needs to be told which half worked.
    async fn send_recovery(
        &self,
        tenant: &TenantId,
        user: &asterius_domain::User,
        now: time::OffsetDateTime,
    ) -> bool {
        let Some(address) = user.email.clone() else {
            return false;
        };
        let Ok(Some(tenant_entity)) = self.tenants.find_by_id(tenant).await else {
            tracing::error!(tenant = %tenant, "cannot read the tenant an account belongs to");
            return false;
        };

        let token = asterius_domain::RecoveryToken::generate();
        let issued = asterius_domain::IssuedRecovery::new(user.id, &token, now);
        let scope = self.store.scope(tenant.clone());
        if let Err(error) = scope.recovery_tokens().issue(&issued).await {
            tracing::error!(%error, tenant = %tenant, "cannot store a recovery token");
            return false;
        }

        // Absolute, because it is going into a message: a browser opening it
        // has no page to resolve a relative path against.
        let link = format!(
            "{}{}?token={}",
            tenant_entity.issuer.as_str().trim_end_matches('/'),
            crate::http::recovery::NEW_PASSWORD_PATH,
            token.expose()
        );
        let message = asterius_domain::Notification::account_recovery(
            address,
            link,
            asterius_domain::RECOVERY_LIFETIME.whole_minutes(),
        )
        .with_expires_at(issued.expires_at);
        if let Err(error) = scope.mail().send(&message).await {
            tracing::error!(%error, tenant = %tenant, "cannot hand off a recovery message");
            return false;
        }
        true
    }
}

#[async_trait::async_trait]
impl AdminBackend for Deployment {
    async fn federation_key_inventory(
        &self,
        tenant: &TenantId,
    ) -> Result<serde_json::Value, DomainError> {
        let keys = asterius_store_pg::PgFederationKeys::new(
            self.store.pool().clone(),
            Arc::clone(&self.kek),
            self.audit(),
        );
        let records = keys.inventory(tenant).await?;
        if records.is_empty() {
            return Err(DomainError::NotFound);
        }
        Ok(serde_json::json!({
            "rotation_period_seconds": asterius_store_pg::ROTATION_PERIOD.whole_seconds(),
            "keys": records.into_iter().map(|record| serde_json::json!({
                "kid": record.kid,
                "state": record.state,
                "public_jwk": asterius_admin_api::keys::public_members(&record.public_jwk),
                "created_at": record.created_at.unix_timestamp(),
                "activated_at": record.activated_at.map(time::OffsetDateTime::unix_timestamp),
                "retired_at": record.retired_at.map(time::OffsetDateTime::unix_timestamp),
            })).collect::<Vec<_>>()
        }))
    }

    async fn federation_key_rotate(
        &self,
        tenant: &TenantId,
        actor: &str,
        now: time::OffsetDateTime,
    ) -> Result<String, DomainError> {
        let keys = asterius_store_pg::PgFederationKeys::new(
            self.store.pool().clone(),
            Arc::clone(&self.kek),
            self.audit(),
        );
        if !keys.has_key(tenant).await? {
            return Err(DomainError::NotFound);
        }
        keys.stage(tenant, asterius_domain::Actor::Admin(actor.to_owned()), now)
            .await
    }

    async fn invitation_statuses(
        &self,
        tenant: &TenantId,
        limit: u32,
        now: time::OffsetDateTime,
    ) -> Result<Vec<asterius_admin_api::backend::InvitationStatus>, DomainError> {
        self.store
            .scope(tenant.clone())
            .invitations()
            .recent(limit)
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|row| {
                        let status = if row.revoked_at.is_some() {
                            "revoked"
                        } else if row.consumed_at.is_some() {
                            "accepted"
                        } else if row.expires_at <= now {
                            "expired"
                        } else {
                            "pending"
                        };
                        asterius_admin_api::backend::InvitationStatus {
                            id: row.id,
                            email: row.email,
                            username: row.username,
                            created_at: row.created_at.unix_timestamp(),
                            expires_at: row.expires_at.unix_timestamp(),
                            status,
                        }
                    })
                    .collect()
            })
    }

    async fn invite_user(
        &self,
        tenant: &Tenant,
        actor: &str,
        request: asterius_admin_api::backend::InvitationRequest,
        now: time::OffsetDateTime,
    ) -> Result<asterius_admin_api::backend::InvitationReceipt, DomainError> {
        let settings = self.settings.for_tenant(&tenant.id).await?;
        if settings
            .acr_policy()
            .achieved(&[asterius_domain::AuthenticationMethod::Password])
            .is_none()
        {
            return Err(DomainError::invalid(
                "acr_policy",
                "password onboarding cannot satisfy this tenant's assurance policy; use another account provisioning path",
            ));
        }
        let expiry = time::OffsetDateTime::from_unix_timestamp(request.expires_at)
            .map_err(|_| DomainError::invalid("expires_at", "invalid timestamp"))?;
        let username = request.username.as_deref().unwrap_or(&request.email);
        let link = format!("{}/invite", tenant.issuer.as_str().trim_end_matches('/'));
        let invitation = self
            .store
            .scope(tenant.id.clone())
            .invitations()
            .invite(asterius_store_pg::NewInvitation {
                email: &request.email,
                username,
                inviter: actor,
                role: request.role.as_deref(),
                group_ids: &request.group_ids,
                expires_at: expiry,
                link_base: &link,
                now,
            })
            .await?;
        Ok(asterius_admin_api::backend::InvitationReceipt {
            id: invitation.id,
            email: invitation.email,
            username: invitation.username,
            role: invitation.role,
            group_ids: invitation.group_ids,
            expires_at: invitation.expires_at.unix_timestamp(),
        })
    }

    async fn resend_invitation(
        &self,
        tenant: &Tenant,
        id: uuid::Uuid,
        expires_at: time::OffsetDateTime,
        now: time::OffsetDateTime,
    ) -> Result<asterius_admin_api::backend::InvitationReceipt, DomainError> {
        let settings = self.settings.for_tenant(&tenant.id).await?;
        if settings
            .acr_policy()
            .achieved(&[asterius_domain::AuthenticationMethod::Password])
            .is_none()
        {
            return Err(DomainError::invalid(
                "acr_policy",
                "password onboarding cannot satisfy this tenant's assurance policy; use another account provisioning path",
            ));
        }
        let link = format!("{}/invite", tenant.issuer.as_str().trim_end_matches('/'));
        let invitation = self
            .store
            .scope(tenant.id.clone())
            .invitations()
            .resend(id, expires_at, &link, now)
            .await?;
        Ok(asterius_admin_api::backend::InvitationReceipt {
            id: invitation.id,
            email: invitation.email,
            username: invitation.username,
            role: invitation.role,
            group_ids: invitation.group_ids,
            expires_at: invitation.expires_at.unix_timestamp(),
        })
    }

    async fn revoke_invitation(
        &self,
        tenant: &TenantId,
        id: uuid::Uuid,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError> {
        self.store
            .scope(tenant.clone())
            .invitations()
            .revoke(id, now)
            .await
    }

    async fn overview(
        &self,
        tenant: &TenantId,
        metric: asterius_admin_api::backend::OverviewMetric,
        now: time::OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let metric = match metric {
            asterius_admin_api::backend::OverviewMetric::Users => {
                asterius_store_pg::OverviewMetric::Users
            }
            asterius_admin_api::backend::OverviewMetric::Sessions => {
                asterius_store_pg::OverviewMetric::Sessions
            }
            asterius_admin_api::backend::OverviewMetric::Applications => {
                asterius_store_pg::OverviewMetric::Applications
            }
            asterius_admin_api::backend::OverviewMetric::Authentication => {
                asterius_store_pg::OverviewMetric::Authentication
            }
            asterius_admin_api::backend::OverviewMetric::Keys => {
                asterius_store_pg::OverviewMetric::Keys
            }
            asterius_admin_api::backend::OverviewMetric::Delivery => {
                asterius_store_pg::OverviewMetric::Delivery
            }
        };
        asterius_store_pg::PgOverview::new(self.store.pool().clone())
            .read(tenant, metric, now)
            .await
    }

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

    /// Gives a role, through the repository whose insert reads
    /// `tenants.is_reserved` in the same statement (`ast-3t8`).
    ///
    /// The reserved-tenant rule is not restated here and must not be: the
    /// composite foreign key and the check constraint on `user_roles` are what
    /// make it true of the data, and a second copy in this method would be the
    /// one that drifts.
    async fn grant_role(
        &self,
        tenant: &TenantId,
        user: UserId,
        role: Role,
    ) -> Result<(), DomainError> {
        PgRoleRepository::new(self.store.pool().clone(), tenant.clone())
            .grant(user, role)
            .await
    }

    async fn revoke_role(
        &self,
        tenant: &TenantId,
        user: UserId,
        role: Role,
    ) -> Result<(), DomainError> {
        PgRoleRepository::new(self.store.pool().clone(), tenant.clone())
            .revoke(user, role)
            .await
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

    async fn tenant_settings_list(
        &self,
    ) -> Result<Vec<(TenantId, asterius_domain::TenantSettings)>, DomainError> {
        PgTenantSettings::new(self.store.pool().clone())
            .list()
            .await
    }

    fn tenant_settings(&self) -> Arc<dyn TenantSettingsRepository> {
        Arc::new(PgTenantSettings::new(self.store.pool().clone()))
    }

    fn themes(&self) -> Arc<dyn asterius_domain::ports::ThemeRepository> {
        self.themes.repository()
    }

    fn theme_changed(&self, tenant: &TenantId) {
        self.themes.invalidate(tenant);
    }

    /// This tenant's initial access tokens (`ast-cu3`).
    ///
    /// Over `self.store`'s pool, which is the pool `POST /register` reserves
    /// from: the console must not be able to issue a credential the endpoint
    /// cannot see.
    fn initial_access_tokens(&self) -> Arc<dyn asterius_domain::ports::InitialAccessTokenStore> {
        Arc::new(asterius_store_pg::PgInitialAccessTokens::new(
            self.store.pool().clone(),
        ))
    }

    fn users(&self) -> Arc<dyn asterius_domain::UserAdministration> {
        Arc::new(DeploymentUsers {
            store: self.store.clone(),
            tenants: Arc::clone(&self.tenants),
            kek: Arc::clone(&self.kek),
            keys: Arc::clone(&self.signer),
            capabilities: self.capabilities,
            argon2: self.argon2,
            queue: self.queue.clone(),
        })
    }

    async fn verified_claims(
        &self,
        tenant: &TenantId,
        user: UserId,
    ) -> Result<Vec<(uuid::Uuid, asterius_domain::VerifiedClaims)>, DomainError> {
        self.store
            .scope(tenant.clone())
            .verified_claims()
            .by_user(user)
            .await
            .map(|rows| rows.into_iter().map(|row| (row.id, row.bundle)).collect())
    }

    async fn add_verified_claims(
        &self,
        tenant: &TenantId,
        user: UserId,
        bundle: &asterius_domain::VerifiedClaims,
        actor: &str,
        now: time::OffsetDateTime,
    ) -> Result<uuid::Uuid, DomainError> {
        self.store
            .scope(tenant.clone())
            .verified_claims()
            .insert(user, bundle, actor, now)
            .await
    }

    async fn revoke_verified_claims(
        &self,
        tenant: &TenantId,
        user: UserId,
        id: uuid::Uuid,
        actor: &str,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError> {
        self.store
            .scope(tenant.clone())
            .verified_claims()
            .revoke(user, id, actor, now)
            .await
    }

    fn groups(&self) -> Arc<dyn asterius_domain::GroupDirectory> {
        Arc::new(asterius_store_pg::PgGroups::new(self.store.pool().clone()))
    }

    fn keys(&self) -> Arc<dyn KeyAdministration> {
        Arc::clone(&self.keys)
    }

    /// The deployment's outbox, for the dead-letter screen (`ast-0ju.9`).
    ///
    /// The handle `main` built, so the screen reads the rows the running
    /// worker is claiming from and reports the budget it is actually
    /// enforcing.
    fn outbox(&self) -> Arc<dyn asterius_domain::outbox::DeadLetterQuery> {
        Arc::clone(&self.outbox)
    }

    fn dead_letter_operations(&self) -> Arc<dyn asterius_domain::outbox::DeadLetterOperations> {
        Arc::clone(&self.dead_letters)
    }

    fn ssf(&self) -> Arc<dyn asterius_admin_api::ssf::SsfAdministration> {
        Arc::new(DeploymentSsf {
            store: self.store.clone(),
            tenants: Arc::clone(&self.tenants),
            keys: Arc::clone(&self.signer),
            kek: Arc::clone(&self.kek),
            capabilities: self.capabilities,
        })
    }

    fn id_jag_bindings(&self) -> Option<Arc<dyn asterius_admin_api::id_jag::IdJagBindings>> {
        Some(Arc::new(DeploymentIdJagBindings {
            store: self.store.clone(),
            trusts: Arc::clone(&self.id_jag_trusts),
        }))
    }

    fn application_roles(&self) -> Arc<dyn asterius_domain::ApplicationRoleDirectory> {
        Arc::new(asterius_store_pg::PgApplicationRoles::new(
            self.store.pool().clone(),
        ))
    }

    /// The tenants' authorization policies (`ast-pj0.4`), over the pool the
    /// PDP decides from — so what an administrator edits is what the
    /// evaluation endpoint reads.
    fn policies(&self) -> Arc<dyn asterius_domain::ports::PolicyStore> {
        let store: Arc<dyn asterius_domain::ports::PolicyStore> = Arc::new(
            asterius_store_pg::PgPolicies::new(self.store.pool().clone()),
        );
        // `ast-lh3.10`: a policy written here is a policy the token endpoint
        // must not keep deciding against. Wrapped rather than called from the
        // handlers, so that a route added later cannot forget it.
        match &self.issuance {
            Some(guard) => Arc::new(crate::http::agent_issuance::InvalidatingPolicies::new(
                store,
                Arc::clone(guard),
            )),
            None => store,
        }
    }

    /// The PDP behind the console's policy test bench (`ast-f7m.9`).
    ///
    /// The same engine over the same pool as [`Self::policies`], so a bench
    /// answers about the document the editor just wrote, and the same
    /// `SubjectFacts` the AuthZEN endpoints resolve through, so it answers
    /// about the subject a relying party would be asking about.
    fn policy_trial(&self) -> Arc<dyn asterius_admin_api::backend::PolicyTrial> {
        Arc::new(DeploymentPolicyTrial {
            settings: self.settings.clone(),
            store: self.store.clone(),
            kek: Arc::clone(&self.kek),
        })
    }

    /// The trail read back (`ast-lh3.9`), over the pool every endpoint
    /// writes it through — so what the console lists is what was recorded,
    /// with no second sink to disagree.
    fn audit_trail(&self) -> Arc<dyn asterius_domain::audit::AuditQuery> {
        Arc::new(PgAuditSink::new(self.store.pool().clone()))
    }

    fn clients(&self) -> Arc<dyn ClientAdministration> {
        Arc::new(DeploymentClients {
            store: self.store.clone(),
            capabilities: self.capabilities,
            outbound: Arc::clone(&self.outbound),
            id_jag_trusts: Arc::clone(&self.id_jag_trusts),
        })
    }

    fn resource_servers(
        &self,
        tenant: &TenantId,
    ) -> Arc<dyn asterius_domain::ports::ResourceServerRepository> {
        Arc::new(asterius_store_pg::PgResourceServers::new(
            self.store.pool().clone(),
            tenant.clone(),
        ))
    }

    fn authorization_details_types(
        &self,
        tenant: &TenantId,
    ) -> Arc<dyn asterius_domain::ports::AuthorizationDetailsTypeRepository> {
        Arc::new(asterius_store_pg::PgAuthorizationDetailsTypes::new(
            self.store.pool().clone(),
            tenant.clone(),
        ))
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

    fn rate_limit_policy(
        &self,
    ) -> Option<(
        asterius_domain::LoginLimits,
        asterius_domain::EndpointLimits,
    )> {
        self.rate_limit_policy
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

#[cfg(test)]
mod automation_tests {
    use super::*;
    use asterius_domain::keys::{Signer as _, SigningAlgorithm};
    use asterius_domain::ports::TenantRepository;
    use asterius_domain::{Issuer, ReplayCheck, ReplayPurpose, TenantStatus};
    use asterius_jose::{LocalKeyStore, SigningKey, thumbprint};
    use asterius_oidc::tokens::JwtId;
    use asterius_oidc::tokens::access::{AccessToken, Audience, Confirmation};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    fn tenant(id: &str) -> Tenant {
        Tenant {
            id: TenantId::new(id),
            issuer: Issuer::parse(&format!("https://as.example/t/{id}")).expect("a valid issuer"),
            default_resource: "https://api.example/".to_owned(),
            custom_host: None,
            display_name: id.to_owned(),
            status: TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn admin_url(tenant: &Tenant, path: &str) -> String {
        format!("{}{path}", tenant.issuer.as_str())
    }

    #[derive(Debug)]
    struct Tenants(Vec<Tenant>);

    #[async_trait::async_trait]
    impl TenantRepository for Tenants {
        async fn find_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, DomainError> {
            Ok(self.0.iter().find(|tenant| &tenant.id == id).cloned())
        }

        async fn find_by_issuer(&self, issuer: &Issuer) -> Result<Option<Tenant>, DomainError> {
            Ok(self
                .0
                .iter()
                .find(|tenant| &tenant.issuer == issuer)
                .cloned())
        }

        async fn find_by_host(&self, host: &str) -> Result<Option<Tenant>, DomainError> {
            Ok(self
                .0
                .iter()
                .find(|tenant| tenant.custom_host.as_deref() == Some(host))
                .cloned())
        }

        async fn list(&self) -> Result<Vec<Tenant>, DomainError> {
            Ok(self.0.clone())
        }

        async fn upsert(&self, _: &Tenant) -> Result<(), DomainError> {
            unreachable!("read-only test repository")
        }

        async fn delete(&self, _: &TenantId) -> Result<(), DomainError> {
            unreachable!("read-only test repository")
        }
    }

    #[derive(Debug, Default)]
    struct Status;

    #[async_trait::async_trait]
    impl AutomationTokenStatus for Status {
        async fn is_denylisted(&self, _: &TenantId, _: &str) -> Result<bool, DomainError> {
            Ok(false)
        }

        async fn revoked_before(
            &self,
            _: &TenantId,
            _: &ClientId,
            _: Option<&GrantId>,
        ) -> Result<Option<time::OffsetDateTime>, DomainError> {
            Ok(None)
        }
    }

    #[derive(Debug, Default)]
    struct Replay(Mutex<BTreeSet<String>>);

    #[async_trait::async_trait]
    impl ReplayGuard for Replay {
        async fn claim(
            &self,
            _: &TenantId,
            _: ReplayPurpose,
            subject: &str,
            jti: &str,
            _: time::OffsetDateTime,
        ) -> Result<ReplayCheck, DomainError> {
            let key = format!("{subject}|{jti}");
            Ok(if self.0.lock().expect("lock").insert(key) {
                ReplayCheck::FirstUse
            } else {
                ReplayCheck::Replay
            })
        }
    }

    struct Fixture {
        resolver: AutomationTokens,
        keys: Arc<LocalKeyStore>,
        dpop_key: SigningKey,
    }

    impl Fixture {
        fn new(tenants: Vec<Tenant>, reserved: Option<TenantId>) -> Self {
            let keys = Arc::new(LocalKeyStore::new());
            for tenant in &tenants {
                keys.generate(&tenant.id, SigningAlgorithm::DEFAULT)
                    .expect("a signing key");
            }
            let dpop_key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("a DPoP key");
            let directory = TenantDirectory::new(Arc::new(Tenants(tenants)));
            let resolver = AutomationTokens {
                status: Arc::new(Status),
                keys: Arc::clone(&keys) as Arc<dyn KeyStore>,
                dpop: Arc::new(crate::http::dpop::DpopEndpoint::new(
                    Arc::new(Replay::default()),
                    None,
                )),
                directory,
                reserved_tenant: reserved,
            };
            Self {
                resolver,
                keys,
                dpop_key,
            }
        }

        async fn token(&self, issuer: &Tenant, audience: &str, scopes: &[&str]) -> String {
            let now = time::OffsetDateTime::now_utc();
            let mut grant = asterius_domain::Grant::new(
                issuer.id.clone(),
                ClientId::new("admin-automation"),
                now,
            );
            grant.scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
            grant.claimed_at = Some(now);
            let claimed = grant.claim(now).expect("a live grant");
            let jkt = thumbprint(&self.dpop_key.public_jwk().expect("a public JWK"))
                .expect("a thumbprint");
            let unsigned = AccessToken::new(
                &issuer.issuer,
                &grant,
                &claimed,
                Audience::new([audience]).expect("an audience"),
                Confirmation::dpop(&jkt).expect("a confirmation"),
                JwtId::generate(),
                now,
            )
            .with_grant_id()
            .build()
            .expect("an access token");
            self.keys
                .sign(
                    &issuer.id,
                    unsigned.required_algorithm(),
                    unsigned.typ(),
                    unsigned.claims(),
                )
                .await
                .expect("a signature")
                .as_str()
                .to_owned()
        }

        fn proof(&self, token: &str, method: &str, url: &str, jti: &str) -> String {
            let header = json!({
                "typ": "dpop+jwt",
                "alg": "EdDSA",
                "jwk": self.dpop_key.public_jwk().expect("a public JWK"),
            });
            let claims = json!({
                "jti": jti,
                "htm": method,
                "htu": url,
                "iat": time::OffsetDateTime::now_utc().unix_timestamp(),
                "ath": B64.encode(Sha256::digest(token.as_bytes())),
            });
            sign_by_hand(&self.dpop_key, &header, &claims)
        }
    }

    fn sign_by_hand(key: &SigningKey, header: &Value, claims: &Value) -> String {
        let signing_input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(header).expect("a header")),
            B64.encode(serde_json::to_vec(claims).expect("claims"))
        );
        let signature = key.sign(signing_input.as_bytes()).expect("a signature");
        format!("{signing_input}.{}", B64.encode(signature))
    }

    #[tokio::test]
    async fn a_valid_dpop_token_resolves_to_its_admin_scopes() {
        let routed = tenant("acme");
        let fixture = Fixture::new(vec![routed.clone()], None);
        let audience = admin_url(&routed, asterius_admin_api::BASE_PATH);
        let token = fixture
            .token(&routed, &audience, &["admin.users:read"])
            .await;
        let url = admin_url(&routed, "/admin/api/v1/users");
        let proof = fixture.proof(&token, "GET", &url, "valid-proof");

        let resolved = fixture
            .resolver
            .resolve(
                &routed,
                &PresentedToken {
                    token: &token,
                    proof: &proof,
                    method: "GET",
                    url: &url,
                },
            )
            .await
            .expect("the stores answer")
            .expect("valid credentials");

        assert_eq!(resolved.subject, "admin-automation");
        assert_eq!(resolved.tenant, Some(routed.id));
        assert_eq!(resolved.scopes, ["admin.users:read"]);
    }

    #[tokio::test]
    async fn a_proof_is_single_use() {
        let routed = tenant("acme");
        let fixture = Fixture::new(vec![routed.clone()], None);
        let audience = admin_url(&routed, asterius_admin_api::BASE_PATH);
        let token = fixture
            .token(&routed, &audience, &["admin.users:read"])
            .await;
        let url = admin_url(&routed, "/admin/api/v1/users");
        let proof = fixture.proof(&token, "GET", &url, "replayed-proof");
        let presented = PresentedToken {
            token: &token,
            proof: &proof,
            method: "GET",
            url: &url,
        };

        assert!(
            fixture
                .resolver
                .resolve(&routed, &presented)
                .await
                .expect("the stores answer")
                .is_some()
        );
        assert!(
            fixture
                .resolver
                .resolve(&routed, &presented)
                .await
                .expect("the stores answer")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_token_for_another_audience_is_refused() {
        let routed = tenant("acme");
        let fixture = Fixture::new(vec![routed.clone()], None);
        let token = fixture
            .token(
                &routed,
                "https://api.example/accounts",
                &["admin.users:read"],
            )
            .await;
        let url = admin_url(&routed, "/admin/api/v1/users");
        let proof = fixture.proof(&token, "GET", &url, "wrong-audience");

        assert!(
            fixture
                .resolver
                .resolve(
                    &routed,
                    &PresentedToken {
                        token: &token,
                        proof: &proof,
                        method: "GET",
                        url: &url,
                    },
                )
                .await
                .expect("the stores answer")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_tenant_token_is_refused_at_another_tenant() {
        let acme = tenant("acme");
        let other = tenant("other");
        let fixture = Fixture::new(vec![acme.clone(), other.clone()], None);
        let audience = admin_url(&acme, asterius_admin_api::BASE_PATH);
        let token = fixture.token(&acme, &audience, &["admin.users:read"]).await;
        let url = admin_url(&other, "/admin/api/v1/users");
        let proof = fixture.proof(&token, "GET", &url, "cross-tenant");

        assert!(
            fixture
                .resolver
                .resolve(
                    &other,
                    &PresentedToken {
                        token: &token,
                        proof: &proof,
                        method: "GET",
                        url: &url,
                    },
                )
                .await
                .expect("the stores answer")
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_reserved_tenant_may_issue_deployment_wide_automation() {
        let reserved = tenant("asterius-admin");
        let routed = tenant("acme");
        let fixture = Fixture::new(
            vec![reserved.clone(), routed.clone()],
            Some(reserved.id.clone()),
        );
        let audience = admin_url(&reserved, asterius_admin_api::BASE_PATH);
        let token = fixture
            .token(&reserved, &audience, &["admin.users:read"])
            .await;
        let url = admin_url(&routed, "/admin/api/v1/users");
        let proof = fixture.proof(&token, "GET", &url, "deployment-wide");

        let resolved = fixture
            .resolver
            .resolve(
                &routed,
                &PresentedToken {
                    token: &token,
                    proof: &proof,
                    method: "GET",
                    url: &url,
                },
            )
            .await
            .expect("the stores answer")
            .expect("reserved-tenant token");

        assert_eq!(resolved.tenant, None);
        assert_eq!(resolved.scopes, ["admin.users:read"]);
    }

    #[tokio::test]
    async fn a_valid_token_without_the_route_scope_is_not_authorized() {
        let routed = tenant("acme");
        let fixture = Fixture::new(vec![routed.clone()], None);
        let audience = admin_url(&routed, asterius_admin_api::BASE_PATH);
        let token = fixture
            .token(&routed, &audience, &["admin.clients:read"])
            .await;
        let url = admin_url(&routed, "/admin/api/v1/users");
        let proof = fixture.proof(&token, "GET", &url, "insufficient-scope");
        let resolved = fixture
            .resolver
            .resolve(
                &routed,
                &PresentedToken {
                    token: &token,
                    proof: &proof,
                    method: "GET",
                    url: &url,
                },
            )
            .await
            .expect("the stores answer")
            .expect("a valid but under-scoped token");
        let held = asterius_admin_api::Held::Scopes {
            tenant: resolved.tenant,
            scopes: resolved.scopes,
        };

        assert!(!held.satisfies(asterius_admin_api::USERS_LIST.authority(), &routed.id));
    }

    #[tokio::test]
    async fn a_malformed_access_token_is_refused() {
        let routed = tenant("acme");
        let fixture = Fixture::new(vec![routed.clone()], None);
        let url = admin_url(&routed, "/admin/api/v1/users");
        let proof = fixture.proof("not-a-jwt", "GET", &url, "invalid-token");

        assert!(
            fixture
                .resolver
                .resolve(
                    &routed,
                    &PresentedToken {
                        token: "not-a-jwt",
                        proof: &proof,
                        method: "GET",
                        url: &url,
                    },
                )
                .await
                .expect("the stores answer")
                .is_none()
        );
    }
}
