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
use asterius_domain::MailSender as _;
use asterius_domain::keys::KeyAdministration;
use asterius_domain::ports::PasskeyRepository as _;
use asterius_domain::ports::RecoveryTokenStore as _;
use asterius_domain::ports::{
    ClientAdministration, ClientUrlFetcher, TenantRepository, TenantSettingsRepository,
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
    outbound: Arc<dyn ClientUrlFetcher>,
    outbox: Arc<dyn asterius_domain::outbox::DeadLetterQuery>,
    dead_letters: Arc<dyn asterius_domain::outbox::DeadLetterOperations>,
    kek: Arc<dyn asterius_jose::Kek>,
    signer: Arc<dyn asterius_domain::keys::Signer>,
    queue: Option<Arc<dyn asterius_domain::outbox::OutboxQueue>>,
    argon2: asterius_domain::Argon2Parameters,
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
            store: parts.store,
            tenants: parts.tenants,
            keys: parts.keys,
            directory: parts.directory,
            settings: parts.settings,
            capabilities: parts.capabilities,
            registration: parts.registration,
            outbound: parts.outbound,
            outbox: parts.outbox,
            dead_letters: parts.dead_letters,
            kek: parts.kek,
            signer: parts.signer,
            queue: parts.queue,
            argon2: parts.argon2,
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
            crate::http::protocol::deployment_acr_policy(),
            tenant,
            request,
            time::OffsetDateTime::now_utc(),
        )
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
#[derive(Clone)]
struct DeploymentClients {
    store: Store,
    capabilities: Capabilities,
    outbound: Arc<dyn ClientUrlFetcher>,
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
        );
        if let Err(error) = scope.mail().send(&message).await {
            tracing::error!(%error, tenant = %tenant, "cannot hand off a recovery message");
            return false;
        }
        true
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

    fn tenant_settings(&self) -> Arc<dyn TenantSettingsRepository> {
        Arc::new(PgTenantSettings::new(self.store.pool().clone()))
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

    fn application_roles(&self) -> Arc<dyn asterius_domain::ApplicationRoleDirectory> {
        Arc::new(asterius_store_pg::PgApplicationRoles::new(
            self.store.pool().clone(),
        ))
    }

    /// The tenants' authorization policies (`ast-pj0.4`), over the pool the
    /// PDP decides from — so what an administrator edits is what the
    /// evaluation endpoint reads.
    fn policies(&self) -> Arc<dyn asterius_domain::ports::PolicyStore> {
        Arc::new(asterius_store_pg::PgPolicies::new(
            self.store.pool().clone(),
        ))
    }

    /// The PDP behind the console's policy test bench (`ast-f7m.9`).
    ///
    /// The same engine over the same pool as [`Self::policies`], so a bench
    /// answers about the document the editor just wrote, and the same
    /// `SubjectFacts` the AuthZEN endpoints resolve through, so it answers
    /// about the subject a relying party would be asking about.
    fn policy_trial(&self) -> Arc<dyn asterius_admin_api::backend::PolicyTrial> {
        Arc::new(DeploymentPolicyTrial {
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
