//! The `asterius` binary.
#![forbid(unsafe_code)]

use asterius_domain::ports::TenantRepository as _;
use asterius_domain::{Argon2Parameters, Lifetimes, ReplayGuard, Secret, TokenLifetimes};
use asterius_domain::{Feature, Tenant, TenantStatus};
use asterius_jose::client_keys::ClientKeyCache;
use asterius_jose::kek::Kek;
use asterius_jose::{CompositeKek, LocalKek};
use asterius_oidc::par;
use asterius_server::client_auth::ClientAuthenticator;
use asterius_server::config::{AdminConfig, KekSource, PasswordSource};
use asterius_server::http::dpop::DpopEndpoint;
use asterius_server::http::protocol::{self, ClientEndpoints, ProtocolState};
use asterius_server::http::server::{OperationalRoutes, app, not_found, serve, shutdown_signal};
use asterius_server::observability::health::HealthState;
use asterius_server::observability::{self, Metrics};
use asterius_server::outbound::HttpsClientUrlFetcher;
use asterius_server::outbox::{
    HttpDeliverer, JournalDeliverer, OutboxWorker, PgPushStreams, SsfPushDeliverer,
};
use asterius_server::retention::RetentionSweep;
use asterius_server::rotation::RotationSweep;
use asterius_server::signing::CachedSigner;
use asterius_server::tenancy::{TenantDirectory, TenantState};
use asterius_server::tenant_settings::SettingsDirectory;
use asterius_server::{Config, VERSION};
use asterius_store_pg::{
    DeploymentAdmin, PgAdminSeed, PgAuditSink, PgClientKeyFetches, PgClientUsage,
    PgInitialAccessTokens, PgKekRewrap, PgReplayGuard, PgRetention, PgTenantRepository,
    PgTenantSettings, ProvisionedTenants, RewrapOutcome, Store, TenantKeyStore,
};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use time::OffsetDateTime;

const DEFAULT_CONFIG_PATH: &str = "asterius.toml";
const USAGE: &str = "usage: asterius [--config <path>] [--config-reference] [--admin-openapi]\n       \
                     asterius rewrap-kek [--new-kek-file <path> | --new-kek-env <var>] \
                     [--config <path>]";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Startup failures go to stderr, not through tracing: the
            // subscriber may not be up yet, and an operator debugging a boot
            // failure should not need a log pipeline to read the reason.
            eprintln!("asterius: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let invocation = Invocation::parse(std::env::args_os().skip(1))?;
    match invocation.command {
        Command::Serve => serve_forever(&invocation.config),
        Command::RewrapKek(new_kek) => rewrap_kek(&invocation.config, new_kek.as_ref()),
    }
}

/// RFC 8705 §2 (`ast-m9c.3`), switched on in both places at once.
///
/// The two halves have to agree: the tenancy layer collects the proxy's
/// certificate at the door, and the authenticator verifies it against the
/// tenant's CAs. Returning them from one function is what makes "the flag is
/// off" mean both — a deployment cannot end up collecting certificates it will
/// never check, or holding anchors nothing reaches.
///
/// A named anchors file that cannot be read stops the process. An operator who
/// listed a CA meant clients to authenticate with it, and a server that started
/// without it would refuse every one of them for a reason only a debug log
/// would carry.
fn mtls(
    state: TenantState,
    config: &Config,
) -> Result<(TenantState, asterius_server::mtls::TenantTrustAnchors), String> {
    if !config.features.mtls {
        return Ok((state, asterius_server::mtls::TenantTrustAnchors::default()));
    }
    let anchors = asterius_server::mtls::TenantTrustAnchors::load(&config.mtls)
        .map_err(|e| format!("cannot load the mTLS trust anchors: {e}"))?;
    Ok((state.with_mtls(Arc::new(config.mtls.clone())), anchors))
}

/// The client authenticator, with the collaborators it is never useful without.
///
/// Extracted from `serve_forever` because the wiring has a reason attached to
/// it and a composition root is not the place to read one: recording a use is
/// wired *here* rather than at the three endpoints that authenticate, so that
/// `unused_client_expiry_seconds` (`ast-cu3`) has one definition of "used".
///
/// `trust_anchors` comes from [`mtls`] and is empty unless the flag is on, so a
/// deployment without mTLS has an authenticator that refuses `tls_client_auth`
/// rather than one that could be persuaded otherwise.
fn client_authenticator(
    client_keys: Arc<ClientKeyCache>,
    replay: &Arc<PgReplayGuard>,
    store: &Store,
    trust_anchors: asterius_server::mtls::TenantTrustAnchors,
) -> Result<Arc<ClientAuthenticator>, String> {
    let authenticator =
        ClientAuthenticator::new(client_keys, Arc::clone(replay) as Arc<dyn ReplayGuard>)
            .map_err(|e| format!("cannot build the client authenticator: {e}"))?
            .recording_use(Arc::new(PgClientUsage::new(store.pool().clone())))
            // `ast-4j1`: a refused client authentication is an audit event.
            // Wired here rather than at the six endpoints that need it,
            // because the authenticator is the one place all six agree on what
            // "this client failed to authenticate" means.
            .auditing(Arc::new(PgAuditSink::new(store.pool().clone())))
            .with_trust_anchors(trust_anchors);
    Ok(Arc::new(authenticator))
}

fn serve_forever(path: &std::path::Path) -> Result<(), String> {
    let config = Config::load(path).map_err(|e| e.to_string())?;

    observability::init(config.log_format);
    let metrics = Metrics::install().map_err(|e| format!("cannot install metrics: {e}"))?;

    let enabled: Vec<&str> = config.features.enabled().map(Feature::as_str).collect();
    tracing::info!(
        version = VERSION,
        config = %path.display(),
        mode = ?config.server.mode,
        tenants = config.tenants.len(),
        features = %if enabled.is_empty() { "none".to_owned() } else { enabled.join(",") },
        "starting"
    );
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("cannot start runtime: {e}"))?;
    runtime.block_on(async move {
        let store = Store::connect(
            config.database.url.expose(),
            config.database.max_connections,
        )
        .await
        .map_err(|e| format!("cannot connect to the database: {e}"))?;
        store
            .migrate()
            .await
            .map_err(|e| format!("cannot apply migrations: {e}"))?;

        // The key-encryption key, before anything that needs it. It seals both
        // the signing keys and each tenant's pairwise salt, and a tenant is
        // created with its salt — so this has to be loaded before the first
        // tenant is written, not just before the first token is signed.
        // Loading it at startup is deliberate either way: a deployment that
        // cannot read its own key material should fail while someone is
        // watching.
        let current = load_kek(&config.kek, "the key-encryption key")?;
        tracing::info!(kek = current.id(), "key-encryption key loaded");

        let kek = with_previous_kek(current, config.kek_previous.as_ref())?;

        // The key store before the tenants, because creating a tenant now
        // provisions its signing keys.
        let (keys, repository) = tenant_repository(&store, &kek);
        bootstrap_tenants(&repository, &config).await?;
        bootstrap_admin(&store, &kek, config.admin.as_ref()).await?;

        // One `dyn TenantRepository` for the process, and it is
        // `ProvisionedTenants`: see `admin_routes` for why that matters.
        let tenants: Arc<dyn asterius_domain::ports::TenantRepository> = Arc::new(repository);
        let directory = TenantDirectory::new(Arc::clone(&tenants));
        // One settings cache for the process, held by the discovery handler
        // and by the admin API, so that a write through the second is visible
        // to the first at once (`ast-f7m.4`). Two instances would each hold
        // their own copy and the invalidation would reach neither.
        let settings =
            SettingsDirectory::new(Arc::new(PgTenantSettings::new(store.pool().clone())));
        let (tenant_state, trust_anchors) =
            mtls(TenantState::new(directory.clone(), &config.server), &config)?;
        let operations = operational_routes(&store, &config, metrics);

        // Client-facing endpoints: the ones that need an authenticated client
        // and the database. Built here rather than lazily so that a deployment
        // that cannot construct them fails at startup, where somebody is
        // watching, rather than on a client's first request.
        // One outbound adapter, three callers: the key cache resolves
        // `jwks_uri` through it, `POST /register` resolves
        // `sector_identifier_uri` through it, and so does the admin API's
        // client screen (`ast-f7m.5`). ADR-0006 says one path, and one instance
        // is how that is spelt here.
        let outbound: Arc<dyn asterius_domain::ports::ClientUrlFetcher> = Arc::new(
            HttpsClientUrlFetcher::new()
                .map_err(|e| format!("cannot build the outbound TLS client: {e}"))?,
        );
        // One `PgOutbox` for the process: the delivery worker claims through it
        // and the admin API's dead-letter screen reads through it, so the
        // screen reports the schedule the worker is enforcing (`ast-0ju.9`).
        let outbox = outbox_handle(&store, config.outbox);
        let admin_context = AdminContext::of(&config, &outbound, &outbox, &kek);
        let client_keys = client_key_cache(&outbound, &store);
        let replay = Arc::new(PgReplayGuard::new(store.pool().clone()));
        let authenticator = client_authenticator(client_keys, &replay, &store, trust_anchors)?;

        let dpop = Arc::new(dpop_endpoint(
            Arc::clone(&replay) as Arc<dyn ReplayGuard>,
            &config,
        )?);

        let routes = protocol::routes(ProtocolState {
            keys: Arc::clone(&keys) as Arc<dyn asterius_domain::KeyStore>,
            capabilities: config.features,
            tenant_settings: Some(settings.clone()),
            clients: Some(Arc::new(ClientEndpoints {
                authenticator,
                store: store.clone(),
                keys: Arc::clone(&keys) as Arc<dyn asterius_domain::KeyStore>,
                capabilities: config.features,
                par_lifetime: par::clamp_lifetime(par::DEFAULT_LIFETIME),
                // What a tenant with no opinion of its own issues under; one
                // that has an opinion overrides it, read through `settings`
                // (`ast-ndk.2`, `ast-5c6`).
                lifetimes: TokenLifetimes::default(),
                tenant_settings: Some(settings.clone()),
                kek: Arc::clone(&kek),
                registration: config.registration.clone(),
                // What a tenant that gates itself registers on (`ast-cu3`).
                // Always wired here: the deployment has a pool, so there is no
                // reason for a tenant's own credentials to be unreadable.
                initial_access_tokens: Some(Arc::new(PgInitialAccessTokens::new(
                    store.pool().clone(),
                ))),
                outbound,
                audit: Arc::new(PgAuditSink::new(store.pool().clone())),
                session_lifetimes: Lifetimes::default().clamped(),
                // Passwords are the legacy path and passkeys are primary, but
                // the parameters are checked here rather than at first login:
                // a deployment configured below the OWASP floor should fail
                // while somebody is watching, not store weak hashes quietly.
                // `ast-2vk.15` makes these configurable; the default is the
                // floor.
                argon2: Some(Argon2Parameters::default()),
                // What bounds online guessing (`ast-2vk.9`). Validated at
                // load, so the handlers get numbers rather than opinions.
                login_limits: config.login,
                // What bounds abuse of the endpoints a client talks to
                // (`ast-p2l.3`). Validated at load, like the login limits.
                endpoint_limits: config.limits,
                signer: prepare_signer(&keys),
                dpop,
                // The same `PgOutbox` the delivery worker claims through, so a
                // back-channel logout token queued at the end-session endpoint
                // is picked up by the worker in this process under the
                // schedule this deployment configured (`ast-o4u.2`).
                outbox: Some(
                    Arc::new(outbox.clone()) as Arc<dyn asterius_domain::outbox::OutboxQueue>
                ),
            })),
        });

        let admin = admin_routes(&store, &tenants, &keys, directory, settings, admin_context);
        let routes = routes.merge(admin).merge(console_routes(&store));
        let routes = routes.fallback(not_found);
        let app = app(routes, tenant_state, Some(operations), &config.server);

        let workers = spawn_workers(
            (*keys).clone(),
            PgRetention::new(store.pool().clone()),
            &store,
            &kek,
            outbox,
            config.outbox,
        );

        let served = serve(&config.server, app, shutdown_signal())
            .await
            .map_err(|e| format!("server stopped: {e}"));

        // Stopped after the listener, not before: a request already in flight
        // may still sign something, and a sweep that is mid-transaction should
        // be allowed to finish it rather than be dropped.
        workers.stop().await;
        served
    })
}

/// The process-level endpoints: `/healthz`, `/readyz` and `/metrics`.
///
/// They describe the process rather than a tenant, which is why `app` mounts
/// them outside tenant resolution — a readiness probe that 404s because the
/// tenant directory cannot load would report the opposite of the truth.
fn operational_routes(store: &Store, config: &Config, metrics: Metrics) -> OperationalRoutes {
    OperationalRoutes {
        health: HealthState {
            store: store.clone(),
            features: Arc::new(config.features.enabled().map(Feature::as_str).collect()),
        },
        metrics,
    }
}

/// What the admin API needs from the configuration and the protocol wiring
/// (`ast-f7m.5`).
///
/// The client-screen three are grouped because they are one decision: a client
/// the console registers must be one `POST /register` would have accepted, so
/// the console validates against the deployment's capabilities, resolves a
/// sector through the deployment's one outbound adapter, and reports the
/// deployment's registration policy. Passing them individually would let a
/// future edit hand the admin API a *different* capability set from the
/// protocol endpoints', and the two would then disagree about what a valid
/// client is.
struct AdminContext {
    capabilities: asterius_domain::Capabilities,
    registration: asterius_server::http::register::RegistrationPolicy,
    outbound: Arc<dyn asterius_domain::ports::ClientUrlFetcher>,
    /// The process's `PgOutbox`, read-only, for the dead-letter screen
    /// (`ast-0ju.9`). Carried here for the reason `outbound` is: it is the
    /// deployment's one handle, and a second one built for the console would
    /// report a backlog nothing is working through.
    outbox: Arc<dyn asterius_domain::DeadLetterQuery>,
    /// The reserved tenant a deployment admin's session lives in (ADR-0010),
    /// or `None` for a deployment with no `[admin]` table and therefore no
    /// deployment admin. Which tenant may hold deployment authority is the
    /// deployment's decision and this file is where it is read (`ast-8gm`).
    reserved_tenant: Option<asterius_domain::TenantId>,
    /// The same `PgOutbox` as a queue, for the back-channel logout tokens an
    /// administrator's revocation sends (`ast-f7m.6`).
    queue: Arc<dyn asterius_domain::outbox::OutboxQueue>,
    /// The key-encryption key the pairwise salts are sealed under, which those
    /// tokens' `sub` is derived through.
    kek: Arc<dyn asterius_jose::Kek>,
}

impl AdminContext {
    /// Takes the deployment's own three, and never builds one of its own.
    ///
    /// `outbound` in particular is *cloned* from the process's single adapter:
    /// it is the third caller of ADR-0006's one outbound path, beside the key
    /// cache and `POST /register`, and a second HTTP client built for the
    /// console would be a second SSRF guard to keep in step.
    fn of(
        config: &Config,
        outbound: &Arc<dyn asterius_domain::ports::ClientUrlFetcher>,
        outbox: &asterius_store_pg::PgOutbox,
        kek: &Arc<dyn asterius_jose::Kek>,
    ) -> Self {
        Self {
            capabilities: config.features,
            registration: config.registration.clone(),
            outbound: Arc::clone(outbound),
            outbox: Arc::new(outbox.clone()),
            reserved_tenant: config.admin.as_ref().map(|admin| admin.tenant.clone()),
            queue: Arc::new(outbox.clone()),
            kek: Arc::clone(kek),
        }
    }
}

/// The admin API (`ast-f7m.1`), ready to merge into the tenanted router.
///
/// Merged into the *tenanted* router rather than mounted beside it, because an
/// administrator's session is a tenant's session: ADR-0010 keeps
/// `Session::tenant` non-optional, so "which tenant's sessions do I look this
/// cookie up in" must be answered before a handler runs. A deployment admin
/// therefore signs in at the reserved tenant's issuer, which is where their
/// session lives — and presents that session at whichever tenant's issuer they
/// are administering, since a `Reach::Tenant` route names no tenant in its
/// path. `reserved_tenant` is what lets the cookie resolve there; the authority
/// check is unchanged and still admits only a deployment-scoped role
/// (`ast-8gm`).
///
/// `tenants` is the process's one `dyn TenantRepository`, which is
/// `ProvisionedTenants`: a tenant created through this API gets its signing
/// keys in the same step, exactly like one declared in the configuration file
/// (`ast-qa3`).
///
/// The client-address layer is applied to these routes only. It copies the
/// address this crate resolved into the extension the admin API's limiter
/// reads, and nothing else needs it.
fn admin_routes(
    store: &Store,
    tenants: &Arc<dyn asterius_domain::ports::TenantRepository>,
    keys: &Arc<TenantKeyStore>,
    directory: TenantDirectory,
    settings: SettingsDirectory,
    context: AdminContext,
) -> axum::Router {
    asterius_admin_api::AdminApi::new(&asterius_admin_api::AdminState {
        backend: Arc::new(asterius_server::admin::Deployment::new(
            asterius_server::admin::DeploymentParts {
                store: store.clone(),
                tenants: Arc::clone(tenants),
                keys: Arc::clone(keys) as Arc<dyn asterius_domain::KeyAdministration>,
                directory,
                settings,
                capabilities: context.capabilities,
                registration: context.registration,
                outbound: context.outbound,
                outbox: context.outbox,
                kek: Arc::clone(&context.kek),
                signer: prepare_signer(keys),
                queue: Some(context.queue),
                argon2: Argon2Parameters::default(),
            },
        )),
        // `ast-a05.8` mints the tokens an automation caller would present.
        // Until it lands the mode answers 401 rather than accepting something
        // nothing verified.
        tokens: None,
        rate_limit: asterius_admin_api::throttle::DEFAULT_LIMIT,
        reserved_tenant: context.reserved_tenant,
    })
    .into_router()
    .layer(axum::middleware::from_fn(
        asterius_server::admin::client_address_layer,
    ))
}

/// The admin console (`ast-f7m.3`), served from inside the binary.
///
/// Merged into the *tenanted* router beside the admin API, and for the same
/// reason: the console's credential is a session, and a session belongs to a
/// tenant, so the shell has to be reached at the issuer whose sessions it will
/// use — `/t/{id}/admin/`, with no console at the root (ADR-0010).
///
/// It takes the store because the entry document is guarded (`ast-wr4`): a
/// visitor with no session is not shown a shell that will discover its own
/// 401, they are sent through the ordinary login flow by way of a first-party
/// interaction. The assets stay stateless.
///
/// A build made without `console/dist` carries an empty bundle and answers 503
/// with a sentence naming the missing step. The routes exist either way, so
/// that a deployment's URL space does not depend on how the binary was built.
fn console_routes(store: &Store) -> axum::Router {
    asterius_server::http::console::routes(store.clone(), asterius_admin_api::Bundle::embedded())
}

/// The client key cache, with its negative half shared through the database.
///
/// In memory alone the negative cache is per replica and per process lifetime,
/// so an unreachable third-party `jwks_uri` is fetched once per replica per
/// backoff window and again after every restart — a rate the operator did not
/// configure and the third party, not this deployment, notices first
/// (`ast-mxc.8`). The shared row makes the window one decision.
fn client_key_cache(
    outbound: &Arc<dyn asterius_domain::ports::ClientUrlFetcher>,
    store: &Store,
) -> Arc<ClientKeyCache> {
    Arc::new(
        ClientKeyCache::new(Arc::clone(outbound))
            .sharing_backoff(Arc::new(PgClientKeyFetches::new(store.pool().clone()))),
    )
}

/// The key store, and the tenant repository the whole process holds.
///
/// `ProvisionedTenants` rather than the bare adapter, so that writing a tenant
/// and giving it signing keys are one step: every consumer here takes the
/// `TenantRepository` port, and none of them can produce a tenant that holds no
/// keys and therefore refuses every client registration (`ast-qa3`). It is also
/// what makes a deployment started with the wrong key-encryption key fail at
/// boot, where somebody is watching, rather than on the first token request:
/// the pass opens the active key it just wrote.
fn tenant_repository(
    store: &Store,
    kek: &Arc<dyn Kek>,
) -> (Arc<TenantKeyStore>, ProvisionedTenants) {
    let keys = Arc::new(TenantKeyStore::new(
        store.pool().clone(),
        Arc::clone(kek),
        Arc::new(PgAuditSink::new(store.pool().clone())),
    ));
    let repository = ProvisionedTenants::new(
        PgTenantRepository::new(store.pool().clone(), Arc::clone(kek)),
        (*keys).clone(),
        Arc::new(asterius_domain::ports::SystemClock),
    );
    (keys, repository)
}

/// Builds the one object in this process that holds an unwrapped private key.
///
/// There is no schedule loop here any more. Provisioning a tenant's keys is
/// part of writing the tenant (`asterius_store_pg::ProvisionedTenants`), so by
/// the time this runs every tenant the configuration declares — and the
/// reserved tenant the admin seed writes — already holds an active key of
/// every advertised algorithm, and a wrong key-encryption key has already
/// failed the boot. A loop over the same tenants would repeat work rather than
/// guarantee anything, and it guaranteed nothing for a tenant created by any
/// other means, which is the bug it used to hide (`ast-qa3`).
///
/// The signer is built here because that is what `PgKeyRepository`'s own
/// documentation says the composition root is for: signing through the
/// repository would unwrap the key on every token, which for a cloud KEK is a
/// network round trip each time.
fn prepare_signer(keys: &Arc<TenantKeyStore>) -> Arc<dyn asterius_domain::keys::Signer> {
    Arc::new(CachedSigner::new(
        (**keys).clone(),
        Arc::new(asterius_domain::ports::SystemClock),
    ))
}

/// The periodic tasks, and the one handle that stops them all.
///
/// They share a stop channel because they share a lifetime: both run for as
/// long as the listener does, and both must be allowed to finish the pass they
/// are in rather than be dropped mid-transaction.
struct Workers {
    stop: tokio::sync::watch::Sender<bool>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Workers {
    /// Asks every task to stop and waits for each to finish its current pass.
    async fn stop(self) {
        let _ = self.stop.send(true);
        for handle in self.handles {
            let _ = handle.await;
        }
    }
}

/// Starts the background sweeps.
///
/// **Rotation** is what makes key rotation something that happens rather than
/// something a restart does (`ast-mxc.9`): `prepare_keys` applies the
/// configured tenants' schedules once at boot and fails loudly if it cannot,
/// and this keeps every tenant's schedule applied for the life of the process,
/// including tenants created through the admin API afterwards.
///
/// **Retention** applies `asterius_store_pg::retention::POLICY`, which names
/// every table in the schema as swept or kept. Not optional and not
/// configurable off: a deployment that does not sweep accumulates expired
/// codes, PAR parameters, session fingerprints and replay markers forever, and
/// the point of storing a credential's digest for sixty seconds is that it is
/// gone afterwards (RFC 9700 §4.2-4.3, FAPI 2.0 SP §7). Safe on every replica
/// at once: it takes a per-tenant advisory lock and skips a tenant somebody
/// else is already sweeping.
fn spawn_workers(
    keys: TenantKeyStore,
    retention: PgRetention,
    store: &Store,
    kek: &Arc<dyn Kek>,
    outbox: asterius_store_pg::PgOutbox,
    schedule: asterius_server::config::OutboxConfig,
) -> Workers {
    let clock: Arc<dyn asterius_domain::ports::Clock> =
        Arc::new(asterius_domain::ports::SystemClock);
    let tenants_for_rotation = Arc::new(PgTenantRepository::new(
        store.pool().clone(),
        Arc::clone(kek),
    ));
    let tenants_for_retention = Arc::new(PgTenantRepository::new(
        store.pool().clone(),
        Arc::clone(kek),
    ));

    let rotation = RotationSweep::new(keys, tenants_for_rotation, Arc::clone(&clock));
    let retention = RetentionSweep::new(retention, tenants_for_retention, Arc::clone(&clock));
    let delivery = outbox_worker(
        outbox,
        schedule,
        Arc::clone(&clock),
        store,
        kek,
        Arc::new(PgAuditSink::new(store.pool().clone())),
    );

    let (stop, stopping) = tokio::sync::watch::channel(false);
    let handles = vec![
        tokio::spawn(rotation.run(stopped(stopping.clone()))),
        tokio::spawn(retention.run(stopped(stopping.clone()))),
        tokio::spawn(delivery.run(stopped(stopping))),
    ];
    Workers { stop, handles }
}

/// The one `PgOutbox` this process holds (`ast-0ju.9`).
///
/// One, and not two. The delivery worker claims through it and the admin API's
/// dead-letter screen reads through it, so the screen reports the schedule the
/// worker is actually enforcing rather than a second copy of the configuration
/// that happens to agree today.
fn outbox_handle(
    store: &Store,
    schedule: asterius_server::config::OutboxConfig,
) -> asterius_store_pg::PgOutbox {
    asterius_store_pg::PgOutbox::with_schedule(
        store.pool().clone(),
        asterius_store_pg::Backoff {
            base: schedule.retry,
            cap: schedule.max_retry,
        },
        schedule.lease,
    )
    .with_max_attempts(schedule.max_attempts)
}

/// The outbox delivery worker, with the deliverers this build registers.
///
/// Three, and none is speculative: the journal, which is `ast-2vk.10`'s mail
/// table becoming a consumer of this worker rather than a table nothing reads;
/// a generic HTTP `POST` through ADR-0006's outbound path, registered for the
/// `logout` family back-channel logout queues into; and SSF push delivery
/// (`ast-0ju.6`), which is a `POST` too but reads the receiver's answer
/// against RFC 8935 §2.3 and stops a stream that has run out of retries. CIBA
/// registers its own when it lands.
///
/// A worker name per process, so two replicas' claims are distinguishable in a
/// log. Random rather than the hostname: a hostname is an operational detail
/// that ends up in a `claimed_by` column and then in a support ticket.
fn outbox_worker(
    outbox: asterius_store_pg::PgOutbox,
    schedule: asterius_server::config::OutboxConfig,
    clock: Arc<dyn asterius_domain::ports::Clock>,
    store: &Store,
    kek: &Arc<dyn Kek>,
    audit: Arc<dyn asterius_domain::audit::AuditSink>,
) -> OutboxWorker {
    let name = format!("worker-{}", uuid::Uuid::new_v4());
    let mut worker = OutboxWorker::new(outbox, Arc::clone(&clock), name)
        .with_pace(schedule.poll, schedule.batch)
        .with(Arc::new(JournalDeliverer));

    match asterius_server::outbound::HttpsPoster::new() {
        Ok(poster) => {
            worker = worker
                .with(Arc::new(HttpDeliverer::new("logout", poster.clone())))
                .with(Arc::new(SsfPushDeliverer::new(
                    Arc::new(PgPushStreams::new(store.clone(), Arc::clone(kek))),
                    Arc::new(poster),
                    audit,
                    clock,
                )));
        }
        Err(error) => {
            // Not fatal, and not silent. A build whose TLS provider will not
            // accept the outbound cipher suites cannot deliver anything over
            // HTTP, and the rows dead-letter with "no deliverer is registered
            // for the logout family" — which is the correct outcome and an
            // impossible one to diagnose without this line.
            tracing::error!(
                %error,
                "could not build the outbound TLS configuration; HTTP outbox \
                 deliveries are disabled in this process"
            );
        }
    }
    worker
}

/// Resolves when the stop channel says so.
async fn stopped(mut stopping: tokio::sync::watch::Receiver<bool>) {
    let _ = stopping.changed().await;
}

/// Re-seals every sealed row under a new key-encryption key.
///
/// The KEK in the configuration file is the one the deployment is running on,
/// so it is the *old* key here; the new one comes from the command line, which
/// is what keeps the two apart without asking an operator to edit the config
/// file half-way through a rotation. See `asterius_store_pg::PgKekRewrap` for
/// what moves and why the pairwise salt cannot simply be updated, and
/// `docs/runbooks/backup-restore.md` §4 for the order the steps go in.
///
/// It is a foreground command with a report on stdout rather than a background
/// sweep: rotating a KEK is an operator decision taken during a change window,
/// and the operator has to read the result before destroying the old material.
/// Running it twice is safe and is in fact the documented procedure — the
/// second pass catches rows written by replicas that were still on the old key
/// during the first.
fn rewrap_kek(path: &std::path::Path, new_kek: Option<&KekSource>) -> Result<(), String> {
    let config = Config::load(path).map_err(|e| e.to_string())?;

    // Two directions, one command. Without `--new-kek-*` the configuration
    // already describes the rotation — `kek_previous_*` is the key the rows are
    // still under and `kek_*` is the key they are going to — which is the
    // online pass: the replicas are already running on the new key and opening
    // the stragglers through `CompositeKek`, so this is only catching them up.
    // With `--new-kek-*` it is the original offline shape, where the
    // configuration names the old key and the new one has not been written into
    // it yet.
    let (from, to) = if let Some(source) = new_kek {
        (
            load_kek(&config.kek, "the key-encryption key")?,
            load_kek(source, "the new key-encryption key")?,
        )
    } else {
        let previous = config.kek_previous.as_ref().ok_or(
            "rewrap-kek needs a destination: pass --new-kek-file or --new-kek-env, or \
                 set keys.kek_previous_file (or keys.kek_previous_env) to the key the rows \
                 are still under",
        )?;
        (
            load_kek(previous, "the previous key-encryption key")?,
            load_kek(&config.kek, "the key-encryption key")?,
        )
    };
    println!(
        "asterius {VERSION}: re-wrapping from {} to {}",
        from.id(),
        to.id()
    );

    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("cannot start runtime: {e}"))?;
    runtime.block_on(async move {
        let store = Store::connect(
            config.database.url.expose(),
            config.database.max_connections,
        )
        .await
        .map_err(|e| format!("cannot connect to the database: {e}"))?;

        // No migration here, deliberately: a rotation is not the moment to
        // change the schema, and the tool has to be runnable against a
        // database whose replicas are mid-upgrade.
        let tenants = PgTenantRepository::new(store.pool().clone(), Arc::clone(&from))
            .list()
            .await
            .map_err(|e| format!("cannot list tenants: {e}"))?;
        let rewrap = PgKekRewrap::new(store.pool().clone());

        let mut incomplete = 0_usize;
        for tenant in &tenants {
            let outcome = rewrap
                .rewrap_tenant(&tenant.id, from.as_ref(), to.as_ref())
                .await
                .map_err(|e| format!("cannot re-wrap tenant {}: {e}", tenant.id))?;

            match outcome {
                RewrapOutcome::Busy => {
                    incomplete += 1;
                    println!("{}: busy, another re-wrap holds this tenant", tenant.id);
                }
                RewrapOutcome::Rewrapped(pass) => {
                    if !pass.is_complete() {
                        incomplete += 1;
                    }
                    println!(
                        "{}: signing keys {}, pairwise salt {}, still on the old key {}, \
                         sealed under an unknown key {}",
                        tenant.id,
                        pass.signing_keys,
                        if pass.pairwise_salt {
                            "re-wrapped"
                        } else {
                            "nothing to do"
                        },
                        pass.left_behind,
                        pass.stranded
                    );
                }
            }
        }

        if incomplete == 0 {
            println!(
                "{} tenant(s) are wholly on {}. Point the configuration at it and restart, \
                 then run this once more before destroying the old material.",
                tenants.len(),
                to.id()
            );
            Ok(())
        } else {
            Err(format!(
                "{incomplete} of {} tenant(s) are not wholly on {}; do not destroy the old \
                 key material — run this again once the replicas are on the new key",
                tenants.len(),
                to.id()
            ))
        }
    })
}

/// The DPoP checker, over the nonce secret the operator configured.
///
/// `[dpop] nonce_secret` is what makes a nonce minted by one replica good at
/// another (`ast-a05.11`). Without it each process mints its own, so a client
/// that gets a nonce from one and presents it to another is told to retry: a
/// round trip rather than a failure, but one per request instead of one per
/// client. That is worth a line in the log rather than silence, because it is
/// invisible from anywhere else — the deployment works, slightly worse.
///
/// # Errors
///
/// Returns a message to print if the endpoint cannot be built.
fn dpop_endpoint(replay: Arc<dyn ReplayGuard>, config: &Config) -> Result<DpopEndpoint, String> {
    let secret = config.dpop.nonce_secret.as_ref();
    if config.features.is_enabled(Feature::DpopNonce) && secret.is_none() {
        tracing::info!(
            "DPoP nonces are per process: no dpop.nonce_secret is configured, so a nonce issued \
             by this replica is not accepted by another"
        );
    }
    DpopEndpoint::for_capabilities(
        replay,
        &config.features,
        // The one place the secret is exposed: it exists to key the HMAC the
        // nonces are derived from, and nothing else reads it.
        secret.map(|secret| secret.expose().as_slice()),
    )
    .map_err(|e| format!("cannot build the DPoP endpoint: {e}"))
}

/// Wraps the current key in a [`CompositeKek`] when a rotation is in flight.
///
/// The previous key is loaded here, at boot, for the reason the current one is:
/// a key that cannot be read is a configuration mistake, and finding that out
/// on the first row that needs it means finding it out from a failed sign-in.
/// It is used on reads only — see [`CompositeKek`] for the risk it takes on,
/// and `docs/runbooks/backup-restore.md` §4 for when to take the line back out.
fn with_previous_kek(
    current: Arc<dyn Kek>,
    previous: Option<&KekSource>,
) -> Result<Arc<dyn Kek>, String> {
    let Some(source) = previous else {
        return Ok(current);
    };
    let previous = load_kek(source, "the previous key-encryption key")?;
    tracing::warn!(
        kek = current.id(),
        previous = previous.id(),
        "a previous key-encryption key is configured: rows that do not open under \
         the current key are retried under it, and it stays readable by this \
         process until the line is removed"
    );
    let composite = CompositeKek::new(current, previous)
        .map_err(|e| format!("cannot use the previous key-encryption key: {e}"))?;
    Ok(Arc::new(composite))
}

/// Loads a KEK from wherever the operator put it.
///
/// `which` names the key in the failure message. There are up to three in play
/// — the one in use, the one a rotation came from, the one it is going to — and
/// "cannot load the key-encryption key" on its own leaves an operator guessing
/// which line of the configuration to look at.
fn load_kek(source: &KekSource, which: &str) -> Result<Arc<dyn Kek>, String> {
    let kek = match source {
        KekSource::File(path) => LocalKek::from_file(path),
        KekSource::Env(variable) => LocalKek::from_env(variable),
    }
    .map_err(|e| format!("cannot load {which}: {e}"))?;
    Ok(Arc::new(kek))
}

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    config: PathBuf,
    command: Command,
}

/// The one thing the binary does, or the one operator command it also offers.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// Run the server. What every deployment does.
    Serve,
    /// Re-seal everything under the KEK named on the command line, and exit.
    ///
    /// `None` means "the destination is in the configuration": the deployment
    /// is already running on `keys.kek_*` and `keys.kek_previous_*` names the
    /// key the remaining rows are still under.
    RewrapKek(Option<KekSource>),
}

impl Invocation {
    /// Parses the arguments, exiting for `--help` and `--config-reference`.
    ///
    /// Hand-rolled, like the rest of this binary's argument handling: the
    /// surface is a subcommand and three flags, and a parser dependency for
    /// that is a dependency to audit for the life of the project.
    fn parse<I>(arguments: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = std::ffi::OsString>,
    {
        let mut arguments = arguments.into_iter();
        let mut path: Option<PathBuf> = None;
        let mut command = Command::Serve;
        let mut new_kek_file: Option<PathBuf> = None;
        let mut new_kek_env: Option<String> = None;

        while let Some(argument) = arguments.next() {
            match argument.to_str() {
                Some("--config" | "-c") => {
                    let value = arguments.next().ok_or("--config needs a path")?;
                    path = Some(PathBuf::from(value));
                }
                Some("--help" | "-h") => {
                    println!("{USAGE}");
                    std::process::exit(0);
                }
                // Prints docs/configuration.md and exits. It lives behind a
                // flag on the server binary rather than in a generator of its
                // own so that the document can only ever be produced by the
                // same build that defines the schema it describes.
                Some("--config-reference") => {
                    print!("{}", asterius_server::config_reference::render());
                    std::process::exit(0);
                }
                // Prints docs/admin-api-openapi.json and exits, behind a flag
                // on this binary for the same reason: the document is
                // generated from the admin API's route registry, so only the
                // build that owns the registry can produce it. A document
                // maintained beside the code is `ast-iko` waiting to happen —
                // there, discovery advertised response modes the server does
                // not implement.
                Some("--admin-openapi") => {
                    print!("{}", asterius_admin_api::openapi::document());
                    std::process::exit(0);
                }
                Some("rewrap-kek") => command = Command::RewrapKek(None),
                Some("--new-kek-file") => {
                    let value = arguments.next().ok_or("--new-kek-file needs a path")?;
                    new_kek_file = Some(PathBuf::from(value));
                }
                Some("--new-kek-env") => {
                    let value = arguments.next().ok_or("--new-kek-env needs a variable")?;
                    new_kek_env = Some(
                        value
                            .into_string()
                            .map_err(|_| "--new-kek-env needs a UTF-8 variable name")?,
                    );
                }
                _ => {
                    return Err(format!(
                        "unexpected argument {}\n{USAGE}",
                        PathBuf::from(argument).display()
                    ));
                }
            }
        }

        // At most one source, and only where it means something. Two sources
        // would leave "which key am I rotating to" to argument order, and a
        // key named for a run that is not a rotation is an operator who typed
        // the wrong command and would otherwise be given a server. None is
        // allowed now: `keys.kek_previous_*` in the configuration says which
        // key the rows are still under, and `rewrap_kek` refuses if neither
        // that nor a flag names a direction.
        let command = match (command, new_kek_file, new_kek_env) {
            (Command::RewrapKek(_), Some(file), None) => {
                Command::RewrapKek(Some(KekSource::File(file)))
            }
            (Command::RewrapKek(_), None, Some(variable)) => {
                Command::RewrapKek(Some(KekSource::Env(variable)))
            }
            (Command::RewrapKek(_), None, None) => Command::RewrapKek(None),
            (Command::RewrapKek(_), _, _) => {
                return Err(format!(
                    "rewrap-kek takes at most one of --new-kek-file and --new-kek-env\n{USAGE}"
                ));
            }
            (Command::Serve, None, None) => Command::Serve,
            (Command::Serve, _, _) => {
                return Err(format!(
                    "--new-kek-file and --new-kek-env belong to rewrap-kek\n{USAGE}"
                ));
            }
        };

        Ok(Self {
            config: path
                .or_else(|| std::env::var_os("ASTERIUS_CONFIG").map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
            command,
        })
    }
}

/// Writes the tenants declared in the configuration into the database.
///
/// The configuration file is the source of truth for which tenants exist at
/// boot; the admin API adds more at runtime. The upsert is idempotent, so a
/// restart re-asserts the declared shape without disturbing anything else — and
/// an operator who corrects an issuer in the file sees it applied rather than
/// silently ignored because the row already existed.
async fn bootstrap_tenants(repository: &ProvisionedTenants, config: &Config) -> Result<(), String> {
    for declared in &config.tenants {
        let existing = repository
            .find_by_id(&declared.id)
            .await
            .map_err(|e| format!("cannot read tenant {}: {e}", declared.id))?;

        let tenant = Tenant {
            id: declared.id.clone(),
            issuer: declared.issuer.clone(),
            custom_host: existing.as_ref().and_then(|t| t.custom_host.clone()),
            display_name: existing
                .as_ref()
                .map_or_else(|| declared.id.to_string(), |t| t.display_name.clone()),
            // Config wins, because it is the thing an operator edits. The
            // stored value is not preserved the way `display_name` is: an
            // audience that silently outlived the configuration that set it is
            // how a tenant keeps minting tokens for a resource server that was
            // decommissioned.
            default_resource: declared.default_resource.clone(),
            status: existing.as_ref().map_or(TenantStatus::Active, |t| t.status),
            // Config wins here too, and for the same reason `default_resource`
            // does: a refresh policy is a security setting an operator edits
            // in the file, and one that silently outlived the file is a
            // rotation window somebody believes they closed.
            refresh: declared.refresh,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        repository
            .upsert(&tenant)
            .await
            .map_err(|e| format!("cannot write tenant {}: {e}", declared.id))?;

        tracing::info!(
            tenant = %tenant.id,
            issuer = %tenant.issuer,
            status = tenant.status.as_str(),
            new = existing.is_none(),
            "tenant ready"
        );
    }
    Ok(())
}

/// Seeds the deployment admin the configuration declares (ADR-0010).
///
/// The reserved tenant, a user in it, a password and a deployment-scoped role,
/// re-asserted idempotently on every boot exactly as `[[tenant]]` is. Nothing
/// happens when `[admin]` is absent: an account that administers every tenant
/// in the process is something an operator asks for.
///
/// A seeded admin that cannot sign in stops the boot. It is the one thing this
/// function exists to produce, the failure is silent everywhere else — the
/// console simply refuses a correct password — and a deployment nobody can
/// administer should fail while somebody is watching.
async fn bootstrap_admin(
    store: &Store,
    kek: &Arc<dyn Kek>,
    admin: Option<&AdminConfig>,
) -> Result<(), String> {
    let Some(admin) = admin else {
        tracing::info!("no [admin] table: no deployment admin is seeded");
        return Ok(());
    };

    let password = read_password(&admin.password)?;
    let seed = PgAdminSeed::new(
        store.pool().clone(),
        Arc::clone(kek),
        // The same floor every other password in the deployment is hashed at.
        // `ast-2vk.15` makes it configurable; until then a seeded admin must
        // not be hashed more cheaply than a user.
        Argon2Parameters::default(),
    );

    let seeded = seed
        .ensure(&DeploymentAdmin {
            tenant: admin.tenant.clone(),
            issuer: admin.issuer.clone(),
            username: admin.username.clone(),
            password,
        })
        .await
        .map_err(|e| format!("cannot seed the deployment admin: {e}"))?;

    if !seeded.can_authenticate {
        return Err(format!(
            "the deployment admin {} in tenant {} cannot authenticate with the \
             configured password: the account or its credential is disabled. Re-enable \
             it, or remove [admin] if the deployment is meant to have no seeded admin",
            admin.username, seeded.tenant
        ));
    }

    tracing::info!(
        tenant = %seeded.tenant,
        username = %admin.username,
        user = %seeded.user.as_uuid(),
        new = seeded.created,
        "deployment admin ready"
    );
    Ok(())
}

/// Reads the deployment admin's initial password from wherever it is kept.
///
/// Trimmed, because the usual way to write a secret to a file adds a newline
/// and a password that silently includes one is a password that only works
/// from that file. Never in the configuration file itself: see
/// [`PasswordSource`].
fn read_password(source: &PasswordSource) -> Result<Secret<String>, String> {
    let raw = match source {
        PasswordSource::File(path) => std::fs::read_to_string(path).map_err(|e| {
            format!(
                "cannot read the admin password from {}: {e}",
                path.display()
            )
        })?,
        PasswordSource::Env(variable) => std::env::var(variable).map_err(|_| {
            format!("the admin password variable {variable} is not set in the environment")
        })?,
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("the configured admin password is empty".to_owned());
    }
    Ok(Secret::new(trimmed.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{Command, Invocation, read_password};
    use asterius_server::config::{KekSource, PasswordSource};
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn parse(arguments: &[&str]) -> Result<Invocation, String> {
        Invocation::parse(arguments.iter().map(OsString::from))
    }

    #[test]
    fn no_arguments_asks_for_a_server() {
        let invocation = parse(&[]).expect("no arguments is a valid invocation");

        assert_eq!(invocation.command, Command::Serve);
    }

    #[test]
    fn a_rewrap_reads_its_new_key_from_a_file() {
        let invocation =
            parse(&["rewrap-kek", "--new-kek-file", "/etc/asterius/kek.new"]).expect("valid");

        assert_eq!(
            invocation.command,
            Command::RewrapKek(Some(KekSource::File(PathBuf::from(
                "/etc/asterius/kek.new"
            ))))
        );
    }

    #[test]
    fn a_rewrap_reads_its_new_key_from_the_environment() {
        let invocation =
            parse(&["rewrap-kek", "--new-kek-env", "ASTERIUS_KEK_NEXT"]).expect("valid");

        assert_eq!(
            invocation.command,
            Command::RewrapKek(Some(KekSource::Env("ASTERIUS_KEK_NEXT".to_owned())))
        );
    }

    /// Two sources would leave "which key am I rotating to" to argument order,
    /// on the one command where guessing wrong is unrecoverable.
    #[test]
    fn a_rewrap_with_two_new_keys_is_refused() {
        let refused = parse(&[
            "rewrap-kek",
            "--new-kek-file",
            "/k",
            "--new-kek-env",
            "ASTERIUS_KEK_NEXT",
        ]);

        assert!(refused.is_err(), "{refused:?}");
    }

    /// A re-wrap with no flag is the online shape: the configuration already
    /// names both keys, `kek_previous_*` being the one the rows are still
    /// under. Whether it really does is `rewrap_kek`'s question — the parser's
    /// job is only to stop inventing a destination that was never typed.
    #[test]
    fn a_rewrap_with_no_new_key_takes_its_direction_from_the_configuration() {
        let invocation = parse(&["rewrap-kek"]).expect("valid");

        assert_eq!(invocation.command, Command::RewrapKek(None));
    }

    /// An operator who meant to rotate and mistyped the subcommand gets an
    /// error rather than a server started with a key it will never use.
    #[test]
    fn a_new_key_without_the_subcommand_is_refused() {
        let refused = parse(&["--new-kek-file", "/k"]);

        assert!(refused.is_err(), "{refused:?}");
    }

    #[test]
    fn a_rewrap_still_takes_the_configuration_path() {
        let invocation = parse(&[
            "rewrap-kek",
            "--config",
            "/etc/asterius/asterius.toml",
            "--new-kek-env",
            "K",
        ])
        .expect("valid");

        assert_eq!(
            invocation.config,
            PathBuf::from("/etc/asterius/asterius.toml")
        );
    }

    // ---- the deployment admin's password ---------------------------------

    /// Writes `content` to a uniquely named file under the temporary
    /// directory. No `tempfile` dependency for three tests, and the name
    /// carries the process id so parallel runs cannot collide.
    fn a_file_containing(content: &str, tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "asterius-admin-password-{}-{tag}",
            std::process::id()
        ));
        std::fs::write(&path, content).expect("write the fixture");
        path
    }

    /// The usual way to put a secret in a file leaves a newline at the end of
    /// it, and a password that silently includes one only works from that file.
    #[test]
    fn a_password_file_is_read_without_its_surrounding_whitespace() {
        let path = a_file_containing("  a long enough passphrase\n", "trailing");

        let password = read_password(&PasswordSource::File(path.clone())).expect("read");

        assert_eq!(password.expose(), "a long enough passphrase");
        let _ = std::fs::remove_file(path);
    }

    /// An empty file is an orchestrator that mounted the wrong secret, not a
    /// deployment that meant to have a password of nothing.
    #[test]
    fn an_empty_password_file_is_refused() {
        let path = a_file_containing("\n", "empty");

        let refused = read_password(&PasswordSource::File(path.clone()));

        assert!(refused.is_err(), "an empty password was accepted");
        let _ = std::fs::remove_file(path);
    }

    /// The message names the variable, because that is what the operator has
    /// to go and set.
    #[test]
    fn an_unset_password_variable_names_itself_in_the_error() {
        let refused = read_password(&PasswordSource::Env(
            "ASTERIUS_A_VARIABLE_NOTHING_SETS".to_owned(),
        ))
        .expect_err("an unset variable cannot yield a password");

        assert!(
            refused.contains("ASTERIUS_A_VARIABLE_NOTHING_SETS"),
            "{refused}"
        );
    }
}
