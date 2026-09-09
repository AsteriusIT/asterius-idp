//! The `asterius` binary.
#![forbid(unsafe_code)]

use asterius_domain::ports::TenantRepository as _;
use asterius_domain::{Argon2Parameters, Lifetimes, ReplayGuard};
use asterius_domain::{Feature, Tenant, TenantStatus};
use asterius_jose::LocalKek;
use asterius_jose::client_keys::ClientKeyCache;
use asterius_jose::kek::Kek;
use asterius_oidc::{code, par};
use asterius_server::client_auth::ClientAuthenticator;
use asterius_server::config::KekSource;
use asterius_server::http::dpop::DpopEndpoint;
use asterius_server::http::protocol::{self, ClientEndpoints, ProtocolState};
use asterius_server::http::server::{OperationalRoutes, app, not_found, serve, shutdown_signal};
use asterius_server::observability::health::HealthState;
use asterius_server::observability::{self, Metrics};
use asterius_server::outbound::HttpsJwksFetcher;
use asterius_server::rotation::RotationSweep;
use asterius_server::signing::CachedSigner;
use asterius_server::tenancy::{TenantDirectory, TenantState};
use asterius_server::{Config, VERSION};
use asterius_store_pg::{PgAuditSink, PgReplayGuard, PgTenantRepository, Store, TenantKeyStore};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use time::OffsetDateTime;

const DEFAULT_CONFIG_PATH: &str = "asterius.toml";
const USAGE: &str = "usage: asterius [--config <path>]";

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
    let path = config_path()?;
    let config = Config::load(&path).map_err(|e| e.to_string())?;

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
        let kek: Arc<dyn Kek> = Arc::new(match &config.kek {
            KekSource::File(path) => LocalKek::from_file(path)
                .map_err(|e| format!("cannot load the key-encryption key: {e}"))?,
            KekSource::Env(variable) => LocalKek::from_env(variable)
                .map_err(|e| format!("cannot load the key-encryption key: {e}"))?,
        });
        tracing::info!(kek = kek.id(), "key-encryption key loaded");

        let repository = PgTenantRepository::new(store.pool().clone(), Arc::clone(&kek));
        bootstrap_tenants(&repository, &config).await?;

        let directory = TenantDirectory::new(Arc::new(repository));
        let tenant_state = TenantState::new(directory, &config.server);
        let operations = OperationalRoutes {
            health: HealthState {
                store: store.clone(),
                features: Arc::new(config.features.enabled().map(Feature::as_str).collect()),
            },
            metrics,
        };

        let (keys, signer) = prepare_keys(&store, &kek, &config).await?;

        // Client-facing endpoints: the ones that need an authenticated client
        // and the database. Built here rather than lazily so that a deployment
        // that cannot construct them fails at startup, where somebody is
        // watching, rather than on a client's first request.
        // One outbound adapter, two callers: the key cache resolves `jwks_uri`
        // through it and client registration resolves `sector_identifier_uri`
        // through it. ADR-0006 says one path, and one instance is how that is
        // spelt here.
        let outbound: Arc<dyn asterius_domain::ports::JwksFetcher> = Arc::new(
            HttpsJwksFetcher::new()
                .map_err(|e| format!("cannot build the outbound TLS client: {e}"))?,
        );
        let client_keys = Arc::new(ClientKeyCache::new(Arc::clone(&outbound)));
        let replay = Arc::new(PgReplayGuard::new(store.pool().clone()));
        let authenticator = Arc::new(
            ClientAuthenticator::new(client_keys, Arc::clone(&replay) as Arc<dyn ReplayGuard>)
                .map_err(|e| format!("cannot build the client authenticator: {e}"))?,
        );

        // DPoP. The nonce secret is per process for now: with more than one
        // replica each mints its own, so a client that gets a nonce from one
        // and presents it to another is told to retry. That costs a round trip
        // rather than correctness, and `ast-a05.11` adds the config key.
        let dpop = Arc::new(
            DpopEndpoint::for_capabilities(
                Arc::clone(&replay) as Arc<dyn ReplayGuard>,
                &config.features,
                None,
            )
            .map_err(|e| format!("cannot build the DPoP endpoint: {e}"))?,
        );

        let routes = protocol::routes(ProtocolState {
            keys: Arc::clone(&keys) as Arc<dyn asterius_domain::KeyStore>,
            capabilities: config.features,
            clients: Some(Arc::new(ClientEndpoints {
                authenticator,
                store: store.clone(),
                capabilities: config.features,
                par_lifetime: par::clamp_lifetime(par::DEFAULT_LIFETIME),
                // `ast-ndk.2` makes this per tenant. The default is the cap
                // itself: a code is redeemed within one round trip of being
                // issued, so a shorter one buys nothing and a slow network
                // loses by it.
                code_lifetime: code::clamp_lifetime(code::DEFAULT_LIFETIME),
                kek: Arc::clone(&kek),
                registration: config.registration.clone(),
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
                signer,
                dpop,
            })),
        })
        .fallback(not_found);
        let app = app(routes, tenant_state, Some(operations), &config.server);

        let (stop_sweep, sweeper) = spawn_rotation(
            (*keys).clone(),
            Arc::new(PgTenantRepository::new(
                store.pool().clone(),
                Arc::clone(&kek),
            )),
        );

        let served = serve(&config.server, app, shutdown_signal())
            .await
            .map_err(|e| format!("server stopped: {e}"));

        // Stopped after the listener, not before: a request already in flight
        // may still sign something, and a sweep that is mid-transaction should
        // be allowed to finish it rather than be dropped.
        let _ = stop_sweep.send(true);
        let _ = sweeper.await;
        served
    })
}

/// Opens the key store, prepares every configured tenant's keys, and builds
/// the one object in this process that holds an unwrapped private key.
///
/// The schedule is applied here rather than left to the sweep so that a
/// deployment started with the wrong key-encryption key fails at boot, where
/// somebody is watching, instead of on the first token request. It is the same
/// call the sweep makes, so there is no separate bootstrap path to diverge
/// from the steady-state one.
///
/// The signer is built here because that is what `PgKeyRepository`'s own
/// documentation says the composition root is for: signing through the
/// repository would unwrap the key on every token, which for a cloud KEK is a
/// network round trip each time.
async fn prepare_keys(
    store: &Store,
    kek: &Arc<dyn asterius_jose::kek::Kek>,
    config: &Config,
) -> Result<(Arc<TenantKeyStore>, Arc<dyn asterius_domain::keys::Signer>), String> {
    let keys = Arc::new(TenantKeyStore::new(
        store.pool().clone(),
        Arc::clone(kek),
        Arc::new(PgAuditSink::new(store.pool().clone())),
    ));

    for tenant in &config.tenants {
        keys.apply_schedule(&tenant.id, OffsetDateTime::now_utc())
            .await
            .map_err(|e| format!("cannot prepare signing keys for {}: {e}", tenant.id))?;
    }

    let signer: Arc<dyn asterius_domain::keys::Signer> = Arc::new(CachedSigner::new(
        (*keys).clone(),
        Arc::new(asterius_domain::ports::SystemClock),
    ));
    Ok((keys, signer))
}

/// Starts the key rotation sweep and hands back the way to stop it.
///
/// Rotation, from here on, is something that happens rather than something a
/// restart does (`ast-mxc.9`). The schedule loop in `run` prepares the
/// configured tenants once and fails loudly if it cannot; this keeps every
/// tenant's schedule applied for the life of the process, including tenants
/// created through the admin API after boot.
fn spawn_rotation(
    keys: TenantKeyStore,
    tenants: Arc<PgTenantRepository>,
) -> (
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let sweep = RotationSweep::new(keys, tenants, Arc::new(asterius_domain::ports::SystemClock));
    let (stop, mut stopping) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(sweep.run(async move {
        let _ = stopping.changed().await;
    }));
    (stop, handle)
}

/// Writes the tenants declared in the configuration into the database.
///
/// The configuration file is the source of truth for which tenants exist at
/// boot; the admin API adds more at runtime. The upsert is idempotent, so a
/// restart re-asserts the declared shape without disturbing anything else — and
/// an operator who corrects an issuer in the file sees it applied rather than
/// silently ignored because the row already existed.
async fn bootstrap_tenants(repository: &PgTenantRepository, config: &Config) -> Result<(), String> {
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

fn config_path() -> Result<PathBuf, String> {
    let mut args = std::env::args_os().skip(1);
    let mut path: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--config" | "-c") => {
                let value = args.next().ok_or("--config needs a path")?;
                path = Some(PathBuf::from(value));
            }
            Some("--help" | "-h") => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            _ => {
                return Err(format!(
                    "unexpected argument {}\n{USAGE}",
                    PathBuf::from(arg).display()
                ));
            }
        }
    }
    Ok(path
        .or_else(|| std::env::var_os("ASTERIUS_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)))
}
