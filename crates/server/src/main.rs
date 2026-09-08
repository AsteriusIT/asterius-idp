//! The `asterius` binary.
#![forbid(unsafe_code)]

use asterius_domain::ports::TenantRepository as _;
use asterius_domain::{Feature, Tenant, TenantStatus};
use asterius_jose::LocalKek;
use asterius_jose::client_keys::ClientKeyCache;
use asterius_jose::kek::Kek;
use asterius_oidc::par;
use asterius_server::client_auth::ClientAuthenticator;
use asterius_server::config::KekSource;
use asterius_server::http::protocol::{self, ClientEndpoints, ProtocolState};
use asterius_server::http::server::{OperationalRoutes, app, not_found, serve, shutdown_signal};
use asterius_server::observability::health::HealthState;
use asterius_server::observability::{self, Metrics};
use asterius_server::outbound::HttpsJwksFetcher;
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

        let keys = Arc::new(TenantKeyStore::new(
            store.pool().clone(),
            kek,
            Arc::new(PgAuditSink::new(store.pool().clone())),
        ));

        // Creates the first key for a new tenant and applies the schedule for
        // an existing one. Same call, so there is no separate bootstrap path to
        // diverge from the steady-state one.
        for tenant in &config.tenants {
            keys.apply_schedule(&tenant.id, OffsetDateTime::now_utc())
                .await
                .map_err(|e| format!("cannot prepare signing keys for {}: {e}", tenant.id))?;
        }

        // Client-facing endpoints: the ones that need an authenticated client
        // and the database. Built here rather than lazily so that a deployment
        // that cannot construct them fails at startup, where somebody is
        // watching, rather than on a client's first request.
        let client_keys = Arc::new(ClientKeyCache::new(Arc::new(
            HttpsJwksFetcher::new()
                .map_err(|e| format!("cannot build the outbound TLS client: {e}"))?,
        )));
        let authenticator = Arc::new(
            ClientAuthenticator::new(
                client_keys,
                Arc::new(PgReplayGuard::new(store.pool().clone())),
            )
            .map_err(|e| format!("cannot build the client authenticator: {e}"))?,
        );

        let routes = protocol::routes(ProtocolState {
            keys: Arc::clone(&keys) as Arc<dyn asterius_domain::KeyStore>,
            capabilities: config.features,
            clients: Some(Arc::new(ClientEndpoints {
                authenticator,
                store: store.clone(),
                capabilities: config.features,
                par_lifetime: par::clamp_lifetime(par::DEFAULT_LIFETIME),
            })),
        })
        .fallback(not_found);
        let app = app(routes, tenant_state, Some(operations), &config.server);

        serve(&config.server, app, shutdown_signal())
            .await
            .map_err(|e| format!("server stopped: {e}"))
    })
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
