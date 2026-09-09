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
use asterius_server::retention::RetentionSweep;
use asterius_server::rotation::RotationSweep;
use asterius_server::signing::CachedSigner;
use asterius_server::tenancy::{TenantDirectory, TenantState};
use asterius_server::{Config, VERSION};
use asterius_store_pg::{
    PgAuditSink, PgKekRewrap, PgReplayGuard, PgRetention, PgTenantRepository, RewrapOutcome, Store,
    TenantKeyStore,
};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use time::OffsetDateTime;

const DEFAULT_CONFIG_PATH: &str = "asterius.toml";
const USAGE: &str = "usage: asterius [--config <path>] [--config-reference]\n       \
                     asterius rewrap-kek (--new-kek-file <path> | --new-kek-env <var>) \
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
        Command::RewrapKek(new_kek) => rewrap_kek(&invocation.config, &new_kek),
    }
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
                keys: Arc::clone(&keys) as Arc<dyn asterius_domain::KeyStore>,
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

        let workers = spawn_workers(
            (*keys).clone(),
            PgRetention::new(store.pool().clone()),
            &store,
            &kek,
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
) -> Workers {
    let clock = Arc::new(asterius_domain::ports::SystemClock);
    let tenants_for_rotation = Arc::new(PgTenantRepository::new(
        store.pool().clone(),
        Arc::clone(kek),
    ));
    let tenants_for_retention = Arc::new(PgTenantRepository::new(
        store.pool().clone(),
        Arc::clone(kek),
    ));

    let rotation = RotationSweep::new(keys, tenants_for_rotation, Arc::clone(&clock) as Arc<_>);
    let retention = RetentionSweep::new(retention, tenants_for_retention, clock);

    let (stop, stopping) = tokio::sync::watch::channel(false);
    let handles = vec![
        tokio::spawn(rotation.run(stopped(stopping.clone()))),
        tokio::spawn(retention.run(stopped(stopping))),
    ];
    Workers { stop, handles }
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
fn rewrap_kek(path: &std::path::Path, new_kek: &KekSource) -> Result<(), String> {
    let config = Config::load(path).map_err(|e| e.to_string())?;

    let from = load_kek(&config.kek)?;
    let to = load_kek(new_kek)?;
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

/// Loads a KEK from wherever the operator put it.
fn load_kek(source: &KekSource) -> Result<Arc<dyn Kek>, String> {
    let kek = match source {
        KekSource::File(path) => LocalKek::from_file(path),
        KekSource::Env(variable) => LocalKek::from_env(variable),
    }
    .map_err(|e| format!("cannot load the key-encryption key: {e}"))?;
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
    RewrapKek(KekSource),
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
                Some("rewrap-kek") => command = Command::RewrapKek(KekSource::Env(String::new())),
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

        // Exactly one source, and only where it means something. Two sources
        // would leave "which key am I rotating to" to argument order, and a
        // key named for a run that is not a rotation is an operator who typed
        // the wrong command and would otherwise be given a server.
        let command = match (command, new_kek_file, new_kek_env) {
            (Command::RewrapKek(_), Some(file), None) => Command::RewrapKek(KekSource::File(file)),
            (Command::RewrapKek(_), None, Some(variable)) => {
                Command::RewrapKek(KekSource::Env(variable))
            }
            (Command::RewrapKek(_), _, _) => {
                return Err(format!(
                    "rewrap-kek needs exactly one of --new-kek-file and --new-kek-env\n{USAGE}"
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

#[cfg(test)]
mod tests {
    use super::{Command, Invocation};
    use asterius_server::config::KekSource;
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
            Command::RewrapKek(KekSource::File(PathBuf::from("/etc/asterius/kek.new")))
        );
    }

    #[test]
    fn a_rewrap_reads_its_new_key_from_the_environment() {
        let invocation =
            parse(&["rewrap-kek", "--new-kek-env", "ASTERIUS_KEK_NEXT"]).expect("valid");

        assert_eq!(
            invocation.command,
            Command::RewrapKek(KekSource::Env("ASTERIUS_KEK_NEXT".to_owned()))
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

    #[test]
    fn a_rewrap_with_no_new_key_is_refused() {
        let refused = parse(&["rewrap-kek"]);

        assert!(refused.is_err(), "{refused:?}");
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
}
