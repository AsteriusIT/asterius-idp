//! Typed configuration: a TOML file, environment overrides, and a validation
//! pass that reports every problem at once.
//!
//! Two properties matter more than the shape of the struct.
//!
//! **A typo must not be silent.** Every table is `deny_unknown_fields`, so
//! `[featurse]` or `dpop_nonces = true` stops the server rather than leaving an
//! operator to discover months later that the flag they set never applied. The
//! error names the full key path, because "unknown field" on its own is not
//! actionable in a file with a dozen tables.
//!
//! **Fixing configuration should take one round trip.** Serde stops at the
//! first error, which turns a five-mistake file into five restarts. So parsing
//! is split in two: a lenient pass where every field is optional, then a
//! validation pass that accumulates problems and reports them together.

use crate::http::register::{
    InitialAccessTokens, MIN_INITIAL_ACCESS_TOKEN_LEN, RegistrationPolicy,
};
use crate::observability::LogFormat;
use asterius_domain::{
    Capabilities, EndpointLimit, EndpointLimits, Issuer, LoginLimits, RateLimit, RefreshPolicy,
    Rotation, Secret, TenantId,
};
use ipnet::IpNet;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The prefix that marks an environment variable as a configuration override.
const ENV_PREFIX: &str = "ASTERIUS__";

/// The separator between key-path segments in an environment variable name.
const ENV_SEPARATOR: &str = "__";

// ---------------------------------------------------------------------------
// The validated configuration
// ---------------------------------------------------------------------------

/// The server's validated configuration.
///
/// None of the configuration structs are `#[non_exhaustive]`. They are built
/// in exactly one place — the validator below — and consumed inside this
/// binary, so sealing them would buy no compatibility and would cost every
/// test a builder.
#[derive(Debug)]
pub struct Config {
    /// Listener and transport settings.
    pub server: ServerConfig,
    /// PostgreSQL connection settings.
    pub database: DatabaseConfig,
    /// Which optional capabilities this deployment offers.
    pub features: Capabilities,
    /// Tenants known at boot. Each one is an issuer.
    pub tenants: Vec<TenantConfig>,
    /// How log lines are rendered.
    pub log_format: LogFormat,
    /// Where the key-encryption key comes from.
    pub kek: KekSource,
    /// Who, if anyone, may register a client dynamically (RFC 7591 §3).
    pub registration: RegistrationPolicy,
    /// The deployment admin to seed at boot, if the operator declared one.
    pub admin: Option<AdminConfig>,
    /// How many failed sign-ins are tolerated, and over what window.
    pub login: LoginLimits,
    /// What each protocol endpoint permits per window (`ast-p2l.3`).
    pub limits: EndpointLimits,
    /// DPoP settings that are not capability flags (`ast-a05.11`).
    pub dpop: DpopConfig,
}

/// Listener and transport settings.
#[derive(Debug)]
pub struct ServerConfig {
    /// The address to listen on.
    pub bind: SocketAddr,
    /// Whether this process terminates TLS itself.
    pub mode: TransportMode,
    /// Certificate and key paths. Present exactly when [`TransportMode::TerminateTls`].
    pub tls: Option<TlsConfig>,
    /// Peers whose forwarding headers are believed. Empty unless
    /// [`TransportMode::BehindProxy`].
    pub trusted_proxies: Vec<IpNet>,
    /// Largest request body accepted, in bytes. Over this, 413.
    pub request_body_limit: usize,
    /// How long a request may take before it is abandoned.
    pub request_timeout: Duration,
}

/// How TLS reaches this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// This process owns the TLS listener (rustls).
    TerminateTls,
    /// A trusted reverse proxy terminates TLS and forwards over the loopback.
    BehindProxy,
}

/// Paths to the server's TLS material.
#[derive(Debug)]
pub struct TlsConfig {
    /// PEM certificate chain, leaf first.
    pub certificate: PathBuf,
    /// PEM private key.
    pub private_key: PathBuf,
}

/// Where the key-encryption key comes from.
///
/// Deliberately an enum with no default. A signing key is encrypted at rest
/// under this, so a deployment that has not said where it lives is a deployment
/// that cannot read its own keys — and silently generating one would mean every
/// restart produced a KEK that could not open yesterday's rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KekSource {
    /// A file holding a base64 32-byte key. The usual production shape: the
    /// file is mounted by the orchestrator and never in the image.
    File(PathBuf),
    /// An environment variable holding the same. Convenient for a container,
    /// and visible in `/proc/self/environ`, so the file is preferred.
    Env(String),
}

/// PostgreSQL connection settings.
#[derive(Debug)]
pub struct DatabaseConfig {
    /// The connection URL. Holds a password, so it never reaches a log.
    pub url: Secret<String>,
    /// Upper bound on pooled connections.
    pub max_connections: u32,
}

/// A tenant known at boot.
#[derive(Debug)]
pub struct TenantConfig {
    /// The tenant's identifier, as it appears in the issuer path.
    pub id: TenantId,
    /// The tenant's canonical issuer identifier.
    pub issuer: Issuer,
    /// The `aud` an access token carries when its grant named no resource.
    ///
    /// Defaults to the issuer, which is the one resource identifier a tenant
    /// is always known to own: UserInfo and introspection live under it, so a
    /// token audienced there is a token for this server's own protected
    /// resources rather than one every resource server should accept. A
    /// deployment fronting a separate API sets it explicitly.
    pub default_resource: String,
    /// What this tenant does with refresh tokens.
    ///
    /// Absent from the file means FAPI 2.0 SP's position: no rotation, and a
    /// refresh token that only works with the DPoP key it was issued to.
    pub refresh: RefreshPolicy,
}

/// The deployment admin seeded at boot (ADR-0010).
///
/// Absent means nothing is seeded. Like `[registration]`, "the operator wrote
/// nothing" and "the operator wrote a table" are different questions: a
/// deployment that never asked for an admin should not grow one, because the
/// account this describes administers every tenant in the process.
#[derive(Debug)]
pub struct AdminConfig {
    /// The reserved tenant the admin lives in. Created if it is not there, and
    /// then undeletable — the cascade from `tenants` is what would otherwise
    /// take the deployment's admins with it.
    pub tenant: TenantId,
    /// The reserved tenant's issuer. A reserved tenant is a real tenant, so it
    /// needs one like any other.
    pub issuer: Issuer,
    /// The admin's login identifier within that tenant.
    pub username: String,
    /// Where the initial password comes from.
    pub password: PasswordSource,
}

/// Where the deployment admin's initial password is read from.
///
/// The same two shapes as [`KekSource`], deliberately: an admin password is a
/// credential, and a credential that can only be supplied as a literal is a
/// credential that ends up in an image layer and in version control. There is
/// no key that takes the password itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordSource {
    /// A file the orchestrator mounts read-only. The production shape.
    File(PathBuf),
    /// A named environment variable, injected by the orchestrator. Visible
    /// through `/proc/self/environ`, so the file is preferred.
    Env(String),
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why the server refused to start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The path we tried to read.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid TOML.
    #[error("{path} is not valid TOML: {message}")]
    Syntax {
        /// The path we tried to parse.
        path: PathBuf,
        /// The parser's message, including line and column.
        message: String,
    },
    /// A key is unknown, or a value has the wrong type.
    #[error("{path}: {message}")]
    Shape {
        /// The key path, e.g. `server.tls`.
        path: String,
        /// What serde objected to.
        message: String,
    },
    /// One or more values are missing or invalid.
    #[error("{0}")]
    Invalid(Problems),
}

/// A single validation problem, tied to the key that caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The key path, e.g. `tenant[0].issuer`.
    pub path: String,
    /// What is wrong with it.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Every validation problem found in one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problems(Vec<Problem>);

impl Problems {
    /// The problems, in the order the keys appear in the file.
    #[must_use]
    pub fn as_slice(&self) -> &[Problem] {
        &self.0
    }

    /// The key paths that have a problem. Convenient in tests.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|p| p.path.as_str())
    }
}

impl fmt::Display for Problems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0.len();
        let plural = if n == 1 { "problem" } else { "problems" };
        write!(f, "configuration has {n} {plural}:")?;
        for problem in &self.0 {
            write!(f, "\n  - {problem}")?;
        }
        Ok(())
    }
}

/// Collects problems so that one pass reports all of them.
#[derive(Debug, Default)]
struct Collector(Vec<Problem>);

impl Collector {
    fn missing(&mut self, path: impl Into<String>) {
        self.problem(path, "required key is missing");
    }

    fn problem(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(Problem {
            path: path.into(),
            message: message.into(),
        });
    }

    fn finish<T>(self, value: T) -> Result<T, ConfigError> {
        if self.0.is_empty() {
            Ok(value)
        } else {
            Err(ConfigError::Invalid(Problems(self.0)))
        }
    }
}

// ---------------------------------------------------------------------------
// The lenient shape
// ---------------------------------------------------------------------------
//
// Every field is optional so that serde never short-circuits on the first
// missing key; `deny_unknown_fields` still rejects typos, which is the one
// class of error worth failing fast on because it cannot be accumulated
// usefully — an unknown key has no validation to run.

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    server: RawServer,
    #[serde(default)]
    database: RawDatabase,
    #[serde(default)]
    features: Capabilities,
    #[serde(default)]
    tenant: Vec<RawTenant>,
    log_format: Option<LogFormat>,
    #[serde(default)]
    keys: RawKeys,
    #[serde(default)]
    registration: Option<RawRegistration>,
    #[serde(default)]
    admin: Option<RawAdmin>,
    #[serde(default)]
    login: RawLogin,
    #[serde(default)]
    limits: RawLimits,
    #[serde(default)]
    dpop: RawDpop,
}

/// The `[login]` table.
///
/// A plain `#[serde(default)]` struct rather than an `Option`, unlike
/// `[registration]` and `[admin]`: those two are postures an operator opts
/// into, and this is a limit that must exist whether anybody thought about it
/// or not. A deployment that says nothing about login abuse still gets the
/// defaults below — an unlimited login endpoint is not a shape this server
/// offers.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLogin {
    failure_window_seconds: Option<u64>,
    max_failures_per_account: Option<u32>,
    max_failures_per_address: Option<u32>,
}

/// The `[limits]` table: what the protocol endpoints permit per window.
///
/// A `#[serde(default)]` struct for the reason `[login]` is one — an
/// unlimited `/register` or `/token` is not a shape this server offers, so a
/// deployment that says nothing still gets the defaults below.
///
/// One window for every endpoint rather than one per endpoint. The numbers
/// that differ between endpoints are the *maxima*, which is where the
/// difference in legitimate traffic actually lies; a per-endpoint window would
/// be five more knobs that mostly change what "per minute" means.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    window_seconds: Option<u64>,
    registration_per_address: Option<u32>,
    client_configuration_per_address: Option<u32>,
    par_per_address: Option<u32>,
    par_per_client: Option<u32>,
    token_per_address: Option<u32>,
    token_per_client: Option<u32>,
    userinfo_per_address: Option<u32>,
}

/// The `[registration]` table.
///
/// Absent means closed, which is why this is an `Option` rather than a
/// `#[serde(default)]` struct: "the operator wrote nothing" and "the operator
/// wrote a table" are different, and only the second one is asked to name a
/// mode. A deployment that never thought about dynamic registration should not
/// be running it.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistration {
    mode: Option<RegistrationMode>,
    initial_access_tokens: Option<Vec<String>>,
}

/// The three postures an operator may choose between.
///
/// Spelled out in the file rather than inferred from whether tokens are
/// present. Inferring it would mean that deleting the last token from
/// `initial_access_tokens` silently turned a gated endpoint into an open one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RegistrationMode {
    /// Nobody may register.
    Closed,
    /// A bearer initial access token is required (RFC 7591 §3).
    InitialAccessToken,
    /// Anybody may register (RFC 7591 §3's SHOULD), behind a rate limiter.
    Open,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeys {
    kek_file: Option<PathBuf>,
    kek_env: Option<String>,
}

/// The `[admin]` table.
///
/// An `Option` for the reason `[registration]` is one: seeding an account that
/// administers the whole deployment is something an operator asks for, never
/// something a default does.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdmin {
    tenant: Option<String>,
    issuer: Option<String>,
    username: Option<String>,
    password_file: Option<PathBuf>,
    password_env: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    bind: Option<String>,
    mode: Option<TransportMode>,
    tls: Option<RawTls>,
    proxy: Option<RawProxy>,
    request_body_limit_bytes: Option<usize>,
    request_timeout_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProxy {
    trusted_cidrs: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDatabase {
    url: Option<String>,
    max_connections: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTenant {
    id: Option<String>,
    // Kept as a string here so that an invalid issuer becomes an accumulated
    // problem with a key path, rather than a serde error that hides the rest.
    issuer: Option<String>,
    default_resource: Option<String>,
    refresh: Option<RawRefresh>,
}

/// `[tenant.refresh]`: what this tenant does with refresh tokens.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRefresh {
    absolute_lifetime_seconds: Option<i64>,
    idle_lifetime_seconds: Option<i64>,
    bind_to_dpop_key: Option<bool>,
    rotation: Option<String>,
    rotation_grace_seconds: Option<i64>,
}

/// Default listener address.
///
/// Not 8443: that is the port `tailscale serve` binds to proxy a local app,
/// and colliding with it means the server will not start on a machine that is
/// doing something entirely reasonable. 9443 keeps the "TLS on a high port"
/// convention without the clash.
pub(crate) const DEFAULT_BIND: &str = "0.0.0.0:9443";
pub(crate) const DEFAULT_MAX_CONNECTIONS: u32 = 16;

/// A deployment that says nothing is assumed to be behind a terminator.
///
/// The safer default of the two: `terminate_tls` without usable key material
/// cannot start at all, whereas a proxy that is not there shows up as a
/// refused connection rather than as cleartext on the wire.
pub(crate) const DEFAULT_MODE: TransportMode = TransportMode::BehindProxy;

/// FAPI 2.0 request bodies are small: a PAR request, a token request, a
/// registration document. 64 KiB is generous for all of them and cheap to
/// refuse above.
pub(crate) const DEFAULT_BODY_LIMIT: usize = 64 * 1024;

/// Long enough for a slow client on a bad link, short enough that holding a
/// connection open is not a denial-of-service primitive.
pub(crate) const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 10;

/// The reserved tenant's identifier when `[admin]` does not name one.
///
/// A tenant id like any other, and readable: ADR-0010 makes the point that an
/// admin surface hiding where its authority lives is harder to audit, not
/// safer.
pub(crate) const DEFAULT_ADMIN_TENANT: &str = "admin";

/// How long failed sign-ins are counted for.
///
/// Fifteen minutes: long enough that an attacker pacing themselves to the
/// limit makes negligible progress against even a weak password, short enough
/// that a person who mistyped theirs is not locked out for an afternoon. NIST
/// SP 800-63B §5.2.2 asks for a bound on attempts and leaves the numbers to
/// the deployment; these are the numbers this deployment starts with.
pub(crate) const DEFAULT_LOGIN_WINDOW_SECONDS: u64 = 900;

/// Failures permitted against one typed identifier per window.
///
/// Ten: enough for a person with a password manager and a bad day, far below
/// the thousands an online guessing attack needs.
pub(crate) const DEFAULT_LOGIN_MAX_PER_ACCOUNT: u32 = 10;

/// Failures permitted from one client address per window.
///
/// Higher than the per-account limit, because one address is legitimately many
/// people: an office, a school, a mobile carrier's NAT. It is the limit that
/// stops a *sweep* — one attempt each against a thousand accounts — which the
/// per-account limit cannot see at all.
pub(crate) const DEFAULT_LOGIN_MAX_PER_ADDRESS: u32 = 100;

/// The shortest counting window an operator may configure.
pub(crate) const MIN_LOGIN_WINDOW_SECONDS: u64 = 30;

/// How long protocol-endpoint requests are counted for.
///
/// A minute, against the login limiter's quarter of an hour, because these
/// limits bound *load* rather than guessing. A caller that is refused has
/// usually made a mistake in its retry loop, and fifteen minutes of refusals
/// for a burst that lasted five seconds is an outage rather than a defence.
pub(crate) const DEFAULT_LIMIT_WINDOW_SECONDS: u64 = 60;

/// The shortest per-endpoint window an operator may configure.
///
/// Below this a fixed window admits `2 × max` in a stretch barely longer than
/// the window itself, which is not a limit anybody reasoned about.
pub(crate) const MIN_LIMIT_WINDOW_SECONDS: u64 = 10;

/// `POST /register` — RFC 7591 — per address, per window.
///
/// The tightest of the five, and the only endpoint here reachable with no
/// credential of any kind when `[registration] mode = "open"`: every accepted
/// request creates a row that lives until somebody deletes it. Twenty a minute
/// is far above what a person integrating a client does and far below what
/// filling a table takes.
pub(crate) const DEFAULT_LIMIT_REGISTRATION_PER_ADDRESS: u32 = 20;

/// RFC 7592 client configuration — per address, per window.
///
/// A management endpoint: a client reads or updates its own registration
/// rarely, and a caller trying many registration access tokens against it is
/// the thing to stop (`ast-m9c.11`). Higher than registration because a read
/// costs a query rather than a row.
pub(crate) const DEFAULT_LIMIT_CLIENT_CONFIGURATION_PER_ADDRESS: u32 = 60;

/// `POST /par` — RFC 9126 — per address, per window.
///
/// One row per accepted request, so this is a write endpoint like
/// registration; but it needs an authenticated client, so an anonymous flood
/// is refused before it stores anything, and the address limit is here for the
/// requests that never authenticate.
pub(crate) const DEFAULT_LIMIT_PAR_PER_ADDRESS: u32 = 60;

/// `POST /par` per authenticated client, per window.
///
/// An order of magnitude above the address limit: one client is legitimately
/// many users starting authorization at once, and this is the number that has
/// to fit a busy relying party rather than a suspicious address.
pub(crate) const DEFAULT_LIMIT_PAR_PER_CLIENT: u32 = 600;

/// `POST /token` — per address, per window.
///
/// Every attempt costs a signature verification and a database round trip, and
/// replaying an authorization code revokes the grant it belongs to (OIDC Core
/// §3.1.3.2), so an abusive caller here has a side effect as well as a cost.
pub(crate) const DEFAULT_LIMIT_TOKEN_PER_ADDRESS: u32 = 120;

/// `POST /token` per authenticated client, per window.
///
/// The busiest endpoint a working deployment has: every authorization and
/// every refresh passes through it. Twenty a second sustained is a great deal
/// of one client and still a bound.
pub(crate) const DEFAULT_LIMIT_TOKEN_PER_CLIENT: u32 = 1200;

/// UserInfo — per address, per window.
///
/// The most generous, because its callers are resource servers rather than
/// browsers: a handful of machines making a request per API call each, all
/// behind one address. A limit sized for a browser would break a working
/// deployment on the day it got busy, and the endpoint is a read of claims the
/// caller already holds a token for.
pub(crate) const DEFAULT_LIMIT_USERINFO_PER_ADDRESS: u32 = 600;

/// The seeded admin's login identifier when `[admin]` does not name one.
pub(crate) const DEFAULT_ADMIN_USERNAME: &str = "admin";

/// Believed by default: nothing but this machine.
pub(crate) const DEFAULT_TRUSTED_PROXIES: [&str; 2] = ["127.0.0.0/8", "::1/128"];

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl Config {
    /// Reads and validates the configuration file, applying overrides from the
    /// process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read or parsed, contains an
    /// unknown key, or fails validation.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let env = std::env::vars().collect();
        Self::parse(&text, path, &env)
    }

    /// Validates configuration from an explicit TOML string and environment map.
    ///
    /// Taking the environment as an argument keeps the whole loader testable
    /// without mutating process-global state, which matters because tests run
    /// in parallel threads within one process.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] as [`Config::load`] does.
    // fuzz-target: config_parse
    pub fn parse(
        text: &str,
        path: &Path,
        env: &BTreeMap<String, String>,
    ) -> Result<Self, ConfigError> {
        let mut table: toml::Table =
            text.parse()
                .map_err(|e: toml::de::Error| ConfigError::Syntax {
                    path: path.to_owned(),
                    message: e.message().to_owned(),
                })?;

        apply_env_overrides(&mut table, env)?;

        let raw: RawConfig =
            serde_path_to_error::deserialize(toml::Value::Table(table)).map_err(|e| {
                let key = e.path().to_string();
                ConfigError::Shape {
                    path: if key.is_empty() {
                        "<root>".to_owned()
                    } else {
                        key
                    },
                    message: e.into_inner().message().to_owned(),
                }
            })?;

        raw.validate(env)
    }
}

impl RawConfig {
    /// `env` is the process environment, not the override map: `[dpop]
    /// nonce_secret_env` names a variable the operator's orchestrator injects,
    /// and reading it here is what lets a malformed one be reported alongside
    /// every other problem in the file.
    fn validate(self, env: &BTreeMap<String, String>) -> Result<Config, ConfigError> {
        let mut errors = Collector::default();

        let server = self.server.validate(&mut errors);

        if self.database.url.is_none() {
            errors.missing("database.url");
        }
        let database = DatabaseConfig {
            url: Secret::new(self.database.url.unwrap_or_default()),
            max_connections: self
                .database
                .max_connections
                .unwrap_or(DEFAULT_MAX_CONNECTIONS),
        };

        let tenants = validate_tenants(self.tenant, &mut errors);

        // Exactly one source, and one is required. Two would leave the server
        // choosing between them silently; none would leave it unable to read
        // the keys it wrote yesterday.
        let kek = match (self.keys.kek_file, self.keys.kek_env) {
            (Some(path), None) => Some(KekSource::File(path)),
            (None, Some(variable)) => Some(KekSource::Env(variable)),
            (None, None) => {
                errors.problem(
                    "keys.kek_file",
                    "a key-encryption key is required: set keys.kek_file or keys.kek_env. \
                     Signing keys are encrypted at rest under it, so there is no safe default",
                );
                None
            }
            (Some(_), Some(_)) => {
                errors.problem(
                    "keys",
                    "set exactly one of keys.kek_file and keys.kek_env, not both",
                );
                None
            }
        };

        let registration = validate_registration(self.registration, &mut errors);
        // The one capability an operator does not write. RFC 7591's endpoint
        // exists exactly when somebody may register at it, so the flag the
        // router and the discovery document read is derived from
        // `[registration] mode` rather than set beside it — `ast-m9c.6`, and
        // the reason a closed deployment no longer advertises a
        // `registration_endpoint` that answers 403.
        let mut features = self.features;
        features.dynamic_client_registration = registration.mode().is_open_at_all();
        let admin = validate_admin(self.admin, &tenants, &mut errors);
        let login = validate_login(&self.login, &mut errors);
        let limits = validate_limits(&self.limits, &mut errors);
        let dpop = validate_dpop(self.dpop, env, &mut errors);

        errors.finish(Config {
            server,
            database,
            features,
            tenants,
            log_format: self.log_format.unwrap_or_default(),
            kek: kek.unwrap_or_else(|| KekSource::Env(String::new())),
            registration,
            admin,
            login,
            limits,
            dpop,
        })
    }
}

/// Turns the `[login]` table into the two limits the sign-in paths apply.
///
/// Both maxima are refused at zero. Zero is spellable and would mean "nobody
/// may ever sign in", which is a way to lock a deployment out of itself by
/// typing one character; an operator who wants that removes the credential
/// method instead. The window has a floor for the mirror reason: a window of
/// zero seconds is a limit that resets before it can be reached.
fn validate_login(raw: &RawLogin, errors: &mut Collector) -> LoginLimits {
    let window = raw
        .failure_window_seconds
        .unwrap_or(DEFAULT_LOGIN_WINDOW_SECONDS);
    if window < MIN_LOGIN_WINDOW_SECONDS {
        errors.problem(
            "login.failure_window_seconds",
            format!("must be at least {MIN_LOGIN_WINDOW_SECONDS}: a shorter window resets before an attacker's attempts add up"),
        );
    }
    let window = time::Duration::seconds(
        i64::try_from(window.max(MIN_LOGIN_WINDOW_SECONDS)).unwrap_or(i64::MAX),
    );

    let mut positive = |key: &str, value: u32| -> u32 {
        if value == 0 {
            errors.problem(
                key,
                "must be at least 1: zero refuses every sign-in, including the operator's",
            );
            return 1;
        }
        value
    };

    LoginLimits {
        per_address: RateLimit {
            max: positive(
                "login.max_failures_per_address",
                raw.max_failures_per_address
                    .unwrap_or(DEFAULT_LOGIN_MAX_PER_ADDRESS),
            ),
            window,
        },
        per_account: RateLimit {
            max: positive(
                "login.max_failures_per_account",
                raw.max_failures_per_account
                    .unwrap_or(DEFAULT_LOGIN_MAX_PER_ACCOUNT),
            ),
            window,
        },
    }
}

/// Turns the `[limits]` table into the per-endpoint limits the wiring applies.
///
/// Every maximum is refused at zero, for the reason the login maxima are: zero
/// is spellable and it means "this endpoint answers 429 to everybody", which
/// is a way to switch the token endpoint off by typing one character. An
/// operator who wants an endpoint closed turns the feature off.
///
/// The window has a floor for the mirror reason: a two-second window resets
/// before a burst can be recognised as one.
fn validate_limits(raw: &RawLimits, errors: &mut Collector) -> EndpointLimits {
    let seconds = raw.window_seconds.unwrap_or(DEFAULT_LIMIT_WINDOW_SECONDS);
    if seconds < MIN_LIMIT_WINDOW_SECONDS {
        errors.problem(
            "limits.window_seconds",
            format!(
                "must be at least {MIN_LIMIT_WINDOW_SECONDS}: a shorter window resets before a burst adds up"
            ),
        );
    }
    let window = time::Duration::seconds(
        i64::try_from(seconds.max(MIN_LIMIT_WINDOW_SECONDS)).unwrap_or(i64::MAX),
    );

    let mut limit = |key: &str, configured: Option<u32>, default: u32| -> RateLimit {
        let max = configured.unwrap_or(default);
        if max == 0 {
            errors.problem(
                key,
                "must be at least 1: zero refuses every request to that endpoint",
            );
        }
        RateLimit {
            max: max.max(1),
            window,
        }
    };

    EndpointLimits {
        registration: EndpointLimit {
            per_address: limit(
                "limits.registration_per_address",
                raw.registration_per_address,
                DEFAULT_LIMIT_REGISTRATION_PER_ADDRESS,
            ),
            // No client bucket: RFC 7591 §3 registration has no client yet, by
            // definition. There is nothing authenticated to charge.
            per_client: None,
        },
        client_configuration: EndpointLimit {
            per_address: limit(
                "limits.client_configuration_per_address",
                raw.client_configuration_per_address,
                DEFAULT_LIMIT_CLIENT_CONFIGURATION_PER_ADDRESS,
            ),
            per_client: None,
        },
        par: EndpointLimit {
            per_address: limit(
                "limits.par_per_address",
                raw.par_per_address,
                DEFAULT_LIMIT_PAR_PER_ADDRESS,
            ),
            per_client: Some(limit(
                "limits.par_per_client",
                raw.par_per_client,
                DEFAULT_LIMIT_PAR_PER_CLIENT,
            )),
        },
        token: EndpointLimit {
            per_address: limit(
                "limits.token_per_address",
                raw.token_per_address,
                DEFAULT_LIMIT_TOKEN_PER_ADDRESS,
            ),
            per_client: Some(limit(
                "limits.token_per_client",
                raw.token_per_client,
                DEFAULT_LIMIT_TOKEN_PER_CLIENT,
            )),
        },
        userinfo: EndpointLimit {
            per_address: limit(
                "limits.userinfo_per_address",
                raw.userinfo_per_address,
                DEFAULT_LIMIT_USERINFO_PER_ADDRESS,
            ),
            // UserInfo presents an access token, not a `client_id`. Reading a
            // client out of a token before it is verified would be trusting a
            // string the caller wrote, so the address bucket holds it alone.
            per_client: None,
        },
    }
}

impl RawServer {
    fn validate(self, errors: &mut Collector) -> ServerConfig {
        let mode = self.mode.unwrap_or(DEFAULT_MODE);

        let bind = match self.bind.as_deref().unwrap_or(DEFAULT_BIND).parse() {
            Ok(addr) => addr,
            Err(e) => {
                errors.problem("server.bind", format!("not a socket address: {e}"));
                DEFAULT_BIND
                    .parse()
                    .expect("the default bind address is a literal")
            }
        };

        // TLS material is required exactly when this process terminates TLS.
        // Reporting a stray `[server.tls]` in `behind_proxy` mode is not
        // pedantry: it is usually a deployment that believes it is doing TLS
        // and is not.
        let tls = match (mode, self.tls) {
            (TransportMode::TerminateTls, tls) => {
                let tls = tls.unwrap_or_default();
                if tls.certificate.is_none() {
                    errors.missing("server.tls.certificate");
                }
                if tls.private_key.is_none() {
                    errors.missing("server.tls.private_key");
                }
                Option::zip(tls.certificate, tls.private_key).map(|(certificate, private_key)| {
                    TlsConfig {
                        certificate,
                        private_key,
                    }
                })
            }
            (TransportMode::BehindProxy, Some(_)) => {
                errors.problem(
                    "server.tls",
                    "TLS material is configured but server.mode is \"behind_proxy\"; \
                     set mode = \"terminate_tls\" or remove [server.tls]",
                );
                None
            }
            (TransportMode::BehindProxy, None) => None,
        };

        let trusted_proxies = Self::validate_trusted_proxies(mode, self.proxy, errors);

        ServerConfig {
            bind,
            mode,
            tls,
            trusted_proxies,
            request_body_limit: self.request_body_limit_bytes.unwrap_or(DEFAULT_BODY_LIMIT),
            request_timeout: Duration::from_secs(
                self.request_timeout_seconds
                    .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECONDS),
            ),
        }
    }

    /// Resolves which peers may speak for a client.
    ///
    /// A forwarding header is an assertion about who the caller is, and
    /// `X-Forwarded-For` is trivially spoofable — so it is believed only when
    /// the immediate peer is one we put there. Configuring trusted proxies
    /// while terminating TLS is rejected for the same reason the mirror case
    /// is: nothing is in front of this process to do the forwarding.
    fn validate_trusted_proxies(
        mode: TransportMode,
        proxy: Option<RawProxy>,
        errors: &mut Collector,
    ) -> Vec<IpNet> {
        if mode == TransportMode::TerminateTls {
            if proxy.is_some() {
                errors.problem(
                    "server.proxy",
                    "trusted proxies are configured but server.mode is \"terminate_tls\"; \
                     nothing is in front of this process to forward anything",
                );
            }
            return Vec::new();
        }

        let raw = proxy.and_then(|p| p.trusted_cidrs).unwrap_or_else(|| {
            DEFAULT_TRUSTED_PROXIES
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        });

        if raw.is_empty() {
            errors.problem(
                "server.proxy.trusted_cidrs",
                "must not be empty in \"behind_proxy\" mode: with no trusted peer, every \
                 forwarding header is ignored and every client appears to come from the proxy",
            );
            return Vec::new();
        }

        let mut nets = Vec::with_capacity(raw.len());
        for (index, cidr) in raw.iter().enumerate() {
            match cidr.parse::<IpNet>() {
                Ok(net) => nets.push(net),
                Err(e) => errors.problem(
                    format!("server.proxy.trusted_cidrs[{index}]"),
                    format!("not a CIDR block: {e}"),
                ),
            }
        }
        nets
    }
}

/// Turns the `[registration]` table into a policy, or reports why it cannot.
///
/// The rules are all of the form "a setting that does nothing is a lie", which
/// is worth spelling out because every one of them has bitten somebody:
///
/// * **No table means closed.** RFC 7591 §3 says an authorization server SHOULD
///   accept unauthenticated registration requests. This deliberately does not,
///   by default. The SHOULD serves interoperability between parties that have
///   never met; a FAPI deployment's clients are counterparties, and the cost of
///   getting the default wrong is an internet-writable row in `clients`.
/// * **A table must name a mode.** Defaulting it would mean the difference
///   between "gated" and "open" could be a key an operator forgot to write.
/// * **`initial_access_token` needs tokens.** A gated endpoint with no tokens
///   is a closed endpoint spelled at length, and an operator who meant to
///   provision one has made a mistake worth stopping for.
/// * **Every token must be long enough.** FAPI 2.0 SP §5.4.1 puts a 128-bit
///   floor under any credential no end user handles; an initial access token is
///   the only thing between the internet and this endpoint.
/// * **`open` must not carry tokens.** They would be inert, and a value that
///   does nothing is one an operator believes is doing something.
fn validate_registration(
    raw: Option<RawRegistration>,
    errors: &mut Collector,
) -> RegistrationPolicy {
    let Some(raw) = raw else {
        return RegistrationPolicy::Closed;
    };

    let Some(mode) = raw.mode else {
        errors.problem(
            "registration.mode",
            "required when [registration] is present: one of \"closed\", \
             \"initial_access_token\" or \"open\"",
        );
        return RegistrationPolicy::Closed;
    };

    let tokens = raw.initial_access_tokens.unwrap_or_default();

    match mode {
        RegistrationMode::Closed | RegistrationMode::Open if !tokens.is_empty() => {
            errors.problem(
                "registration.initial_access_tokens",
                "only has an effect when registration.mode = \"initial_access_token\"",
            );
            RegistrationPolicy::Closed
        }
        RegistrationMode::Closed => RegistrationPolicy::Closed,
        RegistrationMode::Open => RegistrationPolicy::Open,
        RegistrationMode::InitialAccessToken => {
            if tokens.is_empty() {
                errors.problem(
                    "registration.initial_access_tokens",
                    "required when registration.mode = \"initial_access_token\": \
                     with none configured no caller can ever register",
                );
            }
            for (index, token) in tokens.iter().enumerate() {
                if token.len() < MIN_INITIAL_ACCESS_TOKEN_LEN {
                    // The token itself never reaches the message. It is a
                    // credential, this error is printed to a terminal and
                    // usually into a startup log, and the index is enough to
                    // find the entry.
                    errors.problem(
                        format!("registration.initial_access_tokens[{index}]"),
                        format!(
                            "too short: an initial access token needs at least \
                             {MIN_INITIAL_ACCESS_TOKEN_LEN} characters, for the 128 bits of \
                             entropy FAPI 2.0 SP §5.4.1 requires of a credential no end user \
                             handles"
                        ),
                    );
                }
            }
            // Hashed here and not carried further: from this point the process
            // holds no value that could be replayed against itself.
            RegistrationPolicy::Gated(InitialAccessTokens::from_tokens(
                tokens.iter().map(String::as_str),
            ))
        }
    }
}

fn validate_tenants(raw: Vec<RawTenant>, errors: &mut Collector) -> Vec<TenantConfig> {
    let mut tenants = Vec::with_capacity(raw.len());
    // Two tenants sharing an issuer would make `iss` ambiguous, and two sharing
    // an id would make the issuer path ambiguous. Both are detected on the
    // *canonical* issuer, so `https://as.example` and `https://as.example/` are
    // caught as the duplicate they are.
    let mut seen_ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_issuers: BTreeMap<String, usize> = BTreeMap::new();

    for (index, tenant) in raw.into_iter().enumerate() {
        // The id is validated here rather than trusted: it becomes a path
        // segment in the issuer and in every request URL, so a bad one is a
        // routing hazard, not a cosmetic problem.
        let id = match tenant.id {
            None => {
                errors.missing(format!("tenant[{index}].id"));
                None
            }
            Some(raw) => match TenantId::parse(&raw) {
                Ok(id) => Some(id),
                Err(e) => {
                    errors.problem(format!("tenant[{index}].id"), e.to_string());
                    None
                }
            },
        };
        let issuer = match tenant.issuer {
            None => {
                errors.missing(format!("tenant[{index}].issuer"));
                None
            }
            Some(raw) => match Issuer::parse(&raw) {
                Ok(issuer) => Some(issuer),
                Err(e) => {
                    errors.problem(format!("tenant[{index}].issuer"), e.to_string());
                    None
                }
            },
        };

        if let Some(id) = &id
            && let Some(first) = seen_ids.insert(id.as_str().to_owned(), index)
        {
            errors.problem(
                format!("tenant[{index}].id"),
                format!("duplicate of tenant[{first}].id ({id})"),
            );
        }
        if let Some(issuer) = &issuer
            && let Some(first) = seen_issuers.insert(issuer.as_str().to_owned(), index)
        {
            errors.problem(
                format!("tenant[{index}].issuer"),
                format!("duplicate of tenant[{first}].issuer ({issuer})"),
            );
        }

        // Validated here rather than at first token: an audience that is not
        // an absolute https URI without a fragment (RFC 8707 §2) is a boot
        // failure someone is watching, not a signing failure at 3am.
        let default_resource = match tenant.default_resource {
            None => None,
            Some(raw) => match resource_identifier(&raw) {
                Ok(resource) => Some(resource),
                Err(reason) => {
                    errors.problem(format!("tenant[{index}].default_resource"), reason);
                    None
                }
            },
        };

        let refresh = validate_refresh(index, tenant.refresh, errors);

        if let (Some(id), Some(issuer)) = (id, issuer) {
            let default_resource = default_resource.unwrap_or_else(|| issuer.as_str().to_owned());
            tenants.push(TenantConfig {
                id,
                issuer,
                default_resource,
                refresh,
            });
        }
    }
    tenants
}

/// Validates `[tenant.refresh]`.
///
/// Every problem is reported with its key path rather than folded into a
/// default, and one combination is refused outright: a `rotation_grace_seconds`
/// beside `rotation = "none"`. A grace window is only meaningful while tokens
/// are being superseded, so a file that sets one under the non-rotating mode
/// describes something the server will not do — and an operator who wrote it
/// believes rotation is on.
///
/// The mirror of that is also refused: `rotation = "migration"` with no window,
/// because the whole point of the migration mode is that it is time-boxed.
fn validate_refresh(
    index: usize,
    raw: Option<RawRefresh>,
    errors: &mut Collector,
) -> RefreshPolicy {
    let default = RefreshPolicy::default();
    let Some(raw) = raw else {
        return default;
    };

    let absolute = match positive_seconds(
        index,
        "absolute_lifetime_seconds",
        raw.absolute_lifetime_seconds,
        errors,
    ) {
        Some(duration) => duration,
        None => default.absolute_lifetime,
    };

    // Zero is a value here rather than a mistake: it means "no idle clock",
    // which is a policy a long-lived machine integration legitimately wants.
    // Negative is still a mistake.
    let idle = match raw.idle_lifetime_seconds {
        None => default.idle_lifetime,
        Some(0) => None,
        Some(_) => positive_seconds(
            index,
            "idle_lifetime_seconds",
            raw.idle_lifetime_seconds,
            errors,
        )
        .or(default.idle_lifetime),
    };

    let grace = positive_seconds(
        index,
        "rotation_grace_seconds",
        raw.rotation_grace_seconds,
        errors,
    );

    let rotation = match raw.rotation.as_deref() {
        None | Some("none") => {
            if grace.is_some() {
                errors.problem(
                    format!("tenant[{index}].refresh.rotation_grace_seconds"),
                    "a grace window has no meaning without rotation = \"migration\"".to_owned(),
                );
            }
            Rotation::None
        }
        Some("migration") => {
            if let Some(grace) = grace {
                Rotation::Migration { grace }
            } else {
                // The mode is time-boxed by definition, so it cannot be turned
                // on without saying for how long.
                errors.missing(format!("tenant[{index}].refresh.rotation_grace_seconds"));
                Rotation::None
            }
        }
        Some(other) => {
            errors.problem(
                format!("tenant[{index}].refresh.rotation"),
                format!("unknown rotation mode {other:?}; expected \"none\" or \"migration\""),
            );
            Rotation::None
        }
    };

    RefreshPolicy {
        absolute_lifetime: absolute,
        idle_lifetime: idle,
        bind_to_dpop_key: raw.bind_to_dpop_key.unwrap_or(default.bind_to_dpop_key),
        rotation,
    }
    .clamped()
}

/// Reads one `…_seconds` key, reporting anything that is not positive.
fn positive_seconds(
    index: usize,
    key: &str,
    value: Option<i64>,
    errors: &mut Collector,
) -> Option<time::Duration> {
    let value = value?;
    if value <= 0 {
        errors.problem(
            format!("tenant[{index}].refresh.{key}"),
            format!("must be a positive number of seconds, not {value}"),
        );
        return None;
    }
    Some(time::Duration::seconds(value))
}

/// Validates `[admin]`, the deployment admin seeded at boot (ADR-0010).
///
/// Three things can go wrong and each is reported rather than guessed at: no
/// issuer for the reserved tenant, a reserved tenant that is also declared as
/// an ordinary `[[tenant]]`, and a password source that is missing or given
/// twice. The last one follows `[keys]`: two sources would leave the server
/// choosing a credential silently.
fn validate_admin(
    raw: Option<RawAdmin>,
    tenants: &[TenantConfig],
    errors: &mut Collector,
) -> Option<AdminConfig> {
    let raw = raw?;

    let tenant = match TenantId::parse(raw.tenant.as_deref().unwrap_or(DEFAULT_ADMIN_TENANT)) {
        Ok(tenant) => Some(tenant),
        Err(e) => {
            errors.problem("admin.tenant", e.to_string());
            None
        }
    };

    let issuer = match raw.issuer {
        None => {
            errors.missing("admin.issuer");
            None
        }
        Some(raw) => match Issuer::parse(&raw) {
            Ok(issuer) => Some(issuer),
            Err(e) => {
                errors.problem("admin.issuer", e.to_string());
                None
            }
        },
    };

    // The reserved tenant is created and marked by the seed. Declaring it in
    // `[[tenant]]` as well would mean two places assert what it is, and the
    // ordinary bootstrap would be the one that runs second.
    if let Some(tenant) = &tenant
        && tenants.iter().any(|declared| declared.id == *tenant)
    {
        errors.problem(
            "admin.tenant",
            format!(
                "{tenant} is also declared as a [[tenant]]: the reserved tenant is \
                 created by the admin seed and must not be declared twice"
            ),
        );
    }
    if let (Some(issuer), Some(_)) = (&issuer, &tenant)
        && let Some(clash) = tenants.iter().find(|declared| declared.issuer == *issuer)
    {
        errors.problem(
            "admin.issuer",
            format!("duplicate of the issuer declared by tenant {}", clash.id),
        );
    }

    let password = match (raw.password_file, raw.password_env) {
        (Some(path), None) => Some(PasswordSource::File(path)),
        (None, Some(variable)) => Some(PasswordSource::Env(variable)),
        (None, None) => {
            errors.problem(
                "admin.password_file",
                "a deployment admin needs a password: set admin.password_file or \
                 admin.password_env. There is no key that takes the password itself, \
                 and no default — a built-in credential is one every deployment shares",
            );
            None
        }
        (Some(_), Some(_)) => {
            errors.problem(
                "admin",
                "set exactly one of admin.password_file and admin.password_env, not both",
            );
            None
        }
    };

    Some(AdminConfig {
        tenant: tenant?,
        issuer: issuer?,
        username: raw
            .username
            .unwrap_or_else(|| DEFAULT_ADMIN_USERNAME.to_owned()),
        password: password?,
    })
}

/// Checks a configured default resource against RFC 8707 §2.
///
/// The same shape the schema's `default_resource` check enforces and that
/// `Audience::new` enforces again at issuance. Three statements of one rule is
/// deliberate: this one names the config key an operator has to fix.
fn resource_identifier(raw: &str) -> Result<String, String> {
    let parsed = url::Url::parse(raw).map_err(|e| e.to_string())?;
    if parsed.scheme() != "https" {
        return Err("must be https".to_owned());
    }
    if parsed.fragment().is_some() {
        return Err("must not carry a fragment".to_owned());
    }
    Ok(raw.to_owned())
}

/// Overlays `ASTERIUS__SECTION__KEY` variables onto the parsed table.
///
/// The value is parsed as a TOML scalar so that `true`, `16` and `"text"` mean
/// what they say; anything that is not valid TOML on its own is taken as a
/// string, which is what makes `ASTERIUS__DATABASE__URL=postgres://…` work
/// without quoting.
fn apply_env_overrides(
    table: &mut toml::Table,
    env: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    for (name, value) in env {
        let Some(suffix) = name.strip_prefix(ENV_PREFIX) else {
            continue;
        };
        let segments: Vec<String> = suffix.split(ENV_SEPARATOR).map(str::to_lowercase).collect();
        if segments.iter().any(String::is_empty) {
            return Err(ConfigError::Shape {
                path: name.clone(),
                message: "environment override has an empty key segment".to_owned(),
            });
        }
        set_path(table, &segments, parse_scalar(value), name)?;
    }
    Ok(())
}

fn parse_scalar(raw: &str) -> toml::Value {
    // `toml` has no scalar entry point, so round-trip through a one-key table.
    format!("v = {raw}")
        .parse::<toml::Table>()
        .ok()
        .and_then(|mut t| t.remove("v"))
        .unwrap_or_else(|| toml::Value::String(raw.to_owned()))
}

fn set_path(
    table: &mut toml::Table,
    segments: &[String],
    value: toml::Value,
    var: &str,
) -> Result<(), ConfigError> {
    let Some((last, parents)) = segments.split_last() else {
        return Ok(());
    };
    let mut cursor = table;
    for (depth, segment) in parents.iter().enumerate() {
        let entry = cursor
            .entry(segment.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        cursor = entry.as_table_mut().ok_or_else(|| ConfigError::Shape {
            path: segments[..=depth].join("."),
            message: format!("{var} would overwrite a non-table value"),
        })?;
    }
    cursor.insert(last.clone(), value);
    Ok(())
}

// ---------------------------------------------------------------------------
// Introspection, for the generated reference
// ---------------------------------------------------------------------------

/// The name of every table in the file, paired with the keys its deserializer
/// accepts.
///
/// Read *out of the deserializers* rather than listed by hand. A reference
/// document maintained alongside the schema diverges from it on the first key
/// somebody adds; one derived from the schema cannot, and
/// [`crate::config_reference`] turns this into a test that fails the moment the
/// two disagree.
///
/// The trick is `deny_unknown_fields`: offer a struct a key it does not know
/// and serde's error names every key it does. That is the same mechanism an
/// operator's typo hits, so what this reports is exactly what the file accepts.
#[must_use]
pub fn declared_keys() -> BTreeMap<&'static str, Vec<String>> {
    [
        (ROOT_TABLE, accepted_keys::<RawConfig>()),
        ("server", accepted_keys::<RawServer>()),
        ("server.tls", accepted_keys::<RawTls>()),
        ("server.proxy", accepted_keys::<RawProxy>()),
        ("database", accepted_keys::<RawDatabase>()),
        ("features", accepted_keys::<Capabilities>()),
        ("keys", accepted_keys::<RawKeys>()),
        ("registration", accepted_keys::<RawRegistration>()),
        ("tenant", accepted_keys::<RawTenant>()),
        ("tenant.refresh", accepted_keys::<RawRefresh>()),
        ("admin", accepted_keys::<RawAdmin>()),
        ("login", accepted_keys::<RawLogin>()),
        ("limits", accepted_keys::<RawLimits>()),
        ("dpop", accepted_keys::<RawDpop>()),
    ]
    .into_iter()
    .collect()
}

/// How [`declared_keys`] names the top level of the file.
pub const ROOT_TABLE: &str = "<root>";

/// The keys one table's deserializer accepts, in declaration order.
fn accepted_keys<T: serde::de::DeserializeOwned>() -> Vec<String> {
    // A key no table will ever declare, so the error is always the one we want.
    const PROBE: &str = "asterius-probe-for-an-unknown-key";

    let mut table = toml::Table::new();
    table.insert(PROBE.to_owned(), toml::Value::Boolean(false));
    match T::deserialize(toml::Value::Table(table)) {
        // Only reachable if a table loses `deny_unknown_fields`, which would
        // also mean an operator's typo is silently ignored. Empty here makes
        // the reference test fail rather than quietly document nothing.
        Ok(_) => Vec::new(),
        Err(error) => expected_keys(&error.to_string()),
    }
}

/// Pulls the key names out of serde's "unknown field" message.
///
/// Serde renders it as "unknown field X, expected one of A, B", with each name
/// in backticks — or "expected A" for a table with a single key.
fn expected_keys(message: &str) -> Vec<String> {
    message
        .split_once(", expected")
        .map(|(_, tail)| {
            tail.split('`')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// `[dpop]`: the shared nonce secret (`ast-a05.11`)
// ---------------------------------------------------------------------------

/// DPoP settings that are not capability flags.
///
/// Only read when [`asterius_domain::Feature::DpopNonce`] is on. A deployment
/// that issues no nonces holds no key for them.
#[derive(Debug, Default)]
pub struct DpopConfig {
    /// The HMAC key every nonce is derived from, shared between replicas.
    ///
    /// `None` means each process generates its own at boot. That is correct for
    /// one replica and merely wasteful for several: RFC 9449 §8 makes the
    /// handshake self-correcting, so a client that presents replica A's nonce
    /// to replica B is told `use_dpop_nonce` and retries. What it costs is the
    /// retry becoming a per-request coin flip rather than a once-per-client
    /// event, which is the very thing the one-window lookback exists to avoid.
    ///
    /// A [`Secret`], so a `Debug` of the configuration — which is what reaches
    /// a log line and `/admin` — prints `[REDACTED]` rather than the key.
    pub nonce_secret: Option<Secret<Vec<u8>>>,
}

/// The `[dpop]` table.
///
/// The same two spellings as `[keys]`, deliberately and with the same parser
/// ([`asterius_jose::kek::decode_secret`]): this is 32 bytes of base64 supplied
/// by an orchestrator, exactly like the KEK, and a second way of writing a
/// secret into the configuration is a second way to get it wrong. There is no
/// key that takes the secret inline, for the reason `[admin]` has none.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDpop {
    nonce_secret_file: Option<PathBuf>,
    nonce_secret_env: Option<String>,
}

/// Resolves `[dpop] nonce_secret_*` to the bytes the nonce issuer keys on.
///
/// Read here rather than at the composition root, unlike the KEK: a malformed
/// KEK stops the server at the first thing that needs it, whereas a malformed
/// nonce secret would otherwise be indistinguishable from an absent one — and
/// "absent" is a supported deployment. Resolving it during validation is what
/// makes the difference visible, and the message names the key that is wrong.
///
/// Absent is not an error and never will be: it is the single-replica default,
/// announced in the log at startup.
fn validate_dpop(
    raw: RawDpop,
    env: &BTreeMap<String, String>,
    errors: &mut Collector,
) -> DpopConfig {
    let material = match (raw.nonce_secret_file, raw.nonce_secret_env) {
        (None, None) => None,
        (Some(path), None) => asterius_jose::kek::read_secret_file(&path)
            .map_err(|reason| {
                errors.problem(
                    "dpop.nonce_secret_file",
                    format!(
                        "cannot read the DPoP nonce secret from {}: {reason}. \
                             It is 32 bytes, base64: `head -c 32 /dev/urandom | base64`",
                        path.display()
                    ),
                );
            })
            .ok(),
        (None, Some(variable)) => env
            .get(&variable)
            .ok_or("environment variable is unset")
            .and_then(|value| asterius_jose::kek::decode_secret(value))
            .map_err(|reason| {
                errors.problem(
                    "dpop.nonce_secret_env",
                    format!(
                        "cannot read the DPoP nonce secret from {variable}: {reason}. \
                             It is 32 bytes, base64: `head -c 32 /dev/urandom | base64`"
                    ),
                );
            })
            .ok(),
        (Some(_), Some(_)) => {
            errors.problem(
                "dpop",
                "set exactly one of dpop.nonce_secret_file and dpop.nonce_secret_env, not both",
            );
            None
        }
    };

    DpopConfig {
        // `Zeroizing<Vec<u8>>` out, `Secret<Vec<u8>>` in: both zero on drop, and
        // only the second refuses to print itself.
        nonce_secret: material.map(|bytes| Secret::new(bytes.to_vec())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::Feature;

    const MINIMAL: &str = r#"
        [keys]
        kek_env = "ASTERIUS_KEK"

        [database]
        url = "postgres://asterius@localhost/asterius"

        [[tenant]]
        id = "demo"
        issuer = "https://as.example/t/demo"
    "#;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse(text, Path::new("asterius.toml"), &BTreeMap::new())
    }

    fn parse_with_env(text: &str, env: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let env = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::parse(text, Path::new("asterius.toml"), &env)
    }

    fn problems(result: Result<Config, ConfigError>) -> Problems {
        match result {
            Err(ConfigError::Invalid(problems)) => problems,
            Err(other) => panic!("expected validation problems, got {other}"),
            Ok(_) => panic!("expected validation problems, configuration was accepted"),
        }
    }

    #[test]
    fn a_deployment_that_says_nothing_about_login_still_has_limits() {
        let config = parse(MINIMAL).expect("minimal config should be valid");

        assert_eq!(config.login.per_account.max, DEFAULT_LOGIN_MAX_PER_ACCOUNT);
        assert_eq!(config.login.per_address.max, DEFAULT_LOGIN_MAX_PER_ADDRESS);
        assert_eq!(
            config.login.per_account.window.whole_seconds(),
            i64::try_from(DEFAULT_LOGIN_WINDOW_SECONDS).expect("a small number"),
        );
    }

    #[test]
    fn login_limits_are_read_from_the_file() {
        let text = format!(
            "{MINIMAL}\n[login]\nfailure_window_seconds = 60\nmax_failures_per_account = 3\n"
        );

        let config = parse(&text).expect("a valid login table");

        assert_eq!(config.login.per_account.max, 3);
        assert_eq!(config.login.per_account.window.whole_seconds(), 60);
        // Untouched keys keep their defaults rather than collapsing to the one
        // that was set.
        assert_eq!(config.login.per_address.max, DEFAULT_LOGIN_MAX_PER_ADDRESS);
    }

    /// A window that resets before an attacker's attempts add up is a limit in
    /// name only, so it is refused rather than quietly raised.
    #[test]
    fn a_window_below_the_floor_is_refused() {
        let text = format!("{MINIMAL}\n[login]\nfailure_window_seconds = 1\n");

        let problems = problems(parse(&text));

        assert!(
            problems
                .paths()
                .any(|path| path == "login.failure_window_seconds"),
            "{problems}"
        );
    }

    /// Zero is spellable and would refuse every sign-in, including the
    /// operator's own.
    #[test]
    fn a_limit_of_zero_is_refused() {
        let text = format!("{MINIMAL}\n[login]\nmax_failures_per_account = 0\n");

        let problems = problems(parse(&text));

        assert!(
            problems
                .paths()
                .any(|path| path == "login.max_failures_per_account"),
            "{problems}"
        );
    }

    /// An unlimited `/register` is not a shape this server offers, so saying
    /// nothing about it still produces limits.
    #[test]
    fn a_deployment_that_says_nothing_about_endpoints_still_has_limits() {
        // Arrange & Act
        let config = parse(MINIMAL).expect("minimal config should be valid");

        // Assert
        assert_eq!(
            config.limits.registration.per_address.max,
            DEFAULT_LIMIT_REGISTRATION_PER_ADDRESS
        );
        assert_eq!(
            config.limits.token.per_client.map(|limit| limit.max),
            Some(DEFAULT_LIMIT_TOKEN_PER_CLIENT)
        );
    }

    /// The endpoints do not share one number: a limit sized for UserInfo's
    /// resource servers would be no limit at all on registration.
    #[test]
    fn endpoints_do_not_all_get_the_same_default() {
        // Arrange & Act
        let config = parse(MINIMAL).expect("minimal config should be valid");

        // Assert
        assert!(
            config.limits.registration.per_address.max < config.limits.userinfo.per_address.max
        );
    }

    #[test]
    fn endpoint_limits_are_read_from_the_file() {
        // Arrange
        let text =
            format!("{MINIMAL}\n[limits]\nwindow_seconds = 30\nregistration_per_address = 3\n");

        // Act
        let config = parse(&text).expect("a valid limits table");

        // Assert
        assert_eq!(config.limits.registration.per_address.max, 3);
        assert_eq!(
            config
                .limits
                .registration
                .per_address
                .window
                .whole_seconds(),
            30
        );
        // A key nobody touched keeps its default rather than collapsing onto
        // the one that was set.
        assert_eq!(
            config.limits.token.per_address.max,
            DEFAULT_LIMIT_TOKEN_PER_ADDRESS
        );
    }

    /// Zero is spellable and would answer 429 to every caller of that
    /// endpoint.
    #[test]
    fn an_endpoint_limit_of_zero_is_refused() {
        // Arrange
        let text = format!("{MINIMAL}\n[limits]\ntoken_per_client = 0\n");

        // Act
        let problems = problems(parse(&text));

        // Assert
        assert!(
            problems
                .paths()
                .any(|path| path == "limits.token_per_client"),
            "{problems}"
        );
    }

    #[test]
    fn an_endpoint_window_below_the_floor_is_refused() {
        // Arrange
        let text = format!("{MINIMAL}\n[limits]\nwindow_seconds = 1\n");

        // Act
        let problems = problems(parse(&text));

        // Assert
        assert!(
            problems.paths().any(|path| path == "limits.window_seconds"),
            "{problems}"
        );
    }

    #[test]
    fn minimal_configuration_is_accepted_with_defaults() {
        let config = parse(MINIMAL).expect("minimal config should be valid");
        assert_eq!(config.server.bind.to_string(), "0.0.0.0:9443");
        assert_eq!(config.server.mode, TransportMode::BehindProxy);
        assert!(config.server.tls.is_none());
        assert_eq!(config.database.max_connections, 16);
        assert_eq!(config.features, Capabilities::default());
        assert_eq!(config.tenants.len(), 1);
        assert_eq!(
            config.tenants[0].issuer.as_str(),
            "https://as.example/t/demo"
        );
    }

    // ---- unknown keys ----------------------------------------------------

    #[test]
    fn an_unknown_key_names_its_path() {
        let err = parse(&format!("{MINIMAL}\n[server]\nbnid = \"0.0.0.0:1\"\n")).unwrap_err();
        let ConfigError::Shape { path, message } = &err else {
            panic!("expected a shape error, got {err}");
        };
        assert_eq!(path, "server.bnid");
        assert!(message.contains("unknown field"), "{message}");
    }

    #[test]
    fn an_unknown_nested_key_names_its_full_path() {
        let text = format!(
            "{MINIMAL}\n[server]\nmode = \"terminate_tls\"\n[server.tls]\ncert = \"a.pem\"\n"
        );
        let err = parse(&text).unwrap_err();
        let ConfigError::Shape { path, message } = &err else {
            panic!("expected a shape error, got {err}");
        };
        assert_eq!(path, "server.tls.cert");
        assert!(message.contains("unknown field"), "{message}");
    }

    /// ADR-0003 removed RS256 outright, so the flag an operator is most likely
    /// to reach for must fail loudly rather than be ignored.
    #[test]
    fn a_removed_feature_flag_is_rejected_rather_than_ignored() {
        let err = parse(&format!("{MINIMAL}\n[features]\ncompat_rs256 = true\n")).unwrap_err();
        let ConfigError::Shape { path, message } = &err else {
            panic!("expected a shape error, got {err}");
        };
        assert_eq!(path, "features.compat_rs256");
        assert!(message.contains("unknown field"), "{message}");
    }

    #[test]
    fn a_wrong_type_names_its_path() {
        let err = parse("[database]\nmax_connections = \"lots\"\n").unwrap_err();
        let ConfigError::Shape { path, .. } = &err else {
            panic!("expected a shape error, got {err}");
        };
        assert_eq!(path, "database.max_connections");
    }

    #[test]
    fn a_syntax_error_is_reported_before_anything_else() {
        let err = parse("[database\nurl = 1").unwrap_err();
        assert!(matches!(err, ConfigError::Syntax { .. }), "{err}");
    }

    // ---- accumulated validation -----------------------------------------

    /// The point of the two-pass design: five mistakes must cost one restart,
    /// not five.
    #[test]
    fn every_missing_key_is_reported_in_one_pass() {
        let text = r#"
            [server]
            mode = "terminate_tls"

            [[tenant]]
        "#;
        let problems = problems(parse(text));
        let paths: Vec<&str> = problems.paths().collect();
        assert_eq!(
            paths,
            [
                "server.tls.certificate",
                "server.tls.private_key",
                "database.url",
                "tenant[0].id",
                "tenant[0].issuer",
                "keys.kek_file",
            ]
        );
        assert!(
            problems
                .as_slice()
                .iter()
                .filter(|p| !p.path.starts_with("keys."))
                .all(|p| p.message == "required key is missing")
        );
    }

    #[test]
    fn the_error_message_lists_every_problem() {
        let rendered = problems(parse("[server]\nmode = \"terminate_tls\"\n")).to_string();
        assert!(
            rendered.starts_with("configuration has 4 problems:"),
            "{rendered}"
        );
        assert!(
            rendered.contains("\n  - database.url: required key is missing"),
            "{rendered}"
        );
    }

    #[test]
    fn a_single_problem_is_not_pluralised() {
        let rendered = problems(parse(
            "[keys]\nkek_env = \"K\"\n\n[[tenant]]\nid = \"demo\"\n\n[database]\nurl = \"x\"\n",
        ))
        .to_string();
        assert!(
            rendered.starts_with("configuration has 1 problem:"),
            "{rendered}"
        );
    }

    #[test]
    fn tls_material_without_terminate_tls_is_a_problem() {
        let text =
            format!("{MINIMAL}\n[server.tls]\ncertificate = \"c.pem\"\nprivate_key = \"k.pem\"\n");
        let problems = problems(parse(&text));
        assert_eq!(problems.paths().collect::<Vec<_>>(), ["server.tls"]);
        assert!(problems.as_slice()[0].message.contains("behind_proxy"));
    }

    #[test]
    fn terminate_tls_with_material_is_accepted() {
        let text = format!(
            "{MINIMAL}\n[server]\nmode = \"terminate_tls\"\n\
             [server.tls]\ncertificate = \"c.pem\"\nprivate_key = \"k.pem\"\n"
        );
        let config = parse(&text).expect("valid");
        let tls = config.server.tls.expect("tls should be present");
        assert_eq!(tls.certificate, PathBuf::from("c.pem"));
    }

    #[test]
    fn a_bad_bind_address_is_a_problem_not_a_panic() {
        let text = format!("{MINIMAL}\n[server]\nbind = \"not-an-address\"\n");
        assert_eq!(
            problems(parse(&text)).paths().collect::<Vec<_>>(),
            ["server.bind"]
        );
    }

    // ---- issuer validation ----------------------------------------------

    /// RFC 8414 §2 and OIDC Discovery §3. `Issuer` owns the rule; this asserts
    /// that startup actually refuses, and names the offending tenant.
    #[test]
    fn the_server_refuses_to_start_on_a_bad_issuer() {
        for (issuer, expected) in [
            ("http://as.example/t/demo", "https"),
            ("https://as.example/t/demo?x=1", "query"),
            ("https://as.example/t/demo#f", "fragment"),
            ("https://user:pw@as.example", "userinfo"),
            ("as.example", "URL"),
        ] {
            let text = format!(
                "[keys]\nkek_env = \"K\"\n\n[database]\nurl = \"x\"\n\n[[tenant]]\nid = \"demo\"\nissuer = \"{issuer}\"\n"
            );
            let problems = problems(parse(&text));
            assert_eq!(
                problems.paths().collect::<Vec<_>>(),
                ["tenant[0].issuer"],
                "{issuer}"
            );
            assert!(
                problems.as_slice()[0].message.contains(expected),
                "{issuer}: expected {expected:?} in {:?}",
                problems.as_slice()[0].message
            );
        }
    }

    /// RFC 9068 §3 requires a default resource indicator, and the issuer is
    /// the one identifier a tenant is always known to own — UserInfo and
    /// introspection live under it. An operator who names nothing gets that
    /// rather than a token audienced at nothing.
    /// FAPI 2.0 SP §5.3.2.1 item 9. A file that says nothing about refresh
    /// tokens produces the compliant policy, not a permissive one.
    #[test]
    fn a_tenant_with_no_refresh_table_gets_the_fapi_default() {
        // Arrange / Act
        let config = parse(MINIMAL).expect("valid");

        // Assert
        assert_eq!(config.tenants[0].refresh, RefreshPolicy::default());
        assert!(!config.tenants[0].refresh.rotates());
        // RFC 9449 §5: a confidential client's refresh token is not pinned to
        // the proof key, and every client here is confidential.
        assert!(!config.tenants[0].refresh.bind_to_dpop_key);
    }

    #[test]
    fn a_migration_rotation_is_read_with_its_grace_window() {
        // Arrange
        let text = format!(
            "{MINIMAL}\n[tenant.refresh]\nrotation = \"migration\"\n\
             rotation_grace_seconds = 45\n"
        );

        // Act
        let config = parse(&text).expect("valid");

        // Assert
        assert_eq!(
            config.tenants[0].refresh.rotation,
            Rotation::Migration {
                grace: time::Duration::seconds(45)
            }
        );
    }

    /// The mode is time-boxed by definition, so it cannot be turned on
    /// without saying for how long a superseded token stays acceptable.
    #[test]
    fn a_migration_rotation_without_a_grace_window_is_refused() {
        // Arrange
        let text = format!("{MINIMAL}\n[tenant.refresh]\nrotation = \"migration\"\n");

        // Act
        let error = parse(&text).expect_err("must be refused");

        // Assert
        let ConfigError::Invalid(problems) = error else {
            panic!("expected a validation failure");
        };
        assert_eq!(
            problems.paths().collect::<Vec<_>>(),
            ["tenant[0].refresh.rotation_grace_seconds"]
        );
    }

    /// The mirror image, and the one worth refusing rather than ignoring: an
    /// operator who wrote a grace window believes rotation is on.
    #[test]
    fn a_grace_window_without_rotation_is_refused() {
        // Arrange
        let text = format!("{MINIMAL}\n[tenant.refresh]\nrotation_grace_seconds = 45\n");

        // Act
        let error = parse(&text).expect_err("must be refused");

        // Assert
        let ConfigError::Invalid(problems) = error else {
            panic!("expected a validation failure");
        };
        assert_eq!(
            problems.paths().collect::<Vec<_>>(),
            ["tenant[0].refresh.rotation_grace_seconds"]
        );
    }

    /// Zero is a policy — a machine integration with no idle clock — and a
    /// negative number is a mistake. They must not be read as the same thing.
    #[test]
    fn a_zero_idle_lifetime_disables_the_idle_clock_and_a_negative_one_is_refused() {
        // Arrange
        let disabled = format!("{MINIMAL}\n[tenant.refresh]\nidle_lifetime_seconds = 0\n");
        let negative = format!("{MINIMAL}\n[tenant.refresh]\nidle_lifetime_seconds = -1\n");

        // Act
        let config = parse(&disabled).expect("zero is a policy");
        let error = parse(&negative).expect_err("negative is a mistake");

        // Assert
        assert_eq!(config.tenants[0].refresh.idle_lifetime, None);
        let ConfigError::Invalid(problems) = error else {
            panic!("expected a validation failure");
        };
        assert_eq!(
            problems.paths().collect::<Vec<_>>(),
            ["tenant[0].refresh.idle_lifetime_seconds"]
        );
    }

    /// An idle window past the absolute deadline is a setting with no effect,
    /// so it is clamped rather than obeyed or ignored.
    #[test]
    fn an_idle_window_longer_than_the_absolute_lifetime_is_clamped() {
        // Arrange
        let text = format!(
            "{MINIMAL}\n[tenant.refresh]\nabsolute_lifetime_seconds = 3600\n\
             idle_lifetime_seconds = 86400\n"
        );

        // Act
        let config = parse(&text).expect("valid");

        // Assert
        assert_eq!(
            config.tenants[0].refresh.idle_lifetime,
            Some(time::Duration::hours(1))
        );
    }

    #[test]
    fn a_tenant_that_names_no_default_resource_is_audienced_at_its_issuer() {
        let text = "[keys]\nkek_env = \"K\"\n\n[database]\nurl = \"x\"\n\n[[tenant]]\nid = \"demo\"\n\
                    issuer = \"https://as.example/t/demo\"\n";
        let config = parse(text).expect("valid");
        assert_eq!(
            config.tenants[0].default_resource,
            "https://as.example/t/demo"
        );
    }

    #[test]
    fn a_declared_default_resource_wins_over_the_issuer() {
        let text = "[keys]\nkek_env = \"K\"\n\n[database]\nurl = \"x\"\n\n[[tenant]]\nid = \"demo\"\n\
                    issuer = \"https://as.example/t/demo\"\n\
                    default_resource = \"https://api.example/v1\"\n";
        let config = parse(text).expect("valid");
        assert_eq!(config.tenants[0].default_resource, "https://api.example/v1");
    }

    /// RFC 8707 §2: a resource identifier is an absolute URI without a
    /// fragment. Refused at boot, where somebody is watching, rather than at
    /// the first token request, where the failure is a signing error nobody
    /// can connect to a configuration key.
    #[test]
    fn a_default_resource_that_is_not_a_resource_identifier_is_refused() {
        for bad in [
            "http://api.example/",
            "https://api.example/#frag",
            "api.example",
        ] {
            let text = format!(
                "[keys]\nkek_env = \"K\"\n\n[database]\nurl = \"x\"\n\n[[tenant]]\nid = \"demo\"\n\
                 issuer = \"https://as.example/t/demo\"\ndefault_resource = \"{bad}\"\n"
            );
            assert_eq!(
                problems(parse(&text)).paths().collect::<Vec<_>>(),
                ["tenant[0].default_resource"],
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn the_issuer_is_normalised_once_and_stored_canonical() {
        let text = "[keys]\nkek_env = \"K\"\n\n[database]\nurl = \"x\"\n\n[[tenant]]\nid = \"demo\"\n\
                    issuer = \"https://AS.Example:443/t/demo/\"\n";
        let config = parse(text).expect("valid");
        assert_eq!(
            config.tenants[0].issuer.as_str(),
            "https://as.example/t/demo"
        );
    }

    /// `https://as.example` and `https://as.example/` are the same issuer, and
    /// two tenants claiming it would make `iss` ambiguous. Detection happens on
    /// the canonical form, so the inconsistent spelling cannot hide it.
    #[test]
    fn tenants_may_not_share_an_issuer_however_it_is_spelled() {
        let text = "[keys]\nkek_env = \"K\"\n\n[database]\nurl = \"x\"\n\n\
                    [[tenant]]\nid = \"a\"\nissuer = \"https://as.example\"\n\n\
                    [[tenant]]\nid = \"b\"\nissuer = \"https://as.example/\"\n";
        let problems = problems(parse(text));
        assert_eq!(problems.paths().collect::<Vec<_>>(), ["tenant[1].issuer"]);
        assert!(
            problems.as_slice()[0]
                .message
                .contains("duplicate of tenant[0]")
        );
    }

    /// The tenant id becomes a path segment in the issuer, so the config file
    /// is the last place it can be rejected cheaply.
    #[test]
    fn a_tenant_id_that_cannot_be_a_path_segment_is_refused() {
        for bad in ["../etc", "Demo", "a b", "has.dot", ""] {
            let text = format!(
                "[keys]\nkek_env = \"K\"\n\n[database]\nurl = \"x\"\n\n[[tenant]]\nid = \"{bad}\"\n\
                 issuer = \"https://as.example/t/x\"\n"
            );
            let problems = problems(parse(&text));
            assert_eq!(
                problems.paths().collect::<Vec<_>>(),
                ["tenant[0].id"],
                "accepted tenant id {bad:?}"
            );
        }
    }

    #[test]
    fn tenants_may_not_share_an_id() {
        let text = "[keys]\nkek_env = \"K\"\n\n[database]\nurl = \"x\"\n\n\
                    [[tenant]]\nid = \"demo\"\nissuer = \"https://a.example\"\n\n\
                    [[tenant]]\nid = \"demo\"\nissuer = \"https://b.example\"\n";
        assert_eq!(
            problems(parse(text)).paths().collect::<Vec<_>>(),
            ["tenant[1].id"]
        );
    }

    // ---- feature flags ---------------------------------------------------

    #[test]
    fn feature_flags_land_in_one_capabilities_struct() {
        let text = format!("{MINIMAL}\n[features]\nssf = true\ndpop_nonce = true\n");
        let config = parse(&text).expect("valid");
        assert_eq!(
            config.features.enabled().collect::<Vec<_>>(),
            [Feature::Ssf, Feature::DpopNonce]
        );
        assert!(!config.features.is_enabled(Feature::Mtls));
    }

    // ---- environment overrides -------------------------------------------

    #[test]
    fn environment_overrides_replace_file_values_with_typed_scalars() {
        let config = parse_with_env(
            MINIMAL,
            &[
                ("ASTERIUS__DATABASE__MAX_CONNECTIONS", "64"),
                ("ASTERIUS__SERVER__BIND", "127.0.0.1:9443"),
                ("ASTERIUS__FEATURES__SSF", "true"),
            ],
        )
        .expect("valid");
        assert_eq!(config.database.max_connections, 64);
        assert_eq!(config.server.bind.to_string(), "127.0.0.1:9443");
        assert!(config.features.ssf);
    }

    /// A DSN is full of characters that are not valid TOML on their own, so an
    /// unparseable value has to fall back to a string rather than fail.
    #[test]
    fn an_unquoted_environment_value_is_taken_as_a_string() {
        let config = parse_with_env(
            MINIMAL,
            &[(
                "ASTERIUS__DATABASE__URL",
                "postgres://u:p@db:5432/asterius?sslmode=require",
            )],
        )
        .expect("valid");
        assert_eq!(
            config.database.url.expose(),
            "postgres://u:p@db:5432/asterius?sslmode=require"
        );
    }

    #[test]
    fn an_environment_override_can_create_a_table_the_file_omitted() {
        let config =
            parse_with_env(MINIMAL, &[("ASTERIUS__FEATURES__AUTHZEN", "true")]).expect("valid");
        assert!(config.features.authzen);
    }

    #[test]
    fn an_environment_override_is_validated_like_any_other_value() {
        let err =
            parse_with_env(MINIMAL, &[("ASTERIUS__FEATURES__COMPAT_RS256", "true")]).unwrap_err();
        assert!(matches!(err, ConfigError::Shape { .. }), "{err}");
    }

    #[test]
    fn unprefixed_environment_variables_are_ignored() {
        let config =
            parse_with_env(MINIMAL, &[("PATH", "/usr/bin"), ("HOME", "/root")]).expect("valid");
        assert_eq!(config.database.max_connections, 16);
    }

    #[test]
    fn an_override_that_would_shadow_a_scalar_is_rejected() {
        let err = parse_with_env(MINIMAL, &[("ASTERIUS__DATABASE__URL__HOST", "db")]).unwrap_err();
        let ConfigError::Shape { path, message } = &err else {
            panic!("expected a shape error, got {err}");
        };
        assert_eq!(path, "database.url");
        assert!(message.contains("non-table"), "{message}");
    }

    // ---- transport -------------------------------------------------------

    #[test]
    fn transport_defaults_are_the_conservative_ones() {
        let config = parse(MINIMAL).expect("valid");
        assert_eq!(config.server.request_body_limit, 64 * 1024);
        assert_eq!(config.server.request_timeout, Duration::from_secs(10));
        // Behind a proxy by default, believing nothing but this machine.
        assert_eq!(config.server.mode, TransportMode::BehindProxy);
        let trusted: Vec<String> = config
            .server
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(trusted, ["127.0.0.0/8", "::1/128"]);
    }

    #[test]
    fn trusted_proxies_are_parsed_as_cidr_blocks() {
        let text = format!(
            "{MINIMAL}\n[server.proxy]\ntrusted_cidrs = [\"10.42.0.0/16\", \"2001:db8::/32\"]\n"
        );
        let config = parse(&text).expect("valid");
        let trusted: Vec<String> = config
            .server
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(trusted, ["10.42.0.0/16", "2001:db8::/32"]);
    }

    #[test]
    fn a_malformed_cidr_names_its_index() {
        let text = format!(
            "{MINIMAL}\n[server.proxy]\ntrusted_cidrs = [\"10.42.0.0/16\", \"not-a-cidr\"]\n"
        );
        let problems = problems(parse(&text));
        assert_eq!(
            problems.paths().collect::<Vec<_>>(),
            ["server.proxy.trusted_cidrs[1]"]
        );
    }

    /// An empty trust list in proxy mode is almost certainly a mistake: every
    /// forwarding header would be ignored and every client would appear to come
    /// from the proxy, which silently merges all of them into one rate-limit
    /// bucket and one audit identity.
    #[test]
    fn an_empty_trust_list_is_refused_rather_than_silently_ignored() {
        let text = format!("{MINIMAL}\n[server.proxy]\ntrusted_cidrs = []\n");
        let problems = problems(parse(&text));
        assert_eq!(
            problems.paths().collect::<Vec<_>>(),
            ["server.proxy.trusted_cidrs"]
        );
    }

    /// The mirror of the stray-`[server.tls]` rule: nothing is in front of a
    /// process that terminates its own TLS, so configuring proxies is a sign
    /// the operator believes something else is true.
    #[test]
    fn trusted_proxies_while_terminating_tls_is_a_problem() {
        let text = format!(
            "{MINIMAL}\n[server]\nmode = \"terminate_tls\"\n\
             [server.tls]\ncertificate = \"c.pem\"\nprivate_key = \"k.pem\"\n\
             [server.proxy]\ntrusted_cidrs = [\"10.0.0.0/8\"]\n"
        );
        let problems = problems(parse(&text));
        assert_eq!(problems.paths().collect::<Vec<_>>(), ["server.proxy"]);
        assert!(problems.as_slice()[0].message.contains("terminate_tls"));
    }

    #[test]
    fn limits_can_be_tuned() {
        let text = format!(
            "{MINIMAL}\n[server]\nrequest_body_limit_bytes = 8192\nrequest_timeout_seconds = 3\n"
        );
        let config = parse(&text).expect("valid");
        assert_eq!(config.server.request_body_limit, 8192);
        assert_eq!(config.server.request_timeout, Duration::from_secs(3));
    }

    // ---- the key-encryption key ------------------------------------------

    /// There is no safe default. A generated-on-boot KEK would produce a key
    /// that cannot open yesterday's rows, and the failure would surface as
    /// corruption rather than as configuration.
    #[test]
    fn a_missing_key_encryption_key_refuses_the_boot() {
        let text = "[database]\nurl = \"x\"\n";
        let problems = problems(parse(text));
        assert!(
            problems.paths().any(|path| path.starts_with("keys.")),
            "no problem reported for the missing KEK: {:?}",
            problems.paths().collect::<Vec<_>>()
        );
    }

    /// Two sources would leave the server picking one silently, and an operator
    /// reading the other.
    #[test]
    fn exactly_one_key_encryption_key_source_is_permitted() {
        let both = "[database]\nurl = \"x\"\n\n[keys]\nkek_file = \"/k\"\nkek_env = \"K\"\n";
        assert_eq!(problems(parse(both)).paths().collect::<Vec<_>>(), ["keys"]);

        let file = "[database]\nurl = \"x\"\n\n[keys]\nkek_file = \"/etc/asterius/kek\"\n";
        assert_eq!(
            parse(file).expect("valid").kek,
            KekSource::File(PathBuf::from("/etc/asterius/kek"))
        );

        let env = "[database]\nurl = \"x\"\n\n[keys]\nkek_env = \"ASTERIUS_KEK\"\n";
        assert_eq!(
            parse(env).expect("valid").kek,
            KekSource::Env("ASTERIUS_KEK".to_owned())
        );
    }

    // ---- redaction -------------------------------------------------------

    /// The whole config struct is `Debug`, and something will eventually log it.
    #[test]
    fn debugging_the_configuration_does_not_leak_the_database_password() {
        let config = parse_with_env(
            MINIMAL,
            &[(
                "ASTERIUS__DATABASE__URL",
                "postgres://u:sup3rs3cret@db/asterius",
            )],
        )
        .expect("valid");
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("sup3rs3cret"), "leaked: {rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    // ---- dynamic client registration -------------------------------------

    const INITIAL_ACCESS_TOKEN: &str = "vJ8qN2mXbL5-tRw0KePzUA";

    /// A deployment that never mentioned registration must not be running it.
    /// RFC 7591 §3's "SHOULD allow registration requests with no authorization"
    /// is a deliberate non-default here: the SHOULD serves interoperability
    /// between strangers, and the cost of getting it wrong is an
    /// internet-writable row in `clients`.
    #[test]
    fn registration_is_closed_unless_an_operator_opens_it() {
        assert_eq!(
            parse(MINIMAL).expect("valid").registration,
            RegistrationPolicy::Closed
        );
    }

    /// The mode is not inferred from whether tokens are present, because
    /// deleting the last token would then turn a gated endpoint into an open
    /// one without anybody editing the line that says so.
    #[test]
    fn a_registration_table_must_name_its_mode() {
        let text = format!("{MINIMAL}\n[registration]\ninitial_access_tokens = []\n");
        let error = parse(&text).expect_err("a table with no mode");
        assert!(error.to_string().contains("registration.mode"), "{error}");
    }

    #[test]
    fn a_gated_deployment_hashes_the_tokens_it_was_given() {
        let text = format!(
            "{MINIMAL}\n[registration]\nmode = \"initial_access_token\"\n\
             initial_access_tokens = [\"{INITIAL_ACCESS_TOKEN}\"]\n"
        );
        let config = parse(&text).expect("valid");
        let RegistrationPolicy::Gated(tokens) = &config.registration else {
            panic!("expected a gated policy, got {:?}", config.registration);
        };
        assert_eq!(tokens.len(), 1);

        // The token itself must not survive into the loaded configuration, and
        // `Config` is `Debug` — something will eventually log it.
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains(INITIAL_ACCESS_TOKEN),
            "an initial access token reached a Debug rendering: {rendered}"
        );
    }

    /// A gated endpoint with no tokens is a closed endpoint spelled at length,
    /// and an operator who meant to provision one has made a mistake worth
    /// stopping for.
    #[test]
    fn a_gated_deployment_with_no_tokens_is_a_configuration_error() {
        let text = format!("{MINIMAL}\n[registration]\nmode = \"initial_access_token\"\n");
        let error = parse(&text).expect_err("gated with nothing to present");
        assert!(
            error
                .to_string()
                .contains("registration.initial_access_tokens"),
            "{error}"
        );
    }

    /// FAPI 2.0 SP §5.4.1: a credential no end user handles carries at least
    /// 128 bits of entropy. An initial access token is the only thing between
    /// the internet and this endpoint, so a short one is refused at startup —
    /// and the refusal must not print the token it is complaining about.
    #[test]
    fn a_short_initial_access_token_is_refused_without_being_quoted() {
        let text = format!(
            "{MINIMAL}\n[registration]\nmode = \"initial_access_token\"\n\
             initial_access_tokens = [\"hunter2\"]\n"
        );
        let error = parse(&text).expect_err("a seven-character credential");
        let rendered = error.to_string();
        assert!(
            rendered.contains("registration.initial_access_tokens[0]"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("hunter2"),
            "leaked the token: {rendered}"
        );
    }

    /// A value that does nothing is one an operator believes is doing
    /// something. Tokens under `open` would be inert.
    #[test]
    fn tokens_that_could_never_be_checked_are_a_configuration_error() {
        for mode in ["open", "closed"] {
            let text = format!(
                "{MINIMAL}\n[registration]\nmode = \"{mode}\"\n\
                 initial_access_tokens = [\"{INITIAL_ACCESS_TOKEN}\"]\n"
            );
            let error = parse(&text).expect_err("inert tokens under {mode}");
            assert!(
                error
                    .to_string()
                    .contains("registration.initial_access_tokens"),
                "{mode}: {error}"
            );
        }
    }

    #[test]
    fn open_registration_has_to_be_written_out() {
        let text = format!("{MINIMAL}\n[registration]\nmode = \"open\"\n");
        assert_eq!(
            parse(&text).expect("valid").registration,
            RegistrationPolicy::Open
        );
    }

    /// `deny_unknown_fields` covers the new table too: a typo in a security
    /// switch is the one class of configuration error that must stop the
    /// server rather than be discovered later.
    #[test]
    fn a_typo_in_the_registration_table_stops_the_server() {
        let text = format!("{MINIMAL}\n[registration]\nmode = \"open\"\nrate_limit = 10\n");
        let error = parse(&text).expect_err("an unknown key");
        assert!(error.to_string().contains("registration"), "{error}");
    }

    // ---- [admin]: the deployment admin (ADR-0010) ------------------------

    /// The whole table, spelled out once so each test below changes one thing.
    const WITH_ADMIN: &str = r#"
        [keys]
        kek_env = "ASTERIUS_KEK"

        [database]
        url = "postgres://asterius@localhost/asterius"

        [[tenant]]
        id = "demo"
        issuer = "https://as.example/t/demo"

        [admin]
        issuer = "https://as.example/t/admin"
        password_env = "ASTERIUS_ADMIN_PASSWORD"
    "#;

    #[test]
    fn no_admin_table_seeds_no_admin() {
        let config = parse(MINIMAL).expect("valid");

        assert!(
            config.admin.is_none(),
            "an account that administers every tenant must be asked for"
        );
    }

    #[test]
    fn an_admin_table_defaults_its_tenant_and_username() {
        let config = parse(WITH_ADMIN).expect("valid");
        let admin = config.admin.expect("an admin was declared");

        assert_eq!(admin.tenant.as_str(), "admin");
        assert_eq!(admin.username, "admin");
        assert_eq!(admin.issuer.as_str(), "https://as.example/t/admin");
        assert_eq!(
            admin.password,
            PasswordSource::Env("ASTERIUS_ADMIN_PASSWORD".to_owned())
        );
    }

    /// There is no key that takes the password itself: a credential written in
    /// the configuration file is a credential in version control.
    #[test]
    fn an_admin_without_a_password_source_is_refused() {
        let text = WITH_ADMIN.replace("password_env = \"ASTERIUS_ADMIN_PASSWORD\"", "");

        let problems = problems(parse(&text));

        assert!(
            problems.paths().any(|p| p == "admin.password_file"),
            "{problems:?}"
        );
    }

    /// Two sources would leave the server choosing a credential silently, the
    /// same reason `[keys]` refuses both.
    #[test]
    fn an_admin_with_two_password_sources_is_refused() {
        let text = WITH_ADMIN.replace(
            "password_env = \"ASTERIUS_ADMIN_PASSWORD\"",
            "password_env = \"ASTERIUS_ADMIN_PASSWORD\"\n        \
             password_file = \"/etc/asterius/admin-password\"",
        );

        let problems = problems(parse(&text));

        assert!(problems.paths().any(|p| p == "admin"), "{problems:?}");
    }

    /// A reserved tenant is a real tenant, and a tenant is an issuer.
    #[test]
    fn an_admin_without_an_issuer_is_refused() {
        let text = WITH_ADMIN.replace("issuer = \"https://as.example/t/admin\"", "");

        let problems = problems(parse(&text));

        assert!(
            problems.paths().any(|p| p == "admin.issuer"),
            "{problems:?}"
        );
    }

    /// The seed creates and marks the reserved tenant. Declaring it as an
    /// ordinary tenant as well would mean two places assert what it is.
    #[test]
    fn a_reserved_tenant_that_is_also_a_declared_tenant_is_refused() {
        let text = WITH_ADMIN.replace("id = \"demo\"", "id = \"admin\"");

        let problems = problems(parse(&text));

        assert!(
            problems.paths().any(|p| p == "admin.tenant"),
            "{problems:?}"
        );
    }

    // -----------------------------------------------------------------------
    // `[dpop]` — the shared nonce secret (`ast-a05.11`)
    // -----------------------------------------------------------------------

    /// 32 bytes, base64, as an operator's `head -c 32 /dev/urandom | base64`
    /// would print them.
    const A_NONCE_SECRET: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn a_deployment_that_says_nothing_about_dpop_has_no_shared_nonce_secret() {
        let config = parse(MINIMAL).expect("minimal config should be valid");

        assert!(config.dpop.nonce_secret.is_none());
    }

    #[test]
    fn the_nonce_secret_is_read_from_the_variable_it_names() {
        let text = format!("{MINIMAL}\n[dpop]\nnonce_secret_env = \"ASTERIUS_DPOP_NONCE\"\n");

        let config = parse_with_env(&text, &[("ASTERIUS_DPOP_NONCE", A_NONCE_SECRET)])
            .expect("a well-formed secret is accepted");

        let expected = Secret::new((0..32_u8).collect::<Vec<u8>>());
        assert!(
            config
                .dpop
                .nonce_secret
                .expect("the key was set")
                .ct_eq(&expected)
        );
    }

    /// The refusal the KEK gets, for the same reason: a secret that does not
    /// decode is a mistake, and starting anyway would hide it behind a
    /// per-process key that mostly works.
    #[test]
    fn a_nonce_secret_that_is_not_base64_names_the_key_it_came_from() {
        let text = format!("{MINIMAL}\n[dpop]\nnonce_secret_env = \"ASTERIUS_DPOP_NONCE\"\n");

        let problems = problems(parse_with_env(
            &text,
            &[("ASTERIUS_DPOP_NONCE", "not base64 at all!")],
        ));

        assert!(
            problems.paths().any(|p| p == "dpop.nonce_secret_env"),
            "{problems:?}"
        );
    }

    /// Well-formed base64 of the wrong length is the other half of the same
    /// refusal: 32 bytes, not "whatever decoded".
    #[test]
    fn a_nonce_secret_of_the_wrong_length_is_refused() {
        let text = format!("{MINIMAL}\n[dpop]\nnonce_secret_env = \"ASTERIUS_DPOP_NONCE\"\n");

        let problems = problems(parse_with_env(&text, &[("ASTERIUS_DPOP_NONCE", "AAEC")]));

        assert!(
            problems.paths().any(|p| p == "dpop.nonce_secret_env"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_nonce_secret_file_that_cannot_be_read_names_the_key_it_came_from() {
        let text = format!(
            "{MINIMAL}\n[dpop]\nnonce_secret_file = \"/nonexistent/asterius/dpop.nonce\"\n"
        );

        let problems = problems(parse(&text));

        assert!(
            problems.paths().any(|p| p == "dpop.nonce_secret_file"),
            "{problems:?}"
        );
    }

    /// The `[keys]` rule, for the `[keys]` reason: the server would otherwise
    /// choose between the two silently.
    #[test]
    fn a_nonce_secret_given_twice_is_refused() {
        let text = format!(
            "{MINIMAL}\n[dpop]\nnonce_secret_file = \"/etc/asterius/dpop.nonce\"\n\
             nonce_secret_env = \"ASTERIUS_DPOP_NONCE\"\n"
        );

        let problems = problems(parse(&text));

        assert!(problems.paths().any(|p| p == "dpop"), "{problems:?}");
    }

    /// The one property that matters as much as the key working: a `Debug` of
    /// the configuration is what reaches a log line and the admin console.
    #[test]
    fn the_nonce_secret_does_not_print_itself() {
        let text = format!("{MINIMAL}\n[dpop]\nnonce_secret_env = \"ASTERIUS_DPOP_NONCE\"\n");
        let config = parse_with_env(&text, &[("ASTERIUS_DPOP_NONCE", A_NONCE_SECRET)])
            .expect("a well-formed secret is accepted");

        let rendered = format!("{:?}", config.dpop);

        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        assert!(!rendered.contains(A_NONCE_SECRET), "{rendered}");
    }

    #[test]
    fn a_reserved_tenant_sharing_an_issuer_with_a_declared_tenant_is_refused() {
        let text = WITH_ADMIN.replace(
            "issuer = \"https://as.example/t/demo\"",
            "issuer = \"https://as.example/t/admin\"",
        );

        let problems = problems(parse(&text));

        assert!(
            problems.paths().any(|p| p == "admin.issuer"),
            "{problems:?}"
        );
    }
}
