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

use asterius_domain::{Capabilities, Issuer, Secret};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// The prefix that marks an environment variable as a configuration override.
const ENV_PREFIX: &str = "ASTERIUS__";

/// The separator between key-path segments in an environment variable name.
const ENV_SEPARATOR: &str = "__";

// ---------------------------------------------------------------------------
// The validated configuration
// ---------------------------------------------------------------------------

/// The server's validated configuration.
#[derive(Debug)]
#[non_exhaustive]
pub struct Config {
    /// Listener and transport settings.
    pub server: ServerConfig,
    /// PostgreSQL connection settings.
    pub database: DatabaseConfig,
    /// Which optional capabilities this deployment offers.
    pub features: Capabilities,
    /// Tenants known at boot. Each one is an issuer.
    pub tenants: Vec<TenantConfig>,
}

/// Listener and transport settings.
#[derive(Debug)]
#[non_exhaustive]
pub struct ServerConfig {
    /// The address to listen on.
    pub bind: SocketAddr,
    /// Whether this process terminates TLS itself.
    pub mode: TransportMode,
    /// Certificate and key paths. Present exactly when [`TransportMode::TerminateTls`].
    pub tls: Option<TlsConfig>,
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
#[non_exhaustive]
pub struct TlsConfig {
    /// PEM certificate chain, leaf first.
    pub certificate: PathBuf,
    /// PEM private key.
    pub private_key: PathBuf,
}

/// PostgreSQL connection settings.
#[derive(Debug)]
#[non_exhaustive]
pub struct DatabaseConfig {
    /// The connection URL. Holds a password, so it never reaches a log.
    pub url: Secret<String>,
    /// Upper bound on pooled connections.
    pub max_connections: u32,
}

/// A tenant known at boot.
#[derive(Debug)]
#[non_exhaustive]
pub struct TenantConfig {
    /// The tenant's identifier, as it appears in the issuer path.
    pub id: String,
    /// The tenant's canonical issuer identifier.
    pub issuer: Issuer,
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
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    bind: Option<String>,
    mode: Option<TransportMode>,
    tls: Option<RawTls>,
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
}

/// Default listener address.
///
/// Not 8443: that is the port `tailscale serve` binds to proxy a local app,
/// and colliding with it means the server will not start on a machine that is
/// doing something entirely reasonable. 9443 keeps the "TLS on a high port"
/// convention without the clash.
const DEFAULT_BIND: &str = "0.0.0.0:9443";
const DEFAULT_MAX_CONNECTIONS: u32 = 16;

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

        raw.validate()
    }
}

impl RawConfig {
    fn validate(self) -> Result<Config, ConfigError> {
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

        errors.finish(Config {
            server,
            database,
            features: self.features,
            tenants,
        })
    }
}

impl RawServer {
    fn validate(self, errors: &mut Collector) -> ServerConfig {
        let mode = self.mode.unwrap_or(TransportMode::BehindProxy);

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

        ServerConfig { bind, mode, tls }
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
        let id = tenant.id;
        if id.is_none() {
            errors.missing(format!("tenant[{index}].id"));
        }
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
            && let Some(first) = seen_ids.insert(id.clone(), index)
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

        if let (Some(id), Some(issuer)) = (id, issuer) {
            tenants.push(TenantConfig { id, issuer });
        }
    }
    tenants
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

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::Feature;

    const MINIMAL: &str = r#"
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
            ]
        );
        assert!(
            problems
                .as_slice()
                .iter()
                .all(|p| p.message == "required key is missing")
        );
    }

    #[test]
    fn the_error_message_lists_every_problem() {
        let rendered = problems(parse("[server]\nmode = \"terminate_tls\"\n")).to_string();
        assert!(
            rendered.starts_with("configuration has 3 problems:"),
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
            "[[tenant]]\nid = \"demo\"\n\n[database]\nurl = \"x\"\n",
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
                "[database]\nurl = \"x\"\n\n[[tenant]]\nid = \"demo\"\nissuer = \"{issuer}\"\n"
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

    #[test]
    fn the_issuer_is_normalised_once_and_stored_canonical() {
        let text = "[database]\nurl = \"x\"\n\n[[tenant]]\nid = \"demo\"\n\
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
        let text = "[database]\nurl = \"x\"\n\n\
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

    #[test]
    fn tenants_may_not_share_an_id() {
        let text = "[database]\nurl = \"x\"\n\n\
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
}
