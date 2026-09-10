//! Logs, metrics and health.
//!
//! RFC 9700 §4.2 and §4.3 are about credentials leaking through logs and
//! referrers. Logging is where that happens most, because a log line is written
//! by whoever is debugging at the time and read by everyone forever — so the
//! defence cannot be "remember not to log the token".
//!
//! [`redact`] is therefore a field formatter that rewrites values on their way
//! out, using the same scanner the audit trail uses
//! ([`asterius_domain::audit::redaction`]). A `tracing::info!(code = %code)`
//! written in a hurry produces a redacted line, not an incident.

pub mod health;
pub mod metrics;
pub mod redact;

pub use health::{Health, Readiness};
pub use metrics::Metrics;

use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, fmt};

/// How logs are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// Human-readable, for a terminal.
    #[default]
    Text,
    /// One JSON object per line, for a log pipeline.
    Json,
}

/// The default filter when `RUST_LOG` says nothing.
///
/// `asterius` is a prefix, not an exact target: an `EnvFilter` directive
/// matches any target starting with it, so a single entry covers the binary
/// (`asterius`) and every workspace crate (`asterius_web`, `asterius_oidc`,
/// …), including the ones written after this line. Enumerating them by hand
/// is what mutes a new crate the day it is added, so the enumeration lives in
/// the test instead, where it is read back from the workspace manifests.
const DEFAULT_FILTER: &str = "asterius=info,tower_http=warn,sqlx=warn";

/// Installs the subscriber.
pub fn init(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| DEFAULT_FILTER.into());
    let registry = tracing_subscriber::registry().with(filter);

    // `fmt_fields` is where redaction lives: every field of every event and
    // span is rendered through it, so there is no ordering in which a raw
    // credential reaches an appender.
    match format {
        LogFormat::Text => {
            registry
                .with(fmt::layer().fmt_fields(redact::RedactingFields))
                .init();
        }
        LogFormat::Json => {
            registry
                .with(
                    fmt::layer()
                        .with_ansi(false)
                        .fmt_fields(redact::RedactingFields),
                )
                .init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::str::FromStr as _;
    use tracing::Level;
    use tracing_subscriber::filter::Targets;

    /// The tracing target of a crate is its package name with `-` turned into
    /// `_`; a `[[bin]]` target carries its own name instead.
    ///
    /// Read from the manifests rather than listed here on purpose: the point
    /// of the test is to notice crates that did not exist when it was written.
    fn workspace_log_targets() -> Vec<String> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crates/server sits two levels below the workspace root")
            .to_path_buf();
        let manifest: toml::Value = toml::from_str(
            &std::fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest"),
        )
        .expect("workspace manifest parses");
        let members = manifest["workspace"]["members"]
            .as_array()
            .expect("workspace.members is an array");

        let mut targets = Vec::new();
        for member in members {
            let dir = root.join(member.as_str().expect("member path is a string"));
            let member_manifest: toml::Value = toml::from_str(
                &std::fs::read_to_string(dir.join("Cargo.toml")).expect("member manifest"),
            )
            .expect("member manifest parses");
            targets.push(
                member_manifest["package"]["name"]
                    .as_str()
                    .expect("package name is a string")
                    .replace('-', "_"),
            );
            if let Some(bins) = member_manifest.get("bin").and_then(toml::Value::as_array) {
                for bin in bins {
                    targets.push(
                        bin["name"]
                            .as_str()
                            .expect("bin name is a string")
                            .replace('-', "_"),
                    );
                }
            }
        }
        targets
    }

    /// Collects the target of every event the filter let through.
    #[derive(Clone, Default)]
    struct Recorder(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Recorder {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.0
                .lock()
                .expect("the recorder mutex is only taken by this test")
                .push(event.metadata().target().to_owned());
        }
    }

    #[test]
    fn the_default_filter_lets_web_and_admin_api_events_through() {
        // Arrange: the shipped filter, in front of the same registry `init`
        // builds.
        let recorder = Recorder::default();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new(DEFAULT_FILTER))
            .with(recorder.clone());

        // Act: the crates the operator needs to see when a login fails.
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "asterius_web", "login page rendered");
            tracing::info!(target: "asterius_admin_api", "tenant listed");
        });

        // Assert
        let seen = recorder
            .0
            .lock()
            .expect("the recorder mutex is only taken by this test")
            .clone();
        assert_eq!(seen, ["asterius_web", "asterius_admin_api"]);
    }

    #[test]
    fn the_default_filter_selects_every_workspace_crate_at_info() {
        // Arrange: the filter as it ships, against the crates the workspace
        // actually declares today.
        let targets = Targets::from_str(DEFAULT_FILTER).expect("DEFAULT_FILTER parses");
        let workspace = workspace_log_targets();
        assert!(
            workspace.len() >= 8,
            "workspace members were not discovered: {workspace:?}"
        );

        // Act & Assert: a crate born after the filter was written must not be
        // muted by default.
        for target in workspace {
            assert!(
                targets.would_enable(&target, &Level::INFO),
                "`{target}` emits INFO logs that DEFAULT_FILTER discards"
            );
        }
    }
}
