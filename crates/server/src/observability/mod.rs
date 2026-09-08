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
/// The binary's own target is `asterius`; the library is `asterius_server`.
/// Both, or the startup lines never appear.
const DEFAULT_FILTER: &str = "asterius=info,asterius_server=info,asterius_store_pg=info,\
                              tower_http=warn,sqlx=warn";

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
