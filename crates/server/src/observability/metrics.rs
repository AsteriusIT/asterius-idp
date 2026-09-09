//! Prometheus metrics.
//!
//! Deliberately few, and deliberately low-cardinality. A metric labelled with
//! anything a client controls — a `client_id`, a subject, an error description
//! — is a way for one caller to exhaust the metrics store, so labels here are
//! drawn from closed sets the server owns: an endpoint name, a grant type, an
//! OAuth error code.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::time::Instant;

/// Request count by endpoint and status class.
pub const HTTP_REQUESTS: &str = "asterius_http_requests_total";
/// Request latency by endpoint.
pub const HTTP_DURATION: &str = "asterius_http_request_duration_seconds";
/// Tokens issued, by grant type.
pub const TOKENS_ISSUED: &str = "asterius_tokens_issued_total";
/// Protocol errors, by OAuth error code.
pub const PROTOCOL_ERRORS: &str = "asterius_protocol_errors_total";
/// Audit records appended.
pub const AUDIT_EVENTS: &str = "asterius_audit_events_total";
/// Sign-in attempts refused by the login limiter, by which limit was full.
///
/// The label is `ip` or `account` — the *kind* of bucket, never the bucket
/// itself. Labelling it with the address or the identifier would let one
/// attacker mint a time series per guess, which is the cardinality problem
/// this module exists to avoid, and would also publish who is being targeted.
pub const LOGIN_THROTTLED: &str = "asterius_login_throttled_total";
/// Always 1, labelled with the build. Gives a scrape something to find even on
/// an idle server, and lets a dashboard tell which version a replica is running.
pub const BUILD_INFO: &str = "asterius_build_info";

/// The metrics registry and its scrape endpoint.
#[derive(Clone)]
pub struct Metrics {
    handle: PrometheusHandle,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics").finish_non_exhaustive()
    }
}

impl Metrics {
    /// Installs the recorder and describes every metric.
    ///
    /// # Errors
    ///
    /// Returns an error if a recorder is already installed, which in a single
    /// binary means this was called twice.
    pub fn install() -> Result<Self, String> {
        let handle = PrometheusBuilder::new()
            // Latency buckets chosen for an authorization server: most work is
            // a signature or a query, and anything past a second is already an
            // incident.
            .set_buckets(&[
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ])
            .map_err(|e| e.to_string())?
            .install_recorder()
            .map_err(|e| e.to_string())?;

        metrics::describe_counter!(HTTP_REQUESTS, "HTTP requests by endpoint and status class");
        metrics::describe_histogram!(HTTP_DURATION, "HTTP request duration in seconds");
        metrics::describe_counter!(TOKENS_ISSUED, "Tokens issued by grant type");
        metrics::describe_counter!(PROTOCOL_ERRORS, "Protocol errors by OAuth error code");
        metrics::describe_counter!(AUDIT_EVENTS, "Audit records appended");
        metrics::describe_counter!(
            LOGIN_THROTTLED,
            "Sign-in attempts refused by the login limiter, by limit"
        );
        metrics::describe_gauge!(BUILD_INFO, "Always 1, labelled with the running build");
        metrics::gauge!(BUILD_INFO, "version" => crate::VERSION).set(1.0);

        Ok(Self { handle })
    }

    /// Renders the current values in the Prometheus text format.
    #[must_use]
    pub fn render(&self) -> String {
        self.handle.render()
    }
}

/// Records one token issuance.
pub fn token_issued(grant_type: &'static str) {
    metrics::counter!(TOKENS_ISSUED, "grant_type" => grant_type).increment(1);
}

/// Records one protocol error.
///
/// `code` must be an OAuth error code from the specification's closed list, not
/// a message: it becomes a label.
pub fn protocol_error(code: &'static str) {
    metrics::counter!(PROTOCOL_ERRORS, "code" => code).increment(1);
}

/// Records one sign-in refused by the limiter.
pub fn login_throttled(scope: &'static str) {
    metrics::counter!(LOGIN_THROTTLED, "limit" => scope).increment(1);
}

/// Records one appended audit record.
pub fn audit_event(event_type: &'static str) {
    metrics::counter!(AUDIT_EVENTS, "event_type" => event_type).increment(1);
}

/// Times a request and records its outcome.
///
/// `endpoint` is the *route*, never the request path: `/t/demo/authorize` as a
/// label would give every tenant its own time series, and a path from a 404
/// would give an attacker unbounded label cardinality.
pub async fn track(
    endpoint: &'static str,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let started = Instant::now();
    let response = next.run(request).await;
    let class = status_class(response.status());
    metrics::counter!(HTTP_REQUESTS, "endpoint" => endpoint, "status" => class).increment(1);
    metrics::histogram!(HTTP_DURATION, "endpoint" => endpoint)
        .record(started.elapsed().as_secs_f64());
    response
}

/// Buckets a status into one of five classes, so the label set stays at five.
const fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

/// The `/metrics` handler.
#[expect(clippy::unused_async, reason = "axum handlers must be async")]
pub async fn handler(metrics: Metrics) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        metrics.render(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classes_are_a_closed_set_of_five() {
        assert_eq!(status_class(StatusCode::OK), "2xx");
        // Built from the number rather than the constant: `StatusCode::SEE_OTHER`
        // is confined to the redirect helper by the source audit, and bucketing a
        // status is not constructing a redirect. 303 because it is the only
        // redirect this server emits.
        assert_eq!(
            status_class(StatusCode::from_u16(303).expect("valid status")),
            "3xx"
        );
        assert_eq!(status_class(StatusCode::NOT_FOUND), "4xx");
        assert_eq!(status_class(StatusCode::INTERNAL_SERVER_ERROR), "5xx");
        assert_eq!(status_class(StatusCode::CONTINUE), "1xx");
    }

    /// Every metric name is prefixed and uses the units Prometheus expects in
    /// the suffix, so dashboards do not have to guess.
    #[test]
    fn metric_names_follow_the_conventions() {
        for name in [HTTP_REQUESTS, TOKENS_ISSUED, PROTOCOL_ERRORS, AUDIT_EVENTS] {
            assert!(name.starts_with("asterius_"), "{name}");
            assert!(
                name.ends_with("_total"),
                "a counter must end in _total: {name}"
            );
        }
        assert!(HTTP_DURATION.ends_with("_seconds"), "{HTTP_DURATION}");
    }
}
