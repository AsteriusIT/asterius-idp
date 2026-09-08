//! Liveness and readiness.
//!
//! The distinction matters operationally and is often blurred. `/healthz`
//! answers "is this process alive?" and must not touch the database — a
//! database outage that makes every replica fail liveness gets every replica
//! killed, turning an outage into a longer outage. `/readyz` answers "should
//! this process receive traffic?" and must touch the database, because a
//! process that cannot reach its store has nothing useful to say.

use asterius_store_pg::Store;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::sync::Arc;

/// Liveness state: whether the process is running.
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    /// Always `"ok"` — reaching the handler is the check.
    pub status: &'static str,
    /// The running version.
    pub version: &'static str,
}

impl Health {
    /// The current liveness state.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            status: "ok",
            version: crate::VERSION,
        }
    }
}

/// Readiness state.
#[derive(Debug, Clone, Serialize)]
pub struct Readiness {
    /// Whether this process should receive traffic.
    pub ready: bool,
    /// Whether the database answered.
    pub database: bool,
    /// Whether every migration in the binary has been applied.
    pub migrations_applied: bool,
    /// The optional capabilities this deployment offers, for an operator
    /// checking that a rollout carries the flags they expect.
    pub features: Vec<&'static str>,
}

impl IntoResponse for Readiness {
    fn into_response(self) -> Response {
        // 503 until everything the server depends on is actually there, so a
        // load balancer does not send traffic to a replica that will fail it.
        let status = if self.ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (status, Json(self)).into_response()
    }
}

/// What the readiness handler needs.
#[derive(Clone, Debug)]
pub struct HealthState {
    /// The store to ping.
    pub store: Store,
    /// The capabilities to report.
    pub features: Arc<Vec<&'static str>>,
}

/// `GET /healthz`.
pub async fn healthz() -> impl IntoResponse {
    Json(Health::current())
}

/// `GET /readyz`.
pub async fn readyz(axum::extract::State(state): axum::extract::State<HealthState>) -> Readiness {
    check(&state).await
}

/// Runs the readiness checks.
pub async fn check(state: &HealthState) -> Readiness {
    let database = state.store.ping().await;
    let migrations_applied = database && state.store.migrations_applied().await;

    Readiness {
        ready: database && migrations_applied,
        database,
        migrations_applied,
        features: state.features.as_ref().clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liveness_does_not_depend_on_anything_external() {
        let health = Health::current();
        assert_eq!(health.status, "ok");
        assert_eq!(health.version, crate::VERSION);
    }

    #[test]
    fn readiness_is_503_until_every_dependency_is_present() {
        let cases = [
            (false, false, StatusCode::SERVICE_UNAVAILABLE),
            (true, false, StatusCode::SERVICE_UNAVAILABLE),
            (false, true, StatusCode::SERVICE_UNAVAILABLE),
            (true, true, StatusCode::OK),
        ];
        for (database, migrations_applied, expected) in cases {
            let readiness = Readiness {
                ready: database && migrations_applied,
                database,
                migrations_applied,
                features: Vec::new(),
            };
            assert_eq!(
                readiness.into_response().status(),
                expected,
                "database={database} migrations={migrations_applied}"
            );
        }
    }
}
