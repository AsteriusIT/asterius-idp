//! A correlation id for every request.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// The header this id travels in, on the way out.
pub const HEADER: HeaderName = HeaderName::from_static("x-request-id");
/// Always server generated, including when AuthZEN echoes the PEP's header.
pub const SUPPORT_HEADER: HeaderName = HeaderName::from_static("x-asterius-request-id");

tokio::task_local! {
    static AUDIT_REQUEST: RequestId;
}

/// Adds the current HTTP reference to ordinary and transactional audit writes.
/// Tokio scopes it to the request future: concurrent requests, spawned jobs and
/// cancellation cannot inherit another caller's reference.
#[derive(Debug)]
pub struct RequestAuditSink {
    inner: std::sync::Arc<dyn asterius_domain::AuditSink>,
}

impl RequestAuditSink {
    #[must_use]
    pub const fn new(inner: std::sync::Arc<dyn asterius_domain::AuditSink>) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl asterius_domain::AuditSink for RequestAuditSink {
    fn prepare(&self, mut event: asterius_domain::AuditEvent) -> asterius_domain::AuditEvent {
        if let Ok(id) = AUDIT_REQUEST.try_with(|id| id.as_str().to_owned()) {
            event.request_id = Some(id);
        }
        self.inner.prepare(event)
    }

    async fn record(
        &self,
        event: asterius_domain::AuditEvent,
    ) -> Result<(), asterius_domain::DomainError> {
        self.inner.record(self.prepare(event)).await
    }

    async fn record_with_diagnostics(
        &self,
        event: asterius_domain::AuditEvent,
        diagnostics: &asterius_domain::policy::explanation::DecisionExplanation,
    ) -> Result<(), asterius_domain::DomainError> {
        self.inner
            .record_with_diagnostics(self.prepare(event), diagnostics)
            .await
    }
}

/// The HTTP composition's sink. Background/CLI writes retain their own metadata.
#[must_use]
pub fn audit(
    inner: impl asterius_domain::AuditSink + 'static,
) -> std::sync::Arc<dyn asterius_domain::AuditSink> {
    std::sync::Arc::new(RequestAuditSink::new(std::sync::Arc::new(inner)))
}

/// A 128-bit request identifier, rendered as lower-case hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    /// Draws a new identifier from the operating system CSPRNG.
    ///
    /// A counter would be cheaper, but a predictable request id leaks the
    /// server's request rate to anyone who can see two of them, and these end
    /// up in audit records that get shared during incidents.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
        let mut hex = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Self(hex)
    }

    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Attaches a fresh [`RequestId`] to the request and echoes it on the response.
///
/// A client-supplied `X-Request-Id` is deliberately ignored rather than
/// honoured *for the trail*: these ids end up in the audit records, and letting
/// a caller choose its own would let it collide with, or impersonate, another
/// caller's entries. The [`RequestId`] in the extensions — the one every
/// handler records — is therefore always this server's.
///
/// The **response header** is a different question, and one handler answers it
/// differently. AuthZEN's Authorization API 1.0 §10.1.3 requires a PDP to
/// return the `X-Request-ID` the enforcement point sent, so
/// [`crate::http::access_evaluation`] sets that header itself, from a value it
/// has bounded and validated. This layer therefore fills the header in only
/// when the response does not already carry one: a handler that has answered a
/// specification's MUST must not have its answer overwritten by the wiring.
/// Every other response is unchanged.
pub async fn layer(mut request: Request, next: Next) -> Response {
    let id = RequestId::generate();
    let header = HeaderValue::from_str(id.as_str()).expect("hex is a valid header value");
    request.extensions_mut().insert(id.clone());
    let mut response = AUDIT_REQUEST.scope(id, next.run(request)).await;
    response
        .headers_mut()
        .insert(SUPPORT_HEADER, header.clone());
    if !response.headers().contains_key(HEADER) {
        response.headers_mut().insert(HEADER, header);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[derive(Debug)]
    struct UnusedSink;
    #[async_trait::async_trait]
    impl asterius_domain::AuditSink for UnusedSink {
        async fn record(
            &self,
            _event: asterius_domain::AuditEvent,
        ) -> Result<(), asterius_domain::DomainError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn trusted_scope_overwrites_event_metadata_before_atomic_writes() {
        let sink = RequestAuditSink::new(std::sync::Arc::new(UnusedSink));
        let mut event = asterius_domain::AuditEvent::new(
            asterius_domain::TenantId::new("tenant"),
            asterius_domain::audit::EventType::AUTH_LOGIN,
            asterius_domain::audit::Outcome::Success,
            asterius_domain::audit::Actor::System,
            time::OffsetDateTime::UNIX_EPOCH,
        );
        event.request_id = Some("untrusted-existing-reference".to_owned());
        let expected = RequestId::generate();
        let prepared = AUDIT_REQUEST
            .scope(expected.clone(), async {
                asterius_domain::AuditSink::prepare(&sink, event.clone())
            })
            .await;
        assert_eq!(prepared.request_id.as_deref(), Some(expected.as_str()));
        assert_eq!(
            asterius_domain::AuditSink::prepare(&sink, event)
                .request_id
                .as_deref(),
            Some("untrusted-existing-reference")
        );
    }

    #[tokio::test]
    async fn audit_scope_isolated_across_requests_and_spawned_tasks() {
        let first = RequestId::generate();
        let second = RequestId::generate();
        let a = AUDIT_REQUEST.scope(first.clone(), async {
            tokio::task::yield_now().await;
            assert!(
                tokio::spawn(async { AUDIT_REQUEST.try_with(Clone::clone).is_err() })
                    .await
                    .expect("spawn")
            );
            AUDIT_REQUEST.with(Clone::clone)
        });
        let b = AUDIT_REQUEST.scope(second.clone(), async {
            tokio::task::yield_now().await;
            AUDIT_REQUEST.with(Clone::clone)
        });
        let (observed_a, observed_b) = tokio::join!(a, b);
        assert_eq!(observed_a, first);
        assert_eq!(observed_b, second);
        assert!(AUDIT_REQUEST.try_with(Clone::clone).is_err());
    }

    #[tokio::test]
    async fn support_reference_cannot_be_spoofed_by_an_authzen_echo() {
        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::get(async || {
                    (
                        [
                            (HEADER, "caller-chosen"),
                            (SUPPORT_HEADER, "also-caller-chosen"),
                        ],
                        "body",
                    )
                }),
            )
            .layer(axum::middleware::from_fn(layer));
        let response = call(app).await;
        assert_eq!(response.headers()[HEADER], "caller-chosen");
        let support = response.headers()[SUPPORT_HEADER].to_str().expect("header");
        assert_eq!(support.len(), 32);
        assert_ne!(support, "also-caller-chosen");
    }

    /// The ordinary case: a handler that says nothing gets this server's own
    /// identifier on the response.
    #[tokio::test]
    async fn a_response_with_no_identifier_is_given_one() {
        // Arrange
        let app = axum::Router::new()
            .route("/", axum::routing::get(async || "body"))
            .layer(axum::middleware::from_fn(layer));

        // Act
        let response = call(app).await;

        // Assert
        let id = response
            .headers()
            .get(HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("a generated request id");
        assert_eq!(id.len(), 32, "{id}");
    }

    /// `ast-pj0.1`: the AuthZEN endpoint answers §10.1.3 by echoing the PEP's
    /// identifier, and this layer must not overwrite the answer.
    #[tokio::test]
    async fn an_identifier_a_handler_set_is_left_alone() {
        // Arrange
        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::get(async || {
                    (
                        [(HEADER, HeaderValue::from_static("from-the-caller"))],
                        "body",
                    )
                }),
            )
            .layer(axum::middleware::from_fn(layer));

        // Act
        let response = call(app).await;

        // Assert
        assert_eq!(
            response
                .headers()
                .get(HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("from-the-caller")
        );
    }

    /// One `GET /` through a router, which is what both tests above need.
    async fn call(app: axum::Router) -> Response {
        use tower::ServiceExt as _;
        app.oneshot(
            Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .expect("a request"),
        )
        .await
        .expect("a response")
    }

    #[test]
    fn ids_are_128_bits_of_hex_and_do_not_repeat() {
        let ids: HashSet<String> = (0..1000)
            .map(|_| RequestId::generate().as_str().to_owned())
            .collect();
        assert_eq!(ids.len(), 1000, "generated a duplicate request id");
        for id in &ids {
            assert_eq!(id.len(), 32);
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
            );
        }
    }
}
