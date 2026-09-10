//! The generic HTTP deliverer: a `POST` to a URL a client registered.
//!
//! One deliverer, several families. Back-channel logout (OIDC Back-Channel
//! Logout 1.0 §2.5) posts a form to a `backchannel_logout_uri`; SSF push
//! (RFC 8935 §2.1) posts a JWT to a receiver's delivery endpoint; a CIBA ping
//! posts JSON to a `client_notification_endpoint`. The bodies differ and the
//! media types differ, but *reaching* the receiver is the same problem three
//! times, and it is the problem with the security content: a client-supplied
//! URL, an SSRF guard, a TLS configuration, a timeout, and the question of
//! which failures are worth retrying.
//!
//! So the shape of the payload is a field on the row rather than a deliverer
//! of its own. The row's `payload` carries `{"body": …, "content_type": …}`;
//! whoever queued it decided what to send, because that is the part that needs
//! to know the specification. This module decides only how it goes out.
//!
//! # Everything goes through `crate::outbound`
//!
//! ADR-0006: every dereference of a client-supplied URL goes through one path.
//! [`crate::outbound::post`] is that path with a body attached — it borrows
//! the SSRF guard, the resolution, the trust anchors and the connect from
//! [`crate::outbound::jwks`] rather than repeating them. A `POST` to an
//! attacker-chosen address is strictly worse than a `GET` to one, so this is
//! the caller that most needs the guard to be the same guard.
//!
//! # Retry, or not
//!
//! [`crate::outbound::PostError::is_permanent`] decides. A 4xx other than 429
//! means the receiver has read the request and called it wrong; repeating it
//! spends the attempt budget and dead-letters an hour later instead of now.
//! Everything else — a timeout, a 5xx, a connection refused, a 429 — is a
//! receiver having a bad minute, which is exactly what the backoff is for.

use crate::outbound::{HttpsPoster, PostError};
use crate::outbox::{Delivered, Deliverer, Undelivered};
use asterius_domain::outbox::OutboxEvent;

/// The media type used when a row does not name one.
///
/// `application/jwt` rather than `application/json`: the two families this
/// exists for today — back-channel logout's logout token and SSF push's
/// security event token — both send a JWT, and a deliverer that guessed JSON
/// would be wrong for both.
pub const DEFAULT_CONTENT_TYPE: &str = "application/jwt";

/// Posts an outbox row's body to its destination.
#[derive(Debug, Clone)]
pub struct HttpDeliverer {
    family: &'static str,
    poster: HttpsPoster,
}

impl HttpDeliverer {
    /// Builds a deliverer for one family over the process's outbound path.
    ///
    /// The family is a `&'static str` from this binary, never a string a row
    /// supplied: it is also a metric label. See
    /// [`crate::observability::metrics::OUTBOX_DELIVERIES`].
    #[must_use]
    pub const fn new(family: &'static str, poster: HttpsPoster) -> Self {
        Self { family, poster }
    }

    /// Reads the body and its media type out of a row's payload.
    ///
    /// A row whose payload is not the shape this deliverer expects is a
    /// programming error at the queueing end, and it is permanent: the row
    /// will look exactly the same on the tenth attempt.
    fn request(event: &OutboxEvent) -> Result<(&str, &str), Undelivered> {
        let body = event
            .payload
            .get("body")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Undelivered::permanent("the row's payload has no `body` string to post".to_owned())
            })?;
        let content_type = event
            .payload
            .get("content_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_CONTENT_TYPE);
        Ok((body, content_type))
    }
}

#[async_trait::async_trait]
impl Deliverer for HttpDeliverer {
    fn family(&self) -> &'static str {
        self.family
    }

    async fn deliver(&self, event: &OutboxEvent) -> Result<Delivered, Undelivered> {
        let (body, content_type) = Self::request(event)?;

        match self
            .poster
            .post(&event.destination, content_type, body.as_bytes())
            .await
        {
            Ok(_) => Ok(Delivered::Sent),
            Err(failure) => {
                let permanent = failure.is_permanent();
                // `PostError`'s `Display` names a host and a reason and never
                // the URL, which is what makes it safe to store in
                // `outbox.last_error` and render on an operator's screen. See
                // `crate::outbound::post`.
                let detail = failure.to_string();
                tracing::debug!(
                    tenant = %event.tenant,
                    row = event.id,
                    family = self.family,
                    permanent,
                    error = %detail,
                    "an outbox HTTP delivery failed"
                );
                Err(if permanent {
                    Undelivered::permanent(detail)
                } else {
                    Undelivered::transient(detail)
                })
            }
        }
    }
}

/// Whether `error` is one the deliverer would give up on.
///
/// Exposed so that a caller assembling deliverers can assert on the policy
/// without opening a socket.
#[must_use]
pub const fn gives_up_on(error: &PostError) -> bool {
    error.is_permanent()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::TenantId;
    use time::OffsetDateTime;

    fn poster() -> HttpsPoster {
        HttpsPoster::new().expect("build a poster")
    }

    fn event(payload: serde_json::Value, destination: &str) -> OutboxEvent {
        OutboxEvent {
            tenant: TenantId::new("acme"),
            id: 3,
            kind: "logout.backchannel".to_owned(),
            destination: destination.to_owned(),
            payload,
            attempt: 1,
            max_attempts: 10,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// The body is the row's to decide, because only the code that queued it
    /// knows which specification it is speaking. A row without one cannot be
    /// delivered by any number of retries.
    #[tokio::test]
    async fn a_row_with_no_body_is_a_permanent_failure() {
        // Arrange
        let deliverer = HttpDeliverer::new("logout", poster());
        let event = event(
            serde_json::json!({"nothing": "useful"}),
            "https://rp.example/x",
        );

        // Act
        let refused = deliverer
            .deliver(&event)
            .await
            .expect_err("a row with no body must not be posted");

        // Assert
        assert!(refused.permanent);
        assert!(refused.detail.contains("body"));
    }

    /// A JWT is what both families this exists for send, so a row that does
    /// not name a media type gets that one rather than `application/json`.
    #[test]
    fn a_row_without_a_media_type_posts_a_jwt() {
        // Arrange
        let event = event(
            serde_json::json!({"body": "e30.e30."}),
            "https://rp.example/x",
        );

        // Act
        let (body, content_type) = HttpDeliverer::request(&event).expect("a body is present");

        // Assert
        assert_eq!(body, "e30.e30.");
        assert_eq!(content_type, "application/jwt");
    }

    /// A row that names one gets it: back-channel logout posts a form, not a
    /// bare JWT (OIDC Back-Channel Logout 1.0 §2.5).
    #[test]
    fn a_row_may_choose_its_own_media_type() {
        // Arrange
        let event = event(
            serde_json::json!({
                "body": "logout_token=e30.e30.",
                "content_type": "application/x-www-form-urlencoded",
            }),
            "https://rp.example/x",
        );

        // Act
        let (_, content_type) = HttpDeliverer::request(&event).expect("a body is present");

        // Assert
        assert_eq!(content_type, "application/x-www-form-urlencoded");
    }

    /// The SSRF guard is not something this deliverer applies itself — it is
    /// the outbound path's — but a destination inside the deployment must be
    /// refused *through* this deliverer, or the guard is one wiring mistake
    /// away from being bypassed.
    #[tokio::test]
    async fn a_destination_inside_the_deployment_is_refused() {
        // Arrange
        let deliverer = HttpDeliverer::new("logout", poster());
        let event = event(
            serde_json::json!({"body": "e30.e30."}),
            "https://169.254.169.254/latest/meta-data/",
        );

        // Act
        let refused = deliverer
            .deliver(&event)
            .await
            .expect_err("link-local must be refused");

        // Assert
        assert!(
            refused.detail.contains("refusing to fetch"),
            "unexpected reason: {}",
            refused.detail
        );
    }
}
