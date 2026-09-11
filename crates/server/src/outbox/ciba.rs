//! Ping delivery: a `ciba.ping` outbox row becomes a CIBA Core 1.0 §10.2
//! notification.
//!
//! §10.2: "after a successful or failed end-user authentication", the OP posts
//! a JSON object holding the `auth_req_id` to the client's registered
//! `backchannel_client_notification_endpoint`, with the
//! `client_notification_token` from the request as a bearer in the
//! `Authorization` header. The client "SHOULD respond with an HTTP 204", any
//! 2xx is accepted, and the OP "MUST NOT follow redirects". The client then
//! fetches its result from the token endpoint — the ping carries no token,
//! which is what separates it from push delivery (§10.3), the mode this
//! server refuses.
//!
//! # What the row carries, and what it does not
//!
//! The decision that queued the row (`PgCibaRequestRepository::approve` and
//! `deny`) wrote the endpoint as the destination and the request's digest as
//! the payload. Neither credential is on the row: they are opened from the
//! sealed columns of `ciba_requests` at delivery time, through the same KEK
//! that sealed them, and exist in this process for the width of one `POST`.
//! A dump of the outbox is a list of digests and URLs.
//!
//! # Once, and only after a decision
//!
//! A row is queued by the decision and by nothing else — expiry queues
//! nothing, because §10.2 names the two outcomes it notifies and expiry is
//! not one. A row delivered but not acked (the worker crashed between the
//! two) is redelivered by the lease; `notified_at` on the request is what
//! makes the second delivery a no-op rather than a second ping.
//!
//! # Everything goes through `crate::outbound`
//!
//! ADR-0006: the destination is a URL the client registered, so it is
//! dereferenced only through [`crate::outbound::post`] — the SSRF guard, the
//! trust anchors, the five-second total timeout and the refusal to follow
//! redirects are that path's and are asserted where they live. This module
//! decides what to send and what a failure means, against a poster it can be
//! handed a fake of ([`SetPoster`]), because a loopback receiver is impossible
//! by construction and the decisions here are worth asserting without one.
//!
//! # Retry, or not
//!
//! [`PostError::is_permanent`] decides, as for every other family: a 4xx other
//! than 429 is the client saying the request is wrong, and nine more will be
//! just as wrong; everything else is retried on the worker's backoff. Either
//! way, the moment this server *gives up* — a permanent refusal, or the last
//! attempt failing — is written to the trail as a failed
//! `backchannel.notified`, because a client that says it was never called
//! back should be answered from the trail rather than from a dead-letter row
//! that retention will sweep.

use crate::outbound::{PostError, PostRequest};
use crate::outbox::{Delivered, Deliverer, SetPoster, Undelivered};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::outbox::OutboxEvent;
use asterius_domain::ports::Clock;
use asterius_domain::{ClientId, DomainError, TenantId};
use asterius_jose::Kek;
use asterius_oidc::ciba::{ping_authorization, ping_body};
use asterius_store_pg::{PingTarget, Store};
use std::sync::Arc;

/// The family this deliverer answers for.
pub const FAMILY: &str = "ciba";

/// §10.2's body is a JSON object.
pub const PING_CONTENT_TYPE: &str = "application/json";

/// The request state one delivery reads and writes.
///
/// A port for the reason `SsfPushDeliverer`'s is: what this module does with
/// a client's answer is a property of §10.2, and a test that needed Postgres
/// to assert it would be a test nobody writes.
#[async_trait::async_trait]
pub trait PingRequests: std::fmt::Debug + Send + Sync {
    /// What to present, and whether it was already presented.
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the store could not be reached or the seal did not
    /// open.
    async fn target(
        &self,
        tenant: &TenantId,
        auth_req_id_digest: &str,
    ) -> Result<Option<PingTarget>, DomainError>;

    /// Records that the client accepted the notification.
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the write failed.
    async fn mark_notified(
        &self,
        tenant: &TenantId,
        auth_req_id_digest: &str,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError>;
}

/// [`PingRequests`] over `PostgreSQL`.
#[derive(Clone)]
pub struct PgPingRequests {
    store: Store,
    kek: Arc<dyn Kek>,
}

impl std::fmt::Debug for PgPingRequests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PgPingRequests")
    }
}

impl PgPingRequests {
    /// Builds the adapter over the process's store and key-encryption key.
    #[must_use]
    pub const fn new(store: Store, kek: Arc<dyn Kek>) -> Self {
        Self { store, kek }
    }
}

#[async_trait::async_trait]
impl PingRequests for PgPingRequests {
    async fn target(
        &self,
        tenant: &TenantId,
        auth_req_id_digest: &str,
    ) -> Result<Option<PingTarget>, DomainError> {
        self.store
            .scope(tenant.clone())
            .ciba_requests(Arc::clone(&self.kek))
            .for_notification(auth_req_id_digest)
            .await
    }

    async fn mark_notified(
        &self,
        tenant: &TenantId,
        auth_req_id_digest: &str,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError> {
        self.store
            .scope(tenant.clone())
            .ciba_requests(Arc::clone(&self.kek))
            .mark_notified(auth_req_id_digest, now)
            .await
    }
}

/// Delivers `ciba.*` outbox rows by posting §10.2 notifications.
pub struct CibaPingDeliverer {
    requests: Arc<dyn PingRequests>,
    poster: Arc<dyn SetPoster>,
    audit: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for CibaPingDeliverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CibaPingDeliverer")
            .field("requests", &self.requests)
            .finish_non_exhaustive()
    }
}

impl CibaPingDeliverer {
    /// Assembles a deliverer.
    #[must_use]
    pub const fn new(
        requests: Arc<dyn PingRequests>,
        poster: Arc<dyn SetPoster>,
        audit: Arc<dyn AuditSink>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            requests,
            poster,
            audit,
            clock,
        }
    }

    /// Reads the request digest out of a row's payload.
    ///
    /// A row that names no request, or names one by something other than a
    /// SHA-256 digest, is a programming error at the queueing end and is
    /// permanent: it will look the same on the tenth attempt.
    fn digest_of(event: &OutboxEvent) -> Result<&str, Undelivered> {
        let digest = event
            .payload
            .get("request")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Undelivered::permanent("the row's payload names no request to notify".to_owned())
            })?;
        let is_digest = digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit());
        if !is_digest {
            return Err(Undelivered::permanent(
                "the row's payload does not name a request by its digest".to_owned(),
            ));
        }
        Ok(digest)
    }

    /// Writes one entry, and never fails the delivery over it.
    ///
    /// A notification that was accepted and could not be audited is still a
    /// notification that happened; posting it again to make the trail tidy
    /// would ping the client twice. The failure is logged instead.
    async fn record(&self, tenant: &TenantId, client: &str, outcome: Outcome, detail: Detail) {
        let event = AuditEvent::new(
            tenant.clone(),
            EventType::BACKCHANNEL_NOTIFIED,
            outcome,
            // The server posted this, not the client: nobody asked, which is
            // what a notification is.
            Actor::System,
            self.clock.now(),
        )
        .client(ClientId::new(client.to_owned()))
        .detail(detail);
        if let Err(error) = self.audit.record(event).await {
            tracing::error!(
                %error,
                tenant = %tenant,
                "a CIBA ping notification was not written to the audit trail"
            );
        }
    }

    /// What a failed `POST` means, and when the trail hears about it.
    async fn refused(
        &self,
        event: &OutboxEvent,
        target: &PingTarget,
        digest: &str,
        failure: &PostError,
    ) -> Undelivered {
        // `PostError`'s `Display` names a host and a reason and never the URL
        // or the credential, which is what makes it safe to store in
        // `outbox.last_error` and write to the trail.
        let detail = failure.to_string();
        let permanent = failure.is_permanent();
        tracing::debug!(
            tenant = %event.tenant,
            row = event.id,
            family = FAMILY,
            permanent,
            error = %detail,
            "a CIBA ping notification failed"
        );
        if permanent || event.is_final_attempt() {
            let mut recorded = Detail::new()
                .credential("auth_req_id", digest)
                .text("reason", &detail)
                .number("attempt", i64::from(event.attempt));
            if let Some(status) = failure.status() {
                recorded = recorded.number("status", i64::from(status));
            }
            self.record(&event.tenant, &target.client_id, Outcome::Failure, recorded)
                .await;
        }
        if permanent {
            Undelivered::permanent(detail)
        } else {
            Undelivered::transient(detail)
        }
    }
}

#[async_trait::async_trait]
impl Deliverer for CibaPingDeliverer {
    fn family(&self) -> &'static str {
        FAMILY
    }

    async fn deliver(&self, event: &OutboxEvent) -> Result<Delivered, Undelivered> {
        let digest = Self::digest_of(event)?;

        let target = match self.requests.target(&event.tenant, digest).await {
            Ok(Some(target)) => target,
            // Swept by retention, or not a ping request at all. Permanent:
            // the row is not coming back, and a client whose request has
            // expired is told so by the token endpoint (§11 `expired_token`),
            // not by a late notification.
            Ok(None) => {
                return Err(Undelivered::permanent(
                    "the backchannel request no longer exists, or is not a ping request".to_owned(),
                ));
            }
            // A store that cannot be read is this deployment's problem and not
            // the client's; the notification is still owed.
            Err(error) => return Err(Undelivered::transient(error.to_string())),
        };

        if target.notified_at.is_some() {
            // Delivered by an earlier attempt whose ack was lost. §10.2 is
            // one notification per decision; the client has been told.
            return Ok(Delivered::Sent);
        }

        let body = ping_body(&target.credentials.auth_req_id);
        let authorization = ping_authorization(&target.credentials.client_notification_token);
        let request = PostRequest::of(PING_CONTENT_TYPE).authorized_by(Some(&authorization));

        match self
            .poster
            .post(&event.destination, request, body.as_bytes())
            .await
        {
            Ok(status) => {
                if let Err(error) = self
                    .requests
                    .mark_notified(&event.tenant, digest, self.clock.now())
                    .await
                {
                    // The ping landed. If the stamp did not, a redelivery
                    // would ping again — logged so that a client reporting a
                    // duplicate has something to correlate against.
                    tracing::error!(
                        %error,
                        tenant = %event.tenant,
                        row = event.id,
                        "a CIBA ping was accepted but could not be recorded on the request"
                    );
                }
                self.record(
                    &event.tenant,
                    &target.client_id,
                    Outcome::Success,
                    Detail::new()
                        .credential("auth_req_id", digest)
                        .number("status", i64::from(status)),
                )
                .await;
                Ok(Delivered::Sent)
            }
            Err(failure) => Err(self.refused(event, &target, digest, &failure).await),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_store_pg::PingCredentials;
    use std::sync::Mutex;
    use time::OffsetDateTime;

    const ENDPOINT: &str = "https://rp.example/ciba-ping";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const AUTH_REQ_ID: &str = "1c266114-a1be-4252-8ad1-04986c5b9ac1";
    const TOKEN: &str = "8d67dc78-7faa-4d41-aabd-67707b374255";

    /// One request as the fake receiver saw it: URL, `Authorization`,
    /// media type, body.
    type Posted = (String, Option<String>, String, String);

    /// A poster that answers what the test says and keeps what it was sent.
    #[derive(Debug)]
    struct Scripted {
        answer: Result<u16, (u16, Vec<u8>)>,
        seen: Mutex<Vec<Posted>>,
    }

    #[async_trait::async_trait]
    impl SetPoster for Scripted {
        async fn post(
            &self,
            url: &str,
            request: PostRequest<'_>,
            body: &[u8],
        ) -> Result<u16, PostError> {
            self.seen.lock().expect("not poisoned").push((
                url.to_owned(),
                request.authorization.map(str::to_owned),
                request.content_type.to_owned(),
                String::from_utf8_lossy(body).into_owned(),
            ));
            self.answer
                .clone()
                .map_err(|(status, body)| PostError::Refused {
                    host: "rp.example".to_owned(),
                    status,
                    body,
                })
        }
    }

    /// Request state the test controls.
    #[derive(Debug)]
    struct Requests {
        target: Option<PingTarget>,
        marked: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl PingRequests for Requests {
        async fn target(
            &self,
            _tenant: &TenantId,
            _digest: &str,
        ) -> Result<Option<PingTarget>, DomainError> {
            Ok(self.target.clone())
        }

        async fn mark_notified(
            &self,
            _tenant: &TenantId,
            digest: &str,
            _now: OffsetDateTime,
        ) -> Result<bool, DomainError> {
            self.marked
                .lock()
                .expect("not poisoned")
                .push(digest.to_owned());
            Ok(true)
        }
    }

    #[derive(Debug, Default)]
    struct Trail(Mutex<Vec<AuditEvent>>);

    #[async_trait::async_trait]
    impl AuditSink for Trail {
        async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
            self.0.lock().expect("not poisoned").push(event);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Frozen;

    impl Clock for Frozen {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }

    fn pending_target() -> PingTarget {
        PingTarget {
            client_id: "teller".to_owned(),
            notified_at: None,
            credentials: PingCredentials {
                auth_req_id: AUTH_REQ_ID.to_owned(),
                client_notification_token: TOKEN.to_owned(),
            },
        }
    }

    fn event(attempt: u32, max_attempts: u32) -> OutboxEvent {
        OutboxEvent {
            tenant: TenantId::new("acme"),
            id: 11,
            kind: "ciba.ping".to_owned(),
            destination: ENDPOINT.to_owned(),
            payload: serde_json::json!({ "request": DIGEST }),
            attempt,
            max_attempts,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    struct Harness {
        deliverer: CibaPingDeliverer,
        poster: Arc<Scripted>,
        requests: Arc<Requests>,
        trail: Arc<Trail>,
    }

    fn harness(target: Option<PingTarget>, answer: Result<u16, (u16, Vec<u8>)>) -> Harness {
        let poster = Arc::new(Scripted {
            answer,
            seen: Mutex::new(Vec::new()),
        });
        let requests = Arc::new(Requests {
            target,
            marked: Mutex::new(Vec::new()),
        });
        let trail = Arc::new(Trail::default());
        let deliverer = CibaPingDeliverer::new(
            Arc::clone(&requests) as Arc<dyn PingRequests>,
            Arc::clone(&poster) as Arc<dyn SetPoster>,
            Arc::clone(&trail) as Arc<dyn AuditSink>,
            Arc::new(Frozen),
        );
        Harness {
            deliverer,
            poster,
            requests,
            trail,
        }
    }

    /// §10.2: a `POST` to the registered endpoint, JSON body holding the
    /// `auth_req_id` and nothing else, the `client_notification_token` as a
    /// bearer, a 2xx accepted — and then the request is marked so it is not
    /// pinged again, and the trail says it happened.
    #[tokio::test]
    async fn a_decision_is_posted_as_the_specification_says() {
        // Arrange
        let h = harness(Some(pending_target()), Ok(204));

        // Act
        let outcome = h.deliverer.deliver(&event(1, 10)).await;

        // Assert
        assert_eq!(outcome, Ok(Delivered::Sent));
        let seen = h.poster.seen.lock().expect("not poisoned");
        assert_eq!(seen.len(), 1);
        let (url, authorization, content_type, body) = &seen[0];
        assert_eq!(url, ENDPOINT);
        assert_eq!(
            authorization.as_deref(),
            Some("Bearer 8d67dc78-7faa-4d41-aabd-67707b374255")
        );
        assert_eq!(content_type, "application/json");
        let parsed: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(parsed, serde_json::json!({ "auth_req_id": AUTH_REQ_ID }));
        drop(seen);

        assert_eq!(
            *h.requests.marked.lock().expect("not poisoned"),
            vec![DIGEST.to_owned()]
        );
        let trail = h.trail.0.lock().expect("not poisoned");
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].event_type, EventType::BACKCHANNEL_NOTIFIED);
        assert_eq!(trail[0].outcome, Outcome::Success);
    }

    /// A row redelivered after a lost ack finds the request already
    /// notified, and does not ping the client a second time.
    #[tokio::test]
    async fn an_already_notified_request_is_not_pinged_again() {
        // Arrange
        let mut target = pending_target();
        target.notified_at = Some(OffsetDateTime::UNIX_EPOCH);
        let h = harness(Some(target), Ok(204));

        // Act
        let outcome = h.deliverer.deliver(&event(2, 10)).await;

        // Assert
        assert_eq!(outcome, Ok(Delivered::Sent));
        assert!(h.poster.seen.lock().expect("not poisoned").is_empty());
    }

    /// A 4xx is the client saying the request is wrong. It is not retried,
    /// and the moment of giving up is on the trail.
    #[tokio::test]
    async fn a_refusal_is_permanent_and_audited() {
        // Arrange
        let h = harness(Some(pending_target()), Err((401, b"nope".to_vec())));

        // Act
        let outcome = h.deliverer.deliver(&event(1, 10)).await;

        // Assert
        let refused = outcome.expect_err("a 401 is a refusal");
        assert!(refused.permanent);
        assert!(
            !refused.detail.contains("nope"),
            "the receiver's body leaked"
        );
        let trail = h.trail.0.lock().expect("not poisoned");
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].outcome, Outcome::Failure);
        assert!(h.requests.marked.lock().expect("not poisoned").is_empty());
    }

    /// A 5xx is a client having a bad minute: retried on the backoff, and
    /// nothing is written to the trail until the last attempt fails.
    #[tokio::test]
    async fn a_server_error_is_retried_and_audited_only_when_the_budget_is_spent() {
        // Arrange
        let early = harness(Some(pending_target()), Err((503, Vec::new())));
        let last = harness(Some(pending_target()), Err((503, Vec::new())));

        // Act
        let first = early.deliverer.deliver(&event(1, 10)).await;
        let final_attempt = last.deliverer.deliver(&event(10, 10)).await;

        // Assert
        assert!(!first.expect_err("a 503 fails").permanent);
        assert!(early.trail.0.lock().expect("not poisoned").is_empty());
        assert!(!final_attempt.expect_err("a 503 fails").permanent);
        let trail = last.trail.0.lock().expect("not poisoned");
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].outcome, Outcome::Failure);
    }

    /// A request that retention has swept cannot be notified by any number of
    /// retries, and an expired request is not pinged at all (§10.2 names the
    /// two outcomes it notifies; expiry is not one).
    #[tokio::test]
    async fn a_request_that_no_longer_exists_is_a_permanent_failure() {
        // Arrange
        let h = harness(None, Ok(204));

        // Act
        let outcome = h.deliverer.deliver(&event(1, 10)).await;

        // Assert
        assert!(outcome.expect_err("nothing to notify").permanent);
        assert!(h.poster.seen.lock().expect("not poisoned").is_empty());
    }

    /// A row whose payload does not name a request by digest is a queueing
    /// bug, permanent on the first attempt.
    #[tokio::test]
    async fn a_row_that_names_no_request_is_a_permanent_failure() {
        // Arrange
        let h = harness(Some(pending_target()), Ok(204));
        let mut row = event(1, 10);
        row.payload = serde_json::json!({ "request": "not-a-digest" });

        // Act
        let outcome = h.deliverer.deliver(&row).await;

        // Assert
        assert!(outcome.expect_err("not a digest").permanent);
        assert!(h.poster.seen.lock().expect("not poisoned").is_empty());
    }
}
