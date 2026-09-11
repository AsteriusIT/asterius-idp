//! The per-endpoint limiter (`ast-p2l.3`).
//!
//! The counting rules, the bucket keys and the store are the ones the login
//! limiter already uses — [`asterius_domain::rate_limit`], the `rate_limits`
//! table, one fixed window per bucket incremented by one statement. Nothing
//! here is a second mechanism; what is here is the orchestration for endpoints
//! that count *requests* rather than failures, and the decision of what a
//! request is charged to.
//!
//! # Requests, not failures
//!
//! The login limiter counts refusals, because a person who signs in
//! successfully has cost nothing and guessing is the thing to bound. These
//! endpoints are the other way round: `/par` writes a row per request,
//! `/token` runs a signature per request, `/register` creates a client per
//! request. The cost is in the *work*, so the work is what is counted, whether
//! or not it succeeded.
//!
//! # What a request is charged to
//!
//! A **successful** request from a client that authenticated is charged to
//! that client. Everything else is charged to the address it came from.
//!
//! That rule is the answer to the obvious failure of a limiter keyed by
//! address alone: an enterprise NAT or a mobile carrier is one address for
//! thousands of legitimate callers, and a resource server calling UserInfo in
//! a loop is one address making a great deal of entirely correct traffic. It
//! is also the answer to the mirror failure of a limiter keyed by the
//! `client_id` a request *claims*: that one lets anybody exhaust a competitor's
//! budget by putting their `client_id` in a body full of nonsense. A request
//! only reaches the client bucket by succeeding, and a request only succeeds by
//! authenticating, so an attacker can fill nothing but the bucket for their own
//! address.
//!
//! The check before the handler consults both buckets, since which one will be
//! charged is not known until the answer is. Consulting the claimed client's
//! bucket is safe for the same reason: nobody but that client can have filled
//! it.
//!
//! # Why there is no per-tenant bucket
//!
//! A counter shared by every caller of a tenant is a denial of service anybody
//! can aim at everybody: one attacker fills it and every legitimate client is
//! refused. It is the mistake the login limiter avoids by keying its account
//! bucket per identifier rather than per deployment, and it is avoided here
//! for the same reason. Bounding *distributed* abuse — a botnet, one request
//! per address — is not something a counter of this shape can do, and
//! pretending otherwise with a tenant-wide ceiling would trade a real outage
//! for an imaginary defence.
//!
//! # Nothing here is an oracle
//!
//! The limiter never asks whether a client, a user or a registration exists:
//! it hashes what the request claimed and counts. An unregistered `client_id`
//! reaches a full bucket in exactly as many requests as a registered one, and
//! the refusal is byte-for-byte the same. That is the property `ast-2vk.9`
//! established at the login and the one this must not undo.

use crate::http::throttle::Refused;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::rate_limit::{
    Bucket, EndpointLimits, LimitedEndpoint, RateLimit, RateLimitStore, Scope,
};
use asterius_domain::{DomainError, TenantId, audited_once_bucket, endpoint_address_bucket};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::net::IpAddr;
use time::OffsetDateTime;

/// A bucket that has no room left, and the limit that says so.
#[derive(Debug, Clone)]
struct Full {
    /// Which limit was reached, for the metric and the trail.
    scope: Scope,
    /// The counter that was full, so the trail can be written once per window
    /// rather than once per request.
    bucket: Bucket,
    /// The limit it was full against, which is where `Retry-After` comes from.
    limit: RateLimit,
}

/// The limiter, bound to one deployment's limits and one client address.
///
/// Copied per request rather than held on the router state, because the
/// address is part of it. The store behind it is a handle to the shared pool.
#[derive(Debug, Clone, Copy)]
pub struct EndpointThrottle<'a> {
    store: &'a dyn RateLimitStore,
    limits: EndpointLimits,
    address: Option<IpAddr>,
}

impl<'a> EndpointThrottle<'a> {
    /// Builds a limiter over a store, for a request from `address`.
    #[must_use]
    pub const fn new(
        store: &'a dyn RateLimitStore,
        limits: EndpointLimits,
        address: Option<IpAddr>,
    ) -> Self {
        Self {
            store,
            limits,
            address,
        }
    }

    /// The two buckets this request could be charged to, with their limits.
    ///
    /// The client bucket is absent when the endpoint has no client limit or
    /// the request named no client — UserInfo presents an access token rather
    /// than a `client_id`, and reading one out of a token before verifying it
    /// would be trusting a string an attacker wrote.
    fn buckets(&self, endpoint: LimitedEndpoint, client_id: Option<&str>) -> Vec<Full> {
        let limit = self.limits.for_endpoint(endpoint);
        let mut buckets = Vec::with_capacity(2);
        if let Some(address) = self.address {
            buckets.push(Full {
                scope: Scope::Address,
                bucket: endpoint_address_bucket(endpoint, address),
                limit: limit.per_address,
            });
        }
        if let (Some(client_id), Some(per_client)) = (client_id, limit.per_client) {
            buckets.push(Full {
                scope: Scope::Client,
                bucket: asterius_domain::endpoint_client_bucket(endpoint, client_id),
                limit: per_client,
            });
        }
        buckets
    }

    /// Whether this request may reach the handler.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if a counter cannot be read. The caller must
    /// not read that as permission: a limiter that fails open is one an
    /// attacker switches off by loading the database.
    async fn check(
        &self,
        tenant: &TenantId,
        endpoint: LimitedEndpoint,
        client_id: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Option<Full>, DomainError> {
        for full in self.buckets(endpoint, client_id) {
            let counted = self
                .store
                .count(tenant, &full.bucket, full.limit.window_start(now))
                .await?;
            if !full.limit.admits(counted) {
                return Ok(Some(full));
            }
        }
        Ok(None)
    }

    /// Counts one answered request against exactly one bucket.
    ///
    /// The client bucket when the request succeeded and named a client the
    /// endpoint has a limit for, the address bucket otherwise. Exactly one,
    /// never both: charging a successful call to both would mean a client's
    /// own correct traffic still exhausts the address budget of everyone
    /// behind the same NAT, which is the problem the client bucket exists to
    /// solve.
    ///
    /// A write that fails is logged and swallowed. The request has already
    /// been answered, and turning a limiter outage into a failed *response*
    /// would be the wrong way round; it is visible in the logs and in the
    /// absence of the metric.
    async fn charge(
        &self,
        tenant: &TenantId,
        endpoint: LimitedEndpoint,
        client_id: Option<&str>,
        succeeded: bool,
        now: OffsetDateTime,
    ) {
        let buckets = self.buckets(endpoint, client_id);
        let charged = if succeeded {
            buckets
                .iter()
                .find(|full| full.scope == Scope::Client)
                .or_else(|| buckets.first())
        } else {
            buckets.iter().find(|full| full.scope == Scope::Address)
        };
        let Some(full) = charged else {
            return;
        };
        if let Err(error) = self
            .store
            .record(
                tenant,
                &full.bucket,
                full.limit.window_start(now),
                full.limit.window_end(now),
            )
            .await
        {
            tracing::error!(%error, tenant = %tenant, %endpoint, "a request was not counted");
        }
    }

    /// Whether this refusal is the first one for this bucket in this window.
    ///
    /// A marker counter beside the one that was full: the refusals themselves
    /// are not counted, so the full counter cannot answer the question, and
    /// writing one trail record per refused request would let an attacker fill
    /// the trail with the flood it is reporting. A marker that cannot be
    /// written is reported as "not the first", which loses a record rather
    /// than risking a flood.
    async fn first_refusal_in_window(
        &self,
        tenant: &TenantId,
        full: &Full,
        now: OffsetDateTime,
    ) -> bool {
        let marker = audited_once_bucket(&full.bucket);
        match self
            .store
            .record(
                tenant,
                &marker,
                full.limit.window_start(now),
                full.limit.window_end(now),
            )
            .await
        {
            Ok(count) => count == 1,
            Err(error) => {
                tracing::error!(%error, tenant = %tenant, "a throttle marker was not written");
                false
            }
        }
    }
}

/// What [`guard`] needs besides the request itself.
#[derive(Debug, Clone, Copy)]
pub struct LimitContext<'a> {
    /// Whose counters these are. Buckets are already scoped per tenant by the
    /// store, so one tenant's traffic cannot spend another's budget.
    pub tenant: &'a TenantId,
    /// The limiter, carrying this request's address.
    pub throttle: EndpointThrottle<'a>,
    /// Where the once-per-window record goes.
    pub audit: &'a dyn AuditSink,
    /// One clock reading for the whole decision.
    pub now: OffsetDateTime,
}

/// Runs `handler` behind this endpoint's limits.
///
/// The limiter is applied here, in the wiring, rather than inside each
/// handler: a handler that has to remember to call a limiter is a handler that
/// will be written one day without calling it, and the endpoints this covers
/// are precisely the ones where nobody notices until an incident.
///
/// `client_id` is what the request *claimed*, not what it proved — see the
/// module documentation for why that is safe and why the claim alone can never
/// spend the claimed client's budget.
pub async fn guard<F>(
    context: &LimitContext<'_>,
    endpoint: LimitedEndpoint,
    client_id: Option<&str>,
    handler: F,
) -> Response
where
    F: AsyncFnOnce() -> Response,
{
    match context
        .throttle
        .check(context.tenant, endpoint, client_id, context.now)
        .await
    {
        Ok(None) => {}
        Ok(Some(full)) => {
            let refused = Refused {
                scope: full.scope,
                retry_after: full.limit.retry_after(context.now),
            };
            crate::observability::metrics::endpoint_throttled(
                endpoint.as_str(),
                full.scope.as_str(),
            );
            if context
                .throttle
                .first_refusal_in_window(context.tenant, &full, context.now)
                .await
            {
                record_throttled(context, endpoint, refused).await;
            }
            return too_many_requests(refused);
        }
        Err(error) => {
            // Fail closed. Every endpoint behind this limiter needs the same
            // database the counters live in, so a read that failed here would
            // have failed a line later anyway; answering 503 says so plainly
            // instead of letting an unlimited request through on the way to
            // its own failure.
            tracing::error!(%error, tenant = %context.tenant, %endpoint, "a rate limit could not be read");
            return unavailable();
        }
    }

    let response = handler().await;
    context
        .throttle
        .charge(
            context.tenant,
            endpoint,
            client_id,
            response.status().is_success(),
            context.now,
        )
        .await;
    response
}

/// The refusal, in the shape the login limiter already answers with.
///
/// 429 with `Retry-After` in seconds and the same JSON body the throttled
/// passkey endpoints send, rather than a second spelling of the same thing:
/// a client that learned to back off at one endpoint backs off at all of them.
/// `no-store`, because a cached 429 would keep refusing a client after the
/// window rolled over.
fn too_many_requests(refused: Refused) -> Response {
    let seconds = refused.retry_after_seconds();
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        [(header::RETRY_AFTER, seconds.to_string())],
        axum::Json(json!({
            "error": "too_many_attempts",
            "retry_after": seconds,
        })),
    )
        .into_response()
}

/// The answer when the counters cannot be read.
fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(json!({
            "error": "temporarily_unavailable",
            "error_description": "try again shortly",
        })),
    )
        .into_response()
}

/// The trail record for a refused request.
///
/// Names the endpoint and which limit was full, and nothing else. Not the
/// address, not the `client_id`: the request was unauthenticated as far as
/// this code knows, so both are strings an attacker chose, and a trail of them
/// is a place to write attacker-controlled text into an operator's console.
/// The actor is [`Actor::System`] for the same reason the login limiter's is —
/// nobody has been identified.
#[must_use]
pub fn throttled_event(
    tenant: &TenantId,
    endpoint: LimitedEndpoint,
    refused: Refused,
    now: OffsetDateTime,
) -> AuditEvent {
    AuditEvent::new(
        tenant.clone(),
        EventType::REQUEST_THROTTLED,
        Outcome::Failure,
        Actor::System,
        now,
    )
    .detail(
        Detail::new()
            .label("endpoint", endpoint.as_str())
            .label("limit", refused.scope.as_str())
            .number(
                "retry_after_seconds",
                i64::try_from(refused.retry_after_seconds()).unwrap_or(i64::MAX),
            ),
    )
}

/// Appends that record. A failure to write is logged and does not propagate:
/// the request is refused either way, and an audit outage must not become a
/// 500 that an attacker can provoke on purpose.
async fn record_throttled(context: &LimitContext<'_>, endpoint: LimitedEndpoint, refused: Refused) {
    if let Err(failure) = context
        .audit
        .record(throttled_event(
            context.tenant,
            endpoint,
            refused,
            context.now,
        ))
        .await
    {
        tracing::error!(
            %failure,
            tenant = %context.tenant,
            %endpoint,
            "a throttled request was not written to the audit trail"
        );
    }
}

/// The `client_id` a form-encoded request claims, if it names one.
///
/// A lookup in the same `application/x-www-form-urlencoded` list `/token` and
/// `/par` already parse, not a parser of its own: the limiter must agree with
/// the handler about which client a request claimed, and two readers of one
/// body eventually disagree. A body that is not UTF-8, or names no client, is
/// simply a request with no client bucket — the address bucket still holds it.
#[must_use]
pub fn claimed_client_id(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    url::form_urlencoded::parse(text.as_bytes())
        .find(|(key, _)| key == "client_id")
        .map(|(_, value)| value.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use time::Duration;

    /// Counters in memory. Enough to assert what the limiter decides; it is
    /// deliberately not what the server runs, because a per-process counter
    /// limits nothing across replicas.
    #[derive(Debug, Default)]
    struct Counters(Mutex<BTreeMap<(String, i64), u32>>);

    #[async_trait::async_trait]
    impl RateLimitStore for Counters {
        async fn count(
            &self,
            _tenant: &TenantId,
            bucket: &Bucket,
            window_start: OffsetDateTime,
        ) -> Result<u32, DomainError> {
            let counters = self.0.lock().expect("the test store is not poisoned");
            Ok(*counters
                .get(&(bucket.as_str().to_owned(), window_start.unix_timestamp()))
                .unwrap_or(&0))
        }

        async fn record(
            &self,
            _tenant: &TenantId,
            bucket: &Bucket,
            window_start: OffsetDateTime,
            _expires_at: OffsetDateTime,
        ) -> Result<u32, DomainError> {
            let mut counters = self.0.lock().expect("the test store is not poisoned");
            let entry = counters
                .entry((bucket.as_str().to_owned(), window_start.unix_timestamp()))
                .or_default();
            *entry += 1;
            Ok(*entry)
        }

        async fn clear(&self, _tenant: &TenantId, bucket: &Bucket) -> Result<(), DomainError> {
            let mut counters = self.0.lock().expect("the test store is not poisoned");
            counters.retain(|(key, _), _| key != bucket.as_str());
            Ok(())
        }
    }

    /// Records what was appended, so "once per window" can be asserted.
    #[derive(Debug, Default)]
    struct Trail(Mutex<Vec<AuditEvent>>);

    #[async_trait::async_trait]
    impl AuditSink for Trail {
        async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
            self.0
                .lock()
                .expect("the test sink is not poisoned")
                .push(event);
            Ok(())
        }
    }

    fn limit(max: u32) -> RateLimit {
        RateLimit {
            max,
            window: Duration::seconds(60),
        }
    }

    fn limits() -> EndpointLimits {
        let plain = asterius_domain::EndpointLimit {
            per_address: limit(2),
            per_client: None,
        };
        EndpointLimits {
            registration: plain,
            client_configuration: plain,
            par: asterius_domain::EndpointLimit {
                per_address: limit(2),
                per_client: Some(limit(5)),
            },
            token: asterius_domain::EndpointLimit {
                per_address: limit(2),
                per_client: Some(limit(5)),
            },
            userinfo: plain,
            ssf_subjects: plain,
        }
    }

    fn tenant() -> TenantId {
        TenantId::parse("demo").expect("`demo` is a valid tenant id")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a valid timestamp")
    }

    fn address() -> IpAddr {
        "198.51.100.7".parse().expect("a literal address")
    }

    fn context<'a>(store: &'a Counters, audit: &'a Trail) -> LimitContext<'a> {
        LimitContext {
            tenant: &TENANT,
            throttle: EndpointThrottle::new(store, limits(), Some(address())),
            audit,
            now: now(),
        }
    }

    /// One tenant id, so `context` can hand out a borrow of it.
    static TENANT: std::sync::LazyLock<TenantId> =
        std::sync::LazyLock::new(|| TenantId::parse("demo").expect("a valid tenant id"));

    async fn ok() -> Response {
        StatusCode::OK.into_response()
    }

    async fn bad_request() -> Response {
        StatusCode::BAD_REQUEST.into_response()
    }

    #[tokio::test]
    async fn requests_within_the_limit_reach_the_handler() {
        // Arrange
        let store = Counters::default();
        let trail = Trail::default();
        let context = context(&store, &trail);

        // Act
        let first = guard(&context, LimitedEndpoint::Registration, None, ok).await;
        let second = guard(&context, LimitedEndpoint::Registration, None, ok).await;

        // Assert
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_request_past_the_address_limit_is_refused_with_a_retry_hint() {
        // Arrange
        let store = Counters::default();
        let trail = Trail::default();
        let context = context(&store, &trail);
        for _ in 0..2 {
            guard(&context, LimitedEndpoint::Registration, None, ok).await;
        }

        // Act
        let refused = guard(&context, LimitedEndpoint::Registration, None, ok).await;

        // Assert
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(refused.headers().contains_key(header::RETRY_AFTER));
    }

    /// The number an operator sets for `/register` is a number about
    /// `/register`, not a shared pool `/token` can drain.
    #[tokio::test]
    async fn one_endpoints_budget_is_not_spendable_from_another() {
        // Arrange
        let store = Counters::default();
        let trail = Trail::default();
        let context = context(&store, &trail);
        for _ in 0..3 {
            guard(&context, LimitedEndpoint::Registration, None, ok).await;
        }

        // Act
        let elsewhere = guard(&context, LimitedEndpoint::UserInfo, None, ok).await;

        // Assert
        assert_eq!(elsewhere.status(), StatusCode::OK);
    }

    /// The property the whole design turns on: a client that authenticates is
    /// charged to itself, so its correct traffic does not exhaust the budget
    /// of everyone behind the same NAT.
    #[tokio::test]
    async fn a_successful_clients_traffic_does_not_spend_the_address_budget() {
        // Arrange
        let store = Counters::default();
        let trail = Trail::default();
        let context = context(&store, &trail);

        // Act
        for _ in 0..5 {
            let answered = guard(&context, LimitedEndpoint::Token, Some("busy-client"), ok).await;
            assert_eq!(answered.status(), StatusCode::OK);
        }
        let neighbour = guard(&context, LimitedEndpoint::Token, Some("other-client"), ok).await;

        // Assert
        assert_eq!(neighbour.status(), StatusCode::OK);
    }

    /// The mirror trap: if a claimed `client_id` were charged whatever the
    /// answer, anybody could lock a competitor out by naming them in a body
    /// full of nonsense.
    #[tokio::test]
    async fn a_failed_request_cannot_spend_the_budget_of_the_client_it_names() {
        // Arrange
        let store = Counters::default();
        let trail = Trail::default();
        let context = context(&store, &trail);

        // Act
        for _ in 0..2 {
            guard(
                &context,
                LimitedEndpoint::Token,
                Some("victim"),
                bad_request,
            )
            .await;
        }
        let victim = context
            .throttle
            .check(
                context.tenant,
                LimitedEndpoint::Token,
                Some("victim"),
                now(),
            )
            .await
            .expect("the test store counts");

        // Assert: the victim's own bucket is untouched; only the address paid.
        assert!(victim.is_some_and(|full| full.scope == Scope::Address));
    }

    /// A client bucket that is full refuses the client that filled it, or the
    /// per-client limit is decoration.
    #[tokio::test]
    async fn a_client_past_its_own_limit_is_refused() {
        // Arrange
        let store = Counters::default();
        let trail = Trail::default();
        let context = LimitContext {
            // No address: this asserts the client limit alone, which is the
            // one that has to hold when many addresses are one caller.
            throttle: EndpointThrottle::new(&store, limits(), None),
            ..context(&store, &trail)
        };
        for _ in 0..5 {
            guard(&context, LimitedEndpoint::Token, Some("busy"), ok).await;
        }

        // Act
        let refused = guard(&context, LimitedEndpoint::Token, Some("busy"), ok).await;

        // Assert
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// A trail that grows with the flood is a way to bury everything else in
    /// it: the criterion is one record per window.
    #[tokio::test]
    async fn a_flood_is_audited_once_per_window() {
        // Arrange
        let store = Counters::default();
        let trail = Trail::default();
        let context = context(&store, &trail);

        // Act
        for _ in 0..20 {
            guard(&context, LimitedEndpoint::Registration, None, ok).await;
        }

        // Assert
        let records = trail.0.lock().expect("the test sink is not poisoned");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_type, EventType::REQUEST_THROTTLED);
    }

    /// The record names the limit, never the address or the id an attacker
    /// wrote.
    #[test]
    fn the_trail_record_names_the_endpoint_and_no_caller() {
        // Arrange
        let refused = Refused {
            scope: Scope::Address,
            retry_after: Duration::seconds(60),
        };

        // Act
        let event = throttled_event(&tenant(), LimitedEndpoint::Registration, refused, now());

        // Assert
        let rendered = format!("{:?}", event.detail);
        assert!(rendered.contains("registration"));
        assert!(!rendered.contains("198.51.100.7"));
        assert_eq!(event.subject, None);
    }

    /// An unregistered client id must reach a full bucket in exactly as many
    /// requests as a registered one: the limiter never asks the registry
    /// anything, and this is the assertion that says so.
    #[tokio::test]
    async fn an_unknown_client_is_refused_exactly_like_a_known_one() {
        // Arrange
        let store = Counters::default();
        let trail = Trail::default();
        let context = context(&store, &trail);

        // Act
        let mut statuses = Vec::new();
        for client in ["registered", "invented"] {
            let store = Counters::default();
            let trail = Trail::default();
            let context = LimitContext {
                throttle: EndpointThrottle::new(&store, limits(), Some(address())),
                audit: &trail,
                ..context
            };
            for _ in 0..2 {
                guard(&context, LimitedEndpoint::Token, Some(client), bad_request).await;
            }
            statuses.push(
                guard(&context, LimitedEndpoint::Token, Some(client), bad_request)
                    .await
                    .status(),
            );
        }

        // Assert
        assert_eq!(statuses[0], statuses[1]);
        assert_eq!(statuses[0], StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn a_form_body_yields_the_client_it_claims() {
        // Arrange
        let body = b"grant_type=authorization_code&client_id=demo%20app";

        // Act
        let claimed = claimed_client_id(body);

        // Assert
        assert_eq!(claimed.as_deref(), Some("demo app"));
    }

    #[test]
    fn a_body_that_names_no_client_has_no_client_bucket() {
        // Arrange
        let body = b"grant_type=authorization_code";

        // Act & Assert
        assert_eq!(claimed_client_id(body), None);
    }
}
