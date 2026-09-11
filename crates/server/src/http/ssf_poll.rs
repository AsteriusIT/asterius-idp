//! The poll delivery endpoint (RFC 8936 §2; SSF 1.0 §6.1.2, §7.1.1).
//!
//! One `POST`, per stream, at [`crate::http::ssf::POLL_PATH`] + `/` +
//! `stream_id`. The request acknowledges what the receiver has processed,
//! reports what it could not, and asks for more (§2.1); the response is the
//! SETs, by `jti`, and whether the transmitter is holding any back (§2.3).
//!
//! The *shapes* of those two objects are [`asterius_ssf::poll`], which has no
//! database and no HTTP. What is here is who is calling, which stream they may
//! poll, what an acknowledgement does to the queue, and what a refusal looks
//! like on the wire.
//!
//! # The URL names the stream, and the token decides whether it is yours
//!
//! §6.1.2 makes the polling URL "unique per stream and per receiver", and it
//! has to be: a poll request carries no stream identifier, so the address is
//! the only thing that says which stream is meant. That makes the `stream_id`
//! in the path the one piece of routing information a caller supplies, and it
//! is never trusted on its own:
//!
//! 1. It must parse as an identifier this server issues
//!    ([`StreamId::parse`]) — a value that cannot be one is a 404 before any
//!    work is done.
//! 2. The token is checked exactly as the management endpoint checks it —
//!    same five checks, same function (`ssf::authorize_receiver`) — with
//!    §7.1.1's scope for *this* endpoint, [`stream::SCOPE_POLL`].
//! 3. The stream is read back **scoped to the receiver the token names**. So
//!    another receiver's stream is not a stream this endpoint refuses to
//!    deliver from; it is a stream that does not come back, and the 404 is the
//!    truthful answer rather than a chosen one.
//!
//! The DPoP proof is made over the per-stream URL, rebuilt here from the
//! issuer and the identifier this server recognised — never from the request
//! line.
//!
//! # What an acknowledgement means, and what an error report means
//!
//! §2.4 has the receiver drive the queue, and this endpoint does what it says
//! in the order it says it:
//!
//! * `ack` first, then the new batch. An acknowledged SET is gone before the
//!   response is selected, so a receiver never sees a SET it has just
//!   acknowledged come back in the same response.
//! * `setErrs` retires the SET. §2.4 leaves the transmitter a choice here; the
//!   choice this deployment makes is "do not redeliver", because a receiver
//!   that cannot verify a SET cannot verify it on the tenth attempt either,
//!   and the alternative is a queue that never drains and a receiver that
//!   never gets anything *else*. The report is written to the audit trail
//!   first — the receiver's own `err` code and description — because once the
//!   row is gone that entry is the only record that the signal existed.
//! * Everything that is neither acknowledged nor reported stays, and is
//!   delivered again on the next poll. That is §2.4's redelivery rule, and it
//!   is why a receiver crashing halfway through a batch loses nothing.
//!
//! # Long polling is bounded
//!
//! `returnImmediately: false` (§2.1) asks this server to hold the request open
//! until an event is available. It holds it for
//! [`asterius_ssf::poll::MAX_LONG_POLL`] seconds at the outside and then
//! answers with an empty `sets`, which is a valid response and not an error.
//! An unbounded wait would be a receiver deciding how many connections of this
//! server it gets to hold, and a shutdown waiting on all of them.
//!
//! # Threat model note
//!
//! A poll response is a batch of SETs about a tenant's users, handed to
//! whoever presents the token. Two things keep that in its lane and both are
//! above: the stream is read under the receiver's `client_id`, and the SETs
//! themselves carry an `aud` the receiver's verifier checks
//! (`asterius_ssf::StreamAudience`). Nothing in a response is cached —
//! `no-store` on every answer, including the refusals — because a poll
//! response in a shared proxy is one tenant's security signals handed to
//! whoever asks next. See `docs/threat-model.md`.

use crate::http::dpop::{self, DpopEndpoint, NONCE_HEADER, USE_NONCE};
use crate::http::ssf::{
    self, Credential, NotAuthorized, POLL_PATH, SsfTokenStatus, check_scope_challenge,
};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::keys::KeyStore;
use asterius_domain::{ClientId, DomainError, Tenant};
use asterius_oidc::userinfo::{self, UserInfoError};
use asterius_ssf::poll::{MAX_LONG_POLL, PollError, PollRequest, PollResponse, RejectedSet};
use asterius_ssf::stream::{self, Delivery, StreamConfiguration, StreamId};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::time::Duration;
use time::OffsetDateTime;

/// The largest poll request body this endpoint reads.
///
/// Sixteen kibibytes. `asterius_ssf::poll` bounds every member it keeps, but
/// it bounds them after `serde_json` has read the whole body, and a thousand
/// acknowledgements — the most §2.1 allows here — is a few tens of kibibytes
/// of identifiers at most.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// One queued SET, as this endpoint renders it (§2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedSet {
    /// RFC 8417 §2's `jti`, which is the member name in the response.
    pub jti: String,
    /// The compact serialisation, as it was signed.
    pub jws: String,
}

/// What one read of the queue returned (§2.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Batch {
    /// The SETs, oldest first.
    pub sets: Vec<QueuedSet>,
    /// Whether the stream is still holding SETs this batch did not carry.
    pub more_available: bool,
}

/// The queue this endpoint reads and writes.
///
/// Narrow on purpose, like [`ssf::SsfStreamStore`]: every method takes the
/// stream, and the one method that resolves a stream takes the receiver, so
/// there is no call this endpoint can make that is not already scoped to the
/// caller.
#[async_trait::async_trait]
pub trait SsfPollStore: SsfTokenStatus {
    /// The stream this receiver's `stream_id` names, or `None`.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the row cannot be read or is not one the model
    /// accepts.
    async fn find(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
    ) -> Result<Option<StreamConfiguration>, DomainError>;

    /// The oldest `limit` SETs this stream holds, and whether more are held
    /// (§2.3). The rows are not removed: §2.4 has the receiver do that.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the queue cannot be read.
    async fn deliver(
        &self,
        stream: &StreamId,
        limit: usize,
        now: OffsetDateTime,
    ) -> Result<Batch, DomainError>;

    /// Removes the SETs a receiver acknowledged (§2.4). Returns how many rows
    /// went.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the delete fails, in which case nothing was
    /// removed and the SETs are delivered again.
    async fn acknowledge(&self, stream: &StreamId, jtis: &[String]) -> Result<u64, DomainError>;

    /// Retires the SETs a receiver reported an error for (§2.4).
    ///
    /// # Errors
    ///
    /// As [`Self::acknowledge`].
    async fn reject(&self, stream: &StreamId, jtis: &[String]) -> Result<u64, DomainError>;

    /// Whether this stream is holding anything, which is what a long poll
    /// waits on.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the queue cannot be read.
    async fn has_pending(&self, stream: &StreamId) -> Result<bool, DomainError>;
}

/// How long a long poll waits, and how often it looks (§2.1).
///
/// A field rather than two constants so that a test can assert §2.1's
/// behaviour in milliseconds instead of holding a test process open for half a
/// minute. [`PollTiming::bounded`] is what keeps a configured value from
/// exceeding [`MAX_LONG_POLL`] whatever a caller passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollTiming {
    /// The longest a request is held open.
    pub wait: Duration,
    /// How often the queue is looked at while waiting.
    pub interval: Duration,
}

impl Default for PollTiming {
    fn default() -> Self {
        Self {
            wait: Duration::from_secs(MAX_LONG_POLL),
            interval: Duration::from_secs(1),
        }
    }
}

impl PollTiming {
    /// The timing, with the wait clamped to [`MAX_LONG_POLL`].
    #[must_use]
    pub fn bounded(self) -> Self {
        Self {
            wait: self.wait.min(Duration::from_secs(MAX_LONG_POLL)),
            interval: self.interval.max(Duration::from_millis(1)),
        }
    }
}

/// What one poll request needs.
pub struct SsfPollContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The queue, and the stream behind it.
    pub store: &'a dyn SsfPollStore,
    /// Where the tenant's published keys come from.
    pub keys: &'a dyn KeyStore,
    /// Checks the DPoP proof (RFC 9449 §7.1).
    pub dpop: &'a DpopEndpoint,
    /// The trail: what was delivered, acknowledged and rejected.
    pub audit: &'a dyn AuditSink,
    /// The client certificate this request arrived with, if the deployment saw
    /// one from a source it trusts (RFC 8705 §2).
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    /// How long a long poll waits.
    pub timing: PollTiming,
    /// One clock reading for the whole request.
    pub now: OffsetDateTime,
}

impl std::fmt::Debug for SsfPollContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfPollContext")
            .field("timing", &self.timing)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Why a poll stopped.
#[derive(Debug)]
enum Refused {
    /// An RFC 6750 §3 refusal: 400, 401 or 403, in a `WWW-Authenticate`.
    Client(UserInfoError),
    /// The token does not carry [`stream::SCOPE_POLL`].
    MissingScope,
    /// No such stream, not this receiver's, or not one that is polled.
    NotFound,
    /// §2.1's 400, with the reason the model gave.
    Invalid(PollError),
    /// A verb this endpoint does not answer.
    MethodNotAllowed,
    /// A DPoP proof that did not check out (RFC 9449 §7.1).
    Dpop(dpop::Refusal),
    /// This deployment could not finish. Logged, never described.
    Server(DomainError),
}

impl From<DomainError> for Refused {
    fn from(error: DomainError) -> Self {
        Self::Server(error)
    }
}

impl From<PollError> for Refused {
    fn from(error: PollError) -> Self {
        Self::Invalid(error)
    }
}

impl From<NotAuthorized> for Refused {
    fn from(refusal: NotAuthorized) -> Self {
        match refusal {
            NotAuthorized::Client(error) => Self::Client(error),
            NotAuthorized::MissingScope => Self::MissingScope,
            NotAuthorized::Dpop(refusal) => Self::Dpop(refusal),
            NotAuthorized::Server(error) => Self::Server(error),
        }
    }
}

/// The whole endpoint: `POST` at [`POLL_PATH`] + `/` + `stream_id`.
///
/// `addressed` is the path segment as it arrived. Never returns `Err`: every
/// failure is an HTTP response.
pub async fn poll(
    context: SsfPollContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    addressed: &str,
    body: &[u8],
) -> Response {
    match answer(&context, method, headers, addressed, body).await {
        Ok(response) => response,
        Err(refusal) => render(&context, refusal),
    }
}

/// The request, from the path segment to the response body.
async fn answer(
    context: &SsfPollContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    addressed: &str,
    body: &[u8],
) -> Result<Response, Refused> {
    if method != Method::POST {
        return Err(Refused::MethodNotAllowed);
    }
    // Before the token, and deliberately: an identifier this server could
    // never have issued names no stream, so there is nothing a better
    // credential would reach. It also keeps the URL a DPoP proof is rebuilt
    // from to values this server recognises.
    let stream = StreamId::parse(addressed).ok_or(Refused::NotFound)?;

    let receiver = authorize(context, method, headers, &stream).await?;
    let configuration = context
        .store
        .find(&receiver, &stream)
        .await?
        .ok_or(Refused::NotFound)?;
    // A push stream has no polling URL at all (§8.1.1's `delivery`), so this
    // address does not exist for it. 404 rather than a description: telling a
    // receiver "that stream is push" is a fact about a stream it has just
    // proven it owns, but it is still a fact it can read from the management
    // endpoint, where it belongs.
    if configuration.delivery != Delivery::Poll {
        return Err(Refused::NotFound);
    }

    let request = parse(body)?;

    // §2.4, in order: acknowledgements and error reports are applied before
    // the batch is selected.
    let acknowledged = context.store.acknowledge(&stream, &request.ack).await?;
    if acknowledged > 0 {
        record(
            context,
            &receiver,
            EventType::SSF_SETS_ACKNOWLEDGED,
            Outcome::Success,
            Detail::new()
                .credential("stream_id", stream.as_str())
                .number("sets", i64::try_from(acknowledged).unwrap_or(i64::MAX)),
        )
        .await;
    }
    reject(context, &receiver, &stream, &request.set_errs).await?;

    let batch = collect(context, &stream, &request).await?;
    if !batch.sets.is_empty() {
        record(
            context,
            &receiver,
            EventType::SSF_SETS_DELIVERED,
            Outcome::Success,
            Detail::new()
                .credential("stream_id", stream.as_str())
                .number("sets", i64::try_from(batch.sets.len()).unwrap_or(i64::MAX))
                .flag("more_available", batch.more_available),
        )
        .await;
    }

    let mut response = PollResponse::empty().holding_more(batch.more_available);
    for set in batch.sets {
        response = response.with(set.jti, set.jws);
    }
    Ok(no_store(
        axum::Json(Value::Object(response.render())).into_response(),
    ))
}

/// The five checks, with this endpoint's resource and this endpoint's scope.
async fn authorize(
    context: &SsfPollContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    stream: &StreamId,
) -> Result<ClientId, Refused> {
    // The `aud` is the *base* polling endpoint, not the per-stream URL: a
    // receiver holds one token for this transmitter's polling resource and
    // uses it on every stream it owns, and which stream it may reach is
    // decided by the `client_id` in the lookup below rather than by a second
    // copy of that decision in an audience.
    let resource = format!("{}{POLL_PATH}", context.tenant.issuer.as_str());
    ssf::authorize_receiver(
        &Credential {
            tenant: context.tenant,
            keys: context.keys,
            dpop: context.dpop,
            certificate: context.certificate,
            tokens: context.store,
            resource: &resource,
            // Rebuilt from the issuer and the identifier this server
            // recognised, so the URL a proof is compared against is the URL
            // the router matched (§6.1.2).
            target: dpop::ProofTarget::under_path(POLL_PATH, stream.as_str()),
            scope: stream::SCOPE_POLL,
            now: context.now,
        },
        method,
        headers,
    )
    .await
    .map_err(Refused::from)
}

/// §2.4's `setErrs`: the trail entry first, then the row.
///
/// The order is the point. The entry names the SET, the receiver's `err` code
/// and its description; the row is then gone, so an entry written afterwards
/// could not be written at all if the process died in between, and the signal
/// would have vanished without a record.
async fn reject(
    context: &SsfPollContext<'_>,
    receiver: &ClientId,
    stream: &StreamId,
    rejected: &[RejectedSet],
) -> Result<(), Refused> {
    if rejected.is_empty() {
        return Ok(());
    }
    for report in rejected {
        let mut detail = Detail::new()
            .credential("stream_id", stream.as_str())
            .credential("jti", &report.jti)
            // `text` and not `label`: the code is the receiver's string, so it
            // is scanned for anything that looks like a credential before it
            // is stored.
            .text("err", &report.err);
        if let Some(description) = &report.description {
            detail = detail.text("description", description);
        }
        record(
            context,
            receiver,
            EventType::SSF_SET_REJECTED,
            Outcome::Failure,
            detail,
        )
        .await;
    }
    let jtis: Vec<String> = rejected.iter().map(|report| report.jti.clone()).collect();
    context.store.reject(stream, &jtis).await?;
    Ok(())
}

/// The batch this poll is answered with (§2.3), waiting where §2.1 says to.
///
/// The wait is a look at the queue every [`PollTiming::interval`] rather than
/// a notification: a poll queue is one table and one receiver, the interval is
/// a second, and a `LISTEN`/`NOTIFY` subscription would tie a held-open HTTP
/// request to a dedicated database connection for as long as it waits.
async fn collect(
    context: &SsfPollContext<'_>,
    stream: &StreamId,
    request: &PollRequest,
) -> Result<Batch, Refused> {
    let limit = request.batch_size();
    let batch = context.store.deliver(stream, limit, context.now).await?;
    if !batch.sets.is_empty() || !request.waits() {
        return Ok(batch);
    }

    let timing = context.timing.bounded();
    let deadline = tokio::time::Instant::now() + timing.wait;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(timing.interval.min(timing.wait)).await;
        if context.store.has_pending(stream).await? {
            return Ok(context.store.deliver(stream, limit, context.now).await?);
        }
    }
    // §2.1: a long poll that reached its timeout answers with an empty `sets`.
    // That is a response and not an error — the receiver polls again.
    Ok(Batch::default())
}

/// The body, as a §2.1 request.
///
/// The size guard comes first, as at the management endpoint: a bound applied
/// after parsing is a bound applied after the work.
fn parse(body: &[u8]) -> Result<PollRequest, Refused> {
    if body.len() > MAX_BODY_BYTES {
        return Err(Refused::Invalid(PollError::TooLong { member: "body" }));
    }
    // An empty body is an empty object: §2.1's every member is optional, so a
    // receiver sending nothing is asking for a default batch and, per §2.1's
    // default for `returnImmediately`, a long poll.
    if body.is_empty() {
        return Ok(PollRequest::default());
    }
    let value: Value =
        serde_json::from_slice(body).map_err(|_| Refused::Invalid(PollError::NotAnObject))?;
    Ok(PollRequest::parse(&value)?)
}

/// One entry in the trail.
///
/// The actor is the client: a receiver polling with its own token is who made
/// this request, and there is no person to name. Never fails the request —
/// what the entry describes has already happened, and refusing a receiver
/// because the trail is unavailable would make it poll for the same SETs
/// again.
async fn record(
    context: &SsfPollContext<'_>,
    receiver: &ClientId,
    event_type: EventType,
    outcome: Outcome,
    detail: Detail,
) {
    let event = AuditEvent::new(
        context.tenant.id.clone(),
        event_type,
        outcome,
        Actor::Client(receiver.clone()),
        context.now,
    )
    .client(receiver.clone())
    .detail(detail);

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            client = %receiver,
            "a poll delivery was not written to the audit trail"
        );
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// One refusal, in the shape a protected resource uses.
fn render(context: &SsfPollContext<'_>, refusal: Refused) -> Response {
    match refusal {
        Refused::Client(error) => refuse(&error),
        Refused::MissingScope => insufficient_scope(),
        Refused::NotFound => no_store(StatusCode::NOT_FOUND.into_response()),
        Refused::Invalid(error) => problem(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &error.to_string(),
        ),
        Refused::MethodNotAllowed => no_store(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        Refused::Dpop(refusal) => dpop_challenge(&refusal),
        Refused::Server(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "cannot answer a poll request"
            );
            unavailable()
        }
    }
}

/// An RFC 6750 §3 refusal: a status, a challenge per scheme, and no body.
fn refuse(error: &UserInfoError) -> Response {
    let mut response =
        empty(StatusCode::from_u16(error.status()).unwrap_or(StatusCode::UNAUTHORIZED));
    let headers = response.headers_mut();
    for challenge in userinfo::challenges(Some(error)) {
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            headers.append(header::WWW_AUTHENTICATE, value);
        }
    }
    no_store(response)
}

/// RFC 6750 §3.1's `insufficient_scope`, naming the scope §7.1.1 needs here.
fn insufficient_scope() -> Response {
    let mut response = empty(StatusCode::FORBIDDEN);
    if let Ok(value) = HeaderValue::from_str(&check_scope_challenge(stream::SCOPE_POLL)) {
        response
            .headers_mut()
            .append(header::WWW_AUTHENTICATE, value);
    }
    no_store(response)
}

/// A DPoP failure, in the shape a resource server uses (RFC 9449 §7.1, §7.2).
fn dpop_challenge(refusal: &dpop::Refusal) -> Response {
    if let Some(detail) = refusal.detail() {
        tracing::debug!(%detail, "a DPoP proof at the SSF polling endpoint did not check out");
    }
    if refusal.status().is_server_error() {
        return unavailable();
    }

    let mut response = empty(StatusCode::UNAUTHORIZED);
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&format!(
        r#"DPoP error="{}", error_description="the DPoP proof did not check out""#,
        refusal.code()
    )) {
        headers.append(header::WWW_AUTHENTICATE, value);
    }
    if refusal.code() == USE_NONCE
        && let Some(nonce) = refusal.nonce()
        && let Ok(value) = HeaderValue::from_str(nonce)
    {
        headers.insert(NONCE_HEADER, value);
    }
    no_store(response)
}

/// A JSON error body, in the shape OAuth 2.0 uses everywhere else here.
fn problem(status: StatusCode, code: &str, description: &str) -> Response {
    no_store(
        (
            status,
            axum::Json(json!({"error": code, "error_description": description})),
        )
            .into_response(),
    )
}

/// What this endpoint says when it cannot finish.
fn unavailable() -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "this transmitter cannot answer right now",
    )
}

/// A response with a status and nothing in it.
fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = status;
    response
}

/// Every response, without exception.
fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
