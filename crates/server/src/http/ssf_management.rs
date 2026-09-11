//! The SSF stream status and subject endpoints (SSF 1.0 §8.1.2, §8.1.3).
//!
//! Three URLs beside the stream configuration endpoint: the status endpoint
//! ([`STATUS_PATH`], `GET` for §8.1.2.1 and `POST` for §8.1.2.2), the
//! add-subject endpoint ([`ADD_SUBJECT_PATH`], §8.1.3.2) and the
//! remove-subject endpoint ([`REMOVE_SUBJECT_PATH`], §8.1.3.3).
//!
//! The *semantics* are [`asterius_ssf::management`] and
//! [`asterius_ssf::subject`], which have no database and no HTTP. What is here
//! is who is calling, what they may reach, and what a refusal looks like on
//! the wire. The credential checks are not a second copy either: they are
//! [`crate::http::ssf::authorize_receiver`], the same five checks in the same
//! order the configuration and polling endpoints make, with this endpoint's
//! own resource and proof target.
//!
//! # What a status change does to the events (§8.1.2)
//!
//! Nothing in this module moves an event. The three statuses are written to
//! the stream, and the queue reads them:
//!
//! * `paused` stops delivery at the point events are *handed over* and stops
//!   nothing at the point they are produced, so the queue keeps holding them
//!   (§8.1.2's "SHOULD hold") in the order they were queued — which is an
//!   order per subject as well, since it is an order over everything.
//! * `enabled` makes that same queue readable again, so re-enabling a stream
//!   releases what it held without anything having to move it.
//! * `disabled` is enforced where an event is enqueued, so nothing is kept:
//!   §8.1.2 says a disabled transmitter "will not hold any events", and a
//!   queue that filled up while disabled would be exactly that.
//!
//! Both guards are `asterius_store_pg::ssf_poll`, in one place, because a
//! rule about delivery that is spelled out twice is a rule that eventually
//! means two things.
//!
//! # Answering the same way whether or not a subject exists (§9.1)
//!
//! §9.1 warns that the add-subject and remove-subject endpoints are a way to
//! ask "does this person have an account here", one identifier at a time, and
//! recommends answering 200 or 204 even for a subject the transmitter does not
//! recognise. That is what this module does, and it is worth being precise
//! about what it costs:
//!
//! * The **response** is byte-for-byte identical for a subject this tenant
//!   knows and one it does not. No body, no header, no timing decision that
//!   depends on the answer beyond one lookup either way.
//! * A subject this server can resolve and does not recognise is **not
//!   written**. There is nothing to write: no event will ever be about it, and
//!   a row naming an identifier that belongs to nobody here is a personal
//!   identifier kept for no purpose.
//! * A subject this server *cannot* resolve — an `opaque` identifier, a
//!   `uri`, a complex subject naming a session — **is** written. "We hold
//!   nobody by that name" and "we cannot answer that question" are different
//!   facts, and treating the second as the first would silently drop a
//!   legitimate subscription. It leaks nothing, because the response did not
//!   change. (A pairwise `sub` is *not* in this group: OIDC Core §8.1 derives
//!   it one way, but every derived subject this server has issued is a row in
//!   `subject_identifiers`, so an `iss_sub` naming this issuer resolves
//!   whichever sector it was minted under.)
//!
//! The remaining way to probe is volume, so the two endpoints are rate
//! limited per address *and* per authenticated receiver — see
//! [`asterius_domain::LimitedEndpoint::SsfSubjects`] — and a receiver over its
//! budget gets §8.1.3.2's 429 with a `Retry-After`. See
//! `docs/threat-model.md`.

use crate::http::dpop::{self, DpopEndpoint, NONCE_HEADER, USE_NONCE};
use crate::http::limits::LimitContext;
use crate::http::ssf::{
    self, Credential, NotAuthorized, SsfTokenStatus, check_scope_challenge,
};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::keys::KeyStore;
use asterius_domain::{ClientId, DomainError, LimitedEndpoint, Tenant};
use asterius_oidc::userinfo::{self, UserInfoError};
use asterius_ssf::management::{ManagementError, StatusRequest, StreamStatus, SubjectRequest};
use asterius_ssf::stream::{self, StreamId};
use asterius_ssf::subject::Subject;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use time::OffsetDateTime;

/// Where the status endpoint is mounted, under the tenant (§8.1.2).
pub const STATUS_PATH: &str = "/ssf/streams/status";

/// Where a receiver adds a subject (§8.1.3.2).
///
/// A path of its own rather than a verb on the stream, because §8.1.3.2 and
/// §8.1.3.3 are two operations on one collection and SSF 1.0 §7.1 advertises
/// each of them as its own URL (`add_subject_endpoint`,
/// `remove_subject_endpoint`).
pub const ADD_SUBJECT_PATH: &str = "/ssf/streams/subjects:add";

/// Where a receiver removes a subject (§8.1.3.3).
pub const REMOVE_SUBJECT_PATH: &str = "/ssf/streams/subjects:remove";

/// The largest body either endpoint reads.
///
/// Four kibibytes. A status change is three short members and a subject
/// request is one subject identifier, whose canonical form is bounded by
/// [`asterius_ssf::MAX_SUBJECT_BYTES`] — after `serde_json` has read the body,
/// which is why there is a bound here as well.
pub const MAX_BODY_BYTES: usize = 4 * 1024;

/// The query parameter that addresses one stream on a `GET` (§8.1.2.1).
const STREAM_ID_PARAMETER: &str = "stream_id";

/// What an add did (§8.1.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectOutcome {
    /// The subject is a member of the stream now, or already was.
    Member,
    /// No such stream for this receiver.
    NoSuchStream,
    /// The stream already holds as many subjects as it may.
    Full,
}

/// Whether this server can put a name to a subject identifier.
///
/// Three answers rather than two, because "we looked and there is nobody" and
/// "we cannot look" are different facts with different consequences — see the
/// module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recognised {
    /// A principal of this tenant.
    Known,
    /// Resolvable, and nobody here. Answered for, never written down.
    Unknown,
    /// Not something this transmitter can resolve in this direction: an
    /// opaque identifier, a pairwise `sub`, a complex subject.
    Unresolvable,
}

/// Who a subject identifier names, if this server can tell.
///
/// Its own port rather than a method on the subject store, because the
/// question is about *users* and the store is about memberships: an
/// implementation of this reads the directory, and one of those reads a stream
/// nobody has to have permission for.
#[async_trait::async_trait]
pub trait SubjectDirectory: std::fmt::Debug + Send + Sync {
    /// Whether this tenant holds the principal a subject identifier names.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the directory cannot be read. Never
    /// [`Recognised::Unknown`] for a store that is down: that would turn an
    /// outage into a subscription silently not recorded.
    async fn recognises(&self, subject: &Subject) -> Result<Recognised, DomainError>;
}

/// The rows these endpoints read and write.
///
/// Narrow like the other two SSF ports, and every method takes the receiver,
/// so there is no call this endpoint can make that is not already scoped to
/// the caller.
#[async_trait::async_trait]
pub trait SsfManagementStore: SsfTokenStatus {
    /// This stream's status and the reason it was last given (§8.1.2.1).
    ///
    /// `None` is "no such stream for this receiver".
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the row cannot be read or is not one the model
    /// accepts.
    async fn status(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
    ) -> Result<Option<(StreamStatus, Option<String>)>, DomainError>;

    /// Writes a stream's status (§8.1.2.2). `false` is "no such stream for
    /// this receiver".
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the write fails, in which case the status is
    /// unchanged and the caller must not report the new one.
    async fn set_status(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        status: StreamStatus,
        reason: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Adds one subject to a stream (§8.1.3.2). Idempotent.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the write fails, in which case nothing was
    /// written.
    async fn add_subject(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        subject: &Subject,
        verified: Option<bool>,
        now: OffsetDateTime,
    ) -> Result<SubjectOutcome, DomainError>;

    /// Removes one subject from a stream (§8.1.3.3). `false` is "no such
    /// stream for this receiver"; whether the subject was a member is
    /// deliberately not reported (§9.1).
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the write fails, in which case the subject may
    /// still be a member and the caller must not answer 204.
    async fn remove_subject(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        subject: &Subject,
    ) -> Result<bool, DomainError>;
}

/// What one status or subject request needs.
pub struct SsfManagementContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The rows.
    pub store: &'a dyn SsfManagementStore,
    /// Who a subject identifier names, if this server can tell.
    pub directory: &'a dyn SubjectDirectory,
    /// Where the tenant's published keys come from.
    pub keys: &'a dyn KeyStore,
    /// Checks the DPoP proof (RFC 9449 §7.1).
    pub dpop: &'a DpopEndpoint,
    /// The trail. Every status change and every membership change is recorded.
    pub audit: &'a dyn AuditSink,
    /// The client certificate this request arrived with, if the deployment saw
    /// one from a source it trusts (RFC 8705 §2).
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    /// The per-endpoint limiter, for §8.1.3.2's 429.
    pub limits: LimitContext<'a>,
    /// One clock reading for the whole request.
    pub now: OffsetDateTime,
}

impl std::fmt::Debug for SsfManagementContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfManagementContext")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Which of §8.1.3's two operations is being served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership {
    /// §8.1.3.2: add this subject to the stream.
    Add,
    /// §8.1.3.3: remove it.
    Remove,
}

/// Why a request stopped.
#[derive(Debug)]
enum Refused {
    /// An RFC 6750 §3 refusal: 400, 401 or 403, in a `WWW-Authenticate`.
    Client(UserInfoError),
    /// The token does not carry [`stream::SCOPE_MANAGE`].
    MissingScope,
    /// §8.1.2's and §8.1.3's 404: no such stream, or not this receiver's.
    NotFound,
    /// A 400, with the reason the model gave.
    Invalid(ManagementError),
    /// The stream holds as many subjects as it may (§8.1.3.2's 400 case that
    /// is about the receiver's own quota rather than about a subject).
    TooManySubjects,
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

impl From<ManagementError> for Refused {
    fn from(error: ManagementError) -> Self {
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

/// The status endpoint: `GET` (§8.1.2.1) and `POST` (§8.1.2.2) at
/// [`STATUS_PATH`].
///
/// Never returns `Err`: every failure is an HTTP response.
pub async fn status(
    context: SsfManagementContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    query: Option<&str>,
    body: &[u8],
) -> Response {
    match answer_status(&context, method, headers, query, body).await {
        Ok(response) => response,
        Err(refusal) => render(&context, refusal),
    }
}

/// The subject endpoints: `POST` at [`ADD_SUBJECT_PATH`] (§8.1.3.2) and at
/// [`REMOVE_SUBJECT_PATH`] (§8.1.3.3).
///
/// One function for both, because the two differ in one statement and share
/// everything else — the authorization, the parse, the limiter and the rule
/// that the answer must not depend on whether the subject exists. Two
/// functions would be two places for that rule to be got right.
///
/// Never returns `Err`: every failure is an HTTP response.
pub async fn subjects(
    context: SsfManagementContext<'_>,
    membership: Membership,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    match answer_subjects(&context, membership, method, headers, body).await {
        Ok(response) => response,
        Err(refusal) => render(&context, refusal),
    }
}

/// §8.1.2.1 and §8.1.2.2.
async fn answer_status(
    context: &SsfManagementContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    query: Option<&str>,
    body: &[u8],
) -> Result<Response, Refused> {
    let receiver = authorize(context, STATUS_PATH, method, headers).await?;

    match *method {
        Method::GET => {
            let stream = addressed(query).ok_or(Refused::NotFound)?;
            let (status, reason) = context
                .store
                .status(&receiver, &stream)
                .await?
                .ok_or(Refused::NotFound)?;
            Ok(rendered_status(&stream, status, reason.as_deref()))
        }
        Method::POST => {
            let request = StatusRequest::parse(&parse(body)?)?;
            let stream = request.addressed_stream()?.clone();
            // §8.1.2.2 allows a 202 when the transmitter cannot decide
            // immediately. This one always can: a status is a column, the
            // write settles it, and the queue reads the column on the next
            // event rather than being told about the change. So the answer is
            // always 200 with the new status, and a receiver never has to poll
            // §8.1.2.1 to find out whether its request took.
            if !context
                .store
                .set_status(
                    &receiver,
                    &stream,
                    request.status,
                    request.reason.as_deref(),
                    context.now,
                )
                .await?
            {
                return Err(Refused::NotFound);
            }
            record(
                context,
                &receiver,
                EventType::SSF_STREAM_STATUS_CHANGED,
                &stream,
                Detail::new().label("status", request.status.as_str()),
            )
            .await;
            Ok(rendered_status(
                &stream,
                request.status,
                request.reason.as_deref(),
            ))
        }
        _ => Err(Refused::MethodNotAllowed),
    }
}

/// §8.1.3.2 and §8.1.3.3.
async fn answer_subjects(
    context: &SsfManagementContext<'_>,
    membership: Membership,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, Refused> {
    if method != Method::POST {
        return Err(Refused::MethodNotAllowed);
    }
    let path = match membership {
        Membership::Add => ADD_SUBJECT_PATH,
        Membership::Remove => REMOVE_SUBJECT_PATH,
    };
    let receiver = authorize(context, path, method, headers).await?;

    // The limiter runs *after* the credential checks and before the work, so
    // the receiver charged is one that proved who it is — and so a caller
    // walking a list of subject identifiers meets the 429 before any of them
    // reaches the directory. `guard` renders that refusal itself, with the
    // `Retry-After` every throttled endpoint here answers with.
    let response = crate::http::limits::guard(
        &context.limits,
        LimitedEndpoint::SsfSubjects,
        Some(receiver.as_str()),
        async || match change_membership(context, membership, &receiver, body).await {
            Ok(response) => response,
            Err(refusal) => render(context, refusal),
        },
    )
    .await;
    Ok(no_store(response))
}

/// One membership change, once the limiter has admitted it.
async fn change_membership(
    context: &SsfManagementContext<'_>,
    membership: Membership,
    receiver: &ClientId,
    body: &[u8],
) -> Result<Response, Refused> {
    let request = SubjectRequest::parse(&parse(body)?)?;
    let stream = request.addressed_stream()?.clone();

    // §9.1: the same lookup on both paths, so the work a request does is the
    // same whether or not the subject exists.
    let recognised = context.directory.recognises(&request.subject).await?;

    match membership {
        Membership::Add => {
            if recognised == Recognised::Unknown {
                // Answered for and not written down. The stream still has to
                // be this receiver's, or there is nothing to answer *about*:
                // §8.1.3.2 keeps its 404 for the stream, which is a resource
                // the caller either owns or does not.
                if context.store.status(receiver, &stream).await?.is_none() {
                    return Err(Refused::NotFound);
                }
                record(
                    context,
                    receiver,
                    EventType::SSF_SUBJECT_ADDED,
                    &stream,
                    Detail::new().label("recorded", "no"),
                )
                .await;
                return Ok(no_store(StatusCode::OK.into_response()));
            }
            match context
                .store
                .add_subject(
                    receiver,
                    &stream,
                    &request.subject,
                    request.verified,
                    context.now,
                )
                .await?
            {
                SubjectOutcome::Member => {
                    record(
                        context,
                        receiver,
                        EventType::SSF_SUBJECT_ADDED,
                        &stream,
                        Detail::new().label("recorded", "yes"),
                    )
                    .await;
                    Ok(no_store(StatusCode::OK.into_response()))
                }
                SubjectOutcome::NoSuchStream => Err(Refused::NotFound),
                SubjectOutcome::Full => Err(Refused::TooManySubjects),
            }
        }
        Membership::Remove => {
            // §9.3: a receiver may see events about a subject it has just
            // removed, and §8.1.3.3 answers 204 whether or not the subject was
            // a member. The store is told to remove it either way — an
            // unrecognised subject that was somehow recorded must still be
            // removable — and reports only whether the stream was there.
            if !context
                .store
                .remove_subject(receiver, &stream, &request.subject)
                .await?
            {
                return Err(Refused::NotFound);
            }
            record(
                context,
                receiver,
                EventType::SSF_SUBJECT_REMOVED,
                &stream,
                Detail::new(),
            )
            .await;
            Ok(no_store(StatusCode::NO_CONTENT.into_response()))
        }
    }
}

/// The five checks, for whichever of these three URLs is being served.
///
/// The scope is [`stream::SCOPE_MANAGE`] for all of them: §7.1.1 gives the
/// management API one scope, and §8.1.2 and §8.1.3 are that API. The
/// *resource* and the *proof target* are per URL, so a token audienced at the
/// configuration endpoint is not one the status endpoint answers — it is the
/// same rule that keeps a receiver's token for a business API out of here.
async fn authorize(
    context: &SsfManagementContext<'_>,
    path: &'static str,
    method: &Method,
    headers: &HeaderMap,
) -> Result<ClientId, Refused> {
    let resource = format!("{}{path}", context.tenant.issuer.as_str());
    ssf::authorize_receiver(
        &Credential {
            tenant: context.tenant,
            keys: context.keys,
            dpop: context.dpop,
            certificate: context.certificate,
            tokens: context.store,
            resource: &resource,
            target: dpop::ProofTarget::at_path(path),
            scope: stream::SCOPE_MANAGE,
            now: context.now,
        },
        method,
        headers,
    )
    .await
    .map_err(Refused::from)
}

/// The body, as JSON.
///
/// The size guard comes first: everything below it parses, and a bound applied
/// after parsing is a bound applied after the work.
fn parse(body: &[u8]) -> Result<Value, Refused> {
    if body.len() > MAX_BODY_BYTES {
        return Err(Refused::Invalid(ManagementError::TooLong {
            member: "body",
        }));
    }
    serde_json::from_slice(body).map_err(|_| Refused::Invalid(ManagementError::NotAnObject))
}

/// The `stream_id` a query string addresses (§8.1.2.1).
///
/// `None` covers both "no `stream_id`" and "a `stream_id` this server could
/// never have issued", because both name no stream and the answer to both is
/// §8.1.2.1's 404 — a shape check costs a length comparison where a query
/// costs a round trip.
fn addressed(query: Option<&str>) -> Option<StreamId> {
    let raw = url::form_urlencoded::parse(query?.as_bytes())
        .find(|(name, _)| name == STREAM_ID_PARAMETER)
        .map(|(_, value)| value.into_owned())?;
    StreamId::parse(&raw)
}

/// §8.1.2.1's and §8.1.2.2's response.
fn rendered_status(stream: &StreamId, status: StreamStatus, reason: Option<&str>) -> Response {
    no_store(
        axum::Json(Value::Object(asterius_ssf::render_status(
            stream, status, reason,
        )))
        .into_response(),
    )
}

/// One entry in the trail.
///
/// The stream is recorded as a fingerprint rather than as its identifier, for
/// the reason [`crate::http::ssf`] gives. The *subject* is not recorded at
/// all: it is the personal identifier this whole module exists to be careful
/// with, and an operator asking "what did this receiver subscribe to" reads
/// the stream's membership rather than a copy of it in the trail.
///
/// Never fails the request: the change is already committed by the time this
/// runs.
async fn record(
    context: &SsfManagementContext<'_>,
    receiver: &ClientId,
    event_type: EventType,
    stream: &StreamId,
    detail: Detail,
) {
    let event = AuditEvent::new(
        context.tenant.id.clone(),
        event_type,
        Outcome::Success,
        Actor::Client(receiver.clone()),
        context.now,
    )
    .client(receiver.clone())
    .detail(detail.credential("stream_id", stream.as_str()));

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            client = %receiver,
            "an SSF management change was not written to the audit trail"
        );
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// One refusal, in the vocabulary the other two SSF endpoints use.
fn render(context: &SsfManagementContext<'_>, refusal: Refused) -> Response {
    match refusal {
        Refused::Client(error) => refuse(&error),
        Refused::MissingScope => insufficient_scope(),
        Refused::NotFound => no_store(StatusCode::NOT_FOUND.into_response()),
        Refused::Invalid(error) => problem(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &error.to_string(),
        ),
        // About the receiver's own quota and not about any subject, so it says
        // so plainly: §9.1's silence is owed to people who might have an
        // account here, not to a receiver asking about its own stream.
        Refused::TooManySubjects => problem(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "this stream already holds as many subjects as this transmitter allows",
        ),
        Refused::MethodNotAllowed => no_store(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        Refused::Dpop(refusal) => dpop_challenge(&refusal),
        Refused::Server(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "cannot answer an SSF management request"
            );
            unavailable()
        }
    }
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

/// RFC 6750 §3.1's `insufficient_scope`, naming the scope §7.1.1 needs.
fn insufficient_scope() -> Response {
    let mut response = empty(StatusCode::FORBIDDEN);
    if let Ok(value) = HeaderValue::from_str(&check_scope_challenge(stream::SCOPE_MANAGE)) {
        response
            .headers_mut()
            .append(header::WWW_AUTHENTICATE, value);
    }
    no_store(response)
}

/// A DPoP failure, in the shape a resource server uses (RFC 9449 §7.1, §7.2).
fn dpop_challenge(refusal: &dpop::Refusal) -> Response {
    if let Some(detail) = refusal.detail() {
        tracing::debug!(%detail, "a DPoP proof at an SSF management endpoint did not check out");
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

/// What these endpoints say when they cannot finish.
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
///
/// A status answer names a stream a receiver holds and a subject answer is
/// about a person; neither belongs in a shared cache. The configuration
/// endpoint says the same thing, for the same reason (§8.1.1.2).
fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
