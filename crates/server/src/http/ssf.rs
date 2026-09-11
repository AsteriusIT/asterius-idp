//! The SSF Stream Configuration endpoint (SSF 1.0 §8.1.1).
//!
//! One URL and five verbs: `POST` creates a stream (§8.1.1.1), `GET` reads one
//! or lists the caller's (§8.1.1.2), `PATCH` updates the members it carries
//! (§8.1.1.3), `PUT` replaces the receiver-supplied set (§8.1.1.4) and
//! `DELETE` removes the stream (§8.1.1.5).
//!
//! The *semantics* of §8.1.1 are not here: they are
//! [`asterius_ssf::stream`], which has no database and no HTTP. What is here
//! is who is calling, what they may reach, and what a refusal looks like on
//! the wire.
//!
//! # A receiver is a client, and a stream belongs to one receiver
//!
//! §8 says the management API "MUST be protected by standard HTTP
//! authorization" and that the authorization "MUST associate the Event
//! Receiver with the stream identifiers it may act on". Here that is five
//! checks, in this order, each reading only what the one before it
//! established — the same order and the same functions the Grant Management
//! API uses, because it is the same problem:
//!
//! 1. **The token verifies** — signature, `typ`, `iss`, `exp` — through
//!    [`access_token::verify`].
//! 2. **The caller holds it** (RFC 9449 §7.1, RFC 8705 §3): the token's `cnf`
//!    decides what must be presented beside it. A receiver's token comes from
//!    `client_credentials`, which this server refuses to issue unbound at all.
//! 3. **The token is for this resource.** `aud` must be this tenant's stream
//!    configuration endpoint. A receiver's token for a business API is a
//!    perfectly good token and is not one this endpoint answers.
//! 4. **It has not been withdrawn** — the `jti` denylist and the two cutoffs.
//! 5. **It carries [`stream::SCOPE_MANAGE`]**, and the `client_id` it names is
//!    the receiver every subsequent statement is scoped to.
//!
//! The fifth is the frontier this endpoint exists to hold: the `client_id` is
//! in the `WHERE` clause of every read and every write
//! (`asterius_store_pg::ssf_streams`), so another receiver's stream is not a
//! row that comes back and gets refused — it is a row that does not exist, and
//! §8.1.1.2's 404 is the truthful answer rather than a chosen one. See
//! `docs/threat-model.md`.
//!
//! # Nothing here is cached
//!
//! §8.1.1.2 requires `Cache-Control: no-store` on the response, and every
//! response from this module carries it. A stream configuration names a
//! receiver's push endpoint and the event types it watches; a cached copy in a
//! shared proxy is a description of one tenant's monitoring handed to whoever
//! asks next.

use crate::http::access_token;
use crate::http::dpop::{self, DpopEndpoint, NONCE_HEADER, USE_NONCE};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::keys::KeyStore;
use asterius_domain::{ClientId, DomainError, GrantId, Tenant};
use asterius_jose::verify::Verified;
use asterius_oidc::userinfo::{self, Presentation, UserInfoError};
use asterius_ssf::stream::{
    self, StreamConfiguration, StreamError, StreamId, StreamRequest, Transmitter,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use time::OffsetDateTime;

/// Where the stream configuration endpoint is mounted, under the tenant.
///
/// Not in [`asterius_oidc::metadata::Endpoint`], deliberately: SSF 1.0 §7.1
/// advertises this URL in the *transmitter's* document
/// (`/.well-known/ssf-configuration`), and adding it to the OP registry would
/// publish it in a document that does not define the member. The parity the
/// registry buys is kept by
/// [`asterius_ssf::transmitter_metadata`], which is handed this path and
/// mounts and advertises from the one constant.
pub const CONFIGURATION_PATH: &str = "/ssf/streams";

/// Where a receiver polls for its events (RFC 8936).
///
/// Named here and rendered into every poll stream's `delivery.endpoint_url`,
/// because §8.1.1.1 requires the creation response to carry it. The route
/// itself is `ast-0ju.7`; until then a receiver that starts polling gets a 404
/// rather than a stream that silently delivers nothing.
pub const POLL_PATH: &str = "/ssf/poll";

/// The largest stream configuration body this endpoint reads.
///
/// Eight kibibytes. `asterius_ssf::stream` bounds every member it keeps, but
/// it bounds them *after* `serde_json` has parsed the whole body, and an
/// endpoint reachable with one access token should not read an arbitrary
/// number of them.
pub const MAX_BODY_BYTES: usize = 8 * 1024;

/// The query parameter that addresses one stream on a `GET` or a `DELETE`
/// (§8.1.1.2, §8.1.1.5).
const STREAM_ID_PARAMETER: &str = "stream_id";

/// The rows this endpoint reads and writes.
///
/// Narrow on purpose, like UserInfo's and Grant Management's ports: every
/// method takes the receiver, so there is no call this endpoint can make that
/// is not already scoped to the caller.
/// What an SSF endpoint asks about the token a receiver presented, beyond
/// verifying it.
///
/// Its own trait because both SSF endpoints ask exactly these two questions
/// and nothing else about a credential: the stream configuration endpoint here
/// and the polling endpoint in [`crate::http::ssf_poll`], which shares
/// [`authorize_receiver`] with it. Splitting it out is what lets one function
/// hold the five checks for both, rather than each endpoint holding its own
/// copy — and a copy that drifts is a copy that stops checking something.
#[async_trait::async_trait]
pub trait SsfTokenStatus: std::fmt::Debug + Send + Sync {
    /// Whether this `jti` was revoked before its own expiry.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the denylist cannot be read. Never `false` for an
    /// unavailable store.
    async fn is_denylisted(&self, jti: &str) -> Result<bool, DomainError>;

    /// The instant before which this client and this grant withdrew every
    /// access token they had issued, if either of them did.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the mark cannot be read.
    async fn access_tokens_revoked_before(
        &self,
        client: &ClientId,
        grant: Option<&GrantId>,
    ) -> Result<Option<OffsetDateTime>, DomainError>;
}

#[async_trait::async_trait]
pub trait SsfStreamStore: SsfTokenStatus {
    /// Stores a new stream (§8.1.1.1).
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] when this receiver already has a stream for
    /// this audience, which the caller turns into §8.1.1.1's 409.
    async fn create(
        &self,
        receiver: &ClientId,
        stream: &StreamConfiguration,
    ) -> Result<(), DomainError>;

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

    /// Every stream this receiver holds (§8.1.1.2).
    ///
    /// # Errors
    ///
    /// As [`Self::find`].
    async fn list(&self, receiver: &ClientId) -> Result<Vec<StreamConfiguration>, DomainError>;

    /// Writes an updated stream. `false` is "no such stream for this
    /// receiver".
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the write fails.
    async fn save(
        &self,
        receiver: &ClientId,
        stream: &StreamConfiguration,
    ) -> Result<bool, DomainError>;

    /// Removes a stream and abandons what it still owed (§8.1.1.5). `false` is
    /// "no such stream for this receiver".
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the transaction fails, in which case nothing was
    /// removed and the caller must not answer 204.
    async fn delete(&self, receiver: &ClientId, stream: &StreamId) -> Result<bool, DomainError>;
}

/// What one stream configuration request needs.
pub struct SsfContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The rows.
    pub store: &'a dyn SsfStreamStore,
    /// Where the tenant's published keys come from, so a token this server
    /// signed is verified against the same set `/jwks` serves.
    pub keys: &'a dyn KeyStore,
    /// Checks the DPoP proof (RFC 9449 §7.1).
    pub dpop: &'a DpopEndpoint,
    /// The trail. Every change to a stream is recorded.
    pub audit: &'a dyn AuditSink,
    /// The client certificate this request arrived with, if the deployment saw
    /// one from a source it trusts (RFC 8705 §2).
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    /// The event types this deployment can deliver, which is one half of
    /// §8.1.1's `events_delivered`.
    ///
    /// Passed in rather than read from [`stream::SUPPORTED_EVENTS`] here, so
    /// that a test can stand a transmitter up with emitters this build does
    /// not have yet and still assert the intersection rule.
    pub events_supported: &'a BTreeSet<String>,
    /// One clock reading for the whole request.
    pub now: OffsetDateTime,
}

impl std::fmt::Debug for SsfContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfContext")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// The URLs one request needs, built once and borrowed by everything that
/// renders.
///
/// A struct rather than a method, because [`Transmitter`] borrows its strings
/// and a method returning one would be handing out a reference to a temporary.
#[derive(Debug)]
struct Urls {
    /// This tenant's stream configuration endpoint: the `aud` a token must
    /// carry, and the URL a DPoP proof is made over.
    configuration: String,
    /// This tenant's polling endpoint (RFC 8936).
    poll: String,
}

impl Urls {
    fn of(tenant: &Tenant) -> Self {
        Self {
            configuration: format!("{}{CONFIGURATION_PATH}", tenant.issuer.as_str()),
            poll: format!("{}{POLL_PATH}", tenant.issuer.as_str()),
        }
    }
}

/// Why a request stopped.
#[derive(Debug)]
enum Refused {
    /// An RFC 6750 §3 refusal: 400, 401 or 403, in a `WWW-Authenticate`.
    Client(UserInfoError),
    /// The token does not carry [`stream::SCOPE_MANAGE`].
    MissingScope,
    /// §8.1.1's 404: no such stream, or not this receiver's.
    NotFound,
    /// §8.1.1.1's and §8.1.1.3's 400, with the reason the model gave.
    Invalid(StreamError),
    /// §8.1.1.1's 409: this receiver already has a stream for this audience.
    Conflict,
    /// A verb this endpoint does not answer.
    MethodNotAllowed,
    /// A DPoP proof that did not check out (RFC 9449 §7.1).
    Dpop(dpop::Refusal),
    /// This deployment could not finish. Logged, never described.
    Server(DomainError),
}

impl From<DomainError> for Refused {
    fn from(error: DomainError) -> Self {
        match error {
            DomainError::Conflict(_) => Self::Conflict,
            other => Self::Server(other),
        }
    }
}

impl From<UserInfoError> for Refused {
    fn from(error: UserInfoError) -> Self {
        Self::Client(error)
    }
}

impl From<StreamError> for Refused {
    fn from(error: StreamError) -> Self {
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

/// The whole endpoint: `POST`, `GET`, `PATCH`, `PUT` and `DELETE` at
/// [`CONFIGURATION_PATH`].
///
/// One function rather than five handlers, because the five share the
/// authorization above and differ only in what they do afterwards — and
/// because a verb that skipped one of those checks would be the bug this
/// arrangement exists to make impossible.
///
/// Never returns `Err`: every failure is an HTTP response.
pub async fn streams(
    context: SsfContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    query: Option<&str>,
    body: &[u8],
) -> Response {
    let urls = Urls::of(context.tenant);
    let receiver = match authorize(&context, &urls, method, headers).await {
        Ok(receiver) => receiver,
        Err(refusal) => return render(&context, refusal),
    };

    let answer = match *method {
        Method::POST => create(&context, &urls, &receiver, body).await,
        Method::GET => read(&context, &urls, &receiver, query).await,
        Method::PATCH => update(&context, &urls, &receiver, body, Change::Patch).await,
        Method::PUT => update(&context, &urls, &receiver, body, Change::Replace).await,
        Method::DELETE => remove(&context, &receiver, query).await,
        _ => Err(Refused::MethodNotAllowed),
    };

    match answer {
        Ok(response) => response,
        Err(refusal) => render(&context, refusal),
    }
}

/// Which of the two update verbs is being served (§8.1.1.3, §8.1.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    /// `PATCH`: the members the request carries change, the rest are left.
    Patch,
    /// `PUT`: the request is the whole receiver-supplied set.
    Replace,
}

/// The five checks the module documentation lists, for this endpoint.
async fn authorize(
    context: &SsfContext<'_>,
    urls: &Urls,
    method: &Method,
    headers: &HeaderMap,
) -> Result<ClientId, Refused> {
    authorize_receiver(
        &Credential {
            tenant: context.tenant,
            keys: context.keys,
            dpop: context.dpop,
            certificate: context.certificate,
            tokens: context.store,
            resource: &urls.configuration,
            target: dpop::ProofTarget::at_path(CONFIGURATION_PATH),
            scope: stream::SCOPE_MANAGE,
            now: context.now,
        },
        method,
        headers,
    )
    .await
    .map_err(Refused::from)
}

/// What one SSF endpoint's authorization needs, whichever endpoint it is.
///
/// The *resource*, the *proof target* and the *scope* are the three things
/// that differ between the stream configuration endpoint and the polling
/// endpoint; everything else about the five checks is the same, so everything
/// else is [`authorize_receiver`]'s.
pub(crate) struct Credential<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// Where the tenant's published keys come from.
    pub keys: &'a dyn KeyStore,
    /// Checks the DPoP proof (RFC 9449 §7.1).
    pub dpop: &'a DpopEndpoint,
    /// The client certificate this request arrived with, if any (RFC 8705 §2).
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    /// The denylist and the revocation cutoffs.
    pub tokens: &'a dyn SsfTokenStatus,
    /// The `aud` the token must carry: this endpoint's URL.
    pub resource: &'a str,
    /// The URL a DPoP proof is made over, built from the issuer and never from
    /// the request.
    pub target: dpop::ProofTarget<'a>,
    /// The scope SSF 1.0 §7.1.1 requires here.
    pub scope: &'a str,
    /// One clock reading for the whole request.
    pub now: OffsetDateTime,
}

/// Why an SSF request was not authorized.
///
/// Three client-visible shapes and one server failure, which each endpoint
/// renders in its own error vocabulary.
#[derive(Debug)]
pub(crate) enum NotAuthorized {
    /// An RFC 6750 §3 refusal: 400, 401 or 403.
    Client(UserInfoError),
    /// The token verified and does not carry the scope this endpoint needs.
    MissingScope,
    /// A DPoP proof that did not check out (RFC 9449 §7.1).
    Dpop(dpop::Refusal),
    /// This deployment could not finish. Logged, never described.
    Server(DomainError),
}

impl From<DomainError> for NotAuthorized {
    fn from(error: DomainError) -> Self {
        Self::Server(error)
    }
}

impl From<UserInfoError> for NotAuthorized {
    fn from(error: UserInfoError) -> Self {
        Self::Client(error)
    }
}

/// The five checks the module documentation lists, in that order, for either
/// SSF endpoint.
///
/// Returns the receiver: the `client_id` the token names, which every
/// subsequent statement of either endpoint is scoped to.
pub(crate) async fn authorize_receiver(
    credential: &Credential<'_>,
    method: &Method,
    headers: &HeaderMap,
) -> Result<ClientId, NotAuthorized> {
    let offered = headers.get_all(header::AUTHORIZATION).iter().count();
    let authorizations: Vec<&str> = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    // A header that is not UTF-8 is not a credential, and dropping it silently
    // would turn a request that presented one into a request that presented
    // none — which is a different refusal.
    if authorizations.len() != offered {
        return Err(UserInfoError::MalformedCredential.into());
    }
    let presented = userinfo::present(&authorizations, None)?;

    // Step 1.
    let verified = access_token::verify(
        credential.tenant,
        credential.keys,
        presented.token(),
        credential.now,
    )
    .await
    .map_err(|rejected| match rejected {
        access_token::Rejected::Unavailable(error) => NotAuthorized::Server(error),
        access_token::Rejected::Token(error) => {
            // Debug, not warn: a rejected token is routine at a resource
            // server, and which check failed is a description of this server's
            // state an unauthenticated caller has not earned.
            tracing::debug!(%error, "an SSF access token did not verify");
            UserInfoError::InvalidToken.into()
        }
    })?;

    // Step 2.
    sender_constrained(credential, method, headers, &verified, presented).await?;

    // Step 3.
    if !audienced_here(credential.resource, &verified) {
        tracing::debug!(
            tenant = %credential.tenant.id,
            "a token presented at an SSF endpoint is audienced elsewhere"
        );
        return Err(UserInfoError::InvalidToken.into());
    }

    // Step 4.
    let jti = verified
        .claim_str("jti")
        .ok_or(UserInfoError::InvalidToken)?;
    if credential.tokens.is_denylisted(jti).await? {
        return Err(UserInfoError::InvalidToken.into());
    }
    let client = verified
        .claim_str("client_id")
        .ok_or(UserInfoError::InvalidToken)?;
    let client = ClientId::new(client.to_owned());
    let own_grant = verified
        .claim_str("grant_id")
        .map(|id| GrantId::new(id.to_owned()));
    let cutoff = credential
        .tokens
        .access_tokens_revoked_before(&client, own_grant.as_ref())
        .await?;
    if access_token::withdrawn(&verified, cutoff) {
        return Err(UserInfoError::InvalidToken.into());
    }

    // Step 5.
    if !carries_scope(&verified, credential.scope) {
        return Err(NotAuthorized::MissingScope);
    }
    Ok(client)
}

/// Step 2, with UserInfo's rule and UserInfo's function.
async fn sender_constrained(
    credential: &Credential<'_>,
    method: &Method,
    headers: &HeaderMap,
    verified: &Verified,
    presented: Presentation<'_>,
) -> Result<(), NotAuthorized> {
    access_token::check_sender_constraint(
        &access_token::Presented {
            tenant: credential.tenant,
            dpop: credential.dpop,
            // The URL the router mounts, built from the issuer here as
            // everywhere: never from the request.
            target: credential.target,
            certificate: credential.certificate,
            method,
            headers,
            presented,
            now: credential.now,
        },
        verified,
    )
    .await
    .map_err(|refusal| match refusal {
        access_token::NotBound::Refused => UserInfoError::InvalidToken.into(),
        access_token::NotBound::Dpop(refusal) => NotAuthorized::Dpop(refusal),
    })
}

/// Step 3: the resource is the endpoint the token was presented at.
///
/// `aud` may be a string or an array (RFC 7519 §4.1.3), and both are accepted
/// because both are what a token this server minted can carry.
fn audienced_here(resource: &str, verified: &Verified) -> bool {
    match verified.claims.get("aud") {
        Some(Value::String(only)) => only == resource,
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .any(|value| value == resource),
        _ => false,
    }
}

/// Step 5: RFC 8693 §4.2's `scope` claim, split on spaces (RFC 6749 §3.3).
fn carries_scope(verified: &Verified, wanted: &str) -> bool {
    verified
        .claim_str("scope")
        .unwrap_or_default()
        .split(' ')
        .any(|scope| scope == wanted)
}

// ---------------------------------------------------------------------------
// The verbs
// ---------------------------------------------------------------------------

/// `POST` — §8.1.1.1.
///
/// > The Event Transmitter responds with a 201 Created and the Stream
/// > Configuration in the body.
///
/// The default audience is the receiver's own `client_id`: §8.1.1 makes `aud`
/// the audience of every SET the stream carries, and the client identifier is
/// the one value the transmitter knows the receiver answers to. A receiver
/// that verifies SETs against something else says so with `aud` on this
/// request, and then never changes it.
async fn create(
    context: &SsfContext<'_>,
    urls: &Urls,
    receiver: &ClientId,
    body: &[u8],
) -> Result<Response, Refused> {
    let request = parse(body)?;
    let stream =
        StreamConfiguration::create(&request, receiver.as_str(), &transmitter(context, urls))?;
    context.store.create(receiver, &stream).await?;
    record(
        context,
        receiver,
        EventType::SSF_STREAM_CREATED,
        &stream.stream_id,
    )
    .await;
    Ok(no_store(
        (
            StatusCode::CREATED,
            axum::Json(Value::Object(stream.render(&transmitter(context, urls)))),
        )
            .into_response(),
    ))
}

/// `GET` — §8.1.1.2.
///
/// With `stream_id`, the stream it names; without, every stream this receiver
/// holds, which is an empty array for a receiver that has none. A receiver
/// with no stream is not an error: it is the state every receiver is in before
/// its first `POST`.
async fn read(
    context: &SsfContext<'_>,
    urls: &Urls,
    receiver: &ClientId,
    query: Option<&str>,
) -> Result<Response, Refused> {
    let transmitter = transmitter(context, urls);
    let addressed = match addressed(query) {
        Addressed::Absent => {
            let streams = context.store.list(receiver).await?;
            let rendered: Vec<Value> = streams
                .iter()
                .map(|stream| Value::Object(stream.render(&transmitter)))
                .collect();
            return Ok(no_store(axum::Json(rendered).into_response()));
        }
        Addressed::Unknown => return Err(Refused::NotFound),
        Addressed::Stream(id) => id,
    };

    let stream = context
        .store
        .find(receiver, &addressed)
        .await?
        .ok_or(Refused::NotFound)?;
    Ok(no_store(
        axum::Json(Value::Object(stream.render(&transmitter))).into_response(),
    ))
}

/// `PATCH` — §8.1.1.3 — and `PUT` — §8.1.1.4.
///
/// Both take the `stream_id` from the *body*, which is where both sections put
/// it, and both refuse a request that carries a transmitter-supplied member
/// with a value that is not the current one. What differs is only what happens
/// to a receiver-supplied member the request does not carry, and that
/// difference is [`Change`].
async fn update(
    context: &SsfContext<'_>,
    urls: &Urls,
    receiver: &ClientId,
    body: &[u8],
    change: Change,
) -> Result<Response, Refused> {
    let transmitter = transmitter(context, urls);
    let request = parse(body)?;
    let addressed = request.addressed_stream()?;
    let current = context
        .store
        .find(receiver, addressed)
        .await?
        .ok_or(Refused::NotFound)?;

    let updated = match change {
        Change::Patch => current.patch(&request, &transmitter)?,
        Change::Replace => current.replace(&request, &transmitter)?,
    };
    if !context.store.save(receiver, &updated).await? {
        // The stream was there a moment ago and is not now: another request
        // deleted it. The same 404 a read would get.
        return Err(Refused::NotFound);
    }
    record(
        context,
        receiver,
        EventType::SSF_STREAM_UPDATED,
        &updated.stream_id,
    )
    .await;
    Ok(no_store(
        axum::Json(Value::Object(updated.render(&transmitter))).into_response(),
    ))
}

/// `DELETE` — §8.1.1.5.
///
/// > The Event Transmitter responds with a 204 No Content.
///
/// Whatever the stream still owed is abandoned in the same transaction, which
/// is the store's doing: §8.1.1.5 makes "no more events" part of the delete
/// rather than something a worker notices later.
async fn remove(
    context: &SsfContext<'_>,
    receiver: &ClientId,
    query: Option<&str>,
) -> Result<Response, Refused> {
    let addressed = match addressed(query) {
        // §8.1.1.5 addresses the stream in the query, so a `DELETE` without
        // one is a request that names nothing rather than a 404: there is no
        // stream it could have meant.
        Addressed::Absent => return Err(Refused::Invalid(StreamError::MissingStreamId)),
        Addressed::Unknown => return Err(Refused::NotFound),
        Addressed::Stream(id) => id,
    };
    if !context.store.delete(receiver, &addressed).await? {
        return Err(Refused::NotFound);
    }
    record(context, receiver, EventType::SSF_STREAM_DELETED, &addressed).await;
    Ok(no_store(StatusCode::NO_CONTENT.into_response()))
}

/// What this tenant contributes to a rendered stream.
fn transmitter<'a>(context: &'a SsfContext<'_>, urls: &'a Urls) -> Transmitter<'a> {
    Transmitter {
        issuer: context.tenant.issuer.as_str(),
        poll_endpoint: &urls.poll,
        events_supported: context.events_supported,
    }
}

/// The body, as a §8.1.1 request.
///
/// The size guard comes first: everything below it parses, and a bound applied
/// after parsing is a bound applied after the work.
fn parse(body: &[u8]) -> Result<StreamRequest, Refused> {
    if body.len() > MAX_BODY_BYTES {
        return Err(Refused::Invalid(StreamError::TooLong { member: "body" }));
    }
    // An empty body is an empty object: §8.1.1.1's minimal `POST` asks for a
    // stream with every default, and a receiver sending no body means exactly
    // that. `PATCH` and `PUT` still need a `stream_id`, and not finding one
    // here is what says so.
    if body.is_empty() {
        return Ok(StreamRequest::default());
    }
    let value: Value =
        serde_json::from_slice(body).map_err(|_| Refused::Invalid(StreamError::NotAnObject))?;
    Ok(StreamRequest::parse(&value)?)
}

/// What a query string says about which stream is addressed.
///
/// Three answers, because they are three different requests — and a named
/// enum rather than an `Option<Option<_>>`, because "absent" and "present and
/// unusable" are the two a reader would otherwise have to keep straight by
/// nesting depth.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Addressed {
    /// No `stream_id` at all: §8.1.1.2's list, and §8.1.1.5's error.
    Absent,
    /// A `stream_id` that is not one this server issues. It cannot name a
    /// row, so it is a 404 without a lookup — the shape check costs a length
    /// comparison where a query costs a round trip.
    Unknown,
    /// One to look up.
    Stream(StreamId),
}

/// The `stream_id` a query string addresses.
fn addressed(query: Option<&str>) -> Addressed {
    let Some(query) = query else {
        return Addressed::Absent;
    };
    let Some(raw) = url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == STREAM_ID_PARAMETER)
        .map(|(_, value)| value.into_owned())
    else {
        return Addressed::Absent;
    };
    StreamId::parse(&raw).map_or(Addressed::Unknown, Addressed::Stream)
}

/// One entry in the trail, for a change a receiver made.
///
/// The actor is the client: a receiver acting on its own token is who made
/// this request, and there is no person to name. The stream is recorded as a
/// fingerprint rather than as its identifier — it is a 128-bit opaque value in
/// a URL a receiver holds, and `asterius_domain::audit::redaction` says
/// exactly that about long opaque values — which still answers "was it the
/// same stream" across entries.
///
/// Never fails the request: the change is already committed by the time this
/// runs, and refusing the receiver because the trail is unavailable would
/// leave it believing a stream it has created does not exist.
async fn record(
    context: &SsfContext<'_>,
    receiver: &ClientId,
    event_type: EventType,
    stream: &StreamId,
) {
    let event = AuditEvent::new(
        context.tenant.id.clone(),
        event_type,
        Outcome::Success,
        Actor::Client(receiver.clone()),
        context.now,
    )
    .client(receiver.clone())
    .detail(Detail::new().credential("stream_id", stream.as_str()));

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            client = %receiver,
            "a stream configuration change was not written to the audit trail"
        );
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// One refusal, in §8.1.1's error table.
///
/// Everything about the *credential* answers the way RFC 6750 §3 says a
/// protected resource does: a status, a challenge in `WWW-Authenticate`, and
/// no body. The 404 is about a *stream* rather than a credential and carries
/// no challenge, for the reason the Grant Management endpoint gives: it would
/// invite a client to retry with a better token for a stream that is not
/// there.
fn render(context: &SsfContext<'_>, refusal: Refused) -> Response {
    match refusal {
        Refused::Client(error) => refuse(&error),
        Refused::MissingScope => insufficient_scope(),
        Refused::NotFound => no_store(StatusCode::NOT_FOUND.into_response()),
        Refused::Invalid(error) => invalid_request(&error),
        // §8.1.1.1: "409 Conflict — the transmitter does not support multiple
        // streams for the same receiver". The description names the rule
        // rather than the other stream: a receiver that reads its list learns
        // which one it already has, and a caller that cannot read the list has
        // not earned the fact that one exists.
        Refused::Conflict => problem(
            StatusCode::CONFLICT,
            "conflict",
            "this receiver already has a stream for this audience",
        ),
        Refused::MethodNotAllowed => no_store(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        Refused::Dpop(refusal) => dpop_challenge(&refusal),
        Refused::Server(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "cannot answer a stream configuration request"
            );
            unavailable()
        }
    }
}

/// §8.1.1's 400, with the model's own reason.
///
/// The reason is safe to return: [`StreamError`] names members and never
/// echoes a value, which is what keeps a receiver's `description` — and a
/// misdirected credential — out of a response and out of a log.
fn invalid_request(error: &StreamError) -> Response {
    problem(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        &error.to_string(),
    )
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

/// RFC 6750 §3.1's `insufficient_scope` challenge, naming the scope the
/// endpoint needs.
///
/// Shared with [`crate::http::ssf_poll`], which needs the same challenge with
/// [`stream::SCOPE_POLL`] in it: SSF 1.0 §7.1.1 protects both endpoints, and a
/// receiver reading "you need this scope" should read the same sentence
/// whichever of them it called.
pub(crate) fn check_scope_challenge(scope: &str) -> String {
    format!(
        r#"DPoP error="insufficient_scope", error_description="the access token does not carry the scope this request needs", scope="{scope}""#
    )
}

/// RFC 6750 §3.1's `insufficient_scope`, naming the scope §8 needs.
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
        tracing::debug!(%detail, "a DPoP proof at the SSF management endpoint did not check out");
    }
    if refusal.status().is_server_error() {
        // The replay store is unreachable. Not the client's problem, and not a
        // challenge: a better proof will not help.
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

/// Every response, without exception (§8.1.1.2).
fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
