//! `GET`/`POST /userinfo` — the UserInfo endpoint (OIDC Core §5.3).
//!
//! The authorization server as a resource server for its own claims. What a
//! request must look like and what a refusal says live in
//! [`asterius_oidc::userinfo`]; what lives here is everything that needs the
//! outside world: the tenant's keys, the DPoP proof, the denylist, the grant
//! and the user row.
//!
//! # The order of the checks is the security property
//!
//! 1. **Presentation**, which refuses a token in the query string before it is
//!    parsed (FAPI 2.0 SP §5.3.4).
//! 2. **Signature, `typ`, `iss` and expiry**, through the one JWT verifier
//!    (`asterius_jose::verify`) against the keys this tenant publishes.
//!    Nothing in a token is read as a fact before this.
//! 3. **Sender constraint** (RFC 9449 §7.1): the `cnf` decides which scheme is
//!    acceptable, and a DPoP-bound token needs a proof for its key whose `ath`
//!    hashes the token that arrived.
//! 4. **Revocation** — the `jti` denylist, which is the only thing that can
//!    withdraw a stateless token (FAPI 2.0 SP §5.3.4 item 3).
//! 5. **Scope**, which is `insufficient_scope` and a 403 rather than a 401.
//! 6. **The grant**, and only then the claims.
//!
//! Reordering any of the first four would mean answering a question about a
//! token before establishing that it is one.
//!
//! # Claims come from the grant, and from nowhere else
//!
//! [`asterius_oidc::claims::resolve_for_grant`] is the only claim resolution
//! this file can reach: the current request has no `claims` parameter to
//! consult — OIDC Core §5.5 puts it in the *authorization* request — and the
//! user row is read only through that function, whose inputs are the grant's
//! scopes, the grant's claims request and the grant's locales. So "output ⊆
//! consented" holds here for the same reason it holds at the ID token
//! (`ast-1sk.6`): there is no argument at this call site that could carry
//! anything else.

use crate::http::access_token;
use crate::http::dpop::{self, DpopEndpoint, NONCE_HEADER, USE_NONCE};
use asterius_domain::entities::grant::GrantStatus;
use asterius_domain::keys::{KeyStore, Signer, SigningAlgorithm};
use asterius_domain::{DomainError, Grant, GrantId, Tenant, User, UserId};
use asterius_jose::verify::{VerificationError, Verified};
use asterius_oidc::metadata::Endpoint;
use asterius_oidc::userinfo::{self, Presentation, UserInfoError};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

/// The media type of a signed response (OIDC Core §5.3.2).
pub const JWT_CONTENT_TYPE: &str = "application/jwt";

/// The rows this endpoint reads.
///
/// One port for the three reads, because they are one question — "what was
/// this token minted from, and is it still good" — and because a handler
/// holding a grant repository would hold `revoke` and `claim` with it.
/// UserInfo writes nothing.
#[async_trait::async_trait]
pub trait UserInfoSource: std::fmt::Debug + Send + Sync {
    /// The grant a token names.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the row cannot be read or is not one the model
    /// accepts.
    async fn grant(&self, id: &GrantId) -> Result<Option<Grant>, DomainError>;

    /// The person a grant was made for.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the row cannot be read.
    async fn user(&self, id: UserId) -> Result<Option<User>, DomainError>;

    /// Whether this `jti` was revoked before its own expiry.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the denylist cannot be read. Never `false` for an
    /// unavailable store: a token that could not be checked is not a token
    /// this endpoint answers.
    async fn is_denylisted(&self, jti: &str) -> Result<bool, DomainError>;
}

/// What one UserInfo request needs.
pub struct UserInfoContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The rows.
    pub source: &'a dyn UserInfoSource,
    /// Where the tenant's published keys come from, so a token this server
    /// signed is verified against the same set `/jwks` serves.
    pub keys: &'a dyn KeyStore,
    /// Signs a JWT response.
    pub signer: &'a dyn Signer,
    /// Checks the DPoP proof (RFC 9449 §7.1).
    pub dpop: &'a DpopEndpoint,
    /// The client's `userinfo_signed_response_alg`, when it registered one.
    ///
    /// `None` is OIDC Core §5.3.2's default — "the UserInfo Claims are
    /// returned as a UTF-8 encoded JSON object" — and is what the wiring
    /// passes today, because `userinfo_signed_response_alg` is not yet a
    /// registrable client metadata member. The signing path is exercised by this
    /// endpoint's own tests, so turning it on is a change to registration and
    /// not to this file.
    pub signed_response_alg: Option<SigningAlgorithm>,
    /// One clock reading for the whole request.
    pub now: OffsetDateTime,
}

impl std::fmt::Debug for UserInfoContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserInfoContext")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Answers a UserInfo request.
///
/// `method` is the router's, which is what a DPoP proof's `htm` is compared
/// against; `query` is the raw query string, which exists here only so that it
/// can be refused.
///
/// Never returns `Err`: every failure is a response in RFC 6750 §3's shape.
pub async fn userinfo(
    context: UserInfoContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Response {
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
        return refuse(&UserInfoError::MalformedCredential);
    }

    let presented = match userinfo::present(&authorizations, query) {
        Ok(presented) => presented,
        Err(refusal) => return refuse(&refusal),
    };

    match answer(&context, method, headers, presented).await {
        Ok(response) => response,
        Err(Refused::Client(refusal)) => refuse(&refusal),
        Err(Refused::Dpop(refusal)) => dpop_challenge(&refusal),
        Err(Refused::Server(error)) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot answer a UserInfo request");
            unavailable()
        }
    }
}

/// Why a request stopped.
#[derive(Debug)]
enum Refused {
    /// An RFC 6750 §3 refusal the client can act on.
    Client(UserInfoError),
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

impl From<UserInfoError> for Refused {
    fn from(error: UserInfoError) -> Self {
        Self::Client(error)
    }
}

/// The request, with failures as `Err` so the checks read in order.
async fn answer(
    context: &UserInfoContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    presented: Presentation<'_>,
) -> Result<Response, Refused> {
    let verified = verify_access_token(context, presented.token()).await?;

    // RFC 9449 §7.1 and RFC 8705 §3: the `cnf` says how this token may be
    // presented, so the scheme is judged against the token rather than the
    // other way round.
    check_sender_constraint(context, method, headers, &verified, presented).await?;

    // FAPI 2.0 SP §5.3.4 item 3. After the signature, because a `jti` from an
    // unverified token is an attacker's choice of database key.
    let jti = verified
        .claim_str("jti")
        .ok_or(UserInfoError::InvalidToken)?;
    if context.source.is_denylisted(jti).await? {
        return Err(UserInfoError::InvalidToken.into());
    }

    userinfo::check_scope(verified.claim_str("scope"))?;

    let grant = live_grant(context, &verified).await?;
    let released = release(context, &grant).await?;

    // OIDC Core §5.3.2: `sub` MUST be returned, and §5.3.4 has the client
    // compare it with its ID token's. Both come from `Grant::subject`, which
    // is where the pairwise derivation was recorded at authorization — so the
    // two are one value read twice, not two computations that agree.
    let subject = grant.subject.as_ref().ok_or_else(|| {
        Refused::Server(DomainError::invalid(
            "grant",
            "a UserInfo request reached a grant with no subject",
        ))
    })?;
    if verified.claim_str("sub") != Some(subject.as_str()) {
        // The token was minted from this grant, so its `sub` is this grant's.
        // A disagreement means the row moved underneath a live token, and
        // answering with either value would assert something this server
        // cannot stand behind.
        return Err(Refused::Server(DomainError::invalid(
            "sub",
            "the access token's subject is not the grant's",
        )));
    }

    let body = userinfo::body(subject.as_str(), released);
    render(context, &grant, body).await
}

/// Verifies the access token (RFC 9068 §4).
///
/// The verification itself is [`crate::http::access_token::verify`], shared
/// with the revocation endpoint so that the two cannot hold different opinions
/// about what a token of this tenant is. What is decided here is what a
/// failure *means* at UserInfo: a token that did not verify is
/// `invalid_token`, and a key set that could not be read is this deployment's
/// fault and not the caller's.
async fn verify_access_token(
    context: &UserInfoContext<'_>,
    token: &str,
) -> Result<Verified, Refused> {
    access_token::verify(context.tenant, context.keys, token, context.now)
        .await
        .map_err(|rejected| match rejected {
            access_token::Rejected::Unavailable(error) => Refused::Server(error),
            access_token::Rejected::Token(error) => {
                // Debug, not warn: a rejected token is routine at a resource
                // server, and which check failed is a description of this
                // server's state that an unauthenticated caller has not
                // earned.
                log_rejection(&error);
                UserInfoError::InvalidToken.into()
            }
        })
}

/// Records why a token was rejected, for an operator and for nobody else.
fn log_rejection(error: &VerificationError) {
    tracing::debug!(%error, "a UserInfo access token did not verify");
}

/// Holds the presentation to the token's own `cnf` (RFC 9449 §7.1, RFC 8705 §3).
///
/// A DPoP-bound token is usable only under the `DPoP` scheme and only with a
/// proof for the key it is bound to, whose `ath` hashes the token that
/// actually arrived. A certificate-bound token is refused here: this
/// deployment terminates TLS without requesting a client certificate, so there
/// is nothing to compare `x5t#S256` against, and accepting it anyway is how a
/// sender-constrained token becomes a bearer token (`ast-a05.7`).
async fn check_sender_constraint(
    context: &UserInfoContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    verified: &Verified,
    presented: Presentation<'_>,
) -> Result<(), Refused> {
    let jkt = verified
        .claims
        .get("cnf")
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(Value::as_str);
    let Some(jkt) = jkt else {
        // Every token this server issues carries a `cnf` (FAPI 2.0 SP §5.3.2.1
        // item 4), so one without a `jkt` is either certificate-bound — which
        // this endpoint cannot check — or not sender-constrained at all, which
        // is not a token this profile has.
        return Err(UserInfoError::InvalidToken.into());
    };

    if !presented.is_dpop() {
        // RFC 9449 §7.1: "a DPoP-bound access token ... MUST be presented
        // using the DPoP authentication scheme". A client sending one as a
        // bearer token is asking for the binding to be ignored.
        return Err(UserInfoError::InvalidToken.into());
    }

    let binding = context
        .dpop
        .check_with_access_token(
            context.tenant,
            Endpoint::UserInfo,
            method,
            headers,
            presented.token(),
            context.now,
        )
        .await
        .map_err(Refused::Dpop)?
        // No `DPoP` header at all, beside a token bound to a key.
        .ok_or(UserInfoError::InvalidToken)?;

    if binding.jkt.as_str() != jkt {
        // A valid proof for the wrong key: whoever sent this holds a DPoP key
        // and a token bound to a different one.
        return Err(UserInfoError::InvalidToken.into());
    }
    Ok(())
}

/// The grant the token was minted from, if it is still standing.
///
/// The `grant_id` claim is what makes this a lookup rather than a guess: one
/// person may hold several grants to one client, and choosing among them by
/// subject and scope would sometimes release the claims of an authorization
/// this token was not minted under.
///
/// A revoked or expired grant is `invalid_token` rather than an empty answer:
/// the authorization behind the credential is gone, which is the same fact the
/// denylist carries for a token whose revocation was recorded in time.
async fn live_grant(context: &UserInfoContext<'_>, verified: &Verified) -> Result<Grant, Refused> {
    let Some(id) = verified.claim_str("grant_id") else {
        // A token minted without the claim cannot be answered, and that is
        // this deployment's gap rather than the caller's mistake.
        return Err(Refused::Server(DomainError::invalid(
            "grant_id",
            "the access token names no grant, so its claims cannot be resolved",
        )));
    };
    let grant = context
        .source
        .grant(&GrantId::new(id.to_owned()))
        .await?
        .ok_or(UserInfoError::InvalidToken)?;

    if !matches!(grant.status(context.now), GrantStatus::Active) {
        return Err(UserInfoError::InvalidToken.into());
    }
    // The token names a client and so does the grant. A token whose
    // `client_id` is not the grant's does not belong to this row.
    if verified.claim_str("client_id") != Some(grant.client.as_str()) {
        return Err(UserInfoError::InvalidToken.into());
    }
    Ok(grant)
}

/// The claims this grant releases at UserInfo.
///
/// The second call site of `resolve_for_grant`, which takes the scopes, the
/// claims request and the locales from the grant. Nothing here passes anything
/// from the request, because nothing here has anything from the request to
/// pass.
async fn release(
    context: &UserInfoContext<'_>,
    grant: &Grant,
) -> Result<Map<String, Value>, Refused> {
    let id = grant.user.ok_or_else(|| {
        Refused::Server(DomainError::invalid(
            "grant",
            "a UserInfo request reached a grant with no user",
        ))
    })?;
    let user = context.source.user(id).await?.ok_or_else(|| {
        Refused::Server(DomainError::invalid(
            "user",
            "the user this grant was made for no longer exists",
        ))
    })?;
    let resolved = asterius_oidc::claims::resolve_for_grant(&user, grant).map_err(|error| {
        // The request was validated at PAR and re-serialised canonically onto
        // the grant, so a stored one that no longer parses is a damaged row.
        Refused::Server(DomainError::invalid("claims", error.to_string()))
    })?;
    Ok(resolved.userinfo)
}

/// JSON, or a signed JWT when the client registered an algorithm.
async fn render(
    context: &UserInfoContext<'_>,
    grant: &Grant,
    body: Map<String, Value>,
) -> Result<Response, Refused> {
    let Some(algorithm) = context.signed_response_alg else {
        return Ok(no_store(
            (StatusCode::OK, axum::Json(Value::Object(body))).into_response(),
        ));
    };

    // OIDC Core §5.3.2's `iss` and `aud`, written by the builder rather than
    // at the signer, so a signed and an unsigned response cannot disagree
    // about who they are about.
    let claims = userinfo::signed_claims(&context.tenant.issuer, grant.client.as_str(), body);
    let signed = context
        .signer
        .sign(
            &context.tenant.id,
            Some(algorithm),
            userinfo::RESPONSE_TYP,
            &claims,
        )
        .await?;
    Ok(no_store(
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, JWT_CONTENT_TYPE)],
            signed.as_str().to_owned(),
        )
            .into_response(),
    ))
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// An RFC 6750 §3 refusal: a status, a challenge per scheme, and no body.
///
/// The error lives in `WWW-Authenticate` and nowhere else. RFC 6750 defines no
/// response body for a protected resource, and one carrying an OAuth error
/// object would be a second place for the two to disagree.
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

/// A DPoP failure, in the shape a resource server uses (RFC 9449 §7.1, §7.2).
///
/// Not [`dpop::Refusal::into_response`]: that renders the *authorization*
/// server's RFC 6749 §5.2 error object with a 400, and §7.1 has a resource
/// server answer with a 401 and a `WWW-Authenticate: DPoP` challenge instead.
/// The nonce, in a deployment that issues them, rides along on the header §7.2
/// specifies — and only for the refusal that asks for one, so that this
/// endpoint is not a nonce oracle for requests that never had a proof.
fn dpop_challenge(refusal: &dpop::Refusal) -> Response {
    if let Some(detail) = refusal.detail() {
        tracing::debug!(%detail, "a DPoP proof at UserInfo did not check out");
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
    no_store(
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "temporarily_unavailable"})),
        )
            .into_response(),
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
/// The body is a person's claims and the headers carry a challenge; neither
/// belongs in a cache. RFC 9449 §8.2 requires it of anything carrying a
/// `DPoP-Nonce`, and applying it to all of them is cheaper than remembering
/// which.
fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
