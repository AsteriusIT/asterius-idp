//! `POST /revoke` — the revocation endpoint (RFC 7009).
//!
//! A client hands back a credential it no longer wants to hold. What lives
//! here is everything that needs the outside world — the client
//! authentication, the refresh token row, the tenant's keys, the denylist and
//! the trail; what a request must look like and what a presented value could
//! be is [`asterius_oidc::revocation`], which is pure and tested as such.
//!
//! # Almost everything is a 200
//!
//! RFC 7009 §2.2: "The authorization server responds with HTTP status code 200
//! if the token has been revoked successfully or if the client submitted an
//! invalid token." §2.2 also says "the client MUST NOT be able to revoke a
//! token issued to another client" and that such a request is to be treated as
//! one carrying an invalid token.
//!
//! Put together: an unknown token, an expired one, one belonging to another
//! client and one this server never issued all get the same empty 200. That is
//! not politeness. This endpoint is reachable by any registered client, and an
//! answer that distinguished "revoked" from "no such token" would answer "is
//! this string a live credential here?" for anybody with a registration —
//! which is exactly the question a thief holding a stolen value has.
//!
//! The two exceptions are §2.2.1's: `invalid_request` for a request that is
//! not one, and `unsupported_token_type` for a token whose type is identified
//! and cannot be revoked. Neither says anything about whether a *credential*
//! exists.
//!
//! # What revocation withdraws, and what it leaves standing
//!
//! A refresh token: its row is stamped. The grant behind it is left alone, on
//! the strength of Grant Management ID1 §6.5's Note — token revocation "need
//! not" revoke the grant — and because leaving it means a client that signs a
//! user out can reconnect without a second consent screen for an authorization
//! that was never withdrawn. Revoking the *grant* is a different act with a
//! different endpoint and a different audit event.
//!
//! An access token: its `jti` goes on the denylist until its own `exp`, which
//! is the only thing that can withdraw a stateless JWT (RFC 9068 §6) and is
//! consulted wherever this server verifies one itself — today, UserInfo.
//!
//! # The other access tokens minted from the same grant
//!
//! RFC 7009 §2.1's second SHOULD — "also invalidate all access tokens based on
//! the same authorization grant" — cannot be a list. There is no record of
//! those tokens: RFC 9068 access tokens are stateless by design, and the only
//! `jti` this deployment ever holds is the one a caller presents.
//! `PgGrantRepository::revoke` takes the live set as a parameter for the same
//! reason.
//!
//! So the refresh token's revocation writes a *cutoff* on its grant instead,
//! in the transaction that stamps the row (`ast-m9c.13`): every access token
//! that grant minted at or before that instant stops verifying, wherever this
//! server checks one. It is one row per revocation rather than one per token,
//! it does not grow with traffic, and it leaves the grant itself standing —
//! which is the point above.

use crate::http::access_token;
use crate::http::token::{error as oauth_error, is_form_encoded, no_store};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::keys::KeyStore;
use asterius_domain::{Client, ClientId, ClientRepository, DomainError, GrantId, Tenant};
use asterius_jose::verify::Verified;
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::form::Parameters;
use asterius_oidc::revocation::{self, Presented, RevocationError, TokenTypeHint};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

/// The largest form body this endpoint will read.
///
/// A revocation request carries a token and a client assertion and nothing
/// else. The same bound as the token endpoint, because the assertion is the
/// same assertion.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// The writes a revocation makes.
///
/// A port rather than the repositories themselves, so that this endpoint holds
/// exactly two verbs: it cannot reach `redeem`, and it cannot reach a grant's
/// `revoke` — which is the operation RFC 7009 deliberately does *not* perform.
#[async_trait::async_trait]
pub trait RevocationStore: std::fmt::Debug + Send + Sync {
    /// Revokes a refresh token belonging to `client`.
    ///
    /// Returns the grant it drew on when a row matched, and `None` when
    /// nothing of this tenant answers to that digest *and* that client — which
    /// is RFC 7009 §2.2's "invalid token", whether the value was never issued
    /// or was issued to somebody else.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the store could not be written. Never `None` for
    /// an unavailable store: a client told 200 does not retry, and the token
    /// would stay live.
    async fn revoke_refresh_token(
        &self,
        digest: &str,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Option<GrantId>, DomainError>;

    /// Puts an access token's `jti` on the denylist until `expires_at`.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the store could not be written.
    async fn denylist_access_token(
        &self,
        jti: &str,
        grant: Option<&GrantId>,
        revoked_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError>;
}

/// What one revocation request needs.
pub struct RevocationContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This tenant's clients, for the authenticator.
    pub clients: &'a dyn ClientRepository,
    /// The two writes.
    pub store: &'a dyn RevocationStore,
    /// The tenant's published keys, so an access token presented here is
    /// verified against the same set `/jwks` serves and UserInfo reads.
    pub keys: &'a dyn KeyStore,
    /// The trail. Every revocation is recorded, including the ones that
    /// revoked nothing.
    pub audit: &'a dyn AuditSink,
    /// One clock reading for the whole request.
    pub now: OffsetDateTime,
    /// The client certificate this request arrived with (RFC 8705 §2), if the
    /// deployment saw one from a source it trusts.
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
}

impl std::fmt::Debug for RevocationContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationContext")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// What the request turned out to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Done {
    /// A refresh token was stamped.
    RefreshTokenRevoked,
    /// An access token's `jti` was denylisted.
    AccessTokenDenylisted,
    /// Nothing: an unknown value, another client's, or one already past its
    /// own expiry. RFC 7009 §2.2's "invalid token".
    Nothing,
}

impl Done {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RefreshTokenRevoked => "refresh_token",
            Self::AccessTokenDenylisted => "access_token",
            Self::Nothing => "nothing",
        }
    }
}

/// Answers a revocation request.
///
/// `authenticate` is the token endpoint's authenticator, passed in by the
/// wiring. RFC 7009 §2.1 requires client authentication here and this
/// deployment has exactly one implementation of it — `private_key_jwt`, and
/// mTLS behind its flag — so this endpoint does not get a second opinion about
/// who a caller is.
///
/// Never returns `Err`: every outcome is a `Response`.
pub async fn revoke(
    context: RevocationContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    authenticate: impl AsyncFnOnce(&Attempt<'_>, &AssertionRules) -> Result<Client, ClientAuthError>,
) -> Response {
    if body.len() > MAX_BODY_BYTES {
        return oauth_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "body too large",
        );
    }
    if !is_form_encoded(headers) {
        return oauth_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request",
            "content-type must be application/x-www-form-urlencoded",
        );
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "body is not UTF-8",
        );
    };
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    // RFC 7009 §2.1: the client authenticates, before anything is looked up.
    // Everything below is a statement about a client that has proved who it
    // is, which is what makes "is this your token?" a question worth asking.
    let attempt = Attempt {
        assertion: find(&pairs, "client_assertion"),
        assertion_type: find(&pairs, "client_assertion_type"),
        client_id: find(&pairs, "client_id"),
        authorization_header: headers.contains_key(header::AUTHORIZATION),
        certificate: context.certificate,
    };
    let rules = AssertionRules::for_issuer(context.tenant.issuer.as_str());
    let client = match authenticate(&attempt, &rules).await {
        Ok(client) => client,
        Err(failure) => {
            return oauth_error(
                StatusCode::from_u16(failure.status()).unwrap_or(StatusCode::BAD_REQUEST),
                failure.code(),
                "client authentication failed",
            );
        }
    };

    let params = Parameters::from_pairs(pairs);
    let request = match revocation::parse(&params) {
        Ok(request) => request,
        Err(failure) => return refuse(&failure),
    };

    match act(&context, &client, request.token).await {
        Ok((done, grant)) => {
            record(&context, &client, request.hint, done, grant.as_ref()).await;
            // §2.2: "The content of the response body is ignored by the client
            // as all necessary information is conveyed in the response code."
            // So there is none.
            (StatusCode::OK, no_store()).into_response()
        }
        Err(Stopped::Client(failure)) => refuse(&failure),
        Err(Stopped::Server(error)) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                client = %client.id,
                "a revocation could not be carried out"
            );
            // Deliberately not a 200. A client told its token is gone will
            // stop trying to invalidate it, and the token would outlive the
            // outage.
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "the revocation could not be carried out",
            )
        }
    }
}

/// Why a revocation stopped.
#[derive(Debug)]
enum Stopped {
    /// The request was not one (§2.2.1).
    Client(RevocationError),
    /// This deployment could not finish. Logged, never described.
    Server(DomainError),
}

impl From<DomainError> for Stopped {
    fn from(error: DomainError) -> Self {
        Self::Server(error)
    }
}

/// Revokes whatever was presented, if it is this client's to revoke.
async fn act(
    context: &RevocationContext<'_>,
    client: &Client,
    token: &str,
) -> Result<(Done, Option<GrantId>), Stopped> {
    match revocation::classify(token).map_err(Stopped::Client)? {
        // §2.1: an invalid token is a success with nothing done.
        Presented::Unrecognised => Ok((Done::Nothing, None)),
        Presented::RefreshToken { digest } => {
            // The client is half of the `where` clause, so another client's
            // token matches nothing and is reported as nothing.
            let grant = context
                .store
                .revoke_refresh_token(&digest, &client.id, context.now)
                .await?;
            Ok(grant.map_or((Done::Nothing, None), |grant| {
                (Done::RefreshTokenRevoked, Some(grant))
            }))
        }
        Presented::AccessToken => revoke_access_token(context, client, token).await,
    }
}

/// Denylists a presented access token, if this client is the one it was issued
/// to.
///
/// Verification first, and not as a formality: the `jti` is the key a row is
/// written under, and a `jti` read from an unverified token is a database key
/// chosen by whoever sent the request. A token that does not verify — a
/// forgery, another tenant's, one whose `exp` has passed — is §2.1's invalid
/// token and gets the empty 200 with nothing written.
async fn revoke_access_token(
    context: &RevocationContext<'_>,
    client: &Client,
    token: &str,
) -> Result<(Done, Option<GrantId>), Stopped> {
    let verified =
        match access_token::verify(context.tenant, context.keys, token, context.now).await {
            Ok(verified) => verified,
            Err(access_token::Rejected::Unavailable(error)) => return Err(Stopped::Server(error)),
            Err(access_token::Rejected::Token(error)) => {
                // Debug: a token presented at this endpoint has usually just been
                // discarded by its holder, and being past its `exp` is the
                // ordinary case rather than an incident.
                tracing::debug!(%error, "a token presented for revocation did not verify");
                return Ok((Done::Nothing, None));
            }
        };

    // RFC 7009 §2.2 again: a client may not revoke another client's token.
    // RFC 9068 §2.2 puts the client this was issued to in `client_id`, and it
    // is signed, so this comparison is between two facts.
    if verified.claim_str("client_id") != Some(client.id.as_str()) {
        return Ok((Done::Nothing, None));
    }

    let Some(jti) = verified.claim_str("jti") else {
        // RFC 9068 §2.2 makes `jti` REQUIRED, and the verifier does not check
        // it. A token this server issued always carries one, so this is either
        // another issuer's token that shares this tenant's keys — impossible —
        // or a bug here. Nothing can be denylisted without it.
        tracing::error!(
            tenant = %context.tenant.id,
            client = %client.id,
            "a verified access token carried no jti"
        );
        return Ok((Done::Nothing, None));
    };
    let Some(expires_at) = expiry(&verified) else {
        tracing::error!(
            tenant = %context.tenant.id,
            client = %client.id,
            "a verified access token carried no usable exp"
        );
        return Ok((Done::Nothing, None));
    };
    // Recorded when the token names one — a tenant may not have switched the
    // `grant_id` claim on — because it is what ties the trail entry to the
    // authorization it was minted under.
    let grant = verified
        .claim_str("grant_id")
        .map(|id| GrantId::new(id.to_owned()));

    let written = context
        .store
        .denylist_access_token(jti, grant.as_ref(), context.now, expires_at)
        .await?;

    // `false` is a token already past its `exp`, or one already denylisted.
    // Both are "nothing happened just now", and both are a 200.
    Ok(if written {
        (Done::AccessTokenDenylisted, grant)
    } else {
        (Done::Nothing, grant)
    })
}

/// The token's own `exp`, as an instant.
///
/// The verifier has already refused a token whose `exp` has passed, so this is
/// in the future; it is read again here because it is how long the denylist
/// row has to live. A claim that is not a whole number of seconds is `None`
/// rather than a guess.
fn expiry(verified: &Verified) -> Option<OffsetDateTime> {
    let seconds = verified.claims.get("exp")?.as_i64()?;
    OffsetDateTime::from_unix_timestamp(seconds).ok()
}

/// Writes the trail entry for one revocation.
///
/// Recorded whatever happened, including the requests that revoked nothing: a
/// run of those against one client is somebody trying values, and an endpoint
/// that only records its successes would show none of it.
///
/// Never fails the request. RFC 7009 §2.2 has already been satisfied by the
/// write; refusing the client because the trail is unavailable would leave it
/// believing a token it has discarded is still live.
async fn record(
    context: &RevocationContext<'_>,
    client: &Client,
    hint: TokenTypeHint,
    done: Done,
    grant: Option<&GrantId>,
) {
    let detail = Detail::new()
        .label("token_type_hint", hint.as_str())
        .label("revoked", done.as_str());

    let mut event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::TOKEN_REVOKED,
        Outcome::Success,
        Actor::Client(client.id.clone()),
        context.now,
    )
    .client(client.id.clone())
    .detail(detail);
    if let Some(grant) = grant {
        event = event.grant(grant.clone());
    }

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            client = %client.id,
            "a revocation was not written to the audit trail"
        );
    }
}

/// Renders §2.2.1's error shape, which is RFC 6749 §5.2's.
fn refuse(failure: &RevocationError) -> Response {
    oauth_error(
        StatusCode::from_u16(failure.status()).unwrap_or(StatusCode::BAD_REQUEST),
        failure.code(),
        failure.description(),
    )
}

/// The first value of `name`, for client authentication only.
///
/// The same helper the token endpoint has, and for the same reason: the
/// authenticator takes `&str`, and duplicate detection is
/// [`asterius_oidc::revocation::parse`]'s job on the parameters that decide
/// anything.
fn find<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}
