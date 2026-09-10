//! `GET`/`DELETE /grants/{grant_id}` — the Grant Management API (ID1 §6).
//!
//! The authorization server as a resource server for its own authorizations. A
//! client that holds a grant may read what it covers (§6.4) and withdraw it
//! (§6.5); it may do neither to anybody else's.
//!
//! What is *not* here is the vocabulary: the two scopes, the §6.4 body and the
//! `grant_id` shape all live in [`asterius_oidc::grant_management`], which is
//! also where the authorization-request half of the draft is. One draft, one
//! file to change when it moves.
//!
//! # Three credentials in one request, and each is checked against the last
//!
//! 1. **The token verifies** — signature, `typ`, `iss`, `exp` — through the
//!    one verifier every access token this server receives goes through
//!    ([`access_token::verify`]). Nothing in it is a fact before this.
//! 2. **The caller holds it** (RFC 9449 §7.1, RFC 8705 §3): the token's `cnf`
//!    decides what must be presented beside it, and the check is the one
//!    UserInfo makes, from the same function.
//! 3. **The token is for this resource** (§6.2, §6.3). `aud` must name the
//!    grant management endpoint. A `client_credentials` token audienced at a
//!    business API is a perfectly good token and is not one this endpoint
//!    answers — that is what RFC 9068 §5's per-resource audience is for.
//! 4. **It has not been withdrawn** — the `jti` denylist and the two cutoffs,
//!    exactly as UserInfo reads them.
//! 5. **It carries the scope for the verb** (§6.1): `grant_management_query`
//!    for `GET`, `grant_management_revoke` for `DELETE`. A token with one and
//!    not the other can read a grant and not destroy it, which is the whole
//!    reason §6.1 registers two scopes rather than one.
//! 6. **The grant is the caller's** (§6.6). Only then is a row read, and a row
//!    belonging to another client is answered exactly as a row that does not
//!    exist.
//!
//! # Why "somebody else's grant" and "no such grant" are one answer
//!
//! §6.6 gives 404 for "the grant does not exist" and 403 for "the client is
//! not authorized". Taken literally, a client could tell a real `grant_id`
//! from a made-up one by which refusal it got, for every grant in the tenant —
//! an oracle over identifiers this server mints and nobody is meant to
//! enumerate. So 404 covers both, and 403 is kept for the case that is about
//! the *caller* rather than about a row: a token that does not carry the scope
//! for the verb, which the client can see for itself in the token it holds.
//!
//! `PgGrantRepository::revoke` already answers a second revocation with the
//! same `NotFound` for the same reason.
//!
//! # Nothing here is cached, and nothing here is a token
//!
//! §6.4's body is a description of an authorization. The response says
//! `no-store` like every other credential-adjacent answer this server gives,
//! and [`asterius_oidc::grant_management::query_response`] takes a
//! [`Grant`] and nothing else, so there is no argument at that call site that
//! could carry a credential into the body.

use crate::http::access_token;
use crate::http::dpop::{self, DpopEndpoint, NONCE_HEADER, USE_NONCE};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::grant::GrantStatus;
use asterius_domain::keys::KeyStore;
use asterius_domain::{ClientId, DomainError, Grant, GrantId, Tenant};
use asterius_jose::verify::Verified;
use asterius_oidc::grant_management;
use asterius_oidc::metadata::Endpoint;
use asterius_oidc::userinfo::{self, Presentation, UserInfoError};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use time::OffsetDateTime;

/// The rows this endpoint reads and the one write it makes.
///
/// Narrow on purpose, like UserInfo's port: a handler holding a whole grant
/// repository would hold `amend` and `claim` with it, and this endpoint has no
/// business rewriting an authorization.
#[async_trait::async_trait]
pub trait GrantManagementStore: std::fmt::Debug + Send + Sync {
    /// The grant an id names.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the row cannot be read or is not one the model
    /// accepts.
    async fn grant(&self, id: &GrantId) -> Result<Option<Grant>, DomainError>;

    /// Whether this `jti` was revoked before its own expiry.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the denylist cannot be read. Never `false` for an
    /// unavailable store: a token that could not be checked is not a token
    /// this endpoint answers.
    async fn is_denylisted(&self, jti: &str) -> Result<bool, DomainError>;

    /// The instant before which this client and this grant withdrew every
    /// access token they had issued, if either of them did (`ast-m9c.13`).
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the mark cannot be read.
    async fn access_tokens_revoked_before(
        &self,
        client: &ClientId,
        grant: Option<&GrantId>,
    ) -> Result<Option<OffsetDateTime>, DomainError>;

    /// Withdraws a grant and everything minted from it (§6.5).
    ///
    /// `false` is "there was no live grant of that id", which is what a second
    /// `DELETE` finds. It is not an error: §6.5 is idempotent in effect, and
    /// the caller turns it into the 404 §6.6 asks for.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the write failed — in which case nothing was
    /// revoked and the caller must not answer 204.
    async fn revoke(&self, id: &GrantId, now: OffsetDateTime) -> Result<bool, DomainError>;
}

/// What one Grant Management request needs.
pub struct GrantManagementContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The rows.
    pub store: &'a dyn GrantManagementStore,
    /// Where the tenant's published keys come from, so a token this server
    /// signed is verified against the same set `/jwks` serves.
    pub keys: &'a dyn KeyStore,
    /// Checks the DPoP proof (RFC 9449 §7.1).
    pub dpop: &'a DpopEndpoint,
    /// The trail. A revocation is recorded whether or not it revoked anything.
    pub audit: &'a dyn AuditSink,
    /// The client certificate this request arrived with, if the deployment saw
    /// one from a source it trusts (RFC 8705 §2).
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    /// One clock reading for the whole request.
    pub now: OffsetDateTime,
}

impl std::fmt::Debug for GrantManagementContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantManagementContext")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// What the caller asked to do with the grant, and what it must hold to.
///
/// A closed enum rather than the HTTP method, because the two things that
/// differ between the verbs — §6.1's scope and what the answer looks like —
/// are decided in different places, and a handler that matched on `Method`
/// twice could get them out of step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    /// §6.4.
    Query,
    /// §6.5.
    Revoke,
}

impl Operation {
    /// The §6.1 scope the token must carry.
    const fn scope(self) -> &'static str {
        match self {
            Self::Query => grant_management::SCOPE_QUERY,
            Self::Revoke => grant_management::SCOPE_REVOKE,
        }
    }
}

/// `GET /grants/{grant_id}` — §6.4.
///
/// Never returns `Err`: every failure is an HTTP response in §6.6's shape.
pub async fn query(
    context: GrantManagementContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    grant_id: &str,
) -> Response {
    match answer(&context, method, headers, grant_id, Operation::Query).await {
        Ok(grant) => no_store(
            (
                StatusCode::OK,
                axum::Json(grant_management::query_response(&grant)),
            )
                .into_response(),
        ),
        Err(refusal) => render(&context, refusal),
    }
}

/// `DELETE /grants/{grant_id}` — §6.5.
///
/// > The AS MUST revoke the respective grant and all refresh tokens issued
/// > based on that grant. […] It SHOULD also revoke all access tokens.
///
/// All three happen in the one call to [`GrantManagementStore::revoke`], in
/// one transaction: the refresh tokens are marked, the grant's access-token
/// cutoff is written (`ast-m9c.13` — the SHOULD, kept as a MUST, and the only
/// mechanism there is), and the grant is stamped last so it is withdrawn only
/// once the credentials it covers already are.
///
/// Never returns `Err`.
pub async fn revoke(
    context: GrantManagementContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    grant_id: &str,
) -> Response {
    let grant = match answer(&context, method, headers, grant_id, Operation::Revoke).await {
        Ok(grant) => grant,
        Err(refusal) => return render(&context, refusal),
    };

    match context.store.revoke(&grant.id, context.now).await {
        // A grant that was live a moment ago and is not now: another request
        // won the race. §6.6's 404, which is also what a second `DELETE` gets.
        Ok(false) => render(&context, Refused::NotFound),
        Ok(true) => {
            record(&context, &grant).await;
            notify_grant_revoked(&context, &grant).await;
            // §6.5: "204 No Content". No body, so there is nothing for a
            // client to parse and nothing for this server to leak into.
            no_store(StatusCode::NO_CONTENT.into_response())
        }
        Err(error) => render(&context, Refused::Server(error)),
    }
}

/// Why a request stopped.
#[derive(Debug)]
enum Refused {
    /// An RFC 6750 §3 refusal: 400, 401 or 403, in a `WWW-Authenticate`.
    Client(UserInfoError),
    /// §6.1's scope is missing. Separate from [`Self::Client`] because the
    /// challenge names the scope that was wanted, and which one that is
    /// depends on the verb.
    MissingScope(&'static str),
    /// §6.6's 404: no such grant, or not this client's.
    NotFound,
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

/// Everything both verbs do: authorize the caller, then find the grant.
///
/// The order is the module documentation's, and each step reads only what the
/// step before it established.
async fn answer(
    context: &GrantManagementContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    grant_id: &str,
    operation: Operation,
) -> Result<Grant, Refused> {
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
    // No query string is passed: this endpoint's URL is §6.3's, which has
    // none. A credential in one would not be read here in any case, because
    // the only place a token is looked for is the header.
    let presented = userinfo::present(&authorizations, None)?;

    // Step 1.
    let verified =
        access_token::verify(context.tenant, context.keys, presented.token(), context.now)
            .await
            .map_err(|rejected| match rejected {
                access_token::Rejected::Unavailable(error) => Refused::Server(error),
                access_token::Rejected::Token(error) => {
                    // Debug, not warn: a rejected token is routine at a resource
                    // server, and which check failed is a description of this server's
                    // state that an unauthenticated caller has not earned.
                    tracing::debug!(%error, "a Grant Management access token did not verify");
                    UserInfoError::InvalidToken.into()
                }
            })?;

    // Step 2.
    sender_constrained(context, method, headers, grant_id, &verified, presented).await?;

    // Step 3.
    if !audienced_here(context.tenant, &verified) {
        tracing::debug!(
            tenant = %context.tenant.id,
            "a token presented at the grant management endpoint is audienced elsewhere"
        );
        return Err(UserInfoError::InvalidToken.into());
    }

    // Step 4.
    let jti = verified
        .claim_str("jti")
        .ok_or(UserInfoError::InvalidToken)?;
    if context.store.is_denylisted(jti).await? {
        return Err(UserInfoError::InvalidToken.into());
    }
    let client = verified
        .claim_str("client_id")
        .ok_or(UserInfoError::InvalidToken)?;
    let client = ClientId::new(client.to_owned());
    let own_grant = verified
        .claim_str("grant_id")
        .map(|id| GrantId::new(id.to_owned()));
    let cutoff = context
        .store
        .access_tokens_revoked_before(&client, own_grant.as_ref())
        .await?;
    if access_token::withdrawn(&verified, cutoff) {
        return Err(UserInfoError::InvalidToken.into());
    }

    // Step 5.
    if !carries_scope(&verified, operation.scope()) {
        return Err(Refused::MissingScope(operation.scope()));
    }

    // Step 6.
    addressed_grant(context, &client, grant_id).await
}

/// Step 2, with UserInfo's rule and UserInfo's function.
async fn sender_constrained(
    context: &GrantManagementContext<'_>,
    method: &Method,
    headers: &HeaderMap,
    grant_id: &str,
    verified: &Verified,
    presented: Presentation<'_>,
) -> Result<(), Refused> {
    access_token::check_sender_constraint(
        &access_token::Presented {
            tenant: context.tenant,
            dpop: context.dpop,
            // §6.3: the resource is the endpoint plus the grant id, and that
            // is the URL the client made its proof over.
            endpoint: Endpoint::GrantManagement,
            segment: Some(grant_id),
            certificate: context.certificate,
            method,
            headers,
            presented,
            now: context.now,
        },
        verified,
    )
    .await
    .map_err(|refusal| match refusal {
        access_token::NotBound::Refused => UserInfoError::InvalidToken.into(),
        access_token::NotBound::Dpop(refusal) => Refused::Dpop(refusal),
    })
}

/// Step 3: §6.2's resource is this tenant's grant management endpoint.
///
/// The URL is built from the endpoint registry rather than written out, so the
/// audience a client must ask for is the URL the metadata advertises and the
/// path the router mounts — three facts, one source.
///
/// `aud` may be a string or an array (RFC 7519 §4.1.3), and both are accepted
/// because both are what a token this server minted can carry: `Audience`
/// renders one resource as a string.
fn audienced_here(tenant: &Tenant, verified: &Verified) -> bool {
    let resource = Endpoint::GrantManagement.url(&tenant.issuer);
    match verified.claims.get("aud") {
        Some(serde_json::Value::String(only)) => *only == resource,
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
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

/// Step 6: the grant this URL names, if it is this client's and still standing.
///
/// The shape check comes first and costs a length comparison, so a flood of
/// guessed identifiers does not become a flood of queries — the same argument
/// [`grant_management::MAX_GRANT_ID_LEN`] exists for at the pushed request.
///
/// Four ways to get nothing, one answer. See the module documentation.
async fn addressed_grant(
    context: &GrantManagementContext<'_>,
    client: &ClientId,
    grant_id: &str,
) -> Result<Grant, Refused> {
    if !grant_management::is_plausible_grant_id(grant_id) {
        return Err(Refused::NotFound);
    }
    let grant = match context
        .store
        .grant(&GrantId::new(grant_id.to_owned()))
        .await
    {
        Ok(grant) => grant,
        // An id that got past the shape filter and is still not one the
        // storage adapter can parse. Not this deployment's failure and not a
        // row: it is a grant this tenant does not hold.
        Err(DomainError::Invalid { .. }) => None,
        Err(error) => return Err(Refused::Server(error)),
    };
    grant
        .filter(|grant| grant.client == *client)
        // §5.6: a revoked or lapsed grant is not one that can be read or
        // revoked again. A `Pending` one is — it exists, the client made it,
        // and being told it is there is how a client learns it has an
        // authorization nobody has taken a token from yet.
        .filter(|grant| !matches!(grant.status(context.now), GrantStatus::Revoked))
        .ok_or(Refused::NotFound)
}

/// The trail entry for one revocation.
///
/// [`EventType::GRANT_REVOKED`] and not `TOKEN_REVOKED`: those are two facts
/// this trail deliberately keeps apart (RFC 7009 §2.1 revokes a credential and
/// leaves the authorization standing; §6.5 revokes the authorization). The
/// actor is the client, because a client acting on its own token is who made
/// this request — the person the grant is about was not here.
///
/// Never fails the request. The grant is already revoked by the time this
/// runs, and refusing the client because the trail is unavailable would leave
/// it believing an authorization it has destroyed is still live.
async fn record(context: &GrantManagementContext<'_>, grant: &Grant) {
    let mut event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::GRANT_REVOKED,
        Outcome::Success,
        Actor::Client(grant.client.clone()),
        context.now,
    )
    .client(grant.client.clone())
    .grant(grant.id.clone())
    .detail(Detail::new().label("reason", "grant_management_delete"));
    if let Some(subject) = &grant.subject {
        event = event.subject(subject.as_str().to_owned());
    }

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            "a grant revocation was not written to the audit trail"
        );
    }
}

/// The CAEP `session-revoked` seam.
///
/// A grant being withdrawn is the fact a resource server most needs to be told
/// about and is least able to discover: an access token minted from it is a
/// signed JWT that still verifies, and what refuses it is a cutoff only this
/// server can read. OpenID Shared Signals is how that fact travels, and the
/// transmitter is `ast-0ju.8` and does not exist.
///
/// So this does nothing yet, on purpose, and it is named and called from
/// exactly one place for the reason
/// [`crate::http::recovery::notify_credential_change`] is: a hook with a name
/// is a thing a reviewer can find, and the tenant, the client, the subject and
/// the moment are already assembled here for whoever builds the transmitter.
#[expect(
    clippy::unused_async,
    reason = "the seam is async because the transmitter it is waiting for will be"
)]
async fn notify_grant_revoked(context: &GrantManagementContext<'_>, grant: &Grant) {
    tracing::info!(
        tenant = %context.tenant.id,
        client = %grant.client,
        grant = %grant.id,
        "a grant was revoked at the grant management endpoint"
    );
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// One refusal, in §6.6's shape.
///
/// Everything that is about the *credential* answers the way RFC 6750 §3 says
/// a protected resource does: a status, a challenge in `WWW-Authenticate`, and
/// no body. §6.6's 404 is about a *resource* and not about a credential, so it
/// carries no challenge — a `WWW-Authenticate` there would invite a client to
/// retry with a better token for a grant that is not there.
fn render(context: &GrantManagementContext<'_>, refusal: Refused) -> Response {
    match refusal {
        Refused::Client(error) => refuse(&error),
        Refused::MissingScope(scope) => insufficient_scope(scope),
        Refused::NotFound => no_store(StatusCode::NOT_FOUND.into_response()),
        Refused::Dpop(refusal) => dpop_challenge(&refusal),
        Refused::Server(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "cannot answer a grant management request"
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

/// RFC 6750 §3.1's `insufficient_scope`, naming the scope that was wanted.
///
/// §3 says the challenge "SHOULD include the `scope` attribute with the scope
/// necessary to access the protected resource", and here it genuinely helps: a
/// client holding `grant_management_query` and calling `DELETE` is told which
/// of the two §6.1 scopes it needs, which it can ask for at the token endpoint
/// without a support ticket.
fn insufficient_scope(scope: &str) -> Response {
    let mut response = empty(StatusCode::FORBIDDEN);
    if let Ok(value) = HeaderValue::from_str(&format!(
        r#"DPoP error="insufficient_scope", error_description="the access token does not carry the scope this request needs", scope="{scope}""#
    )) {
        response
            .headers_mut()
            .append(header::WWW_AUTHENTICATE, value);
    }
    no_store(response)
}

/// A DPoP failure, in the shape a resource server uses (RFC 9449 §7.1, §7.2).
fn dpop_challenge(refusal: &dpop::Refusal) -> Response {
    if let Some(detail) = refusal.detail() {
        tracing::debug!(%detail, "a DPoP proof at the grant management endpoint did not check out");
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
/// The body describes an authorization and the headers carry a challenge;
/// neither belongs in a cache. RFC 9449 §8.2 requires it of anything carrying
/// a `DPoP-Nonce`, and applying it to all of them is cheaper than remembering
/// which.
fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::{OffsetDateTime, Operation, Tenant, audienced_here, carries_scope};
    use asterius_domain::keys::SigningAlgorithm;
    use asterius_jose::verify::Verified;
    use serde_json::json;

    /// A verified token carrying exactly the claims a test cares about.
    ///
    /// Built by hand rather than signed: the signature is
    /// [`access_token::verify`]'s subject, and what is under test here is what
    /// happens to the claims *after* it has been checked.
    fn verified(claims: serde_json::Value) -> Verified {
        Verified {
            claims,
            kid: None,
            algorithm: SigningAlgorithm::DEFAULT,
        }
    }

    fn tenant() -> Tenant {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant");
        Tenant {
            id: asterius_domain::TenantId::parse("demo").expect("a tenant id"),
            issuer: asterius_domain::Issuer::parse("https://as.example/t/demo").expect("an issuer"),
            custom_host: None,
            display_name: "Demo".to_owned(),
            default_resource: "https://api.example/".to_owned(),
            status: asterius_domain::TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// §6.1 registers two scopes, and each verb wants its own.
    ///
    /// A server that accepted either would let a read-only token destroy an
    /// authorization, which is the whole reason there are two.
    #[test]
    fn each_verb_wants_its_own_scope() {
        // Arrange, Act, Assert
        assert_eq!(Operation::Query.scope(), "grant_management_query");
        assert_eq!(Operation::Revoke.scope(), "grant_management_revoke");
        assert_ne!(Operation::Query.scope(), Operation::Revoke.scope());
    }

    /// RFC 6749 §3.3: `scope` is a space-delimited list, and a prefix of a
    /// scope is not that scope.
    #[test]
    fn a_scope_is_matched_whole_and_never_as_a_prefix() {
        // Arrange
        let token = verified(json!({"scope": "openid grant_management_query"}));

        // Act, Assert
        assert!(carries_scope(&token, "grant_management_query"));
        assert!(!carries_scope(&token, "grant_management_revoke"));
        assert!(
            !carries_scope(&token, "grant_management"),
            "a prefix of a granted scope is not a granted scope"
        );
    }

    /// A token with no `scope` claim carries no scope.
    ///
    /// RFC 9068 §2.2.3 makes the claim optional, and an absent one must not
    /// read as "everything": the endpoint would then be open to any token of
    /// the tenant that happened to be audienced here.
    #[test]
    fn a_token_with_no_scope_claim_carries_none() {
        // Arrange
        let token = verified(json!({"client_id": "billing"}));

        // Act, Assert
        assert!(!carries_scope(&token, "grant_management_query"));
    }

    /// §6.2: the audience is *this* tenant's grant management endpoint, in
    /// either of the two shapes RFC 7519 §4.1.3 allows.
    #[test]
    fn the_audience_must_be_this_tenants_grant_management_endpoint() {
        // Arrange
        let tenant = tenant();

        // Act, Assert: one resource renders as a string, several as an array.
        for right in [
            json!({"aud": "https://as.example/t/demo/grants"}),
            json!({"aud": ["https://api.example/", "https://as.example/t/demo/grants"]}),
        ] {
            assert!(
                audienced_here(&tenant, &verified(right.clone())),
                "refused {right}"
            );
        }

        // Act, Assert: the business API, another tenant's endpoint, and a
        // token with no audience at all.
        for wrong in [
            json!({"aud": "https://api.example/"}),
            json!({"aud": "https://as.example/t/other/grants"}),
            json!({"aud": ["https://api.example/"]}),
            json!({"client_id": "billing"}),
        ] {
            assert!(
                !audienced_here(&tenant, &verified(wrong.clone())),
                "accepted {wrong} as this endpoint's audience"
            );
        }
    }
}
