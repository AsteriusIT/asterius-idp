//! `POST /introspect` — the token introspection endpoint (RFC 7662).
//!
//! A resource server holds a token somebody presented to it and asks this
//! server what it is. What a request must look like and which members an
//! answer may carry is [`asterius_oidc::introspection`], which is pure and
//! tested as such; what lives here is everything that needs the outside world
//! — the client authentication, the tenant's keys, the denylist, the
//! revocation cutoffs, the grant, the refresh-token row and the registry that
//! says who is a resource server for what.
//!
//! # Two questions, and only one of them may be answered
//!
//! RFC 7662 §2.3 separates them, and this module keeps them separate:
//!
//! * *May this caller use the endpoint at all?* §2.1 requires client
//!   authentication, and a caller that fails it gets a **401** with no body.
//!   That says nothing about any token.
//! * *May this caller be told about **this** token?* §2.2's note: "if the
//!   protected resource is not allowed to introspect this particular token"
//!   the answer is `active: false` — a 200, indistinguishable from an expired
//!   token, a revoked one and one this server never issued.
//!
//! §4 is why the second one collapses: "an attacker could use this endpoint
//! to determine whether a token is valid". An endpoint that answered
//! `invalid_token` for a forgery, `403` for somebody else's token and
//! `active: false` for an expired one would be a three-way oracle over any
//! string a caller cares to try — which is token scanning with the server's
//! help.
//!
//! # Who is allowed to be told
//!
//! Two callers, and no others:
//!
//! * the **client the token was issued to** (`client_id`, RFC 9068 §2.2 —
//!   signed, so the comparison is between two facts), which is the caller that
//!   could have read every member of the answer out of its own token; and
//! * a client the operator registered as a **resource server for one of the
//!   token's audiences** (`ResourceRegistry::introspects`, `ast-1sk.1`). §4
//!   requires this to be a registration rather than a default: "only allow
//!   ... protected resources that are authorized".
//!
//! Nobody else, including every other registered client of the tenant. A
//! deployment that has registered no introspecting client has an endpoint
//! only a token's own client can use, which is the narrowest posture §2.1
//! permits, and it is the posture every existing deployment is migrated into.
//!
//! # The answer costs the same whoever asks
//!
//! Every store read this endpoint makes happens **before** the authorization
//! decision and regardless of it: the denylist, the cutoffs, the grant, the
//! registry. The decision is a comparison on values already in hand, and the
//! only thing it chooses is which of two bodies is serialised.
//!
//! That is deliberate and it is asserted by a test that counts the reads
//! rather than by a stopwatch. §4's attacker is not timing one request; they
//! are looking for any observable that separates "this token exists" from
//! "this token is not yours", and a short-circuit that skipped three queries
//! for an unauthorized caller would be exactly that observable — visible in
//! latency, in database load, and in the trail. A timing assertion would be
//! flaky and would prove less: what is wanted is not "the two took the same
//! number of microseconds" but "the two did the same work", and the work is
//! countable.
//!
//! # Refresh tokens
//!
//! Introspectable by their own client and by nobody else. A refresh token has
//! no audience — it is presented at the token endpoint, never at a resource
//! server — so there is no resource server that could be authorized for one,
//! and a registry entry cannot make one. The lookup is keyed by the digest
//! *and* the authenticated client, so another client's refresh token matches
//! no row and is `active: false`, which is the same answer an unknown value
//! gets.

use crate::http::access_token;
use crate::http::token::{error as oauth_error, is_form_encoded, no_store};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::grant::GrantStatus;
use asterius_domain::keys::KeyStore;
use asterius_domain::{
    Client, ClientId, ClientRepository, DomainError, Grant, GrantId, ResourceRegistry, Tenant,
};
use asterius_jose::verify::Verified;
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::form::Parameters;
use asterius_oidc::introspection::{self, IntrospectionError, IntrospectionResponse};
use asterius_oidc::revocation::{self, Presented, TokenTypeHint};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

/// The largest form body this endpoint will read.
///
/// The same bound the token and revocation endpoints have: an introspection
/// request carries a token and a client assertion, and the assertion is the
/// same assertion.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// What one refresh token row says about itself.
///
/// A record of its own rather than the store's, so this module does not
/// depend on the adapter's row type — and so that what an introspection
/// answer may contain about a refresh token is a list written here, where the
/// specification sections are, rather than whatever a `select *` returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenFacts {
    /// The grant it draws on, for the private `grant_id` member.
    pub grant: GrantId,
    /// The scopes it may be refreshed for (§2.2's `scope`).
    pub scopes: std::collections::BTreeSet<String>,
    /// When it was minted (§2.2's `iat`).
    pub issued_at: OffsetDateTime,
    /// The deadline that never moves (§2.2's `exp`).
    ///
    /// The absolute one and not the idle one. §2.2 defines `exp` as "the time
    /// on or after which this token MUST NOT be accepted", and the idle
    /// deadline moves every time the token is used: a resource server that
    /// cached the answer would hold a value that was already wrong.
    pub expires_at: OffsetDateTime,
    /// What holds it, already shaped as RFC 7800 §3.1's `cnf` — RFC 9449
    /// §6.2's member. `None` for a row whose binding cannot be rendered as
    /// one.
    pub confirmation: Option<Value>,
}

/// The rows this endpoint reads.
///
/// One port for the five reads, for the reason UserInfo has one: they are one
/// question — "what is this token, and is it still good" — and a handler
/// holding a grant repository would hold `revoke` and `claim` with it. This
/// endpoint writes nothing but its audit entry.
#[async_trait::async_trait]
pub trait IntrospectionSource: std::fmt::Debug + Send + Sync {
    /// Whether this `jti` was revoked before its own expiry.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the denylist cannot be read. Never `false` for an
    /// unavailable store: a token that could not be checked must not be
    /// reported active.
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

    /// The grant a token names.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the row cannot be read or is not one the model
    /// accepts.
    async fn grant(&self, id: &GrantId) -> Result<Option<Grant>, DomainError>;

    /// This tenant's registered resource servers (RFC 8707 §3).
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the registry cannot be read. Never an empty
    /// registry for an unavailable store: that would turn an outage into an
    /// endpoint that answers `active: false` to every legitimate resource
    /// server, which is an authorization decision taken by a failure.
    async fn resource_servers(&self) -> Result<ResourceRegistry, DomainError>;

    /// The live refresh token this digest names, if it belongs to `client`.
    ///
    /// The client is half of the lookup rather than a comparison afterwards,
    /// so another client's token matches no row — the same shape RFC 7009
    /// §2.2 requires of revocation, and the same answer.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the row cannot be read.
    async fn refresh_token(
        &self,
        digest: &str,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Option<RefreshTokenFacts>, DomainError>;
}

/// What one introspection request needs.
pub struct IntrospectionContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This tenant's clients, for the authenticator.
    pub clients: &'a dyn ClientRepository,
    /// The rows.
    pub source: &'a dyn IntrospectionSource,
    /// The tenant's published keys, so an access token presented here is
    /// verified against the same set `/jwks` serves and UserInfo reads.
    pub keys: &'a dyn KeyStore,
    /// The trail. Every call is recorded, including the ones that told the
    /// caller nothing.
    pub audit: &'a dyn AuditSink,
    /// Whether this tenant puts the `grant_id` correlator in its access
    /// tokens (`TenantSettings::grant_id_in_access_token`, `ast-txw`).
    ///
    /// Read by the wiring and passed in, so this module holds no settings
    /// port. It decides one thing: whether the private `grant_id` member is
    /// in the response. A tenant that withholds the correlator from the token
    /// withholds it here too — handing it over at this endpoint instead would
    /// be spending the decision without making it.
    pub grant_id_exposed: bool,
    /// One clock reading for the whole request.
    pub now: OffsetDateTime,
    /// The client certificate this request arrived with (RFC 8705 §2), if the
    /// deployment saw one from a source it trusts.
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
}

impl std::fmt::Debug for IntrospectionContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionContext")
            .field("now", &self.now)
            .field("grant_id_exposed", &self.grant_id_exposed)
            .finish_non_exhaustive()
    }
}

/// Answers an introspection request.
///
/// `authenticate` is the token endpoint's authenticator, passed in by the
/// wiring, for the reason the revocation endpoint takes the same one: RFC
/// 7662 §2.1 requires client authentication here, and this deployment has one
/// implementation of it, so this endpoint does not get a second opinion about
/// who a caller is.
///
/// Never returns `Err`: every outcome is a `Response`.
pub async fn introspect(
    context: IntrospectionContext<'_>,
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

    // §2.1: the caller authenticates, before anything is looked up. Everything
    // below is a statement to a caller that has proved who it is, which is
    // what makes "may you be told about this token" a question with an answer.
    let attempt = Attempt {
        assertion: find(&pairs, "client_assertion"),
        assertion_type: find(&pairs, "client_assertion_type"),
        client_id: find(&pairs, "client_id"),
        authorization_header: headers.contains_key(header::AUTHORIZATION),
        certificate: context.certificate,
    };
    let rules = AssertionRules::for_issuer(context.tenant.issuer.as_str());
    let caller = match authenticate(&attempt, &rules).await {
        Ok(client) => client,
        Err(failure) => {
            // §2.3: "If the protected resource uses OAuth 2.0 client
            // credentials to authenticate to the introspection endpoint and
            // its credentials are invalid, the authorization server responds
            // with an HTTP 401". A 401 whatever the authenticator would have
            // said elsewhere: at the token endpoint a malformed assertion is a
            // 400 about the request, and here the only fact worth reporting is
            // that the caller is not one this endpoint knows.
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                failure.code(),
                "client authentication failed",
            );
        }
    };

    let params = Parameters::from_pairs(pairs);
    let request = match introspection::parse(&params) {
        Ok(request) => request,
        Err(failure) => return refuse(&failure),
    };

    match answer(&context, &caller, request.token).await {
        Ok(response) => {
            record(&context, &caller, request.hint, response.is_active()).await;
            // §2.2: "the introspection endpoint responds with a JSON object".
            // `no-store` because the object describes a live credential:
            // caching it would let a shared proxy answer a later question
            // about a token that has since been revoked.
            (StatusCode::OK, no_store(), axum::Json(response.into_json())).into_response()
        }
        Err(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                client = %caller.id,
                "an introspection could not be answered"
            );
            // Deliberately not `active: false`. §2.2's note collapses three
            // *facts about a token* into that answer; an outage is not one of
            // them, and a resource server told `active: false` would refuse a
            // request its user is entitled to make and would not retry.
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "the introspection could not be carried out",
            )
        }
    }
}

/// Works out what to say about the presented value.
///
/// The error type is [`DomainError`] and nothing else: every refusal a caller
/// can be told about is `active: false`, so the only `Err` left is a store
/// this deployment could not read.
async fn answer(
    context: &IntrospectionContext<'_>,
    caller: &Client,
    token: &str,
) -> Result<IntrospectionResponse, DomainError> {
    // The same classifier the revocation endpoint uses, and for the same
    // reason: what *shape* a presented value has is one question with one
    // answer, and two copies of it would disagree about which values are
    // refresh tokens. Its `UnsupportedTokenType` is not an error here — §2.2's
    // note has no room for one — so an ID token or a client assertion
    // presented at this endpoint is simply not active.
    match revocation::classify(token) {
        Ok(Presented::AccessToken) => describe_access_token(context, caller, token).await,
        Ok(Presented::RefreshToken { digest }) => {
            describe_refresh_token(context, caller, &digest).await
        }
        Ok(Presented::Unrecognised) | Err(_) => Ok(IntrospectionResponse::inactive()),
    }
}

/// Describes a JWT access token, if this caller may be told about it.
///
/// The order below is the module's "same work whoever asks" property written
/// out: verification, then **every** read, then one decision. Nothing between
/// the verification and the decision depends on who the caller is.
async fn describe_access_token(
    context: &IntrospectionContext<'_>,
    caller: &Client,
    token: &str,
) -> Result<IntrospectionResponse, DomainError> {
    // Signature, `typ`, `iss` and `exp`, through the one verifier every other
    // JWT this server receives goes through. A token that fails this is not
    // one of ours — or is past its own expiry, which §2.2 defines as not
    // active — and either way the answer is the same.
    let verified =
        match access_token::verify(context.tenant, context.keys, token, context.now).await {
            Ok(verified) => verified,
            Err(access_token::Rejected::Unavailable(error)) => return Err(error),
            Err(access_token::Rejected::Token(error)) => {
                // Debug and not warn: a resource server introspecting a token that
                // expired while its holder was reading a page is the ordinary
                // case, not an incident.
                tracing::debug!(%error, "a token presented for introspection did not verify");
                return Ok(IntrospectionResponse::inactive());
            }
        };

    // RFC 9068 §2.2 makes all three REQUIRED, and they are read from a token
    // whose signature has been checked, so each is a fact rather than a claim.
    // A token missing one is not one this server minted.
    let (Some(jti), Some(issued_to)) = (verified.claim_str("jti"), verified.claim_str("client_id"))
    else {
        return Ok(IntrospectionResponse::inactive());
    };
    let issued_to = ClientId::new(issued_to.to_owned());
    let grant = verified
        .claim_str("grant_id")
        .map(|id| GrantId::new(id.to_owned()));

    // --- the reads, none of which depends on who is asking ---

    // FAPI 2.0 SP §5.3.4 item 3, and the one thing that can withdraw a named
    // stateless token.
    let denylisted = context.source.is_denylisted(jti).await?;
    // The bulk half: a deprovisioned client (RFC 7592 §2.3) and a revoked
    // refresh token (RFC 7009 §2.1) withdraw tokens nobody wrote down.
    let cutoff = context
        .source
        .access_tokens_revoked_before(&issued_to, grant.as_ref())
        .await?;
    // The grant, when the token names one. A tenant that withholds the
    // correlator (`ast-txw`) has no id to read a row by, and this endpoint
    // does **not** fall back to UserInfo's search by `sub` and `client_id`:
    // that search refuses when a person holds two grants to one client, and a
    // refusal there would be an `active: false` that depends on how many
    // authorizations the person happens to hold — an answer about somebody
    // else's account state, leaked through this endpoint. The cutoff above
    // still covers the revocations that matter, because revoking a grant
    // writes one.
    let grant_status = match grant.as_ref() {
        Some(id) => context
            .source
            .grant(id)
            .await?
            .map(|g| g.status(context.now)),
        None => None,
    };
    // RFC 7662 §4: who is authorized to introspect what.
    let registry = context.source.resource_servers().await?;

    // --- one decision, on values already in hand ---

    let live = !denylisted
        && !access_token::withdrawn(&verified, cutoff)
        // A token that names a grant is only live while the row still stands:
        // a grant this tenant no longer holds, or holds as revoked, expired or
        // never claimed from, is not authority a token may draw on. A token
        // that names none — the tenant withholds the correlator (`ast-txw`) —
        // has no row to consult, and its own `exp` and the cutoffs above are
        // the whole answer.
        && grant
            .as_ref()
            .is_none_or(|_| grant_status == Some(GrantStatus::Active));
    let allowed = caller.id == issued_to || registry.introspects(&caller.id, audiences(&verified));

    Ok(if live && allowed {
        introspection::describe(&verified.claims, context.grant_id_exposed)
    } else {
        IntrospectionResponse::inactive()
    })
}

/// Describes a refresh token, if it is this caller's.
///
/// One read. The client is half of the lookup, so "not yours" and "no such
/// token" are the same miss and cannot be told apart by anything, including
/// how long the miss took.
async fn describe_refresh_token(
    context: &IntrospectionContext<'_>,
    caller: &Client,
    digest: &str,
) -> Result<IntrospectionResponse, DomainError> {
    let Some(facts) = context
        .source
        .refresh_token(digest, &caller.id, context.now)
        .await?
    else {
        return Ok(IntrospectionResponse::inactive());
    };

    // Rendered as the claims an access token would carry and then projected
    // through the one projection, so that the two kinds of token cannot come
    // to publish differently-named members for the same fact. `aud` is absent
    // because a refresh token has none: it is presented at the token endpoint,
    // and inventing an audience for it would tell a resource server it is
    // something it could be shown.
    let mut claims = Map::new();
    claims.insert(
        "iss".to_owned(),
        Value::String(context.tenant.issuer.as_str().to_owned()),
    );
    claims.insert(
        "client_id".to_owned(),
        Value::String(caller.id.as_str().to_owned()),
    );
    if !facts.scopes.is_empty() {
        claims.insert(
            "scope".to_owned(),
            Value::String(
                facts
                    .scopes
                    .iter()
                    .cloned()
                    .collect::<Vec<String>>()
                    .join(" "),
            ),
        );
    }
    claims.insert("iat".to_owned(), json!(facts.issued_at.unix_timestamp()));
    claims.insert("exp".to_owned(), json!(facts.expires_at.unix_timestamp()));
    if let Some(confirmation) = facts.confirmation {
        claims.insert("cnf".to_owned(), confirmation);
    }
    claims.insert(
        "grant_id".to_owned(),
        Value::String(facts.grant.as_str().to_owned()),
    );

    Ok(introspection::describe(
        &Value::Object(claims),
        context.grant_id_exposed,
    ))
}

/// The audiences a verified token names (RFC 9068 §2.2's `aud`).
///
/// RFC 7519 §4.1.3 allows both spellings — an array of strings, and a single
/// string for the one-element case — and both are read, because a resource
/// server's entitlement must not depend on how the audience happened to be
/// serialised.
fn audiences(verified: &Verified) -> Vec<&str> {
    match verified.claims.get("aud") {
        Some(Value::String(single)) => vec![single.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Writes the trail entry for one introspection.
///
/// Recorded whatever the answer, which is the point: a caller walking token
/// values gets `active: false` every time and learns nothing from any single
/// answer, so a run of these entries against one caller is the only place the
/// walk is visible at all (RFC 7662 §4's token scanning).
///
/// The entry names the caller, the hint it sent and whether it was told the
/// token was active. It does **not** name the token, the `jti` or the client
/// the token was issued to: the first two are — or identify — a live
/// credential, and the third would turn the trail into the correlation between
/// resource servers and clients that §4 asks this endpoint not to publish.
///
/// Never fails the request. The answer has already been computed and is
/// correct; refusing the caller because the trail is unavailable would deny a
/// resource server a decision it is entitled to make.
async fn record(
    context: &IntrospectionContext<'_>,
    caller: &Client,
    hint: TokenTypeHint,
    active: bool,
) {
    let detail = Detail::new()
        .label("token_type_hint", hint.as_str())
        .label("active", if active { "true" } else { "false" });

    let event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::TOKEN_INTROSPECTED,
        Outcome::Success,
        Actor::Client(caller.id.clone()),
        context.now,
    )
    .client(caller.id.clone())
    .detail(detail);

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            client = %caller.id,
            "an introspection was not written to the audit trail"
        );
    }
}

/// Renders §2.3's error shape, which is RFC 6749 §5.2's.
fn refuse(failure: &IntrospectionError) -> Response {
    oauth_error(
        StatusCode::from_u16(failure.status()).unwrap_or(StatusCode::BAD_REQUEST),
        failure.code(),
        failure.description(),
    )
}

/// The first value of `name`, for client authentication only.
///
/// The same helper the token and revocation endpoints have, and for the same
/// reason: the authenticator takes `&str`, and duplicate detection is
/// [`asterius_oidc::introspection::parse`]'s job on the parameters that decide
/// anything.
fn find<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::keys::SigningAlgorithm;
    use std::sync::Mutex;

    /// What a fake source was asked, in order.
    #[derive(Debug, Default)]
    struct Reads(Mutex<Vec<&'static str>>);

    impl Reads {
        fn saw(&self, what: &'static str) {
            self.0.lock().expect("a test lock").push(what);
        }

        fn taken(&self) -> Vec<&'static str> {
            self.0.lock().expect("a test lock").clone()
        }
    }

    /// A source that answers "nothing is wrong" and records what it was asked.
    #[derive(Debug, Default)]
    struct Source {
        reads: Reads,
        denylisted: bool,
        cutoff: Option<OffsetDateTime>,
        registry: ResourceRegistry,
    }

    #[async_trait::async_trait]
    impl IntrospectionSource for Source {
        async fn is_denylisted(&self, _jti: &str) -> Result<bool, DomainError> {
            self.reads.saw("denylist");
            Ok(self.denylisted)
        }

        async fn access_tokens_revoked_before(
            &self,
            _client: &ClientId,
            _grant: Option<&GrantId>,
        ) -> Result<Option<OffsetDateTime>, DomainError> {
            self.reads.saw("cutoff");
            Ok(self.cutoff)
        }

        async fn grant(&self, _id: &GrantId) -> Result<Option<Grant>, DomainError> {
            self.reads.saw("grant");
            Ok(None)
        }

        async fn resource_servers(&self) -> Result<ResourceRegistry, DomainError> {
            self.reads.saw("registry");
            Ok(self.registry.clone())
        }

        async fn refresh_token(
            &self,
            _digest: &str,
            _client: &ClientId,
            _now: OffsetDateTime,
        ) -> Result<Option<RefreshTokenFacts>, DomainError> {
            self.reads.saw("refresh");
            Ok(None)
        }
    }

    fn verified(claims: Value) -> Verified {
        Verified {
            claims,
            kid: None,
            algorithm: SigningAlgorithm::DEFAULT,
        }
    }

    /// RFC 7519 §4.1.3: a single-valued `aud` may be a bare string, and a
    /// resource server's entitlement must not turn on the serialisation.
    #[test]
    fn a_string_audience_reads_as_one_audience() {
        // Arrange
        let token = verified(json!({ "aud": "https://api.example/accounts" }));

        // Act
        let named = audiences(&token);

        // Assert
        assert_eq!(named, vec!["https://api.example/accounts"]);
    }

    /// An array `aud` reads as every member, so a token minted for two APIs is
    /// introspectable by each.
    #[test]
    fn an_array_audience_reads_as_every_member() {
        // Arrange
        let token = verified(json!({ "aud": ["https://a.example", "https://b.example"] }));

        // Act
        let named = audiences(&token);

        // Assert
        assert_eq!(named, vec!["https://a.example", "https://b.example"]);
    }

    /// A token with no `aud`, or one whose `aud` is neither shape, names no
    /// audience — so it entitles no resource server. RFC 9068 §2.2 makes the
    /// claim REQUIRED, so this is not a token this server mints, and the safe
    /// answer to an unanswerable question is "nobody".
    #[test]
    fn a_missing_or_malformed_audience_names_nobody() {
        for claims in [json!({}), json!({ "aud": 7 }), json!({ "aud": [7, {}] })] {
            // Arrange
            let token = verified(claims.clone());

            // Act
            let named = audiences(&token);

            // Assert
            assert!(named.is_empty(), "{claims} named an audience");
        }
    }

    /// The fake source's bookkeeping is what the non-divergence assertions in
    /// `tests/introspection.rs` are built on, so it is worth one test of its
    /// own: an unrecorded read would make those assertions pass vacuously.
    #[tokio::test]
    async fn the_test_source_records_every_read() {
        // Arrange
        let source = Source::default();

        // Act
        source.is_denylisted("j").await.expect("a fake read");
        source
            .access_tokens_revoked_before(&ClientId::new("c"), None)
            .await
            .expect("a fake read");
        source.resource_servers().await.expect("a fake read");

        // Assert
        assert_eq!(source.reads.taken(), vec!["denylist", "cutoff", "registry"]);
    }
}
