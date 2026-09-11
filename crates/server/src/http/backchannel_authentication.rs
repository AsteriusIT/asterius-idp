//! `POST /bc-authorize` — CIBA Core 1.0 §7.1, §7.2 and §7.3.
//!
//! Where a client asks this server to obtain a person's approval *without a
//! browser*. It hands back an `auth_req_id`, and the client either polls the
//! token endpoint with it (§10.1) or waits to be notified (§10.2); the person
//! is asked somewhere else entirely, minutes later.
//!
//! # This is the one endpoint that names somebody who is not here
//!
//! Every other flow in this server begins with a user in front of a browser.
//! This one begins with a client asserting an identity through a *hint*, and
//! this server resolving it. Three consequences run through the whole module:
//!
//! * **The client is authenticated first, always.** FAPI-CIBA and ADR-0002:
//!   `private_key_jwt` or mTLS, through the same dispatch every other
//!   client-authenticated endpoint uses. Nothing about a person is looked up
//!   for a caller that has not proved who it is.
//! * **A hint that resolves to nobody is `unknown_user_id` and nothing more.**
//!   §13 names the code, so the oracle is the specification's rather than
//!   this server's invention — but it *is* an oracle, and
//!   `docs/threat-model.md` states the boundary and what bounds it: an
//!   authenticated, registered client, and one `backchannel.refused` record
//!   per probe.
//! * **The request is recorded as pending and acted on by nobody here.** The
//!   row is the whole of what this endpoint produces beside the
//!   acknowledgement: the approvals inbox (`ast-lh3.6`) reads it, the token
//!   endpoint (`ast-lh3.5`) spends it.
//!
//! # Three limits, because three different things are being spent
//!
//! `ast-5lw`. An authenticated client used to be able to raise an unbounded
//! number of approval requests against one person: every one of them sends a
//! message and puts another line in their inbox, which is
//! approval fatigue — press approve to make it stop — and a way to flood a
//! mailbox. So:
//!
//! * the address and client buckets of [`crate::http::limits`], through
//!   `guard`, after client authentication so the client charged is one that
//!   proved who it is;
//! * a bucket keyed by the *person the hint resolved to*
//!   ([`LimitedEndpoint::Backchannel`]'s `per_subject`), which is the only
//!   limit here counting something a third party pays for. Keyed by the
//!   resolved account rather than by the hint as it was typed, so that an
//!   address, a username and an `id_token_hint` naming one person are one
//!   budget;
//! * a ceiling on how many requests may be *waiting* for one person at once
//!   ([`ciba::MAX_PENDING_PER_USER`]), which is what the two rate limits
//!   cannot express: a window that rolls over lets a slow, patient client keep
//!   an inbox permanently full.
//!
//! The refusals are §13 error objects, and the two rate-limit refusals are
//! byte-identical: a client cannot tell the client bucket from the subject
//! bucket, and so cannot use a 429 to learn that a hint named somebody real.
//! It never learns anything new from them anyway — §13's `unknown_user_id` is
//! the oracle the specification mandates, and it is already documented in
//! `docs/threat-model.md`.
//!
//! # The client-assertion audience is wider here, and only here
//!
//! §7.1: an OP that takes JWT client assertions at this endpoint "MUST accept
//! its Issuer Identifier, Token Endpoint URL, or Backchannel Authentication
//! Endpoint URL" as `aud`. FAPI 2.0 SP §5.3.2.1 item 8 says "issuer only", and
//! everywhere else in this server that is what
//! [`AssertionRules::for_issuer`] enforces. The widening is
//! [`Audiences::ciba_backchannel`], it is applied at this handler and nowhere
//! else, and it widens the accepted *values* without touching the form rule —
//! `aud` is still a string, never an array, so an assertion naming this server
//! and somebody else is still refused.

use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::entities::client::GrantType;
use asterius_domain::rate_limit::LimitedEndpoint;
use asterius_domain::{AuditSink, Client, ClientRepository, KeyStore, Tenant, User};
use asterius_jose::client_keys::ClientKeyCache;
use asterius_jose::verify::{Policy, TypRule};
use asterius_oidc::ciba::{self, BackchannelRequest, CibaError, Hint, MintedAuthReqId, Submission};
use asterius_oidc::client_auth::{AssertionRules, Attempt, Audiences, ClientAuthError};
use asterius_oidc::form::Parameters;
use asterius_oidc::metadata::Endpoint;
use asterius_store_pg::PgUserRepository;
use asterius_store_pg::{NewCibaRequest, PgCibaRequestRepository, PingCredentials};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, body::Bytes};
use serde_json::json;
use time::OffsetDateTime;

/// The largest form body this endpoint will read.
///
/// The same 16 KiB the token, pushed-request and device-authorization
/// endpoints allow. A backchannel authentication request is a client
/// assertion, a hint that may itself be a JWT and — in the §7.1.1 shape — a
/// second JWT carrying every parameter, so the bound covers three tokens
/// comfortably and refuses a megabyte somebody posted for fun.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// What the handler needs.
pub struct BackchannelContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This tenant's clients.
    pub clients: &'a dyn ClientRepository,
    /// This tenant's users, for resolving a hint.
    pub users: &'a PgUserRepository,
    /// This tenant's signing keys, for an `id_token_hint` this server issued.
    pub keys: &'a dyn KeyStore,
    /// The *clients'* keys, for a §7.1.1 signed request.
    pub client_keys: &'a ClientKeyCache,
    /// Where the pending request is recorded.
    pub ciba_requests: &'a PgCibaRequestRepository,
    /// Where the decision is recorded.
    pub audit: &'a dyn AuditSink,
    /// How the person is told that something is waiting for them
    /// (`ast-lh3.6`).
    ///
    /// CIBA Core 1.0 §8 has the decision taken on a device the client never
    /// touches. A request nobody is told about is a request that expires
    /// unseen, so the notification is part of accepting one — but only part:
    /// the answer to the client is the same whether or not a message could be
    /// handed off, because §7.3's acknowledgement says nothing about the
    /// person and must not start saying whether they are reachable.
    pub mail: &'a dyn asterius_domain::MailSender,
    /// The client certificate this request arrived with (RFC 8705 §2), if the
    /// deployment saw one from a source it trusts.
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    /// Whether this tenant offers Grant Management, and whether it requires an
    /// action (ID1 §7.1).
    pub grant_management: asterius_oidc::grant_management::Policy,
    /// The per-endpoint limiter (`ast-5lw`), carrying this request's address,
    /// the trail and one clock reading.
    pub limits: crate::http::limits::LimitContext<'a>,
    /// The request identifier, for correlating the audit record with the logs.
    pub request_id: Option<&'a str>,
}

impl std::fmt::Debug for BackchannelContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackchannelContext").finish_non_exhaustive()
    }
}

/// Handles a backchannel authentication request.
///
/// # Errors
///
/// Never returns `Err`: every failure is a `Response` in the shape §13
/// specifies, which is RFC 6749 §5.2's object with CIBA's own codes in it.
pub async fn authorize(
    context: BackchannelContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    authenticate: impl AsyncFnOnce(&Attempt<'_>, &AssertionRules) -> Result<Client, ClientAuthError>,
    now: OffsetDateTime,
) -> Response {
    if body.len() > MAX_BODY_BYTES {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "body too large",
        );
    }
    if !crate::http::token::is_form_encoded(headers) {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request",
            "content-type must be application/x-www-form-urlencoded",
        );
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "body is not UTF-8",
        );
    };
    // Pairs rather than a map: RFC 6749 §3.1 forbids a repeated parameter, and
    // a map would resolve one silently before anything could object.
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    // First, so that every later error is one an authenticated client is
    // entitled to see — and so that the hint of an unauthenticated caller is
    // never resolved against this tenant's directory.
    let attempt = Attempt {
        assertion: find(&pairs, "client_assertion"),
        assertion_type: find(&pairs, "client_assertion_type"),
        client_id: find(&pairs, "client_id"),
        authorization_header: headers.contains_key(header::AUTHORIZATION),
        certificate: context.certificate,
    };
    let client = match authenticate(&attempt, &assertion_rules(context.tenant)).await {
        Ok(client) => client,
        Err(failure) => {
            return error(
                StatusCode::from_u16(failure.status()).unwrap_or(StatusCode::UNAUTHORIZED),
                failure.code(),
                "client authentication failed",
            );
        }
    };

    // §13's `unauthorized_client`, decided before the request is read. A
    // client without the grant is told what is wrong with *it* rather than
    // what is wrong with a request it was never entitled to make — and this is
    // where FAPI-CIBA's refusal of push lands for a client that somehow holds
    // one, since a delivery mode this server does not answer in cannot survive
    // `ClientRegistration`.
    if !client.registration.allows(GrantType::Ciba) {
        return refused(&context, &client, None, &CibaError::UnauthorizedClient, now).await;
    }

    // After authentication, like the SSF management endpoints': the client
    // charged is one that proved who it is, so nobody can spend a competitor's
    // budget by naming them. The address bucket still holds everything that
    // did not succeed.
    let params = Parameters::from_pairs(pairs);
    crate::http::limits::guard(
        &context.limits,
        LimitedEndpoint::Backchannel,
        Some(client.id.as_str()),
        async || recorded(&context, &client, params, now).await,
    )
    .await
}

/// Everything after client authentication: validate, resolve, record, answer.
///
/// Split from [`authorize`] because the preamble is about *this HTTP request*
/// — its size, its media type, its encoding, its credential — and this is
/// about the CIBA request inside it. Two concerns, and the second is the one a
/// reader comes here for.
async fn recorded(
    context: &BackchannelContext<'_>,
    client: &Client,
    params: Parameters,
    now: OffsetDateTime,
) -> Response {
    let request = match validated(context, client, &params, now).await {
        Ok(request) => request,
        Err(failure) => return refused(context, client, None, &failure, now).await,
    };

    // §7.2 step 2: the hint names a user, or the request has no subject and
    // §13's `unknown_user_id` is the answer.
    let user = match resolved(context, client, &request.hint, now).await {
        Ok(user) => user,
        Err(failure) => return refused(context, client, None, &failure, now).await,
    };

    // Both limits about the *person*, before anything is written or sent.
    // The order is: count this request against them, then refuse if their
    // inbox is already full. A request refused by either has still cost the
    // subject bucket, which is deliberate — the budget is "attempts to bother
    // this person", not "times we succeeded".
    if let Some(refusal) = crate::http::limits::guard_subject(
        &context.limits,
        LimitedEndpoint::Backchannel,
        &user.id.as_uuid().to_string(),
    )
    .await
    {
        return refusal;
    }
    if let Err(failure) = self::room_for_one_more(context, &user, now).await {
        return refused(context, client, None, &failure, now).await;
    }

    let minted = MintedAuthReqId::generate();
    // Unreachable: the grant and the mode are registered together
    // (`0020_ciba_client_metadata.sql`), and `validate` has already refused a
    // policy with no mode. Answered rather than asserted, because a panic here
    // would be a request that killed a task.
    let Some(delivery_mode) = client.registration.backchannel_token_delivery_mode else {
        return refused(context, client, None, &CibaError::UnauthorizedClient, now).await;
    };
    let new = NewCibaRequest {
        client_id: client.id.as_str().to_owned(),
        user_id: user.id,
        scopes: request.scopes.iter().cloned().collect(),
        authorization_details: serde_json::Value::Array(request.authorization_details.to_json()),
        acr_values: request.acr_values.clone(),
        binding_message: request.binding_message.clone(),
        delivery_mode: delivery_mode.as_str().to_owned(),
        // In ping mode the store keeps what the §10.2 notification will
        // present — this `auth_req_id` and the token — sealed under the
        // tenant's KEK, and the token's digest beside it. Neither reaches the
        // row in the clear; see `0034_ciba_ping_credentials.sql`.
        ping: request
            .client_notification_token
            .as_deref()
            .map(|token| PingCredentials {
                auth_req_id: minted.expose().to_owned(),
                client_notification_token: token.to_owned(),
            }),
        expires_at: now + request.expires_in,
        interval: ciba::POLL_INTERVAL,
    };

    if let Err(failure) = context
        .ciba_requests
        .issue(minted.digest(), &new, now)
        .await
    {
        tracing::error!(
            %failure,
            client = %client.id,
            tenant = %context.tenant.id,
            "cannot record a backchannel authentication request"
        );
        return unavailable();
    }

    notify(context, client, &user, &request, now).await;

    record(
        context,
        client,
        Some(&user),
        Outcome::Success,
        Detail::new()
            .label("delivery_mode", delivery_mode.as_str())
            .label("hint", request.hint.parameter())
            .number("expires_in", request.expires_in.whole_seconds())
            .flag("binding_message", request.binding_message.is_some()),
        EventType::BACKCHANNEL_REQUESTED,
        now,
    )
    .await;

    // §7.3's acknowledgement. Three members and no more: the client learns
    // nothing here about the person, about whether they are reachable, or
    // about what they will be shown.
    (
        StatusCode::OK,
        crate::http::token::no_store(),
        Json(json!({
            "auth_req_id": minted.expose(),
            "expires_in": request.expires_in.whole_seconds(),
            "interval": ciba::POLL_INTERVAL.whole_seconds(),
        })),
    )
        .into_response()
}

/// Whether this person has room for another pending request (`ast-5lw`).
///
/// [`ciba::MAX_PENDING_PER_USER`] and its documentation carry the decision:
/// the *new* request is refused, and nothing already waiting is touched.
///
/// Counted from the same read the approvals inbox renders itself from, rather
/// than from a `count(*)` of its own, so "what is waiting" means one thing in
/// this server: a row that is pending, unexpired and this person's. A store
/// that cannot be read is [`CibaError::AccessDenied`] for the reason
/// [`directory_failure`] gives — "we could not look" is not "there is room".
///
/// The refusal names no user in the trail and says nothing about the person to
/// the client beyond what the request already asserted about them.
async fn room_for_one_more(
    context: &BackchannelContext<'_>,
    user: &User,
    now: OffsetDateTime,
) -> Result<(), CibaError> {
    let waiting = context
        .ciba_requests
        .pending_for_user(&user.id, now)
        .await
        .map_err(|failure| {
            tracing::error!(
                %failure,
                tenant = %context.tenant.id,
                "cannot count the approvals already waiting for a user"
            );
            CibaError::AccessDenied
        })?;
    if ciba::room_for_another_pending(waiting.len()) {
        Ok(())
    } else {
        Err(CibaError::TooManyPending)
    }
}

/// Tells the person that something is waiting for them (`ast-lh3.6`).
///
/// The link is to the inbox and never to one request: a URL that decided which
/// approval was being answered would be a URL somebody could aim a person at,
/// and §7.1's `binding_message` exists precisely so that the decision rests on
/// comparing two screens rather than on having followed a link. The message
/// carries that same binding message, for that comparison.
///
/// Every failure is logged and swallowed. An account with no address cannot be
/// mailed and the client is not told so; a sender that refuses is this
/// deployment's problem and not the client's. §10.2's ping is the *client's*
/// notification and is queued by the decision, not here.
async fn notify(
    context: &BackchannelContext<'_>,
    client: &Client,
    user: &asterius_domain::User,
    request: &BackchannelRequest,
    now: OffsetDateTime,
) {
    let Some(address) = user.email.clone() else {
        tracing::info!(
            tenant = %context.tenant.id,
            client = %client.id,
            "a backchannel request was accepted for an account with no address; \
             nothing was sent, and the request waits in the inbox"
        );
        return;
    };
    // Absolute, for the recovery link's reason: it is going into a message,
    // and a browser opening it has no page to resolve a relative path
    // against. Built from the tenant's issuer, so a path-mounted tenant's
    // link comes back through the prefix it is served under (`ast-295`).
    let link = format!(
        "{}{}",
        context.tenant.issuer.as_str().trim_end_matches('/'),
        crate::http::approvals::PAGE_PATH,
    );
    let message = asterius_domain::Notification::approval_requested(
        address,
        link,
        client.registration.client_name.clone(),
        request.binding_message.clone(),
        (request.expires_in).whole_minutes(),
    );
    let _ = now;
    if let Err(error) = context.mail.send(&message).await {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            "cannot hand off an approval notification; the request still waits in the inbox"
        );
    }
}

/// The assertion rules this endpoint applies, and no other one does.
///
/// §7.1's three audiences. Built from [`Endpoint`] rather than written out, so
/// the URL a client is told to audience its assertion at — the one in
/// `backchannel_authentication_endpoint` — is the URL that is accepted here.
fn assertion_rules(tenant: &Tenant) -> AssertionRules {
    AssertionRules {
        audiences: Audiences::ciba_backchannel(
            tenant.issuer.as_str(),
            Endpoint::Token.url(&tenant.issuer),
            Endpoint::BackchannelAuthentication.url(&tenant.issuer),
        ),
        ..AssertionRules::for_issuer(tenant.issuer.as_str())
    }
}

/// Reads the request, unwrapping a §7.1.1 signed one first.
///
/// The signed shape is verified and then turned into the *same* parameters an
/// unsigned request would have arrived as, so [`ciba::validate`] is the only
/// place a backchannel authentication request is judged.
async fn validated(
    context: &BackchannelContext<'_>,
    client: &Client,
    params: &Parameters,
    now: OffsetDateTime,
) -> Result<BackchannelRequest, CibaError> {
    let policy = ciba::RequestPolicy::of(&client.registration, context.grant_management);
    let inner = match ciba::submission(params, &client.registration)? {
        Submission::Direct => None,
        Submission::Signed(jwt) => Some(signed_parameters(context, client, &jwt, now).await?),
    };
    ciba::validate(
        inner.as_ref().unwrap_or(params),
        client.id.as_str(),
        &client.registration,
        policy,
    )
}

/// Verifies a §7.1.1 signed authentication request and reads its claims.
///
/// The algorithm is the registered one and only that one, exactly as a request
/// object is verified at `/par`: a client that registered `ES256` and sends
/// `PS256` is refused although both are on ADR-0003's list, because the
/// alternative lets a client downgrade itself. There is no `none`, because
/// [`asterius_domain::SigningAlgorithm`] cannot parse one.
///
/// §7.1.1 adds three claims to what a request object needs — `iat`, `nbf` and
/// `jti` — and they are required here rather than left to the generic
/// verifier: the JWT is a *replayable* authorization to bother a person, and
/// the three together are what bound the window and identify a repeat.
async fn signed_parameters(
    context: &BackchannelContext<'_>,
    client: &Client,
    jwt: &str,
    now: OffsetDateTime,
) -> Result<Parameters, CibaError> {
    let algorithm = client
        .registration
        .backchannel_authentication_request_signing_alg
        .ok_or(CibaError::Invalid("request"))?;

    // Parsed, not trusted: the only thing read before verification is the
    // `kid`, and only to narrow an already-trusted set of the client's keys.
    let unverified = asterius_jose::jws::parse(jwt).map_err(|_| CibaError::Invalid("request"))?;
    let key_set = context
        .client_keys
        .resolve(
            &context.tenant.id,
            &client.id,
            &client.registration.jwks,
            unverified.kid().as_ref(),
            now,
        )
        .await
        .map_err(|_| CibaError::Invalid("request"))?;

    // CIBA §7.1.1 registers no `typ` for the object, so one is not required —
    // but the list stays closed: a JWT announcing itself as an access token or
    // a DPoP proof is not a backchannel authentication request whatever it
    // carries.
    let policy = Policy::new(TypRule::OptionalOneOf(&["JWT", "jwt"]), vec![algorithm])
        .issued_by(client.id.as_str());
    let verified = asterius_jose::verify::verify(jwt, &policy, &key_set, now)
        .map_err(|_| CibaError::Invalid("request"))?;

    // §7.1.1: "`iat` ... `nbf` ... `jti` ... REQUIRED".
    for claim in ["iat", "nbf", "jti"] {
        if verified.claims.get(claim).is_none() {
            return Err(CibaError::Invalid("request"));
        }
    }

    // `iss`, `aud` and `exp` are §7.1.1's too, and the same three a request
    // object carries — so the same reader states them, rather than a second
    // one that could come to a different conclusion about an `aud` array.
    asterius_oidc::request_object::parameters(
        &verified.claims,
        client.id.as_str(),
        context.tenant.issuer.as_str(),
        now,
    )
    .map_err(|_| CibaError::Invalid("request"))
}

/// Turns §7.1's hint into the user it names (§7.2 step 2).
///
/// Each of the three hints is resolved by its own rule, and all three end in
/// the same refusal where they name nobody:
///
/// * **`login_hint`** is looked up as an address and then as a username. Two
///   lookups rather than a guess at which it is: an operator's login policy is
///   not something a client knows, and a hint that is a username at one tenant
///   is an address at another.
/// * **`id_token_hint`** must be an ID token *this tenant signed*, audienced
///   at *this client*, whose `sub` resolves in any sector. Expiry is ignored,
///   which OIDC Core §3.1.2.1 requires of an OP reading a hint — a client
///   holding a two-hour-old ID token is the ordinary case.
/// * **`login_hint_token`** is §14's, and §14 requires the OP to know which
///   issuers it will take one from. This deployment has no such configuration,
///   so there is no issuer whose signature would be accepted and the parameter
///   is refused with `invalid_request` — which is the acceptance criterion's
///   own answer for a token "not signed by a configured issuer", and the only
///   safe one: the alternative is reading an unverified assertion about who
///   somebody is.
async fn resolved(
    context: &BackchannelContext<'_>,
    client: &Client,
    hint: &Hint,
    now: OffsetDateTime,
) -> Result<User, CibaError> {
    match hint {
        Hint::Login(value) => {
            let found = match context.users.find_by_email(value).await {
                Ok(Some(user)) => Some(user),
                Ok(None) => context
                    .users
                    .find_by_username(value)
                    .await
                    .map_err(|failure| directory_failure(context, &failure))?,
                Err(failure) => return Err(directory_failure(context, &failure)),
            };
            found.ok_or(CibaError::UnknownUserId)
        }
        Hint::IdToken(value) => {
            let Some(claims) = crate::http::id_token_hint::verified_claims(
                context.keys,
                context.tenant,
                value,
                now,
            )
            .await
            else {
                // A token this tenant did not sign is not a hint about
                // anybody here. `invalid_request` rather than
                // `unknown_user_id`: nothing was resolved, so nothing is
                // being said about whether a user exists.
                return Err(CibaError::Invalid("id_token_hint"));
            };
            if !crate::http::id_token_hint::names_client(&claims, client.id.as_str()) {
                tracing::warn!(
                    tenant = %context.tenant.id,
                    client = %client.id,
                    "an id_token_hint issued to another client was presented at bc-authorize"
                );
                return Err(CibaError::Invalid("id_token_hint"));
            }
            let Some(subject) = crate::http::id_token_hint::subject(&claims) else {
                return Err(CibaError::Invalid("id_token_hint"));
            };
            context
                .users
                .find_by_subject(&asterius_domain::SubjectId::new(subject.to_owned()))
                .await
                .map_err(|failure| directory_failure(context, &failure))?
                .ok_or(CibaError::UnknownUserId)
        }
        // §14. No configured issuer, so no token from one.
        Hint::LoginToken(_) => Err(CibaError::Invalid("login_hint_token")),
    }
}

/// A directory that could not be read is not a user that does not exist.
///
/// Answered as `access_denied` rather than `unknown_user_id`, because the
/// second would tell a client that a hint names nobody when what happened is
/// that this server could not look. A client that retried on the strength of
/// it would be probing a database that is down.
fn directory_failure(
    context: &BackchannelContext<'_>,
    failure: &asterius_domain::DomainError,
) -> CibaError {
    tracing::error!(
        %failure,
        tenant = %context.tenant.id,
        "cannot resolve a backchannel authentication hint"
    );
    CibaError::AccessDenied
}

/// Renders a §13 refusal and records it.
async fn refused(
    context: &BackchannelContext<'_>,
    client: &Client,
    user: Option<&User>,
    failure: &CibaError,
    now: OffsetDateTime,
) -> Response {
    tracing::debug!(
        error = %failure,
        client = %client.id,
        tenant = %context.tenant.id,
        "backchannel authentication request refused"
    );
    record(
        context,
        client,
        user,
        Outcome::Failure,
        Detail::new().label("error", failure.code()),
        EventType::BACKCHANNEL_REFUSED,
        now,
    )
    .await;
    error(
        StatusCode::from_u16(failure.status()).unwrap_or(StatusCode::BAD_REQUEST),
        failure.code(),
        &failure.to_string(),
    )
}

/// Writes one event about this request.
///
/// The *user* is on the record when there is one, because the question this
/// trail has to answer is "which client asked about which person" — and it is
/// absent from every refusal, because a refusal that named a user would put
/// the answer to `unknown_user_id` in the trail for anybody who can read it.
async fn record(
    context: &BackchannelContext<'_>,
    client: &Client,
    user: Option<&User>,
    outcome: Outcome,
    detail: Detail,
    event_type: EventType,
    now: OffsetDateTime,
) {
    let mut event = AuditEvent::new(
        context.tenant.id.clone(),
        event_type,
        outcome,
        Actor::Client(client.id.clone()),
        now,
    )
    .client(client.id.clone())
    .detail(detail);
    if let Some(user) = user {
        // The account identifier, not the hint: a `login_hint` is an address
        // somebody typed and the trail is not the place for one.
        event = event.subject(user.id.as_uuid().to_string());
    }
    if let Some(request_id) = context.request_id {
        event = event.request_id(request_id);
    }
    if let Err(failure) = context.audit.record(event).await {
        tracing::error!(
            %failure,
            tenant = %context.tenant.id,
            "a backchannel authentication request was not written to the audit trail"
        );
    }
}

/// What a client is told when this server could not record its request.
///
/// `temporarily_unavailable` and a 503, as at the device authorization
/// endpoint: retrying is the right thing to do, and a `server_error` would
/// tell the client to stop.
fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "the backchannel authentication request could not be recorded",
    )
}

/// The first value of `name`, for client authentication only.
fn find<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// A §13 error object, in the shape the token endpoint renders.
fn error(status: StatusCode, code: &str, description: &str) -> Response {
    crate::http::token::error(status, code, description)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::Issuer;

    fn tenant() -> Tenant {
        Tenant {
            id: asterius_domain::TenantId::parse("demo").expect("a tenant id"),
            issuer: Issuer::parse("https://as.example/t/demo").expect("an issuer"),
            default_resource: "https://api.example/".to_owned(),
            custom_host: None,
            display_name: "demo".to_owned(),
            status: asterius_domain::TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// CIBA Core 1.0 §7.1: the three audiences, and only at this endpoint.
    #[test]
    fn the_assertion_audience_is_the_three_values_the_specification_names() {
        // Arrange
        let tenant = tenant();

        // Act
        let rules = assertion_rules(&tenant);

        // Assert
        assert_eq!(
            rules.audiences.accepted(),
            [
                "https://as.example/t/demo".to_owned(),
                "https://as.example/t/demo/token".to_owned(),
                "https://as.example/t/demo/bc-authorize".to_owned(),
            ]
        );
    }

    /// FAPI 2.0 SP §5.3.2.1 item 8 elsewhere: the widening is this endpoint's
    /// alone, and every other endpoint still takes the issuer and nothing
    /// else.
    #[test]
    fn no_other_endpoint_widens_its_audiences() {
        // Arrange
        let tenant = tenant();

        // Act
        let elsewhere = AssertionRules::for_issuer(tenant.issuer.as_str());

        // Assert
        assert_eq!(
            elsewhere.audiences.accepted(),
            ["https://as.example/t/demo".to_owned()]
        );
    }

    /// The lifetime cap is the tenant's, not the client's: a rule stated in
    /// two places is a rule that drifts, so the assertion rules this endpoint
    /// builds keep the deployment's ceiling.
    #[test]
    fn widening_the_audience_does_not_widen_the_assertion_lifetime() {
        // Arrange
        let tenant = tenant();

        // Act
        let rules = assertion_rules(&tenant);

        // Assert
        assert_eq!(
            rules.max_lifetime,
            AssertionRules::for_issuer(tenant.issuer.as_str()).max_lifetime
        );
    }
}
