//! The interaction endpoints: the pages a user actually walks through.
//!
//! `GET /interaction/{id}` renders whatever stage the interaction has reached;
//! `POST /interaction/{id}` takes the decision and advances it. The rules —
//! the id/cookie pair, the CSRF token, the stage machine — are
//! [`asterius_web::interaction`], and the pages are `asterius_web::pages`.
//! What lives here is the HTTP.
//!
//! # The order every request goes through
//!
//! 1. **The two credentials.** The id in the path and the id in the
//!    `__Host-` cookie must both be present and equal. A mismatch is fatal:
//!    the interaction is destroyed and the cookie cleared.
//! 2. **The record.** Absent, expired and already-consumed are one answer —
//!    the error page — because a browser that could tell them apart could
//!    probe for live interactions.
//! 3. **The CSRF token**, on a POST only.
//! 4. **The stage transition**, which the state machine either permits or
//!    does not.
//!
//! Nothing later re-checks what an earlier step established, and nothing
//! earlier depends on a later one.
//!
//! # What is not here yet
//!
//! Verifying a credential. `ast-2vk.5` (passwords) and `ast-2vk.3`/`ast-2vk.4`
//! (passkeys) own that, and until one of them lands `CredentialVerifier` has
//! no implementation. The seam is typed rather than stubbed: a deployment with
//! no authenticator renders the login page and refuses the submission with a
//! fixed message, which is what a server that cannot sign anybody in should
//! do. It does not pretend to authenticate.

use crate::http::redirect::SeeOther;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::session::SessionId;
use asterius_domain::{
    AuthenticationMethod, CodeBinding, CodeIssuer, CredentialVerifier, Grant, GrantRepository,
    InteractionRecord, InteractionRepository, Lifetimes, Secret, SectorIdentifier, Session,
    SessionId as DomainSessionId, SessionRepository, SubjectResolver, Tenant, TenantId, UserId,
};
use asterius_oidc::code::{self, AuthorizationResponse, MintedCode};
use asterius_oidc::consent::{ConsentRequest, Decision};
use asterius_web::interaction::{
    self, CsrfToken, InteractionError, InteractionId, Stage, StoredDecision, StoredState,
};
use asterius_web::pages::{self, ConsentPage, ErrorPage, LoginPage, ScopeLine, nonce_attribute};
use asterius_web::{Document, csp::Nonce};
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::{Duration, OffsetDateTime};

/// What the handlers need.
pub struct InteractionContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This tenant's interactions.
    pub requests: &'a dyn InteractionRepository,
    /// How to check a credential, when this deployment has a method.
    pub credentials: Option<&'a dyn CredentialVerifier>,
    /// Where a successful sign-in becomes a session.
    pub sessions: &'a dyn SessionRepository,
    /// How long this tenant's sessions live.
    pub lifetimes: Lifetimes,
    /// Who is signed in, shown on the consent screen so a user on a shared
    /// machine can see whose account is about to be granted.
    pub username: Option<&'a str>,
    /// This tenant's clients, for the name and metadata the consent screen
    /// shows.
    ///
    /// Read only when the consent stage is actually rendered. Loading a
    /// registration to draw a form nobody has authenticated for would be work
    /// an unauthenticated visitor can make this server do.
    pub clients: &'a dyn asterius_domain::ClientRepository,
    /// Where a completed authorization is recorded.
    pub grants: &'a dyn GrantRepository,
    /// Where the code that carries it is stored.
    ///
    /// The issuing half only. This handler has no way to *redeem* a code, and
    /// that is deliberate — see [`asterius_domain::CodeIssuer`].
    pub codes: &'a dyn CodeIssuer,
    /// How the `sub` this client will see is resolved (OIDC Core §8.1).
    pub subjects: &'a dyn SubjectResolver,
    /// How long an issued code lives, clamped to the profile's 60-second cap.
    pub code_lifetime: Duration,
    /// The CSP nonce the document middleware drew for this response.
    pub nonce: &'a Nonce,
    /// Where the security-relevant things that happen here are recorded.
    ///
    /// The interaction endpoints are where a person authenticates and where a
    /// credential of theirs comes into existence, and neither is something the
    /// trail can be missing. [`record_passkey_registered`] is the first user.
    pub audit: &'a dyn AuditSink,
}

impl std::fmt::Debug for InteractionContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractionContext").finish_non_exhaustive()
    }
}

/// Builds the trail record for a passkey that has just been registered.
///
/// Separate from [`record_passkey_registered`] so the shape of the event can be
/// asserted without a sink, a tenant and eight repositories.
///
/// Three identities are named, and each answers a different question. The
/// tenant says whose directory grew a credential; the subject and the
/// [`Actor::User`] say for whom, and they are the same person here because a
/// passkey is registered by its owner and by nobody else — an operator adding
/// a credential to somebody else's account would be an [`Actor::Admin`] event,
/// which this is not. The credential is named by the digest of its row id
/// rather than by the id: `Detail::text` classifies a UUID as
/// credential-shaped and would redact it anyway, and a digest is how the rest
/// of this trail says *which* one. It is deterministic, so every
/// `credential.*` event about one passkey lines up, and an investigator
/// holding the row id can hash it to find them.
#[must_use]
pub fn passkey_registered_event(
    tenant: &TenantId,
    user: &UserId,
    credential: &uuid::Uuid,
    now: OffsetDateTime,
) -> AuditEvent {
    let subject = user.as_uuid().to_string();
    AuditEvent::new(
        tenant.clone(),
        EventType::CREDENTIAL_CREATED,
        Outcome::Success,
        Actor::User(subject.clone()),
        now,
    )
    .subject(subject)
    .detail(
        Detail::new()
            .label("kind", "passkey")
            .label("method", AuthenticationMethod::Passkey.as_str())
            .credential("credential_id", credential.to_string()),
    )
}

/// Appends a registered passkey to the audit trail.
///
/// A failure is logged and does not propagate, which is the call
/// `http::register` makes and for the same reason: the credential row is
/// already committed by the time this runs, and failing the ceremony
/// afterwards would leave a user holding an authenticator the server told them
/// had not been registered. The transactional outbox (`ast-0ju.9`) is what
/// closes that gap for good.
pub async fn record_passkey_registered(
    context: &InteractionContext<'_>,
    user: &UserId,
    credential: &uuid::Uuid,
    now: OffsetDateTime,
) {
    let event = passkey_registered_event(&context.tenant.id, user, credential, now);
    if let Err(failure) = context.audit.record(event).await {
        tracing::error!(
            %failure,
            tenant = %context.tenant.id,
            "a registered passkey was not written to the audit trail"
        );
    }
}

/// `GET /interaction/{id}` — render the current stage.
pub async fn show(
    context: InteractionContext<'_>,
    id: &str,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let (presented, mut state, record) = match resume(&context, id, headers, now).await {
        Ok(resumed) => resumed,
        Err(response) => return *response,
    };

    // A fresh token per rendering. Reloading the page twice before deciding is
    // something a user does, and each rendering carries its own token — the
    // previous one stops working, which is the same rule as one submission per
    // token seen from the other side.
    let token = state.issue_csrf();
    if let Err(error) = save(&context, &presented, &state, None, now).await {
        return *error;
    }

    let offer = describe(&context, &record).await;
    render(&context, state.stage, &token, id, None, offer.as_ref())
}

/// Builds the consent offer for a request, when one is needed.
///
/// Returns `None` for any stage that does not show it, and for a client that
/// has gone away between the push and now — which renders the error page
/// rather than a consent screen naming nobody.
async fn describe(
    context: &InteractionContext<'_>,
    record: &InteractionRecord,
) -> Option<ConsentRequest> {
    let client = context.clients.find(&record.client).await.ok()??;

    // The redirect URI was validated at push time against this client's
    // registered set, so its host is one the client actually owns — which is
    // what makes showing it worth anything (FAPI 2.0 SP §7).
    let redirect_host = record
        .parameters
        .get("redirect_uri")
        .and_then(serde_json::Value::as_str)
        .and_then(|uri| url::Url::parse(uri).ok())
        .and_then(|uri| uri.host_str().map(ToOwned::to_owned))
        .unwrap_or_default();

    let scopes: std::collections::BTreeSet<String> = record
        .parameters
        .get("scopes")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();

    let resources = record
        .parameters
        .get("resources")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();

    Some(ConsentRequest::new(
        client.registration.client_name.clone(),
        redirect_host,
        &scopes,
        resources,
        // Per-tenant scope wording is `ast-ndk.2`. Until then a scope is shown
        // by name, which is honest: an unexplained scope should look
        // unexplained.
        |_| None,
    ))
}

/// `POST /interaction/{id}` — take a decision and advance.
pub async fn submit(
    context: InteractionContext<'_>,
    id: &str,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let (presented, mut state, record) = match resume(&context, id, headers, now).await {
        Ok(resumed) => resumed,
        Err(response) => return *response,
    };

    let form: Vec<(String, String)> = url::form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let field = |name: &str| {
        form.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    // The synchroniser token, before anything is acted on.
    if state.check_csrf(field("csrf")).is_err() {
        // 403 and the error page. Not a redirect back to the form: a request
        // that failed this check did not come from a page this server
        // rendered, and sending it a fresh token would be handing one out to
        // whoever forged it.
        return error_page(
            &context,
            StatusCode::FORBIDDEN,
            InteractionError::CsrfFailed,
        );
    }
    // Spent whatever happens next. A token that survived a failed submission
    // would let the same body be replayed until the interaction expired.
    state.spend_csrf();

    match state.stage {
        Stage::Login => sign_in(&context, &presented, state, id, &form, &record, now).await,
        Stage::Consent => decide(&context, &presented, state, &form, &record, now).await,
        // `ast-2vk.7` owns step-up. A submission at `Response` has nothing
        // left to submit: the request was spent when the response was sent.
        Stage::StepUp | Stage::Response => error_page(
            &context,
            StatusCode::NOT_IMPLEMENTED,
            InteractionError::NotAvailable,
        ),
    }
}

/// The login stage: check a credential, start a session, move on.
///
/// Its own function because `submit` is the dispatch and this is the only arm
/// with any depth — and because the clippy line limit is a reasonable proxy for
/// "this is doing more than one thing".
async fn sign_in(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    mut state: StoredState,
    id: &str,
    form: &[(String, String)],
    record: &InteractionRecord,
    now: OffsetDateTime,
) -> Response {
    let field = |name: &str| {
        form.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    let Some(credentials) = context.credentials else {
        // No method is registered, so nobody can sign in. Saying so is
        // better than a generic failure: the deployment is
        // misconfigured and an operator needs to know which way.
        let token = state.issue_csrf();
        if let Err(error) = save(context, presented, &state, None, now).await {
            return *error;
        }
        return render(
            context,
            Stage::Login,
            &token,
            id,
            Some("Signing in is not available on this server."),
            None,
        );
    };

    let (Some(username), Some(password)) = (field("username"), field("password")) else {
        return retry(
            context,
            presented,
            state,
            id,
            now,
            "Enter a username and password.",
        )
        .await;
    };

    match credentials
        .verify(username, Secret::new(password.to_owned()))
        .await
    {
        Ok(Some(user)) => {
            // A session id the browser has never held before. See
            // `asterius_domain::entities::session`: an id it held
            // *before* authenticating is one an attacker may have
            // planted, and this is the moment that stops mattering.
            let id_value = SessionId::generate();
            let session = Session::begin(
                context.tenant.id.clone(),
                &id_value,
                user,
                vec![AuthenticationMethod::Password],
                now,
                context.lifetimes,
            );
            if let Err(error) = context.sessions.begin(&session).await {
                tracing::error!(%error, "cannot start a session");
                return error_page(
                    context,
                    StatusCode::SERVICE_UNAVAILABLE,
                    InteractionError::NotAvailable,
                );
            }

            // `ast-2vk.7` decides whether a step-up is needed; until
            // then an authenticated user goes straight to consent.
            if state.stage.may_advance_to(Stage::Consent) {
                state.stage = Stage::Consent;
            }
            let token = state.issue_csrf();
            if let Err(error) =
                save(context, presented, &state, Some(&session.id_digest), now).await
            {
                return *error;
            }

            // Signed in, so the next screen is consent — which needs the
            // offer.
            let offer = describe(context, record).await;
            let mut response = render(context, state.stage, &token, id, None, offer.as_ref());
            set_session_cookie(&mut response, &id_value);
            response
        }
        // One message for "no such user" and "wrong password". The
        // verifier already equalises the *timing*; this equalises what
        // is said. Both halves are needed — identical text with a
        // measurable delay is still an oracle.
        Ok(None) => {
            retry(
                context,
                presented,
                state,
                id,
                now,
                "Those details did not match.",
            )
            .await
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot verify a credential");
            error_page(
                context,
                StatusCode::SERVICE_UNAVAILABLE,
                InteractionError::NotAvailable,
            )
        }
    }
}

/// The consent stage: record what the user actually agreed to.
///
/// A denial is an ordinary outcome and takes the same path as an approval —
/// both advance to [`Stage::Response`], where `ast-gxh.4` turns the decision
/// into either a code or an `access_denied`, through the same validated
/// redirect URI. Making refusal the harder path would be a consent screen that
/// does not really offer a choice.
async fn decide(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    mut state: StoredState,
    form: &[(String, String)],
    record: &InteractionRecord,
    now: OffsetDateTime,
) -> Response {
    let Some(offer) = describe(context, record).await else {
        tracing::error!(tenant = %context.tenant.id, "cannot describe a request at consent");
        return error_page(
            context,
            StatusCode::INTERNAL_SERVER_ERROR,
            InteractionError::NotAvailable,
        );
    };

    let approved = match form
        .iter()
        .find(|(k, _)| k == "decision")
        .map(|(_, v)| v.as_str())
    {
        Some("allow") => true,
        Some("deny") => false,
        // Neither button. A form this server did not render, or one a browser
        // submitted oddly; either way there is no decision to record.
        _ => {
            return error_page(
                context,
                StatusCode::BAD_REQUEST,
                InteractionError::CsrfFailed,
            );
        }
    };

    // Every ticked box. Unticked ones are simply absent, which is how an HTML
    // checkbox declines.
    let granted: std::collections::BTreeSet<String> = form
        .iter()
        .filter(|(k, _)| k == "scope")
        .map(|(_, v)| v.clone())
        .collect();

    let decision = match offer.decide(approved, &granted) {
        Ok(decision) => decision,
        Err(error) => {
            // The submission does not correspond to what was displayed. This
            // is not something a user does by hand.
            tracing::warn!(
                %error,
                tenant = %context.tenant.id,
                "a consent submission did not match the offer"
            );
            return error_page(
                context,
                StatusCode::BAD_REQUEST,
                InteractionError::CsrfFailed,
            );
        }
    };

    state.decision = Some(match &decision {
        Decision::Approved { scopes } => StoredDecision::Approved {
            scopes: scopes.iter().cloned().collect(),
        },
        Decision::Denied => StoredDecision::Denied,
    });
    if !state.stage.may_advance_to(Stage::Response) {
        return error_page(
            context,
            StatusCode::BAD_REQUEST,
            InteractionError::IllegalTransition,
        );
    }
    state.stage = Stage::Response;
    state.spend_csrf();

    if let Err(error) = save(context, presented, &state, None, now).await {
        return *error;
    }

    complete(context, presented, &decision, record, now).await
}

/// Turns the recorded decision into the authorization response.
///
/// # Why the request is spent before anything is minted
///
/// FAPI 2.0 SP §5.3.2.2 Note 3 puts one-time use at the completion of
/// authorization. This is that point, and the spend goes *first*: if two tabs
/// submit the same consent, one of them must produce no authorization response
/// at all, and the only way to guarantee that is to decide the winner before
/// either has minted anything. Minting first and spending after would leave a
/// window in which two codes exist for one authorization.
///
/// # Why a failure after that point is a redirect and not a page
///
/// The opposite of `/authorize`, and for the opposite reason. There the
/// redirect URI could not be trusted — the request might belong to another
/// client, or not exist. Here it came from a request this server validated
/// against the client's registration at push time, so it *is* the client's,
/// and RFC 6749 §4.1.2.1 says errors go there. A user who has decided should
/// end up back at the application either way; an error page would strand them
/// with a client still waiting.
async fn complete(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    decision: &Decision,
    record: &InteractionRecord,
    now: OffsetDateTime,
) -> Response {
    let string = |name: &str| {
        record
            .parameters
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
    };

    // Before the spend, because without it there is nowhere to send anything
    // and the interaction should stay recoverable.
    let Some(redirect_uri) = string("redirect_uri") else {
        tracing::error!(
            tenant = %context.tenant.id,
            "a stored request has no redirect_uri"
        );
        return error_page(
            context,
            StatusCode::INTERNAL_SERVER_ERROR,
            InteractionError::NotAvailable,
        );
    };
    let state = string("state");
    let issuer = context.tenant.issuer.as_str().to_owned();

    if let Err(error) = context
        .requests
        .complete_interaction(&presented.digest(), now)
        .await
    {
        // Some other submission got here first, or the window closed. Either
        // way this one must not send a second authorization response.
        tracing::warn!(%error, tenant = %context.tenant.id, "nothing live to complete");
        return error_page(
            context,
            StatusCode::BAD_REQUEST,
            InteractionError::NotAvailable,
        );
    }

    let response = match decision {
        // RFC 6749 §4.1.2.1. A refusal travels the same road as an approval.
        Decision::Denied => AuthorizationResponse::Error {
            error: "access_denied",
            state,
            issuer,
        },
        Decision::Approved { scopes } => match mint(context, scopes, record, now).await {
            Ok(code) => AuthorizationResponse::Code {
                code,
                state,
                issuer,
            },
            Err(error) => AuthorizationResponse::Error {
                error,
                state,
                issuer,
            },
        },
    };

    redirect(context, &response, &redirect_uri)
}

/// The approval path: a grant, a code, and the binding that ties them.
///
/// Returns the code to hand back, or the RFC 6749 §4.1.2.1 error code to
/// redirect with instead. Nothing here renders anything — the caller owns the
/// response, so there is one place where `iss` is attached and one place where
/// the 303 is built.
async fn mint(
    context: &InteractionContext<'_>,
    scopes: &std::collections::BTreeSet<String>,
    record: &InteractionRecord,
    now: OffsetDateTime,
) -> Result<String, &'static str> {
    let string = |name: &str| {
        record
            .parameters
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
    };

    let Ok(Some(client)) = context.clients.find(&record.client).await else {
        tracing::error!(tenant = %context.tenant.id, "the client went away mid-authorization");
        return Err("server_error");
    };

    // Who this is about. The session digest was written when the user signed
    // in; a session that is gone or no longer usable means the authorization
    // has nobody behind it, and issuing a code anyway would bind a grant to a
    // user who is not there.
    let Some(digest) = record.session.as_deref() else {
        tracing::error!(tenant = %context.tenant.id, "consent was recorded with no session");
        return Err("server_error");
    };
    let session = match context.sessions.find(digest).await {
        Ok(Some(session)) if session.status(now).is_usable() => session,
        Ok(_) => {
            tracing::info!(tenant = %context.tenant.id, "the session ended before consent completed");
            return Err("access_denied");
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read the session");
            return Err("server_error");
        }
    };

    // OIDC Core §8.1. A pairwise client sees its own sector's `sub`; a public
    // one sees the sector every public subject shares.
    let Ok(sector) = SectorIdentifier::of_client(&client) else {
        tracing::error!(tenant = %context.tenant.id, "this client has no sector to identify in");
        return Err("server_error");
    };
    let user = UserId::new(session.user);
    let subject = match context.subjects.subject(user, &sector).await {
        Ok(subject) => subject,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot resolve a subject");
            return Err("server_error");
        }
    };

    let mut grant = Grant::new(context.tenant.id.clone(), record.client.clone(), now);
    grant.user = Some(user);
    grant.subject = Some(subject);
    grant.scopes = scopes.iter().cloned().collect();
    grant.resources = record
        .parameters
        .get("resources")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    grant.session = Some(DomainSessionId::new(digest.to_owned()));
    // `claimed_at` stays `None`: Grant Management ID1 §5.6 makes a grant
    // `active` when a credential has been *claimed*, and nothing has been. The
    // token endpoint stamps it when the code is redeemed.

    let grant_id = grant.id.clone();
    if let Err(error) = context.grants.create(&grant).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot record a grant");
        return Err("server_error");
    }

    let Some(code_challenge) = string("code_challenge") else {
        // FAPI 2.0 SP §5.3.2.2 item 5 makes PKCE mandatory and
        // `authorize::validate` enforces it at push time, so a stored request
        // without one did not come from this server. Refusing is the only safe
        // reading: a code with no challenge is redeemable by whoever holds it.
        tracing::error!(tenant = %context.tenant.id, "a stored request has no code_challenge");
        return Err("server_error");
    };
    let minted = MintedCode::generate();
    let binding = CodeBinding {
        client_id: record.client.as_str().to_owned(),
        grant_id,
        code_challenge,
        // Byte-for-byte the URI the code is being sent to, so redemption can
        // compare rather than re-derive (OIDC Core §3.1.3.2).
        redirect_uri: string("redirect_uri").unwrap_or_default(),
        nonce: string("nonce"),
        // RFC 9449 §10: when the request pinned a key, the code is pinned too.
        dpop_jkt: string("dpop_jkt"),
        expires_at: now + code::clamp_lifetime(context.code_lifetime),
    };
    if let Err(error) = context.codes.issue(minted.digest(), &binding, now).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot store a code");
        return Err("server_error");
    }

    Ok(minted.expose().to_owned())
}

/// Sends the browser back to the client.
///
/// The cookie goes with it. The interaction is spent by the time this is
/// reached, so a cookie left in the browser is one an attacker can keep
/// presenting against a row that will never answer again.
fn redirect(
    context: &InteractionContext<'_>,
    response: &AuthorizationResponse,
    redirect_uri: &str,
) -> Response {
    let Ok(location) = response.redirect_url(redirect_uri) else {
        tracing::error!(tenant = %context.tenant.id, "a registered redirect URI will not parse");
        return error_page(
            context,
            StatusCode::INTERNAL_SERVER_ERROR,
            InteractionError::NotAvailable,
        );
    };
    // Through `SeeOther`, never open-coded: 303 is the status FAPI 2.0 SP
    // §5.3.2.2 items 10–11 leave available, and the helper is also where
    // response splitting through `Location` is refused.
    let Ok(see_other) = SeeOther::to(&location) else {
        tracing::error!(tenant = %context.tenant.id, "a redirect location is not a header value");
        return error_page(
            context,
            StatusCode::INTERNAL_SERVER_ERROR,
            InteractionError::NotAvailable,
        );
    };

    let mut response = see_other.into_response();
    // The URL in this header carries an authorization code.
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    clear(&mut response);
    response
}

/// Re-renders the current stage with a message and a fresh token.
async fn retry(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    mut state: StoredState,
    id: &str,
    now: OffsetDateTime,
    message: &str,
) -> Response {
    let token = state.issue_csrf();
    if let Err(error) = save(context, presented, &state, None, now).await {
        return *error;
    }
    render(context, state.stage, &token, id, Some(message), None)
}

/// The two-credential check and the record lookup.
///
/// Returns the response to send when either fails, so a caller cannot forget
/// to stop.
async fn resume(
    context: &InteractionContext<'_>,
    id: &str,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Result<(InteractionId, StoredState, InteractionRecord), Box<Response>> {
    let presented = InteractionId::from_presented(id.to_owned());
    let from_cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(interaction::id_from_cookie_header);

    if let Err(failure) = asterius_web::Interaction::resume(&presented, from_cookie.as_ref()) {
        if failure.is_fatal() {
            // FAPI 2.0 SP §6.5. Somebody is being deceived and this server
            // cannot tell which party, so the flow ends for both. The cookie
            // goes too: one left behind is one an attacker can keep trying.
            let digest = presented.digest();
            if let Err(error) = context.requests.destroy_interaction(&digest).await {
                tracing::error!(%error, "cannot destroy a mismatched interaction");
            }
            tracing::warn!(
                tenant = %context.tenant.id,
                "interaction destroyed: the path and the cookie disagree"
            );
            let mut response = error_page(context, StatusCode::BAD_REQUEST, failure);
            clear(&mut response);
            return Err(Box::new(response));
        }
        return Err(Box::new(error_page(
            context,
            StatusCode::BAD_REQUEST,
            failure,
        )));
    }

    match context
        .requests
        .by_interaction(&presented.digest(), now)
        .await
    {
        Ok(Some(record)) => Ok((presented, StoredState::from_stored(&record.state), record)),
        // Absent, expired and consumed are one answer.
        Ok(None) => Err(Box::new(error_page(
            context,
            StatusCode::NOT_FOUND,
            InteractionError::NotAvailable,
        ))),
        Err(error) => {
            tracing::error!(%error, "cannot read an interaction");
            Err(Box::new(error_page(
                context,
                StatusCode::SERVICE_UNAVAILABLE,
                InteractionError::NotAvailable,
            )))
        }
    }
}

/// Writes progress, or produces the response that says it could not.
async fn save(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    state: &StoredState,
    session: Option<&str>,
    now: OffsetDateTime,
) -> Result<(), Box<Response>> {
    let value = serde_json::to_value(state).unwrap_or_default();
    match context
        .requests
        .save_interaction_state(&presented.digest(), &value, session, now)
        .await
    {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::error!(%error, "cannot record interaction progress");
            // A page rendered with a token that was never stored would refuse
            // its own submission, which looks like a CSRF failure to a user
            // who did nothing wrong.
            Err(Box::new(error_page(
                context,
                StatusCode::SERVICE_UNAVAILABLE,
                InteractionError::NotAvailable,
            )))
        }
    }
}

/// Renders the page for a stage.
fn render(
    context: &InteractionContext<'_>,
    stage: Stage,
    csrf: &CsrfToken,
    id: &str,
    message: Option<&str>,
    offer: Option<&ConsentRequest>,
) -> Response {
    let action = format!("/interaction/{id}");
    match stage {
        Stage::Login | Stage::StepUp => Document::render(context.nonce, |nonce| {
            pages::render(&LoginPage {
                locale: "en",
                tenant_name: &context.tenant.display_name,
                action: &action,
                csrf: csrf.expose(),
                login_hint: None,
                message,
                nonce_attribute: nonce_attribute(nonce),
            })
        })
        .into_response(),
        Stage::Consent => {
            let Some(offer) = offer else {
                // The stage says consent but nothing loaded the request. That
                // is a wiring fault, not the user's, and rendering an empty
                // consent screen would ask them to agree to nothing.
                tracing::error!(
                    tenant = %context.tenant.id,
                    "the consent stage was reached with no request loaded"
                );
                return error_page(
                    context,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    InteractionError::NotAvailable,
                );
            };
            Document::render(context.nonce, |nonce| {
                pages::render(&ConsentPage {
                    locale: "en",
                    tenant_name: &context.tenant.display_name,
                    client_name: &offer.client_name,
                    username: context.username.unwrap_or_default(),
                    redirect_host: &offer.redirect_host,
                    scopes: offer
                        .scopes
                        .iter()
                        .map(|scope| ScopeLine {
                            name: scope.name.clone(),
                            description: scope.description.clone(),
                            required: scope.required,
                        })
                        .collect(),
                    offline_access: offer.offline_access,
                    resources: offer.resources.iter().cloned().collect(),
                    action: &action,
                    csrf: csrf.expose(),
                    nonce_attribute: nonce_attribute(nonce),
                })
            })
            .into_response()
        }
        // Unreachable in practice: reaching `Response` spends the request in
        // the same call that sends the redirect, so a later `GET` finds
        // nothing and never gets this far. Rendering rather than redirecting
        // is still the right answer if it ever does — replaying a stored
        // authorization response on a reload is what one-time use forbids.
        Stage::Response => error_page(
            context,
            StatusCode::NOT_IMPLEMENTED,
            InteractionError::NotAvailable,
        ),
    }
}

/// The error page: one generic message, one correlation id.
///
/// The id is logged beside the real reason, so an operator can find what
/// happened and the page carries none of it.
fn error_page(
    context: &InteractionContext<'_>,
    status: StatusCode,
    reason: InteractionError,
) -> Response {
    let correlation = interaction::correlation_id();
    tracing::info!(
        correlation_id = %correlation,
        tenant = %context.tenant.id,
        reason = %reason,
        "interaction error page shown"
    );

    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            locale: "en",
            tenant_name: &context.tenant.display_name,
            message: "Something went wrong, and this request cannot continue.",
            correlation_id: &correlation,
            nonce_attribute: nonce_attribute(nonce),
        })
    });
    (status, document).into_response()
}

/// Adds the header that removes the interaction cookie.
fn clear(response: &mut Response) {
    if let Ok(value) = interaction::clear_cookie().parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Attaches the session cookie after a successful sign-in.
///
/// Every attribute matches the interaction cookie's and for the same reasons:
/// the `__Host-` prefix is browser-enforced (HTTPS, no `Domain`, `Path=/`),
/// `HttpOnly` keeps it away from script, and `SameSite=Lax` stops a cross-site
/// POST carrying it while still allowing the top-level navigation a user
/// arrives by.
///
/// No `Max-Age`: it is a session cookie, and the session row's own two clocks
/// are the authority on lifetime. A cookie that outlived the row would only
/// produce a confusing sign-in loop.
fn set_session_cookie(response: &mut Response, id: &SessionId) {
    let cookie = format!(
        "{}={}; Secure; HttpOnly; SameSite=Lax; Path=/",
        asterius_domain::entities::session::COOKIE_NAME,
        id.expose()
    );
    if let Ok(value) = cookie.parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::audit::{DetailValue, fingerprint};

    fn registered() -> (TenantId, UserId, uuid::Uuid, AuditEvent) {
        let tenant = TenantId::new("demo");
        let user = UserId::generate();
        let credential = uuid::Uuid::new_v4();
        let event = passkey_registered_event(
            &tenant,
            &user,
            &credential,
            OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("a valid timestamp"),
        );
        (tenant, user, credential, event)
    }

    #[test]
    fn a_registered_passkey_is_recorded_against_its_tenant_and_user() {
        let (tenant, user, _, event) = registered();

        assert_eq!(event.tenant, tenant);
        assert_eq!(event.subject, Some(user.as_uuid().to_string()));
        assert_eq!(event.actor, Actor::User(user.as_uuid().to_string()));
    }

    #[test]
    fn a_registered_passkey_is_recorded_as_a_created_credential() {
        let (_, _, _, event) = registered();

        assert_eq!(event.event_type, EventType::CREDENTIAL_CREATED);
        assert_eq!(event.outcome, Outcome::Success);
    }

    #[test]
    fn a_registered_passkey_names_the_credential_row_by_digest() {
        let (_, _, credential, event) = registered();

        let recorded = event
            .detail
            .iter()
            .find(|(key, _)| key.as_str() == "credential_id")
            .map(|(_, value)| value.clone());

        assert_eq!(
            recorded,
            Some(DetailValue::Fingerprint(fingerprint(
                &credential.to_string()
            )))
        );
    }

    /// A digest is only useful if the same credential always produces it.
    #[test]
    fn the_same_credential_is_named_the_same_way_twice() {
        let tenant = TenantId::new("demo");
        let user = UserId::generate();
        let credential = uuid::Uuid::new_v4();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("a valid timestamp");

        let first = passkey_registered_event(&tenant, &user, &credential, now);
        let second = passkey_registered_event(&tenant, &user, &credential, now);

        assert_eq!(first.detail, second.detail);
    }
}
