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

use asterius_domain::entities::session::SessionId;
use asterius_domain::{
    AuthenticationMethod, CredentialVerifier, InteractionRecord, InteractionRepository, Lifetimes,
    Secret, Session, SessionRepository, Tenant,
};
use asterius_oidc::consent::{ConsentRequest, Decision};
use asterius_web::interaction::{
    self, CsrfToken, InteractionError, InteractionId, Stage, StoredDecision, StoredState,
};
use asterius_web::pages::{self, ConsentPage, ErrorPage, LoginPage, ScopeLine, nonce_attribute};
use asterius_web::{Document, csp::Nonce};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

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
    /// The CSP nonce the document middleware drew for this response.
    pub nonce: &'a Nonce,
}

impl std::fmt::Debug for InteractionContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractionContext").finish_non_exhaustive()
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
        // `ast-2vk.7` owns step-up; `ast-gxh.4` turns a decision into a code.
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

    // `ast-gxh.4` picks it up from here.
    error_page(
        context,
        StatusCode::NOT_IMPLEMENTED,
        InteractionError::NotAvailable,
    )
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
        // `ast-gxh.4` turns a decision into a code and a redirect. Reaching
        // this stage means one was made and has nowhere to go yet.
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
