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
//! (passkeys) own that, and until one of them lands [`UserAuthentication`] has
//! no implementation. The seam is typed rather than stubbed: a deployment with
//! no authenticator renders the login page and refuses the submission with a
//! fixed message, which is what a server that cannot sign anybody in should
//! do. It does not pretend to authenticate.

use asterius_domain::{DomainError, InteractionRepository, Secret, Tenant};
use asterius_web::interaction::{
    self, CsrfToken, InteractionError, InteractionId, Stage, StoredState,
};
use asterius_web::pages::{self, ErrorPage, LoginPage, nonce_attribute};
use asterius_web::{Document, csp::Nonce};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

/// How a user proves who they are.
///
/// One method per implementation; a deployment may register none, in which
/// case nobody can sign in and the login form says so. That is deliberately
/// not the same as "sign-in succeeds by default".
#[async_trait::async_trait]
pub trait UserAuthentication: Send + Sync {
    /// Verifies a username and password, returning a session id on success.
    ///
    /// The password arrives in a [`Secret`], so it is redacted in `Debug` and
    /// zeroised on drop — it passes through several frames on its way here and
    /// each one is a chance to log it.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the credential store could not be reached.
    /// A *wrong* credential is `Ok(None)`, not an error: it is an ordinary
    /// outcome, and conflating it with an outage would turn every database
    /// blip into "your password is wrong".
    async fn verify(
        &self,
        tenant: &Tenant,
        username: &str,
        password: Secret<String>,
    ) -> Result<Option<String>, DomainError>;
}

/// What the handlers need.
pub struct InteractionContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This tenant's interactions.
    pub requests: &'a dyn InteractionRepository,
    /// How to sign a user in, when this deployment can.
    pub authentication: Option<&'a dyn UserAuthentication>,
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
    let (presented, mut state) = match resume(&context, id, headers, now).await {
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

    render(&context, state.stage, &token, id, None)
}

/// `POST /interaction/{id}` — take a decision and advance.
pub async fn submit(
    context: InteractionContext<'_>,
    id: &str,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let (presented, mut state) = match resume(&context, id, headers, now).await {
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
        Stage::Login => {
            let Some(authentication) = context.authentication else {
                // No method is registered, so nobody can sign in. Saying so is
                // better than a generic failure: the deployment is
                // misconfigured and an operator needs to know which way.
                let token = state.issue_csrf();
                if let Err(error) = save(&context, &presented, &state, None, now).await {
                    return *error;
                }
                return render(
                    &context,
                    Stage::Login,
                    &token,
                    id,
                    Some("Signing in is not available on this server."),
                );
            };

            let (Some(username), Some(password)) = (field("username"), field("password")) else {
                return retry(
                    &context,
                    &presented,
                    state,
                    id,
                    now,
                    "Enter a username and password.",
                )
                .await;
            };

            match authentication
                .verify(context.tenant, username, Secret::new(password.to_owned()))
                .await
            {
                Ok(Some(session)) => {
                    // `ast-2vk.7` decides whether a step-up is needed; until
                    // then an authenticated user goes straight to consent.
                    if state.stage.may_advance_to(Stage::Consent) {
                        state.stage = Stage::Consent;
                    }
                    let token = state.issue_csrf();
                    if let Err(error) =
                        save(&context, &presented, &state, Some(&session), now).await
                    {
                        return *error;
                    }
                    render(&context, state.stage, &token, id, None)
                }
                // One message for "no such user" and "wrong password". The
                // difference is an account-enumeration oracle and nothing else.
                Ok(None) => {
                    retry(
                        &context,
                        &presented,
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
                        &context,
                        StatusCode::SERVICE_UNAVAILABLE,
                        InteractionError::NotAvailable,
                    )
                }
            }
        }
        // `ast-uwv.1` owns the consent decision and `ast-gxh.4` the response.
        // Refusing here is honest: the stage exists, the page renders, and the
        // decision has nowhere to go yet.
        Stage::StepUp | Stage::Consent | Stage::Response => error_page(
            &context,
            StatusCode::NOT_IMPLEMENTED,
            InteractionError::NotAvailable,
        ),
    }
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
    render(context, state.stage, &token, id, Some(message))
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
) -> Result<(InteractionId, StoredState), Box<Response>> {
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
        Ok(Some(record)) => Ok((presented, StoredState::from_stored(&record.state))),
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
        // `ast-uwv.1` renders the consent screen from the grant it is asking
        // about; until that exists there is nothing to show.
        Stage::Consent | Stage::Response => error_page(
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
