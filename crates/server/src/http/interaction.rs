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

use crate::http::form_action_origin;
use crate::http::throttle;
use crate::tenancy::MountPrefix;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::session::SessionId;
use asterius_domain::locale::{Locale, UiLocales};
use asterius_domain::{
    AuthenticationMethod, AuthorizationDetailsTypeRepository, ClientRequest, CodeBinding,
    CodeIssuer, CredentialVerifier, FirstPartyDestination, Grant, GrantRepository,
    InteractionRecord, InteractionRepository, Lifetimes, Secret, SectorIdentifier,
    SessionId as DomainSessionId, SessionRepository, SubjectResolver, Tenant, TenantId, UserId,
};
use asterius_oidc::authorize::ResponseMode;
use asterius_oidc::code::{AuthorizationResponse, MintedCode};
use asterius_oidc::consent::{ConsentRequest, Decision, DetailRequest};
use asterius_oidc::consent_memory::{Asked, MemoryPolicy, Remembered};
use asterius_oidc::decision::Requirements;
use asterius_web::Brand;
use asterius_web::i18n::Catalog;
use asterius_web::interaction::{
    self, CsrfToken, InteractionError, InteractionId, Stage, StoredDecision, StoredState,
};
use asterius_web::pages::{self, ConsentPage, ErrorPage, LoginPage, ScopeLine, nonce_attribute};
use asterius_web::{Document, FormActionOrigin, csp::Nonce};
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::{Duration, OffsetDateTime};

/// The query the sign-up page's "already have an account?" link carries.
///
/// A query rather than a second route, because it is the *same* interaction:
/// the person is still completing one authorization and the browser still holds
/// one cookie for it. All it does is move the stage from
/// [`Stage::Register`] to [`Stage::Login`], which
/// [`Stage::may_advance_to`] permits for the reason it permits the step-up's
/// backward move — it discards progress rather than granting any. Nothing else
/// reads it, and at any other stage it does nothing at all.
pub const SIGN_IN_QUERY: &str = "signin";

/// What the handlers need.
pub struct InteractionContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The three layers a page's language is chosen from (OIDC Core §3.1.2.1).
    ///
    /// Not a `Catalog`, because the top layer of the negotiation is on the
    /// stored request and the caller has not read it: `ui_locales` travelled
    /// with the push, and this handler is the first thing that has both it and
    /// the browser in front of it.
    pub language: &'a crate::http::i18n::PageLanguage,
    /// This tenant's interactions.
    pub requests: &'a dyn InteractionRepository,
    /// How to check a credential, when this deployment has a method.
    pub credentials: Option<&'a dyn CredentialVerifier>,
    /// Where a successful sign-in becomes a session.
    pub sessions: &'a dyn SessionRepository,
    /// How long this tenant's sessions live.
    pub lifetimes: Lifetimes,
    /// The authentication contexts this tenant can produce (`ast-2vk.7`).
    ///
    /// Consulted when an authentication succeeds, to decide which `acr` the
    /// session it produces carries — and, for an essential request, to make
    /// that value one of the ones the client asked for (OIDC Core §5.5.1.1).
    pub acr: &'a asterius_domain::AcrPolicy,
    /// This tenant's clients, for the name and metadata the consent screen
    /// shows.
    ///
    /// Read only when the consent stage is actually rendered. Loading a
    /// registration to draw a form nobody has authenticated for would be work
    /// an unauthenticated visitor can make this server do.
    pub clients: &'a dyn asterius_domain::ClientRepository,
    /// Where a completed authorization is recorded, and where the consent
    /// memory is read from (`ast-uwv.3`): a grant is both.
    pub grants: &'a dyn GrantRepository,
    /// How a grant a client already holds is amended (Grant Management ID1
    /// §5.2).
    ///
    /// `Some` exactly when [`asterius_domain::Feature::GrantManagement`] is on
    /// for this tenant, and `None` otherwise. A stored request cannot name a
    /// `grant_id` unless the pushed-request endpoint validated one, and that
    /// endpoint only does so behind the same flag — so `None` here and a stored
    /// `grant_management_action` together are a request that outlived the flag
    /// being switched off, which is refused rather than honoured.
    pub grant_amendments: Option<&'a dyn asterius_domain::GrantAmendments>,
    /// This tenant's registered authorization details types (RFC 9396 §2.1),
    /// for the sentence the consent screen shows for each element.
    ///
    /// `None` is a deployment with no registry wired, and then a rich
    /// authorization is shown by type name alone. It is never a reason to fall
    /// back to rendering the element's JSON: a consent page must not put
    /// attacker-composed text in front of the person it is asking (RFC 9396
    /// §12).
    pub authorization_details_types: Option<&'a dyn AuthorizationDetailsTypeRepository>,
    /// Whether this tenant remembers a consent it already has, and for how long
    /// it remembers an `offline_access` one.
    pub memory: MemoryPolicy,
    /// Where the code that carries it is stored.
    ///
    /// The issuing half only. This handler has no way to *redeem* a code, and
    /// that is deliberate — see [`asterius_domain::CodeIssuer`].
    pub codes: &'a dyn CodeIssuer,
    /// How the `sub` this client will see is resolved (OIDC Core §8.1).
    pub subjects: &'a dyn SubjectResolver,
    /// How long an issued code lives.
    ///
    /// This tenant's setting when it has one, the deployment's otherwise —
    /// resolved by [`crate::http::protocol`] out of an
    /// `asterius_domain::TokenLifetimes`, which is why it is under FAPI 2.0 SP
    /// §5.3.2.1 item 11's sixty seconds without being checked again here
    /// (`ast-5c6`).
    pub code_lifetime: Duration,
    /// The CSP nonce the document middleware drew for this response.
    pub nonce: &'a Nonce,
    /// How failed sign-ins are counted, and where this request came from.
    ///
    /// Consulted before the credential is checked and written to after one is
    /// refused, so the cost of a wrong guess is paid by whoever made it. It is
    /// part of the context rather than a parameter of `sign_in` because a
    /// login handler that can be written without it is one that will be.
    pub throttle: crate::http::throttle::LoginThrottle<'a>,
    /// Where the security-relevant things that happen here are recorded.
    ///
    /// The interaction endpoints are where a person authenticates and where a
    /// credential of theirs comes into existence, and neither is something the
    /// trail can be missing. [`record_passkey_registered`] is the first user.
    pub audit: &'a dyn AuditSink,
    /// The prefix routing removed from this request's path (`ast-295`).
    ///
    /// Every URL this handler hands to the browser — the form action, the
    /// paths the sign-in script fetches — has to carry it back, because
    /// `/interaction/{id}` is mounted under the tenant and nowhere else.
    pub mount: MountPrefix,
    /// Where a self-service sign-up is written, for a tenant that offers one.
    ///
    /// `Some` exactly when
    /// [`asterius_domain::Feature::SelfRegistration`] is on for this tenant,
    /// and `None` otherwise — which is the same flag the pushed-request
    /// endpoint read to accept `prompt=create` and the same one the discovery
    /// document advertised it under. A stored request cannot ask for
    /// [`Stage::Register`] unless that flag was on, so `None` here and a
    /// stored `Register` stage together are a request that outlived the flag
    /// being switched off: it is refused rather than honoured, by the handler
    /// that would otherwise write the row.
    pub registrar: Option<crate::http::signup::Registrar<'a>>,
    /// The account behind a user id, for the name a screen puts on a person.
    ///
    /// Read once, after a credential has been accepted, so that
    /// `StoredState::signed_in_as` carries the display name rather than the
    /// login identifier (`ast-pew`, `ast-bo5`).
    pub directory: &'a dyn asterius_domain::UserDirectory,
    /// The email-verification gate, for a tenant that requires a proved
    /// address (`ast-vae`).
    ///
    /// `Some` exactly when `TenantSettings::require_verified_email` is on, and
    /// `None` otherwise. Shaped like [`Self::registrar`] and for the same
    /// reason: the setting is read where the context is built, so there is no
    /// state in which a handler holds the token store and forgets to consult
    /// the flag — and no state in which the flag is on and the store is
    /// missing.
    pub verification: Option<crate::http::verify_email::Gate<'a>>,
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
    record_registered_passkey(context.audit, &context.tenant.id, user, credential, now).await;
}

/// The same record, for a caller holding a sink and a tenant rather than the
/// whole context.
///
/// `crate::http::passkeys` is that caller: enrolment happens outside any
/// authorization, so it has no interaction, no client and no consent offer —
/// eight of the ten things [`InteractionContext`] carries. Both entry points
/// exist so that neither has to assemble state it does not use, and both go
/// through [`passkey_registered_event`], so there is one shape of this record.
pub async fn record_registered_passkey(
    audit: &dyn AuditSink,
    tenant: &TenantId,
    user: &UserId,
    credential: &uuid::Uuid,
    now: OffsetDateTime,
) {
    let event = passkey_registered_event(tenant, user, credential, now);
    if let Err(failure) = audit.record(event).await {
        tracing::error!(
            %failure,
            tenant = %tenant,
            "a registered passkey was not written to the audit trail"
        );
    }
}

/// `GET /interaction/{id}` — render the current stage.
pub async fn show(
    context: InteractionContext<'_>,
    id: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let (presented, mut state, record) = match resume(&context, id, headers, now).await {
        Ok(resumed) => resumed,
        Err(response) => return *response,
    };

    // The sign-up page's way out (`SIGN_IN_QUERY`). Asked for by a person
    // pressing a link, and it only ever asks for *more* authentication: the
    // move is refused by the stage machine from anywhere but `Register`, so a
    // link followed at consent time cannot undo a decision.
    if state.stage == Stage::Register
        && query.is_some_and(asks_for_sign_in)
        && state
            .stage
            .may_advance_to(Stage::Login, &record.continuation)
    {
        state.stage = Stage::Login;
    }

    // A first-party interaction whose sign-in is finished has nowhere left to
    // go but its destination, and the passkey path is how it gets here: that
    // ceremony answers 204 and the page's script then navigates *to this URL*
    // (`login.html`'s `data-next-url`), because the same script serves an
    // authorization, where the next screen is consent. The password path
    // redirects from inside `sign_in`; this is the same redirect for the
    // browser that arrived by the other door, and without it a passkey sign-in
    // to a first-party page ends on the error page below (`ast-lh3.3` found
    // it on the device flow; the admin console reaches it the same way).
    //
    // `arrive` spends the interaction, so a reload finds nothing and the
    // response is not replayable.
    if state.stage == Stage::Response
        && let Some(destination) = record.continuation.first_party()
    {
        return arrive(&context, &presented, destination, now).await;
    }

    // Before a token is issued and a page is drawn: a consent this person has
    // already given is a screen they do not have to see again (`ast-uwv.3`).
    if let Some(response) =
        skip_consent_if_remembered(&context, &presented, state.clone(), &record, now).await
    {
        return response;
    }

    // The language, decided here and only here: this is the first screen of the
    // journey and the only place that has the pushed request, this browser and
    // the tenant's settings at once. Written into the state so that the pages
    // that follow — including the ones drawn by a POST, which is a different
    // request with its own headers — are in the same language as this one.
    let locale = state
        .locale
        .as_deref()
        .and_then(Locale::matching)
        .unwrap_or_else(|| opening_locale(&context, &record));
    state.locale = Some(locale.as_tag().to_owned());

    // A fresh token per rendering. Reloading the page twice before deciding is
    // something a user does, and each rendering carries its own token — the
    // previous one stops working, which is the same rule as one submission per
    // token seen from the other side.
    let token = state.issue_csrf();
    if let Err(error) = save(&context, &presented, &state, None, now).await {
        return *error;
    }

    let offer = describe(&context, &record).await;
    render(
        &context,
        &Screen {
            locale,
            stage: state.stage,
            csrf: &token,
            id,
            message: None,
            offer: offer.as_ref(),
            signed_in: state.username.as_deref(),
            typed: None,
        },
    )
}

/// The consent screen's contents, and the one origin its form may reach.
///
/// The two travel together because they come from the same place — the stored
/// request of *this* authorization — and separating them is how a page ends up
/// naming one client while widening `form-action` for another.
struct ConsentOffer {
    /// What the user is asked to agree to.
    request: ConsentRequest,
    /// The origin of the validated `redirect_uri`, when it is one a
    /// `form-action` source expression can name (`ast-jsq`).
    form_action: Option<FormActionOrigin>,
}

/// Builds the consent offer for a request, when one is needed.
///
/// Returns `None` for any stage that does not show it, for a client that has
/// gone away between the push and now — which renders the error page rather
/// than a consent screen naming nobody — and for an interaction that has no
/// client at all (ADR-0009), which has nothing to offer and never reaches
/// [`Stage::Consent`] to be asked.
async fn describe(
    context: &InteractionContext<'_>,
    record: &InteractionRecord,
) -> Option<ConsentOffer> {
    let request = record.client_request()?;
    let client = context.clients.find(&request.client).await.ok()??;

    // The redirect URI was validated at push time against this client's
    // registered set, so its host is one the client actually owns — which is
    // what makes showing it worth anything (FAPI 2.0 SP §7).
    let redirect_uri = request
        .parameters
        .get("redirect_uri")
        .and_then(serde_json::Value::as_str)
        .and_then(|uri| url::Url::parse(uri).ok());
    let redirect_host = redirect_uri
        .as_ref()
        .and_then(|uri| uri.host_str().map(ToOwned::to_owned))
        .unwrap_or_default();
    let form_action = redirect_uri.as_ref().and_then(form_action_origin);

    let scopes: std::collections::BTreeSet<String> = request
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

    let resources = request
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

    // RFC 9396 §2: read back through the same parser the push used, then
    // described from the tenant's registry. The element's own JSON never
    // reaches the page — see `DetailRequest`.
    let details = request
        .parameters
        .get("authorization_details")
        .and_then(|value| asterius_domain::AuthorizationDetails::from_value(value).ok())
        .unwrap_or_default();
    let registry = if details.is_empty() {
        // Not read when there is nothing to describe, so a tenant whose clients
        // do not use rich authorization pays nothing for the feature.
        asterius_domain::AuthorizationDetailsRegistry::default()
    } else {
        match context.authorization_details_types {
            None => asterius_domain::AuthorizationDetailsRegistry::default(),
            Some(types) => match types.list().await {
                Ok(types) => asterius_domain::AuthorizationDetailsRegistry::new(types),
                // A registry that cannot be read shows the type names alone,
                // which is the same answer an undescribed type gets. Refusing
                // the page instead would mean an outage in a description table
                // stopped people from consenting at all.
                Err(error) => {
                    tracing::error!(%error, tenant = %context.tenant.id, "cannot read the authorization details type registry");
                    asterius_domain::AuthorizationDetailsRegistry::default()
                }
            },
        }
    };
    let authorization_details = DetailRequest::offer(&details, |name| {
        registry
            .get(name)
            .and_then(|kind| kind.consent_template.clone())
    });

    Some(ConsentOffer {
        request: ConsentRequest::new(
            client.registration.client_name.clone(),
            redirect_host,
            &scopes,
            resources,
            authorization_details,
            // Per-tenant scope wording is `ast-ndk.2`. Until then a scope is
            // shown by name, which is honest: an unexplained scope should look
            // unexplained.
            |_| None,
        ),
        form_action,
    })
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
        // `Login` and `StepUp` take the same submission and the same form: the
        // difference between them is not what is asked of the person, it is
        // what the answer is worth — a step-up rotates onto the session that is
        // already there and accumulates its `amr` (`http::step_up`), where a
        // login starts one. Refusing a password at `StepUp` would instead
        // strand every request whose essential `acr` a password *does* satisfy.
        Stage::Login | Stage::StepUp => {
            sign_in(&context, &presented, state, id, &form, &record, now).await
        }
        Stage::Register => {
            create_account(&context, &presented, state, id, &form, &record, now).await
        }
        Stage::Consent => decide(&context, &presented, state, &form, &record, now).await,
        // A submission at `Response` has nothing left to submit: the request
        // was spent when the response was sent.
        Stage::Response => error_page(
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
    state: StoredState,
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
        return no_method(context, presented, state, id, now).await;
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

    let attempt = context.throttle.attempt(Some(username));
    let mut state = match gate(context, presented, state, id, &attempt, now).await {
        Ok(state) => state,
        Err(response) => return *response,
    };

    match credentials
        .verify(username, Secret::new(password.to_owned()))
        .await
    {
        Ok(Some(user)) => {
            // The name that was just proved, kept for the screens that follow
            // (`ast-bo5`). The passkey path fills the same field through the
            // same function, so neither can drift from the other.
            //
            // What goes in it is the *display* name — OIDC Core §5.1's
            // `preferred_username` when the account has one, the login
            // identifier when it does not (`ast-pew`). Resolved from the
            // account rather than from what was typed: the two differ in case
            // and in whitespace even when they name the same person, and a
            // consent screen that echoed the typed form would be showing
            // attacker-chosen text on a successful sign-in. A read that fails
            // falls back to the identifier rather than failing the sign-in —
            // this is a caption, not a decision.
            let named = match context
                .directory
                .by_id(asterius_domain::UserId::new(user))
                .await
            {
                Ok(Some(account)) => crate::http::signup::display_name(&account).to_owned(),
                Ok(None) => username.to_owned(),
                Err(error) => {
                    tracing::warn!(%error, tenant = %context.tenant.id, "cannot read the account just signed in");
                    username.to_owned()
                }
            };
            state.signed_in_as(&named);
            // The credential verified, so the failures counted against this
            // identifier are stale: the person proved they are who the counter
            // was about (`ast-b3u`). Only reachable from here, where something
            // actually matched — a refusal below clears nothing, which is what
            // keeps the reset from being an enumeration oracle.
            context
                .throttle
                .record_success(&context.tenant.id, &attempt)
                .await;
            authenticated(context, presented, state, id, record, user, now).await
        }
        // One message for "no such user" and "wrong password". The
        // verifier already equalises the *timing*; this equalises what
        // is said. Both halves are needed — identical text with a
        // measurable delay is still an oracle.
        Ok(None) => {
            // The failure is counted against both buckets and recorded once.
            // Neither step asks whether the account exists, which is what
            // keeps a locked-out identifier indistinguishable from an invented
            // one.
            context
                .throttle
                .record_failure(&context.tenant.id, &attempt, now)
                .await;
            throttle::record_failed_password(context.audit, &context.tenant.id, now).await;
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

/// Everything that follows a credential this server accepted.
///
/// Split out of [`sign_in`] where the split cannot reorder a check: above the
/// line a credential is being decided, below it the decision is being made
/// into a session. It is also the one place a session is created on a password
/// path — the console's entry (`ast-wr4`) reaches it through the same
/// [`submit`], not through a login of its own — so the fresh id, the `amr` and
/// the cookie attributes are one implementation rather than two that agree.
async fn authenticated(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    mut state: StoredState,
    id: &str,
    record: &InteractionRecord,
    user: uuid::Uuid,
    now: OffsetDateTime,
) -> Response {
    // `ast-vae`: an address this tenant requires to be proved, and has not
    // been. Before the session is established, which is the requirement — a
    // session is precisely what an unverified account must not get, so this
    // cannot be a check the caller makes afterwards and then decides what to
    // do about. The interaction is left where it is: nothing advances, no
    // cookie is written, and no code is ever issued, which is what "does not
    // finish an OIDC login" means.
    //
    // The person is not told their credential was wrong — it was not, and
    // saying so would send them to the recovery form to reset a password that
    // works. They are shown the confirmation page, with a link already sent.
    if let Some(response) = blocked_by_verification(context, user, now).await {
        return *response;
    }

    // What the request asked for about `acr`, read off the stored parameters
    // rather than guessed: an essential value (OIDC Core §5.5.1.1) has to be
    // the value written onto the session, or the ID token would report a class
    // the client did not ask for and the requirement would fail on the token it
    // claims to satisfy. A first-party interaction has no client request and
    // asks for nothing (`ast-2vk.7`).
    let requested = record
        .client_request()
        .map(|request| Requirements::from_parameters(&request.parameters))
        .unwrap_or_default();

    // A session id the browser has never held before. See
    // `asterius_domain::entities::session`: an id it held
    // *before* authenticating is one an attacker may have
    // planted, and this is the moment that stops mattering. A
    // step-up rotates the existing session rather than starting a
    // new one — `http::step_up` owns that, and its guards.
    let established = match crate::http::step_up::establish(
        crate::http::step_up::Authentication {
            sessions: context.sessions,
            tenant: &context.tenant.id,
            acr: context.acr,
            lifetimes: context.lifetimes,
        },
        state.stage,
        record.session.as_deref(),
        user,
        vec![AuthenticationMethod::Password],
        &requested,
        now,
    )
    .await
    {
        Ok(established) => established,
        Err(error) => {
            tracing::error!(%error, "cannot start a session");
            return error_page(
                context,
                StatusCode::SERVICE_UNAVAILABLE,
                InteractionError::NotAvailable,
            );
        }
    };
    let id_value = established.id;

    // The trail entry for the sign-in itself (`ast-j7u`). Here, and once: this
    // is the single point on the password path where a session exists because
    // a credential was accepted, so the three ways out below — first-party
    // destination, remembered consent, consent screen — cannot each write one
    // and cannot between them write none. A step-up reaches it through the
    // same line, which is why the record names the session it rotated onto
    // rather than being suppressed: "this factor was proved at this moment" is
    // the fact the trail is short of, not a duplicate of the first login.
    record_signed_in(context, user, &established.digest, now).await;

    // `ast-2vk.7` decides whether a step-up is needed; until then
    // an authenticated user goes straight to whatever this interaction
    // was for — the consent screen for an authorization, the
    // destination itself for a first-party login, which has nobody to
    // consent to.
    let next = Stage::after_login(&record.continuation);
    if state.stage.may_advance_to(next, &record.continuation) {
        state.stage = next;
    }

    // ADR-0009's path. The session is written and the interaction is
    // over: there is no client, no scope and no screen left, so this
    // returns before a consent offer is even described.
    if let Some(destination) = record.continuation.first_party() {
        state.spend_csrf();
        if let Err(error) = save(context, presented, &state, Some(&established.digest), now).await {
            return *error;
        }
        let mut response = arrive(context, presented, destination, now).await;
        set_session_cookie(&mut response, &id_value);
        return response;
    }

    let token = state.issue_csrf();
    if let Err(error) = save(context, presented, &state, Some(&established.digest), now).await {
        return *error;
    }

    // The session was written a line ago, so the record this handler
    // was resumed with does not name it yet, and the consent memory is
    // keyed by who is signed in. Carrying the digest across rather than
    // re-reading the row: it is the same value the `save` above just
    // stored, and a second read could only disagree with it.
    let record = InteractionRecord {
        session: Some(established.digest.clone()),
        ..record.clone()
    };
    if let Some(response) =
        skip_consent_if_remembered(context, presented, state.clone(), &record, now).await
    {
        let mut response = response;
        set_session_cookie(&mut response, &id_value);
        return response;
    }

    // Signed in, so the next screen is consent — which needs the
    // offer.
    let offer = describe(context, &record).await;
    let mut response = render(
        context,
        &Screen {
            locale: locale_of(context, &state),
            stage: state.stage,
            csrf: &token,
            id,
            message: None,
            offer: offer.as_ref(),
            signed_in: state.username.as_deref(),
            typed: None,
        },
    );
    set_session_cookie(&mut response, &id_value);
    response
}

/// The email-verification gate, as a page to return or nothing (`ast-vae`).
///
/// Split out of [`authenticated`] rather than inlined, and boxed like every
/// other early return there, so that the one line at the call site reads as
/// what it is: a decision taken *before* a session exists, whose only two
/// outcomes are "carry on" and "this response instead".
///
/// `None` is "carry on", which covers the tenant that does not require a
/// proved address, the account that has one, and the account that has no
/// address at all — see [`crate::http::verify_email::gate`] for why the last
/// of those is not blocked.
async fn blocked_by_verification(
    context: &InteractionContext<'_>,
    user: uuid::Uuid,
    now: OffsetDateTime,
) -> Option<Box<Response>> {
    let gate = context.verification.as_ref()?;
    let account = match context
        .directory
        .by_id(asterius_domain::UserId::new(user))
        .await
    {
        Ok(account) => account,
        Err(error) => {
            // A read that fails must not open the gate. This tenant has asked
            // for an address to be proved, and "the database was briefly
            // unavailable" is not a proof.
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "cannot read an account at the email verification gate"
            );
            return Some(Box::new(error_page(
                context,
                StatusCode::SERVICE_UNAVAILABLE,
                InteractionError::NotAvailable,
            )));
        }
    }?;

    crate::http::verify_email::gate(
        gate,
        context.tenant,
        context.audit,
        context.nonce,
        &context.mount,
        &account,
        now,
    )
    .await
    .map(Box::new)
}

/// Where the consent behind a grant came from.
///
/// Two values rather than a `bool`, and carried all the way to the audit trail
/// rather than inferred there. Once a screen can be skipped, "the user
/// approved this" stops being one fact: it is either a person pressing a button
/// now, or this server deciding that a person pressed one before. An
/// investigator asking "was anybody actually looking at the screen when this
/// grant was made" must be able to answer it from the record, and no later
/// reader can reconstruct it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsentSource {
    /// The user was shown the offer and approved it.
    Screen,
    /// A consent recorded earlier covered the request (`ast-uwv.3`).
    Memory,
}

impl ConsentSource {
    /// The value that appears in the audit trail.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Screen => "screen",
            Self::Memory => "memory",
        }
    }
}

/// Appends the consent behind a grant to the audit trail.
///
/// A failure is logged and does not propagate, for the reason
/// [`record_registered_passkey`] gives: the grant is already committed, and
/// refusing the authorization afterwards would strand a user who did nothing
/// wrong. The transactional outbox (`ast-0ju.9`) is what closes that gap.
///
/// The scopes are recorded as a count and not as a list. What was granted is
/// on the grant, which this event names; repeating it here would put the same
/// fact in two places, free to disagree, and would put a client's scope tokens
/// into a trail that is kept longer than the grant is.
/// Applies Grant Management ID1 §5.2 to the grant the request named, if it
/// named one.
///
/// `Ok(None)` is "this request asked for no amendment", which is every request
/// that asked for `create` or for nothing at all — and every request on a
/// deployment that does not offer the feature, because the pushed-request
/// endpoint would not have stored the parameters.
///
/// `grant` arrives as the grant this authorization *would have created*: the
/// scopes the person just approved, the rich authorization, the claims request,
/// and the session and authentication of the sign-in that just happened. On
/// success it is rewritten in place to the amended grant, so the audit record
/// and everything after it describe what was actually stored.
///
/// # The check that could not be made at the push
///
/// §5.4's third `invalid_grant_id` case is a grant "whose user is not the
/// authenticated user", and at the push there is no authenticated user — the
/// browser has not been redirected yet. It is checked here, and reported as a
/// redirect to the client's `redirect_uri`, because by now that is the only
/// channel left: the client is not on the connection and the person in front of
/// the browser has nothing to do with the mistake.
///
/// A grant that has been revoked, or that has come to belong to another client,
/// since the push is refused here for the same reason and with the same code.
/// The window is short — a `request_uri` lives ninety seconds — but a
/// revocation inside it must not be undone by a merge.
///
/// # Errors
///
/// The RFC 6749 §4.1.2.1 code to redirect with: `invalid_grant_id` (§5.4) for a
/// grant this person and this client may not amend, `invalid_request` for a
/// merge that would not fit in a row, and `server_error` when the store failed.
async fn amended(
    context: &InteractionContext<'_>,
    parameters: &serde_json::Value,
    grant: &mut Grant,
    user: UserId,
    now: OffsetDateTime,
) -> Result<Option<asterius_domain::GrantId>, &'static str> {
    let string = |name: &str| parameters.get(name).and_then(serde_json::Value::as_str);
    let (Some(action), Some(grant_id)) = (string("grant_management_action"), string("grant_id"))
    else {
        return Ok(None);
    };
    let Some(action) = asterius_oidc::grant_management::Action::parse(action) else {
        // Unreachable: the push refused every other spelling before this row
        // existed. Refused rather than treated as `create`, because a request
        // that asked to amend a grant and silently got a new one has been
        // answered with something it did not ask for.
        tracing::error!(
            tenant = %context.tenant.id,
            "a stored request names a grant_management_action this server does not have"
        );
        return Err("server_error");
    };
    if !action.needs_an_existing_grant() {
        return Ok(None);
    }

    let Some(grants) = context.grant_amendments else {
        // The flag was switched off between the push and the sign-in. The
        // client asked for an amendment and there is nothing here to make one.
        tracing::warn!(
            tenant = %context.tenant.id,
            "a stored request asks to amend a grant on a tenant that no longer offers it"
        );
        return Err("invalid_grant_id");
    };

    let id = asterius_domain::GrantId::new(grant_id.to_owned());
    let held = match grants.find(&id).await {
        Ok(held) => held,
        Err(asterius_domain::DomainError::Invalid { .. }) => None,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read the grant to amend");
            return Err("server_error");
        }
    };
    // One code for "no such grant", "not this client's" and "not this
    // person's": telling them apart is an oracle for somebody else's
    // authorizations (§5.4 registers one code, and that is why).
    let Some(mut held) = held.filter(|held| {
        asterius_oidc::grant_management::may_be_amended(held, &grant.client, now)
            && asterius_oidc::grant_management::belongs_to(held, &user)
    }) else {
        tracing::info!(
            tenant = %context.tenant.id,
            "an authorization named a grant this person and client cannot amend"
        );
        return Err("invalid_grant_id");
    };

    if action.apply(&mut held, grant, now).is_err() {
        tracing::info!(
            tenant = %context.tenant.id,
            "a merge would have produced a grant too large to store"
        );
        return Err("invalid_request");
    }

    // §5.2's "shall invalidate existing refresh tokens" happens inside this
    // one call, in the transaction that writes the new permissions.
    if let Err(error) = grants.amend(&held, now).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot amend a grant");
        return Err("server_error");
    }

    let id = held.id.clone();
    *grant = held;
    Ok(Some(id))
}

async fn record_consent(
    context: &InteractionContext<'_>,
    grant: &Grant,
    source: ConsentSource,
    now: OffsetDateTime,
) {
    let mut event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::CONSENT_GRANTED,
        Outcome::Success,
        grant.subject.as_ref().map_or(Actor::System, |subject| {
            Actor::User(subject.as_str().to_owned())
        }),
        now,
    )
    .client(grant.client.clone())
    .grant(grant.id.clone())
    .detail(Detail::new().label("source", source.as_str()).number(
        "scopes",
        i64::try_from(grant.scopes.len()).unwrap_or(i64::MAX),
    ));
    if let Some(subject) = &grant.subject {
        event = event.subject(subject.as_str().to_owned());
    }
    if let Err(failure) = context.audit.record(event).await {
        tracing::error!(
            %failure,
            tenant = %context.tenant.id,
            "a granted consent was not written to the audit trail"
        );
    }
}

/// Takes a consent this person has already given, instead of asking again.
///
/// Returns the authorization response when the memory covers the whole
/// request, and `None` — meaning "draw the screen" — in every other case,
/// including every case this function could not decide. That asymmetry is the
/// design: the only way out of here with a grant is a memory that positively
/// covers what is being asked for, so a session that cannot be read, a subject
/// that cannot be resolved or a store that will not answer all lead to the
/// screen rather than to a grant nobody agreed to.
///
/// # Why this is not a shortcut around the stage machine
///
/// It still moves `Login -> Consent -> Response`, through
/// [`Stage::may_advance_to`], and it still produces a [`Decision::Approved`]
/// that [`complete`] turns into a code the same way a submitted form would.
/// What is skipped is the rendering, not the record: the grant `mint` writes
/// says exactly what was granted, and `asterius_oidc::claims::record_on_grant`
/// copies the consented claims onto it, so `ast-1sk.6`'s consent boundary holds
/// for a remembered consent exactly as it does for a fresh one.
///
/// # `prompt=consent`
///
/// OIDC Core §3.1.2.1: the client asked for the user to be prompted, and a
/// memory is not an answer to that. It is checked here rather than left to the
/// memory, because it is a fact about the request and not about the person.
async fn skip_consent_if_remembered(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    mut state: StoredState,
    record: &InteractionRecord,
    now: OffsetDateTime,
) -> Option<Response> {
    if state.stage != Stage::Consent {
        return None;
    }
    // A first-party interaction cannot be here — `Stage::may_advance_to`
    // refuses `Consent` for one — and if it somehow were, it has no client
    // whose earlier consent could cover anything.
    let request = record.client_request()?;
    let prompted = request
        .parameters
        .get("prompts")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|value| value == "consent")
        });
    if prompted {
        return None;
    }

    let subject = subject_of_record(context, record, now).await?;
    let grants = match context.grants.for_subject(&subject).await {
        Ok(grants) => grants,
        Err(error) => {
            // The screen, not an error page: the user can still consent, and
            // a store that cannot answer "what have they agreed to before"
            // has not said that they agreed to anything.
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read the consent memory");
            return None;
        }
    };
    let asked = Asked::from_parameters(&request.parameters);
    let covered = Remembered::of_client(&grants, &request.client, &subject, now).covers(
        &asked,
        context.memory,
        now,
    );
    if covered.delta().is_some() {
        // Something is new. `ast-uwv.5` narrows the screen to the delta;
        // until then the whole offer is shown, which asks for more than is
        // strictly outstanding and never for less.
        return None;
    }

    // What was asked for, which the memory has just been shown to cover in
    // full. Read off the request rather than off the grants: a grant that
    // covers *more* than this request must not widen it.
    let decision = Decision::Approved {
        scopes: asked.scopes.clone(),
    };
    state.decision = Some(StoredDecision::Approved {
        scopes: asked.scopes.iter().cloned().collect(),
    });
    if !state
        .stage
        .may_advance_to(Stage::Response, &record.continuation)
    {
        return None;
    }
    state.stage = Stage::Response;
    state.spend_csrf();
    save(context, presented, &state, None, now).await.ok()?;

    tracing::info!(
        tenant = %context.tenant.id,
        client = %request.client,
        "the consent screen was skipped: this request is covered by an earlier consent"
    );
    Some(
        complete(
            context,
            presented,
            &decision,
            record,
            ConsentSource::Memory,
            now,
        )
        .await,
    )
}

/// The `sub` this client sees for the user the interaction authenticated.
///
/// `None` whenever the answer is not certain — no session on the record, a
/// session that has ended, a client that has gone, a subject that will not
/// resolve. Every one of those is a reason to ask rather than to remember.
async fn subject_of_record(
    context: &InteractionContext<'_>,
    record: &InteractionRecord,
    now: OffsetDateTime,
) -> Option<asterius_domain::SubjectId> {
    let digest = record.session.as_deref()?;
    let session = context.sessions.find(digest).await.ok()??;
    if !session.status(now).is_usable() {
        return None;
    }
    let client = context
        .clients
        .find(&record.client_request()?.client)
        .await
        .ok()??;
    let sector = SectorIdentifier::of_client(&client).ok()?;
    context
        .subjects
        .subject(UserId::new(session.user), &sector)
        .await
        .ok()
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

    let decision = match offer.request.decide(approved, &granted) {
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
    if !state
        .stage
        .may_advance_to(Stage::Response, &record.continuation)
    {
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

    complete(
        context,
        presented,
        &decision,
        record,
        ConsentSource::Screen,
        now,
    )
    .await
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
    source: ConsentSource,
    now: OffsetDateTime,
) -> Response {
    // A decision belongs to an authorization: it is what the user said to a
    // *client*. A first-party interaction never reaches consent and therefore
    // never reaches here, so this is a wiring fault rather than a case.
    let Some(request) = record.client_request() else {
        tracing::error!(
            tenant = %context.tenant.id,
            "a consent decision was recorded for an interaction with no client"
        );
        return error_page(
            context,
            StatusCode::INTERNAL_SERVER_ERROR,
            InteractionError::NotAvailable,
        );
    };
    let string = |name: &str| {
        request
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
        Decision::Approved { scopes } => {
            match mint(context, scopes, request, record, source, now).await {
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
            }
        }
    };

    // How it is delivered was decided at push time and stored, so this reads
    // back a validated value rather than parsing anything the browser carried
    // (`ast-gxh.5`). A record with no `response_mode` is a query response,
    // which is what it was when it was pushed.
    let mode = match string("response_mode") {
        None => ResponseMode::Query,
        Some(raw) => ResponseMode::parse(&raw).unwrap_or_else(|_| {
            // Unreachable: `authorize::validate` refused every other spelling
            // before this row existed. A query response is the safe reading —
            // the parameters are the same either way, and the client's own
            // `redirect_uri` is where they go.
            tracing::error!(
                tenant = %context.tenant.id,
                "a stored request names a response_mode this server does not have"
            );
            ResponseMode::Query
        }),
    };

    match mode {
        ResponseMode::Query => redirect(context, &response, &redirect_uri),
        // The third acceptance criterion of `ast-gxh.5` is this line's doing:
        // `response` is already either a code or an error, so an error reaches
        // the client the way the client asked to be answered.
        ResponseMode::FormPost => form_post(context, &response, &redirect_uri),
    }
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
    request: &ClientRequest,
    record: &InteractionRecord,
    source: ConsentSource,
    now: OffsetDateTime,
) -> Result<String, &'static str> {
    let string = |name: &str| {
        request
            .parameters
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
    };

    let Ok(Some(client)) = context.clients.find(&request.client).await else {
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

    let mut grant = Grant::new(context.tenant.id.clone(), request.client.clone(), now);
    grant.user = Some(user);
    grant.subject = Some(subject);
    grant.scopes = scopes.iter().cloned().collect();
    grant.resources = request
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
    // RFC 9396 §3: what the user approved, recorded on the authorization it was
    // approved in. Read back through the same parser the push used rather than
    // copied as raw JSON — a stored request is not a trusted input, and a grant
    // that carried an element this server can no longer read would be an
    // authorization it could not describe or filter. What cannot be read back
    // is dropped rather than guessed at, which can only ever narrow the grant.
    grant.authorization_details = request
        .parameters
        .get("authorization_details")
        .and_then(|value| asterius_domain::AuthorizationDetails::from_value(value).ok())
        .map(|details| details.to_json())
        .unwrap_or_default();
    // The consent boundary (`ast-1sk.6`): the claims request the user approved
    // and the language they asked to be answered in are copied onto the grant
    // here, and `claims::resolve_for_grant` reads them from nowhere else.
    asterius_oidc::claims::record_on_grant(&request.parameters, &mut grant);
    grant.session = Some(DomainSessionId::new(digest.to_owned()));
    // OIDC Core §2's `auth_time`, `acr` and `amr`, copied off the session at
    // the one moment the session is certainly there (`ast-dlk`). §11 makes
    // `offline_access` access "when the End-User is not present", so a grant
    // carrying it outlives the session row — and a sweep, a sign-out or a
    // retention policy taking that row away must not leave the server with no
    // honest answer to when the person authenticated. See
    // `asterius_domain::GrantAuthentication` for why this is a snapshot and
    // not a pointer, and why a later step-up does not rewrite it.
    grant.authentication = Some(asterius_domain::GrantAuthentication {
        authenticated_at: session.authenticated_at,
        acr: session.acr.clone(),
        amr: session.amr.clone(),
    });
    // `claimed_at` stays `None`: Grant Management ID1 §5.6 makes a grant
    // `active` when a credential has been *claimed*, and nothing has been. The
    // token endpoint stamps it when the code is redeemed.

    // Grant Management ID1 §5.2: `merge` and `replace` amend the grant the
    // request named instead of creating a new one, and the client keeps the
    // `grant_id` it already had. `create`, and every request that asked for
    // nothing, take the path this server has always taken.
    let amendment = amended(context, &request.parameters, &mut grant, user, now).await?;
    let grant_id = if let Some(existing) = amendment {
        existing
    } else {
        let minted = grant.id.clone();
        if let Err(error) = context.grants.create(&grant).await {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot record a grant");
            return Err("server_error");
        }
        minted
    };
    record_consent(context, &grant, source, now).await;

    let Some(code_challenge) = string("code_challenge") else {
        // FAPI 2.0 SP §5.3.2.2 item 5 makes PKCE mandatory and
        // `authorize::validate` enforces it at push time, so a stored request
        // without one did not come from this server. Refusing is the only safe
        // reading: a code with no challenge is redeemable by whoever holds it.
        tracing::error!(tenant = %context.tenant.id, "a stored request has no code_challenge");
        return Err("server_error");
    };
    let minted = MintedCode::generate();
    let binding = code_binding(
        request,
        grant_id,
        code_challenge,
        &string,
        now + context.code_lifetime,
    );
    if let Err(error) = context.codes.issue(minted.digest(), &binding, now).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot store a code");
        return Err("server_error");
    }

    Ok(minted.expose().to_owned())
}

/// Everything an authorization code is bound to, assembled from the stored
/// request.
///
/// A function of its own so that [`mint`] stays a readable sequence of steps.
/// `parameter` is the stored request's reader, passed in rather than the map
/// itself, because the map's shape is `mint`'s business and not this one's.
fn code_binding(
    request: &ClientRequest,
    grant_id: asterius_domain::GrantId,
    code_challenge: String,
    parameter: &impl Fn(&str) -> Option<String>,
    expires_at: OffsetDateTime,
) -> CodeBinding {
    CodeBinding {
        client_id: request.client.as_str().to_owned(),
        grant_id,
        code_challenge,
        // Byte-for-byte the URI the code is being sent to, so redemption can
        // compare rather than re-derive (OIDC Core §3.1.3.2).
        redirect_uri: parameter("redirect_uri").unwrap_or_default(),
        nonce: parameter("nonce"),
        // RFC 9449 §10: when the request pinned a key, the code is pinned too.
        dpop_jkt: parameter("dpop_jkt"),
        // Grant Management ID1 §5.5: the token response carries `grant_id`
        // "if a valid grant management action was requested", and the code is
        // the only thing that still connects this request to the redemption.
        //
        // Re-parsed rather than copied, so the value written to the row is one
        // of the three `Action` spellings and never whatever a stored
        // parameter happens to hold. All three count, `create` included: §5.5
        // is about an *action* having been requested, not about a grant having
        // been amended, and a client that asked to create a grant is precisely
        // the one with no other way to learn its id.
        grant_management_action: parameter("grant_management_action")
            .as_deref()
            .and_then(asterius_oidc::grant_management::Action::parse)
            .map(|action| action.as_str().to_owned()),
        // The tenant's setting, used as it stands. It reached the caller
        // through `asterius_domain::TokenLifetimes`, which cannot hold a value
        // above FAPI 2.0 SP §5.3.2.1 item 11's sixty seconds, so there is
        // nothing to clamp here — and a clamp would be the second, silent
        // authority `ast-5c6` removed.
        expires_at,
    }
}

/// The end of a first-party interaction: the browser goes to the destination.
///
/// # Why there is no URL anywhere in this function
///
/// `destination` is a [`FirstPartyDestination`] — a variant of a closed enum —
/// and [`crate::http::console::location_of`] turns it into a compiled-in path.
/// Nothing the browser sent is consulted, so there is no destination to
/// validate, no allow-list to keep in step with the router, and no open
/// redirect to get wrong (ADR-0009, `ast-wr4`). A `next` parameter would put
/// all three back.
///
/// The interaction is spent first, for the reason [`complete`] gives: two tabs
/// that both submit a login must produce one arrival, and the spend is what
/// decides which. The interaction cookie goes with the response, because one
/// left in the browser is one an attacker can keep presenting against a row
/// that will never answer again.
async fn arrive(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    destination: FirstPartyDestination,
    now: OffsetDateTime,
) -> Response {
    if let Err(error) = context
        .requests
        .complete_interaction(&presented.digest(), now)
        .await
    {
        tracing::warn!(%error, tenant = %context.tenant.id, "nothing live to complete");
        return error_page(
            context,
            StatusCode::BAD_REQUEST,
            InteractionError::NotAvailable,
        );
    }

    let Ok(redirect) =
        crate::http::redirect::SeeOther::to(crate::http::console::location_of(destination))
    else {
        // Unreachable: the location is a `&'static str` in this crate with no
        // control character in it.
        tracing::error!(
            tenant = %context.tenant.id,
            "a compiled-in destination is not a usable Location"
        );
        return error_page(
            context,
            StatusCode::INTERNAL_SERVER_ERROR,
            InteractionError::NotAvailable,
        );
    };

    let mut response = redirect.into_response();
    clear(&mut response);
    // The response carries a `Set-Cookie` for a fresh session.
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
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
    deliver(context, ResponseMode::Query, response, redirect_uri)
}

/// Builds the authorization response and clears the spent interaction.
///
/// The shape of the response is `http::deliver`'s, shared with `/authorize` so
/// that there is one implementation of what a `query` and a `form_post`
/// response are. What stays here is the cookie: the interaction is spent by the
/// time this is reached, and one left in the browser is one an attacker can
/// keep presenting against a row that will never answer again.
fn deliver(
    context: &InteractionContext<'_>,
    mode: ResponseMode,
    response: &AuthorizationResponse,
    redirect_uri: &str,
) -> Response {
    match crate::http::deliver::build(
        context.tenant,
        context.nonce,
        &context.mount,
        mode,
        response,
        redirect_uri,
    ) {
        Ok(mut response) => {
            clear(&mut response);
            response
        }
        Err(error) => {
            // Unreachable: the redirect URI was matched against the client's
            // registration at the push, and `http::par` refuses a `form_post`
            // whose origin no policy can name while the client is still on the
            // connection to be told.
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "a validated redirect URI cannot carry its own response"
            );
            error_page(
                context,
                StatusCode::INTERNAL_SERVER_ERROR,
                InteractionError::NotAvailable,
            )
        }
    }
}

/// Delivers the authorization response as a page the browser posts to the
/// client (`ast-gxh.5`).
///
/// The page itself is `http::deliver`'s, shared with `/authorize`: one
/// implementation of OAuth 2.0 Form Post Response Mode §2, one place that names
/// the single origin `form-action` may reach, and one place that draws the
/// nonce. What this adds is the interaction's own cookie, spent with the
/// response that ends it — exactly as on the redirect path.
fn form_post(
    context: &InteractionContext<'_>,
    response: &AuthorizationResponse,
    redirect_uri: &str,
) -> Response {
    deliver(context, ResponseMode::FormPost, response, redirect_uri)
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
    render(
        context,
        &Screen {
            locale: locale_of(context, &state),
            stage: state.stage,
            csrf: &token,
            id,
            message: Some(message),
            offer: None,
            signed_in: state.username.as_deref(),
            typed: None,
        },
    )
}

/// Whether a query string asks for the sign-in page instead of the sign-up one.
///
/// Parsed as a form-urlencoded query rather than matched as a substring: a
/// value carrying `signin` inside another parameter is not a person pressing
/// the link, and `contains` cannot tell them apart.
fn asks_for_sign_in(query: &str) -> bool {
    url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == SIGN_IN_QUERY)
}

/// The registration stage: create the account, then sign the person in.
///
/// OpenID Connect Prompt Create 1.0 §3. The order is the one that cannot leave
/// a person stranded: the account is written first, and only then does this
/// become the ordinary authenticated path — §3 treats a successful creation as
/// an authentication, and [`authenticated`] is the one implementation of what
/// follows one. So a sign-up that succeeds reaches the consent screen through
/// exactly the code a password sign-in reaches it through, and there is no
/// second session-creation path to review.
///
/// The address is **not** verified here and the flow is not blocked on it.
/// Prompt Create §3 does not require it, and a flow that refused to continue
/// until a mailbox was read would strand the client's authorization on
/// something no browser can finish. `email_verified` stays `false`.
async fn create_account(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    state: StoredState,
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
    let typed = TypedSignup {
        username: field("username").unwrap_or_default().to_owned(),
        display_name: field("display_name").unwrap_or_default().to_owned(),
        email: field("email").unwrap_or_default().to_owned(),
    };

    // The flag, checked where the row would be written. A stored request can
    // only have reached `Stage::Register` if the tenant offered `create` when
    // it was pushed; a tenant that has switched it off since must not have an
    // account created for it anyway. The error page rather than a form that
    // will refuse: there is nothing the person can type to fix it.
    let Some(registrar) = context.registrar.as_ref() else {
        tracing::warn!(
            tenant = %context.tenant.id,
            "a sign-up reached this server for a tenant that does not offer registration"
        );
        return error_page(
            context,
            StatusCode::NOT_IMPLEMENTED,
            InteractionError::NotAvailable,
        );
    };

    // Every sign-up is counted, not only the refused ones. This form is an
    // unauthenticated way to write rows into `users`, so the bucket the login
    // form counts wrong guesses in is the bucket that bounds it (`ast-2vk.9`).
    let attempt = context.throttle.attempt(field("email"));
    let state = match gate(context, presented, state, id, &attempt, now).await {
        Ok(state) => state,
        Err(response) => return *response,
    };
    context
        .throttle
        .record_failure(&context.tenant.id, &attempt, now)
        .await;

    let accepted = match asterius_domain::AcceptedRegistration::accept(
        field("username").unwrap_or_default(),
        field("display_name"),
        field("email").unwrap_or_default(),
        field("password").unwrap_or_default(),
    ) {
        Ok(accepted) => accepted,
        // The domain's own sentence, which names the field that has to change
        // (WCAG 2.2 SC 3.3.1) and says nothing about any account: every one of
        // these is a statement about what was typed.
        Err(refusal) => {
            return retry_signup(
                context,
                presented,
                state,
                id,
                &typed,
                now,
                &refusal.to_string(),
            )
            .await;
        }
    };

    let created = match registrar.create(context.tenant, &accepted, now).await {
        Ok(user) => user,
        Err(crate::http::signup::SignupRefusal::Taken) => {
            // One sentence for a taken username and a taken address. A sign-up
            // page cannot avoid saying that *something* is in use, but it does
            // not have to say which — see `http::signup`.
            return retry_signup(
                context,
                presented,
                state,
                id,
                &typed,
                now,
                "That username or email address is not available.",
            )
            .await;
        }
        Err(crate::http::signup::SignupRefusal::NoPasswordMethod) => {
            tracing::error!(
                tenant = %context.tenant.id,
                "a sign-up reached this server with no password method configured"
            );
            return error_page(
                context,
                StatusCode::NOT_IMPLEMENTED,
                InteractionError::NotAvailable,
            );
        }
        Err(crate::http::signup::SignupRefusal::Storage(error)) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot create an account");
            return error_page(
                context,
                StatusCode::SERVICE_UNAVAILABLE,
                InteractionError::NotAvailable,
            );
        }
    };

    record_account_created(context, &created, now).await;

    let mut state = state;
    // The name the screens that follow use, through the one field `ast-bo5`
    // named: the display name when the person gave one, the login identifier
    // otherwise.
    state.signed_in_as(crate::http::signup::display_name(&created));
    authenticated(
        context,
        presented,
        state,
        id,
        record,
        *created.id.as_uuid(),
        now,
    )
    .await
}

/// Records the two things a sign-up brings into existence.
///
/// Two events, because they are two facts: an account, and a credential on it.
/// `credential.created` is the same event the passkey path writes, so "what
/// credentials does this account have, and when did they appear" is one query
/// rather than two.
///
/// `user.created` is `Actor::System`: nobody with a name did this, which is
/// exactly what distinguishes a self-registration from an administrator's
/// creation in the trail. The detail says which door it came through.
async fn record_account_created(
    context: &InteractionContext<'_>,
    created: &asterius_domain::User,
    now: OffsetDateTime,
) {
    let subject = created.id.as_uuid().to_string();
    record_event(
        context,
        AuditEvent::new(
            context.tenant.id.clone(),
            EventType::USER_CREATED,
            Outcome::Success,
            Actor::System,
            now,
        )
        .subject(subject.clone())
        .detail(Detail::new().label("path", "self-registration")),
    )
    .await;
    record_event(
        context,
        AuditEvent::new(
            context.tenant.id.clone(),
            EventType::CREDENTIAL_CREATED,
            Outcome::Success,
            Actor::User(subject.clone()),
            now,
        )
        .subject(subject)
        .detail(Detail::new().label("credential", "password")),
    )
    .await;
}

/// Re-renders the sign-up form with what was typed and why it was refused.
///
/// The password is not carried back; see [`TypedSignup`].
async fn retry_signup(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    mut state: StoredState,
    id: &str,
    typed: &TypedSignup,
    now: OffsetDateTime,
    message: &str,
) -> Response {
    let token = state.issue_csrf();
    if let Err(error) = save(context, presented, &state, None, now).await {
        return *error;
    }
    render(
        context,
        &Screen {
            locale: locale_of(context, &state),
            stage: state.stage,
            csrf: &token,
            id,
            message: Some(message),
            offer: None,
            signed_in: state.username.as_deref(),
            typed: Some(typed),
        },
    )
}

/// Appends a password sign-in to the audit trail (`ast-j7u`).
///
/// The counterpart of `http::passkeys::record_signed_in`, built the same way
/// and carrying the same fields, because the two are read together: an
/// operator asking "how did this account sign in" must get one answer shaped
/// one way, not a passkey answer and a hole where the commonest credential
/// was. The `method` detail is the RFC 8176 `amr` value the session was given,
/// taken from [`AuthenticationMethod`] rather than written out, so the trail
/// and the ID token cannot disagree about what was proved.
///
/// The session is named by its digest — what the row is keyed by, never the
/// value the browser holds — which is what lets the console follow a session
/// back to the authentication that opened it.
///
/// A failure to write is logged and does not propagate: the person is signed
/// in either way, and an audit outage must not become a sign-in that is
/// refused for a reason nobody can act on.
async fn record_signed_in(
    context: &InteractionContext<'_>,
    user: uuid::Uuid,
    session_digest: &str,
    now: OffsetDateTime,
) {
    let subject = user.to_string();
    record_event(
        context,
        AuditEvent::new(
            context.tenant.id.clone(),
            EventType::AUTH_LOGIN,
            Outcome::Success,
            Actor::User(subject.clone()),
            now,
        )
        .subject(subject)
        .session(DomainSessionId::new(session_digest.to_owned()))
        .detail(
            Detail::new()
                .label("kind", "password")
                .label("method", AuthenticationMethod::Password.as_str()),
        ),
    )
    .await;
}

/// Writes one event, or says in the log that it could not.
///
/// A helper because this module writes several, and a trail with a hole in it
/// is worse than one that says where the hole is.
async fn record_event(context: &InteractionContext<'_>, event: AuditEvent) {
    if let Err(error) = context.audit.record(event).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot record an interaction event");
    }
}

/// The limiter, before the credential is looked at.
///
/// That order is the only one that helps: a limit consulted after Argon2id has
/// run has already paid for the guess it was meant to refuse, so a limiter
/// behind the verification would bound the guessing without bounding the work.
///
/// Returns the state to carry on with, or the response to send instead.
async fn gate(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    state: StoredState,
    id: &str,
    attempt: &throttle::Attempt,
    now: OffsetDateTime,
) -> Result<StoredState, Box<Response>> {
    match context
        .throttle
        .check(&context.tenant.id, attempt, now)
        .await
    {
        Ok(None) => Ok(state),
        Ok(Some(refused)) => {
            throttle::record_throttled(context.audit, &context.tenant.id, refused, now).await;
            Err(Box::new(
                throttled(context, presented, state, id, now, refused).await,
            ))
        }
        Err(error) => {
            // Fail closed. A limiter that answers "no idea" is not permission,
            // and the store it could not reach is the same one the credential
            // check is about to need.
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read the login limiter");
            Err(Box::new(error_page(
                context,
                StatusCode::SERVICE_UNAVAILABLE,
                InteractionError::NotAvailable,
            )))
        }
    }
}

/// The login page, saying that nobody can sign in here.
///
/// Not a generic failure, unlike everything else on this path: a deployment
/// with no credential method is misconfigured rather than under attack, and
/// there is no account to enumerate when there is no verifier to ask. An
/// operator needs to know which way it is broken.
async fn no_method(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    mut state: StoredState,
    id: &str,
    now: OffsetDateTime,
) -> Response {
    let token = state.issue_csrf();
    if let Err(error) = save(context, presented, &state, None, now).await {
        return *error;
    }
    render(
        context,
        &Screen {
            locale: locale_of(context, &state),
            stage: Stage::Login,
            csrf: &token,
            id,
            message: Some("Signing in is not available on this server."),
            offer: None,
            signed_in: state.username.as_deref(),
            typed: None,
        },
    )
}

/// The login page again, refusing to check anything this time.
///
/// The same page and the same words a wrong password gets, plus a hint about
/// when to come back — the criterion `ast-2vk.9` states. The status is 429 and
/// the hint is repeated in `Retry-After`, so a client that reads headers and a
/// person who reads English are told the same thing.
///
/// It says the attempt was throttled, and it says nothing about whose. Two
/// people typing the same wrong identifier see this in the same number of
/// attempts whether that identifier belongs to anybody or not.
async fn throttled(
    context: &InteractionContext<'_>,
    presented: &InteractionId,
    state: StoredState,
    id: &str,
    now: OffsetDateTime,
    refused: throttle::Refused,
) -> Response {
    let mut response = retry(context, presented, state, id, now, &refused.hint()).await;
    // Only a rendered page is turned into a refusal. `retry` answers with an
    // error page of its own when the interaction cannot be saved, and
    // relabelling that as 429 would say the limiter refused something it did
    // not.
    if response.status() == StatusCode::OK {
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        if let Ok(value) = HeaderValue::from_str(&refused.retry_after_seconds().to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
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
    // Every `cookie` field, not just the first: HTTP/2 lets a client split the
    // list, and this page always has two `__Host-` cookies in flight (ast-bze).
    let from_cookie = interaction::id_from_cookie_header(&crate::http::cookies(headers));

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

/// The language an interaction in progress is being conducted in.
///
/// The stored tag when there is one — see `StoredState::locale` — and a fresh
/// negotiation from this browser and this tenant when there is not. Never an
/// error: OIDC Core §3.1.2.1 forbids one.
fn locale_of(context: &InteractionContext<'_>, state: &StoredState) -> Locale {
    state
        .locale
        .as_deref()
        .and_then(Locale::matching)
        .unwrap_or_else(|| context.language.negotiate(&UiLocales::default()))
}

/// The language this interaction begins in, from the request that started it.
///
/// The full three layers: the `ui_locales` the client pushed, then the
/// browser's `Accept-Language`, then the tenant's default. Called once, on the
/// first screen, and written into the state so that the rest of the journey
/// does not re-decide it.
fn opening_locale(context: &InteractionContext<'_>, record: &InteractionRecord) -> Locale {
    let asked = record
        .client_request()
        .map_or_else(asterius_domain::locale::UiLocales::default, |request| {
            crate::http::i18n::stored_ui_locales(&request.parameters)
        });
    context.language.negotiate(&asked)
}

/// One rendering: which screen, in which language, with which token.
///
/// A struct rather than seven parameters. The list grew a language when
/// `ast-ndk.5` landed, and a call whose arguments are seven values of four
/// types is one where two of them get swapped in a rebase without the compiler
/// noticing.
struct Screen<'a> {
    /// The language the whole journey is being conducted in.
    locale: Locale,
    /// Which page.
    stage: Stage,
    /// The synchroniser token issued with this rendering.
    csrf: &'a CsrfToken,
    /// The interaction id, for the form's action.
    id: &'a str,
    /// A previous failure, in this server's own words.
    message: Option<&'a str>,
    /// What is being asked for, when the screen is the consent one.
    offer: Option<&'a ConsentOffer>,
    /// Who is signed in, once somebody is.
    signed_in: Option<&'a str>,
    /// What was typed into the sign-up form last time, when this is a retry of
    /// it. Their own text, escaped by the template like anyone else's.
    typed: Option<&'a TypedSignup>,
}

/// The three sign-up fields worth handing back after a refusal.
///
/// The password is not among them, and never will be: a rejected form that
/// re-rendered the password would put it in the HTML, in the browser's cache
/// and in any proxy that logs bodies. Retyping it is the cost.
#[derive(Debug, Default)]
struct TypedSignup {
    /// The login identifier they chose.
    username: String,
    /// The display name, if they gave one.
    display_name: String,
    /// The address.
    email: String,
}

/// The parts of the consent screen that are not the offer itself.
///
/// The offer is [`ConsentOffer`] and travels separately, because it is the one
/// thing on this page that came from the client rather than from this server.
struct ConsentChrome<'a> {
    /// The words, and the language they are in.
    text: &'a Catalog,
    /// Where the decision posts.
    action: &'a str,
    /// The face this page draws itself in (`ast-vn7`).
    font_url: &'a str,
    /// The synchroniser token issued with this rendering.
    csrf: &'a CsrfToken,
    /// Who is signed in, so a person on a shared machine can see it is them
    /// (`ast-bo5`).
    signed_in: Option<&'a str>,
}

/// Draws the consent screen, and widens `form-action` for it alone.
///
/// This form posts back to the interaction, but its answer is a 303 to the
/// client — and `form-action` governs that redirect too, so the consent screen
/// is the one page that names the client's origin (`ast-jsq`). No other stage
/// does: the widening is attached here and nowhere else.
fn consent_page(
    context: &InteractionContext<'_>,
    offer: &ConsentOffer,
    chrome: &ConsentChrome<'_>,
) -> Response {
    let request = &offer.request;
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ConsentPage {
            text: chrome.text,
            tenant_name: &context.tenant.display_name,
            client_name: &request.client_name,
            username: chrome.signed_in.unwrap_or_default(),
            redirect_host: &request.redirect_host,
            scopes: request
                .scopes
                .iter()
                .map(|scope| ScopeLine {
                    name: scope.name.clone(),
                    description: scope.description.clone(),
                    required: scope.required,
                })
                .collect(),
            offline_access: request.offline_access,
            resources: request.resources.iter().cloned().collect(),
            authorization_details: request
                .authorization_details
                .iter()
                .map(|detail| pages::DetailLine {
                    name: detail.name.clone(),
                    description: detail.description.clone(),
                    locations: detail.locations.clone(),
                    actions: detail.actions.clone(),
                    datatypes: detail.datatypes.clone(),
                })
                .collect(),
            action: chrome.action,
            csrf: chrome.csrf.expose(),
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(chrome.font_url),
        })
    });
    match offer.form_action.clone() {
        Some(origin) => document.with_form_post_to(origin).into_response(),
        None => document.into_response(),
    }
}

/// What the sign-in page is drawn from.
///
/// A struct for the reason [`SignUpPage`] is one: the fields are all `&str`,
/// and a renderer taking eight of them positionally is a renderer whose call
/// site can transpose two.
struct SignInPage<'a> {
    /// The words, and the language they are in.
    text: &'a Catalog,
    /// Where the form posts, and where a passkey sign-in navigates.
    action: &'a str,
    /// Where the script asks for its assertion options.
    passkey_options: &'a str,
    /// Where it posts the assertion back.
    passkey_finish: &'a str,
    /// Account recovery, for the "forgot your password?" link.
    recovery_href: &'a str,
    /// The face this page draws itself in (`ast-vn7`).
    font_url: &'a str,
    /// The synchroniser token issued with this rendering.
    csrf: &'a CsrfToken,
    /// Why the previous submission was refused, if there was one.
    message: Option<&'a str>,
}

/// Draws the sign-in page, which is also the step-up page.
fn sign_in_page(context: &InteractionContext<'_>, page: &SignInPage<'_>) -> Response {
    Document::render(context.nonce, |nonce| {
        pages::render(&LoginPage {
            text: page.text,
            tenant_name: &context.tenant.display_name,
            action: page.action,
            passkey_options_action: page.passkey_options,
            passkey_finish_action: page.passkey_finish,
            csrf: page.csrf.expose(),
            login_hint: None,
            message: page.message,
            // `ast-ndk.4`: the way back into an account, offered where a
            // person discovers they cannot get in. Only where there is a
            // password to recover — a deployment with no password method has
            // nothing for `/recovery` to reset, and a link to a page that
            // refuses everybody is worse than no link.
            recovery_href: context.credentials.is_some().then_some(page.recovery_href),
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(page.font_url),
        })
    })
    .into_response()
}

/// What the sign-up page is drawn from.
///
/// A struct rather than seven arguments, for the reason the lint that asked
/// for it gives: a renderer with seven positional parameters is a renderer
/// whose call site can transpose two of them.
struct SignUpPage<'a> {
    /// The words, and the language they are in.
    text: &'a Catalog,
    /// Where the form posts: this interaction, at whatever stage it is.
    action: &'a str,
    /// The same URL, asking for the sign-in page instead.
    sign_in_href: &'a str,
    /// The face this page draws itself in (`ast-vn7`).
    font_url: &'a str,
    /// The synchroniser token issued with this rendering.
    csrf: &'a CsrfToken,
    /// Why the previous submission was refused, if there was one.
    message: Option<&'a str>,
    /// What was typed into it, so a refusal does not make somebody type it
    /// all again. Never the password; see [`TypedSignup`].
    typed: Option<&'a TypedSignup>,
}

/// Draws the sign-up page (OpenID Connect Prompt Create 1.0 §3).
///
/// Lifted out of [`render`] rather than inlined in its arm: the page has more
/// fields than any other stage's, and every one of them is a value a stranger
/// influenced. It posts to the same action as every other stage — this is one
/// interaction and the browser posts back to it — and the "already have an
/// account?" link is that same URL with the query
/// [`SIGN_IN_QUERY`] on it.
fn sign_up_page(context: &InteractionContext<'_>, page: &SignUpPage<'_>) -> Response {
    Document::render(context.nonce, |nonce| {
        pages::render(&pages::RegistrationPage {
            text: page.text,
            tenant_name: &context.tenant.display_name,
            action: page.action,
            csrf: page.csrf.expose(),
            username: page.typed.map(|typed| typed.username.as_str()),
            email: page.typed.map(|typed| typed.email.as_str()),
            display_name: page.typed.map(|typed| typed.display_name.as_str()),
            // Both stated in the markup and both enforced again by
            // `AcceptedRegistration::accept`: an attribute is a courtesy to
            // the browser, never a control.
            minimum_password_length: asterius_domain::entities::password::MIN_LENGTH,
            maximum_display_name_length: asterius_domain::MAX_DISPLAY_NAME_LENGTH,
            sign_in_href: page.sign_in_href,
            message: page.message,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(page.font_url),
        })
    })
    .into_response()
}

/// Renders the page for a stage.
fn render(context: &InteractionContext<'_>, screen: &Screen<'_>) -> Response {
    let &Screen {
        locale,
        stage,
        csrf,
        id,
        message,
        offer,
        signed_in,
        typed,
    } = screen;
    // Under the prefix the tenancy layer removed: this page is served at
    // `/t/{tenant}/interaction/{id}` and posts back to itself (`ast-295`).
    let action = context.mount.absolute(&format!("/interaction/{id}"));
    // The two endpoints the sign-in script talks to. Built by
    // `http::passkeys`, so the page and the router cannot disagree about where
    // they are.
    let (passkey_options, passkey_finish) = crate::http::passkeys::login_paths(&context.mount, id);
    // The face this page draws itself in, under the same prefix (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    // Account recovery and the sign-up page's way out, both under the prefix
    // for the reason the action is.
    let recovery_href = context.mount.absolute(crate::http::recovery::REQUEST_PATH);
    let sign_in_href = format!("{action}?{SIGN_IN_QUERY}");
    // One catalogue per rendering, and the `lang` attribute comes out of it
    // too: a page cannot say `fr` over English words.
    let text = &context.language.catalog(locale);
    match stage {
        Stage::Login | Stage::StepUp => sign_in_page(
            context,
            &SignInPage {
                text,
                action: &action,
                passkey_options: &passkey_options,
                passkey_finish: &passkey_finish,
                recovery_href: &recovery_href,
                font_url: &font_url,
                csrf,
                message,
            },
        ),
        // Prompt Create 1.0 §3.
        Stage::Register => sign_up_page(
            context,
            &SignUpPage {
                text,
                action: &action,
                sign_in_href: &sign_in_href,
                font_url: &font_url,
                csrf,
                message,
                typed,
            },
        ),
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
            consent_page(
                context,
                offer,
                &ConsentChrome {
                    text,
                    action: &action,
                    font_url: &font_url,
                    csrf,
                    signed_in,
                },
            )
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

    // No stored request has been loaded on every path that reaches here — a
    // browser mismatch is refused before anything is read — so the negotiation
    // is the two layers that are always available: this browser's field and the
    // tenant's default.
    let text = &context.language.for_request(&UiLocales::default());
    let font_url = crate::http::font_url(&context.mount);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            text,
            tenant_name: &context.tenant.display_name,
            message: text.error_cannot_continue(),
            correlation_id: &correlation,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
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
pub(crate) fn set_session_cookie(response: &mut Response, id: &SessionId) {
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
    use axum::http::HeaderValue;

    /// The `ast-bze` site: `resume` reads the interaction cookie, and a client
    /// is free to put it in a *second* `cookie` field (RFC 9113 §8.2.3). The
    /// session cookie coming first is the ordinary case for a signed-in user
    /// mid-flow, and reading only the first field made it a silent 401.
    #[test]
    fn the_interaction_cookie_is_read_from_a_second_cookie_field() {
        // Arrange
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-asterius_session=a-session"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-asterius_ix=an-interaction"),
        );

        // Act
        let found = interaction::id_from_cookie_header(&crate::http::cookies(&headers));

        // Assert
        assert_eq!(
            found.map(|id| id.expose().to_owned()),
            Some("an-interaction".to_owned())
        );
    }

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
