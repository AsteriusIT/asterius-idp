//! `GET|POST /authorize` — where a client's request becomes a user's.
//!
//! RFC 9126 §4. The client has already pushed the whole authorization request
//! and holds a `request_uri`; it sends the user agent here with that plus
//! `client_id`, and nothing else that matters. This endpoint looks the request
//! up, checks it belongs to the client that is named, mints the browser's
//! credential, and redirects into the interaction.
//!
//! # Why almost nothing is validated here
//!
//! Because it already was. `asterius_oidc::authorize::validate` ran at push
//! time, against an *authenticated* client, and the result was stored. Nothing
//! reaching this endpoint can change it: the parameters are not in the URL,
//! and the only thing the browser carries is a reference. Re-validating would
//! mean a second implementation of the same rules — and the interesting bugs
//! in OAuth live in the gap between two implementations of one rule.
//!
//! What *is* checked here is the pair of things that are new: the `client_id`
//! in the URL against the one the request was pushed by, and the fact that the
//! request is still live.
//!
//! # Why an error here is a page and not a redirect
//!
//! RFC 6749 §4.1.2.1: the AS "MUST NOT automatically redirect the user-agent
//! to the invalid redirection URI". At this endpoint the request may be
//! unknown, expired, or for another client — in every one of those cases this
//! server has no redirect URI it has any business sending a browser to. So
//! every failure renders the error page, and `Location` appears only on the
//! success path.

use crate::http::redirect::SeeOther;
use crate::tenancy::MountPrefix;
use asterius_domain::{
    AuthRequestRepository, ClientId, GrantRepository, InteractionRepository, PushedRequest,
    Session, SubjectId, Tenant,
};
use asterius_oidc::authorize::ResponseMode;
use asterius_oidc::code::AuthorizationResponse;
use asterius_oidc::consent_memory::{Asked, MemoryPolicy, Remembered};
use asterius_oidc::decision::{
    Consent, DecisionPolicy, Interaction, Requirements, SessionState, Unmet, decide,
};
use asterius_oidc::par;
use asterius_web::interaction::{self, InteractionId, Stage, StoredState};
use asterius_web::pages::{ErrorPage, nonce_attribute};
use asterius_web::{Document, csp::Nonce};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

/// What the handler needs.
pub struct AuthorizeContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The client's view of a pushed request.
    pub requests: &'a dyn AuthRequestRepository,
    /// The browser's view of the same rows.
    pub interactions: &'a dyn InteractionRepository,
    /// The session this browser already has, when it has a usable one.
    ///
    /// Resolved by the caller from the session cookie, because "usable" is a
    /// question about a row and a clock rather than about HTTP. `None` covers
    /// no cookie, an unknown session, and one that is expired, idle or
    /// revoked — OIDC Core §3.1.2.1 asks whether the End-User "is logged in",
    /// and none of those three is.
    pub session: Option<&'a Session>,
    /// The grants this user already holds, for the consent memory
    /// (`ast-uwv.3`).
    pub grants: &'a dyn GrantRepository,
    /// The accounts, read for one thing only: the name the consent screen puts
    /// on the person it is about (`ast-bo5`).
    ///
    /// Needed here because an interaction that begins at [`Stage::Consent`]
    /// has had no sign-in step to record it (`ast-k7f`), and a screen that
    /// says "Signed in as ." is a screen somebody on a shared machine cannot
    /// check.
    pub users: &'a dyn asterius_domain::UserDirectory,
    /// What this tenant will do without being asked.
    pub policy: DecisionPolicy,
    /// The authentication contexts this tenant can produce (`ast-2vk.7`).
    ///
    /// Consulted twice here, for the two questions OIDC Core asks separately:
    /// whether an essential `acr` is producible at all (Unmet Authentication
    /// Requirements 1.0 §2) and whether the session in front of us has produced
    /// one (§5.5.1.1). A voluntary `acr_values` is not consulted at all — it is
    /// honoured by the login that follows, which writes the highest value it
    /// reached onto the session (§3.1.2.1).
    pub acr: &'a asterius_domain::AcrPolicy,
    /// Whether this tenant remembers consent, and for how long it remembers an
    /// `offline_access` one.
    pub memory: MemoryPolicy,
    /// The CSP nonce for this response.
    pub nonce: &'a Nonce,
    /// The prefix routing removed from this request's path, put back on the
    /// `Location` that sends the browser into the interaction (`ast-295`).
    pub mount: MountPrefix,
}

impl std::fmt::Debug for AuthorizeContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizeContext").finish_non_exhaustive()
    }
}

/// Handles an authorization request.
///
/// `parameters` are the query or form pairs, whichever verb was used — OIDC
/// Core §3.1.2.1 permits both and they carry the same two values.
pub async fn authorize(
    context: AuthorizeContext<'_>,
    parameters: &[(String, String)],
    subject_of: impl AsyncFnOnce(&ClientId, uuid::Uuid) -> Option<String>,
    now: OffsetDateTime,
) -> Response {
    let value = |name: &str| {
        let mut found = parameters.iter().filter(|(k, _)| k == name);
        let first = found.next().map(|(_, v)| v.as_str());
        // RFC 6749 §3.1 again: a repeated parameter is refused, not resolved.
        if found.next().is_some() { None } else { first }
    };

    // FAPI 2.0 SP §5.3.2.2 item 3: an authorization request that did not come
    // through PAR is rejected. There is no branch here that reads `scope` or
    // `redirect_uri` from the URL, so there is no path by which one could.
    let Some(request_uri) = value("request_uri") else {
        return error_page(&context, StatusCode::BAD_REQUEST);
    };
    let Some(client_id) = value("client_id") else {
        return error_page(&context, StatusCode::BAD_REQUEST);
    };

    // Shape first, so a guessed value costs a string comparison rather than a
    // query (RFC 9126 §7.1).
    let Ok(digest) = par::digest_of(request_uri) else {
        return error_page(&context, StatusCode::BAD_REQUEST);
    };

    // `peek`, not `consume`. FAPI 2.0 SP §5.3.2.2 Note 3 puts one-time use at
    // the *completion* of authorization, not at page load: a user who reloads
    // before deciding has done nothing wrong. The interaction's own
    // one-per-request guard is what stops this being reusable.
    let stored = match context.requests.peek(&digest, now).await {
        Ok(Some(stored)) => stored,
        // Unknown, expired and consumed are one answer. A browser that could
        // tell them apart could probe for live requests.
        Ok(None) => return error_page(&context, StatusCode::NOT_FOUND),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a pushed request");
            return error_page(&context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // The check this endpoint exists to make. A `request_uri` issued to one
    // client, presented in a request naming another, is refused — and refused
    // as a *page*, because the redirect URI on the stored request belongs to
    // the client that pushed it, not to whoever is asking now.
    if stored.client.as_str() != client_id {
        tracing::warn!(
            tenant = %context.tenant.id,
            "a request_uri was presented under a different client_id"
        );
        return error_page(&context, StatusCode::BAD_REQUEST);
    }

    // What this request needs before it can be answered (`ast-gxh.8`). Decided
    // here, before an interaction exists, because that is the only place from
    // which a `prompt=none` request can be refused *without* a page having been
    // rendered: OIDC Core §3.1.2.1 forbids displaying any authentication or
    // consent user interface for one, and an interaction row is the first step
    // towards displaying one.
    let requirements = requirements(&context, &stored);
    // The `sub` this client sees for the session's user, resolved whenever
    // there is a usable session. It used to be resolved only for an
    // `id_token_hint`, on the grounds that a lookup per browser hit is not
    // worth a comparison nobody asked for — but the consent memory is keyed by
    // it (`asterius_oidc::consent_memory`), and a memory that could not name
    // the person it is about would be a memory about the wrong one. It also
    // costs the same query the interaction is about to make anyway.
    let subject = match context.session {
        Some(session) if session.status(now).is_usable() => {
            subject_of(&stored.client, session.user).await
        }
        _ => None,
    };
    let consent = match &subject {
        Some(subject) => {
            remembered_consent(&context, &stored, &SubjectId::new(subject.clone()), now).await
        }
        // No subject means no session, or a session whose subject could not be
        // resolved. Neither is somebody this server can say has consented
        // before, and the failing-closed reading of "I do not know" is to ask.
        None => Consent::Required,
    };
    let state = match context.session {
        Some(session) if session.status(now).is_usable() => SessionState::Active {
            session,
            subject: subject.as_deref(),
            consent,
        },
        _ => SessionState::None,
    };

    let decision = decide(&requirements, &state, context.policy, context.acr, now);
    match decision {
        // All of these continue into the interaction — including `Silent`,
        // which continues into it in order to come straight back out again: the
        // interaction is where a code is minted and a grant is written, and a
        // second implementation of that here would be a second implementation
        // of the consent boundary. *Which* screen comes first is the
        // interaction's own stage machine, and it is not decided twice — except
        // for the two stages that depend on a session this handler resolved and
        // on a policy the interaction does not hold, which `begin_at` records
        // below.
        Interaction::Silent
        | Interaction::Login
        | Interaction::SelectAccount
        | Interaction::StepUp
        | Interaction::Consent
        | Interaction::Register => {}
        Interaction::Refuse(unmet) => return refuse(&context, &stored, unmet),
    }

    // The browser's credential. Minted here, never derived from the
    // `request_uri` — a client that could compute it could drive the user's
    // login.
    let id = InteractionId::generate();
    if let Err(error) = context
        .interactions
        .begin_interaction(&digest, &id.digest(), now)
        .await
    {
        // Either the request went away between the peek and here, or it
        // already has an interaction — a second `/authorize` on one
        // `request_uri` is a replay. Both render the same page.
        tracing::warn!(%error, tenant = %context.tenant.id, "cannot begin an interaction");
        return error_page(&context, StatusCode::BAD_REQUEST);
    }

    // Where the interaction starts, when it does not start at the beginning.
    //
    // `Stage::Login` is the default and it is the right default: it asks for
    // more than may be needed and never for less. The decisions that may start
    // later are the ones this handler resolved a *session* to make — the
    // step-up rotates that session (`ast-2vk.7`), a silent request is answered
    // from it (`ast-ovr`), and a consent decision was reached only because the
    // session was found live, fresh and about the right person (`ast-k7f`) —
    // and none of them is a question the interaction can re-decide, because the
    // browser's cookie is not something it resolves.
    match decision {
        Interaction::StepUp => begin_at(&context, &id.digest(), Stage::StepUp, None, now).await,
        // Two arrivals at one stage, because from here they are the same fact:
        // the person is signed in and the only thing that might still be owed
        // is a decision.
        //
        // `Silent` owes nothing — `http::interaction::show` reads the consent
        // memory back and advances `Consent -> Response` without drawing a
        // screen. `Consent` owes exactly one screen, which is what single
        // sign-on is: a client this user has never agreed to costs them a
        // decision and not their credentials (`ast-k7f`). `decide` returns it
        // only for a session that is usable, that `prompt=login` and `max_age`
        // did not make stale, and whose `acr` meets an essential request — so
        // the guards of OIDC Core §3.1.2.1, §3.1.2.3 and §5.5.1.1 are already
        // spent by the time this arm is reached, and every one of them lands
        // on `Login` or `StepUp` instead.
        //
        // Neither is a shortcut around the stage machine: the move out of
        // `Consent` is still made through `Stage::may_advance_to`, and a memory
        // that does not cover the request renders the consent screen to the
        // person the session names rather than granting anything.
        Interaction::Silent | Interaction::Consent => {
            // The name the screen puts on that person (`ast-bo5`). Resolved for
            // the consent decision only: the silent path draws no screen, and a
            // query per silent authorization would buy nothing.
            let username = if decision == Interaction::Consent {
                signed_in_username(&context, now).await
            } else {
                None
            };
            begin_at(&context, &id.digest(), Stage::Consent, username, now).await;
        }
        Interaction::Login
        | Interaction::SelectAccount
        | Interaction::Register
        | Interaction::Refuse(_) => {}
    }

    // Through `SeeOther`, never open-coded. `http::source_audit` enforces
    // that, and it is right to: 303 is the status that turns a POST into the
    // GET the interaction page expects, and the helper is also where response
    // splitting through a `Location` is refused. FAPI 2.0 SP §5.3.2.2 items
    // 10–11 forbid 307 outright.
    // Under the prefix the tenancy layer removed: the interaction lives at
    // `/t/{tenant}/interaction/{id}`, and a root-absolute `Location` would
    // send the browser to a path this server mounts nothing at (`ast-295`).
    let target = context
        .mount
        .absolute(&format!("/interaction/{}", id.expose()));
    let Ok(redirect) = SeeOther::to(&target) else {
        // Unreachable: the id is base64url. Refusing rather than sending a
        // header we could not build is the only safe reading.
        return error_page(&context, StatusCode::INTERNAL_SERVER_ERROR);
    };

    let mut response = redirect.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = interaction::set_cookie(&id).parse() {
        headers.insert(header::SET_COOKIE, value);
    }
    // The redirect carries a credential in both the URL and the cookie.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Records that an interaction begins somewhere other than the beginning.
///
/// The one place an interaction is started anywhere other than
/// [`Stage::Login`]: the step-up, the silent request and the consent of a
/// signed-in user all come through here, so there is a single answer to "what
/// does it mean to begin at a stage" rather than one per decision.
///
/// Written after `begin_interaction` because the row has to exist to be
/// updated, and it carries the session the stage is *about* — the step-up
/// needs to know which session to rotate (`ast-2vk.7`), a silent request needs
/// to know whose consent to look up (`ast-ovr`), and a consent screen shown
/// without a sign-in needs to name the person it is about (`ast-k7f`), while
/// the browser's cookie is not something the interaction handler re-resolves.
///
/// `username` is what that screen displays, and `None` for every stage that
/// draws no screen naming anybody.
///
/// A failure here is logged and not fatal. An interaction whose state was not
/// written starts at [`Stage::Login`], which asks the user for more than was
/// needed rather than for less: the session that would have been rotated is
/// replaced by a fresh one, and the user who would have seen nothing signs in
/// again. Both are worse than the intended path and neither grants anything.
async fn begin_at(
    context: &AuthorizeContext<'_>,
    interaction: &str,
    stage: Stage,
    username: Option<String>,
    now: OffsetDateTime,
) {
    let beginning = serde_json::to_value(StoredState {
        stage,
        username,
        ..StoredState::default()
    })
    .unwrap_or_default();
    let session = context.session.map(|session| session.id_digest.as_str());
    if let Err(error) = context
        .interactions
        .save_interaction_state(interaction, &beginning, session, now)
        .await
    {
        tracing::error!(
            %error,
            tenant = %context.tenant.id,
            ?stage,
            "cannot record the stage an interaction begins at"
        );
    }
}

/// The name of the person whose session this browser is carrying.
///
/// Read for one purpose: the consent screen has to say whose account is about
/// to be granted (`ast-bo5`). An interaction that begins at [`Stage::Consent`]
/// never passes through the sign-in that would otherwise have recorded it.
///
/// `None` whenever the answer is not certain — no usable session, an account
/// that is gone, a store that will not answer. The screen then names nobody,
/// which is what it did before this path existed; refusing the authorization
/// over a display name would be a worse answer than an unnamed screen, and the
/// grant that follows is keyed by the session either way.
async fn signed_in_username(context: &AuthorizeContext<'_>, now: OffsetDateTime) -> Option<String> {
    let session = context
        .session
        .filter(|session| session.status(now).is_usable())?;
    match context
        .users
        .by_id(asterius_domain::UserId::new(session.user))
        .await
    {
        Ok(account) => account.map(|account| account.username),
        Err(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "cannot read the account a consent screen names"
            );
            None
        }
    }
}

/// Whether this request is already covered by a consent this person gave
/// before (`ast-uwv.3`).
///
/// The memory is the grants themselves — there is no consent table, for the
/// reasons `asterius_oidc::consent_memory` sets out — so this is a read of the
/// grants the subject holds, folded through the rule that decides which of them
/// still stand.
///
/// # Why a store failure answers `Required`
///
/// Because the two ways of being wrong are not symmetrical. A memory that
/// cannot be read and is treated as "granted" completes an authorization
/// nobody was asked about; treated as "required", it shows a consent screen to
/// somebody who has seen it before. The second is an inconvenience and the
/// first is a consent failure, so the unreadable case takes the same answer as
/// the empty one.
async fn remembered_consent(
    context: &AuthorizeContext<'_>,
    stored: &PushedRequest,
    subject: &SubjectId,
    now: OffsetDateTime,
) -> Consent {
    let grants = match context.grants.for_subject(subject).await {
        Ok(grants) => grants,
        Err(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "cannot read the grants a consent decision depends on"
            );
            return Consent::Required;
        }
    };
    let asked = Asked::from_parameters(&stored.parameters);
    Remembered::of_client(&grants, &stored.client, subject, now)
        .covers(&asked, context.memory, now)
        .consent()
}

/// Reads the decision's inputs back off the stored request.
///
/// The reading itself is [`Requirements::from_parameters`], shared with the
/// login that follows so that the value `/authorize` decided a step-up against
/// and the value the session ends up carrying cannot disagree (`ast-0zg`). What
/// is left here is the one thing that crate cannot do: say out loud that a row
/// this server wrote will not parse back. `asterius-oidc` has no logger by
/// design, and a damaged `claims` document turning a requirement into a
/// suggestion is something an operator has to be able to see.
fn requirements(context: &AuthorizeContext<'_>, stored: &PushedRequest) -> Requirements {
    if stored
        .parameters
        .get("claims")
        .is_some_and(|claims| asterius_oidc::claims::ClaimsRequest::from_json(claims).is_err())
    {
        tracing::error!(
            tenant = %context.tenant.id,
            client = %stored.client,
            "a stored claims request will not parse back"
        );
    }
    Requirements::from_parameters(&stored.parameters)
}

/// Answers the client with the reason its request cannot be served.
///
/// A redirect — or a form post — rather than a page, and this is the one place
/// in this handler where that is right. Everywhere else `/authorize` refuses
/// with a page because the redirect URI cannot be trusted: the request may be
/// unknown, expired, or another client's. Here it is none of those. The request
/// was found, it belongs to the client that is asking, and its `redirect_uri`
/// was matched against that client's registration at the push. RFC 6749
/// §4.1.2.1 says an error then goes to the client, and OIDC Core §3.1.2.6
/// defines exactly which error this is.
///
/// The response travels in the mode the request asked for, `form_post`
/// included: `ast-gxh.5` delivered that path for errors as well as for codes,
/// and an error that quietly arrived as a query response would reach a client
/// that is waiting for a POST.
///
/// # Why the request is left alive
///
/// Nothing is consumed here. The refusal is a pure function of the request and
/// the browser's session, so a retry produces the same answer — and a user who
/// signs in elsewhere and comes back should meet a request that can now be
/// served, rather than one this server threw away while telling them to log in.
/// The push's own expiry is what bounds it.
fn refuse(context: &AuthorizeContext<'_>, stored: &PushedRequest, unmet: Unmet) -> Response {
    let string = |name: &str| {
        stored
            .parameters
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
    };
    let Some(redirect_uri) = string("redirect_uri") else {
        // A stored request with no redirect URI did not come from this server's
        // own validator, and there is nowhere to send the browser.
        tracing::error!(tenant = %context.tenant.id, "a stored request has no redirect_uri");
        return error_page(context, StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mode = string("response_mode")
        .map(|raw| ResponseMode::parse(&raw).unwrap_or_default())
        .unwrap_or_default();

    tracing::info!(
        tenant = %context.tenant.id,
        client = %stored.client,
        error = unmet.code(),
        "an authorization request cannot be served"
    );

    let response = AuthorizationResponse::Error {
        error: unmet.code(),
        state: string("state"),
        // RFC 9207 §3: the issuer travels with every authorization response,
        // including this one, so a client can tell which server answered.
        issuer: context.tenant.issuer.as_str().to_owned(),
    };
    match crate::http::deliver::build(
        context.tenant,
        context.nonce,
        mode,
        &response,
        &redirect_uri,
    ) {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "a validated redirect URI cannot carry an authorization error"
            );
            error_page(context, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// The error page. Never a redirect — see the module documentation.
fn error_page(context: &AuthorizeContext<'_>, status: StatusCode) -> Response {
    let correlation = interaction::correlation_id();
    tracing::info!(
        correlation_id = %correlation,
        tenant = %context.tenant.id,
        %status,
        "authorization request refused"
    );

    let document = Document::render(context.nonce, |nonce| {
        asterius_web::pages::render(&ErrorPage {
            locale: "en",
            tenant_name: &context.tenant.display_name,
            message: "This sign-in request cannot be continued.",
            correlation_id: &correlation,
            nonce_attribute: nonce_attribute(nonce),
        })
    });
    (status, document).into_response()
}
