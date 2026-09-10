//! The admin console's door: how a session comes to exist for it.
//!
//! ADR-0009 settled what the console *is* — a first-party, same-origin
//! application authenticated by `__Host-asterius_session`, with no OAuth token
//! anywhere in the browser — and left open how a session opens for it. This is
//! that answer, and it is the smallest one available: the console does not
//! authenticate anybody. It sends them through the login flow that already
//! exists, by opening an **interaction** whose continuation is a first-party
//! destination rather than a client's `redirect_uri` (`ast-wr4`).
//!
//! # Why not a second login path
//!
//! Because the session is produced by
//! the private `interaction::sign_in` and by nothing else. Everything that
//! flow has learned to do — rotating the session id at authentication,
//! throttling before the verifier runs, saying the same sentence for "no such
//! user" and "wrong password" with the timing equalised, recording `acr` and
//! `amr` — would have to be learned again by a second path, and ADR-0009 says
//! plainly why that is refused: a second authentication path is a second thing
//! to get wrong, and it would throw away the `acr`/`amr` that
//! "administrative actions require a phishing-resistant authenticator" will be
//! built on.
//!
//! # Why the destination is not a parameter
//!
//! There is no `next=`. The interaction stores a
//! [`FirstPartyDestination`] variant, and [`location_of`] maps it to a path
//! compiled into this binary. A browser cannot supply a destination, so there
//! is no destination to validate and no allow-list to drift: the open redirect
//! is impossible by construction rather than by vigilance.
//!
//! # What a deployment admin has to have proved
//!
//! A usable session is not the whole answer any more (`ast-895`). A visitor
//! holding a deployment-scoped role whose session records only a password is
//! sent back through the login flow rather than shown the console, because the
//! passkey their account holds is what this surface requires and that flow is
//! what knows how to ask for it. The policy is
//! `asterius_domain::admin_access_policy`; `/admin/api` applies the same one,
//! and has to, since this document is inert without it.
//!
//! # Why the console lives under a tenant
//!
//! ADR-0010 keeps `Session::tenant` non-optional, and the deployment
//! administrator is a user of the reserved tenant (`ast-1cj`). So the console
//! is at `/t/{tenant}/admin/` and there is no console at the root: a session
//! opened in one tenant is not a session in another, and this module refuses
//! one that names a different tenant even if a lookup ever handed it over.

use crate::http::redirect::SeeOther;
use asterius_domain::entities::session;
use asterius_domain::{
    AdminAdmission, DomainError, FirstPartyDestination, InteractionRepository, PasskeyEnrolment,
    Role, Session, SessionRepository, Tenant, UserId, admin_access_policy,
};
use asterius_web::csp::Nonce;
use asterius_web::interaction::{self, InteractionId};
use axum::Extension;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::{Duration, OffsetDateTime};

/// How long the door stays open once somebody has knocked.
///
/// Longer than a pushed authorization request's ninety seconds, because the
/// person on the other side of this one is typing a password rather than
/// following a redirect a client has already prepared. Short enough that an
/// abandoned login is a row that goes away by itself.
pub const ENTRY_LIFETIME: Duration = Duration::minutes(10);

/// Where a first-party interaction sends the browser when it is finished.
///
/// **Relative on purpose.** The tenancy layer strips `/t/{id}` before routing,
/// so a handler cannot see whether it is serving `/t/demo/interaction/…` or
/// `/interaction/…`, and a root-relative `/admin/` would drop the prefix and
/// land outside the tenant. Resolved against either form, `../admin/` is the
/// console of the tenant the interaction belongs to — which is the same
/// reasoning `asterius_admin_api::console` gives for its asset URLs.
///
/// A `match` over a closed enum, so adding a destination is a compile error
/// here and nowhere else has to be told.
#[must_use]
pub const fn location_of(destination: FirstPartyDestination) -> &'static str {
    match destination {
        FirstPartyDestination::AdminConsole => "../admin/",
        // The device verification page (`ast-lh3.3`), reached from
        // `/interaction/{id}` and so one segment up, like the console.
        FirstPartyDestination::DeviceVerification => "../device",
    }
}

/// The console's routes, ready to merge into the tenanted router.
///
/// The assets come from `asterius_admin_api`, which owns the bundle; the entry
/// document is mounted here, because deciding whether this visitor may see it
/// needs a session repository and therefore a tenant — and the tenant is what
/// the layer above has just resolved. The redirect from `/admin` to `/admin/`
/// is mounted here too, for the reason the private `slashless` gives.
///
/// Only `GET` is mounted, on all three. Nothing under `/admin/` changes
/// anything: the console's writes go to `/admin/api`, which has the
/// session-bound CSRF defence ADR-0009 requires, and a state-changing route
/// that could be reached by a top-level navigation is exactly what that ADR
/// forbids.
pub fn routes(store: asterius_store_pg::Store, bundle: asterius_admin_api::Bundle) -> Router {
    asterius_admin_api::console::assets(bundle)
        .merge(slashless())
        .route(
            asterius_admin_api::console::INDEX_PATH,
            axum::routing::get(index).with_state(ConsoleState { store, bundle }),
        )
}

/// `/admin` without its trailing slash — a mistake a person makes by typing.
///
/// A redirect rather than a second copy of the document, because the console's
/// asset URLs are relative and only resolve inside `/admin/`. The target is
/// relative too, so that the `/t/{id}` prefix the tenancy layer has already
/// stripped — and which no handler below it can see — survives the trip.
///
/// It is mounted here, and not beside the assets in
/// `asterius_admin_api::console`, for the reason [`crate::http::redirect`]
/// gives: every redirect this codebase emits is a 303 built by [`SeeOther`],
/// `admin-api` may not depend on this crate (`scripts/check-layering.sh`), and
/// a 308 open-coded on the other side of that line is exactly what `ast-a8h`
/// had to undo. Only `GET` is mounted, so a state-changing verb meets the same
/// 405 here as on every other console route.
fn slashless() -> Router {
    Router::new().route(
        asterius_admin_api::console::BASE_PATH,
        axum::routing::get(slashless_redirect),
    )
}

/// Where `/admin` sends the browser: the entry document, named relatively.
const SLASHLESS_TARGET: &str = "admin/";

/// `GET /admin` — the redirect to `/admin/`.
async fn slashless_redirect() -> Response {
    let Ok(redirect) = SeeOther::to(SLASHLESS_TARGET) else {
        // Unreachable: the target is a compiled-in ASCII path.
        tracing::error!("the console redirect target is not a usable Location");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    redirect.into_response()
}

/// What the mounted entry document holds.
#[derive(Debug, Clone)]
struct ConsoleState {
    store: asterius_store_pg::Store,
    bundle: asterius_admin_api::Bundle,
}

/// [`AdminStanding`] against this deployment's store.
#[derive(Debug, Clone)]
struct StoredStanding {
    store: asterius_store_pg::Store,
    tenant: asterius_domain::TenantId,
}

#[async_trait::async_trait]
impl AdminStanding for StoredStanding {
    async fn roles(&self, user: UserId) -> Result<Vec<Role>, DomainError> {
        let granted = asterius_store_pg::PgRoleRepository::new(
            self.store.pool().clone(),
            self.tenant.clone(),
        )
        .roles_of(user)
        .await?;
        Ok(granted.into_iter().map(|role| role.role).collect())
    }

    async fn passkey_enrolment(&self, user: UserId) -> Result<PasskeyEnrolment, DomainError> {
        use asterius_domain::ports::PasskeyRepository as _;

        let credentials = self
            .store
            .scope(self.tenant.clone())
            .passkeys()
            .credential_ids(&user)
            .await?;
        Ok(if credentials.is_empty() {
            PasskeyEnrolment::None
        } else {
            PasskeyEnrolment::Enrolled
        })
    }
}

/// `GET /admin/` as axum sees it.
async fn index(
    State(state): State<ConsoleState>,
    Extension(tenant): Extension<std::sync::Arc<Tenant>>,
    Extension(nonce): Extension<Nonce>,
    headers: HeaderMap,
) -> Response {
    let scope = state.store.scope(tenant.id.clone());
    let interactions = scope.auth_requests();
    let sessions = scope.sessions();
    let standing = StoredStanding {
        store: state.store.clone(),
        tenant: tenant.id.clone(),
    };
    enter(
        &ConsoleContext {
            tenant: &tenant,
            interactions: &interactions,
            sessions: &sessions,
            standing: &standing,
            nonce: &nonce,
            bundle: state.bundle,
        },
        &headers,
        OffsetDateTime::now_utc(),
    )
    .await
}

/// What the console entry needs to know about the person behind a session.
///
/// A port rather than the store, for the reason every other handler in this
/// module has one: `enter` is driven by `crates/server/tests/console.rs`
/// without a database, and "a deployment admin on a password meets a login
/// page" is a criterion that has to be testable there rather than only in an
/// end-to-end run somebody may skip.
///
/// Two questions and not a repository, because those are the two the rule
/// asks. Handing this layer a role repository would let a later edit grant one
/// from here.
#[async_trait::async_trait]
pub trait AdminStanding: Send + Sync {
    /// Every role the user holds in this tenant.
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the store could not be read.
    async fn roles(&self, user: UserId) -> Result<Vec<Role>, DomainError>;

    /// Whether the user has a passkey that could have been asked for.
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the store could not be read.
    async fn passkey_enrolment(&self, user: UserId) -> Result<PasskeyEnrolment, DomainError>;
}

/// What the console entry needs.
pub struct ConsoleContext<'a> {
    /// The tenant this request arrived at, and the only tenant whose session
    /// counts here.
    pub tenant: &'a Tenant,
    /// Where a first-party interaction is opened.
    pub interactions: &'a dyn InteractionRepository,
    /// Where the cookie's session is looked up.
    pub sessions: &'a dyn SessionRepository,
    /// What the visitor holds, and what they could have proved (`ast-895`).
    pub standing: &'a dyn AdminStanding,
    /// The CSP nonce this response was drawn with.
    pub nonce: &'a Nonce,
    /// The built console, or an empty bundle when this binary carries none.
    pub bundle: asterius_admin_api::Bundle,
}

impl std::fmt::Debug for ConsoleContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsoleContext").finish_non_exhaustive()
    }
}

/// `GET /admin/` — the console, or the way in to it.
///
/// A signed-in visitor gets the entry document. Everyone else gets a login,
/// through the ordinary interaction pages: no page of the console is rendered
/// to somebody with no session, so the shell is not a thing an unauthenticated
/// visitor can make this server draw.
pub async fn enter(
    context: &ConsoleContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    if let Some(session) = signed_in(context, headers, now).await {
        match admission(context, &session).await {
            Ok(AdminAdmission::Admitted | AdminAdmission::AdmittedPendingEnrolment) => {
                return asterius_admin_api::console::document(context.bundle, context.nonce);
            }
            // `ast-895`: a deployment admin whose session records only a
            // password meets the login page again, which is where the passkey
            // it holds can be presented. Not an error page — there is a
            // credential this person has and can use, and the shortest route
            // to it is the one flow that knows how to ask for it.
            //
            // The session is left alone. It is a perfectly good session for
            // everything that is not the admin surface, and revoking it here
            // would sign the user out of the tenant to enforce a rule about
            // the console.
            Ok(AdminAdmission::StepUpRequired) => return begin(context, now).await,
            // "We could not tell what you hold" is not "then come in", and it
            // is not "you have no session" either: sending an administrator
            // round the login loop for a database that is down would look like
            // a credential problem and hide an outage.
            Err(error) => {
                tracing::error!(
                    %error,
                    tenant = %context.tenant.id,
                    "cannot decide what a console visitor is allowed to see"
                );
                return unavailable();
            }
        }
    }
    begin(context, now).await
}

/// Whether this session may see the console, or must authenticate again.
///
/// The policy is `asterius_domain::admin_access_policy`, the same one
/// `asterius_admin_api::auth` applies to `/admin/api` — the two are the shell
/// and the data behind it, and a rule enforced in one and not the other would
/// be a console that draws itself and then fails every request.
///
/// A store that cannot be read is an error and never an admission: "we could
/// not tell what roles you hold" must not resolve to "then come in".
///
/// # Errors
///
/// [`DomainError`] from either read. The caller turns it into a 503.
async fn admission(
    context: &ConsoleContext<'_>,
    session: &Session,
) -> Result<AdminAdmission, DomainError> {
    let user = UserId::new(session.user);
    let roles = context.standing.roles(user).await?;

    if !admin_access_policy::enrolment_decides(&roles, &session.amr) {
        return Ok(AdminAdmission::Admitted);
    }

    let enrolment = context.standing.passkey_enrolment(user).await?;

    let admission = admin_access_policy::admit(&roles, &session.amr, enrolment);
    if admission == AdminAdmission::AdmittedPendingEnrolment {
        tracing::warn!(
            tenant = %context.tenant.id,
            user = %user.as_uuid(),
            "the console admitted a deployment admin on a password: this account has no \
             passkey, and the enrolment window stays open until it registers one"
        );
    }
    Ok(admission)
}

/// The answer when this server cannot decide, which is not "come in".
fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        "the console is not available\n",
    )
        .into_response()
}

/// The session behind the cookie, when there is a usable one *of this tenant*.
///
/// The repository is already scoped to the tenant, so a session digest from
/// another one does not resolve here — the tenant comparison is the second
/// lock on that door, and it is cheap. Both are needed: the scoping is a
/// property of how this handler was assembled, and the criterion "a session in
/// tenant A does not open the console of tenant B" should not rest on an
/// assembly step being remembered.
async fn signed_in(
    context: &ConsoleContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Option<Session> {
    let cookies = crate::http::cookies(headers);
    let value = interaction::cookie_value(&cookies, session::COOKIE_NAME)?;
    let digest = asterius_domain::sha256_hex(value.as_bytes());
    let session = match context.sessions.find(&digest).await {
        Ok(session) => session?,
        Err(error) => {
            // A session that cannot be read is not a session. The visitor
            // meets a sign-in page, which is what this server does everywhere
            // else it cannot answer that question.
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a session at the console");
            return None;
        }
    };
    if session.tenant != context.tenant.id {
        tracing::warn!(
            tenant = %context.tenant.id,
            "a session of another tenant was presented at this console"
        );
        return None;
    }
    session.status(now).is_usable().then_some(session)
}

/// Opens a first-party interaction and sends the browser to its login page.
///
/// The same 303-and-cookie pair `/authorize` produces, and for the same
/// reasons: 303 so a browser fetches the next page rather than repeating this
/// request, the id in both the URL and a `__Host-` cookie so that a leaked URL
/// is inert without the cookie (FAPI 2.0 SP §6.5), and `no-store` because the
/// response carries a credential.
async fn begin(context: &ConsoleContext<'_>, now: OffsetDateTime) -> Response {
    let id = InteractionId::generate();
    if let Err(error) = context
        .interactions
        .begin_first_party_interaction(
            &id.digest(),
            FirstPartyDestination::AdminConsole,
            now + ENTRY_LIFETIME,
            now,
        )
        .await
    {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot open a console login");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            "signing in is not available\n",
        )
            .into_response();
    }

    // Relative, for the reason `location_of` gives: the tenant prefix is not
    // visible from here, and `interaction/{id}` resolved against `/t/x/admin/`
    // is this tenant's interaction page.
    let Ok(redirect) = SeeOther::to(&format!("../interaction/{}", id.expose())) else {
        // Unreachable: an interaction id is base64url.
        tracing::error!(tenant = %context.tenant.id, "an interaction id is not a usable Location");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let mut response = redirect.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = interaction::set_cookie(&id).parse() {
        headers.insert(header::SET_COOKIE, value);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    /// One request against the slash-less route, as axum sees it.
    async fn slashless_request(verb: &str) -> Response {
        let request = Request::builder()
            .method(verb)
            .uri(asterius_admin_api::console::BASE_PATH)
            .body(Body::empty())
            .expect("a request");
        slashless()
            .oneshot(request)
            .await
            .expect("the router answered")
    }

    /// A typed `/admin` reaches `/admin/`, with the only redirect status this
    /// codebase allows.
    #[tokio::test]
    async fn the_slashless_path_redirects_with_see_other() {
        // Arrange / Act
        let response = slashless_request("GET").await;

        // Assert
        assert_eq!(response.status().as_u16(), 303);
        assert_eq!(
            response.headers().get(header::LOCATION).expect("Location"),
            SLASHLESS_TARGET
        );
    }

    /// The target is relative because the tenancy layer strips `/t/{id}`
    /// before routing: a root-relative `/admin/` would drop the tenant.
    #[test]
    fn the_slashless_target_keeps_a_tenant_prefix() {
        let base = url::Url::parse("https://as.example/t/demo/admin").expect("a url");
        let resolved = base.join(SLASHLESS_TARGET).expect("a join");
        assert_eq!(resolved.path(), "/t/demo/admin/");

        let base = url::Url::parse("https://as.example/admin").expect("a url");
        let resolved = base.join(SLASHLESS_TARGET).expect("a join");
        assert_eq!(
            resolved.path(),
            asterius_admin_api::console::INDEX_PATH,
            "the slash-less path must land on the entry document"
        );
    }

    /// The mutating-verb guard that `asterius_admin_api::console` applies to
    /// the rest of `/admin` follows the route to its new home. A 405 rather
    /// than a 404 is the point: it proves the path is still mounted *and* that
    /// only `GET` answers there, which a 404 would not distinguish from a
    /// route lost in the move.
    #[tokio::test]
    async fn the_slashless_path_refuses_a_state_changing_verb() {
        for verb in ["POST", "PUT", "DELETE"] {
            let response = slashless_request(verb).await;
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{verb} /admin"
            );
        }
    }

    /// The destination is a variant, and the mapping is total: every variant
    /// has a path, and no path is a URL somebody could have supplied.
    #[test]
    fn every_first_party_destination_has_a_compiled_in_relative_path() {
        // One variant today. The `match` in `location_of` is what makes a
        // second one a compile error rather than a silent gap, so this asserts
        // the shape of the answer rather than the length of the list.
        let location = location_of(FirstPartyDestination::AdminConsole);
        assert!(
            !location.contains("://") && !location.starts_with('/'),
            "{location} is not a relative path"
        );
        assert!(
            location.ends_with('/'),
            "{location} needs its trailing slash"
        );
    }

    /// `../admin/` resolved against both shapes of interaction URL lands on
    /// the console of the tenant the interaction belongs to. The tenancy layer
    /// strips `/t/{id}`, so the handler that emits this cannot tell which it
    /// is serving.
    #[test]
    fn the_destination_resolves_under_the_tenant_prefix_and_without_one() {
        let base = url::Url::parse("https://as.example/t/demo/interaction/abc").expect("a url");
        let resolved = base
            .join(location_of(FirstPartyDestination::AdminConsole))
            .expect("a join");
        assert_eq!(resolved.path(), "/t/demo/admin/");

        let base = url::Url::parse("https://as.example/interaction/abc").expect("a url");
        let resolved = base
            .join(location_of(FirstPartyDestination::AdminConsole))
            .expect("a join");
        assert_eq!(resolved.path(), "/admin/");
    }

    /// A sanity check on the pair: the entry document is served where the
    /// login sends people.
    #[test]
    fn the_destination_is_where_the_console_is_mounted() {
        let base = url::Url::parse("https://as.example/interaction/abc").expect("a url");
        let resolved = base
            .join(location_of(FirstPartyDestination::AdminConsole))
            .expect("a join");
        assert_eq!(resolved.path(), asterius_admin_api::console::INDEX_PATH);
    }

    /// The id is minted here and never derived from anything a request
    /// carried, so two visitors never share one.
    #[test]
    fn two_entries_mint_two_interaction_ids() {
        let first = InteractionId::generate();
        let second = InteractionId::generate();
        assert_ne!(first.digest(), second.digest());
    }
}
