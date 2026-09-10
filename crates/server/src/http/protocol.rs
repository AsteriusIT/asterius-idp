//! The protocol routes, mounted from the endpoint registry.
//!
//! Every route here comes from [`asterius_oidc::metadata::Endpoint`], which is
//! the same list the discovery document is rendered from. That is the whole
//! design: an endpoint cannot be advertised without being mounted, or mounted
//! without being advertised, because there is one iterator and both read it.
//!
//! Most handlers still answer 501. That is deliberate — see the
//! module documentation on `asterius_oidc::metadata` for why advertising a
//! not-yet-built endpoint and answering 501 is more honest than omitting it
//! from a document the specification says must contain it.

use crate::client_auth::ClientAuthenticator;
use crate::http::authorization_code::AuthorizationCode;
use crate::http::authorize::{self, AuthorizeContext};
use crate::http::client_configuration::{self, ConfigurationContext};
use crate::http::dpop::DpopEndpoint;
use crate::http::interaction::{self, InteractionContext};
use crate::http::logout;
use crate::http::par::{self, PushContext};
use crate::http::passkeys::{self, PasskeyContext, PasskeyLoginContext};
use crate::http::refresh::RefreshToken;
use crate::http::register::{self, RegisterContext, RegistrationPolicy};
use crate::http::revocation;
use crate::http::token::{self, TokenContext};
use crate::http::userinfo;
use crate::tenancy::MountPrefix;
use crate::tenant_settings::SettingsDirectory;
use asterius_domain::{Capabilities, DomainError, KeyStore, Tenant, TokenLifetimes};
use asterius_oidc::client_auth::{AssertionRules, Attempt};
use asterius_oidc::metadata::{self, Endpoint};
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

/// How long a client may cache the discovery document.
///
/// Five minutes. Long enough that a client is not refetching it on every
/// request, short enough that turning a feature flag off takes effect while an
/// operator is still watching.
const METADATA_MAX_AGE: u32 = 300;

/// How long a client may cache the JWKS.
///
/// Deliberately shorter than the rotation grace period. A verifier that cached
/// the key set must have refetched it before the key it holds stops being
/// published, or a valid token starts failing for a reason nobody can see.
/// `ast-mxc.3` owns the rotation schedule; until it lands this is a fixed
/// conservative value.
const JWKS_MAX_AGE: u32 = 300;

/// What the protocol handlers need.
#[derive(Clone)]
pub struct ProtocolState {
    /// Where signing keys come from.
    pub keys: Arc<dyn KeyStore>,
    /// What this deployment offers. The same value the router was built from,
    /// so the document cannot describe a different server than the one running.
    pub capabilities: Capabilities,
    /// Each tenant's settings, cached, for the flags it has switched off.
    ///
    /// `None` is a deployment where no tenant has settings of its own — which
    /// is every test that only cares about the deployment's capabilities — and
    /// then the document describes exactly [`Self::capabilities`]. It is not a
    /// fallback for a *failed* read: see [`crate::tenant_settings`].
    pub tenant_settings: Option<SettingsDirectory>,
    /// How endpoints that require an authenticated client get one.
    ///
    /// `None` leaves those endpoints answering 501 rather than accepting
    /// unauthenticated requests. That is the safe default for a partially
    /// wired deployment: an endpoint with no way to authenticate must not be
    /// one that skips authentication.
    pub clients: Option<Arc<ClientEndpoints>>,
}

/// The database-backed pieces the client-facing endpoints need.
///
/// Separate from [`ProtocolState`] so that the discovery and JWKS handlers —
/// which need none of it — can be tested without a database.
pub struct ClientEndpoints {
    /// Authenticates the client behind a request.
    pub authenticator: Arc<ClientAuthenticator>,
    /// Tenant-scoped repositories.
    pub store: asterius_store_pg::Store,
    /// What a deployment offers, for re-validating a stored registration.
    pub capabilities: Capabilities,
    /// How long a `request_uri` lives, already clamped.
    pub par_lifetime: time::Duration,
    /// How long this deployment's artefacts live when a tenant has expressed
    /// no opinion of its own.
    ///
    /// A [`TokenLifetimes`], not two durations: the type cannot be built
    /// outside the profile's caps, so the fallback is under them by
    /// construction and nothing downstream has to check it again (`ast-5c6`).
    pub lifetimes: TokenLifetimes,
    /// Each tenant's settings, cached — where the lifetimes above are
    /// overridden.
    ///
    /// `None` is a deployment with no settings repository wired, which reads
    /// as "no tenant has an opinion" and never as a fallback for a *failed*
    /// read: see [`crate::tenant_settings`] and [`lifetimes_for`].
    pub tenant_settings: Option<SettingsDirectory>,
    /// Opens the tenant's pairwise salt, which every `sub` derives from.
    pub kek: Arc<dyn asterius_jose::Kek>,
    /// This deployment's keys, for verifying a token *this server* issued.
    ///
    /// Two callers. The end-session endpoint's `id_token_hint` needs the
    /// public half of a key that may already have been retired (OIDC
    /// RP-Initiated Logout 1.0 §4), which is what
    /// [`KeyStore::public_key`]
    /// resolves and what the published JWKS no longer contains; UserInfo
    /// verifies an access token against the set `/jwks` publishes, and it is
    /// the same handle so that the two cannot hold different opinions about
    /// which keys are current.
    ///
    /// Registration reads it too, to refuse an `id_token_signed_response_alg`
    /// this tenant holds no active key for. The same handle again, and for the
    /// same reason: the set that check consults must be the set the deployment
    /// actually signs from.
    pub keys: Arc<dyn KeyStore>,
    /// Who may register a client, and how.
    pub registration: RegistrationPolicy,
    /// ADR-0006's one outbound path, for the URLs a registration document
    /// names. Shared with nothing else: the client key cache holds its own
    /// handle to the same adapter.
    pub outbound: Arc<dyn asterius_domain::ports::JwksFetcher>,
    /// Where registration decisions are recorded.
    pub audit: Arc<dyn asterius_domain::AuditSink>,
    /// How long this deployment's sessions live.
    pub session_lifetimes: asterius_domain::Lifetimes,
    /// Argon2id parameters, checked against the floor at startup.
    ///
    /// `None` when the deployment has no password method configured, which is
    /// a legitimate shape — passkeys are primary — and which the login page
    /// reports rather than failing obscurely.
    pub argon2: Option<asterius_domain::Argon2Parameters>,
    /// Signs everything this deployment issues.
    ///
    /// Held rather than built per request: it caches the unwrapped private
    /// keys, and a per-request one would decrypt on every token — see
    /// [`crate::signing::CachedSigner`].
    pub signer: Arc<dyn asterius_domain::keys::Signer>,
    /// How many failed sign-ins this deployment tolerates, and over what
    /// window (`ast-2vk.9`).
    ///
    /// The counters themselves are rows in `rate_limits`, reached through the
    /// same pool as everything else: a limit held in process memory would be
    /// multiplied by the replica count, which is the same argument ADR-0008
    /// makes about the pairwise-salt cache.
    pub login_limits: asterius_domain::LoginLimits,
    /// What each protocol endpoint permits per window (`ast-p2l.3`), already
    /// validated, so the wiring applies numbers rather than opinions.
    pub endpoint_limits: asterius_domain::EndpointLimits,
    /// Validates DPoP proofs on every endpoint that takes one.
    ///
    /// Always present: the *decision* about whether proofs are required lives
    /// inside it (`Feature::DpopNonce` for nonces, `dpop_bound_access_tokens`
    /// on the client for the proof itself), so there is no configuration in
    /// which this endpoint should skip the check rather than run it and find
    /// nothing.
    pub dpop: Arc<DpopEndpoint>,
}

impl ClientEndpoints {
    /// The password verifier for one tenant, when passwords are configured.
    ///
    /// Built per request rather than held: it carries a decoy hash computed at
    /// construction, and one per tenant per process would be a cache with a
    /// lifetime nobody has thought about. Building it costs one Argon2id hash,
    /// which is the same order as the verification that follows.
    fn passwords(
        &self,
        tenant: &asterius_domain::TenantId,
    ) -> Option<asterius_store_pg::PgPasswordVerifier> {
        let parameters = self.argon2?;
        asterius_store_pg::PgPasswordVerifier::new(
            self.store.pool().clone(),
            tenant.clone(),
            parameters,
        )
        .inspect_err(|error| tracing::error!(%error, "cannot build a password verifier"))
        .ok()
    }
}

impl std::fmt::Debug for ClientEndpoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientEndpoints").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ProtocolState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolState").finish_non_exhaustive()
    }
}

/// Mounts every enabled endpoint, plus the two discovery documents.
///
/// The tenancy middleware has already stripped the tenant from the path and put
/// the resolved [`Tenant`] in the request extensions, so handlers here mount at
/// bare paths and take the tenant as an extractor. A handler therefore has no
/// tenant parameter it could get wrong.
///
/// The deployment's flags decide what is *mounted*; a tenant's flags decide
/// what its requests reach, because the router is built once per process and a
/// tenant is only known per request. [`tenant_feature_guard`] is that second
/// half, and it reads the same [`Endpoint`] registry and the same
/// `effective_capabilities` the document is rendered from — so an endpoint a
/// tenant switched off is absent from its metadata *and* answers 404, which is
/// what `ast-edc` closes and what the parity test in `tests/discovery.rs`
/// asserts for every gated endpoint.
pub fn routes(state: ProtocolState) -> Router {
    let capabilities = state.capabilities;
    let guard = FeatureGuard {
        capabilities,
        tenant_settings: state.tenant_settings.clone(),
    };
    let built = state.clients.clone();
    let built_clients = built.is_some();
    let mut router = Router::new()
        // OIDC Discovery §4 and RFC 8414 §3. Both forms of the URL are
        // normalised to these paths by the tenancy middleware, so one route
        // serves the path-appended and path-inserted spellings.
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/oauth-authorization-server", get(discovery))
        .route(Endpoint::Jwks.path(), get(jwks))
        .with_state(state);

    // The endpoints that need an authenticated client, when the deployment has
    // the database wiring for them. `ast-gxh.1`, `ast-a05.1`.
    if let Some(endpoints) = built {
        router = router
            .route(
                Endpoint::PushedAuthorizationRequest.path(),
                post(pushed_authorization_request).with_state(Arc::clone(&endpoints)),
            )
            .route(
                Endpoint::Token.path(),
                post(token_endpoint).with_state(Arc::clone(&endpoints)),
            )
            // RFC 7009 §2.1: `POST` only, form-encoded, client-authenticated.
            // No DPoP check: nothing is issued here, so there is no key to
            // bind anything to — the client authentication is what says whose
            // token this is.
            .route(
                Endpoint::Revocation.path(),
                post(revocation_endpoint).with_state(Arc::clone(&endpoints)),
            )
            // OIDC Core §3.1.2.1 permits GET and POST at the authorization
            // endpoint, and RFC 9126 §4 says what they carry: `client_id` and
            // `request_uri`, nothing else that matters.
            .route(
                Endpoint::Authorization.path(),
                get(authorization_endpoint)
                    .post(authorization_endpoint_form)
                    .with_state(Arc::clone(&endpoints)),
            )
            // The interaction pages. Deliberately not in the endpoint
            // registry: they are not part of the protocol surface a client
            // discovers, they are this server's own user interface, and
            // advertising them would invite a client to link straight into
            // one.
            // OIDC Core §5.3.1 permits GET and POST. Neither carries a body
            // this endpoint reads: FAPI 2.0 SP §5.3.4 accepts the access token
            // in the header only, so a form-encoded `access_token` is not a
            // credential here any more than a query parameter is.
            .route(
                Endpoint::UserInfo.path(),
                get(userinfo_endpoint)
                    .post(userinfo_endpoint)
                    .with_state(Arc::clone(&endpoints)),
            )
            // RFC 7591. No DPoP check: there is no client authentication at
            // this endpoint and no client yet to bind a proof to.
            .route(
                Endpoint::Registration.path(),
                post(client_registration).with_state(Arc::clone(&endpoints)),
            )
            // RFC 7592. The URL `POST /register` hands back in
            // `registration_client_uri`, built from the same registry so the
            // two cannot drift. No DPoP check: the credential is the
            // registration access token and there is no client authentication
            // to bind a proof to.
            .route(
                &client_configuration::path(),
                get(client_configuration_read)
                    .put(client_configuration_update)
                    .delete(client_configuration_remove)
                    .with_state(Arc::clone(&endpoints)),
            )
            // OIDC RP-Initiated Logout 1.0 §2: both verbs, same parameters.
            // The GET is what a link in a relying party's user interface is,
            // and the POST is both a form-encoded request and the answer to
            // this server's own confirmation page.
            .route(
                Endpoint::EndSession.path(),
                get(end_session)
                    .post(end_session_form)
                    .with_state(Arc::clone(&endpoints)),
            )
            .route(
                "/interaction/{id}",
                get(interaction_show)
                    .post(interaction_submit)
                    .with_state(Arc::clone(&endpoints)),
            )
            // Passkey enrolment (`ast-2vk.15`). Not in the endpoint registry,
            // for the same reason the interaction pages are not: this is the
            // server's own user interface, reached with a session cookie, and
            // a client has no business linking into it.
            .route(
                passkeys::PAGE_PATH,
                get(passkey_page).with_state(Arc::clone(&endpoints)),
            )
            .route(
                passkeys::OPTIONS_PATH,
                post(passkey_options).with_state(Arc::clone(&endpoints)),
            )
            .route(
                passkeys::FINISH_PATH,
                post(passkey_finish).with_state(Arc::clone(&endpoints)),
            )
            // Passkey authentication (`ast-2vk.4`). Under the interaction
            // rather than under `/passkeys`, because that is what these are
            // bound to: there is no session yet, and the interaction id in the
            // path — matched against the one in the cookie — is what says two
            // requests came from the same visitor.
            .route(
                passkeys::LOGIN_OPTIONS_PATH,
                post(passkey_login_options).with_state(Arc::clone(&endpoints)),
            )
            .route(
                passkeys::LOGIN_FINISH_PATH,
                post(passkey_login_finish).with_state(endpoints),
            );
    }

    router = mount_the_unbuilt(router, capabilities, built_clients);

    // Outermost of this router's own layers, so it runs before any handler and
    // after the tenancy middleware has resolved the tenant.
    router.layer(axum::middleware::from_fn_with_state(
        guard,
        tenant_feature_guard,
    ))
}

/// Mounts a 501 at every enabled endpoint that has no handler yet.
///
/// From the registry, so that the parity test — and a client reading the
/// document — find a route rather than a 404. `built_clients` is whether the
/// deployment has the database wiring, because those endpoints are mounted for
/// real above and must not be shadowed by a constant answer here.
fn mount_the_unbuilt(
    mut router: Router,
    capabilities: Capabilities,
    built_clients: bool,
) -> Router {
    for endpoint in Endpoint::enabled(&capabilities) {
        if endpoint == Endpoint::Jwks
            || (built_clients
                && matches!(
                    endpoint,
                    Endpoint::PushedAuthorizationRequest
                        | Endpoint::Token
                        | Endpoint::Revocation
                        | Endpoint::Authorization
                        | Endpoint::Registration
                        | Endpoint::EndSession
                        | Endpoint::UserInfo
                ))
        {
            continue;
        }
        router = router.route(endpoint.path(), any(not_implemented));
    }
    router
}

/// The per-tenant half of the capability gate.
///
/// Holds the same two things the discovery handler reads, and nothing else:
/// what the deployment offers, and where a tenant's subtractions come from.
#[derive(Clone, Debug)]
struct FeatureGuard {
    /// What this deployment offers.
    capabilities: Capabilities,
    /// Each tenant's settings, or `None` where no tenant has any of its own —
    /// and then the deployment's flags are the whole answer and this guard has
    /// nothing to decide.
    tenant_settings: Option<SettingsDirectory>,
}

/// The endpoint a request path belongs to, when that endpoint is gated on a
/// feature.
///
/// Read off [`Endpoint::ALL`] rather than from a list kept here: a new gated
/// endpoint is guarded the moment it is registered, which is the property
/// `ast-o0t.3` bought and this must not spend. Endpoints with no
/// [`Endpoint::required_feature`] are `None` — there is nothing a tenant could
/// switch off — and so are this server's own pages, which are not in the
/// registry at all.
fn gated_endpoint(path: &str) -> Option<Endpoint> {
    Endpoint::ALL.into_iter().find(|endpoint| {
        endpoint.required_feature().is_some()
            && path
                .strip_prefix(endpoint.path())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// Refuses a request for a feature this tenant switched off.
///
/// The refusal is a **404**, the same status a request gets when the
/// *deployment* does not run the feature: the tenant's document does not name
/// the URL, so as far as this tenant is concerned the endpoint does not exist,
/// and answering 501 or 403 would confirm to a client that knows the URL that
/// there is something behind it. A tenant that never switched anything off
/// sees no change.
///
/// A settings read that fails answers 503, exactly as [`discovery`] does and
/// for the same reason: falling back to the deployment's capabilities would
/// reopen the endpoint an operator has just closed.
async fn tenant_feature_guard(
    State(guard): State<FeatureGuard>,
    tenant: Option<Extension<Arc<Tenant>>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Some(directory) = guard.tenant_settings.as_ref() else {
        return next.run(request).await;
    };
    let Some(endpoint) = gated_endpoint(request.uri().path()) else {
        return next.run(request).await;
    };

    // The tenancy middleware runs outside this router, so a gated path with no
    // resolved tenant is a wiring fault rather than a request. Refusing beats
    // guessing which tenant's flags to apply.
    let Some(Extension(tenant)) = tenant else {
        tracing::error!(path = %request.uri().path(), "no tenant on a tenant-gated route");
        return unavailable();
    };

    let capabilities = match directory.for_tenant(&tenant.id).await {
        Ok(settings) => settings.effective_capabilities(guard.capabilities),
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };

    if endpoint.is_enabled(&capabilities) {
        next.run(request).await
    } else {
        crate::http::server::not_found().await.into_response()
    }
}

/// The 503 every settings-read failure answers with.
///
/// RFC 6749 §5.2 has no code for "come back later" and OAuth 2.0's
/// `temporarily_unavailable` (§4.1.2.1) is the closest the family has: the
/// request was well-formed and this server is at fault, so a client is told to
/// retry rather than to stop.
fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"error":"temporarily_unavailable"}"#,
    )
        .into_response()
}

/// `GET /.well-known/openid-configuration` and
/// `GET /.well-known/oauth-authorization-server`.
///
/// RFC 8414 §5: the OAuth and OpenID documents are compatible, and this serves
/// the same bytes at both locations. Two documents would be two things to keep
/// in step, and the one that is read less often would be the one that rots.
async fn discovery(
    State(state): State<ProtocolState>,
    Extension(tenant): Extension<Arc<Tenant>>,
) -> Response {
    // A tenant may switch a deployment feature *off*, never on
    // (`asterius_domain::TenantSettings`), so this can only ever narrow what
    // the document advertises — and it is read through a cache the admin API
    // drops on write, which is what makes a flag change visible to the next
    // request rather than to the one five minutes later (`ast-f7m.4`).
    let capabilities = match &state.tenant_settings {
        None => state.capabilities,
        Some(directory) => match directory.for_tenant(&tenant.id).await {
            Ok(settings) => settings.effective_capabilities(state.capabilities),
            // Fails closed: advertising the deployment's capabilities here
            // would republish exactly the features a tenant switched off.
            Err(error) => {
                tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
                return unavailable();
            }
        },
    };

    let document = metadata::provider_metadata(&tenant.issuer, &capabilities);
    cacheable_json(&document, METADATA_MAX_AGE)
}

/// `GET /jwks`.
///
/// OIDC Discovery §3 and OIDC Core §10.1.1. Serves the public half of every
/// published key — pending, active and retiring — because a verifier needs the
/// new key before it is used and the old one after it stops being used.
async fn jwks(
    State(state): State<ProtocolState>,
    Extension(tenant): Extension<Arc<Tenant>>,
) -> Response {
    let keys = match state.keys.published_keys(&tenant.id).await {
        Ok(keys) => keys,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the key set");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"error":"temporarily_unavailable"}"#,
            )
                .into_response();
        }
    };

    let document = json!({
        "keys": keys.into_iter().map(|key| key.public_jwk).collect::<Vec<Value>>(),
    });
    cacheable_json(&document, JWKS_MAX_AGE)
}

/// `POST /par` — RFC 9126.
///
/// The wiring only. Everything that decides anything lives in
/// [`crate::http::par::push`], which is where the tests are: this function's
/// whole job is to turn a request into that call, with the tenant's
/// repositories and a closure that authenticates.
async fn pushed_authorization_request(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    // `Option`, because the extension is the tenancy layer's doing: a request
    // that arrived without it is a wiring fault, and a limiter with no address
    // still holds the client bucket rather than answering 500.
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    let limits = endpoint_limits(
        &endpoints,
        &tenant,
        &limiter,
        client.as_deref(),
        time::OffsetDateTime::now_utc(),
    );
    let claimed = crate::http::limits::claimed_client_id(&body);
    crate::http::limits::guard(
        &limits,
        asterius_domain::LimitedEndpoint::PushedAuthorizationRequest,
        claimed.as_deref(),
        async || pushed_authorization_request_inner(&endpoints, &tenant, &headers, &body).await,
    )
    .await
}

/// The push itself, once the limiter has admitted it.
async fn pushed_authorization_request_inner(
    endpoints: &ClientEndpoints,
    tenant: &Arc<Tenant>,
    headers: &axum::http::HeaderMap,
    body: &axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    let requests = scope.auth_requests();

    // RFC 9449 §10.1: a pushed request may carry a proof as well as the
    // `dpop_jkt` parameter. Checked before the body is looked at, because a
    // proof that does not verify makes the rest of the request moot.
    let now = time::OffsetDateTime::now_utc();
    let binding = match endpoints
        .dpop
        .check(
            tenant,
            Endpoint::PushedAuthorizationRequest,
            &axum::http::Method::POST,
            headers,
            now,
        )
        .await
    {
        Ok(binding) => binding,
        Err(refusal) => return refusal.into_response(),
    };

    let authenticator = Arc::clone(&endpoints.authenticator);
    let tenant_for_auth = Arc::clone(tenant);
    let clients_for_auth = scope.clients(endpoints.capabilities);

    par::push(
        PushContext {
            tenant,
            clients: &clients,
            requests: &requests,
            keys: endpoints.keys.as_ref(),
            policy: authorization_policy(),
            lifetime: endpoints.par_lifetime,
        },
        headers,
        body,
        async |attempt: &Attempt<'_>, rules: &AssertionRules| {
            authenticator
                .authenticate(&tenant_for_auth, &clients_for_auth, attempt, rules, now)
                .await
        },
        binding.as_ref().map(|b| &b.jkt),
        now,
    )
    .await
}

/// `GET`/`POST /userinfo` — OIDC Core §5.3.
///
/// Wiring only. Everything that decides anything is in
/// [`crate::http::userinfo::userinfo`], which is where the tests are.
///
/// The query string is handed over rather than parsed, because the only thing
/// this endpoint does with it is refuse a request that put a credential there
/// (FAPI 2.0 SP §5.3.4).
async fn userinfo_endpoint(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Response {
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    let limits = endpoint_limits(
        &endpoints,
        &tenant,
        &limiter,
        client.as_deref(),
        time::OffsetDateTime::now_utc(),
    );
    // The address bucket alone. The caller is a resource server presenting an
    // access token, and the client it belongs to is inside a token this code
    // has not verified yet — reading a bucket key out of it would be trusting
    // a string the caller wrote. The limit is correspondingly the most
    // generous of the five, because one address here is legitimately a fleet
    // of resource servers rather than one browser.
    crate::http::limits::guard(
        &limits,
        asterius_domain::LimitedEndpoint::UserInfo,
        None,
        async || userinfo_endpoint_inner(&endpoints, &tenant, &method, &uri, &headers).await,
    )
    .await
}

/// The UserInfo response itself, once the limiter has admitted the request.
async fn userinfo_endpoint_inner(
    endpoints: &ClientEndpoints,
    tenant: &Arc<Tenant>,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    headers: &axum::http::HeaderMap,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let source = StoredClaims {
        grants: scope.grants(),
        // The KEK is the same one every other user read takes: the claim bag
        // is encrypted at rest.
        users: scope.users(Arc::clone(&endpoints.kek)),
    };

    userinfo::userinfo(
        userinfo::UserInfoContext {
            tenant,
            source: &source,
            keys: endpoints.keys.as_ref(),
            signer: endpoints.signer.as_ref(),
            dpop: endpoints.dpop.as_ref(),
            // OIDC Core §5.3.2's default. `userinfo_signed_response_alg` is
            // not a registrable client metadata member yet, and inventing a
            // per-deployment default would sign responses no client asked to
            // be signed.
            signed_response_alg: None,
            now: time::OffsetDateTime::now_utc(),
        },
        method,
        headers,
        uri.query(),
    )
    .await
}

/// `POST /revoke` — RFC 7009 §2.
///
/// Wiring only, like the token endpoint: everything that decides anything is
/// in [`crate::http::revocation::revoke`], and the client is authenticated by
/// the same closure the token endpoint passes — one authenticator, so there is
/// no second opinion about who a caller is (RFC 7009 §2.1).
///
/// No per-endpoint limiter yet: `asterius_domain::LimitedEndpoint` covers the
/// five endpoints that were built when `ast-p2l.3` landed, and adding a sixth
/// is a change to the configuration surface rather than to this file.
async fn revocation_endpoint(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    let store = StoredTokens {
        grants: scope.grants(),
        refresh_tokens: scope.refresh_tokens(),
    };

    let now = time::OffsetDateTime::now_utc();
    let authenticator = Arc::clone(&endpoints.authenticator);
    let tenant_for_auth = Arc::clone(&tenant);
    let clients_for_auth = scope.clients(endpoints.capabilities);

    revocation::revoke(
        revocation::RevocationContext {
            tenant: &tenant,
            clients: &clients,
            store: &store,
            keys: endpoints.keys.as_ref(),
            audit: endpoints.audit.as_ref(),
            now,
        },
        &headers,
        &body,
        async |attempt: &Attempt<'_>, rules: &AssertionRules| {
            authenticator
                .authenticate(&tenant_for_auth, &clients_for_auth, attempt, rules, now)
                .await
        },
    )
    .await
}

/// The two writes a revocation makes.
///
/// Narrow on purpose, like [`StoredClaims`]: RFC 7009 revokes credentials and
/// leaves the grant standing (Grant Management ID1 §6.5 Note), and an endpoint
/// holding `PgGrantRepository::revoke` is one edit away from doing otherwise.
#[derive(Debug)]
struct StoredTokens {
    grants: asterius_store_pg::PgGrantRepository,
    refresh_tokens: asterius_store_pg::PgRefreshTokenRepository,
}

#[async_trait::async_trait]
impl revocation::RevocationStore for StoredTokens {
    async fn revoke_refresh_token(
        &self,
        digest: &str,
        client: &asterius_domain::ClientId,
        now: time::OffsetDateTime,
    ) -> Result<Option<asterius_domain::GrantId>, asterius_domain::DomainError> {
        self.refresh_tokens.revoke(digest, client, now).await
    }

    async fn denylist_access_token(
        &self,
        jti: &str,
        grant: Option<&asterius_domain::GrantId>,
        revoked_at: time::OffsetDateTime,
        expires_at: time::OffsetDateTime,
    ) -> Result<bool, asterius_domain::DomainError> {
        self.grants
            .denylist_access_token(jti, grant, revoked_at, expires_at)
            .await
    }
}

/// The stored rows behind UserInfo.
///
/// Reads only, and exactly three of them. The port is narrow so that this
/// endpoint cannot reach `revoke` or `claim` through the repository it happens
/// to hold.
#[derive(Debug)]
struct StoredClaims {
    grants: asterius_store_pg::PgGrantRepository,
    users: asterius_store_pg::PgUserRepository,
}

#[async_trait::async_trait]
impl userinfo::UserInfoSource for StoredClaims {
    async fn grant(
        &self,
        id: &asterius_domain::GrantId,
    ) -> Result<Option<asterius_domain::Grant>, asterius_domain::DomainError> {
        self.grants.find(id).await
    }

    async fn user(
        &self,
        id: asterius_domain::UserId,
    ) -> Result<Option<asterius_domain::User>, asterius_domain::DomainError> {
        self.users.find(id).await
    }

    async fn is_denylisted(&self, jti: &str) -> Result<bool, asterius_domain::DomainError> {
        self.grants.is_denylisted(jti).await
    }
}

/// `POST /token` — RFC 6749 §3.2.
///
/// Wiring only, like the PAR handler: everything that decides anything is in
/// [`crate::http::token::token`].
///
/// No grant handlers are registered yet, so every dispatched grant answers
/// 501. `ast-a05.2` and its siblings add them without touching this function.
async fn token_endpoint(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    let limits = endpoint_limits(
        &endpoints,
        &tenant,
        &limiter,
        client.as_deref(),
        time::OffsetDateTime::now_utc(),
    );
    let claimed = crate::http::limits::claimed_client_id(&body);
    crate::http::limits::guard(
        &limits,
        asterius_domain::LimitedEndpoint::Token,
        claimed.as_deref(),
        async || token_endpoint_inner(&endpoints, &tenant, &headers, &body).await,
    )
    .await
}

/// The token request itself, once the limiter has admitted it.
async fn token_endpoint_inner(
    endpoints: &ClientEndpoints,
    tenant: &Arc<Tenant>,
    headers: &axum::http::HeaderMap,
    body: &axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);

    let now = time::OffsetDateTime::now_utc();
    let binding = match endpoints
        .dpop
        .check(
            tenant,
            Endpoint::Token,
            &axum::http::Method::POST,
            headers,
            now,
        )
        .await
    {
        Ok(binding) => binding,
        Err(refusal) => return refusal.into_response(),
    };

    let authenticator = Arc::clone(&endpoints.authenticator);
    let tenant_for_auth = Arc::clone(tenant);
    let clients_for_auth = scope.clients(endpoints.capabilities);

    // The grant handler is built here, per request, rather than held on
    // `ClientEndpoints`. Two of the things it needs are facts about *this*
    // request — the instant it arrived and the DPoP key it proved — and
    // `GrantHandler::handle` receives neither. PAR solved the same problem the
    // same way, by computing the proof key at the edge and handing it down.
    let codes = scope.codes();
    let grants = scope.grants();
    let refresh_tokens = scope.refresh_tokens();
    let sessions = scope.sessions();
    // Read only, to project the claims the grant covers into the ID token
    // (OIDC Core §5.4, §5.5). The KEK is the same one every other user read
    // takes, because the claim bag is encrypted at rest.
    let users = scope.users(Arc::clone(&endpoints.kek));
    // One read for both grants, so that whichever this request turns out to be
    // it mints under the same numbers — the same argument `now` and the proof
    // key are resolved once, just above.
    let lifetimes = match lifetimes_for(endpoints, tenant).await {
        Ok(lifetimes) => lifetimes,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };
    let authorization_code = AuthorizationCode {
        codes: &codes,
        grants: &grants,
        refresh_tokens: &refresh_tokens,
        sessions: &sessions,
        users: &users,
        signer: endpoints.signer.as_ref(),
        lifetimes,
        proof_key: binding.as_ref().map(|binding| &binding.jkt),
        now,
    };
    // The same repositories, and deliberately the same `now` and proof key:
    // whichever grant the request turns out to be, it is judged against one
    // clock reading and one proven key.
    let refresh_token = RefreshToken {
        tokens: &refresh_tokens,
        grants: &grants,
        sessions: &sessions,
        users: &users,
        signer: endpoints.signer.as_ref(),
        audit: endpoints.audit.as_ref(),
        lifetimes,
        proof_key: binding.as_ref().map(|binding| &binding.jkt),
        now,
    };

    let mut response = token::token(
        TokenContext {
            tenant,
            clients: &clients,
            capabilities: endpoints.capabilities,
            grants: &[&authorization_code, &refresh_token],
        },
        headers,
        body,
        async |attempt: &Attempt<'_>, rules: &AssertionRules| {
            authenticator
                .authenticate(&tenant_for_auth, &clients_for_auth, attempt, rules, now)
                .await
        },
    )
    .await;

    // RFC 9449 §8.2: hand the client the next nonce on a successful response,
    // so a well-behaved one sees the `use_dpop_nonce` refusal exactly once
    // rather than on every request.
    if let Some(binding) = &binding {
        DpopEndpoint::supply_nonce(&mut response, binding);
    }
    response
}

/// `POST /register` — RFC 7591 §3.
async fn client_registration(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    let limits = endpoint_limits(
        &endpoints,
        &tenant,
        &limiter,
        client.as_deref(),
        time::OffsetDateTime::now_utc(),
    );
    // No client bucket: RFC 7591 §3 is where a client comes from, so there is
    // no authenticated client to charge and the address holds it alone. This
    // is the endpoint an unauthenticated caller reaches most easily, which is
    // why its address limit is the tightest of the five.
    crate::http::limits::guard(
        &limits,
        asterius_domain::LimitedEndpoint::Registration,
        None,
        async || client_registration_inner(&endpoints, &tenant, &request_id, &headers, &body).await,
    )
    .await
}

/// The registration itself, once the limiter has admitted it.
async fn client_registration_inner(
    endpoints: &ClientEndpoints,
    tenant: &Arc<Tenant>,
    request_id: &crate::http::request_id::RequestId,
    headers: &axum::http::HeaderMap,
    body: &axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    register::register(
        RegisterContext {
            tenant,
            clients: &clients,
            keys: endpoints.keys.as_ref(),
            capabilities: endpoints.capabilities,
            outbound: endpoints.outbound.as_ref(),
            policy: &endpoints.registration,
            audit: endpoints.audit.as_ref(),
            request_id: Some(request_id.as_str()),
        },
        headers,
        body,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// Builds the context the three RFC 7592 handlers share.
fn configuration_context<'a>(
    endpoints: &'a ClientEndpoints,
    tenant: &'a Tenant,
    clients: &'a asterius_store_pg::PgClientRepository,
    request_id: &'a crate::http::request_id::RequestId,
) -> ConfigurationContext<'a> {
    ConfigurationContext {
        tenant,
        clients,
        configuration: clients,
        keys: endpoints.keys.as_ref(),
        capabilities: endpoints.capabilities,
        outbound: endpoints.outbound.as_ref(),
        audit: endpoints.audit.as_ref(),
        request_id: Some(request_id.as_str()),
    }
}

/// `GET /register/{client_id}` — RFC 7592 §2.1.
async fn client_configuration_read(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    Path(client_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    let limits = endpoint_limits(
        &endpoints,
        &tenant,
        &limiter,
        client.as_deref(),
        time::OffsetDateTime::now_utc(),
    );
    // The address bucket alone, deliberately. The `client_id` here is a path
    // segment anybody can write, and the credential is the registration access
    // token; charging a bucket named by the path would let a caller spend a
    // registration's budget by guessing at its id, which is exactly the
    // guessing this limit is meant to bound (`ast-m9c.11`).
    crate::http::limits::guard(
        &limits,
        asterius_domain::LimitedEndpoint::ClientConfiguration,
        None,
        async || {
            let scope = endpoints.store.scope(tenant.id.clone());
            let clients = scope.clients(endpoints.capabilities);
            client_configuration::read(
                &configuration_context(&endpoints, &tenant, &clients, &request_id),
                &client_id,
                &headers,
                time::OffsetDateTime::now_utc(),
            )
            .await
        },
    )
    .await
}

/// `PUT /register/{client_id}` — RFC 7592 §2.2.
async fn client_configuration_update(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    Path(client_id): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    let limits = endpoint_limits(
        &endpoints,
        &tenant,
        &limiter,
        client.as_deref(),
        time::OffsetDateTime::now_utc(),
    );
    crate::http::limits::guard(
        &limits,
        asterius_domain::LimitedEndpoint::ClientConfiguration,
        None,
        async || {
            let scope = endpoints.store.scope(tenant.id.clone());
            let clients = scope.clients(endpoints.capabilities);
            client_configuration::update(
                &configuration_context(&endpoints, &tenant, &clients, &request_id),
                &client_id,
                &headers,
                &body,
                time::OffsetDateTime::now_utc(),
            )
            .await
        },
    )
    .await
}

/// `DELETE /register/{client_id}` — RFC 7592 §2.3.
async fn client_configuration_remove(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    Path(client_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    let limits = endpoint_limits(
        &endpoints,
        &tenant,
        &limiter,
        client.as_deref(),
        time::OffsetDateTime::now_utc(),
    );
    crate::http::limits::guard(
        &limits,
        asterius_domain::LimitedEndpoint::ClientConfiguration,
        None,
        async || {
            let scope = endpoints.store.scope(tenant.id.clone());
            let clients = scope.clients(endpoints.capabilities);
            client_configuration::remove(
                &configuration_context(&endpoints, &tenant, &clients, &request_id),
                &client_id,
                &headers,
                time::OffsetDateTime::now_utc(),
            )
            .await
        },
    )
    .await
}

/// `GET /authorize` — RFC 9126 §4.
async fn authorization_endpoint(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    run_authorize(
        &endpoints,
        &tenant,
        &nonce,
        mount_of(mount),
        &headers,
        &pairs,
    )
    .await
}

/// `POST /authorize` — the same request, form-encoded.
async fn authorization_endpoint_form(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(&body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    run_authorize(
        &endpoints,
        &tenant,
        &nonce,
        mount_of(mount),
        &headers,
        &pairs,
    )
    .await
}

/// The prefix the tenancy layer removed from this request, or the root.
///
/// `Option`, like the client address next to it: the extension is that
/// layer's doing, and a request that reached a handler without it was routed
/// at the root, which is exactly what the root prefix describes.
fn mount_of(mount: Option<Extension<MountPrefix>>) -> MountPrefix {
    mount.map_or_else(MountPrefix::root, |Extension(prefix)| prefix)
}

/// The half both verbs share.
///
/// The session comes from the cookie the browser sent, and it is resolved here
/// rather than in the handler because "usable" is a question for the session
/// repository and the clock. A cookie naming a session that is expired, idle or
/// revoked is the same as no cookie at all (`ast-gxh.8`).
async fn run_authorize(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    nonce: &asterius_web::csp::Nonce,
    mount: MountPrefix,
    headers: &axum::http::HeaderMap,
    pairs: &[(String, String)],
) -> Response {
    let now = time::OffsetDateTime::now_utc();
    let scope = endpoints.store.scope(tenant.id.clone());
    let requests = scope.auth_requests();
    let sessions = scope.sessions();
    let clients = scope.clients(endpoints.capabilities);
    let subjects = scope.users(std::sync::Arc::clone(&endpoints.kek));

    // Every `cookie` field, not just the first (ast-bze).
    let cookies = crate::http::cookies(headers);
    let session = match asterius_web::interaction::cookie_value(
        &cookies,
        asterius_domain::entities::session::COOKIE_NAME,
    ) {
        Some(presented) => {
            let digest = asterius_domain::sha256_hex(presented.as_bytes());
            match asterius_domain::SessionRepository::find(&sessions, &digest).await {
                Ok(session) => session,
                Err(error) => {
                    // Not fatal: a request whose session cannot be read is one
                    // with no session, and the user meets a sign-in page rather
                    // than an error. Deciding otherwise would take the store's
                    // availability and make it the availability of every
                    // authorization.
                    tracing::error!(%error, tenant = %tenant.id, "cannot read a session at /authorize");
                    None
                }
            }
        }
        None => None,
    };

    authorize::authorize(
        AuthorizeContext {
            tenant,
            requests: &requests,
            interactions: &requests,
            session: session.as_ref(),
            grants: &scope.grants(),
            policy: decision_policy(),
            memory: memory_policy(),
            nonce,
            mount,
        },
        pairs,
        // OIDC Core §8.1: the `sub` this client sees, which is the identifier an
        // `id_token_hint` from this client would have named. Resolved only when
        // there is a hint to compare against.
        async |client: &asterius_domain::ClientId, user: uuid::Uuid| {
            let found = clients.find(client).await.ok()??;
            let sector = asterius_domain::SectorIdentifier::of_client(&found).ok()?;
            subjects
                .subject(asterius_domain::UserId::new(user), &sector)
                .await
                .ok()
                .map(|subject| subject.as_str().to_owned())
        },
        now,
    )
    .await
}

/// What this deployment does without being asked, at the authorization
/// endpoint.
///
/// No account chooser: this server keeps one session per browser, so there is
/// nothing to choose between, and a `prompt=none` request naming another
/// subject is `login_required` rather than `account_selection_required`. The
/// day a chooser exists this is the line that changes.
const fn decision_policy() -> asterius_oidc::decision::DecisionPolicy {
    asterius_oidc::decision::DecisionPolicy::new(false)
}

/// Whether this deployment remembers a consent it has already been given.
///
/// It does. A server that asks the same question every morning trains the
/// person to answer it without reading it, which is the consent failure FAPI
/// 2.0 SP §7 names, and OIDC Core §3.1.2.1's `prompt=none` cannot succeed at
/// all without a memory to consult. The "always ask" tenant switch is the
/// argument to this constructor and per-tenant settings are `ast-f7m.4`; the
/// `offline_access` window keeps
/// `asterius_oidc::consent_memory::DEFAULT_OFFLINE_ACCESS_MEMORY`, which is a
/// decision with a reason written down beside it rather than a default nobody
/// chose.
const fn memory_policy() -> asterius_oidc::consent_memory::MemoryPolicy {
    asterius_oidc::consent_memory::MemoryPolicy::new(false)
}

/// What this deployment offers an authorization request, in one place.
///
/// One function rather than a literal at each call site, because the push and
/// the discovery document must agree: a tenant that advertises a `prompt` value
/// its validator refuses has told clients to send something it will reject.
///
/// `prompt=create` is off. OpenID Connect Prompt Create 1.0 §3 sends the user
/// to a registration screen, and this server has none — `ast-2vk.5` and the
/// enrolment story own that — so the honest answer is the default one. When a
/// tenant grows self-service registration this is the line that changes, and
/// `prompt_values_supported` follows it without being edited.
const fn authorization_policy() -> asterius_oidc::authorize::AuthorizationPolicy {
    asterius_oidc::authorize::AuthorizationPolicy::new(false)
}

/// The lifetimes this request issues under (`ast-5c6`).
///
/// The tenant's, when a settings repository is wired; the deployment's
/// otherwise. There is no third source and no clamp on the way out: a
/// [`TokenLifetimes`] cannot be built above the profile's ceilings, so a value
/// that arrives here is already compliant and issuance can use it as it stands.
///
/// A read that *fails* is not the fallback, for the reason
/// [`crate::tenant_settings`] gives about feature flags and which applies at
/// least as strongly here: quietly issuing under this build's numbers would
/// hand out a credential that lives longer than the operator configured, and
/// nothing would say so. The caller answers 503 and the client retries.
///
/// # Errors
///
/// Whatever the settings repository returns, including a stored document this
/// build refuses to read.
async fn lifetimes_for(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
) -> Result<TokenLifetimes, DomainError> {
    match &endpoints.tenant_settings {
        None => Ok(endpoints.lifetimes),
        Some(directory) => Ok(directory.for_tenant(&tenant.id).await?.lifetimes()),
    }
}

/// Builds the context both end-session handlers share.
fn logout_context<'a>(
    endpoints: &'a ClientEndpoints,
    tenant: &'a Tenant,
    sessions: &'a asterius_store_pg::PgSessionRepository,
    clients: &'a asterius_store_pg::PgClientRepository,
    nonce: &'a asterius_web::csp::Nonce,
    request_id: &'a crate::http::request_id::RequestId,
) -> logout::LogoutContext<'a> {
    logout::LogoutContext {
        tenant,
        sessions,
        clients,
        keys: endpoints.keys.as_ref(),
        audit: endpoints.audit.as_ref(),
        nonce,
        request_id: Some(request_id.as_str()),
    }
}

/// `GET /logout` — OIDC RP-Initiated Logout 1.0 §2.
async fn end_session(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    headers: axum::http::HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    let scope = endpoints.store.scope(tenant.id.clone());
    let sessions = scope.sessions();
    let clients = scope.clients(endpoints.capabilities);
    logout::show(
        logout_context(
            &endpoints,
            &tenant,
            &sessions,
            &clients,
            &nonce,
            &request_id,
        ),
        &headers,
        &pairs,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `POST /logout` — the same request, form-encoded, and the confirmation
/// page's answer.
async fn end_session_form(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(&body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let scope = endpoints.store.scope(tenant.id.clone());
    let sessions = scope.sessions();
    let clients = scope.clients(endpoints.capabilities);
    logout::submit(
        logout_context(
            &endpoints,
            &tenant,
            &sessions,
            &clients,
            &nonce,
            &request_id,
        ),
        &headers,
        &pairs,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `GET /interaction/{id}`.
async fn interaction_show(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Path(id): Path<String>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let requests = scope.auth_requests();
    let sessions = scope.sessions();
    let clients = scope.clients(endpoints.capabilities);
    let grants = scope.grants();
    let codes = scope.codes();
    let users = scope.users(Arc::clone(&endpoints.kek));
    let passwords = endpoints.passwords(&tenant.id);
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    let lifetimes = match lifetimes_for(&endpoints, &tenant).await {
        Ok(lifetimes) => lifetimes,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };
    interaction::show(
        InteractionContext {
            tenant: &tenant,
            requests: &requests,
            credentials: passwords
                .as_ref()
                .map(|v| v as &dyn asterius_domain::CredentialVerifier),
            sessions: &sessions,
            lifetimes: endpoints.session_lifetimes,
            // `ast-2vk.8` resolves a display name; until then the consent
            // screen names the signed-in user only when the session carries
            // one.
            username: None,
            clients: &clients,
            grants: &grants,
            memory: memory_policy(),
            codes: &codes,
            subjects: &users,
            code_lifetime: lifetimes.authorization_code(),
            nonce: &nonce,
            throttle: throttle(&endpoints, &limiter, client.as_deref()),
            audit: endpoints.audit.as_ref(),
            mount: mount_of(mount),
        },
        &id,
        &headers,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `POST /interaction/{id}`.
//
// Eight extractors rather than seven. The lint guards call sites, and this
// function has none: axum builds every argument from the request, so the
// count costs a reader nothing and costs a caller nobody. The alternative —
// bundling `tenant` and `mount` behind one `FromRequestParts` — is worth
// doing when a third handler needs it, not for the second (`ast-295`).
#[allow(clippy::too_many_arguments)]
async fn interaction_submit(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Path(id): Path<String>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    // `Option`, because the extension is the tenancy layer's doing and a
    // request that reached here without it is a wiring fault rather than a
    // reason to answer 500. A limiter with no address still counts the
    // account bucket, which is the half that bounds guessing at one user.
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let requests = scope.auth_requests();
    let sessions = scope.sessions();
    let clients = scope.clients(endpoints.capabilities);
    let grants = scope.grants();
    let codes = scope.codes();
    let users = scope.users(Arc::clone(&endpoints.kek));
    let passwords = endpoints.passwords(&tenant.id);
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    let lifetimes = match lifetimes_for(&endpoints, &tenant).await {
        Ok(lifetimes) => lifetimes,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };
    interaction::submit(
        InteractionContext {
            tenant: &tenant,
            requests: &requests,
            credentials: passwords
                .as_ref()
                .map(|v| v as &dyn asterius_domain::CredentialVerifier),
            sessions: &sessions,
            lifetimes: endpoints.session_lifetimes,
            // `ast-2vk.8` resolves a display name; until then the consent
            // screen names the signed-in user only when the session carries
            // one.
            username: None,
            clients: &clients,
            grants: &grants,
            memory: memory_policy(),
            codes: &codes,
            subjects: &users,
            code_lifetime: lifetimes.authorization_code(),
            nonce: &nonce,
            throttle: throttle(&endpoints, &limiter, client.as_deref()),
            audit: endpoints.audit.as_ref(),
            mount: mount_of(mount),
        },
        &id,
        &headers,
        &body,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// The per-endpoint limiter for one request (`ast-p2l.3`).
///
/// Built per request because the client address is part of it, exactly like
/// [`throttle`], and over the same store: one table, one mechanism, two sets
/// of buckets.
fn endpoint_limits<'a>(
    endpoints: &'a ClientEndpoints,
    tenant: &'a Tenant,
    limiter: &'a asterius_store_pg::PgRateLimitStore,
    client: Option<&crate::http::forwarded::ClientAddr>,
    now: time::OffsetDateTime,
) -> crate::http::limits::LimitContext<'a> {
    crate::http::limits::LimitContext {
        tenant: &tenant.id,
        throttle: crate::http::limits::EndpointThrottle::new(
            limiter,
            endpoints.endpoint_limits,
            client.map(|client| client.ip),
        ),
        audit: endpoints.audit.as_ref(),
        now,
    }
}

/// The login limiter for one request.
///
/// Built per request because the client address is part of it. The store
/// behind it is a handle to the shared pool, so this costs an `Arc` clone.
fn throttle<'a>(
    endpoints: &ClientEndpoints,
    limiter: &'a asterius_store_pg::PgRateLimitStore,
    client: Option<&crate::http::forwarded::ClientAddr>,
) -> crate::http::throttle::LoginThrottle<'a> {
    crate::http::throttle::LoginThrottle::new(
        limiter,
        endpoints.login_limits,
        client.map(|client| client.ip),
    )
}

/// Builds the context the three passkey routes share.
///
/// One helper because the three differ only in what they do with it, and three
/// copies of a five-field literal is three places for one of them to drift.
fn passkey_context<'a>(
    endpoints: &'a ClientEndpoints,
    tenant: &'a Tenant,
    passkeys: &'a asterius_store_pg::PgPasskeyRepository,
    sessions: &'a asterius_store_pg::PgSessionRepository,
    users: &'a asterius_store_pg::PgUserRepository,
    nonce: &'a asterius_web::csp::Nonce,
    mount: MountPrefix,
) -> PasskeyContext<'a> {
    PasskeyContext {
        tenant,
        passkeys,
        sessions,
        users,
        nonce,
        audit: endpoints.audit.as_ref(),
        mount,
    }
}

/// `GET /passkeys`.
async fn passkey_page(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let passkeys = scope.passkeys();
    let sessions = scope.sessions();
    let users = scope.users(Arc::clone(&endpoints.kek));
    passkeys::page(
        passkey_context(
            &endpoints,
            &tenant,
            &passkeys,
            &sessions,
            &users,
            &nonce,
            mount_of(mount),
        ),
        &headers,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `POST /passkeys/options`.
async fn passkey_options(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let passkeys = scope.passkeys();
    let sessions = scope.sessions();
    let users = scope.users(Arc::clone(&endpoints.kek));
    passkeys::options(
        passkey_context(
            &endpoints,
            &tenant,
            &passkeys,
            &sessions,
            &users,
            &nonce,
            mount_of(mount),
        ),
        &headers,
        &body,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `POST /passkeys/finish`.
async fn passkey_finish(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let passkeys = scope.passkeys();
    let sessions = scope.sessions();
    let users = scope.users(Arc::clone(&endpoints.kek));
    passkeys::finish(
        passkey_context(
            &endpoints,
            &tenant,
            &passkeys,
            &sessions,
            &users,
            &nonce,
            mount_of(mount),
        ),
        &headers,
        &body,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `POST /interaction/{id}/passkey/options`.
async fn passkey_login_options(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Path(id): Path<String>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let passkeys = scope.passkeys();
    let requests = scope.auth_requests();
    let sessions = scope.sessions();
    let users = scope.users(Arc::clone(&endpoints.kek));
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    passkeys::login_options(
        PasskeyLoginContext {
            tenant: &tenant,
            passkeys: &passkeys,
            requests: &requests,
            sessions: &sessions,
            users: &users,
            lifetimes: endpoints.session_lifetimes,
            audit: endpoints.audit.as_ref(),
            throttle: throttle(&endpoints, &limiter, client.as_deref()),
        },
        &id,
        &headers,
        &body,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `POST /interaction/{id}/passkey/finish`.
async fn passkey_login_finish(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Path(id): Path<String>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let passkeys = scope.passkeys();
    let requests = scope.auth_requests();
    let sessions = scope.sessions();
    let users = scope.users(Arc::clone(&endpoints.kek));
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    passkeys::login_finish(
        PasskeyLoginContext {
            tenant: &tenant,
            passkeys: &passkeys,
            requests: &requests,
            sessions: &sessions,
            users: &users,
            lifetimes: endpoints.session_lifetimes,
            audit: endpoints.audit.as_ref(),
            throttle: throttle(&endpoints, &limiter, client.as_deref()),
        },
        &id,
        &headers,
        &body,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// An endpoint that is advertised but not yet built.
///
/// 501 rather than 404: the endpoint is part of this server's described shape,
/// and a 404 would tell a client it is looking in the wrong place when it is
/// not. The body is an OAuth-shaped error so a client's existing parsing works.
async fn not_implemented() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        [(header::CONTENT_TYPE, "application/json")],
        Json(json!({
            "error": "temporarily_unavailable",
            "error_description": "this endpoint is not implemented yet",
        })),
    )
        .into_response()
}

/// Serves JSON with a cache lifetime and a strong `ETag`.
///
/// The `ETag` is a digest of the body, so a client that revalidates gets a 304
/// whenever the document has not changed — which for metadata is almost always.
/// Deriving it from the bytes rather than from a version counter means it is
/// correct without anyone remembering to bump anything.
fn cacheable_json(document: &Value, max_age: u32) -> Response {
    let body = document.to_string();
    let etag = format!(
        "\"{}\"",
        hex::encode(&Sha256::digest(body.as_bytes())[..16])
    );

    let cache_control = HeaderValue::try_from(format!("public, max-age={max_age}"))
        .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=300"));
    let etag =
        HeaderValue::try_from(etag).unwrap_or_else(|_| HeaderValue::from_static("\"unavailable\""));

    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CACHE_CONTROL, cache_control),
            (header::ETAG, etag),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{Endpoint, gated_endpoint};
    use asterius_domain::LimitedEndpoint;

    /// The guard must recognise every endpoint a tenant can switch off, and
    /// only those: an endpoint it fails to recognise is one whose route stays
    /// open after the metadata stopped naming it, which is `ast-edc`.
    #[test]
    fn the_guard_recognises_exactly_the_gated_endpoints() {
        for endpoint in Endpoint::ALL {
            // Arrange
            let expected = endpoint.required_feature().map(|_| endpoint);

            // Act
            let found = gated_endpoint(endpoint.path());

            // Assert
            assert_eq!(found, expected, "{endpoint:?} at {}", endpoint.path());
        }
    }

    /// A path *under* a gated endpoint is that endpoint too — a resource id
    /// appended to `/grants` must not be the way round the guard — while a
    /// path that merely starts with the same letters is not.
    #[test]
    fn a_subpath_is_guarded_and_a_lookalike_is_not() {
        // Arrange
        let base = Endpoint::GrantManagement.path();

        // Act & Assert
        assert_eq!(
            gated_endpoint(&format!("{base}/abc")),
            Some(Endpoint::GrantManagement)
        );
        assert_eq!(gated_endpoint(&format!("{base}xyz")), None);
    }

    /// Every endpoint the domain says has limits must be handed to the
    /// limiter here, and every call must be at a route this file mounts.
    ///
    /// A source assertion rather than a request, because what can go wrong is
    /// an *omission*: somebody adds an endpoint to the registry, mounts it,
    /// and never wires the guard. No request against the endpoints that do
    /// exist would notice, which is precisely why the list is checked against
    /// the wiring rather than against a reviewer's memory (`ast-p2l.3`).
    #[test]
    fn every_limited_endpoint_is_wired_to_the_limiter() {
        // Arrange
        let source = include_str!("protocol.rs");

        for endpoint in LimitedEndpoint::ALL {
            // Act
            let variant = match endpoint {
                LimitedEndpoint::Registration => "LimitedEndpoint::Registration",
                LimitedEndpoint::ClientConfiguration => "LimitedEndpoint::ClientConfiguration",
                LimitedEndpoint::PushedAuthorizationRequest => {
                    "LimitedEndpoint::PushedAuthorizationRequest"
                }
                LimitedEndpoint::Token => "LimitedEndpoint::Token",
                LimitedEndpoint::UserInfo => "LimitedEndpoint::UserInfo",
            };

            // Assert
            assert!(
                source.contains(variant),
                "{endpoint} has limits but no handler passes it to `limits::guard`"
            );
        }
    }
}
