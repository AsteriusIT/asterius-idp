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
use crate::http::backchannel_authentication::{self, BackchannelContext};
use crate::http::client_configuration::{self, ConfigurationContext};
use crate::http::client_credentials::ClientCredentials;
use crate::http::device::{self, DeviceContext};
use crate::http::device_authorization::{self, DeviceAuthorizationContext};
use crate::http::device_code::DeviceCode;
use crate::http::dpop::DpopEndpoint;
use crate::http::grant_management;
use crate::http::interaction::{self, InteractionContext};
use crate::http::logout;
use crate::http::par::{self, PushContext};
use crate::http::passkeys::{self, PasskeyContext, PasskeyLoginContext};
use crate::http::recovery;
use crate::http::refresh::RefreshToken;
use crate::http::register::{self, RegisterContext, RegistrationPolicy};
use crate::http::revocation;
use crate::http::ssf::CONFIGURATION_PATH as SSF_STREAMS_PATH;
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
    /// read: see [`crate::tenant_settings`] and the private `lifetimes_for`.
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
    /// The per-tenant initial access tokens `POST /register` spends
    /// (`ast-cu3`).
    ///
    /// `None` is a deployment with no store wired, which is every test that
    /// only exercises the deployment's own gate. It is not a fallback: a
    /// tenant that has narrowed itself to `initial_access_token` registers
    /// nobody when this is absent, because the credentials it asked for cannot
    /// be read. See `register::admit`.
    pub initial_access_tokens: Option<Arc<dyn asterius_domain::ports::InitialAccessTokenStore>>,
    /// ADR-0006's one outbound path, for the URLs a registration document
    /// names. Shared with nothing else: the client key cache holds its own
    /// handle to the same adapter.
    pub outbound: Arc<dyn asterius_domain::ports::ClientUrlFetcher>,
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
    /// Where a back-channel logout token is queued (`ast-o4u.2`).
    ///
    /// The process's one outbox, as the port rather than the adapter, so the
    /// end-session handler stays testable without a database and this crate
    /// keeps one place where rows are written.
    ///
    /// `None` is a deployment with no outbox wired, which is every test that
    /// exercises the pages rather than the notification. It is not a fallback:
    /// with no queue there is nowhere to put a logout token, and
    /// `logout::notify_participants` says so in the log and notifies nobody
    /// rather than reporting a notification it did not make.
    ///
    /// Last in the struct, so a parallel change adding another member does not
    /// have to be reconciled line by line.
    pub outbox: Option<Arc<dyn asterius_domain::outbox::OutboxQueue>>,
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
/// tenant is only known per request. The private `tenant_feature_guard` is that second
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
        // SSF 1.0 §7.2 (`ast-0ju.1`). Mounted whatever the deployment's flags
        // say and gated inside the handler; see [`ssf_configuration`].
        .route(&ssf_configuration_path(), get(ssf_configuration))
        .route(Endpoint::Jwks.path(), get(jwks))
        .with_state(state)
        // The typeface the end-user pages are drawn in (`ast-vn7`). Here, with
        // the browser-facing routes, so that it is reached under a tenant's
        // prefix exactly like the pages that name it — and so that no
        // deployment can be assembled without it, which would be pages whose
        // `@font-face` 404s.
        .merge(crate::http::assets::routes());

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
                post(passkey_login_finish).with_state(Arc::clone(&endpoints)),
            )
            // Account recovery (`ast-2vk.10`). Not in the endpoint registry,
            // for the reason the interaction pages and the passkey pages are
            // not: this is the server's own user interface. It is the one part
            // of it a person reaches with no credential at all, which is why
            // every request through it is limited and recorded.
            //
            // Both verbs on both paths, and no script on either: the whole
            // flow is two forms and a link (`ast-ndk.4`).
            .route(
                recovery::REQUEST_PATH,
                get(recovery_request_page)
                    .post(recovery_request_submit)
                    .with_state(Arc::clone(&endpoints)),
            )
            .route(
                recovery::NEW_PASSWORD_PATH,
                get(recovery_new_password_page)
                    .post(recovery_new_password_submit)
                    .with_state(Arc::clone(&endpoints)),
            );

        router = mount_features(router, capabilities, endpoints);
    }

    // The layer is outermost of this router's own, so it runs before any
    // handler and after the tenancy middleware has resolved the tenant.
    mount_the_unbuilt(router, capabilities, built_clients).layer(
        axum::middleware::from_fn_with_state(guard, tenant_feature_guard),
    )
}

/// Mounts the routes of the features this deployment has switched on.
///
/// One call rather than two at the call site, because [`routes`] is at
/// clippy's line ceiling and because these are the same kind of thing: a
/// router that exists only where the deployment's flag does.
fn mount_features(
    router: Router,
    capabilities: Capabilities,
    endpoints: Arc<ClientEndpoints>,
) -> Router {
    let router = mount_grant_management(router, capabilities, &endpoints);
    let router = mount_backchannel_authentication(router, capabilities, &endpoints);
    let router = mount_ssf(router, capabilities, &endpoints);
    router.merge(device_pages(endpoints))
}

/// Mounts the SSF Stream Configuration endpoint (SSF 1.0 §8.1.1,
/// `ast-0ju.3`), where the deployment has it.
///
/// Not from the [`Endpoint`] registry, and therefore not from
/// [`mount_the_unbuilt`]: §7.1 advertises this URL in the transmitter's own
/// document, and [`ssf_configuration`] names it from the same constant this
/// route is mounted at. That is the parity the registry buys, kept by hand
/// across two lines rather than by an iterator across thirteen.
///
/// The *deployment's* flag decides whether the route exists at all; a tenant
/// that has switched `ssf` off is refused inside the handler, exactly as it is
/// for the transmitter document, because the per-tenant guard reads the
/// registry and this path is not in it.
fn mount_ssf(
    router: Router,
    capabilities: Capabilities,
    endpoints: &Arc<ClientEndpoints>,
) -> Router {
    if !capabilities.is_enabled(asterius_domain::Feature::Ssf) {
        return router;
    }
    router.route(
        SSF_STREAMS_PATH,
        any(ssf_streams).with_state(Arc::clone(endpoints)),
    )
}

/// Mounts the backchannel authentication endpoint (CIBA Core 1.0 §7).
///
/// One route, `POST` only, form-encoded and client-authenticated
/// (FAPI-CIBA). No DPoP check: nothing is issued here, so there is no key to
/// bind anything to — the proof is required at the token endpoint, where the
/// access token is.
///
/// The *deployment's* flag decides whether the route exists at all; the
/// per-tenant half is [`tenant_feature_guard`], which recognises the path as
/// [`Endpoint::BackchannelAuthentication`] because [`gated_endpoint`] reads
/// the registry rather than a list kept beside it. A tenant that has switched
/// CIBA off gets the 404 its own discovery document implies.
fn mount_backchannel_authentication(
    router: Router,
    capabilities: Capabilities,
    endpoints: &Arc<ClientEndpoints>,
) -> Router {
    if !Endpoint::BackchannelAuthentication.is_enabled(&capabilities) {
        return router;
    }
    router.route(
        Endpoint::BackchannelAuthentication.path(),
        post(backchannel_authentication_endpoint).with_state(Arc::clone(endpoints)),
    )
}

/// Mounts the Grant Management API (ID1 §6.3), where the deployment has it.
///
/// §6.3: "the resource URL is constructed by appending the `grant_id` to the
/// `grant_management_endpoint`". The base path is the registry's — the same
/// one `/grants` is advertised under — so the URL a client builds from the
/// metadata is the URL this matches.
///
/// The *deployment's* flag decides whether the route exists at all. The
/// per-tenant half is [`tenant_feature_guard`], which recognises this path as
/// [`Endpoint::GrantManagement`] because it recognises every path under it;
/// but that guard is inert on a deployment with no settings repository, and a
/// route that existed there would answer for a feature this deployment does
/// not advertise.
fn mount_grant_management(
    router: Router,
    capabilities: Capabilities,
    endpoints: &Arc<ClientEndpoints>,
) -> Router {
    if !capabilities.grant_management {
        return router;
    }
    router.route(
        &format!("{}/{{grant_id}}", Endpoint::GrantManagement.path()),
        get(grant_query)
            .delete(grant_revoke)
            .with_state(Arc::clone(endpoints)),
    )
}

/// The whole of the device authorization grant's HTTP surface (RFC 8628).
///
/// The endpoint of §3.1, which is in the registry and therefore in the
/// discovery document, and the two verification pages of §3.3, which are
/// deliberately not: they are this server's own user interface, reached with a
/// session cookie, and `verification_uri` is published in the *device
/// authorization response* rather than in a document a client reads.
///
/// A router of their own, merged rather than chained, because [`routes`] is at
/// clippy's line ceiling and because these three are one feature: a reader
/// looking for the device flow finds it here rather than in three places.
fn device_pages(endpoints: Arc<ClientEndpoints>) -> Router {
    Router::new()
        // RFC 8628 §3.1: `POST` only, form-encoded, and — FAPI 2.0 SP
        // §5.3.2.1 item 3 — client-authenticated. No DPoP check: nothing is
        // issued here, so there is no key to bind anything to. The proof is
        // required at the token endpoint, where the access token is.
        .route(
            Endpoint::DeviceAuthorization.path(),
            post(device_authorization_endpoint).with_state(Arc::clone(&endpoints)),
        )
        .route(
            device::PAGE_PATH,
            get(device_page)
                .post(device_submit)
                .with_state(Arc::clone(&endpoints)),
        )
        .route(
            device::CONFIRM_PATH,
            post(device_confirm).with_state(endpoints),
        )
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
                        | Endpoint::DeviceAuthorization
                        | Endpoint::BackchannelAuthentication
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

    // `acr_values_supported` comes from the same ladder `/authorize` consults,
    // for the reason RFC 8414 §2 gives: a document that advertised a class this
    // server would refuse as `unmet_authentication_requirements` would be
    // telling clients to ask for something it cannot do (`ast-2vk.7`).
    // RFC 9396 §9.1, and the same argument again: the types a tenant has
    // registered are rows in a table, so the document is built from the table.
    // A deployment with no store wired advertises none, which is honest — it
    // has no registry, so it can honour no `authorization_details`.
    let authorization_details_types = match &state.clients {
        None => Vec::new(),
        Some(endpoints) => {
            use asterius_domain::AuthorizationDetailsTypeRepository as _;
            let scope = endpoints.store.scope(tenant.id.clone());
            match scope.authorization_details_types().list().await {
                Ok(types) => {
                    asterius_domain::AuthorizationDetailsRegistry::new(types).supported_types()
                }
                // Fails closed, like the capabilities read above: advertising a
                // list this server cannot presently check against would tell a
                // client to send a value the pushed request endpoint is
                // refusing for the very same reason.
                Err(error) => {
                    tracing::error!(%error, tenant = %tenant.id, "cannot read the authorization details type registry");
                    return unavailable();
                }
            }
        }
    };

    // Grant Management ID1 §7.1. Read from the same place the pushed-request
    // validator reads it, so `grant_management_action_required` in this
    // document and the answer a request without an action gets are one
    // decision rather than two.
    let grant_management = match &state.clients {
        None => asterius_oidc::grant_management::Policy::new(
            capabilities.is_enabled(asterius_domain::Feature::GrantManagement),
            false,
        ),
        Some(endpoints) => match grant_management_policy(endpoints, &tenant, capabilities).await {
            Ok(policy) => policy,
            Err(error) => {
                tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
                return unavailable();
            }
        },
    };

    let document = metadata::provider_metadata(
        &tenant.issuer,
        &capabilities,
        acr_policy(),
        &authorization_details_types,
        grant_management,
    );
    cacheable_json(&document, METADATA_MAX_AGE)
}

/// Where the SSF transmitter configuration is served (SSF 1.0 §7.2).
///
/// Built from the document name the `asterius-ssf` crate owns and the prefix
/// the tenancy middleware strips against, so the path this router mounts is
/// the path that middleware normalises both well-known forms to — the
/// `/t/{tenant}/.well-known/…` one and RFC 8414 §3.1's inserted
/// `/.well-known/…/t/{tenant}`.
fn ssf_configuration_path() -> String {
    format!(
        "{}{}",
        asterius_oidc::tenancy::WELL_KNOWN_PREFIX,
        asterius_ssf::WELL_KNOWN_DOCUMENT
    )
}

/// `GET /.well-known/ssf-configuration`.
///
/// SSF 1.0 §7.2.3: 200 and `application/json`. The document itself is
/// [`asterius_ssf::transmitter_metadata`], which explains why it names the
/// OP's `jwks_uri` and why it names no management endpoint yet.
///
/// The feature gate is here rather than at mount time because a tenant may
/// switch `Feature::Ssf` off under a deployment that has it on, and the
/// refusal is a **404** for the reason `tenant_feature_guard` gives: as far as
/// this tenant is concerned there is no transmitter, so there is nothing at
/// this URL. A failed settings read answers 503 rather than falling back to
/// the deployment's flags, which would publish a transmitter an operator has
/// just withdrawn.
async fn ssf_configuration(
    State(state): State<ProtocolState>,
    Extension(tenant): Extension<Arc<Tenant>>,
) -> Response {
    let capabilities = match &state.tenant_settings {
        None => state.capabilities,
        Some(directory) => match directory.for_tenant(&tenant.id).await {
            Ok(settings) => settings.effective_capabilities(state.capabilities),
            Err(error) => {
                tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
                return unavailable();
            }
        },
    };

    if !capabilities.is_enabled(asterius_domain::Feature::Ssf) {
        return crate::http::server::not_found().await.into_response();
    }

    // The same URL the OP metadata advertises, from the same registry: the
    // keys that verify a SET are the keys that verify an ID token
    // (`ast-0ju.2`), and two ways of spelling their location would be two
    // things to keep in step.
    // §7.1's `configuration_endpoint`, named exactly when it is mounted: the
    // route needs the database wiring a stream is stored in, so a deployment
    // without it advertises no management endpoint rather than one that 404s
    // (`asterius_ssf::metadata`).
    let configuration_endpoint = state
        .clients
        .as_ref()
        .map(|_| format!("{}{SSF_STREAMS_PATH}", tenant.issuer.as_str()));
    let document = asterius_ssf::transmitter_metadata(
        &tenant.issuer,
        &Endpoint::Jwks.url(&tenant.issuer),
        configuration_endpoint.as_deref(),
    );
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
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
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
    let certificate = certificate.as_deref().map(|presented| &presented.leaf);
    crate::http::limits::guard(
        &limits,
        asterius_domain::LimitedEndpoint::PushedAuthorizationRequest,
        claimed.as_deref(),
        async || {
            pushed_authorization_request_inner(&endpoints, &tenant, &headers, &body, certificate)
                .await
        },
    )
    .await
}

/// The push itself, once the limiter has admitted it.
async fn pushed_authorization_request_inner(
    endpoints: &ClientEndpoints,
    tenant: &Arc<Tenant>,
    headers: &axum::http::HeaderMap,
    body: &axum::body::Bytes,
    certificate: Option<&asterius_oidc::mtls::ClientCertificate>,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    let requests = scope.auth_requests();
    let resource_servers = scope.resource_servers();
    let authorization_details_types = scope.authorization_details_types();

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

    // JAR (RFC 9101) is a per-tenant flag, read the way every other one is: a
    // tenant may switch a deployment feature off and never on, and a failed
    // read is an error rather than the deployment's answer — advertising
    // `request_parameter_supported: false` while still accepting a `request`
    // is exactly the drift `tenant_feature_guard` exists to prevent.
    let capabilities = match capabilities_for(endpoints, tenant).await {
        Ok(capabilities) => capabilities,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };
    let request_objects = capabilities
        .is_enabled(asterius_domain::Feature::RequestObject)
        .then(|| endpoints.authenticator.client_keys().as_ref());

    // Grant Management ID1 §5.2, read exactly the way JAR is: one flag decides
    // both what the discovery document advertises and whether this endpoint has
    // a store to look a `grant_id` up in.
    let grant_management = match grant_management_policy(endpoints, tenant, capabilities).await {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };
    let grant_store = scope.grants();
    let grants: Option<&dyn asterius_domain::GrantAmendments> =
        grant_management.supported.then_some(&grant_store);

    par::push(
        PushContext {
            tenant,
            clients: &clients,
            requests: &requests,
            resource_servers: &resource_servers,
            authorization_details_types: &authorization_details_types,
            keys: endpoints.keys.as_ref(),
            policy: authorization_policy(capabilities).with_grant_management(grant_management),
            lifetime: endpoints.par_lifetime,
            certificate,
            request_objects,
            grants,
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
    // RFC 8705 §3: a certificate-bound access token is checked against the
    // certificate *this* request arrived with, which reaches this server the
    // same way the token endpoint's does.
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Response {
    let certificate = certificate.as_deref().map(|presented| &presented.leaf);
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
        async || {
            userinfo_endpoint_inner(&endpoints, &tenant, &method, &uri, &headers, certificate).await
        },
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
    certificate: Option<&asterius_oidc::mtls::ClientCertificate>,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let source = StoredClaims {
        grants: scope.grants(),
        // The KEK is the same one every other user read takes: the claim bag
        // is encrypted at rest.
        users: scope.users(Arc::clone(&endpoints.kek)),
        // Read only for its `userinfo_signed_response_alg`, and only after the
        // access token verified — see `StoredClaims::signed_response_alg`.
        clients: scope.clients(endpoints.capabilities),
        // `ast-095`: the application roles the response reports. The port is
        // deployment-wide, so the tenant travels beside it.
        tenant: tenant.id.clone(),
        roles: scope.application_roles(),
    };

    userinfo::userinfo(
        userinfo::UserInfoContext {
            tenant,
            source: &source,
            keys: endpoints.keys.as_ref(),
            signer: endpoints.signer.as_ref(),
            dpop: endpoints.dpop.as_ref(),
            certificate,
            now: time::OffsetDateTime::now_utc(),
        },
        method,
        headers,
        uri.query(),
    )
    .await
}

/// `GET /grants/{grant_id}` — Grant Management ID1 §6.4.
///
/// Wiring only: everything that decides anything is in
/// [`crate::http::grant_management`], which is where the tests are.
async fn grant_query(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
    Path(grant_id): Path<String>,
    method: axum::http::Method,
    headers: axum::http::HeaderMap,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let store = StoredGrants {
        grants: scope.grants(),
    };
    grant_management::query(
        grant_management_context(
            &endpoints,
            &tenant,
            &store,
            certificate.as_deref().map(|c| &**c),
        ),
        &method,
        &headers,
        &grant_id,
    )
    .await
}

/// `DELETE /grants/{grant_id}` — Grant Management ID1 §6.5.
async fn grant_revoke(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
    Path(grant_id): Path<String>,
    method: axum::http::Method,
    headers: axum::http::HeaderMap,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let store = StoredGrants {
        grants: scope.grants(),
    };
    grant_management::revoke(
        grant_management_context(
            &endpoints,
            &tenant,
            &store,
            certificate.as_deref().map(|c| &**c),
        ),
        &method,
        &headers,
        &grant_id,
    )
    .await
}

/// The context both verbs take, assembled once so they cannot differ.
fn grant_management_context<'a>(
    endpoints: &'a ClientEndpoints,
    tenant: &'a Tenant,
    store: &'a StoredGrants,
    certificate: Option<&'a crate::mtls::PresentedCertificate>,
) -> grant_management::GrantManagementContext<'a> {
    grant_management::GrantManagementContext {
        tenant,
        store,
        keys: endpoints.keys.as_ref(),
        dpop: endpoints.dpop.as_ref(),
        audit: endpoints.audit.as_ref(),
        certificate: certificate.map(|presented| &presented.leaf),
        now: time::OffsetDateTime::now_utc(),
    }
}

/// The rows behind the Grant Management API.
///
/// One repository, and the endpoint reaches exactly four of its methods
/// through the port — `amend` and `claim` are not among them.
#[derive(Debug)]
struct StoredGrants {
    grants: asterius_store_pg::PgGrantRepository,
}

#[async_trait::async_trait]
impl grant_management::GrantManagementStore for StoredGrants {
    async fn grant(
        &self,
        id: &asterius_domain::GrantId,
    ) -> Result<Option<asterius_domain::Grant>, asterius_domain::DomainError> {
        self.grants.find(id).await
    }

    async fn is_denylisted(&self, jti: &str) -> Result<bool, asterius_domain::DomainError> {
        self.grants.is_denylisted(jti).await
    }

    async fn access_tokens_revoked_before(
        &self,
        client: &asterius_domain::ClientId,
        grant: Option<&asterius_domain::GrantId>,
    ) -> Result<Option<time::OffsetDateTime>, asterius_domain::DomainError> {
        self.grants.revoked_before(client, grant).await
    }

    /// Grant Management ID1 §6.5, in one transaction.
    ///
    /// [`asterius_domain::RevocationReason::UserRevoked`] because that is what
    /// the reason means here: §6.5's `DELETE` is the client acting on the
    /// person's behalf to withdraw *the authorization*, which is a different
    /// fact from RFC 7009's `ClientRevoked` — that one hands a credential back
    /// and leaves the grant standing.
    ///
    /// No live access tokens are named: this caller holds one token and it is
    /// its own, not the grant's. What withdraws the grant's is the cutoff
    /// `revoke` writes.
    ///
    /// [`asterius_domain::DomainError::NotFound`] is `false` and not an error:
    /// it is what a second `DELETE` finds, and it is also what an id this
    /// tenant never held would find.
    async fn revoke(
        &self,
        id: &asterius_domain::GrantId,
        now: time::OffsetDateTime,
    ) -> Result<bool, asterius_domain::DomainError> {
        match self
            .grants
            .revoke(id, asterius_domain::RevocationReason::UserRevoked, &[], now)
            .await
        {
            Ok(_) => Ok(true),
            Err(asterius_domain::DomainError::NotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// `POST`, `GET`, `PATCH`, `PUT` and `DELETE` at `/ssf/streams` — SSF 1.0
/// §8.1.1.
///
/// Wiring only: everything that decides anything is in
/// [`crate::http::ssf::streams`], which is where the tests are. One `any`
/// route rather than five, because §8.1.1 is one resource with five verbs and
/// the module answers 405 for the rest itself — a router that matched only the
/// five would answer 405 without the `Cache-Control` every response of this
/// endpoint carries.
async fn ssf_streams(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // The per-tenant half of the gate. This path is not in the endpoint
    // registry, so `tenant_feature_guard` does not cover it; the refusal is
    // the same 404, for the same reason it gives.
    match capabilities_for(&endpoints, &tenant).await {
        Ok(capabilities) if capabilities.is_enabled(asterius_domain::Feature::Ssf) => {}
        Ok(_) => return crate::http::server::not_found().await.into_response(),
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    }

    let scope = endpoints.store.scope(tenant.id.clone());
    let store = StoredStreams {
        streams: scope.ssf_streams(),
        grants: scope.grants(),
    };
    // What this build can emit. Empty today; see
    // `asterius_ssf::stream::SUPPORTED_EVENTS`.
    let events_supported: std::collections::BTreeSet<String> =
        asterius_ssf::stream::SUPPORTED_EVENTS
            .iter()
            .map(|event| (*event).to_owned())
            .collect();
    crate::http::ssf::streams(
        crate::http::ssf::SsfContext {
            tenant: &tenant,
            store: &store,
            keys: endpoints.keys.as_ref(),
            dpop: endpoints.dpop.as_ref(),
            audit: endpoints.audit.as_ref(),
            certificate: certificate.as_deref().map(|presented| &presented.leaf),
            events_supported: &events_supported,
            now: time::OffsetDateTime::now_utc(),
        },
        &method,
        &headers,
        uri.query(),
        &body,
    )
    .await
}

/// The rows behind the SSF management API.
///
/// Two repositories, because the endpoint asks two different questions: what
/// streams this receiver has, and whether the token it presented is still
/// good. The second is the grant repository's, and it is the same pair of
/// reads UserInfo and Grant Management make.
#[derive(Debug)]
struct StoredStreams {
    streams: asterius_store_pg::PgSsfStreams,
    grants: asterius_store_pg::PgGrantRepository,
}

#[async_trait::async_trait]
impl crate::http::ssf::SsfStreamStore for StoredStreams {
    async fn create(
        &self,
        receiver: &asterius_domain::ClientId,
        stream: &asterius_ssf::stream::StreamConfiguration,
    ) -> Result<(), DomainError> {
        self.streams.create(receiver, stream).await
    }

    async fn find(
        &self,
        receiver: &asterius_domain::ClientId,
        stream: &asterius_ssf::stream::StreamId,
    ) -> Result<Option<asterius_ssf::stream::StreamConfiguration>, DomainError> {
        self.streams.find(receiver, stream).await
    }

    async fn list(
        &self,
        receiver: &asterius_domain::ClientId,
    ) -> Result<Vec<asterius_ssf::stream::StreamConfiguration>, DomainError> {
        self.streams.list(receiver).await
    }

    async fn save(
        &self,
        receiver: &asterius_domain::ClientId,
        stream: &asterius_ssf::stream::StreamConfiguration,
    ) -> Result<bool, DomainError> {
        self.streams.save(receiver, stream).await
    }

    async fn delete(
        &self,
        receiver: &asterius_domain::ClientId,
        stream: &asterius_ssf::stream::StreamId,
    ) -> Result<bool, DomainError> {
        self.streams.delete(receiver, stream).await
    }

    async fn is_denylisted(&self, jti: &str) -> Result<bool, DomainError> {
        self.grants.is_denylisted(jti).await
    }

    async fn access_tokens_revoked_before(
        &self,
        client: &asterius_domain::ClientId,
        grant: Option<&asterius_domain::GrantId>,
    ) -> Result<Option<time::OffsetDateTime>, DomainError> {
        self.grants.revoked_before(client, grant).await
    }
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
    // `Option`, like the client address: the extension exists only when the
    // `mtls` flag is on *and* a certificate reached this server from a source
    // it trusts (`crate::tenancy::layer`). Its absence is "no certificate",
    // never an error.
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let certificate = certificate.as_deref().map(|presented| &presented.leaf);
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
            certificate,
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
/// Reads only, and exactly four of them. The port is narrow so that this
/// endpoint cannot reach `revoke` or `claim` through the repository it happens
/// to hold.
#[derive(Debug)]
struct StoredClaims {
    grants: asterius_store_pg::PgGrantRepository,
    users: asterius_store_pg::PgUserRepository,
    clients: asterius_store_pg::PgClientRepository,
    tenant: asterius_domain::TenantId,
    roles: asterius_store_pg::PgApplicationRoles,
}

#[async_trait::async_trait]
impl userinfo::UserInfoSource for StoredClaims {
    async fn grant(
        &self,
        id: &asterius_domain::GrantId,
    ) -> Result<Option<asterius_domain::Grant>, asterius_domain::DomainError> {
        self.grants.find(id).await
    }

    /// The same query the grants dashboard and the consent memory read
    /// (`PgGrantRepository::list_for_subject`), so "which grants does this
    /// person hold" has one answer here too.
    async fn grants_for_subject(
        &self,
        subject: &asterius_domain::SubjectId,
    ) -> Result<Vec<asterius_domain::Grant>, asterius_domain::DomainError> {
        self.grants.list_for_subject(subject).await
    }

    async fn roles(
        &self,
        user: asterius_domain::UserId,
    ) -> Result<asterius_domain::HeldRoles, asterius_domain::DomainError> {
        use asterius_domain::ports::ApplicationRoleDirectory;
        self.roles.held_by(&self.tenant, user).await
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

    /// OIDC Core §5.3.2, from the client's own registration (`ast-e89`).
    ///
    /// A client that is gone signs nothing: its grants outlive the row only
    /// until the next revocation sweep, and answering `application/jwt` for a
    /// registration this server can no longer read would assert a shape
    /// nobody registered. An unreadable row is an error and not a `None`, so
    /// the signature is never dropped by a failing database.
    async fn signed_response_alg(
        &self,
        client: &asterius_domain::ClientId,
    ) -> Result<Option<asterius_domain::keys::SigningAlgorithm>, asterius_domain::DomainError> {
        Ok(self
            .clients
            .find(client)
            .await?
            .and_then(|client| client.registration.userinfo_signed_response_alg))
    }

    async fn access_tokens_revoked_before(
        &self,
        client: &asterius_domain::ClientId,
        grant: Option<&asterius_domain::GrantId>,
    ) -> Result<Option<time::OffsetDateTime>, asterius_domain::DomainError> {
        self.grants.revoked_before(client, grant).await
    }
}

/// `POST /token` — RFC 6749 §3.2.
///
/// Wiring only, like the PAR handler: everything that decides anything is in
/// [`crate::http::token::token`].
///
/// Five grants are registered: `authorization_code`, `refresh_token`,
/// `client_credentials`, `device_code` and `token-exchange`. Anything else this
/// deployment advertises but has not built answers 501, and a further handler
/// joins the list below without touching the dispatch, the error shape or the
/// caching rules.
async fn token_endpoint(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
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
    let certificate = certificate.as_deref().map(|presented| &presented.leaf);
    crate::http::limits::guard(
        &limits,
        asterius_domain::LimitedEndpoint::Token,
        claimed.as_deref(),
        async || token_endpoint_inner(&endpoints, &tenant, &headers, &body, certificate).await,
    )
    .await
}

/// The token request itself, once the limiter has admitted it.
async fn token_endpoint_inner(
    endpoints: &ClientEndpoints,
    tenant: &Arc<Tenant>,
    headers: &axum::http::HeaderMap,
    body: &axum::body::Bytes,
    certificate: Option<&asterius_oidc::mtls::ClientCertificate>,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());

    let now = time::OffsetDateTime::now_utc();
    let binding = match token_endpoint_proof(endpoints, tenant, headers, now).await {
        Ok(binding) => binding,
        Err(refusal) => return *refusal,
    };

    // One read for all five grants, so that whichever this request turns out
    // to be it mints under the same settings — the same argument `now` and the
    // proof key are resolved once, just above.
    let issuing = match issuing_policy(endpoints, tenant).await {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };

    dispatch_grants(
        endpoints,
        tenant,
        &scope,
        issuing,
        Dispatching {
            certificate,
            headers,
            body,
            binding: binding.as_ref(),
            now,
        },
    )
    .await
}

/// What one token request proved and carried, resolved at the edge.
///
/// A struct because every member is a fact about *this* request, and a
/// signature matched by position is one in which the headers and the body can
/// be swapped.
struct Dispatching<'a> {
    certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    headers: &'a axum::http::HeaderMap,
    body: &'a axum::body::Bytes,
    binding: Option<&'a crate::http::dpop::Binding>,
    now: time::OffsetDateTime,
}

/// Builds every grant handler and hands the request to whichever owns it.
///
/// Separate from [`token_endpoint_inner`] because the handlers borrow the
/// repositories beside them: they have to be built in the frame that
/// dispatches, and that frame is better holding nothing else. Adding a grant
/// is adding a value to the list at the bottom.
async fn dispatch_grants(
    endpoints: &ClientEndpoints,
    tenant: &Arc<Tenant>,
    scope: &asterius_store_pg::TenantScope<'_>,
    issuing: Issuing,
    request: Dispatching<'_>,
) -> Response {
    // Named once, because every handler below takes all three and a request
    // judged against two clock readings is two requests.
    let Dispatching {
        certificate, now, ..
    } = request;
    let Issuing {
        lifetimes,
        grant_id_claim,
        grant_management,
        ssf,
    } = issuing;

    let clients = scope.clients(endpoints.capabilities);
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
    // (OIDC Core §5.4, §5.5). The KEK is the one every other user read takes.
    let users = scope.users(Arc::clone(&endpoints.kek));
    // RFC 8707: what a `resource` may name and what an `aud` may hold.
    let resource_servers = scope.resource_servers();
    let application_roles = scope.application_roles();
    // One value for every grant: what this request proved possession of. The
    // registration decides which half binds the token (RFC 9449 §6, RFC 8705
    // §3), so no grant handler chooses for itself.
    let constraint = crate::http::issuance::SenderConstraint {
        proof_key: request.binding.map(|binding| &binding.jkt),
        certificate,
    };
    let authorization_code = AuthorizationCode {
        roles: &application_roles,
        codes: &codes,
        grants: &grants,
        refresh_tokens: &refresh_tokens,
        sessions: &sessions,
        users: &users,
        resource_servers: &resource_servers,
        signer: endpoints.signer.as_ref(),
        grant_id_claim,
        grant_management,
        lifetimes,
        constraint,
        now,
    };
    // The same repositories, and deliberately the same `now` and proof key:
    // whichever grant the request turns out to be, it is judged against one
    // clock reading and one proven key.
    // The third grant, on the same clock reading and the same proven key. It
    // needs neither codes nor sessions nor users: a client-only token is about
    // the client and nothing else (RFC 9068 §2.2).
    let client_credentials = ClientCredentials {
        grants: &grants,
        resource_servers: &resource_servers,
        signer: endpoints.signer.as_ref(),
        audit: endpoints.audit.as_ref(),
        grant_id_claim,
        grant_management,
        ssf,
        lifetimes,
        constraint,
        now,
    };
    // The fourth grant (RFC 8628 §3.4). Built from the code grant's own
    // borrows, so the two cannot be handed different repositories, a different
    // clock reading or a different proven key.
    let device_codes = scope.device_codes();
    let device_code = DeviceCode::sharing(&authorization_code, &device_codes);
    // The fifth grant (RFC 8693). It reads the client registry — the policy
    // that decides whether one client's token may be exchanged by another
    // lives on the client the token was minted for — and this deployment's
    // keys, because the subject token is one *this* server issued and nothing
    // else can say so.
    let token_exchange = crate::http::token_exchange::TokenExchange::sharing(
        &authorization_code,
        &clients,
        endpoints.keys.as_ref(),
        endpoints.audit.as_ref(),
    );
    let refresh_token = RefreshToken::sharing(&authorization_code, endpoints.audit.as_ref());

    let mut response = token::token(
        TokenContext {
            tenant,
            clients: &clients,
            capabilities: endpoints.capabilities,
            grants: &[
                &authorization_code,
                &refresh_token,
                &client_credentials,
                &device_code,
                &token_exchange,
            ],
            certificate,
        },
        request.headers,
        request.body,
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
    if let Some(binding) = request.binding {
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
    let tenant_policy = match registration_policy_for(endpoints, tenant).await {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };
    // What *this tenant* can do, not what the deployment can. A grant behind a
    // flag the tenant switched off reaches an endpoint that answers 404
    // (`tenant_feature_guard`) and a document that does not advertise it, so
    // registering a client for it mints a client that fails at first use —
    // which is the failure `GrantType::required_feature` exists to move to
    // registration time, where the client can still read why. A settings read
    // that fails is an error and never the deployment's answer, as everywhere
    // else here (`ast-lh3.7`).
    let capabilities = match capabilities_for(endpoints, tenant).await {
        Ok(capabilities) => capabilities,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    register::register(
        RegisterContext {
            tenant,
            tenant_policy: &tenant_policy,
            clients: &clients,
            keys: endpoints.keys.as_ref(),
            capabilities,
            outbound: endpoints.outbound.as_ref(),
            policy: &endpoints.registration,
            initial_access_tokens: endpoints
                .initial_access_tokens
                .as_ref()
                .map(std::convert::AsRef::as_ref),
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
    tenant_policy: &'a asterius_domain::RegistrationPolicy,
    capabilities: Capabilities,
) -> ConfigurationContext<'a> {
    ConfigurationContext {
        tenant,
        tenant_policy,
        clients,
        configuration: clients,
        keys: endpoints.keys.as_ref(),
        capabilities,
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
            let tenant_policy = match registration_policy_for(&endpoints, &tenant).await {
                Ok(policy) => policy,
                Err(error) => {
                    tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
                    return unavailable();
                }
            };
            let scope = endpoints.store.scope(tenant.id.clone());
            let clients = scope.clients(endpoints.capabilities);
            client_configuration::read(
                &configuration_context(
                    &endpoints,
                    &tenant,
                    &clients,
                    &request_id,
                    &tenant_policy,
                    // A read validates no document, so the deployment's flags
                    // are the whole answer: narrowing them here would refuse a
                    // client its own record.
                    endpoints.capabilities,
                ),
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
            let tenant_policy = match registration_policy_for(&endpoints, &tenant).await {
                Ok(policy) => policy,
                Err(error) => {
                    tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
                    return unavailable();
                }
            };
            // RFC 7592 §2.2 replaces the whole document, so an update *is* a
            // registration and is held to the tenant's flags exactly as one is.
            let capabilities = match capabilities_for(&endpoints, &tenant).await {
                Ok(capabilities) => capabilities,
                Err(error) => {
                    tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
                    return unavailable();
                }
            };
            let scope = endpoints.store.scope(tenant.id.clone());
            let clients = scope.clients(endpoints.capabilities);
            client_configuration::update(
                &configuration_context(
                    &endpoints,
                    &tenant,
                    &clients,
                    &request_id,
                    &tenant_policy,
                    capabilities,
                ),
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
            let tenant_policy = match registration_policy_for(&endpoints, &tenant).await {
                Ok(policy) => policy,
                Err(error) => {
                    tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
                    return unavailable();
                }
            };
            let scope = endpoints.store.scope(tenant.id.clone());
            let clients = scope.clients(endpoints.capabilities);
            client_configuration::remove(
                &configuration_context(
                    &endpoints,
                    &tenant,
                    &clients,
                    &request_id,
                    &tenant_policy,
                    // A deletion validates no document either, and a client
                    // must be able to delete itself whatever the tenant has
                    // switched off since.
                    endpoints.capabilities,
                ),
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
    let language = page_language(endpoints, tenant, headers).await;
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
            language: &language,
            requests: &requests,
            interactions: &requests,
            session: session.as_ref(),
            grants: &scope.grants(),
            // The same repository the subject resolver below reads, asked a
            // different question: the name a consent screen shown without a
            // sign-in has to display (`ast-k7f`, `ast-bo5`).
            users: &subjects,
            policy: decision_policy(),
            acr: acr_policy(),
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

/// Which authentication contexts this deployment can produce (`ast-2vk.7`).
///
/// `asterius_domain::AcrPolicy::default()`: the three rungs this server can
/// actually stand behind — a password, a WebAuthn assertion, and a WebAuthn
/// assertion whose UV bit was set — plus EAP ACR Values 1.0's `phr` as a name
/// for the second. Nothing on it is a class this build cannot verify having
/// reached.
///
/// A function rather than a literal at each call site, and for the reason
/// [`decision_policy`] is one: the discovery document, the authorization
/// decision and the session an authentication writes must all be reading the
/// same ladder. Per-tenant ladders are the obvious next step and are not this
/// one — they need a store, and `crates/domain/src/entities/acr_policy.rs`
/// already carries the round-trip (`AcrPolicy::from_json`) a column would use.
fn acr_policy() -> &'static asterius_domain::AcrPolicy {
    // Built once. It is immutable, it is read on every authorization and every
    // discovery request, and a fresh copy per request would be an allocation
    // per rung to arrive at the same answer.
    static POLICY: std::sync::LazyLock<asterius_domain::AcrPolicy> =
        std::sync::LazyLock::new(asterius_domain::AcrPolicy::default);
    &POLICY
}

/// What this deployment offers an authorization request, in one place.
///
/// One function rather than a literal at each call site, because the push and
/// the discovery document must agree: a tenant that advertises a `prompt` value
/// its validator refuses has told clients to send something it will reject.
///
/// `prompt=create` follows [`Feature::SelfRegistration`], narrowed to this
/// tenant before it gets here. OpenID Connect Prompt Create 1.0 §3 sends the
/// user to a registration screen, and a tenant that provisions its accounts has
/// none to send them to: refusing the value is what §4 asks an OP that does not
/// support it to do. `metadata::provider_metadata` builds its policy from the
/// same flag, so the document and this validator cannot disagree (`ast-2vk.8`).
const fn authorization_policy(
    capabilities: Capabilities,
) -> asterius_oidc::authorize::AuthorizationPolicy {
    asterius_oidc::authorize::AuthorizationPolicy::new(
        capabilities.is_enabled(asterius_domain::Feature::SelfRegistration),
    )
}

/// Where a self-service sign-up is written, for a tenant that offers one.
///
/// `None` unless [`asterius_domain::Feature::SelfRegistration`] survives this
/// tenant's own subtraction — the same value `authorization_policy` builds the
/// `prompt=create` decision from and the same one the discovery document
/// advertises. One read, three uses: a tenant cannot advertise the value,
/// accept it at the push and then have no registrar behind the page.
fn registrar<'a>(
    users: &'a asterius_store_pg::PgUserRepository,
    passwords: Option<&'a asterius_store_pg::PgPasswordVerifier>,
    capabilities: Capabilities,
) -> Option<crate::http::signup::Registrar<'a>> {
    capabilities
        .is_enabled(asterius_domain::Feature::SelfRegistration)
        .then_some(crate::http::signup::Registrar { users, passwords })
}

/// This tenant's Grant Management posture (Grant Management ID1 §7.1).
///
/// Both halves come from the same two reads the discovery document is built
/// from — the deployment's flag, narrowed by the tenant's own subtraction, and
/// the tenant's `grant_management_action_required` — so a tenant cannot
/// advertise one thing and validate another. A deployment with no settings
/// repository wired has no tenant to require anything, and the deployment flag
/// alone decides.
async fn grant_management_policy(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    capabilities: asterius_domain::Capabilities,
) -> Result<asterius_oidc::grant_management::Policy, DomainError> {
    let supported = capabilities.is_enabled(asterius_domain::Feature::GrantManagement);
    let action_required = match &endpoints.tenant_settings {
        None => false,
        Some(directory) => directory
            .for_tenant(&tenant.id)
            .await?
            .grant_management_action_required(endpoints.capabilities),
    };
    Ok(asterius_oidc::grant_management::Policy::new(
        supported,
        action_required,
    ))
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

/// The DPoP proof this token request arrived with, if it arrived with one.
///
/// RFC 9449 §5: a proof is checked against the method and the URL of the
/// request it was made for, which is why this is resolved once at the edge and
/// handed down rather than re-derived by each grant handler.
///
/// # Errors
///
/// The refusal, already rendered: [`dpop::Refusal`] knows the authorization
/// server's shape for one (RFC 9449 §5.2), and re-deciding it here would be a
/// second opinion.
async fn token_endpoint_proof(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    headers: &axum::http::HeaderMap,
    now: time::OffsetDateTime,
) -> Result<Option<crate::http::dpop::Binding>, Box<Response>> {
    endpoints
        .dpop
        .check(
            tenant,
            Endpoint::Token,
            &axum::http::Method::POST,
            headers,
            now,
        )
        .await
        .map_err(|refusal| Box::new(refusal.into_response()))
}

/// Everything about a tenant that shapes a token, read together.
///
/// A struct rather than three reads at three points in
/// [`token_endpoint_inner`], because all three must describe the *same*
/// tenant at the same moment: a token whose lifetime came from one reading and
/// whose claims came from another is a token no setting explains.
#[derive(Debug, Clone, Copy)]
struct Issuing {
    /// How long the access token lives (`ast-5c6`).
    lifetimes: TokenLifetimes,
    /// Whether it carries `grant_id` (RFC 9068 §2.2.3.1).
    grant_id_claim: bool,
    /// Whether the grant management endpoint is an audience it may be minted
    /// for (Grant Management ID1 §6.2).
    ///
    /// The tenant's own narrowing, not the deployment's flags: a tenant that
    /// has switched Grant Management off has no grant management endpoint —
    /// [`tenant_feature_guard`] answers 404 there — so a token audienced at it
    /// would be a token for a URL that does not exist here.
    grant_management: bool,
    /// Whether the SSF stream configuration endpoint is an audience a
    /// client-only token may be minted for (SSF 1.0 §8, `ast-0ju.3`).
    ///
    /// The tenant's own narrowing, exactly as above and for the same reason: a
    /// tenant that has switched SSF off has no management endpoint — the
    /// handler answers 404 there — so a token audienced at it would be a token
    /// for a URL that does not exist here.
    ssf: bool,
}

/// Reads the three, from one settings lookup.
///
/// # Errors
///
/// Whatever the settings read failed with. Never a default: falling back would
/// mint tokens under a policy this tenant has just replaced.
async fn issuing_policy(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
) -> Result<Issuing, DomainError> {
    let Some(directory) = &endpoints.tenant_settings else {
        return Ok(Issuing {
            lifetimes: endpoints.lifetimes,
            grant_id_claim: asterius_domain::TenantSettings::default().grant_id_in_access_token(),
            grant_management: endpoints
                .capabilities
                .is_enabled(asterius_domain::Feature::GrantManagement),
            ssf: endpoints
                .capabilities
                .is_enabled(asterius_domain::Feature::Ssf),
        });
    };
    let settings = directory.for_tenant(&tenant.id).await?;
    Ok(Issuing {
        lifetimes: settings.lifetimes(),
        grant_id_claim: settings.grant_id_in_access_token(),
        grant_management: settings
            .effective_capabilities(endpoints.capabilities)
            .is_enabled(asterius_domain::Feature::GrantManagement),
        ssf: settings
            .effective_capabilities(endpoints.capabilities)
            .is_enabled(asterius_domain::Feature::Ssf),
    })
}

/// What this tenant can do, given what the deployment can do.
///
/// The same narrowing [`discovery`] renders its document from, so an endpoint
/// cannot honour a feature the tenant's own metadata says is off. A read that
/// *fails* is an error and never the deployment's capabilities: falling back
/// would reopen exactly what a tenant has just switched off.
async fn capabilities_for(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
) -> Result<Capabilities, DomainError> {
    match &endpoints.tenant_settings {
        None => Ok(endpoints.capabilities),
        Some(directory) => Ok(directory
            .for_tenant(&tenant.id)
            .await?
            .effective_capabilities(endpoints.capabilities)),
    }
}

/// This tenant's registration policy, or the deployment's silence.
///
/// `None` settings repository means no tenant has an opinion, exactly as
/// [`lifetimes_for`] reads it. A read that *fails* is an error and never the
/// default: falling back would reopen a registration endpoint a tenant has just
/// closed, which is the mistake [`tenant_feature_guard`] refuses to make.
async fn registration_policy_for(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
) -> Result<asterius_domain::RegistrationPolicy, DomainError> {
    match &endpoints.tenant_settings {
        None => Ok(asterius_domain::RegistrationPolicy::default()),
        Some(directory) => Ok(directory
            .for_tenant(&tenant.id)
            .await?
            .registration()
            .clone()),
    }
}

/// The three layers a page's language is chosen from, for this tenant and this
/// request.
///
/// Never an error, unlike [`capabilities_for`]: a settings row that cannot be
/// read costs a tenant its configured default and its own wording, and costs
/// nobody a sign-in. `crate::http::i18n` states why the two reads differ.
async fn page_language(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    headers: &axum::http::HeaderMap,
) -> crate::http::i18n::PageLanguage {
    let settings = match &endpoints.tenant_settings {
        None => None,
        Some(directory) => match directory.for_tenant(&tenant.id).await {
            Ok(settings) => Some(settings),
            Err(error) => {
                tracing::warn!(
                    %error,
                    tenant = %tenant.id,
                    "cannot read the tenant settings that name the page language; the built-in                      wording is served instead"
                );
                None
            }
        },
    };
    crate::http::i18n::PageLanguage::new(settings.as_ref(), headers)
}

/// The wording a logout context starts with, before the caller replaces it.
///
/// Never rendered: both handlers assign the negotiated catalogue immediately.
/// It exists so that the shared builder has a value for a field only the caller
/// can compute.
static ENGLISH: asterius_web::Catalog =
    asterius_web::Catalog::new(asterius_domain::locale::Locale::English);

/// Whether this tenant's logout also withdraws the refresh tokens issued under
/// the session (`ast-o4u.2`).
///
/// `false` whenever the answer is not certain — no settings repository, or a
/// row that would not read — and that is the safe direction here rather than
/// the strict one: the failure of a *read* must not withdraw a client's
/// offline access, which no logout would then give back. A tenant that has
/// asked for the revocation and whose settings cannot be read gets a logout
/// that is incomplete and logged, not one that revokes more than it should.
async fn revoke_refresh_on_logout(endpoints: &ClientEndpoints, tenant: &Tenant) -> bool {
    let Some(directory) = &endpoints.tenant_settings else {
        return false;
    };
    match directory.for_tenant(&tenant.id).await {
        Ok(settings) => settings.revoke_refresh_on_logout(),
        Err(error) => {
            tracing::warn!(
                %error,
                tenant = %tenant.id,
                "cannot read the settings that decide revoke_refresh_on_logout; \
                 refresh tokens are left alone"
            );
            false
        }
    }
}

/// The tenant-scoped repositories an end-session request reads and writes
/// through.
///
/// A struct rather than four parameters: they are built together at the two
/// call sites, from one `scope`, and passing them one by one is how a handler
/// ends up with a repository scoped to a different tenant than its neighbour.
struct LogoutStores<'a> {
    sessions: &'a asterius_store_pg::PgSessionRepository,
    clients: &'a asterius_store_pg::PgClientRepository,
    /// The `sub` each participating client knows this person by.
    subjects: &'a asterius_store_pg::PgUserRepository,
    /// The refresh tokens a tenant with `revoke_refresh_on_logout` withdraws.
    credentials: &'a asterius_store_pg::PgRefreshTokenRepository,
}

/// Builds the context both end-session handlers share.
fn logout_context<'a>(
    endpoints: &'a ClientEndpoints,
    tenant: &'a Tenant,
    stores: &LogoutStores<'a>,
    revoke_refresh: bool,
    nonce: &'a asterius_web::csp::Nonce,
    request_id: &'a crate::http::request_id::RequestId,
    mount: Option<Extension<MountPrefix>>,
) -> logout::LogoutContext<'a> {
    let LogoutStores {
        sessions,
        clients,
        subjects,
        credentials,
    } = *stores;
    logout::LogoutContext {
        // Replaced by the caller, which is the only thing that has the
        // request's `ui_locales` in front of it. A default here rather than an
        // eighth parameter: this builder is shared by both verbs and it already
        // carries as many as a reader can hold.
        text: &ENGLISH,
        tenant,
        sessions,
        clients,
        keys: endpoints.keys.as_ref(),
        audit: endpoints.audit.as_ref(),
        nonce,
        request_id: Some(request_id.as_str()),
        mount: mount_of(mount),
        subjects,
        credentials: Some(credentials),
        revoke_refresh,
        signer: endpoints.signer.as_ref(),
        outbox: endpoints
            .outbox
            .as_deref()
            .map(|queue| queue as &dyn asterius_domain::outbox::OutboxQueue),
    }
}

/// `GET /logout` — OIDC RP-Initiated Logout 1.0 §2.
async fn end_session(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    // Before anything is validated: RP-Initiated Logout §4's refusal page is a
    // page too, and it is in the language the request asked for.
    let text = page_language(&endpoints, &tenant, &headers)
        .await
        .for_request(&crate::http::i18n::form_ui_locales(&pairs));
    let scope = endpoints.store.scope(tenant.id.clone());
    let sessions = scope.sessions();
    let clients = scope.clients(endpoints.capabilities);
    // The pairwise `sub` each participating client knows this person by, for
    // the logout token (Back-Channel Logout 1.0 §2.4).
    let subjects = scope.users(Arc::clone(&endpoints.kek));
    // The tenant policy that decides whether this logout reaches the refresh
    // tokens issued under the session (`ast-o4u.2`).
    let credentials = scope.refresh_tokens();
    let revoke_refresh = revoke_refresh_on_logout(&endpoints, &tenant).await;
    let stores = LogoutStores {
        sessions: &sessions,
        clients: &clients,
        subjects: &subjects,
        credentials: &credentials,
    };
    let mut context = logout_context(
        &endpoints,
        &tenant,
        &stores,
        revoke_refresh,
        &nonce,
        &request_id,
        mount,
    );
    context.text = &text;
    logout::show(context, &headers, &pairs, time::OffsetDateTime::now_utc()).await
}

/// `POST /logout` — the same request, form-encoded, and the confirmation
/// page's answer.
async fn end_session_form(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(&body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    // Before anything is validated: RP-Initiated Logout §4's refusal page is a
    // page too, and it is in the language the request asked for.
    let text = page_language(&endpoints, &tenant, &headers)
        .await
        .for_request(&crate::http::i18n::form_ui_locales(&pairs));
    let scope = endpoints.store.scope(tenant.id.clone());
    let sessions = scope.sessions();
    let clients = scope.clients(endpoints.capabilities);
    // The pairwise `sub` each participating client knows this person by, for
    // the logout token (Back-Channel Logout 1.0 §2.4).
    let subjects = scope.users(Arc::clone(&endpoints.kek));
    // The tenant policy that decides whether this logout reaches the refresh
    // tokens issued under the session (`ast-o4u.2`).
    let credentials = scope.refresh_tokens();
    let revoke_refresh = revoke_refresh_on_logout(&endpoints, &tenant).await;
    let stores = LogoutStores {
        sessions: &sessions,
        clients: &clients,
        subjects: &subjects,
        credentials: &credentials,
    };
    let mut context = logout_context(
        &endpoints,
        &tenant,
        &stores,
        revoke_refresh,
        &nonce,
        &request_id,
        mount,
    );
    context.text = &text;
    logout::submit(context, &headers, &pairs, time::OffsetDateTime::now_utc()).await
}

/// `GET /interaction/{id}`.
// Eight extractors, for the reason `interaction_submit` below gives: axum
// builds every one of them from the request, so the count costs no caller
// anything. The query is here for one link — the sign-up page's way to the
// sign-in page (`interaction::SIGN_IN_QUERY`).
#[allow(clippy::too_many_arguments)]
async fn interaction_show(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Path(id): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
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
    let detail_types = scope.authorization_details_types();
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
    // Grant Management ID1 §5.2. The same flag the pushed-request endpoint
    // read: a stored request can only name a `grant_id` if it was on then, and
    // a tenant that has switched it off since must not have the amendment made
    // for it anyway.
    let capabilities = match capabilities_for(&endpoints, &tenant).await {
        Ok(capabilities) => capabilities,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };
    let grant_amendments: Option<&dyn asterius_domain::GrantAmendments> = capabilities
        .is_enabled(asterius_domain::Feature::GrantManagement)
        .then_some(&grants);
    let language = page_language(&endpoints, &tenant, &headers).await;
    interaction::show(
        InteractionContext {
            tenant: &tenant,
            language: &language,
            requests: &requests,
            credentials: passwords
                .as_ref()
                .map(|v| v as &dyn asterius_domain::CredentialVerifier),
            sessions: &sessions,
            lifetimes: endpoints.session_lifetimes,
            acr: acr_policy(),
            clients: &clients,
            grants: &grants,
            grant_amendments,
            memory: memory_policy(),
            authorization_details_types: Some(&detail_types),
            codes: &codes,
            subjects: &users,
            code_lifetime: lifetimes.authorization_code(),
            nonce: &nonce,
            throttle: throttle(&endpoints, &limiter, client.as_deref()),
            audit: endpoints.audit.as_ref(),
            mount: mount_of(mount),
            registrar: registrar(&users, passwords.as_ref(), capabilities),
            directory: &users,
        },
        &id,
        query.as_deref(),
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
    let detail_types = scope.authorization_details_types();
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
    // Grant Management ID1 §5.2. The same flag the pushed-request endpoint
    // read: a stored request can only name a `grant_id` if it was on then, and
    // a tenant that has switched it off since must not have the amendment made
    // for it anyway.
    let capabilities = match capabilities_for(&endpoints, &tenant).await {
        Ok(capabilities) => capabilities,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };
    let grant_amendments: Option<&dyn asterius_domain::GrantAmendments> = capabilities
        .is_enabled(asterius_domain::Feature::GrantManagement)
        .then_some(&grants);
    let language = page_language(&endpoints, &tenant, &headers).await;
    interaction::submit(
        InteractionContext {
            tenant: &tenant,
            language: &language,
            requests: &requests,
            credentials: passwords
                .as_ref()
                .map(|v| v as &dyn asterius_domain::CredentialVerifier),
            sessions: &sessions,
            lifetimes: endpoints.session_lifetimes,
            acr: acr_policy(),
            clients: &clients,
            grants: &grants,
            grant_amendments,
            memory: memory_policy(),
            authorization_details_types: Some(&detail_types),
            codes: &codes,
            subjects: &users,
            code_lifetime: lifetimes.authorization_code(),
            nonce: &nonce,
            throttle: throttle(&endpoints, &limiter, client.as_deref()),
            audit: endpoints.audit.as_ref(),
            mount: mount_of(mount),
            registrar: registrar(&users, passwords.as_ref(), capabilities),
            directory: &users,
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

/// Builds the context the four recovery routes share.
///
/// One helper for the same reason `passkey_context` is one: four copies of a
/// ten-field literal is four places for one of them to drift, and the field
/// that would drift is the limiter.
#[allow(clippy::too_many_arguments)]
fn recovery_context<'a>(
    endpoints: &'a ClientEndpoints,
    tenant: &'a Tenant,
    users: &'a asterius_store_pg::PgUserRepository,
    passwords: Option<&'a asterius_store_pg::PgPasswordVerifier>,
    tokens: &'a asterius_store_pg::PgRecoveryTokens,
    mail: &'a asterius_store_pg::PgOutboxMailSender,
    sessions: &'a asterius_store_pg::PgSessionRepository,
    limiter: &'a asterius_store_pg::PgRateLimitStore,
    client: Option<&crate::http::forwarded::ClientAddr>,
    nonce: &'a asterius_web::csp::Nonce,
    mount: MountPrefix,
) -> recovery::RecoveryContext<'a> {
    recovery::RecoveryContext {
        tenant,
        users,
        passwords,
        tokens,
        mail,
        sessions,
        audit: endpoints.audit.as_ref(),
        throttle: throttle(endpoints, limiter, client),
        nonce,
        mount,
    }
}

/// `GET /recovery` — the form that asks for an address.
async fn recovery_request_page(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    mount: Option<Extension<MountPrefix>>,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let users = scope.users(Arc::clone(&endpoints.kek));
    let tokens = scope.recovery_tokens();
    let mail = scope.mail();
    let sessions = scope.sessions();
    let passwords = endpoints.passwords(&tenant.id);
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    recovery::show_request(&recovery_context(
        &endpoints,
        &tenant,
        &users,
        passwords.as_ref(),
        &tokens,
        &mail,
        &sessions,
        &limiter,
        client.as_deref(),
        &nonce,
        mount_of(mount),
    ))
}

/// `POST /recovery` — draw a token and hand a message to the sender.
#[allow(clippy::too_many_arguments)]
async fn recovery_request_submit(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let users = scope.users(Arc::clone(&endpoints.kek));
    let tokens = scope.recovery_tokens();
    let mail = scope.mail();
    let sessions = scope.sessions();
    let passwords = endpoints.passwords(&tenant.id);
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    recovery::submit_request(
        &recovery_context(
            &endpoints,
            &tenant,
            &users,
            passwords.as_ref(),
            &tokens,
            &mail,
            &sessions,
            &limiter,
            client.as_deref(),
            &nonce,
            mount_of(mount),
        ),
        &headers,
        &body,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `GET /recovery/new?token=…` — the page the mailed link leads to.
#[allow(clippy::too_many_arguments)]
async fn recovery_new_password_page(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    mount: Option<Extension<MountPrefix>>,
    uri: axum::http::Uri,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let users = scope.users(Arc::clone(&endpoints.kek));
    let tokens = scope.recovery_tokens();
    let mail = scope.mail();
    let sessions = scope.sessions();
    let passwords = endpoints.passwords(&tenant.id);
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    recovery::show_new_password(
        &recovery_context(
            &endpoints,
            &tenant,
            &users,
            passwords.as_ref(),
            &tokens,
            &mail,
            &sessions,
            &limiter,
            client.as_deref(),
            &nonce,
            mount_of(mount),
        ),
        uri.query(),
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `POST /recovery/new` — spend the token and set the credential.
#[allow(clippy::too_many_arguments)]
async fn recovery_new_password_submit(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let users = scope.users(Arc::clone(&endpoints.kek));
    let tokens = scope.recovery_tokens();
    let mail = scope.mail();
    let sessions = scope.sessions();
    let passwords = endpoints.passwords(&tenant.id);
    let limiter = asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone());
    recovery::submit_new_password(
        &recovery_context(
            &endpoints,
            &tenant,
            &users,
            passwords.as_ref(),
            &tokens,
            &mail,
            &sessions,
            &limiter,
            client.as_deref(),
            &nonce,
            mount_of(mount),
        ),
        &headers,
        &body,
        time::OffsetDateTime::now_utc(),
    )
    .await
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
            acr: acr_policy(),
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
            acr: acr_policy(),
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

/// `POST /bc-authorize` — CIBA Core 1.0 §7.1.
async fn backchannel_authentication_endpoint(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    let users = scope.users(Arc::clone(&endpoints.kek));
    let ciba_requests = scope.ciba_requests();
    let certificate = certificate.as_deref().map(|presented| &presented.leaf);
    let now = time::OffsetDateTime::now_utc();

    // The same read the discovery document is rendered from, so a tenant
    // cannot advertise one Grant Management policy and validate another.
    let capabilities = match capabilities_for(&endpoints, &tenant).await {
        Ok(capabilities) => capabilities,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };
    let grant_management = match grant_management_policy(&endpoints, &tenant, capabilities).await {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read the tenant's settings");
            return unavailable();
        }
    };

    let authenticator = Arc::clone(&endpoints.authenticator);
    let tenant_for_auth = Arc::clone(&tenant);
    let clients_for_auth = scope.clients(endpoints.capabilities);

    backchannel_authentication::authorize(
        BackchannelContext {
            tenant: &tenant,
            clients: &clients,
            users: &users,
            keys: endpoints.keys.as_ref(),
            client_keys: endpoints.authenticator.client_keys().as_ref(),
            ciba_requests: &ciba_requests,
            audit: endpoints.audit.as_ref(),
            certificate,
            grant_management,
            request_id: Some(request_id.as_str()),
        },
        &headers,
        &body,
        async |attempt: &Attempt<'_>, rules: &AssertionRules| {
            authenticator
                .authenticate(&tenant_for_auth, &clients_for_auth, attempt, rules, now)
                .await
        },
        now,
    )
    .await
}

/// `POST /device_authorization` — RFC 8628 §3.1.
async fn device_authorization_endpoint(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    certificate: Option<Extension<Arc<crate::mtls::PresentedCertificate>>>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    let device_codes = scope.device_codes();
    let certificate = certificate.as_deref().map(|presented| &presented.leaf);
    let now = time::OffsetDateTime::now_utc();

    let authenticator = Arc::clone(&endpoints.authenticator);
    let tenant_for_auth = Arc::clone(&tenant);
    let clients_for_auth = scope.clients(endpoints.capabilities);

    device_authorization::authorize(
        DeviceAuthorizationContext {
            tenant: &tenant,
            clients: &clients,
            device_codes: &device_codes,
            certificate,
            mount: mount_of(mount),
        },
        &headers,
        &body,
        async |attempt: &Attempt<'_>, rules: &AssertionRules| {
            authenticator
                .authenticate(&tenant_for_auth, &clients_for_auth, attempt, rules, now)
                .await
        },
        now,
    )
    .await
}

/// The parameters `GET /device` reads: RFC 8628 §3.3.1's prefilled code.
#[derive(Debug, serde::Deserialize)]
struct UserCodeQuery {
    /// The code a `verification_uri_complete` carried, if any.
    user_code: Option<String>,
}

/// `GET /device` — the code-entry page.
async fn device_page(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    mount: Option<Extension<MountPrefix>>,
    axum::extract::Query(query): axum::extract::Query<UserCodeQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let parts = device_parts(&endpoints, &tenant);
    device::page(
        &device_context(
            &endpoints,
            &tenant,
            &parts,
            client.as_deref(),
            &nonce,
            mount,
        ),
        &headers,
        query.user_code.as_deref(),
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `POST /device` — the code somebody typed.
#[allow(clippy::too_many_arguments)]
async fn device_submit(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    mount: Option<Extension<MountPrefix>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let parts = device_parts(&endpoints, &tenant);
    device::submit(
        &device_context(
            &endpoints,
            &tenant,
            &parts,
            client.as_deref(),
            &nonce,
            mount,
        ),
        &headers,
        &body,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `POST /device/confirm` — the answer.
#[allow(clippy::too_many_arguments)]
async fn device_confirm(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    client: Option<Extension<crate::http::forwarded::ClientAddr>>,
    mount: Option<Extension<MountPrefix>>,
    axum::extract::Query(query): axum::extract::Query<UserCodeQuery>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let parts = device_parts(&endpoints, &tenant);
    device::confirm(
        &device_context(
            &endpoints,
            &tenant,
            &parts,
            client.as_deref(),
            &nonce,
            mount,
        ),
        &headers,
        &body,
        query.user_code.as_deref(),
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// The tenant-scoped repositories the device pages hold borrows of.
///
/// A struct rather than seven locals at three call sites: the context borrows
/// all of them, so they have to outlive it, and one owner is one lifetime to
/// get right instead of seven.
struct DeviceParts {
    device_codes: asterius_store_pg::PgDeviceCodeRepository,
    sessions: asterius_store_pg::PgSessionRepository,
    interactions: asterius_store_pg::PgAuthRequestRepository,
    clients: asterius_store_pg::PgClientRepository,
    grants: asterius_store_pg::PgGrantRepository,
    users: asterius_store_pg::PgUserRepository,
    limiter: asterius_store_pg::PgRateLimitStore,
}

fn device_parts(endpoints: &Arc<ClientEndpoints>, tenant: &Arc<Tenant>) -> DeviceParts {
    let scope = endpoints.store.scope(tenant.id.clone());
    DeviceParts {
        device_codes: scope.device_codes(),
        sessions: scope.sessions(),
        interactions: scope.auth_requests(),
        clients: scope.clients(endpoints.capabilities),
        grants: scope.grants(),
        users: scope.users(Arc::clone(&endpoints.kek)),
        limiter: asterius_store_pg::PgRateLimitStore::new(endpoints.store.pool().clone()),
    }
}

fn device_context<'a>(
    endpoints: &'a ClientEndpoints,
    tenant: &'a Tenant,
    parts: &'a DeviceParts,
    client: Option<&crate::http::forwarded::ClientAddr>,
    nonce: &'a asterius_web::csp::Nonce,
    mount: Option<Extension<MountPrefix>>,
) -> DeviceContext<'a> {
    DeviceContext {
        tenant,
        device_codes: &parts.device_codes,
        sessions: &parts.sessions,
        interactions: &parts.interactions,
        clients: &parts.clients,
        grants: &parts.grants,
        subjects: &parts.users,
        acr: acr_policy(),
        limits: &parts.limiter,
        address: client.map(|client| client.ip),
        nonce,
        audit: endpoints.audit.as_ref(),
        mount: mount_of(mount),
    }
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
