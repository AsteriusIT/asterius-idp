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
use crate::http::par::{self, PushContext};
use crate::http::register::{self, RegisterContext, RegistrationPolicy};
use crate::http::token::{self, TokenContext};
use asterius_domain::{Capabilities, KeyStore, Tenant};
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
    /// How long an authorization code lives, already clamped to the profile's
    /// 60-second cap (FAPI 2.0 SP §5.3.2.1 item 11).
    pub code_lifetime: time::Duration,
    /// Opens the tenant's pairwise salt, which every `sub` derives from.
    pub kek: Arc<dyn asterius_jose::Kek>,
    /// Who may register a client, and how.
    pub registration: RegistrationPolicy,
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
pub fn routes(state: ProtocolState) -> Router {
    let capabilities = state.capabilities;
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
            .route(
                "/interaction/{id}",
                get(interaction_show)
                    .post(interaction_submit)
                    .with_state(endpoints),
            );
    }

    // Everything else exists but is not built yet. Mounted from the registry so
    // that the parity test — and a client reading the document — find a route
    // rather than a 404.
    for endpoint in Endpoint::enabled(&capabilities) {
        if endpoint == Endpoint::Jwks
            || (built_clients
                && matches!(
                    endpoint,
                    Endpoint::PushedAuthorizationRequest
                        | Endpoint::Token
                        | Endpoint::Authorization
                        | Endpoint::Registration
                ))
        {
            continue;
        }
        router = router.route(endpoint.path(), any(not_implemented));
    }

    router
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
    // Per-tenant flags are `ast-f7m.4`; until then a tenant has the
    // deployment's capabilities, and this is the one line that will change.
    let document = metadata::provider_metadata(&tenant.issuer, &state.capabilities);
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
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
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
            &tenant,
            Endpoint::PushedAuthorizationRequest,
            &axum::http::Method::POST,
            &headers,
            now,
        )
        .await
    {
        Ok(binding) => binding,
        Err(refusal) => return refusal.into_response(),
    };

    let authenticator = Arc::clone(&endpoints.authenticator);
    let tenant_for_auth = Arc::clone(&tenant);
    let clients_for_auth = scope.clients(endpoints.capabilities);

    par::push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            lifetime: endpoints.par_lifetime,
        },
        &headers,
        &body,
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
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);

    let now = time::OffsetDateTime::now_utc();
    let binding = match endpoints
        .dpop
        .check(
            &tenant,
            Endpoint::Token,
            &axum::http::Method::POST,
            &headers,
            now,
        )
        .await
    {
        Ok(binding) => binding,
        Err(refusal) => return refusal.into_response(),
    };

    let authenticator = Arc::clone(&endpoints.authenticator);
    let tenant_for_auth = Arc::clone(&tenant);
    let clients_for_auth = scope.clients(endpoints.capabilities);

    // The grant handler is built here, per request, rather than held on
    // `ClientEndpoints`. Two of the things it needs are facts about *this*
    // request — the instant it arrived and the DPoP key it proved — and
    // `GrantHandler::handle` receives neither. PAR solved the same problem the
    // same way, by computing the proof key at the edge and handing it down.
    let codes = scope.codes();
    let grants = scope.grants();
    let sessions = scope.sessions();
    let authorization_code = AuthorizationCode {
        codes: &codes,
        grants: &grants,
        sessions: &sessions,
        signer: endpoints.signer.as_ref(),
        proof_key: binding.as_ref().map(|binding| &binding.jkt),
        now,
    };

    let mut response = token::token(
        TokenContext {
            tenant: &tenant,
            clients: &clients,
            capabilities: endpoints.capabilities,
            grants: &[&authorization_code],
        },
        &headers,
        &body,
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
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    register::register(
        RegisterContext {
            tenant: &tenant,
            clients: &clients,
            capabilities: endpoints.capabilities,
            policy: &endpoints.registration,
            audit: endpoints.audit.as_ref(),
            request_id: Some(request_id.as_str()),
        },
        &headers,
        &body,
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
        capabilities: endpoints.capabilities,
        audit: endpoints.audit.as_ref(),
        request_id: Some(request_id.as_str()),
    }
}

/// `GET /register/{client_id}` — RFC 7592 §2.1.
async fn client_configuration_read(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    Path(client_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    client_configuration::read(
        &configuration_context(&endpoints, &tenant, &clients, &request_id),
        &client_id,
        &headers,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `PUT /register/{client_id}` — RFC 7592 §2.2.
async fn client_configuration_update(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    Path(client_id): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
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
}

/// `DELETE /register/{client_id}` — RFC 7592 §2.3.
async fn client_configuration_remove(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(request_id): Extension<crate::http::request_id::RequestId>,
    Path(client_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let clients = scope.clients(endpoints.capabilities);
    client_configuration::remove(
        &configuration_context(&endpoints, &tenant, &clients, &request_id),
        &client_id,
        &headers,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `GET /authorize` — RFC 9126 §4.
async fn authorization_endpoint(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    run_authorize(&endpoints, &tenant, &nonce, &pairs).await
}

/// `POST /authorize` — the same request, form-encoded.
async fn authorization_endpoint_form(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
    body: axum::body::Bytes,
) -> Response {
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(&body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    run_authorize(&endpoints, &tenant, &nonce, &pairs).await
}

/// The half both verbs share.
async fn run_authorize(
    endpoints: &ClientEndpoints,
    tenant: &Tenant,
    nonce: &asterius_web::csp::Nonce,
    pairs: &[(String, String)],
) -> Response {
    let scope = endpoints.store.scope(tenant.id.clone());
    let requests = scope.auth_requests();
    authorize::authorize(
        AuthorizeContext {
            tenant,
            requests: &requests,
            interactions: &requests,
            nonce,
        },
        pairs,
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
            codes: &codes,
            subjects: &users,
            code_lifetime: endpoints.code_lifetime,
            nonce: &nonce,
        },
        &id,
        &headers,
        time::OffsetDateTime::now_utc(),
    )
    .await
}

/// `POST /interaction/{id}`.
async fn interaction_submit(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Path(id): Path<String>,
    Extension(nonce): Extension<asterius_web::csp::Nonce>,
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
            codes: &codes,
            subjects: &users,
            code_lifetime: endpoints.code_lifetime,
            nonce: &nonce,
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
