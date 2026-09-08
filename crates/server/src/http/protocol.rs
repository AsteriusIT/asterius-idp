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
use crate::http::par::{self, PushContext};
use crate::http::token::{self, TokenContext};
use asterius_domain::{Capabilities, KeyStore, Tenant};
use asterius_oidc::client_auth::{AssertionRules, Attempt};
use asterius_oidc::metadata::{self, Endpoint};
use axum::extract::{Extension, State};
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
                post(token_endpoint).with_state(endpoints),
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
                    Endpoint::PushedAuthorizationRequest | Endpoint::Token
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
                .authenticate(
                    &tenant_for_auth,
                    &clients_for_auth,
                    attempt,
                    rules,
                    time::OffsetDateTime::now_utc(),
                )
                .await
        },
        time::OffsetDateTime::now_utc(),
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

    let authenticator = Arc::clone(&endpoints.authenticator);
    let tenant_for_auth = Arc::clone(&tenant);
    let clients_for_auth = scope.clients(endpoints.capabilities);

    token::token(
        TokenContext {
            tenant: &tenant,
            clients: &clients,
            capabilities: endpoints.capabilities,
            grants: &[],
        },
        &headers,
        &body,
        async |attempt: &Attempt<'_>, rules: &AssertionRules| {
            authenticator
                .authenticate(
                    &tenant_for_auth,
                    &clients_for_auth,
                    attempt,
                    rules,
                    time::OffsetDateTime::now_utc(),
                )
                .await
        },
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
