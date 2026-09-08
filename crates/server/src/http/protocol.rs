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

use asterius_domain::{Capabilities, KeyStore, Tenant};
use asterius_oidc::metadata::{self, Endpoint};
use axum::extract::{Extension, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
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
    let mut router = Router::new()
        // OIDC Discovery §4 and RFC 8414 §3. Both forms of the URL are
        // normalised to these paths by the tenancy middleware, so one route
        // serves the path-appended and path-inserted spellings.
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/oauth-authorization-server", get(discovery))
        .route(Endpoint::Jwks.path(), get(jwks))
        .with_state(state);

    // Everything else exists but is not built yet. Mounted from the registry so
    // that the parity test — and a client reading the document — find a route
    // rather than a 404.
    for endpoint in Endpoint::enabled(&capabilities) {
        if endpoint == Endpoint::Jwks {
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
