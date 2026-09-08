//! `POST /token` — the token endpoint (RFC 6749 §3.2, OIDC Core §3.1.3).
//!
//! One handler for every grant. It authenticates the client, works out which
//! grant is being asked for, and hands the request to whichever handler owns
//! it. What is *not* delegated is the part that must be identical everywhere:
//! the transport rules, the error shape, and `Cache-Control: no-store`.
//!
//! That last one is the reason this file exists rather than six near-copies.
//! RFC 6749 §5.1 requires `no-store` on a *successful* token response, and a
//! response body holding an access token that a proxy is allowed to cache is
//! the token handed to whoever asks next. Applying it here means it cannot be
//! the one thing a new grant handler forgets.
//!
//! # Grant handlers
//!
//! A grant is implemented by a [`GrantHandler`] and registered with the
//! endpoint. A grant with no registered handler answers 501 rather than an
//! OAuth error: "this server does not implement that yet" is an honest thing
//! to say, and `unsupported_grant_type` would be a lie about a grant the
//! discovery document advertises.

use asterius_domain::entities::client::GrantType;
use asterius_domain::{Capabilities, Client, ClientRepository, Tenant};
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::form::Parameters;
use asterius_oidc::token::{self, TokenError};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, body::Bytes};
use serde_json::json;

/// The largest form body this endpoint will read.
///
/// A token request is small: a grant type, a code or refresh token, maybe a
/// resource indicator. Token exchange carries a subject token, which is the
/// only large one, and 16 KiB covers a JWT comfortably.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// One grant, implemented.
///
/// The trait exists so that the framework can be finished and tested before
/// any grant is: `ast-a05.2` and its siblings add implementations without
/// touching the dispatch, the error shape, or the caching rules.
#[async_trait::async_trait]
pub trait GrantHandler: Send + Sync {
    /// Which grant this handles.
    fn grant(&self) -> GrantType;

    /// Issues tokens, or fails.
    ///
    /// The client is already authenticated and already known to be permitted
    /// this grant, so a handler never has to re-check either.
    async fn handle(&self, tenant: &Tenant, client: &Client, params: &Parameters) -> Response;
}

/// What the handler needs.
pub struct TokenContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This tenant's clients.
    pub clients: &'a dyn ClientRepository,
    /// What this deployment offers.
    pub capabilities: Capabilities,
    /// The grant handlers this deployment has.
    pub grants: &'a [&'a dyn GrantHandler],
}

impl std::fmt::Debug for TokenContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenContext").finish_non_exhaustive()
    }
}

/// Handles a token request.
///
/// # Errors
///
/// Never returns `Err`: every failure is a `Response` in the shape RFC 6749
/// §5.2 specifies.
pub async fn token(
    context: TokenContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    authenticate: impl AsyncFnOnce(&Attempt<'_>, &AssertionRules) -> Result<Client, ClientAuthError>,
) -> Response {
    if body.len() > MAX_BODY_BYTES {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "body too large",
        );
    }
    if !is_form_encoded(headers) {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request",
            "content-type must be application/x-www-form-urlencoded",
        );
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "body is not UTF-8",
        );
    };

    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    // RFC 6749 §3.2: the client authenticates here. Everything after this is a
    // statement about a client that has proved who it is, which is what makes
    // `unauthorized_client` safe to return.
    let attempt = Attempt {
        assertion: find(&pairs, "client_assertion"),
        assertion_type: find(&pairs, "client_assertion_type"),
        client_id: find(&pairs, "client_id"),
        authorization_header: headers.contains_key(header::AUTHORIZATION),
        client_certificate: false,
    };
    let rules = AssertionRules::for_issuer(context.tenant.issuer.as_str());

    let client = match authenticate(&attempt, &rules).await {
        Ok(client) => client,
        Err(failure) => {
            let mapped = TokenError::ClientAuthentication {
                code: failure.code(),
                status: failure.status(),
            };
            return render(&mapped, "client authentication failed");
        }
    };

    let params = Parameters::from_pairs(pairs);
    let dispatch = match token::dispatch(&params, &client.registration, &context.capabilities) {
        Ok(dispatch) => dispatch,
        Err(failure) => {
            // The detail — which parameter was duplicated — goes to the log,
            // where an operator can act on it. The client gets a constant.
            // `TokenError`'s own `Display` names the parameter, and the
            // parameter name was chosen by whoever sent the request; putting
            // it in the response body would make this a reflection.
            tracing::debug!(
                error = %failure,
                client = %client.id,
                tenant = %context.tenant.id,
                "token request refused"
            );
            return render(&failure, description_for(&failure));
        }
    };

    let Some(handler) = context
        .grants
        .iter()
        .find(|handler| handler.grant() == dispatch.grant())
    else {
        // Advertised, permitted, and not built. 501 rather than an OAuth error
        // for the same reason the other unbuilt endpoints answer 501: the
        // client did nothing wrong, and telling it otherwise sends it looking
        // for a fault it does not have.
        return (
            StatusCode::NOT_IMPLEMENTED,
            no_store(),
            Json(json!({
                "error": "temporarily_unavailable",
                "error_description": "this grant type is not implemented yet",
            })),
        )
            .into_response();
    };

    let mut response = handler.handle(context.tenant, &client, &params).await;

    // RFC 6749 §5.1, applied here rather than trusted to each handler. A
    // successful token response that a cache may keep is an access token
    // served to the next person who asks for the same URL.
    let response_headers = response.headers_mut();
    response_headers.insert(header::CACHE_CONTROL, HEADER_NO_STORE);
    response_headers.insert(header::PRAGMA, HEADER_NO_CACHE);
    response
}

const HEADER_NO_STORE: header::HeaderValue = header::HeaderValue::from_static("no-store");
const HEADER_NO_CACHE: header::HeaderValue = header::HeaderValue::from_static("no-cache");

fn no_store() -> [(header::HeaderName, header::HeaderValue); 2] {
    [
        (header::CACHE_CONTROL, HEADER_NO_STORE),
        (header::PRAGMA, HEADER_NO_CACHE),
    ]
}

/// The client-facing description of a failure.
///
/// A constant per variant. RFC 6749 §5.2 makes `error_description` optional
/// and human-readable; it does not make it a place to put the request back.
const fn description_for(failure: &TokenError) -> &'static str {
    match failure {
        TokenError::DuplicateParameter(_) => "a parameter was sent more than once",
        TokenError::MissingGrantType => "grant_type is required",
        TokenError::MalformedRequest => "the request is not well formed",
        TokenError::UnsupportedGrantType => "unsupported grant type",
        TokenError::UnauthorizedClient => "this client may not use that grant type",
        TokenError::ClientAuthentication { .. } => "client authentication failed",
        // `TokenError` is `#[non_exhaustive]`, so a new variant compiles
        // rather than breaking the build. It gets a vague description, which
        // is the safe direction to fail in: a description is a courtesy, and
        // the `error` code beside it is the part a client acts on.
        _ => "the request could not be processed",
    }
}

/// Renders a [`TokenError`] in the shape of RFC 6749 §5.2.
fn render(failure: &TokenError, description: &str) -> Response {
    error(
        StatusCode::from_u16(failure.status()).unwrap_or(StatusCode::BAD_REQUEST),
        failure.code(),
        description,
    )
}

/// An RFC 6749 §5.2 error object.
///
/// `error_description` is written here, never echoed from the request. The
/// specification also restricts it to a printable ASCII subset, so anything
/// outside that is dropped rather than sent — a description is a courtesy, and
/// not one worth breaking a client's parser for.
fn error(status: StatusCode, code: &str, description: &str) -> Response {
    let description: String = description
        .chars()
        .filter(|c| matches!(c, ' '..='~') && *c != '"' && *c != '\\')
        .take(256)
        .collect();
    (
        status,
        no_store(),
        Json(json!({ "error": code, "error_description": description })),
    )
        .into_response()
}

/// The first value of `name`, for client authentication only.
fn find<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Whether the request is a form post, ignoring any charset parameter.
fn is_form_encoded(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|kind| {
                kind.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        })
}
