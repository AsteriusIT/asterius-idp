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
//!
//! A handler renders its own OAuth errors, because they are statements about
//! the request it was given and nobody else can make them. What it cannot
//! render on its own is a failure of the *server*: [`not_issued`] is here for
//! those, so that "this deployment cannot sign for this client" reads the same
//! whichever grant hit it.

use asterius_domain::entities::client::GrantType;
use asterius_domain::keys::SigningAlgorithm;
use asterius_domain::{Capabilities, Client, ClientRepository, DomainError, Tenant};
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
    /// The client certificate this request arrived with (RFC 8705 §2), if the
    /// deployment saw one from a source it trusts.
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
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
        certificate: context.certificate,
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

pub(crate) fn no_store() -> [(header::HeaderName, header::HeaderValue); 2] {
    [
        (header::CACHE_CONTROL, HEADER_NO_STORE),
        (header::PRAGMA, HEADER_NO_CACHE),
    ]
}

/// An RFC 6749 §5.2 error a grant handler decided on.
///
/// Every code a *grant* can reach — `invalid_grant`, `invalid_request`,
/// `invalid_scope` — is a 400. `invalid_client` is the one §5.2 code with its
/// own status, and a handler never returns it: by the time one runs, the
/// client has authenticated. So the status is not a parameter, and a handler
/// cannot accidentally answer a bad code with a 200.
///
/// The description is `&'static str` for the same reason `description_for`
/// below is: it is written here, never assembled from the request.
#[must_use]
pub fn refused(code: &'static str, description: &'static str) -> Response {
    error(StatusCode::BAD_REQUEST, code, description)
}

/// The answer when a grant handler could not issue tokens.
///
/// A [`DomainError`] reaching here is the server's own fault. Everything a
/// client can get wrong at this endpoint — an unknown code, a PKCE verifier
/// that does not match, a `redirect_uri` that is not the one the
/// authorization request carried — is an RFC 6749 §5.2 `invalid_grant`, which
/// a handler renders itself because only it knows which check failed. What
/// reaches this function is the state of the deployment, and §5.2 defines no
/// code for that; both codes below are §4.1.2.1's, borrowed the way
/// [`crate::http::client_configuration`] already borrows them.
///
/// The split is whether retrying helps.
///
/// [`DomainError::NoSigningKey`] says it does not. The tenant holds no active
/// key of the algorithm this client registered as `id_token_signed_response_alg`
/// — which OpenID Connect Dynamic Client Registration 1.0 §2 turned into an
/// obligation on *this server* the moment it accepted that registration.
/// Nothing the client sends changes it and nothing in the system repairs it
/// unattended: an operator has to create the key or stop accepting the
/// registration (`ast-a05.13`). `temporarily_unavailable` would tell a
/// well-behaved client to come back and fail again, indefinitely, so this is
/// `server_error` and a 500.
///
/// Everything else is read as transient — a store that could not be reached —
/// and gets `temporarily_unavailable` and a 503, where retrying is the right
/// thing for the client to do.
///
/// Either way it is logged at error level with the tenant, the client and the
/// algorithm, because nothing else in the system will report it: the client is
/// handed a constant, and the operator whose configuration is wrong is not the
/// person making the request.
pub fn not_issued(tenant: &Tenant, client: &Client, failure: &DomainError) -> Response {
    let DomainError::NoSigningKey { algorithm } = failure else {
        tracing::error!(
            %failure,
            tenant = %tenant.id,
            client = %client.id,
            "a token request could not be served"
        );
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "the token request could not be served",
        );
    };

    tracing::error!(
        tenant = %tenant.id,
        client = %client.id,
        // `None` means any active key would have done and the tenant holds
        // none at all — a worse fault than one missing ES256 key, and it
        // should not read as the same line.
        algorithm = algorithm.map_or("none at all", SigningAlgorithm::as_str),
        "this tenant has no signing key this client can be issued tokens under"
    );
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "this deployment cannot sign tokens for this client",
    )
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
pub(crate) fn error(status: StatusCode, code: &str, description: &str) -> Response {
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
pub(crate) fn is_form_encoded(headers: &HeaderMap) -> bool {
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
