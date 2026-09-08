//! `POST /par` — the pushed authorization request endpoint (RFC 9126).
//!
//! The entry point of every flow this server runs, because ADR-0002 makes PAR
//! the only way to start one. Which makes this the place where an
//! authorization request stops being attacker-controlled input and becomes
//! something stored: it arrives over an authenticated connection, is validated
//! in full, and is exchanged for a reference that carries no information.
//!
//! # Why every failure here is a response and not a redirect
//!
//! RFC 6749 §4.1.2.1 draws the line: an error is redirected to the client's
//! `redirect_uri` *only* when that URI has been validated. At this endpoint it
//! frequently has not been — that may be the very thing that failed — and
//! there is no user agent to redirect anyway, because the client is talking to
//! us directly. So every path here returns a JSON error to the client, and
//! `Location` never appears. A PAR endpoint that redirected would be an open
//! redirector reachable before authentication.

use asterius_domain::{AuthRequestRepository, Client, ClientRepository, PushedRequest, Tenant};
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::form::Parameters;
use asterius_oidc::par::MintedRequestUri;
use asterius_oidc::{authorize, metadata::Endpoint};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, body::Bytes};
use serde_json::json;
use time::OffsetDateTime;

/// The largest form body this endpoint will read.
///
/// RFC 9126 §2.3 allows a 413. A pushed request is a few hundred bytes of
/// parameters plus whatever `claims` and `authorization_details` the client
/// sends; 16 KiB is generous for that and small enough that an unauthenticated
/// caller cannot make this server buffer meaningfully.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// What the handler needs to answer a push.
///
/// Deliberately not `Clone`-ing a database handle per request: the caller
/// holds the pool and hands out tenant-scoped repositories.
#[derive(Debug)]
pub struct PushContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This tenant's clients.
    pub clients: &'a dyn ClientRepository,
    /// This tenant's pushed requests.
    pub requests: &'a dyn AuthRequestRepository,
    /// How long a reference lives, already clamped by
    /// `asterius_oidc::par::clamp_lifetime`.
    pub lifetime: time::Duration,
}

/// Handles a pushed authorization request.
///
/// Returns the 201 body of RFC 9126 §2.2 on success, and an RFC 6749 §5.2
/// error object otherwise.
///
/// # Errors
///
/// Never returns `Err`: every failure is a `Response`, because RFC 9126 §2.3
/// specifies the error format and a client is entitled to it.
pub async fn push(
    context: PushContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    authenticate: impl AsyncFnOnce(&Attempt<'_>, &AssertionRules) -> Result<Client, ClientAuthError>,
    proof_key: Option<&asterius_domain::Kid>,
    now: OffsetDateTime,
) -> Response {
    if body.len() > MAX_BODY_BYTES {
        // RFC 9126 §2.3 names 413 for exactly this.
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "body too large",
        );
    }

    // `application/x-www-form-urlencoded`, and nothing else. RFC 9126 §2.1
    // says the request is posted as a form; accepting JSON as well would mean
    // two parsers with two chances to disagree about the same request.
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
    // Pairs, not a map: RFC 6749 §3.1 forbids a repeated parameter, and a map
    // would have silently resolved it before anything could object.
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    // FAPI 2.0 SP §5.3.2.2 item 4: a pushed request without client
    // authentication is rejected. Authentication comes first, so that every
    // later error is one an authenticated client is entitled to see.
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
            // The client is unauthenticated, so it learns the code and nothing
            // else. `WWW-Authenticate` is absent because this server accepts no
            // header-based scheme — see `ClientAuthError::status`.
            return error(
                StatusCode::from_u16(failure.status()).unwrap_or(StatusCode::UNAUTHORIZED),
                failure.code(),
                "client authentication failed",
            );
        }
    };

    // The request itself. Everything the client asked for is checked here,
    // once, while it is still a request and not yet a flow.
    let parameters = Parameters::from_pairs(pairs);
    let request = match authorize::validate(&parameters, client.id.as_str(), &client.registration) {
        Ok(request) => request,
        Err(failure) => {
            return error(
                StatusCode::BAD_REQUEST,
                failure.code(),
                &failure.to_string(),
            );
        }
    };

    // RFC 9449 §10.1 lets a client pin the authorization code to a DPoP key
    // either by sending a proof on this request or by naming the thumbprint in
    // `dpop_jkt`. Both spellings must be supported, and a request that uses
    // both and disagrees with itself does not name a key at all.
    let dpop_jkt =
        match crate::http::dpop::reconcile_par_key(proof_key, request.dpop_jkt.as_deref()) {
            Ok(jkt) => jkt,
            Err(refusal) => return refusal.into_response(),
        };

    // The reference. Minted after validation, so a rejected push leaves
    // nothing behind to expire.
    let minted = MintedRequestUri::generate();
    let expires_at = now + context.lifetime;
    let record = PushedRequest {
        tenant: context.tenant.id.clone(),
        request_uri_digest: minted.digest().to_owned(),
        client: client.id.clone(),
        parameters: serialise(&request),
        dpop_jkt,
        pushed_at: now,
        expires_at,
    };

    if let Err(failure) = context.requests.push(&record).await {
        tracing::error!(%failure, tenant = %context.tenant.id, "cannot store a pushed request");
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "the request could not be stored",
        );
    }

    // RFC 9126 §2.2: 201, with `request_uri` and `expires_in`.
    //
    // `no-store` because the body contains a credential. A cached 201 is a
    // `request_uri` handed to whoever asks next.
    (
        StatusCode::CREATED,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({
            "request_uri": minted.uri(),
            "expires_in": context.lifetime.whole_seconds(),
        })),
    )
        .into_response()
}

/// The path this endpoint is mounted at, from the one registry.
#[must_use]
pub const fn path() -> &'static str {
    Endpoint::PushedAuthorizationRequest.path()
}

/// The first value of `name`.
///
/// Returning the first is safe *here* only because `authorize::validate`
/// refuses a repeated parameter outright; this is used for client
/// authentication, which runs first, and a request that duplicated
/// `client_assertion` would be refused a moment later regardless.
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

/// The validated request, as the JSON that goes into `parameters`.
///
/// Written by hand rather than derived, so that adding a field to
/// [`authorize::AuthorizationRequest`] is a deliberate decision about what is
/// stored rather than an automatic one. The `code_challenge` is stored as the
/// string it is: it is a public value (RFC 7636 §4.2), and the verifier — the
/// secret half — never reaches this server until redemption.
fn serialise(request: &authorize::AuthorizationRequest) -> serde_json::Value {
    json!({
        "client_id": request.client_id,
        "redirect_uri": request.redirect_uri,
        "scopes": request.scopes,
        "code_challenge": request.code_challenge.as_str(),
        "state": request.state,
        "nonce": request.nonce,
        "prompts": request.prompts.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "max_age": request.max_age,
        "acr_values": request.acr_values,
        "login_hint": request.login_hint,
        "resources": request.resources,
        "dpop_jkt": request.dpop_jkt,
        "openid": request.openid,
    })
}

/// An RFC 6749 §5.2 error object.
///
/// `error_description` is written by this server, never echoed from the
/// request: an endpoint that quotes its input back is a reflection primitive,
/// and this one is reachable before authentication.
fn error(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({ "error": code, "error_description": description })),
    )
        .into_response()
}
