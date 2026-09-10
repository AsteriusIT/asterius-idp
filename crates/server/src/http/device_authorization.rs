//! `POST /device_authorization` — RFC 8628 §3.1 and §3.2.
//!
//! Where a device with no browser starts a flow. It hands back two codes: one
//! it polls the token endpoint with, and one a person types into a browser
//! somewhere else.
//!
//! # This endpoint authenticates its client, which is a deviation worth naming
//!
//! RFC 8628 §3.1 says the request is made "as described in Section 3.2.1 of
//! [RFC 6749]", which for the public clients the device flow was written for
//! means a bare `client_id` and no credential at all. FAPI 2.0 SP §5.3.2.1
//! item 3 withdraws that: an authorization server conforming to the profile
//! "shall only support confidential clients". This deployment follows the
//! profile — ADR-0002 already removed `client_secret_*` and `none` from every
//! endpoint — so a device flow here is for a *confidential* device: an agent
//! or an appliance holding a private key, authenticating with
//! `private_key_jwt` or mTLS through the same dispatch every other endpoint
//! uses.
//!
//! The consequence is deliberate and it is a narrowing: a smart television
//! shipped with no per-instance credential cannot use this endpoint. What it
//! buys is that §5.2's device-code brute forcing is bounded by an
//! authenticated caller rather than by entropy alone, and that a stolen device
//! code cannot be redeemed by anybody but the client it was issued to.
//!
//! # No `redirect_uri`, no PKCE, no `state`
//!
//! There is no authorization *response* in this flow — the device learns the
//! outcome by polling — so there is no redirect to protect, nothing to bind a
//! code verifier to and no browser round trip for a `state` to detect. What
//! replaces them is the pairing of two independently drawn codes plus the
//! confirmation step in the browser (§3.3.1, §5.4).
//!
//! [RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2.1

use asterius_domain::entities::client::GrantType;
use asterius_domain::{Client, ClientRepository, Tenant};
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::device as rfc8628;
use asterius_oidc::device::{MintedDeviceCode, UserCode};
use asterius_oidc::form::Parameters;
use asterius_store_pg::{NewDeviceAuthorization, PgDeviceCodeRepository};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, body::Bytes};
use serde_json::json;
use time::OffsetDateTime;

use crate::http::device as pages;

/// The largest form body this endpoint will read.
///
/// A device authorization request is a client assertion, a `scope` and
/// possibly an `authorization_details`. The same 16 KiB the pushed request
/// endpoint and the token endpoint allow, for the same reason: it covers a JWT
/// comfortably and refuses a megabyte somebody posted for fun.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// What the handler needs.
pub struct DeviceAuthorizationContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This tenant's clients.
    pub clients: &'a dyn ClientRepository,
    /// Where the authorization is recorded.
    pub device_codes: &'a PgDeviceCodeRepository,
    /// The client certificate this request arrived with (RFC 8705 §2), if the
    /// deployment saw one from a source it trusts.
    pub certificate: Option<&'a asterius_oidc::mtls::ClientCertificate>,
    /// The prefix routing removed from this request's path (`ast-295`), so the
    /// `verification_uri` names the URL the browser must actually reach.
    pub mount: crate::tenancy::MountPrefix,
}

impl std::fmt::Debug for DeviceAuthorizationContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuthorizationContext")
            .finish_non_exhaustive()
    }
}

/// How many times a user-code collision is retried before the request fails.
///
/// A ~34.5-bit space and a handful of outstanding authorizations make a
/// collision vanishingly unlikely, but "vanishingly" is not "never" and the
/// unique index refuses the second row rather than letting two flows share a
/// code. Three draws, then a `server_error`: a loop with no bound would turn a
/// tenant that had somehow filled its code space into a request that never
/// returns.
const COLLISION_RETRIES: usize = 3;

/// Handles a device authorization request.
///
/// # Errors
///
/// Never returns `Err`: every failure is a `Response` in the shape RFC 6749
/// §5.2 specifies, which is what RFC 8628 §3.2 refers to for errors.
pub async fn authorize(
    context: DeviceAuthorizationContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    authenticate: impl AsyncFnOnce(&Attempt<'_>, &AssertionRules) -> Result<Client, ClientAuthError>,
    now: OffsetDateTime,
) -> Response {
    if body.len() > MAX_BODY_BYTES {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "body too large",
        );
    }
    if !crate::http::token::is_form_encoded(headers) {
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
    // Pairs rather than a map: RFC 6749 §3.1 forbids a repeated parameter, and
    // a map would resolve one silently before anything could object.
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    // FAPI 2.0 SP §5.3.2.1 item 3, through the dispatch every other
    // client-authenticated endpoint uses. First, so that every later error is
    // one an authenticated client is entitled to see.
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
            return error(
                StatusCode::from_u16(failure.status()).unwrap_or(StatusCode::UNAUTHORIZED),
                failure.code(),
                "client authentication failed",
            );
        }
    };

    // RFC 6749 §5.2's `unauthorized_client`: "The authenticated client is not
    // authorized to use this authorization grant type." Checked here rather
    // than left to the token endpoint, because a device that is shown a code
    // and a URL by a server that will refuse the redemption ten minutes later
    // has sent a person to a browser for nothing.
    if !client.registration.allows(GrantType::DeviceCode) {
        return error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "this client may not use the device authorization grant",
        );
    }

    let params = Parameters::from_pairs(pairs);
    let request = match rfc8628::validate(&params, client.id.as_str(), &client.registration) {
        Ok(request) => request,
        Err(failure) => {
            tracing::debug!(
                error = %failure,
                client = %client.id,
                tenant = %context.tenant.id,
                "device authorization request refused"
            );
            return error(
                StatusCode::BAD_REQUEST,
                failure.code(),
                &failure.to_string(),
            );
        }
    };

    let expires_at = now + rfc8628::MAX_LIFETIME;
    let new = NewDeviceAuthorization {
        client_id: client.id.as_str().to_owned(),
        scopes: request.scopes.iter().cloned().collect(),
        authorization_details: serde_json::Value::Array(request.authorization_details.to_json()),
        expires_at,
        interval: rfc8628::POLL_INTERVAL,
    };

    let (minted, user_code) = match recorded(&context, &client, &new, now).await {
        Ok(codes) => codes,
        Err(refusal) => return *refusal,
    };

    // §3.2's two URIs. Absolute, because the device renders one on a screen
    // and a person types it into a browser that has no base to resolve
    // against — and built from the issuer, which already carries the mount
    // prefix a path-based tenant is reached under (`ast-295`).
    let verification_uri = format!("{}{}", context.tenant.issuer.as_str(), pages::PAGE_PATH);
    let displayed = user_code.formatted();
    // §3.3.1: the same URI with the code in it, so a device that can show a QR
    // code can spare the person the typing. The code is percent-encoded
    // although the alphabet needs none of it, because a URL built by
    // concatenation is a habit that outlives the alphabet that made it safe.
    let verification_uri_complete = format!(
        "{verification_uri}?user_code={}",
        url::form_urlencoded::byte_serialize(displayed.as_bytes()).collect::<String>()
    );

    (
        StatusCode::OK,
        crate::http::token::no_store(),
        Json(json!({
            "device_code": minted.expose(),
            "user_code": displayed,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": rfc8628::MAX_LIFETIME.whole_seconds(),
            "interval": rfc8628::POLL_INTERVAL.whole_seconds(),
        })),
    )
        .into_response()
}

/// Draws the two codes and records the authorization.
///
/// The device code is drawn once — 256 bits does not collide — and the user
/// code is redrawn on the unique-index violation that says two live
/// authorizations would otherwise share one, because the browser finds a row
/// by that code alone and a collision would put one person's approval on
/// another person's device.
///
/// # Errors
///
/// The `Response` to send instead, already in RFC 6749 §5.2's shape.
async fn recorded(
    context: &DeviceAuthorizationContext<'_>,
    client: &Client,
    new: &NewDeviceAuthorization,
    now: OffsetDateTime,
) -> Result<(MintedDeviceCode, UserCode), Box<Response>> {
    let minted = MintedDeviceCode::generate();
    for attempt in 0..COLLISION_RETRIES {
        let candidate = UserCode::generate();
        match context
            .device_codes
            .issue(minted.digest(), &candidate.digest(), new, now)
            .await
        {
            Ok(()) => return Ok((minted, candidate)),
            Err(asterius_domain::DomainError::Conflict(_)) if attempt + 1 < COLLISION_RETRIES => {}
            Err(failure) => {
                tracing::error!(
                    %failure,
                    client = %client.id,
                    tenant = %context.tenant.id,
                    "cannot record a device authorization"
                );
                return Err(Box::new(unavailable()));
            }
        }
    }
    tracing::error!(
        client = %client.id,
        tenant = %context.tenant.id,
        "three user codes in a row collided"
    );
    Err(Box::new(unavailable()))
}

/// What a device is told when this server could not record its request.
///
/// `temporarily_unavailable` and a 503: retrying is the right thing for the
/// device to do, and a `server_error` would tell it to stop.
fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "the device authorization could not be recorded",
    )
}

/// The first value of `name`, for client authentication only.
fn find<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// An RFC 6749 §5.2 error object, in the shape the token endpoint renders.
fn error(status: StatusCode, code: &str, description: &str) -> Response {
    crate::http::token::error(status, code, description)
}
