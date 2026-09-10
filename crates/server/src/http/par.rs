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
    /// This tenant's registered resource servers (RFC 8707 §2.1).
    ///
    /// Consulted here rather than at the token endpoint alone, because this is
    /// where an authenticated client is on the connection: a `resource` this
    /// deployment does not serve is a mistake the client can fix now, and
    /// storing the request instead would mean the flow runs, the person signs
    /// in and consents, and the redemption then fails with `invalid_target`.
    pub resource_servers: &'a dyn asterius_domain::ResourceServerRepository,
    /// This tenant's registered authorization details types (RFC 9396 §2.1).
    ///
    /// Consulted here for the reason the resource server registry is: an
    /// `authorization_details` naming a type this deployment does not define,
    /// or an element that does not satisfy that type's schema, is a mistake the
    /// client can fix on this connection. Storing the request instead would
    /// mean the flow runs, the person is shown a consent page describing an
    /// authorization nobody can render, and the redemption then fails.
    pub authorization_details_types: &'a dyn asterius_domain::AuthorizationDetailsTypeRepository,
    /// This tenant's published and retired keys, for the `id_token_hint`.
    ///
    /// OIDC Core §3.1.2.1 says the hint "MUST be validated", and this is the
    /// endpoint where a validation can still be reported to the client that
    /// sent it rather than to a browser.
    pub keys: &'a dyn asterius_domain::KeyStore,
    /// What this tenant offers, as the request validator sees it.
    pub policy: authorize::AuthorizationPolicy,
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
    let request = match authorize::validate(
        &parameters,
        client.id.as_str(),
        &client.registration,
        context.policy,
    ) {
        Ok(request) => request,
        Err(failure) => {
            return error(
                StatusCode::BAD_REQUEST,
                failure.code(),
                &failure.to_string(),
            );
        }
    };

    // OIDC Core §3.1.2.1: an `id_token_hint` "MUST be validated". Here, while
    // the client that sent it is still on the connection — the browser that
    // arrives at `/authorize` later has no way to be told, and would meet a
    // request that could never be answered.
    let hinted_subject = match hinted_subject(&context, &client, &request, now).await {
        Ok(subject) => subject,
        Err(refusal) => return *refusal,
    };

    if let Some(refusal) = refuse_an_unservable_form_post(&request) {
        return refusal;
    }

    // RFC 8707 §3: "the authorization server MUST validate the resource
    // parameter". `authorize::validate` has checked its shape and the client's
    // own allow-list; what is left needs the registry, and so needs I/O.
    if let Some(refusal) = refuse_an_unregistered_resource(&context, &request).await {
        return refusal;
    }

    // RFC 9396 §3, the half `authorize::validate` could not do without I/O:
    // the type is one this tenant defines, and the element satisfies its
    // schema.
    if let Some(refusal) =
        refuse_an_unusable_authorization_detail(&context, &client, &request).await
    {
        return refusal;
    }

    // RFC 9449 §10.1 lets a client pin the authorization code to a DPoP key
    // either by sending a proof on this request or by naming the thumbprint in
    // `dpop_jkt`. Both spellings must be supported, and a request that uses
    // both and disagrees with itself does not name a key at all.
    let dpop_jkt =
        match crate::http::dpop::reconcile_par_key(proof_key, request.dpop_jkt.as_deref()) {
            Ok(jkt) => jkt,
            Err(refusal) => return refusal.into_response(),
        };

    stored(&context, &client, &request, hinted_subject, dpop_jkt, now).await
}

/// Stores the validated request and answers with its reference.
///
/// Split from [`push`] so that the endpoint reads as the sequence of checks it
/// is, and this reads as the one write it is.
///
/// # Errors
///
/// Never returns `Err`; every outcome is a `Response` (RFC 9126 §2.2 and §2.3).
async fn stored(
    context: &PushContext<'_>,
    client: &Client,
    request: &authorize::AuthorizationRequest,
    hinted_subject: Option<String>,
    dpop_jkt: Option<String>,
    now: OffsetDateTime,
) -> Response {
    // The reference. Minted after validation, so a rejected push leaves
    // nothing behind to expire.
    let minted = MintedRequestUri::generate();
    let expires_at = now + context.lifetime;
    let record = PushedRequest {
        tenant: context.tenant.id.clone(),
        request_uri_digest: minted.digest().to_owned(),
        client: client.id.clone(),
        parameters: serialise(request, hinted_subject.as_deref(), dpop_jkt.as_deref()),
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

/// Validates the `id_token_hint` and returns the subject it names.
///
/// OIDC Core §3.1.2.1: the parameter is an "ID Token previously issued by the
/// Authorization Server", and §2's rules about `aud` and `azp` say who it was
/// issued to. Three things must hold, and a request that breaks any of them is
/// refused rather than continued without the hint:
///
/// * it verifies against this tenant's keys, retired ones included, and is not
///   refused for being expired — `id_token_hint::verified_claims` is that half,
///   shared with the logout endpoint;
/// * its audience is **this** client, which the logout endpoint cannot check
///   because it is what the hint is being read *for*;
/// * it names a `sub`, which is the whole reason the parameter is read here.
///
/// Dropping a hint that fails would be the dangerous reading: the client asked
/// for an authorization *about a particular person*, and answering about
/// whoever happens to be signed in is exactly the confusion the parameter
/// exists to prevent.
///
/// `Ok(None)` when the request carried no hint, which is most requests.
///
/// # Errors
///
/// The RFC 6749 §5.2 error response to send instead of a `request_uri`.
async fn hinted_subject(
    context: &PushContext<'_>,
    client: &Client,
    request: &authorize::AuthorizationRequest,
    now: OffsetDateTime,
) -> Result<Option<String>, Box<Response>> {
    let Some(hint) = request.id_token_hint.as_deref() else {
        return Ok(None);
    };
    let refused = || {
        // One message for "did not verify", "for another client" and "no
        // subject". A client that could tell them apart could probe this
        // tenant's key set with tokens it did not receive.
        Box::new(error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "id_token_hint is not an ID token this server issued to this client",
        ))
    };
    let Some(claims) =
        crate::http::id_token_hint::verified_claims(context.keys, context.tenant, hint, now).await
    else {
        return Err(refused());
    };
    if !crate::http::id_token_hint::names_client(&claims, client.id.as_str()) {
        tracing::warn!(
            tenant = %context.tenant.id,
            "an id_token_hint issued to another client was pushed"
        );
        return Err(refused());
    }
    match crate::http::id_token_hint::subject(&claims) {
        Some(subject) => Ok(Some(subject.to_owned())),
        None => Err(refused()),
    }
}

/// Refuses `response_mode=form_post` for a callback no policy can name.
///
/// The page is served under `form-action 'self' <origin>`, and CSP Level 3
/// §2.3.1 builds `host-source` from `host-char = ALPHA / DIGIT / "-"` — so an
/// origin a URL parser is happy with may still be one a policy cannot spell,
/// an IPv6 literal being the case a client can actually register. Serving the
/// page anyway would mean a browser holding a form its own policy forbids it
/// to submit, with no error anywhere: the user waits, the client waits.
///
/// Refused here rather than at completion, which is the bead's own
/// recommendation, because here there is an authenticated client on the
/// connection to be told — half an hour before a user would have met the page.
///
/// `None` when the request is servable, which is every request that did not
/// ask for `form_post`.
fn refuse_an_unservable_form_post(request: &authorize::AuthorizationRequest) -> Option<Response> {
    if request.response_mode != authorize::ResponseMode::FormPost {
        return None;
    }
    let nameable = url::Url::parse(&request.redirect_uri)
        .ok()
        .as_ref()
        .and_then(crate::http::form_action_origin)
        .is_some();
    (!nameable).then(|| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "response_mode=form_post needs a redirect_uri whose origin a \
             content security policy can name",
        )
    })
}

/// Refuses a `resource` this tenant has not registered (RFC 8707 §2.1, §3).
///
/// The registry is read only when the request named a resource, so a tenant
/// that has registered none pays nothing for a feature its clients do not use.
///
/// A registry that cannot be read is `temporarily_unavailable` and not
/// `invalid_target`: "we cannot tell" must not be spelled like "you asked for
/// something that does not exist", or an outage looks to every client like the
/// operator withdrew their API.
///
/// `None` when the request may be stored, which is every request that named no
/// resource.
async fn refuse_an_unregistered_resource(
    context: &PushContext<'_>,
    request: &authorize::AuthorizationRequest,
) -> Option<Response> {
    if request.resources.is_empty() {
        return None;
    }
    let registered = match context.resource_servers.list().await {
        Ok(servers) => asterius_domain::ResourceRegistry::new(servers),
        Err(failure) => {
            tracing::error!(%failure, tenant = %context.tenant.id, "cannot read the resource server registry");
            return Some(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "the request could not be validated",
            ));
        }
    };
    request
        .resources
        .iter()
        .any(|resource| !registered.registers(resource))
        .then(|| {
            error(
                StatusCode::BAD_REQUEST,
                asterius_domain::InvalidTarget::CODE,
                "the resource parameter does not name a resource server this tenant serves",
            )
        })
}

/// Refuses an `authorization_details` this tenant cannot honour (RFC 9396 §3).
///
/// `authorize::validate` has already checked the shape, the limits and the
/// client's own §9.2 `authorization_details_types`. What is left needs the
/// registry, and so needs I/O: the type must be one this tenant has defined,
/// the element must satisfy that type's schema, and every §2.2 `locations`
/// value must be a resource server the client could actually be issued a token
/// for.
///
/// That last set is the intersection of the client's RFC 8707 allow-list and
/// this tenant's resource registry, computed here rather than taken from either
/// alone: a `locations` naming an API the client may not reach is an
/// authorization it could never exercise, and one naming an API this deployment
/// withdrew is an audience nothing answers to.
///
/// A registry that cannot be read is `temporarily_unavailable` and not
/// `invalid_authorization_details`, for the reason the resource check gives:
/// "we cannot tell" must not be spelled like "you asked for something that does
/// not exist".
///
/// `None` when the request may be stored, which is every request that carried
/// no `authorization_details`.
async fn refuse_an_unusable_authorization_detail(
    context: &PushContext<'_>,
    client: &Client,
    request: &authorize::AuthorizationRequest,
) -> Option<Response> {
    if request.authorization_details.is_empty() {
        return None;
    }
    let registry = match context.authorization_details_types.list().await {
        Ok(types) => asterius_domain::AuthorizationDetailsRegistry::new(types),
        Err(failure) => {
            tracing::error!(%failure, tenant = %context.tenant.id, "cannot read the authorization details type registry");
            return Some(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "the request could not be validated",
            ));
        }
    };

    // Only read when an element actually names a location, so a tenant whose
    // clients do not use `locations` pays nothing for the feature.
    let permitted_locations = if request.authorization_details.locations().is_empty() {
        std::collections::BTreeSet::new()
    } else {
        match context.resource_servers.list().await {
            Ok(servers) => {
                let registered = asterius_domain::ResourceRegistry::new(servers);
                client
                    .registration
                    .resources
                    .iter()
                    .filter(|resource| registered.registers(resource))
                    .cloned()
                    .collect()
            }
            Err(failure) => {
                tracing::error!(%failure, tenant = %context.tenant.id, "cannot read the resource server registry");
                return Some(error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "the request could not be validated",
                ));
            }
        }
    };

    registry
        .validate(
            &request.authorization_details,
            &client.registration.authorization_details_types,
            &permitted_locations,
        )
        .err()
        .map(|_| {
            error(
                StatusCode::BAD_REQUEST,
                asterius_domain::InvalidAuthorizationDetails::CODE,
                "the authorization_details parameter is not one this client may be authorized for",
            )
        })
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
fn serialise(
    request: &authorize::AuthorizationRequest,
    hinted_subject: Option<&str>,
    dpop_jkt: Option<&str>,
) -> serde_json::Value {
    json!({
        "client_id": request.client_id,
        "redirect_uri": request.redirect_uri,
        // What the response *is*, decided here and read at completion. A
        // handler that re-parsed `response_mode` from somewhere else would be
        // a second validator of the same parameter.
        "response_mode": request.response_mode.as_str(),
        "scopes": request.scopes,
        "code_challenge": request.code_challenge.as_str(),
        "state": request.state,
        "nonce": request.nonce,
        "prompts": request.prompts.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "max_age": request.max_age,
        "acr_values": request.acr_values,
        "login_hint": request.login_hint,
        // The *subject* the `id_token_hint` named, never the hint itself. The
        // token is a credential-shaped string with a signature on it and no
        // further use once it has been verified; what the decision at
        // `/authorize` needs is the one claim it was read for, and storing the
        // rest would be keeping somebody's ID token in a row that outlives the
        // connection it arrived on.
        "id_token_hint_sub": hinted_subject,
        "resources": request.resources,
        // The *reconciled* pin, never `request.dpop_jkt`. RFC 9449 §10.1 lets a
        // client pin the code by naming the thumbprint or by attaching a proof
        // to the push, and `reconcile_par_key` has already decided which key
        // that is. Storing the raw parameter here would drop the pin of every
        // client that used the header spelling: the code issuer builds the
        // binding from these parameters and never sees the column beside them,
        // so the code would be issued unpinned and the token endpoint would
        // have nothing to compare the presented proof against (`ast-36g`).
        "dpop_jkt": dpop_jkt,
        // The *parsed* request, canonically serialised, and not the document
        // the client sent. This is what will be copied onto the grant when the
        // user consents, and a grant records the decision: a member this
        // server declined to understand was no part of it, and storing the raw
        // document would leave one for a later reader to find.
        "claims": request.claims.to_json(),
        // OIDC Core §5.2. Stored with the authorization it was expressed in,
        // because the token request that follows carries no such parameter.
        "claims_locales": request.claims_locales.preferences(),
        // RFC 9396 §2, the *parsed* elements and not the document the client
        // sent, for the same reason `claims` is parsed: this is what will be
        // copied onto the grant when the user consents, and it has already been
        // held to its type's schema. `consent_memory` reads this member under
        // this name, so a request whose rich authorization is already covered
        // by a standing grant is not put in front of the user again.
        "authorization_details": request.authorization_details.to_json(),
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
