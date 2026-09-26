//! Tenant-routed SAML browser SSO for an already authenticated browser.
//!
//! The SP's signed AuthnRequest is verified against operator-pinned trust,
//! and its ID is reserved only after the browser session and account are
//! usable. A browser without a session receives a local refusal and can
//! authenticate before the SP retries; no untrusted request is carried through
//! a login redirect. Unsupported request controls such as ForceAuthn,
//! IsPassive and RequestedAuthnContext are rejected by the bounded parser.
//! The response can only post to the trusted ACS.

use crate::http::protocol::ClientEndpoints;
use crate::saml::{Assertion, IdpMetadata, sign_metadata};
use crate::saml_idp_signer::{SamlIdpSigner, validate_key_pair};
use crate::saml_validation::{SamlRequestValidator, ValidationError};
use asterius_domain::{SessionRepository as _, Tenant, UserId, UserStatus};
use asterius_web::Brand;
use asterius_web::pages::{FormPostPage, ResponseField, nonce_attribute};
use asterius_web::{Document, csp::Nonce};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use url::Url;

/// Tenant-relative metadata, mounted only alongside the live SSO route.
pub const METADATA_PATH: &str = "/saml/metadata";

/// Only these two bindings have live request verification and response paths.
pub fn routes(endpoints: Arc<ClientEndpoints>) -> Router {
    Router::new()
        .route("/saml/sso", get(redirect).post(post_form))
        .route(METADATA_PATH, get(metadata))
        .with_state(endpoints)
}

async fn metadata(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
) -> Response {
    let repository = endpoints
        .store
        .scope(tenant.id.clone())
        .saml_idp_keys(Arc::clone(&endpoints.kek));
    let active = match repository.load_for_signing().await {
        Ok(Some(active)) => active,
        Ok(None) => return refused(StatusCode::NOT_FOUND),
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot load SAML metadata signing key");
            return refused(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    if let Err(error) = validate_key_pair(&active.certificate_der, &active.private_key_pkcs8) {
        tracing::error!(%error, tenant = %tenant.id, "invalid SAML metadata signing key");
        return refused(StatusCode::SERVICE_UNAVAILABLE);
    }
    let published = match repository.published().await {
        Ok(published) => published,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot load SAML published certificates");
            return refused(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    if published.len() > 2
        || published.iter().filter(|key| key.state == "active").count() != 1
        || !published
            .iter()
            .any(|key| key.state == "active" && key.certificate_der == active.certificate_der)
    {
        tracing::error!(tenant = %tenant.id, "inconsistent SAML certificate rotation state");
        return refused(StatusCode::SERVICE_UNAVAILABLE);
    }
    let certificates = published
        .iter()
        .map(|key| key.certificate_der.as_slice())
        .collect::<Vec<_>>();
    let sso_url = format!("{}/saml/sso", tenant.issuer.as_str().trim_end_matches('/'));
    let document = match sign_metadata(
        &IdpMetadata {
            entity_id: tenant.issuer.as_str(),
            sso_url: &sso_url,
            signing_certificates_der: &certificates,
        },
        &active.private_key_pkcs8,
    ) {
        Ok(document) => document,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot sign SAML metadata");
            return refused(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                "application/samlmetadata+xml; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        document,
    )
        .into_response()
}

async fn redirect(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<Nonce>,
    mount: Option<Extension<crate::tenancy::MountPrefix>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(query) = uri.query() else {
        return refused(StatusCode::BAD_REQUEST);
    };
    issue(
        endpoints,
        tenant,
        nonce,
        mount,
        headers,
        Input::Redirect(query.to_owned()),
    )
    .await
}

async fn post_form(
    State(endpoints): State<Arc<ClientEndpoints>>,
    Extension(tenant): Extension<Arc<Tenant>>,
    Extension(nonce): Extension<Nonce>,
    mount: Option<Extension<crate::tenancy::MountPrefix>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > crate::saml_post::MAX_POST_BODY_BYTES {
        return refused(StatusCode::BAD_REQUEST);
    }
    let Some(content_type) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
    else {
        return refused(StatusCode::BAD_REQUEST);
    };
    issue(
        endpoints,
        tenant,
        nonce,
        mount,
        headers.clone(),
        Input::Post(content_type.to_owned(), body.to_vec()),
    )
    .await
}

enum Input {
    Redirect(String),
    Post(String, Vec<u8>),
}

async fn issue(
    endpoints: Arc<ClientEndpoints>,
    tenant: Arc<Tenant>,
    nonce: Nonce,
    mount: Option<Extension<crate::tenancy::MountPrefix>>,
    headers: HeaderMap,
    input: Input,
) -> Response {
    let now = OffsetDateTime::now_utc();
    let scope = endpoints.store.scope(tenant.id.clone());
    let cookies = crate::http::cookies(&headers);
    let Some(cookie) = asterius_web::interaction::cookie_value(
        &cookies,
        asterius_domain::entities::session::COOKIE_NAME,
    ) else {
        return refused(StatusCode::UNAUTHORIZED);
    };
    let digest = asterius_domain::sha256_hex(cookie.as_bytes());
    let session = match scope.sessions().find_for_browser(&digest, now).await {
        Ok(Some(session)) if session.tenant == tenant.id && session.status(now).is_usable() => {
            session
        }
        Ok(_) => return refused(StatusCode::UNAUTHORIZED),
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read SAML browser session");
            return refused(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let user = match scope
        .users(Arc::clone(&endpoints.kek))
        .find(UserId::new(session.user))
        .await
    {
        Ok(Some(user)) if user.status == UserStatus::Active => user,
        Ok(_) => return refused(StatusCode::UNAUTHORIZED),
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot read SAML account");
            return refused(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    if session.authenticated_at > now || session.amr.is_empty() {
        return refused(StatusCode::UNAUTHORIZED);
    }

    let validator = SamlRequestValidator::new(endpoints.store.clone());
    let request = match input {
        Input::Redirect(query) => validator.validate_redirect(&tenant, &query, now).await,
        Input::Post(content_type, body) => {
            validator
                .validate_post(&tenant, &content_type, &body, now)
                .await
        }
    };
    let request = match request {
        Ok(request) => request,
        Err(ValidationError::Refused) => return refused(StatusCode::BAD_REQUEST),
        Err(ValidationError::Store(error)) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot validate SAML request");
            return refused(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let expires_at = (now + Duration::minutes(5))
        .min(session.expires_at)
        .min(session.idle_expires_at);
    if expires_at <= now {
        return refused(StatusCode::UNAUTHORIZED);
    }
    let assertion_id = format!("_{}", uuid::Uuid::new_v4().simple());
    let response_id = format!("_{}", uuid::Uuid::new_v4().simple());
    let session_index = format!("_{}", session.public_sid);
    let subject = user.id.to_string();
    let assertion = Assertion {
        id: &assertion_id,
        issuer: tenant.issuer.as_str(),
        subject: &subject,
        audience: request.sp_entity_id(),
        recipient: request.acs_url(),
        in_response_to: request.request_id(),
        session_index: &session_index,
        authn_context_class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
        authenticated_at: session.authenticated_at,
        issued_at: now,
        expires_at,
    };
    let signed = match SamlIdpSigner::new(endpoints.store.clone(), Arc::clone(&endpoints.kek))
        .build_response(&tenant, &request, &response_id, &assertion)
        .await
    {
        Ok(xml) => xml,
        Err(error) => {
            tracing::error!(%error, tenant = %tenant.id, "cannot issue SAML response");
            return refused(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let Ok(acs) = Url::parse(request.acs_url()) else {
        return refused(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Some(origin) = crate::http::form_action_origin(&acs) else {
        return refused(StatusCode::SERVICE_UNAVAILABLE);
    };
    let mut fields = vec![ResponseField {
        name: "SAMLResponse".to_owned(),
        value: STANDARD.encode(signed),
    }];
    if let Some(relay) = request.relay_state() {
        let Ok(relay) = std::str::from_utf8(relay) else {
            return refused(StatusCode::BAD_REQUEST);
        };
        fields.push(ResponseField {
            name: "RelayState".to_owned(),
            value: relay.to_owned(),
        });
    }
    let mount = mount.map_or_else(crate::tenancy::MountPrefix::root, |Extension(mount)| mount);
    let font_url = crate::http::font_url(&mount);
    let document = Document::render(&nonce, |nonce| {
        asterius_web::pages::render(&FormPostPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &tenant.display_name,
            redirect_host: acs.host_str().unwrap_or_default(),
            action: request.acs_url(),
            fields,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .with_form_post_to(origin);
    document.into_response()
}

fn refused(status: StatusCode) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        "SAML request refused\n",
    )
        .into_response()
}
