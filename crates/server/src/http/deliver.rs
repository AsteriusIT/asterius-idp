//! Sending an authorization response to the client, in the mode it asked for.
//!
//! One authorization request produces exactly one of two shapes: a 303 with the
//! parameters in the `redirect_uri`'s query (OAuth 2.0 Multiple Response Type
//! Encoding Practices §2.1, the default for `response_type=code`), or a page
//! the browser posts to that URI (OAuth 2.0 Form Post Response Mode §2). Which
//! one was decided at the push and stored; `ast-gxh.5` is where that decision
//! came from.
//!
//! This module is the *only* place either is built. It exists because there are
//! now two callers — the interaction, which delivers a code or an
//! `access_denied` after the user has decided, and `/authorize`, which
//! delivers an OIDC Core §3.1.2.6 error before anything has been shown — and a
//! second implementation of "how a `form_post` page is served" is exactly the
//! kind of duplication that ends with one of the two forgetting the
//! `form-action` origin, or the `no-store`, or the nonce.
//!
//! # What a caller still owns
//!
//! The response body is built here; the cookies are not. The interaction has a
//! credential to clear and `/authorize` has none, and a module that guessed
//! would either leave a spent cookie in a browser or clear one that is still
//! needed.

use crate::http::form_action_origin;
use crate::http::redirect::SeeOther;
use asterius_domain::Tenant;
use asterius_oidc::authorize::ResponseMode;
use asterius_oidc::code::AuthorizationResponse;
use asterius_web::Brand;
use asterius_web::pages::{FormPostPage, ResponseField, nonce_attribute};
use asterius_web::{Document, csp::Nonce};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

/// Why an authorization response could not be delivered.
///
/// Both variants are unreachable through a request this server accepted: the
/// `redirect_uri` was parsed and matched against the client's registration at
/// the push, and `http::par` refuses `response_mode=form_post` for a callback
/// no content security policy can name. They exist so that the impossible case
/// is *refused* rather than silently downgraded — a client that asked for a
/// POST and received a query response has been answered in a mode it did not
/// ask for, and its own security analysis is now wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Undeliverable {
    /// The stored `redirect_uri` will not parse, or will not take parameters.
    #[error("the redirect URI cannot carry this response")]
    Unusable,
    /// `form_post` to an origin a `form-action` source expression cannot name.
    #[error("no content security policy can name this callback's origin")]
    Unnameable,
}

/// Builds the response that carries `response` to `redirect_uri`.
///
/// # Errors
///
/// [`Undeliverable`] for a callback this server cannot answer at all. The
/// caller renders its own error page: the two callers are at different points
/// in the flow and have different things to say.
pub fn build(
    tenant: &Tenant,
    nonce: &Nonce,
    mount: &crate::tenancy::MountPrefix,
    mode: ResponseMode,
    response: &AuthorizationResponse,
    redirect_uri: &str,
) -> Result<Response, Undeliverable> {
    match mode {
        ResponseMode::Query => query(response, redirect_uri),
        ResponseMode::FormPost => form_post(tenant, nonce, mount, response, redirect_uri),
    }
}

/// The 303.
///
/// Through [`SeeOther`], never open-coded: `http::source_audit` enforces that,
/// and it is right to — 303 is the status FAPI 2.0 SP §5.3.2.2 items 10–11
/// leave available, and the helper is also where response splitting through a
/// `Location` is refused.
fn query(response: &AuthorizationResponse, redirect_uri: &str) -> Result<Response, Undeliverable> {
    let location = response
        .redirect_url(redirect_uri)
        .map_err(|_| Undeliverable::Unusable)?;
    let see_other = SeeOther::to(&location).map_err(|_| Undeliverable::Unusable)?;

    let mut response = see_other.into_response();
    // The URL in this header carries an authorization code, or the fact that a
    // particular person could not be authenticated. Neither belongs in a cache.
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// The self-submitting form (OAuth 2.0 Form Post Response Mode §2).
///
/// The parameters are the same ones the query mode would put in the URL —
/// [`AuthorizationResponse::query`] produces both — and they travel as hidden
/// inputs in a form whose action is the client's registered `redirect_uri`.
///
/// Three things are true of this response and none of them is set here.
/// `Cache-Control: no-store` and the policy come from the document middleware,
/// which is the only place that writes either; the nonce on the auto-submit
/// script is the one that middleware drew, because [`Document::render`] is the
/// only way to build the page and it takes the nonce. What *is* set here is the
/// one origin `form-action` may name, and it comes from the `redirect_uri` this
/// authorization was validated against at push time — never from a parameter of
/// the request being answered.
fn form_post(
    tenant: &Tenant,
    nonce: &Nonce,
    mount: &crate::tenancy::MountPrefix,
    response: &AuthorizationResponse,
    redirect_uri: &str,
) -> Result<Response, Undeliverable> {
    // Where this page fetches its face, under the prefix routing removed
    // (`ast-vn7`). This one is a `form_post` response and posts to the client,
    // but it is still a page of *this* server and draws itself in its face.
    let font_url = crate::http::font_url(mount);
    let url = url::Url::parse(redirect_uri).map_err(|_| Undeliverable::Unusable)?;
    let origin = form_action_origin(&url).ok_or(Undeliverable::Unnameable)?;
    let action = response
        .form_action(redirect_uri)
        .map_err(|_| Undeliverable::Unusable)?;

    let fields = response
        .query()
        .into_iter()
        .map(|(name, value)| ResponseField {
            name: name.to_owned(),
            value,
        })
        .collect();
    let document = Document::render(nonce, |nonce| {
        asterius_web::pages::render(&FormPostPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &tenant.display_name,
            redirect_host: url.host_str().unwrap_or_default(),
            action: &action,
            fields,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .with_form_post_to(origin);

    Ok(document.into_response())
}
