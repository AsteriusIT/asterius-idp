//! HTTP transport: router assembly, middleware and the listener.

use asterius_web::FormActionOrigin;
use axum::http::{HeaderMap, header};

/// Where a page fetches the typeface, under the prefix routing removed.
///
/// One helper rather than the expression repeated at each of the nineteen
/// places a page is rendered: `asterius_web::brand::font_path` is what the
/// route in [`assets`] is mounted at, and `MountPrefix::absolute` is what puts
/// a page under `/t/{tenant}` back on it (`ast-295`). A site that wrote one
/// without the other would serve a page whose `@font-face` 404s — visibly
/// wrong only on a path-based tenant, which is the kind of bug that ships.
#[must_use]
pub fn font_url(mount: &crate::tenancy::MountPrefix) -> String {
    mount.absolute(asterius_web::brand::font_path())
}

pub mod access_evaluation;
pub mod access_search;
pub mod access_token;
pub mod account;
pub mod account_grants;
pub mod account_passkeys;
pub mod account_password;
pub mod account_sessions;
pub mod approvals;
pub mod assets;
pub mod authorization_code;
pub mod authorize;
pub mod backchannel_authentication;
pub mod ciba_grant;
pub mod client_configuration;
pub mod client_credentials;
pub mod console;
pub mod deliver;
pub mod device;
pub mod device_authorization;
pub mod device_code;
pub mod dpop;
pub mod forwarded;
pub mod grant_management;
pub mod i18n;
pub mod id_token_hint;
pub mod interaction;
pub mod issuance;
pub mod limits;
pub mod logout;
pub mod par;
pub mod passkeys;
pub mod protocol;
pub mod recovery;
pub mod redirect;
pub mod refresh;
pub mod register;
pub mod request_id;
pub mod request_object;
pub mod revocation;
pub mod security_headers;
pub mod server;
pub mod signup;
pub mod software_statement;
mod source_audit;
pub mod ssf;
pub mod ssf_management;
pub mod ssf_poll;
pub mod step_up;
pub mod throttle;
pub mod tls;
pub mod token;
pub mod token_exchange;
pub mod userinfo;
pub mod verify_email;

/// The one origin a page of this server's may submit to, other than itself.
///
/// Two callers, and they are the two pages whose submission ends up at the
/// client. The consent screen: a browser applies `form-action` to the
/// *redirects* of a submission and not only to its action, so a consent screen
/// served under `form-action 'self'` cannot deliver the 303 that carries the
/// authorization code to a client on another origin (`ast-jsq`). The
/// `response_mode=form_post` page: its form posts straight there
/// (`ast-gxh.5`).
///
/// Shared rather than written twice, because the rule is the same one and it
/// is the rule that matters: the widening is exactly one origin — the one
/// belonging to the `redirect_uri` this authorization was validated against
/// (ADR-0005) — never a raw query parameter, and never the client's whole
/// registered set, which may span several origins.
///
/// `None` for anything a CSP `host-source` cannot express, which is a private
/// scheme callback: for the consent screen that navigation leaves the browser
/// rather than happening inside it, so the strict policy stays; for a
/// `form_post` response there is nothing a browser could post to at all, which
/// is why `par` refuses the combination at the push.
pub(crate) fn form_action_origin(redirect_uri: &url::Url) -> Option<FormActionOrigin> {
    // `Origin::ascii_serialization` is `scheme://host[:port]` with a default
    // port omitted, which is the canonical spelling `FormActionOrigin` accepts;
    // an opaque origin serialises to `null`, which it refuses.
    FormActionOrigin::parse(&redirect_uri.origin().ascii_serialization()).ok()
}

/// Every `Cookie` header the request carries, joined into one list.
///
/// Not `HeaderMap::get`. HTTP/2 permits a cookie list to be split across
/// several `cookie` fields — RFC 9113 §8.2.3 says a user agent MAY do it and
/// that a server MUST join them before parsing — and Chromium does, so `get`
/// returns whichever cookie happened to be sent first. That is a bug with no
/// symptom until two `__Host-` cookies exist at once, which is every page this
/// server serves to a signed-in user mid-flow: the interaction cookie arrives
/// first and the session cookie is silently missed, so the user is told they
/// are not signed in (`ast-bze`).
///
/// Shared by the three readers — the interaction resume, the logout handler
/// and the passkey page — because the mistake is the same one at each and one
/// site left behind is the whole bug still present.
pub(crate) fn cookies(headers: &HeaderMap) -> String {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ")
}

pub use redirect::SeeOther;
pub use request_id::RequestId;
pub use server::{serve, shutdown_signal, with_middleware};

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    /// RFC 9113 §8.2.3: the list may arrive split, and the server joins it
    /// before parsing. `HeaderMap::get` would have returned the first field
    /// only, which is the whole of `ast-bze`.
    #[test]
    fn cookie_fields_split_across_http2_frames_are_joined() {
        // Arrange
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("first=one"));
        headers.append(header::COOKIE, HeaderValue::from_static("second=two"));

        // Act
        let joined = cookies(&headers);

        // Assert
        assert_eq!(joined, "first=one; second=two");
    }

    /// A request with no cookie at all is an empty list, not a stray separator
    /// a parser would read as an empty pair.
    #[test]
    fn no_cookie_field_is_an_empty_list() {
        // Arrange
        let headers = HeaderMap::new();

        // Act
        let joined = cookies(&headers);

        // Assert
        assert_eq!(joined, "");
    }
}
