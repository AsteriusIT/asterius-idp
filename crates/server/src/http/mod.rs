//! HTTP transport: router assembly, middleware and the listener.

use asterius_web::FormActionOrigin;

pub mod authorization_code;
pub mod authorize;
pub mod client_configuration;
pub mod dpop;
pub mod forwarded;
pub mod interaction;
pub mod logout;
pub mod par;
pub mod protocol;
pub mod redirect;
pub mod register;
pub mod request_id;
pub mod security_headers;
pub mod server;
mod source_audit;
pub mod tls;
pub mod token;
pub mod userinfo;

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

pub use redirect::SeeOther;
pub use request_id::RequestId;
pub use server::{serve, shutdown_signal, with_middleware};
