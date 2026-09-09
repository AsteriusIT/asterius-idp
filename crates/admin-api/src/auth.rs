//! The two authentication modes, and the one place a request passes through.
//!
//! ADR-0009 settles the first: the console is a first-party same-origin app
//! authenticated by the `__Host-asterius_session` cookie, and **no OAuth token
//! reaches the browser**. The second is automation — a DPoP-bound access token
//! from an admin client (RFC 6749 §4.4, RFC 9449 §7).
//!
//! # Which mode a request is in is decided by what it presents, once
//!
//! An `Authorization` header means automation; otherwise the cookie. Deciding
//! once, here, is what makes the CSRF rule stateable: **a session-authenticated
//! mutation requires `X-CSRF-Token`, and a token-authenticated one does not**.
//! The asymmetry is not laxness — a bearer `Authorization` header is not
//! attached by a browser to a cross-site request, so there is no ambient
//! credential to forge with, which is the whole content of RFC 9700 §4.7. What
//! a token call requires instead is the DPoP proof, which binds it to a key
//! and to this method and URL.
//!
//! A request presenting *both* is refused rather than resolved. It is a shape
//! no legitimate caller produces, and choosing one credential over the other
//! would be a place where the choice could be made differently later.
//!
//! # The order of the checks is the order of their cost
//!
//! Rate limit, then origin, then credential, then CSRF, then authority. An
//! unauthenticated caller must not be able to make this server do a database
//! read per request, and an authority check on a principal that does not exist
//! is a check on nothing.

use asterius_domain::entities::session::COOKIE_NAME;
use asterius_domain::entities::session::SessionId;
use asterius_domain::{SessionStatus, Tenant, TenantId, UserId};
use axum::http::{HeaderMap, header};

use crate::backend::{AdminBackend, AdminTokens, PresentedToken, TokenPrincipal};
use crate::error::AdminError;
use crate::rbac::Held;

/// Who is making a request, once resolved.
#[derive(Debug, Clone)]
pub enum Principal {
    /// The console, holding a session cookie.
    Console {
        /// The tenant the session belongs to.
        tenant: TenantId,
        /// The signed-in user.
        user: UserId,
        /// The session id as presented, kept so the CSRF token can be compared
        /// against it and never stored anywhere.
        session_id: String,
        /// The authority the user was found to hold.
        held: Held,
    },
    /// An automation client, holding a DPoP-bound access token.
    Automation {
        /// What the audit trail records.
        subject: String,
        /// The authority the token was found to carry.
        held: Held,
    },
}

impl Principal {
    /// The authority this principal holds.
    #[must_use]
    pub const fn held(&self) -> &Held {
        match self {
            Self::Console { held, .. } | Self::Automation { held, .. } => held,
        }
    }

    /// The string [`asterius_domain::Actor::Admin`] carries.
    ///
    /// ADR-0009 and ADR-0010 both say this is a **user** identifier and not a
    /// client identifier, which is why the console arm returns the user's uuid
    /// rather than anything about the browser.
    #[must_use]
    pub fn audit_actor(&self) -> String {
        match self {
            Self::Console { user, .. } => user.as_uuid().to_string(),
            Self::Automation { subject, .. } => subject.clone(),
        }
    }

    /// Whether this principal is subject to the CSRF check.
    ///
    /// True for the console — an ambient cookie — and false for a token, whose
    /// `Authorization` header a browser never attaches cross-site.
    #[must_use]
    pub const fn needs_csrf(&self) -> bool {
        matches!(self, Self::Console { .. })
    }
}

/// The credential a request carried, before it was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presented<'a> {
    Cookie(&'a str),
    Token { token: &'a str, proof: &'a str },
    Nothing,
}

/// Reads the credential out of the headers.
///
/// # Errors
///
/// [`AdminError::InvalidToken`] when an `Authorization` header is present but
/// is not a usable `DPoP` presentation: a `Bearer` token (FAPI 2.0 SP requires
/// sender-constrained tokens, and RFC 9449 §7.1 gives them their own scheme),
/// a `DPoP` presentation with no proof header, or both credential kinds at
/// once.
fn presented<'a>(headers: &'a HeaderMap, cookies: &'a str) -> Result<Presented<'a>, AdminError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let cookie = session_cookie(cookies);

    match (authorization, cookie) {
        // A caller holding both has not decided which credential it is using,
        // and neither should this server.
        (Some(_), Some(_)) => Err(AdminError::InvalidToken),
        (Some(raw), None) => {
            // RFC 9449 §7.1: the scheme is `DPoP`, not `Bearer`. A `Bearer`
            // presentation is refused rather than accepted-without-a-proof,
            // which would be the whole sender-constraint gone.
            let token = raw
                .strip_prefix("DPoP ")
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .ok_or(AdminError::InvalidToken)?;
            let proof = headers
                .get("dpop")
                .and_then(|value| value.to_str().ok())
                .filter(|proof| !proof.is_empty())
                .ok_or(AdminError::InvalidToken)?;
            Ok(Presented::Token { token, proof })
        }
        (None, Some(id)) => Ok(Presented::Cookie(id)),
        (None, None) => Ok(Presented::Nothing),
    }
}

/// The session cookie's value, out of a joined cookie list.
///
/// The list is joined by the caller for the RFC 9113 §8.2.3 reason
/// `asterius_server::http::cookies` documents: HTTP/2 may split it, and
/// reading only the first field silently misses the session whenever two
/// `__Host-` cookies are in flight.
fn session_cookie(cookies: &str) -> Option<&str> {
    cookies
        .split(';')
        .map(str::trim)
        .find_map(|pair| {
            pair.strip_prefix(COOKIE_NAME)
                .and_then(|rest| rest.strip_prefix('='))
        })
        .filter(|value| !value.is_empty())
}

/// What one request needs to be authenticated.
#[derive(Debug, Clone, Copy)]
pub struct Credentials<'a> {
    /// Every `Cookie` field, already joined.
    pub cookies: &'a str,
    /// The request's method, for the DPoP proof's `htm`.
    pub method: &'a str,
    /// The request's absolute URL, for the proof's `htu`.
    pub url: &'a str,
}

/// Resolves whoever is making this request.
///
/// `tenant` is the tenant the request was routed to, which for a session is
/// the tenant whose store the cookie is looked up in: sessions are per tenant
/// (ADR-0010 keeps `Session::tenant` non-optional), so a cookie minted in one
/// tenant simply does not resolve in another's.
///
/// # Errors
///
/// [`AdminError::Unauthenticated`] when nothing was presented,
/// [`AdminError::SessionUnusable`] when a cookie resolved to a session that is
/// expired, idle or revoked, and [`AdminError::InvalidToken`] when a token was
/// presented and is not one this server will act on.
pub async fn authenticate(
    backend: &dyn AdminBackend,
    tokens: Option<&dyn AdminTokens>,
    tenant: &Tenant,
    headers: &HeaderMap,
    credentials: Credentials<'_>,
) -> Result<Principal, AdminError> {
    match presented(headers, credentials.cookies)? {
        Presented::Nothing => Err(AdminError::Unauthenticated),
        Presented::Cookie(id) => console(backend, tenant, id).await,
        Presented::Token { token, proof } => {
            // Not yet buildable: `ast-a05.8` mints the tokens this would
            // resolve. Refusing is the honest answer — accepting a token
            // nothing verified would be the opposite of what the mode is for.
            let Some(tokens) = tokens else {
                return Err(AdminError::InvalidToken);
            };
            automation(
                tokens,
                &PresentedToken {
                    token,
                    proof,
                    method: credentials.method,
                    url: credentials.url,
                },
            )
            .await
        }
    }
}

async fn console(
    backend: &dyn AdminBackend,
    tenant: &Tenant,
    id: &str,
) -> Result<Principal, AdminError> {
    let presented = SessionId::from_presented(id.to_owned());
    let session = backend
        .session(&tenant.id, &presented.digest())
        .await
        .map_err(|error| AdminError::from_storage("admin.session", &error))?
        .ok_or(AdminError::SessionUnusable)?;

    // Every non-`Active` state is one 401: idle, expired and revoked are the
    // same instruction to a console — sign in again — and distinguishing them
    // to an anonymous caller says which cookies were once real.
    if !matches!(session.status(now()), SessionStatus::Active) {
        return Err(AdminError::SessionUnusable);
    }

    let user = UserId::new(session.user);
    let roles = backend
        .roles(&tenant.id, user)
        .await
        .map_err(|error| AdminError::from_storage("admin.roles", &error))?;

    Ok(Principal::Console {
        tenant: tenant.id.clone(),
        user,
        session_id: id.to_owned(),
        held: Held::Roles {
            tenant: tenant.id.clone(),
            roles,
        },
    })
}

async fn automation(
    tokens: &dyn AdminTokens,
    presented: &PresentedToken<'_>,
) -> Result<Principal, AdminError> {
    let resolved = tokens
        .resolve(presented)
        .await
        .map_err(|error| AdminError::from_storage("admin.token", &error))?
        .ok_or(AdminError::InvalidToken)?;

    let TokenPrincipal {
        subject,
        tenant,
        scopes,
    } = resolved;

    Ok(Principal::Automation {
        subject,
        held: Held::Scopes { tenant, scopes },
    })
}

/// The wall clock, for the session's two deadlines.
fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_with_nothing_presents_nothing() {
        assert_eq!(
            presented(&HeaderMap::new(), "").expect("no credential"),
            Presented::Nothing
        );
    }

    #[test]
    fn the_session_cookie_is_found_among_others() {
        // Arrange
        let cookies = format!("other=1; {COOKIE_NAME}=the-id; another=2");

        // Act / Assert
        assert_eq!(session_cookie(&cookies), Some("the-id"));
    }

    /// The `__Host-` prefix is part of the name, so a cookie without it is a
    /// different cookie and not this one.
    #[test]
    fn a_cookie_without_the_host_prefix_is_not_the_session() {
        assert_eq!(session_cookie("asterius_session=the-id"), None);
    }

    #[test]
    fn an_empty_session_cookie_is_no_cookie() {
        assert_eq!(session_cookie(&format!("{COOKIE_NAME}=")), None);
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                *name,
                axum::http::HeaderValue::from_str(value).expect("a header value"),
            );
        }
        map
    }

    /// FAPI 2.0 SP wants sender-constrained tokens and RFC 9449 §7.1 gives
    /// them their own scheme. A `Bearer` presentation is a token with no
    /// proof, and accepting one would remove the constraint entirely.
    #[test]
    fn a_bearer_token_is_refused_rather_than_accepted_without_a_proof() {
        // Arrange
        let sent = headers(&[("authorization", "Bearer an-access-token")]);

        // Act / Assert
        assert!(matches!(
            presented(&sent, ""),
            Err(AdminError::InvalidToken)
        ));
    }

    #[test]
    fn a_dpop_presentation_without_a_proof_header_is_refused() {
        // Arrange
        let sent = headers(&[("authorization", "DPoP an-access-token")]);

        // Act / Assert
        assert!(matches!(
            presented(&sent, ""),
            Err(AdminError::InvalidToken)
        ));
    }

    #[test]
    fn a_dpop_presentation_with_a_proof_is_the_automation_mode() {
        // Arrange
        let sent = headers(&[("authorization", "DPoP an-access-token"), ("dpop", "a.b.c")]);

        // Act / Assert
        assert_eq!(
            presented(&sent, "").expect("a token"),
            Presented::Token {
                token: "an-access-token",
                proof: "a.b.c"
            }
        );
    }

    /// A caller holding both has not decided which credential it is using, and
    /// letting this server decide would be a place the decision could change.
    #[test]
    fn presenting_a_cookie_and_a_token_at_once_is_refused() {
        // Arrange
        let sent = headers(&[("authorization", "DPoP a-token"), ("dpop", "a.b.c")]);

        // Act / Assert
        assert!(matches!(
            presented(&sent, &format!("{COOKIE_NAME}=an-id")),
            Err(AdminError::InvalidToken)
        ));
    }

    #[test]
    fn only_the_console_is_subject_to_csrf() {
        // Arrange
        let automation = Principal::Automation {
            subject: "svc".to_owned(),
            held: Held::Scopes {
                tenant: None,
                scopes: vec![],
            },
        };

        // Act / Assert
        assert!(!automation.needs_csrf());
    }

    /// ADR-0009: the string `AuditActor::Admin` carries is a *user*
    /// identifier.
    #[test]
    fn the_console_is_audited_as_the_user_behind_it() {
        // Arrange
        let user = UserId::generate();
        let tenant = TenantId::parse("acme").expect("a valid tenant id");
        let principal = Principal::Console {
            tenant: tenant.clone(),
            user,
            session_id: "an-id".to_owned(),
            held: Held::Roles {
                tenant,
                roles: vec![],
            },
        };

        // Act / Assert
        assert_eq!(principal.audit_actor(), user.as_uuid().to_string());
    }
}
