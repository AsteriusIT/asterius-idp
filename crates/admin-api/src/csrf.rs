//! The layered CSRF defence ADR-0009 requires of `/admin/api`.
//!
//! The console is authenticated by an ambient cookie, so a cross-site page can
//! cause a request that carries it (RFC 9700 §4.7). Three layers answer that,
//! and the ADR is explicit that no one of them is trusted alone:
//!
//! 1. **A synchroniser token derived from the session**, sent in
//!    `X-CSRF-Token` on every non-`GET`, compared in constant time. Derived
//!    rather than stored, exactly like `asterius_oidc::logout`'s
//!    confirmation token: there is no interaction row for a `fetch` API to
//!    hang a token on, and a derivation has no row to expire, no race between
//!    two tabs and nothing to clean up. A cross-site page cannot compute it
//!    because it cannot read the `HttpOnly` cookie it is derived from.
//! 2. **`Sec-Fetch-Site` and `Origin`.** Fetch metadata is set by the browser
//!    and not settable by script; `Origin` is sent on every non-`GET`. Either
//!    saying "somewhere else" refuses the request before the token is even
//!    looked at.
//! 3. **`SameSite=Lax`**, which `crates/web/src/session.rs` already writes.
//!    It is the third layer and deliberately not the first: it is `Lax` rather
//!    than `Strict` because a top-level navigation back from a relying party
//!    is how a user arrives, so it does not protect a top-level `GET`. That is
//!    the whole reason a state-changing route may not be mounted on `GET`, and
//!    [`crate::operations`] makes that impossible to express rather than
//!    forbidden by review.
//!
//! # Why the derivation is not the session id
//!
//! The token is `sha256("asterius.admin.csrf.v1" | session_id)`. It is a
//! *different* value from the cookie and from the storage digest, so a token
//! that leaks — into a URL, a log, a screenshot of the console's network tab —
//! is not a session and is not a lookup key either. The domain separator
//! carries a version so a future change of scheme does not silently accept
//! both.

use asterius_domain::credentials::sha256_hex;
use axum::http::{HeaderMap, header};
use subtle::ConstantTimeEq as _;

use crate::error::AdminError;

/// The header a console sends its synchroniser token in.
pub const HEADER: &str = "x-csrf-token";

/// The domain separator. Versioned, so a later scheme cannot be confused with
/// this one by a token minted under the old one.
const DOMAIN: &str = "asterius.admin.csrf.v1";

/// The token belonging to the session whose id is `session_id`.
///
/// The *id*, not its digest: the digest is what the server stores, so deriving
/// from it would mean anyone holding the database could mint a token for a
/// session they cannot otherwise present. The id lives only in the browser.
#[must_use]
pub fn token(session_id: &str) -> String {
    sha256_hex(format!("{DOMAIN}|{session_id}").as_bytes())
}

/// Whether `presented` is the token belonging to `session_id`, in constant
/// time.
///
/// Constant time because the comparison is against a value an attacker may
/// guess repeatedly: a byte-at-a-time early return turns 2^256 guesses into
/// 32 × 16 of them.
#[must_use]
pub fn matches(session_id: &str, presented: &str) -> bool {
    let expected = token(session_id);
    // Lengths differ only for a malformed token, and `ct_eq` on slices of
    // different lengths is not defined, so the length check comes first. It
    // leaks the length of a value whose length is a constant of the scheme.
    expected.len() == presented.len() && bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
}

/// What the browser said about where the request came from.
///
/// Three values rather than a `bool`, because "the browser did not say"
/// (an old browser with no fetch metadata, a non-browser client) is not the
/// same as "the browser said it came from elsewhere", and collapsing them
/// would either lock out a client or accept an attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// The browser says this request came from this origin.
    Same,
    /// The browser says it did not.
    Cross,
    /// Nothing in the request says either way.
    Unstated,
}

/// Reads `Sec-Fetch-Site` and `Origin` into one verdict.
///
/// `expected_origin` is this deployment's own origin, in the `scheme://host`
/// form a browser sends: it comes from the tenant's issuer, never from a `Host`
/// header, because a header the caller chose is a check the caller passes.
///
/// The two sources are read in that order and the *stricter* answer wins. A
/// browser that sends `Sec-Fetch-Site: cross-site` is refused even if it also
/// sends a matching `Origin`, which is a shape only a confused proxy or an
/// attacker produces.
// fuzz-target: admin_fetch_metadata
#[must_use]
pub fn site(headers: &HeaderMap, expected_origin: &str) -> Site {
    let fetch_site = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);

    match fetch_site {
        // `none` is a user typing the URL or a bookmark: not cross-site, and
        // not something a `fetch` from another page can produce.
        Some("same-origin" | "none") => return Site::Same,
        Some("same-site" | "cross-site") => return Site::Cross,
        // An unknown token is not a promise of anything. Fall through to
        // `Origin` rather than trusting a value this build does not know.
        Some(_) | None => {}
    }

    match headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    {
        // `null` is an opaque origin — a sandboxed iframe, a `data:` document.
        // It is never this deployment.
        Some("null") => Site::Cross,
        Some(origin) if origin.eq_ignore_ascii_case(expected_origin) => Site::Same,
        Some(_) => Site::Cross,
        None => Site::Unstated,
    }
}

/// The whole check one state-changing request is subject to.
///
/// `session_id` is the id from the cookie, already resolved to a usable
/// session. `expected_origin` is this deployment's origin.
///
/// An [`Site::Unstated`] verdict is *accepted* here and the synchroniser token
/// carries the request on its own. That is the deliberate division of labour
/// between the layers: fetch metadata is a fast refusal for the browsers that
/// send it, and the token is the one that must hold for the ones that do not.
/// Refusing `Unstated` outright would lock out every non-browser caller of the
/// console API — including this repository's own tests — while adding nothing
/// an attacker could not already do by omitting the headers, since a browser
/// will not let script omit them.
///
/// # Errors
///
/// [`AdminError::CrossSite`] when the browser says the request came from
/// somewhere else, [`AdminError::CsrfMissing`] when no token was sent and
/// [`AdminError::CsrfMismatch`] when the one sent is not this session's.
pub fn check(
    headers: &HeaderMap,
    session_id: &str,
    expected_origin: &str,
) -> Result<(), AdminError> {
    if site(headers, expected_origin) == Site::Cross {
        return Err(AdminError::CrossSite);
    }

    let presented = headers
        .get(HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AdminError::CsrfMissing)?;

    if matches(session_id, presented) {
        Ok(())
    } else {
        Err(AdminError::CsrfMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const ORIGIN: &str = "https://as.example";

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).expect("a header value"));
        }
        map
    }

    /// The token is a *different* value from the id it is derived from, so a
    /// token in a log is not a session.
    #[test]
    fn the_token_is_not_the_session_id_it_derives_from() {
        // Arrange
        let id = "a-session-id";

        // Act
        let derived = token(id);

        // Assert
        assert_ne!(derived, id);
        assert!(!derived.contains(id));
    }

    #[test]
    fn two_sessions_do_not_share_a_token() {
        assert_ne!(token("one"), token("two"));
    }

    /// The scheme's version is part of what is hashed, so a token minted under
    /// a future scheme cannot be accepted by this one by accident.
    #[test]
    fn the_derivation_is_domain_separated() {
        assert_ne!(token("x"), sha256_hex(b"x"));
    }

    #[test]
    fn a_session_matches_only_its_own_token() {
        // Arrange
        let mine = token("mine");

        // Act / Assert
        assert!(matches("mine", &mine));
        assert!(!matches("yours", &mine));
    }

    #[test]
    fn a_token_of_the_wrong_length_does_not_match() {
        assert!(!matches("mine", ""));
        assert!(!matches("mine", &format!("{}x", token("mine"))));
    }

    #[test]
    fn a_same_origin_fetch_is_same_site() {
        assert_eq!(
            site(&headers(&[("sec-fetch-site", "same-origin")]), ORIGIN),
            Site::Same
        );
    }

    /// `same-site` is a *sibling subdomain*, which under a `__Host-` cookie is
    /// still somebody else. Refused with `cross-site`.
    #[test]
    fn a_sibling_subdomain_is_refused_like_any_other_origin() {
        assert_eq!(
            site(&headers(&[("sec-fetch-site", "same-site")]), ORIGIN),
            Site::Cross
        );
    }

    /// Fetch metadata is stricter than `Origin` and wins over it: this shape
    /// is only produced by a confused proxy or by an attacker.
    #[test]
    fn fetch_metadata_wins_over_a_matching_origin_header() {
        // Arrange
        let sent = headers(&[("sec-fetch-site", "cross-site"), ("origin", ORIGIN)]);

        // Act / Assert
        assert_eq!(site(&sent, ORIGIN), Site::Cross);
    }

    #[test]
    fn an_unknown_fetch_metadata_token_falls_back_to_origin() {
        assert_eq!(
            site(
                &headers(&[("sec-fetch-site", "future"), ("origin", ORIGIN)]),
                ORIGIN
            ),
            Site::Same
        );
        assert_eq!(
            site(
                &headers(&[
                    ("sec-fetch-site", "future"),
                    ("origin", "https://evil.example")
                ]),
                ORIGIN
            ),
            Site::Cross
        );
    }

    /// A sandboxed iframe or a `data:` document serialises its origin as
    /// `null`, which is never this deployment.
    #[test]
    fn an_opaque_origin_is_cross_site() {
        assert_eq!(site(&headers(&[("origin", "null")]), ORIGIN), Site::Cross);
    }

    #[test]
    fn a_request_saying_nothing_is_unstated_rather_than_same_site() {
        assert_eq!(site(&HeaderMap::new(), ORIGIN), Site::Unstated);
    }

    #[test]
    fn a_cross_site_request_is_refused_before_the_token_is_read() {
        // Arrange
        let sent = headers(&[("sec-fetch-site", "cross-site"), (HEADER, &token("mine"))]);

        // Act
        let outcome = check(&sent, "mine", ORIGIN);

        // Assert
        assert!(matches!(outcome, Err(AdminError::CrossSite)));
    }

    #[test]
    fn a_same_origin_request_without_a_token_is_refused() {
        // Arrange
        let sent = headers(&[("sec-fetch-site", "same-origin")]);

        // Act
        let outcome = check(&sent, "mine", ORIGIN);

        // Assert
        assert!(matches!(outcome, Err(AdminError::CsrfMissing)));
    }

    #[test]
    fn another_sessions_token_is_refused() {
        // Arrange
        let sent = headers(&[("sec-fetch-site", "same-origin"), (HEADER, &token("yours"))]);

        // Act
        let outcome = check(&sent, "mine", ORIGIN);

        // Assert
        assert!(matches!(outcome, Err(AdminError::CsrfMismatch)));
    }

    #[test]
    fn this_sessions_token_from_this_origin_is_accepted() {
        // Arrange
        let sent = headers(&[("origin", ORIGIN), (HEADER, &token("mine"))]);

        // Act
        let outcome = check(&sent, "mine", ORIGIN);

        // Assert
        assert!(outcome.is_ok());
    }
}
