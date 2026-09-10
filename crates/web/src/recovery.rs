//! The synchroniser token for the account-recovery pages.
//!
//! # Why this is not [`crate::interaction`]'s CSRF
//!
//! Every other form this server renders is inside an interaction: there is a
//! server-side record, the token lives in it, and the token in the form is
//! checked against the stored one. The recovery pages have no such record and
//! cannot have one — the first of them is reached by an unauthenticated
//! stranger who has typed nothing yet, and giving that stranger a row to
//! create is handing an anonymous visitor a write. A reset form that cost a
//! database insert per view would be a denial-of-service tool with a Send
//! button.
//!
//! So these two pages use a signed-by-possession double submit: a `__Host-`
//! cookie carries a freshly drawn token, the form carries the same value, and
//! the submission is accepted only if the two match. The properties that make
//! that sound here rather than merely traditional:
//!
//! * `__Host-` forces `Secure` and `Path=/` and forbids `Domain`, so a
//!   sibling subdomain — the classic way a double submit is broken — cannot
//!   write this cookie into the browser's jar for this origin;
//! * `SameSite=Lax` means a cross-site POST does not carry it at all, so the
//!   attacker's forged form arrives with no cookie and no match is possible;
//! * `HttpOnly`, so a script that gets a foothold cannot read the value and
//!   put it in a form of its own;
//! * the value is 256 bits from the same generator every other credential
//!   comes from, and the comparison is constant time.
//!
//! # What it deliberately does not do
//!
//! It does not identify anybody, it does not survive a browser restart, and it
//! is not the reset token. The reset token is the thing that says *which
//! account*; this says only that a submission came from a page this server
//! rendered to this browser. Two locks, two jobs — see `password_new.html`.

use crate::interaction::{CsrfToken, cookie_value};

/// The cookie the token lives in.
///
/// `__Host-` for the reasons above. A different name from the interaction
/// cookie so that the two cannot be confused by a handler or overwritten by
/// each other: a user who has a login in flight and clicks a reset link in
/// another tab has both at once.
pub const COOKIE_NAME: &str = "__Host-asterius_rc";

/// Why a recovery submission was refused before anything else happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the recovery form was not submitted by a page this server rendered")]
pub struct CsrfFailed;

/// Draws a token and the `Set-Cookie` value that carries it.
///
/// One token per rendering. Reusing one across pages would make it a
/// long-lived value in a browser's jar, and there is nothing to gain from
/// that: the form is rendered in the same response that sets the cookie.
#[must_use]
pub fn issue() -> (CsrfToken, String) {
    let token = CsrfToken::generate();
    let cookie = format!(
        "{COOKIE_NAME}={}; Secure; HttpOnly; SameSite=Lax; Path=/",
        token.expose()
    );
    (token, cookie)
}

/// The `Set-Cookie` value that removes it.
///
/// The attributes must match the ones it was set with or the browser keeps the
/// original. Sent once the recovery is over, so that a token nobody needs is
/// not left sitting in the jar to be replayed against the next rendering.
#[must_use]
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
}

/// Whether this submission carries the token this browser was given.
///
/// # Errors
///
/// [`CsrfFailed`] when the cookie is absent, the field is absent, or the two
/// differ. One error for all three, for [`crate::interaction::check_csrf`]'s
/// reason: which way a forged submission failed is not the submitter's
/// business.
pub fn check(cookie_header: &str, presented: Option<&str>) -> Result<(), CsrfFailed> {
    let issued = cookie_value(cookie_header, COOKIE_NAME).ok_or(CsrfFailed)?;
    let presented = presented.ok_or(CsrfFailed)?;
    if presented.is_empty() {
        return Err(CsrfFailed);
    }
    let issued = CsrfToken::from_presented(issued.to_owned());
    let presented = CsrfToken::from_presented(presented.to_owned());
    if issued.matches(&presented) {
        Ok(())
    } else {
        Err(CsrfFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value in the cookie is the value the form must carry.
    #[test]
    fn a_matching_pair_is_accepted() {
        // Arrange
        let (token, cookie) = issue();
        let header = cookie.split(';').next().expect("the name=value pair");

        // Act
        let checked = check(header, Some(token.expose()));

        // Assert
        assert!(checked.is_ok());
    }

    /// The cross-site case: `SameSite=Lax` means the forged POST arrives with
    /// no cookie, and no cookie is a refusal rather than a pass.
    #[test]
    fn a_submission_with_no_cookie_is_refused() {
        // Arrange
        let (token, _) = issue();

        // Act
        let checked = check("", Some(token.expose()));

        // Assert
        assert_eq!(checked.unwrap_err(), CsrfFailed);
    }

    /// A cookie with no field is the other half of the same failure.
    #[test]
    fn a_submission_with_no_field_is_refused() {
        // Arrange
        let (_, cookie) = issue();
        let header = cookie.split(';').next().expect("the name=value pair");

        // Act
        let checked = check(header, None);

        // Assert
        assert_eq!(checked.unwrap_err(), CsrfFailed);
    }

    /// A token the attacker chose does not match the one the browser holds.
    #[test]
    fn a_mismatched_token_is_refused() {
        // Arrange
        let (_, cookie) = issue();
        let header = cookie.split(';').next().expect("the name=value pair");
        let other = CsrfToken::generate();

        // Act
        let checked = check(header, Some(other.expose()));

        // Assert
        assert_eq!(checked.unwrap_err(), CsrfFailed);
    }

    /// An empty field must not satisfy an empty-ish cookie by accident. The
    /// cookie parser already refuses an empty value; this pins the other side.
    #[test]
    fn an_empty_field_is_refused() {
        // Arrange
        let (_, cookie) = issue();
        let header = cookie.split(';').next().expect("the name=value pair");

        // Act
        let checked = check(header, Some(""));

        // Assert
        assert_eq!(checked.unwrap_err(), CsrfFailed);
    }

    /// The `__Host-` prefix is what makes a sibling subdomain unable to write
    /// this cookie. Asserted on the emitted attributes because the browser
    /// only honours the prefix when they are exactly these.
    #[test]
    fn the_cookie_carries_the_host_prefix_attributes() {
        // Arrange, Act
        let (_, cookie) = issue();

        // Assert
        assert!(cookie.starts_with("__Host-asterius_rc="));
        assert!(cookie.contains("; Secure"));
        assert!(cookie.contains("; HttpOnly"));
        assert!(cookie.contains("; SameSite=Lax"));
        assert!(cookie.contains("; Path=/"));
        assert!(!cookie.contains("Domain="));
    }

    /// A clear must match the set, attribute for attribute, or the browser
    /// keeps the original.
    #[test]
    fn clearing_matches_the_attributes_it_was_set_with() {
        // Arrange
        let (_, set) = issue();

        // Act
        let cleared = clear_cookie();

        // Assert
        let attributes = |value: &str| {
            value
                .split(';')
                .skip(1)
                .map(str::trim)
                .filter(|part| *part != "Max-Age=0")
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(attributes(&cleared), attributes(&set));
        assert!(cleared.contains("Max-Age=0"));
    }

    /// Two renderings are two tokens.
    #[test]
    fn each_rendering_draws_its_own_token() {
        // Arrange, Act
        let (first, _) = issue();
        let (second, _) = issue();

        // Assert
        assert!(!first.matches(&second));
    }
}
