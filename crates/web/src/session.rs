//! The session cookie, written and removed by one pair of functions.
//!
//! Setting and clearing a cookie are the same statement with `Max-Age=0` on
//! the end, and a browser that is sent a `Set-Cookie` whose attributes differ
//! from the ones the cookie was created with keeps the original. So the two
//! are written here, next to each other, from the same attribute list: a
//! logout that "cleared" a cookie the browser kept is a session that looks
//! ended and is not.
//!
//! Reading is [`crate::interaction::cookie_value`], which is the same reader
//! the interaction cookie uses.

use asterius_domain::entities::session::COOKIE_NAME;

/// The attributes every rendering of this cookie carries.
///
/// `__Host-` is browser-enforced (set over HTTPS, no `Domain`, `Path=/`), so
/// a compromised sibling subdomain cannot plant a session id — which is the
/// other half of the fixation defence that rotation provides. `HttpOnly`
/// keeps it away from script. `SameSite=Lax`, not `Strict`, because a
/// top-level navigation back from a relying party is how a user arrives.
const ATTRIBUTES: &str = "Secure; HttpOnly; SameSite=Lax; Path=/";

/// The `Set-Cookie` value that carries a session id to the browser.
///
/// No `Max-Age`: it is a session cookie, and the session row's own two clocks
/// are the authority on lifetime. A cookie that outlived the row would only
/// produce a confusing sign-in loop.
#[must_use]
pub fn set_cookie(id: &str) -> String {
    format!("{COOKIE_NAME}={id}; {ATTRIBUTES}")
}

/// The `Set-Cookie` value that removes it.
///
/// Sent whenever the session behind it has ended — logout, revocation, a row
/// that no longer resolves. A cookie left in the browser after the session
/// ended is a value an attacker can keep presenting.
#[must_use]
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; {ATTRIBUTES}; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cookie_carries_every_attribute_it_relies_on() {
        let cookie = set_cookie("a-session-id");
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
            assert!(cookie.contains(attribute), "missing {attribute}: {cookie}");
        }
        assert!(cookie.starts_with("__Host-"), "{cookie}");
        assert!(!cookie.contains("SameSite=Strict"), "{cookie}");
        assert!(!cookie.to_lowercase().contains("domain="), "{cookie}");
        assert!(!cookie.contains("Max-Age"), "{cookie}");
    }

    /// The rule this module exists for: a browser keeps a cookie whose
    /// removal does not match how it was set.
    #[test]
    fn clearing_matches_setting_attribute_for_attribute() {
        let set = set_cookie("a-session-id");
        let cleared = clear_cookie();
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
            assert!(
                set.contains(attribute) && cleared.contains(attribute),
                "{attribute}"
            );
        }
        assert!(
            cleared.starts_with(&format!("{COOKIE_NAME}=;")),
            "{cleared}"
        );
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        assert!(
            !cleared.contains("a-session-id"),
            "clearing must not resend the id: {cleared}"
        );
    }
}
