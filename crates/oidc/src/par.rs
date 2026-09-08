//! Pushed authorization requests: the `request_uri`, and what it is worth.
//!
//! RFC 9126. A client posts the whole authorization request to this server,
//! authenticated, and gets back a short-lived reference. The user agent then
//! carries only that reference to `/authorize`.
//!
//! ADR-0002 makes this the *only* way to start a flow, which FAPI 2.0 SP
//! §5.3.2.2 items 2–4 require. Three properties follow, and they are the
//! reason the profile insists:
//!
//! * **The request cannot be modified in the browser.** Everything that
//!   matters was fixed while an authenticated client was on the connection.
//! * **The request cannot be read from the browser.** No `scope`, `state`,
//!   `login_hint` or `claims` in a URL, a history entry, a `Referer`, or a
//!   proxy log.
//! * **A rejection is an error response, not a redirect.** The AS never has to
//!   decide whether it is safe to bounce an error to a URI it has not
//!   validated.
//!
//! # What a `request_uri` is
//!
//! A bearer reference to a stored request. Anyone holding one can begin an
//! authorization flow as that client, which is why §7.1 asks for real entropy
//! and why the value is stored only as a digest — the same treatment any other
//! bearer credential gets here.

use asterius_domain::{OpaqueToken, sha256_hex};
use time::Duration;

/// The URN prefix of a `request_uri` (RFC 9126 §2.2).
///
/// The specification says the AS "MAY construct the `request_uri` value using
/// the form `urn:ietf:params:oauth:request_uri:<reference-value>`". Taking the
/// option means a client, a log or an operator can tell at a glance what a
/// value is, and it makes the reference unmistakably not a URL — nothing will
/// try to dereference it.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// Bits of entropy in a reference.
///
/// RFC 9126 §7.1 defers to RFC 9101 §10.2 clause (d) rather than naming a
/// number. 256 is what every other bearer credential here carries, and the
/// floor `OpaqueToken` enforces is 128.
pub const REFERENCE_BITS: usize = 256;

/// How long a pushed request lives, unless a tenant says less.
///
/// FAPI 2.0 SP §5.3.2.2 item 12 caps this below 600 seconds. Ninety is
/// generous for "the user agent is redirected now" and short enough that a
/// reference leaked into a log is almost always already useless.
pub const DEFAULT_LIFETIME: Duration = Duration::seconds(90);

/// The longest lifetime any tenant may configure.
///
/// FAPI 2.0 SP §5.3.2.2 item 12: "shall issue pushed authorization requests
/// `request_uri` with `expires_in` values of less than 600 seconds". *Less
/// than*, so 599 and not 600.
pub const MAX_LIFETIME: Duration = Duration::seconds(599);

/// A freshly minted reference and the URI that carries it.
///
/// The reference is a credential: anyone holding one can begin an
/// authorization flow as that client. It is written exactly twice — into the
/// response body, and, as a digest, into the database — and is redacted
/// everywhere else, including `Debug`, so that putting the value in a
/// `tracing` field cannot leak it.
pub struct MintedRequestUri {
    /// The value handed to the client. Written once, into the response body.
    uri: String,
    /// What to store: the digest, never the value.
    digest: String,
}

impl std::fmt::Debug for MintedRequestUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The digest is safe to show and is what an operator correlating a log
        // line with a row actually wants.
        f.debug_struct("MintedRequestUri")
            .field("uri", &"[REDACTED]")
            .field("digest", &self.digest)
            .finish()
    }
}

impl MintedRequestUri {
    /// Mints a reference.
    #[must_use]
    pub fn generate() -> Self {
        let token = OpaqueToken::generate_bits::<REFERENCE_BITS>();
        // The digest is taken over the *reference*, not the whole URN. The
        // prefix is a constant, so including it would add no entropy and would
        // couple stored rows to a spelling this server might restate.
        let digest = sha256_hex(token.expose().as_bytes());
        Self {
            uri: format!("{REQUEST_URI_PREFIX}{}", token.expose()),
            digest,
        }
    }

    /// The value to return to the client.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The value to store.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Why a presented `request_uri` could not be turned into a lookup key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RequestUriError {
    /// Not the URN form this server issues.
    #[error("not a request_uri issued by this server")]
    NotOurs,
    /// The right shape, but the reference is not one we could have minted.
    #[error("request_uri reference is malformed")]
    Malformed,
}

/// Turns a presented `request_uri` into the digest to look up.
///
/// Shape is checked before the database is touched. A value that could not
/// have been issued is refused without a query, so a flood of guesses costs a
/// string comparison rather than a round trip — which is most of what
/// RFC 9126 §7.1 is asking for.
///
/// # Errors
///
/// [`RequestUriError`] if `presented` is not a reference this server issues.
// fuzz-target: request_uri
pub fn digest_of(presented: &str) -> Result<String, RequestUriError> {
    let reference = presented
        .strip_prefix(REQUEST_URI_PREFIX)
        .ok_or(RequestUriError::NotOurs)?;

    // `OpaqueToken::generate_bits` produces unpadded base64url. Anything else
    // was not minted here, whatever it decodes to.
    let expected_len = REFERENCE_BITS.div_ceil(6);
    if reference.len() != expected_len
        || !reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(RequestUriError::Malformed);
    }

    Ok(sha256_hex(reference.as_bytes()))
}

/// Clamps a configured lifetime into what the profile permits.
///
/// Clamped rather than refused: an operator who sets 3600 should get a
/// compliant server, not one that will not start. FAPI 2.0 SP §5.3.2.2
/// item 12 is the ceiling.
#[must_use]
pub fn clamp_lifetime(configured: Duration) -> Duration {
    configured.clamp(Duration::seconds(1), MAX_LIFETIME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn a_minted_uri_carries_the_urn_prefix_and_a_full_length_reference() {
        let minted = MintedRequestUri::generate();
        assert!(minted.uri().starts_with(REQUEST_URI_PREFIX));
        let reference = minted
            .uri()
            .strip_prefix(REQUEST_URI_PREFIX)
            .expect("prefix");
        assert_eq!(reference.len(), REFERENCE_BITS.div_ceil(6));
        assert_eq!(digest_of(minted.uri()).expect("ours"), minted.digest());
    }

    /// RFC 9126 §7.1. Two references colliding would let one client resume
    /// another's request, so the only acceptable number of collisions is none.
    #[test]
    fn references_do_not_repeat() {
        let mut seen = HashSet::new();
        for _ in 0..2_000 {
            assert!(
                seen.insert(MintedRequestUri::generate().uri().to_owned()),
                "a reference repeated"
            );
        }
    }

    /// The stored form is a digest: a leaked database row must not yield a
    /// usable `request_uri`.
    #[test]
    fn the_stored_digest_does_not_contain_the_reference() {
        let minted = MintedRequestUri::generate();
        let reference = minted
            .uri()
            .strip_prefix(REQUEST_URI_PREFIX)
            .expect("prefix");
        assert_eq!(minted.digest().len(), 64, "not a hex SHA-256");
        assert!(!minted.digest().contains(reference));
    }

    #[test]
    fn a_value_this_server_could_not_have_issued_is_refused_without_a_lookup() {
        for wrong in [
            "",
            "https://as.example/request/abc",
            "urn:ietf:params:oauth:request_uri",
            "urn:ietf:params:oauth:request_uri:",
            // Right prefix, wrong length.
            "urn:ietf:params:oauth:request_uri:short",
            // Right length, wrong alphabet.
            &format!("{REQUEST_URI_PREFIX}{}", "+".repeat(43)),
            &format!("{REQUEST_URI_PREFIX}{}", "=".repeat(43)),
            // A near miss on the prefix.
            "urn:ietf:params:oauth:request-uri:abc",
            "URN:IETF:PARAMS:OAUTH:REQUEST_URI:abc",
        ] {
            assert!(
                digest_of(wrong).is_err(),
                "accepted a request_uri we could not have issued: {wrong:?}"
            );
        }
    }

    /// FAPI 2.0 SP §5.3.2.2 item 12: *less than* 600 seconds.
    #[test]
    fn a_lifetime_is_clamped_below_the_profile_ceiling() {
        assert_eq!(clamp_lifetime(Duration::seconds(30)), Duration::seconds(30));
        assert_eq!(clamp_lifetime(Duration::hours(1)), MAX_LIFETIME);
        assert!(MAX_LIFETIME < Duration::seconds(600));
        assert!(DEFAULT_LIFETIME < Duration::seconds(600));
        // Never zero or negative: a request that has already expired when it
        // is issued is a client that can never succeed and cannot tell why.
        assert_eq!(clamp_lifetime(Duration::ZERO), Duration::seconds(1));
        assert_eq!(clamp_lifetime(Duration::seconds(-5)), Duration::seconds(1));
    }

    /// A `request_uri` in a log is a usable credential for whoever reads the
    /// log. The digest is not, and is what correlates a line with a row.
    #[test]
    fn the_reference_is_redacted_in_the_debug_rendering() {
        let minted = MintedRequestUri::generate();
        let rendered = format!("{minted:?}");
        let reference = minted
            .uri()
            .strip_prefix(REQUEST_URI_PREFIX)
            .expect("prefix");
        assert!(!rendered.contains(reference), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        assert!(rendered.contains(minted.digest()), "{rendered}");
    }
}
