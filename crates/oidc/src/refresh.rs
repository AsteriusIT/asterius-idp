//! Refresh tokens: the value, its digest, and the scope arithmetic of a
//! refresh request (RFC 6749 §1.5, §6).
//!
//! A refresh token is the longest-lived credential this server issues and the
//! only one that can be presented without a user anywhere near a browser. That
//! is what makes the three decisions in this module the ones worth writing
//! down.
//!
//! # It is opaque, and it is 256 bits
//!
//! Not a JWT. A refresh token is presented to exactly one party — the
//! authorization server that minted it — so there is nothing for a
//! self-describing token to buy, and a great deal for it to leak: a JWT
//! refresh token tells anybody who reads a log which user, which client and
//! which scopes an integration holds. RFC 6749 §10.4 asks only that the value
//! be unguessable; 256 bits of `getrandom` entropy is the same budget every
//! other opaque value here spends.
//!
//! # It is stored as a digest, never as itself
//!
//! [`MintedRefreshToken`] hands out the value once and keeps the SHA-256 of
//! it, which is what reaches the database — the same treatment
//! `clients.registration_access_token_hash` and the pairwise salt get. The
//! property that buys is precise: a dump of `refresh_tokens` is a list of
//! digests, and a digest cannot be presented at the token endpoint. Nothing
//! preimages a 256-bit random value, so the digest is not a "hash a password"
//! decision and does not want a KDF; it is a lookup key that happens to be
//! one-way (RFC 9700 §4.14).
//!
//! # Narrowing is allowed; widening is not
//!
//! RFC 6749 §6: "the scope of the access request … MUST NOT include any scope
//! not originally granted by the resource owner, and if omitted is treated as
//! equal to the scope originally granted". [`requested_scopes`] is that
//! sentence and nothing more — the comparison is against what *this token* was
//! issued for, not against the grant, because a token already narrowed once
//! must not widen back on the next refresh.

use asterius_domain::{OpaqueToken, sha256_hex};
use std::collections::BTreeSet;

/// Bits of entropy in a refresh token.
///
/// RFC 6749 §10.4 requires only that the value be unguessable. 256 is what an
/// authorization code and a registration access token here already spend, and
/// the credential that lives for a month is not the one to economise on.
pub const REFRESH_TOKEN_BITS: usize = 256;

/// The number of base64url characters a refresh token has.
///
/// Derived from [`REFRESH_TOKEN_BITS`] rather than written down, so the two
/// cannot drift: [`digest_of`] rejects anything of another length before it
/// touches the database.
pub const REFRESH_TOKEN_LEN: usize = REFRESH_TOKEN_BITS.div_ceil(6);

/// The most scopes a refresh request may name.
///
/// A bound on the parser, not a policy: the granted set is itself bounded by
/// `Grant::MAX_SCOPES`, so a request naming more than this cannot be a subset
/// of anything and is refused before the set is built.
pub const MAX_SCOPES: usize = 64;

/// A freshly minted refresh token and the digest to store.
///
/// The value reaches exactly two places: the token response, and the client
/// that reads it. The digest reaches the database. Nothing carries the value
/// anywhere else, which is what [`std::fmt::Debug`] below is for.
pub struct MintedRefreshToken {
    value: OpaqueToken,
    digest: String,
}

impl MintedRefreshToken {
    /// Mints a refresh token.
    #[must_use]
    pub fn generate() -> Self {
        let value = OpaqueToken::generate_bits::<REFRESH_TOKEN_BITS>();
        let digest = sha256_hex(value.expose().as_bytes());
        Self { value, digest }
    }

    /// The value to put in the token response.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.value.expose()
    }

    /// The value to store.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl std::fmt::Debug for MintedRefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedRefreshToken")
            .field("value", &"[REDACTED]")
            .field("digest", &self.digest)
            .finish()
    }
}

/// Turns a presented refresh token into the digest to look up.
///
/// The shape is checked before the database is touched, so a guess costs a
/// length comparison rather than a query — and a token endpoint that queries
/// on every string a caller sends is a token endpoint an attacker can use to
/// make the database do work.
///
/// # Errors
///
/// [`MalformedRefreshToken`] when the value could not have been issued here.
// fuzz-target: refresh_token
pub fn digest_of(presented: &str) -> Result<String, MalformedRefreshToken> {
    if presented.len() != REFRESH_TOKEN_LEN
        || !presented
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(MalformedRefreshToken);
    }
    Ok(sha256_hex(presented.as_bytes()))
}

/// A presented value that this server could not have issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a refresh token issued by this server")]
pub struct MalformedRefreshToken;

/// Works out what scopes a refresh request may have.
///
/// RFC 6749 §6, in three rules:
///
/// * `scope` absent is "equal to the scope originally granted", so `granted`
///   comes back unchanged;
/// * a subset is a narrowing, which is allowed and is the whole reason the
///   parameter exists;
/// * anything else — one token outside the set — is `invalid_scope`, and the
///   whole request fails rather than being trimmed to what is permitted. A
///   client that asked for more than it holds has a bug or has been fed a
///   scope by somebody else, and silently trimming would hand it a token it
///   believes is broader than it is.
///
/// The comparison is against what the *presented token* was issued for and not
/// against the grant. That is the difference between a narrowing being
/// permanent and a narrowing being a suggestion: a token minted for `openid`
/// out of a grant covering `openid payments` must not be able to refresh its
/// way back to `payments`.
///
/// # Errors
///
/// [`ScopeError`] when the request is not a subset of `granted`, names a scope
/// that is not an RFC 6749 §3.3 `scope-token`, or is implausibly long.
// fuzz-target: refresh_token_scope
pub fn requested_scopes(
    raw: Option<&str>,
    granted: &BTreeSet<String>,
) -> Result<BTreeSet<String>, ScopeError> {
    let Some(raw) = raw else {
        return Ok(granted.clone());
    };

    let mut requested = BTreeSet::new();
    for token in raw.split_whitespace() {
        // Checked even though every member of `granted` already passed it:
        // the failure below is a set-membership test, and a caller reading
        // this function should not have to know that `granted` is clean to see
        // that its output is.
        if !asterius_domain::entities::grant::is_scope_token(token) {
            return Err(ScopeError::NotAScopeToken);
        }
        if !granted.contains(token) {
            return Err(ScopeError::NotGranted);
        }
        requested.insert(token.to_owned());
        if requested.len() > MAX_SCOPES {
            return Err(ScopeError::TooMany);
        }
    }

    // `scope=""` and `scope="   "` parse to nothing. RFC 6749 §6 does not
    // describe a refresh that grants no scope at all, and a token with an
    // empty `scope` claim is one a resource server has no rule for, so an
    // empty request is read as the omission it looks like rather than as an
    // instruction to mint an authorization that permits nothing.
    if requested.is_empty() {
        return Ok(granted.clone());
    }
    Ok(requested)
}

/// Why a refresh request's `scope` was refused.
///
/// Every variant is RFC 6749 §5.2's `invalid_scope`; they are separate here so
/// that the log can say which one it was while the client is told one thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeError {
    /// A scope outside the set this token was issued for.
    #[error("the request names a scope this refresh token was not issued for")]
    NotGranted,
    /// A value that is not an RFC 6749 §3.3 `scope-token`.
    #[error("the request names something that is not a scope token")]
    NotAScopeToken,
    /// More scopes than any grant could hold.
    #[error("the request names more scopes than a grant may carry")]
    TooMany,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn granted(scopes: &[&str]) -> BTreeSet<String> {
        scopes.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The value handed to the client and the value stored are not the same
    /// thing, and the stored one must not be presentable.
    #[test]
    fn a_minted_token_stores_a_digest_and_not_the_value() {
        // Arrange
        let minted = MintedRefreshToken::generate();

        // Act
        let digest = minted.digest().to_owned();

        // Assert
        assert_ne!(digest, minted.expose());
        assert_eq!(digest, sha256_hex(minted.expose().as_bytes()));
    }

    /// A minted token is one `digest_of` recognises. The two halves are
    /// written apart and this is what keeps them one credential.
    #[test]
    fn a_minted_token_digests_to_the_digest_it_was_minted_with() {
        // Arrange
        let minted = MintedRefreshToken::generate();

        // Act
        let looked_up = digest_of(minted.expose()).expect("a minted token is well formed");

        // Assert
        assert_eq!(looked_up, minted.digest());
    }

    /// RFC 6749 §10.4 is about guessing. Two mints must not collide.
    #[test]
    fn two_minted_tokens_differ() {
        assert_ne!(
            MintedRefreshToken::generate().expose(),
            MintedRefreshToken::generate().expose()
        );
    }

    /// The `Debug` rendering is what ends up in a `tracing` field by accident.
    #[test]
    fn the_debug_rendering_does_not_carry_the_value() {
        // Arrange
        let minted = MintedRefreshToken::generate();

        // Act
        let rendered = format!("{minted:?}");

        // Assert
        assert!(!rendered.contains(minted.expose()));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn a_value_of_the_wrong_length_is_refused_without_a_lookup() {
        assert_eq!(digest_of("short"), Err(MalformedRefreshToken));
        assert_eq!(
            digest_of(&"a".repeat(REFRESH_TOKEN_LEN + 1)),
            Err(MalformedRefreshToken)
        );
    }

    #[test]
    fn a_value_outside_the_base64url_alphabet_is_refused() {
        // Arrange
        let padded = format!("{}=", "a".repeat(REFRESH_TOKEN_LEN - 1));

        // Act
        let result = digest_of(&padded);

        // Assert
        assert_eq!(result, Err(MalformedRefreshToken));
    }

    /// RFC 6749 §6: "if omitted is treated as equal to the scope originally
    /// granted".
    #[test]
    fn an_omitted_scope_is_the_scope_the_token_holds() {
        // Arrange
        let held = granted(&["openid", "payments"]);

        // Act
        let effective = requested_scopes(None, &held).expect("omission is legal");

        // Assert
        assert_eq!(effective, held);
    }

    /// Narrowing is the reason the parameter exists.
    #[test]
    fn a_subset_narrows_the_request() {
        // Arrange
        let held = granted(&["openid", "payments", "profile"]);

        // Act
        let effective = requested_scopes(Some("openid profile"), &held).expect("a subset");

        // Assert
        assert_eq!(effective, granted(&["openid", "profile"]));
    }

    /// RFC 6749 §6: "MUST NOT include any scope not originally granted".
    #[test]
    fn a_scope_outside_the_granted_set_is_refused() {
        // Arrange
        let held = granted(&["openid"]);

        // Act
        let error = requested_scopes(Some("openid payments"), &held).expect_err("widening");

        // Assert
        assert_eq!(error, ScopeError::NotGranted);
    }

    /// The whole request fails; it is not trimmed to the permitted part. A
    /// client that got a token narrower than it asked for would act as if it
    /// had the broader one.
    #[test]
    fn a_widening_request_is_not_silently_trimmed() {
        // Arrange
        let held = granted(&["openid", "profile"]);

        // Act
        let result = requested_scopes(Some("openid payments profile"), &held);

        // Assert
        assert!(result.is_err(), "a widening request must fail, not shrink");
    }

    /// An empty `scope` is the omission it looks like, not a request for an
    /// authorization that permits nothing.
    #[test]
    fn an_empty_scope_parameter_is_the_granted_set() {
        // Arrange
        let held = granted(&["openid"]);

        // Act
        let effective = requested_scopes(Some("   "), &held).expect("blank is an omission");

        // Assert
        assert_eq!(effective, held);
    }

    /// A scope carrying a space would become two scopes at a resource server
    /// (RFC 9068 §2.2.3); one carrying a quote is outside §3.3's grammar. The
    /// splitter makes the first unreachable, so this asserts the second.
    #[test]
    fn a_value_outside_the_scope_token_grammar_is_refused() {
        // Arrange
        let held = granted(&["openid"]);

        // Act
        let error = requested_scopes(Some("open\"id"), &held).expect_err("not a scope token");

        // Assert
        assert_eq!(error, ScopeError::NotAScopeToken);
    }

    /// Duplicates collapse rather than counting twice, so a request repeating
    /// one scope a thousand times is not a way past `MAX_SCOPES`.
    #[test]
    fn a_repeated_scope_is_one_scope() {
        // Arrange
        let held = granted(&["openid"]);

        // Act
        let effective = requested_scopes(Some("openid openid openid"), &held).expect("a subset");

        // Assert
        assert_eq!(effective, held);
    }
}
