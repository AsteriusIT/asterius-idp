//! Account recovery: the token a reset link carries, and what it is worth.
//!
//! # The threat this whole module lives under
//!
//! A recovery token is a *credential that resets credentials*. Whoever holds
//! one can take the account, and the only thing standing between an attacker
//! and one is a mailbox. NIST SP 800-63B §6.1.2.3 is explicit about what that
//! costs: a memorised-secret reset by an out-of-band channel is authentication
//! by possession of that channel, so the token has to be treated as a real
//! authenticator secret — at least 112 bits of entropy in the specification's
//! terms, single use, short-lived, and stored hashed so a database copy is not
//! a pile of account takeovers. This server draws
//! [`RECOVERY_TOKEN_BITS`], which is well past both that floor and FAPI 2.0
//! SP §5.4.1 item 4's 128.
//!
//! # Why there is a parser at all
//!
//! The token arrives from a browser: a query parameter on the link, then a
//! hidden form field on the page that link opens. Both are attacker-controlled
//! strings until something says otherwise, and the thing that says otherwise
//! is [`RecoveryToken::parse`]. It runs *before* any database work, so a
//! request carrying a megabyte of junk costs a length check rather than an
//! index probe, and it accepts exactly the shape this server issues — no
//! trimming, no padding tolerance, no case folding. A parser that repaired its
//! input would make two different strings name one token, and single use is a
//! property of a row, not of a spelling.

use crate::credentials::{OpaqueToken, sha256_hex};
use crate::entities::user::UserId;
use time::{Duration, OffsetDateTime};

/// How much entropy a recovery token carries.
///
/// 256 bits, the same as every other opaque credential this server issues.
/// The ticket's floor is 128; the margin is the same one
/// [`crate::credentials::DEFAULT_ENTROPY_BITS`] argues for, and it costs six
/// characters in a URL.
pub const RECOVERY_TOKEN_BITS: usize = 256;

/// The number of `base64url` characters [`RECOVERY_TOKEN_BITS`] encodes to.
///
/// Unpadded base64 is four characters per three bytes; 32 bytes is 42 whole
/// characters plus one carrying the last two bits.
const TOKEN_CHARS: usize = 43;

/// How long a recovery token is good for.
///
/// Fifteen minutes. Long enough to arrive by mail and be clicked, short enough
/// that a link sitting in an unattended inbox stops being an account. OWASP's
/// Forgot Password Cheat Sheet asks for "a short expiration time"; the number
/// is this deployment's answer to that, not a specification's.
pub const RECOVERY_LIFETIME: Duration = Duration::minutes(15);

/// Why a presented string is not a recovery token.
///
/// Deliberately coarse at the boundary: nothing built from this is ever shown
/// to the person who presented it, because "your token is 42 characters long"
/// is a hint about the shape of the secret. It exists so that logs and tests
/// can tell the cases apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryTokenError {
    /// Not the length this server issues.
    #[error("a recovery token is not this length")]
    Length,
    /// A character outside unpadded `base64url` (RFC 4648 §5).
    #[error("a recovery token contains a character it cannot contain")]
    Alphabet,
}

/// A syntactically well-formed recovery token.
///
/// Holding one says nothing about whether it exists, is unspent or has
/// expired — that is [`crate::ports::RecoveryTokenStore::spend`]'s answer. It
/// says only that this string is the right shape to look up, which is what
/// stops the lookup being a place to send arbitrary bytes.
///
/// Like [`OpaqueToken`], it prints redacted and does not implement
/// `PartialEq`: comparison happens on the digest, in the database, not here.
#[derive(Debug)]
pub struct RecoveryToken(OpaqueToken);

impl RecoveryToken {
    /// Draws a fresh token.
    #[must_use]
    pub fn generate() -> Self {
        Self(OpaqueToken::generate_bits::<RECOVERY_TOKEN_BITS>())
    }

    /// Reads a token that arrived from a browser.
    ///
    /// # Errors
    ///
    /// [`RecoveryTokenError`] when the string is not the exact shape this
    /// server issues. No repair is attempted: see the module documentation.
    // fuzz-target: recovery_token
    pub fn parse(presented: &str) -> Result<Self, RecoveryTokenError> {
        if presented.len() != TOKEN_CHARS {
            return Err(RecoveryTokenError::Length);
        }
        if !presented
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(RecoveryTokenError::Alphabet);
        }
        Ok(Self(OpaqueToken::from_presented(presented.to_owned())))
    }

    /// The token itself, for the link that carries it.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// What the database stores: the SHA-256 of the token, hex-encoded.
    ///
    /// Hashed rather than encrypted, and unsalted rather than Argon2id, for
    /// the reason every other opaque credential in this server is: the input
    /// already has 256 bits of entropy, so there is nothing to brute force and
    /// a slow hash would only make the lookup slow.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256_hex(self.0.expose().as_bytes())
    }
}

/// A token that has been drawn and is about to be written down.
///
/// One value rather than three arguments, so that a store cannot be handed a
/// digest with somebody else's expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedRecovery {
    /// Whose account this resets.
    pub user: UserId,
    /// The digest of the token that was mailed. The token itself is never
    /// here — it exists in the mail and in the request that spends it.
    pub token_digest: String,
    /// When it was drawn.
    pub issued_at: OffsetDateTime,
    /// When it stops working, whatever else happens.
    pub expires_at: OffsetDateTime,
}

impl IssuedRecovery {
    /// A token for `user`, expiring [`RECOVERY_LIFETIME`] from `now`.
    #[must_use]
    pub fn new(user: UserId, token: &RecoveryToken, now: OffsetDateTime) -> Self {
        Self {
            user,
            token_digest: token.digest(),
            issued_at: now,
            expires_at: now + RECOVERY_LIFETIME,
        }
    }

    /// Whether this token has run out, independently of the store.
    ///
    /// The store enforces the same thing in SQL — that is where the race is
    /// closed — and this exists so the rule can be tested without a database
    /// and asserted on a row that was read for another reason.
    #[must_use]
    pub fn has_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor the ticket names, and the one FAPI 2.0 SP §5.4.1 item 4 sets.
    #[test]
    fn a_token_carries_at_least_128_bits() {
        // Arrange, Act, Assert
        const { assert!(RECOVERY_TOKEN_BITS >= crate::credentials::MIN_ENTROPY_BITS) };
    }

    /// NIST SP 800-63B §6.1.2.3: a short validity, and OWASP's cheat sheet
    /// asks the same. Fifteen minutes is what the ticket fixed.
    #[test]
    fn a_token_lives_fifteen_minutes() {
        // Arrange
        let now = OffsetDateTime::UNIX_EPOCH;

        // Act
        let issued = IssuedRecovery::new(UserId::generate(), &RecoveryToken::generate(), now);

        // Assert
        assert_eq!(issued.expires_at - issued.issued_at, Duration::minutes(15));
    }

    /// One second past the deadline is past it. The boundary is inclusive at
    /// the expiry instant: a token whose `expires_at` is now is spent.
    #[test]
    fn a_token_is_expired_at_its_deadline() {
        // Arrange
        let now = OffsetDateTime::UNIX_EPOCH;
        let issued = IssuedRecovery::new(UserId::generate(), &RecoveryToken::generate(), now);

        // Act
        let expired = issued.has_expired(issued.expires_at);

        // Assert
        assert!(expired);
    }

    /// A token still inside its window is not expired.
    #[test]
    fn a_fresh_token_is_not_expired() {
        // Arrange
        let now = OffsetDateTime::UNIX_EPOCH;
        let issued = IssuedRecovery::new(UserId::generate(), &RecoveryToken::generate(), now);

        // Act
        let expired = issued.has_expired(now + Duration::minutes(14));

        // Assert
        assert!(!expired);
    }

    /// What this server issues is what the parser accepts. A generator and a
    /// parser that disagree is a reset link nobody can use.
    #[test]
    fn a_generated_token_parses() {
        // Arrange
        let token = RecoveryToken::generate();
        let wire = token.expose().to_owned();

        // Act
        let parsed = RecoveryToken::parse(&wire);

        // Assert
        assert_eq!(parsed.expect("a generated token parses").expose(), wire);
    }

    /// The digest is what the row holds, and two readings of one token must
    /// produce the same one or the lookup never matches.
    #[test]
    fn the_digest_is_stable_across_a_round_trip() {
        // Arrange
        let token = RecoveryToken::generate();
        let parsed = RecoveryToken::parse(token.expose()).expect("parse");

        // Act
        let digest = parsed.digest();

        // Assert
        assert_eq!(digest, token.digest());
    }

    /// The digest is not the token. Stated as a test because the whole
    /// "hashed at rest" requirement is this one line being true.
    #[test]
    fn the_digest_is_not_the_token() {
        // Arrange
        let token = RecoveryToken::generate();

        // Act
        let digest = token.digest();

        // Assert
        assert_ne!(digest, token.expose());
    }

    /// A truncated token is refused rather than looked up as a prefix.
    #[test]
    fn a_short_token_is_refused() {
        // Arrange
        let token = RecoveryToken::generate();
        let truncated = token.expose()[..TOKEN_CHARS - 1].to_owned();

        // Act
        let parsed = RecoveryToken::parse(&truncated);

        // Assert
        assert_eq!(parsed.unwrap_err(), RecoveryTokenError::Length);
    }

    /// A token with something appended is a different string, not the same
    /// token with noise. Trailing whitespace is the common form and it is the
    /// one that a trimming parser would turn into a second spelling.
    #[test]
    fn a_token_with_trailing_whitespace_is_refused() {
        // Arrange
        let token = RecoveryToken::generate();
        let padded = format!("{} ", token.expose());

        // Act
        let parsed = RecoveryToken::parse(&padded);

        // Assert
        assert_eq!(parsed.unwrap_err(), RecoveryTokenError::Length);
    }

    /// Standard base64's `+` and `/`, and its `=` padding, are not this
    /// alphabet: RFC 4648 §5 is what makes a token survive a URL unescaped.
    #[test]
    fn a_token_outside_the_url_safe_alphabet_is_refused() {
        // Arrange
        let mut wire = RecoveryToken::generate().expose().to_owned();
        wire.replace_range(0..1, "+");

        // Act
        let parsed = RecoveryToken::parse(&wire);

        // Assert
        assert_eq!(parsed.unwrap_err(), RecoveryTokenError::Alphabet);
    }

    /// A multi-byte character makes `len()` and character count disagree; the
    /// parser must not accept a string it cannot have issued.
    #[test]
    fn a_token_with_a_multibyte_character_is_refused() {
        // Arrange
        let wire = "é".repeat(TOKEN_CHARS);

        // Act
        let parsed = RecoveryToken::parse(&wire);

        // Assert
        assert!(parsed.is_err());
    }

    /// The empty string is the shape a missing form field arrives as.
    #[test]
    fn an_empty_token_is_refused() {
        // Arrange, Act
        let parsed = RecoveryToken::parse("");

        // Assert
        assert_eq!(parsed.unwrap_err(), RecoveryTokenError::Length);
    }

    /// Two draws are two tokens. A generator that repeated itself would hand
    /// one person another person's reset link.
    #[test]
    fn two_tokens_differ() {
        // Arrange, Act
        let first = RecoveryToken::generate();
        let second = RecoveryToken::generate();

        // Assert
        assert_ne!(first.expose(), second.expose());
    }
}
