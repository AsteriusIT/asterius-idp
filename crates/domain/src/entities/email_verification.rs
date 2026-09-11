//! Email verification: the token a confirmation link carries, and the one
//! thing it is allowed to prove.
//!
//! # What this token is worth, and what it is not
//!
//! A [`crate::RecoveryToken`] is a credential that *resets* credentials:
//! holding one is holding the account. This one is deliberately weaker. All it
//! establishes is that whoever followed the link could read mail sent to one
//! address at one moment — which is precisely what OIDC Core §5.1 says
//! `email_verified` asserts, and nothing more. It signs nobody in, it sets no
//! credential, and a handler that treated it as an authentication would have
//! turned "prove you can read this mailbox" into "take this account", which is
//! account takeover by way of a sign-up form.
//!
//! It is still built to the same specification as the recovery token — 256
//! bits, single use, fifteen minutes, stored as a digest — for two reasons.
//! The first is that `email_verified` is an assertion relying parties act on:
//! Core §5.1 warns that the claim is not unique and that an RP must not use it
//! as an identifier, but plenty of them provision accounts from it anyway, so a
//! guessable confirmation link is an account takeover *at the relying party*.
//! The second is that this deployment already has one opaque-token discipline
//! and a second, weaker one would be the one somebody copies next.
//!
//! # The address is in the row, not inferred at spend time
//!
//! [`IssuedEmailVerification`] carries the address the message went to, and
//! [`crate::EmailVerificationStore::spend`] hands it back. The handler must
//! compare it with the address the account holds *now* before it writes
//! `email_verified = true`.
//!
//! Without that, the flow is an attacker's: sign up as `attacker@evil.test`,
//! ask for a link, change the address on the account to `victim@bank.test`
//! through the account pages, then follow the link that is still outstanding.
//! The token was proved against a mailbox the attacker owns and the flag would
//! land on a mailbox they do not. Storing what was proved, rather than
//! recomputing it from mutable state at the end, is what closes that; the
//! store also supersedes a user's outstanding tokens whenever a new one is
//! drawn, which closes the same door from the other side.

use crate::credentials::{OpaqueToken, sha256_hex};
use crate::entities::user::UserId;
use time::{Duration, OffsetDateTime};

/// How much entropy a verification token carries.
///
/// 256 bits, like every other opaque credential this server issues. The
/// ticket's floor is 128 and this is well past it; see the module
/// documentation for why the floor applies to a token that authenticates
/// nobody.
pub const EMAIL_VERIFICATION_TOKEN_BITS: usize = 256;

/// The number of `base64url` characters [`EMAIL_VERIFICATION_TOKEN_BITS`]
/// encodes to.
///
/// Unpadded base64 is four characters per three bytes; 32 bytes is 42 whole
/// characters plus one carrying the last two bits.
const TOKEN_CHARS: usize = 43;

/// How long a verification link is good for.
///
/// Fifteen minutes, the same as [`crate::RECOVERY_LIFETIME`], and the same
/// number for the same reason: long enough to arrive and be clicked, short
/// enough that a link left in an unattended mailbox is not a standing
/// assertion about that mailbox. The resend button is what a person who was
/// slower than that uses.
pub const EMAIL_VERIFICATION_LIFETIME: Duration = Duration::minutes(15);

/// Why a presented string is not a verification token.
///
/// Coarse at the boundary, like [`crate::RecoveryTokenError`]: nothing built
/// from this is shown to whoever presented it, because "your token is 42
/// characters long" is a hint about the shape of the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EmailVerificationTokenError {
    /// Not the length this server issues.
    #[error("an email verification token is not this length")]
    Length,
    /// A character outside unpadded `base64url` (RFC 4648 §5).
    #[error("an email verification token contains a character it cannot contain")]
    Alphabet,
}

/// A syntactically well-formed verification token.
///
/// Holding one says nothing about whether it exists, is unspent or has
/// expired — that is [`crate::EmailVerificationStore::spend`]'s answer. It says
/// only that this string is the right shape to look up, which is what stops
/// the lookup being a place to send arbitrary bytes.
///
/// Prints redacted and does not implement `PartialEq`: comparison happens on
/// the digest, in the database.
#[derive(Debug)]
pub struct EmailVerificationToken(OpaqueToken);

impl EmailVerificationToken {
    /// Draws a fresh token.
    #[must_use]
    pub fn generate() -> Self {
        Self(OpaqueToken::generate_bits::<EMAIL_VERIFICATION_TOKEN_BITS>())
    }

    /// Reads a token that arrived from a browser.
    ///
    /// # Errors
    ///
    /// [`EmailVerificationTokenError`] when the string is not the exact shape
    /// this server issues. No repair is attempted — no trimming, no padding
    /// tolerance, no case folding — because a parser that repaired its input
    /// would make two spellings name one token, and single use is a property
    /// of a row rather than of a spelling.
    // fuzz-target: email_verification_token
    pub fn parse(presented: &str) -> Result<Self, EmailVerificationTokenError> {
        if presented.len() != TOKEN_CHARS {
            return Err(EmailVerificationTokenError::Length);
        }
        if !presented
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(EmailVerificationTokenError::Alphabet);
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
/// One value rather than four arguments, so that a store cannot be handed a
/// digest with somebody else's address or somebody else's expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedEmailVerification {
    /// Whose address this confirms.
    pub user: UserId,
    /// The address the message was sent to, recorded as it was at that moment.
    ///
    /// This is the fact the token proves, and it is stored rather than
    /// recomputed: see the module documentation on the change-address attack.
    pub address: String,
    /// The digest of the token that was mailed. The token itself is never
    /// here — it exists in the mail and in the request that spends it.
    pub token_digest: String,
    /// When it was drawn.
    pub issued_at: OffsetDateTime,
    /// When it stops working, whatever else happens.
    pub expires_at: OffsetDateTime,
}

impl IssuedEmailVerification {
    /// A token for `user` at `address`, expiring
    /// [`EMAIL_VERIFICATION_LIFETIME`] from `now`.
    #[must_use]
    pub fn new(
        user: UserId,
        address: &str,
        token: &EmailVerificationToken,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            user,
            address: address.to_owned(),
            token_digest: token.digest(),
            issued_at: now,
            expires_at: now + EMAIL_VERIFICATION_LIFETIME,
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

/// What spending a token established.
///
/// Two facts and not one, because the handler needs both to decide whether the
/// flag may be written: *whose* account, and *which address* was proved. A
/// store that returned only the user would have made the change-address attack
/// in the module documentation unfixable at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAddress {
    /// The account the token was issued for.
    pub user: UserId,
    /// The address that has just been proved readable.
    pub address: String,
}

impl VerifiedAddress {
    /// Whether this proof is about the address the account holds now.
    ///
    /// The comparison is ASCII-case-insensitive on the whole string. That is
    /// wider than the RFC 5321 §2.4 rule — a local part is case sensitive and
    /// only the domain is not — and wider is the safe direction here: the two
    /// strings being compared are both addresses *this server recorded for
    /// this account*, so the only way they differ in case is that somebody
    /// re-entered their own address differently, and refusing that would strand
    /// a real person. It never admits a different mailbox, because a different
    /// mailbox differs by more than case.
    ///
    /// # Errors
    ///
    /// Nothing; `false` is the whole of the refusal, and the caller must treat
    /// it as "do not write the flag".
    #[must_use]
    pub fn still_matches(&self, current: Option<&str>) -> bool {
        current.is_some_and(|current| current.eq_ignore_ascii_case(&self.address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor the ticket names, and the one FAPI 2.0 SP §5.4.1 item 4 sets
    /// for the credentials this server issues.
    #[test]
    fn a_token_carries_at_least_128_bits() {
        // Arrange, Act, Assert
        const {
            assert!(EMAIL_VERIFICATION_TOKEN_BITS >= crate::credentials::MIN_ENTROPY_BITS);
        };
    }

    /// Fifteen minutes, as the ticket fixed it.
    #[test]
    fn a_token_lives_fifteen_minutes() {
        // Arrange
        let now = OffsetDateTime::UNIX_EPOCH;

        // Act
        let issued = IssuedEmailVerification::new(
            UserId::generate(),
            "ada@example.test",
            &EmailVerificationToken::generate(),
            now,
        );

        // Assert
        assert_eq!(issued.expires_at - issued.issued_at, Duration::minutes(15));
    }

    /// The boundary is inclusive at the expiry instant.
    #[test]
    fn a_token_is_expired_at_its_deadline() {
        // Arrange
        let issued = IssuedEmailVerification::new(
            UserId::generate(),
            "ada@example.test",
            &EmailVerificationToken::generate(),
            OffsetDateTime::UNIX_EPOCH,
        );

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
        let issued = IssuedEmailVerification::new(
            UserId::generate(),
            "ada@example.test",
            &EmailVerificationToken::generate(),
            now,
        );

        // Act
        let expired = issued.has_expired(now + Duration::minutes(14));

        // Assert
        assert!(!expired);
    }

    /// The address the message went to is what the row records, so that the
    /// flag can only ever land on the mailbox that was proved.
    #[test]
    fn an_issued_token_records_the_address_it_was_sent_to() {
        // Arrange
        let address = "ada@example.test";

        // Act
        let issued = IssuedEmailVerification::new(
            UserId::generate(),
            address,
            &EmailVerificationToken::generate(),
            OffsetDateTime::UNIX_EPOCH,
        );

        // Assert
        assert_eq!(issued.address, address);
    }

    /// What this server issues is what the parser accepts. A generator and a
    /// parser that disagree is a confirmation link nobody can use.
    #[test]
    fn a_generated_token_parses() {
        // Arrange
        let token = EmailVerificationToken::generate();
        let wire = token.expose().to_owned();

        // Act
        let parsed = EmailVerificationToken::parse(&wire);

        // Assert
        assert_eq!(parsed.expect("a generated token parses").expose(), wire);
    }

    /// The digest is what the row holds, and two readings of one token must
    /// produce the same one or the lookup never matches.
    #[test]
    fn the_digest_is_stable_across_a_round_trip() {
        // Arrange
        let token = EmailVerificationToken::generate();
        let parsed = EmailVerificationToken::parse(token.expose()).expect("parse");

        // Act
        let digest = parsed.digest();

        // Assert
        assert_eq!(digest, token.digest());
    }

    /// "Hashed at rest" is this one line being true.
    #[test]
    fn the_digest_is_not_the_token() {
        // Arrange
        let token = EmailVerificationToken::generate();

        // Act
        let digest = token.digest();

        // Assert
        assert_ne!(digest, token.expose());
    }

    /// A truncated token is refused rather than looked up as a prefix.
    #[test]
    fn a_short_token_is_refused() {
        // Arrange
        let token = EmailVerificationToken::generate();
        let truncated = token.expose()[..TOKEN_CHARS - 1].to_owned();

        // Act
        let parsed = EmailVerificationToken::parse(&truncated);

        // Assert
        assert_eq!(parsed.unwrap_err(), EmailVerificationTokenError::Length);
    }

    /// Trailing whitespace is the common way a token arrives mangled, and it
    /// is the one a trimming parser would turn into a second spelling.
    #[test]
    fn a_token_with_trailing_whitespace_is_refused() {
        // Arrange
        let padded = format!("{} ", EmailVerificationToken::generate().expose());

        // Act
        let parsed = EmailVerificationToken::parse(&padded);

        // Assert
        assert_eq!(parsed.unwrap_err(), EmailVerificationTokenError::Length);
    }

    /// Standard base64's `+` and `/` are not this alphabet: RFC 4648 §5 is
    /// what makes a token survive a URL unescaped.
    #[test]
    fn a_token_outside_the_url_safe_alphabet_is_refused() {
        // Arrange
        let mut wire = EmailVerificationToken::generate().expose().to_owned();
        wire.replace_range(0..1, "+");

        // Act
        let parsed = EmailVerificationToken::parse(&wire);

        // Assert
        assert_eq!(parsed.unwrap_err(), EmailVerificationTokenError::Alphabet);
    }

    /// The empty string is the shape a missing query parameter arrives as.
    #[test]
    fn an_empty_token_is_refused() {
        // Arrange, Act
        let parsed = EmailVerificationToken::parse("");

        // Assert
        assert_eq!(parsed.unwrap_err(), EmailVerificationTokenError::Length);
    }

    /// Two draws are two tokens.
    #[test]
    fn two_tokens_differ() {
        // Arrange, Act
        let first = EmailVerificationToken::generate();
        let second = EmailVerificationToken::generate();

        // Assert
        assert_ne!(first.expose(), second.expose());
    }

    /// The attack the address column exists for: a link proved against one
    /// mailbox must not confirm another.
    #[test]
    fn a_proof_does_not_match_an_address_that_has_since_changed() {
        // Arrange
        let proved = VerifiedAddress {
            user: UserId::generate(),
            address: "attacker@evil.test".to_owned(),
        };

        // Act
        let matches = proved.still_matches(Some("victim@bank.test"));

        // Assert
        assert!(!matches);
    }

    /// The ordinary case: the address has not moved.
    #[test]
    fn a_proof_matches_the_address_it_was_sent_to() {
        // Arrange
        let proved = VerifiedAddress {
            user: UserId::generate(),
            address: "ada@example.test".to_owned(),
        };

        // Act
        let matches = proved.still_matches(Some("ada@example.test"));

        // Assert
        assert!(matches);
    }

    /// Case is not a different mailbox, and refusing it would strand somebody
    /// who retyped their own address.
    #[test]
    fn a_proof_matches_its_address_in_another_case() {
        // Arrange
        let proved = VerifiedAddress {
            user: UserId::generate(),
            address: "Ada@Example.Test".to_owned(),
        };

        // Act
        let matches = proved.still_matches(Some("ada@example.test"));

        // Assert
        assert!(matches);
    }

    /// An account whose address has been removed has nothing to confirm.
    #[test]
    fn a_proof_matches_no_address_at_all() {
        // Arrange
        let proved = VerifiedAddress {
            user: UserId::generate(),
            address: "ada@example.test".to_owned(),
        };

        // Act
        let matches = proved.still_matches(None);

        // Assert
        assert!(!matches);
    }
}
