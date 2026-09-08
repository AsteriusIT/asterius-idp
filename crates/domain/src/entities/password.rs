//! Password policy and Argon2id parameters.
//!
//! Passwords are the legacy path here — passkeys are primary (`ast-2vk.3`,
//! `ast-2vk.4`) — but "legacy" is not "less carefully". A password database is
//! the single most valuable thing this server holds, because people reuse
//! them: a leak here is a leak everywhere that user has an account.
//!
//! # What this module decides, and what it does not
//!
//! It decides the *policy*: what a password may be, and what parameters a hash
//! must have been computed with. It performs no hashing — that needs `argon2`,
//! which is an adapter concern, and keeping the policy here means the rules
//! are testable without computing a single hash.
//!
//! # The parameter floor
//!
//! OWASP's Password Storage Cheat Sheet gives Argon2id m=19 MiB, t=2, p=1 as a
//! minimum. RFC 9106 §4 gives two recommended configurations and is explicit
//! that the second (64 MiB, t=3) is for memory-constrained environments.
//!
//! The floor is enforced **at startup**, not at hash time. A deployment
//! configured below it should fail while somebody is watching, rather than
//! quietly storing weak hashes that nobody notices until the breach.

use std::fmt;

/// Argon2id parameters, known to be at or above the floor.
///
/// Construction is the proof: [`Argon2Parameters::new`] is the only way to make
/// one and it refuses anything weaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Parameters {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// The least memory a hash may be computed with, in KiB.
///
/// 19 MiB, from OWASP's Password Storage Cheat Sheet. Memory is what makes
/// Argon2id expensive to attack in parallel on a GPU; the iteration count
/// alone is not a substitute.
pub const MIN_MEMORY_KIB: u32 = 19 * 1024;

/// The least iterations a hash may be computed with.
pub const MIN_ITERATIONS: u32 = 2;

/// The least parallelism.
pub const MIN_PARALLELISM: u32 = 1;

/// The most memory an operator may ask for, in KiB.
///
/// 1 GiB. Not a security bound — more is stronger — but a configuration
/// mistake that asks for 100 GiB per login turns the login endpoint into a way
/// to exhaust the server's memory, and an unauthenticated caller chooses how
/// often to trigger it.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// The most iterations.
pub const MAX_ITERATIONS: u32 = 16;

impl Default for Argon2Parameters {
    /// OWASP's minimum, which is also a sensible default.
    fn default() -> Self {
        Self {
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: MIN_PARALLELISM,
        }
    }
}

/// Why a set of parameters was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParameterError {
    /// Below [`MIN_MEMORY_KIB`].
    #[error("argon2 memory must be at least {MIN_MEMORY_KIB} KiB")]
    MemoryTooLow,
    /// Below [`MIN_ITERATIONS`].
    #[error("argon2 iterations must be at least {MIN_ITERATIONS}")]
    IterationsTooLow,
    /// Below [`MIN_PARALLELISM`].
    #[error("argon2 parallelism must be at least {MIN_PARALLELISM}")]
    ParallelismTooLow,
    /// Above a bound that would make a login a denial-of-service lever.
    #[error("argon2 parameters are implausibly large")]
    ImplausiblyLarge,
}

impl Argon2Parameters {
    /// Checks parameters against the floor.
    ///
    /// # Errors
    ///
    /// [`ParameterError`] naming the first bound that failed. Call this at
    /// startup: a deployment configured below the floor should not start.
    pub const fn new(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self, ParameterError> {
        if memory_kib < MIN_MEMORY_KIB {
            return Err(ParameterError::MemoryTooLow);
        }
        if iterations < MIN_ITERATIONS {
            return Err(ParameterError::IterationsTooLow);
        }
        if parallelism < MIN_PARALLELISM {
            return Err(ParameterError::ParallelismTooLow);
        }
        if memory_kib > MAX_MEMORY_KIB || iterations > MAX_ITERATIONS {
            return Err(ParameterError::ImplausiblyLarge);
        }
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// Memory cost, in KiB.
    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// Iteration count.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }

    /// Degree of parallelism.
    #[must_use]
    pub const fn parallelism(self) -> u32 {
        self.parallelism
    }

    /// Whether a hash computed with `self` should be recomputed to reach
    /// `target`.
    ///
    /// Rehashing happens on the next *successful* login, which is the only
    /// moment the plaintext is available. That means raising the parameters
    /// upgrades the database gradually, as people sign in, rather than all at
    /// once — and an account that never signs in keeps its old hash, which is
    /// why raising the floor is not a substitute for expiring stale accounts.
    #[must_use]
    pub const fn is_weaker_than(self, target: Self) -> bool {
        self.memory_kib < target.memory_kib
            || self.iterations < target.iterations
            || self.parallelism < target.parallelism
    }
}

impl fmt::Display for Argon2Parameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "m={},t={},p={}",
            self.memory_kib, self.iterations, self.parallelism
        )
    }
}

/// The shortest password accepted.
///
/// NIST SP 800-63B §5.1.1.2: at least 8 characters, measured after
/// normalisation.
pub const MIN_LENGTH: usize = 8;

/// The longest password accepted.
///
/// The same section requires accepting at least 64. 128 is the ceiling here,
/// because Argon2id's cost is independent of input length and an unbounded
/// password is an unbounded allocation on an unauthenticated endpoint.
pub const MAX_LENGTH: usize = 128;

/// Why a password was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PasswordError {
    /// Shorter than [`MIN_LENGTH`] after normalisation.
    #[error("password must be at least {MIN_LENGTH} characters")]
    TooShort,
    /// Longer than [`MAX_LENGTH`].
    #[error("password must be at most {MAX_LENGTH} characters")]
    TooLong,
    /// On the deny list.
    ///
    /// NIST SP 800-63B §5.1.1.2 asks for a check against known-common and
    /// breached values. It explicitly does *not* ask for composition rules,
    /// and this server has none: a rule that forces a digit produces
    /// `Password1`, which is on every list there is.
    #[error("password is too common")]
    TooCommon,
}

/// A password that has passed policy, ready to be hashed.
///
/// Holds the *normalised* form, which is what must be hashed: NIST SP 800-63B
/// §5.1.1.2 requires NFKC so that a password typed on one keyboard verifies
/// when typed on another. Hashing the raw bytes would make a password with a
/// composed accent fail after the user switched devices.
///
/// Wrapped in [`crate::Secret`], so it is redacted in `Debug` and zeroised on
/// drop.
#[derive(Debug)]
pub struct AcceptedPassword(crate::Secret<String>);

impl AcceptedPassword {
    /// Applies policy to a candidate.
    ///
    /// `is_common` decides the deny-list question. It is a closure rather than
    /// a baked-in list so that the list can be large, loaded once, and shared
    /// — and so that a breach-check port (`ast-2vk.10`) can be dropped in
    /// without changing this signature.
    ///
    /// # Errors
    ///
    /// [`PasswordError`] naming what was wrong. The *caller* decides how much
    /// of that to tell the user: on a sign-in form the answer is nothing.
    pub fn accept(
        candidate: &str,
        is_common: impl FnOnce(&str) -> bool,
    ) -> Result<Self, PasswordError> {
        let normalised = normalise(candidate);

        // Counted in characters, not bytes. A password of eight emoji is eight
        // characters and thirty-two bytes; refusing it for being "too long"
        // while accepting eight ASCII letters would be a rule about the user's
        // language rather than about entropy.
        let length = normalised.chars().count();
        if length < MIN_LENGTH {
            return Err(PasswordError::TooShort);
        }
        if length > MAX_LENGTH {
            return Err(PasswordError::TooLong);
        }
        if is_common(&normalised) {
            return Err(PasswordError::TooCommon);
        }

        Ok(Self(crate::Secret::new(normalised)))
    }

    /// The bytes to hash.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

/// Normalises a password for hashing and comparison.
///
/// NIST SP 800-63B §5.1.1.2: "the verifier SHOULD apply the Normalization
/// Process for Stabilized Strings using either the NFKC or NFKD normalization".
/// Without it, the same password typed on a Mac and on Windows can produce
/// different bytes and so a failed login the user cannot explain.
///
/// Trailing and leading whitespace is *not* stripped. It is part of the
/// password the user chose, and quietly trimming it would mean two different
/// passwords authenticate the same account.
// fuzz-target: password_policy
#[must_use]
pub fn normalise(candidate: &str) -> String {
    use unicode_normalization::UnicodeNormalization as _;
    candidate.nfkc().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn never_common(_: &str) -> bool {
        false
    }

    // ---- parameters ------------------------------------------------------

    #[test]
    fn the_owasp_minimum_is_the_default_and_is_accepted() {
        let default = Argon2Parameters::default();
        assert_eq!(default.memory_kib(), 19 * 1024);
        assert_eq!(default.iterations(), 2);
        assert_eq!(default.parallelism(), 1);
        assert_eq!(
            Argon2Parameters::new(19 * 1024, 2, 1),
            Ok(default),
            "the documented OWASP minimum must be constructible"
        );
    }

    /// A deployment configured below the floor should not start.
    #[test]
    fn parameters_below_the_floor_are_refused() {
        assert_eq!(
            Argon2Parameters::new(19 * 1024 - 1, 2, 1),
            Err(ParameterError::MemoryTooLow)
        );
        assert_eq!(
            Argon2Parameters::new(19 * 1024, 1, 1),
            Err(ParameterError::IterationsTooLow)
        );
        assert_eq!(
            Argon2Parameters::new(19 * 1024, 2, 0),
            Err(ParameterError::ParallelismTooLow)
        );
        // Zero everywhere is the shape of an unset configuration.
        assert!(Argon2Parameters::new(0, 0, 0).is_err());
    }

    /// More is stronger, but an unauthenticated caller chooses how often to
    /// trigger a login.
    #[test]
    fn implausible_parameters_are_refused_too() {
        assert_eq!(
            Argon2Parameters::new(MAX_MEMORY_KIB + 1, 2, 1),
            Err(ParameterError::ImplausiblyLarge)
        );
        assert_eq!(
            Argon2Parameters::new(19 * 1024, MAX_ITERATIONS + 1, 1),
            Err(ParameterError::ImplausiblyLarge)
        );
        // The ceiling itself is fine.
        assert!(Argon2Parameters::new(MAX_MEMORY_KIB, MAX_ITERATIONS, 1).is_ok());
    }

    #[test]
    fn a_weaker_hash_is_recognised_for_rehashing() {
        let floor = Argon2Parameters::default();
        let stronger = Argon2Parameters::new(64 * 1024, 3, 2).expect("valid");

        assert!(floor.is_weaker_than(stronger));
        assert!(!stronger.is_weaker_than(floor));
        assert!(!floor.is_weaker_than(floor), "equal is not weaker");

        // Weaker in any single dimension counts.
        let more_memory_fewer_rounds = Argon2Parameters::new(64 * 1024, 2, 1).expect("valid");
        assert!(
            more_memory_fewer_rounds.is_weaker_than(stronger),
            "fewer iterations is weaker even with more memory"
        );
    }

    // ---- policy ----------------------------------------------------------

    #[test]
    fn a_reasonable_password_is_accepted() {
        let accepted =
            AcceptedPassword::accept("correct horse battery staple", never_common).expect("accept");
        assert_eq!(accepted.expose(), "correct horse battery staple");
    }

    /// NIST SP 800-63B §5.1.1.2: at least 8, and at least 64 must be allowed.
    #[test]
    fn the_length_bounds_are_the_ones_the_guidance_names() {
        assert_eq!(
            AcceptedPassword::accept("short7!", never_common).err(),
            Some(PasswordError::TooShort)
        );
        assert!(AcceptedPassword::accept("eight8!!", never_common).is_ok());

        // 64 characters must be accepted.
        let sixty_four = "a".repeat(64);
        assert!(AcceptedPassword::accept(&sixty_four, never_common).is_ok());

        assert!(AcceptedPassword::accept(&"a".repeat(MAX_LENGTH), never_common).is_ok());
        assert_eq!(
            AcceptedPassword::accept(&"a".repeat(MAX_LENGTH + 1), never_common).err(),
            Some(PasswordError::TooLong)
        );
    }

    /// Length is counted in characters. Refusing eight emoji for being "too
    /// long" would be a rule about the user's language.
    #[test]
    fn length_is_measured_in_characters_not_bytes() {
        let eight_emoji = "🔑🔑🔑🔑🔑🔑🔑🔑";
        assert_eq!(eight_emoji.len(), 32, "the fixture is multi-byte");
        assert_eq!(eight_emoji.chars().count(), 8);
        assert!(
            AcceptedPassword::accept(eight_emoji, never_common).is_ok(),
            "an eight-character password was refused for its byte length"
        );
    }

    /// NFKC, so the same password typed on two keyboards verifies.
    #[test]
    fn passwords_are_normalised_before_hashing() {
        // "é" composed (U+00E9) and decomposed (U+0065 U+0301).
        let composed = "caf\u{e9}wordsss";
        let decomposed = "cafe\u{301}wordsss";
        assert_ne!(composed, decomposed, "the fixture is not already equal");

        let a = AcceptedPassword::accept(composed, never_common).expect("accept");
        let b = AcceptedPassword::accept(decomposed, never_common).expect("accept");
        assert_eq!(
            a.expose(),
            b.expose(),
            "two spellings of one password would hash differently"
        );
    }

    /// Whitespace is part of the password. Trimming it would mean two
    /// different passwords authenticate one account.
    #[test]
    fn surrounding_whitespace_is_preserved() {
        let padded = AcceptedPassword::accept("  spaced out  ", never_common).expect("accept");
        assert_eq!(padded.expose(), "  spaced out  ");
        assert_ne!(padded.expose(), "spaced out");
    }

    /// A deny list, and no composition rules — a rule that forces a digit
    /// produces `Password1`.
    #[test]
    fn a_common_password_is_refused_and_no_composition_rule_exists() {
        assert_eq!(
            AcceptedPassword::accept("password123", |candidate| candidate == "password123").err(),
            Some(PasswordError::TooCommon)
        );

        // All lower case, no digit, no symbol: accepted, because there is no
        // composition rule to fail.
        assert!(AcceptedPassword::accept("plainlowercasewords", never_common).is_ok());
    }

    /// The deny list sees the *normalised* form, or a user could evade it with
    /// a different spelling of the same string.
    #[test]
    fn the_deny_list_is_consulted_with_the_normalised_password() {
        let seen = std::cell::RefCell::new(String::new());
        let _ = AcceptedPassword::accept("cafe\u{301}wordsss", |candidate| {
            seen.borrow_mut().push_str(candidate);
            false
        });
        assert_eq!(
            seen.into_inner(),
            "caf\u{e9}wordsss",
            "the deny list saw the raw form, so a different spelling evades it"
        );
    }

    #[test]
    fn an_accepted_password_is_redacted_in_debug() {
        let accepted =
            AcceptedPassword::accept("correct horse battery", never_common).expect("accept");
        let rendered = format!("{accepted:?}");
        assert!(!rendered.contains("correct horse"), "{rendered}");
        assert!(rendered.contains("REDACTED"), "{rendered}");
    }

    #[test]
    fn normalisation_is_idempotent() {
        for candidate in [
            "plain",
            "cafe\u{301}",
            "ﬁle",
            "①②③",
            "",
            "  spaced  ",
            "\u{fb01}n",
        ] {
            let once = normalise(candidate);
            assert_eq!(normalise(&once), once, "for {candidate:?}");
        }
    }
}
