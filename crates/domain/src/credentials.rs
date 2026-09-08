//! Credential material: how it is drawn, how it is compared, how it is stored.
//!
//! Everything this server issues that is not a JWT is an [`OpaqueToken`] —
//! authorization codes, refresh tokens, device codes, `auth_req_id`,
//! registration access tokens, CSRF tokens. Such a token has no structure,
//! carries no claims and means nothing outside the row that records it, so its
//! entire security rests on three properties: it cannot be guessed, comparing
//! it leaks nothing about it, and a copy of the database does not contain it.
//!
//! FAPI 2.0 SP §5.4.1 item 4 sets the first of those: a credential that an end
//! user never handles must carry at least 128 bits of entropy. RFC 6749 §10.10
//! says the same thing from the other end — an authorization code or a refresh
//! token is a bearer credential, so a guessable one is an account. RFC 8628
//! §6.1 sets a deliberately *lower* bar for the device-flow user code, because
//! a human reads that one aloud; it is not an [`OpaqueToken`] and will get its
//! own type, with its own rate limit, when the device flow lands.
//!
//! This module reads the operating system CSPRNG directly rather than through a
//! port, which is the one place `asterius-domain` touches the outside world.
//! ADR-0001's rule exists so that protocol logic can be tested without a
//! database and so that an adapter can be swapped; neither applies here. The OS
//! CSPRNG is in the trusted computing base (see `docs/threat-model.md` §2), it
//! has no alternative implementation worth having, and a port would add exactly
//! one thing: a seam through which a deterministic test double could be
//! injected into a running server. That is a worse outcome than the rule it
//! would satisfy.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use std::fmt;
use zeroize::Zeroize as _;

use crate::secret::Secret;

/// What [`OpaqueToken::generate`] draws, and what every issuing path should
/// use unless a specification says otherwise.
///
/// Twice the FAPI floor, for 43 characters. The margin is not superstition: a
/// token is looked up by digest, so the relevant bound is a collision across
/// every token a deployment ever issues, and 128 bits leaves less headroom
/// there than the same number does against a direct guess.
pub const DEFAULT_ENTROPY_BITS: usize = 256;

/// The floor from FAPI 2.0 SP §5.4.1 item 4.
pub const MIN_ENTROPY_BITS: usize = 128;

/// The ceiling.
///
/// Not a security bound — it is what lets the raw entropy live in a fixed stack
/// buffer, so those bytes never reach the allocator and cannot survive in a
/// freed block that nothing wipes. No OAuth credential needs more than this.
const MAX_ENTROPY_BITS: usize = 512;

/// Whether `bits` is an entropy size [`OpaqueToken`] will produce.
///
/// This is a separate function from the `const` block that enforces it so that
/// the rule can be tested. The `const` block is the guarantee — it makes a
/// short token a compile error — and this is how we check the rule it enforces
/// is the rule we meant.
#[must_use]
pub const fn is_permitted_entropy(bits: usize) -> bool {
    bits >= MIN_ENTROPY_BITS && bits <= MAX_ENTROPY_BITS && bits.is_multiple_of(8)
}

/// A credential with no internal structure, drawn from the operating system
/// CSPRNG and rendered as unpadded `base64url`.
///
/// The alphabet is [RFC 4648 §5] without padding, which is what makes a token
/// safe to put in a URL, a form field, a header and a JSON string without any
/// further escaping — and therefore what stops a token being mangled on one
/// path and compared against its unmangled self on another.
///
/// Like [`Secret`], it prints `[REDACTED]`, zeroes on drop, and does **not**
/// implement `PartialEq`: see [`crate::secret`] for why that absence is the
/// point rather than an oversight.
///
/// [RFC 4648 §5]: https://www.rfc-editor.org/rfc/rfc4648#section-5
pub struct OpaqueToken(Secret<String>);

impl OpaqueToken {
    /// Draws a token with [`DEFAULT_ENTROPY_BITS`] of entropy.
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_bits::<DEFAULT_ENTROPY_BITS>()
    }

    /// Draws a token carrying exactly `BITS` bits of entropy.
    ///
    /// `BITS` is a const parameter rather than an argument on purpose. The FAPI
    /// floor is then a compile error, not a `Result` that a caller can unwrap
    /// or a runtime panic that only fires on the path nobody tested — and there
    /// is no way to reach this code with a size that has not been checked.
    ///
    /// Use it only where a specification names a different size; everything
    /// else should call [`Self::generate`].
    #[must_use]
    pub fn generate_bits<const BITS: usize>() -> Self {
        const {
            assert!(
                is_permitted_entropy(BITS),
                "token entropy must be a whole number of bytes, at least 128 bits (FAPI 2.0 SP §5.4.1) and at most 512"
            );
        }

        let mut buffer = [0_u8; MAX_ENTROPY_BITS / 8];
        // A failure here is the operating system refusing to seed us. Carrying
        // on would mint a credential out of a buffer of zeros, so there is
        // nothing to fall back to and nothing to log: stop.
        getrandom::fill(&mut buffer[..BITS / 8]).expect("the OS CSPRNG must be available");
        let token = URL_SAFE_NO_PAD.encode(&buffer[..BITS / 8]);
        // The encoded String is the only copy we keep; wipe the raw draw before
        // the stack slot is reused by whatever runs next.
        buffer.zeroize();
        Self(Secret::new(token))
    }

    /// Wraps a token that arrived from a client.
    ///
    /// Nothing is validated here, and that is deliberate. Every path that
    /// consumes a presented token either hashes it or compares it in constant
    /// time, neither of which cares about its shape — so a length or charset
    /// check would buy no safety and would hand an attacker a second, much
    /// cheaper oracle: a malformed token rejected before the lookup is
    /// distinguishable from a well-formed one that simply does not exist.
    #[must_use]
    pub fn from_presented(value: String) -> Self {
        Self(Secret::new(value))
    }

    /// The token as text.
    ///
    /// Two call sites are legitimate: putting a freshly generated token into a
    /// response, and handing a presented one to storage or to a comparison.
    /// Every other one is a leak, which is why this is a named method and not a
    /// `Display` impl.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose().as_str()
    }

    /// The at-rest form: SHA-256 of the token, lower-case hex.
    ///
    /// The row stores this and never the token itself, so a backup, a read
    /// replica or a `pg_dump` pasted into a support ticket contains nothing
    /// replayable. Plain SHA-256 rather than Argon2id is the right choice
    /// *here* and only here: the input is CSPRNG output with no dictionary to
    /// slow down, and a memory-hard hash on the token lookup path would be a
    /// denial-of-service surface an unauthenticated caller could pull on.
    /// Passwords, which do have a dictionary, get Argon2id.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256_hex(self.expose().as_bytes())
    }

    /// Whether `other` is the same token, in time that does not depend on how
    /// many leading characters match.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for OpaqueToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// SHA-256 of `bytes`, lower-case hex.
///
/// This is the only at-rest form for an opaque credential. It is a bare digest
/// with no salt, because the lookup has to find the row *by* the digest — a
/// per-row salt would force a table scan, and the property that makes salting
/// unnecessary is the same one that makes the bare digest safe: the input has
/// at least 128 bits of entropy, so there is no candidate set to precompute.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// FAPI 2.0 SP §5.4.1 item 4: credentials not handled by an end user carry
    /// at least 128 bits of entropy. The default doubles it.
    #[test]
    fn the_default_token_carries_256_bits_of_entropy() {
        let token = OpaqueToken::generate();
        let raw = URL_SAFE_NO_PAD
            .decode(token.expose())
            .expect("a generated token is valid base64url");
        assert_eq!(raw.len() * 8, DEFAULT_ENTROPY_BITS);
    }

    #[test]
    fn a_token_is_unpadded_base64url_and_survives_a_url_intact() {
        let token = OpaqueToken::generate_bits::<128>();
        assert_eq!(token.expose().len(), 22, "128 bits is 22 base64 symbols");
        assert!(
            token
                .expose()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "token left the RFC 4648 §5 alphabet: {}",
            token.expose()
        );
    }

    /// The entropy floor is enforced by a `const` block, so a violation never
    /// reaches a test — it fails to build. What can be tested is the predicate
    /// that block asserts, which is where a mistake would actually live.
    #[test]
    fn the_entropy_floor_rejects_everything_below_the_fapi_minimum() {
        assert!(!is_permitted_entropy(0));
        assert!(!is_permitted_entropy(64));
        assert!(!is_permitted_entropy(MIN_ENTROPY_BITS - 8));
        assert!(is_permitted_entropy(MIN_ENTROPY_BITS));
        assert!(is_permitted_entropy(DEFAULT_ENTROPY_BITS));
        // A size that is not a whole number of bytes would silently round down
        // to fewer bits than the caller asked for.
        assert!(!is_permitted_entropy(129));
        // Above the ceiling the fixed stack buffer would overflow its slice.
        assert!(!is_permitted_entropy(MAX_ENTROPY_BITS + 8));
    }

    /// How many tokens the statistical checks draw.
    ///
    /// Large enough that a generator returning anything but full-entropy output
    /// fails loudly, small enough to stay a few milliseconds: the suite is
    /// sub-second by policy, and a slow check is a check that gets deleted.
    const DRAWS: usize = 4096;

    #[test]
    fn no_two_tokens_out_of_thousands_are_ever_the_same() {
        let tokens: HashSet<String> = (0..DRAWS)
            .map(|_| OpaqueToken::generate().expose().to_owned())
            .collect();
        assert_eq!(
            tokens.len(),
            DRAWS,
            "the generator repeated itself; at 256 bits a collision in {DRAWS} draws \
             means the source is not the CSPRNG we think it is"
        );
    }

    #[test]
    fn token_symbols_are_uniform_across_the_whole_base64url_alphabet() {
        // Only the first 42 symbols of a 43-character token are full 6-bit
        // groups; the last one carries the 4 leftover bits of the 32nd byte and
        // can therefore only take 16 values. Including it would make a correct
        // generator look skewed.
        const FULL_SYMBOLS: usize = 42;
        const ALPHABET: usize = 64;

        let mut counts = [0_usize; ALPHABET];
        for _ in 0..DRAWS {
            let token = OpaqueToken::generate();
            for symbol in token.expose().bytes().take(FULL_SYMBOLS) {
                counts[symbol_index(symbol)] += 1;
            }
        }

        let observed = DRAWS * FULL_SYMBOLS;
        #[allow(clippy::cast_precision_loss)]
        let expected = observed as f64 / ALPHABET as f64;
        assert!(
            counts.iter().all(|&count| count > 0),
            "some symbols never appeared, so the generator cannot reach part of \
             its own alphabet: {counts:?}"
        );

        // Pearson's chi-square over 63 degrees of freedom. A uniform source
        // scores about 63; the threshold below is exceeded with probability
        // around 3e-10, so a failure here is a broken generator and not a bad
        // day. A stuck bit or a truncated draw scores in the thousands.
        #[allow(clippy::cast_precision_loss)]
        let chi_square: f64 = counts
            .iter()
            .map(|&count| {
                let deviation = count as f64 - expected;
                deviation * deviation / expected
            })
            .sum();
        assert!(
            chi_square < 160.0,
            "symbol distribution is skewed: chi-square {chi_square:.1} over 63 \
             degrees of freedom, expected around 63"
        );
    }

    /// Position of a `base64url` symbol in the RFC 4648 §5 alphabet.
    fn symbol_index(symbol: u8) -> usize {
        let index = match symbol {
            b'A'..=b'Z' => symbol - b'A',
            b'a'..=b'z' => symbol - b'a' + 26,
            b'0'..=b'9' => symbol - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            other => panic!(
                "token contained {:?}, which is not base64url",
                other as char
            ),
        };
        usize::from(index)
    }

    #[test]
    fn a_token_never_prints_itself() {
        let token = OpaqueToken::generate();
        assert_eq!(format!("{token:?}"), "[REDACTED]");
        assert_eq!(format!("{token}"), "[REDACTED]");
        assert!(!format!("{token:?} {token}").contains(token.expose()));
    }

    #[test]
    fn a_token_matches_itself_and_nothing_else() {
        let token = OpaqueToken::generate();
        let presented = OpaqueToken::from_presented(token.expose().to_owned());
        assert!(token.ct_eq(&presented));

        let other = OpaqueToken::generate();
        assert!(!token.ct_eq(&other));

        // A prefix must not match: this is the case a short-circuiting
        // comparison would answer faster than a full mismatch.
        let prefix = OpaqueToken::from_presented(token.expose()[..10].to_owned());
        assert!(!token.ct_eq(&prefix));
    }

    /// The digest is what the database holds, so it has to be stable across
    /// processes and match what any other SHA-256 implementation would produce
    /// for the same input — otherwise a token issued before an upgrade stops
    /// being redeemable after it.
    #[test]
    fn the_stored_digest_is_plain_sha_256_hex() {
        // RFC 6234 §8.5 test vector: SHA-256 of "abc".
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let token = OpaqueToken::from_presented("abc".to_owned());
        assert_eq!(token.digest(), sha256_hex(b"abc"));
        assert_eq!(token.digest().len(), 64);
    }

    #[test]
    fn the_digest_of_a_token_does_not_contain_the_token() {
        let token = OpaqueToken::generate();
        let digest = token.digest();
        assert!(
            !digest.contains(token.expose()),
            "the at-rest form leaked the credential it is meant to replace"
        );
        assert_ne!(OpaqueToken::generate().digest(), digest);
    }
}
