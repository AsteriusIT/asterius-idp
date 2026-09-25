//! RFC 6238 TOTP primitives (`ast-s36.15.1`).
//!
//! This module supplies the algorithm and secret handling only. It does not
//! decide enrollment, accepted clock skew, rate limits, replay prevention or
//! which tenant policies may accept TOTP; those belong to the dependent
//! lifecycle and authentication work.

use crate::secret::Secret;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::fmt;

/// RFC 6238's interoperable default step size.
pub const DEFAULT_STEP_SECONDS: u64 = 30;
/// The default number of decimal digits returned by authenticator apps.
pub const DEFAULT_DIGITS: u32 = 6;
/// The seed length recommended for HMAC-SHA-1 by RFC 6238 §5.1.
pub const SECRET_LENGTH: usize = 20;

/// Why a TOTP value could not be generated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TotpError {
    /// The operating system's cryptographic random source failed.
    #[error("cannot generate a TOTP secret")]
    Random,
    /// The caller supplied a zero period or a digit count outside 6–8.
    #[error("invalid TOTP parameters")]
    Parameters,
    /// HMAC rejected its key. This is unreachable for the fixed-size secret,
    /// but returned instead of relying on an unchecked crypto invariant.
    #[error("invalid TOTP secret length")]
    SecretLength,
}

/// A per-account TOTP seed.
///
/// `Debug` is always redacted and the bytes are zeroized when this value drops.
/// Call [`Self::expose`] only while constructing a one-time enrollment response;
/// never include that response in logs or return it after enrollment confirms.
pub struct TotpSecret(Secret<[u8; SECRET_LENGTH]>);

impl TotpSecret {
    /// Generates a fresh seed from the operating system's cryptographic RNG.
    ///
    /// # Errors
    ///
    /// [`TotpError::Random`] if the operating system cannot provide random
    /// bytes. Enrollment must fail closed in that case.
    pub fn generate() -> Result<Self, TotpError> {
        let mut bytes = [0_u8; SECRET_LENGTH];
        getrandom::fill(&mut bytes).map_err(|_| TotpError::Random)?;
        Ok(Self(Secret::new(bytes)))
    }

    /// Wraps seed material read from a protected store or supplied by a test.
    ///
    /// The length is fixed in the type, so a caller cannot install a short key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_LENGTH]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Borrows seed bytes for provisioning or encrypted storage.
    ///
    /// This is intentionally explicit because an ordinary byte slice loses the
    /// redaction and zeroization guarantees of this wrapper.
    #[must_use]
    pub const fn expose(&self) -> &[u8; SECRET_LENGTH] {
        self.0.expose()
    }

    /// Computes the default six-digit code for a Unix timestamp.
    ///
    /// RFC 6238 §4.2 uses floor division of Unix time by the period and encodes
    /// that moving factor as an eight-byte, big-endian counter.
    pub fn code_at(&self, unix_seconds: u64) -> Result<String, TotpError> {
        self.code_at_with(unix_seconds, DEFAULT_STEP_SECONDS, DEFAULT_DIGITS)
    }

    /// Computes a code with an explicit period and digit count.
    ///
    /// Eight digits are permitted for RFC 6238's published test vectors. A
    /// period of zero and digit counts outside 6–8 are refused.
    pub fn code_at_with(
        &self,
        unix_seconds: u64,
        step_seconds: u64,
        digits: u32,
    ) -> Result<String, TotpError> {
        if step_seconds == 0 || !(6..=8).contains(&digits) {
            return Err(TotpError::Parameters);
        }

        let counter = (unix_seconds / step_seconds).to_be_bytes();
        let mut mac =
            Hmac::<Sha1>::new_from_slice(self.0.expose()).map_err(|_| TotpError::SecretLength)?;
        mac.update(&counter);
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 0x0f);
        let binary = u32::from_be_bytes([
            digest[offset],
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]) & 0x7fff_ffff;
        let modulus = 10_u32.pow(digits);
        Ok(format!(
            "{:0width$}",
            binary % modulus,
            width = digits as usize
        ))
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> TotpSecret {
        TotpSecret::from_bytes(*b"12345678901234567890")
    }

    /// RFC 6238 Appendix B's SHA-1 vectors, using the RFC's eight-digit form.
    #[test]
    fn matches_rfc_6238_sha1_test_vectors() {
        let seed = secret();
        for (timestamp, expected) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(
                seed.code_at_with(timestamp, 30, 8)
                    .expect("RFC parameters are valid"),
                expected,
                "timestamp {timestamp}"
            );
        }
    }

    /// The same vector truncated to the six digits an authenticator displays.
    #[test]
    fn default_code_uses_six_digits_and_thirty_second_steps() {
        assert_eq!(secret().code_at(59).expect("valid defaults"), "287082");
    }

    #[test]
    fn invalid_period_and_digit_counts_are_refused() {
        let seed = secret();
        assert!(matches!(
            seed.code_at_with(59, 0, 6),
            Err(TotpError::Parameters)
        ));
        for digits in [0, 5, 9] {
            assert!(matches!(
                seed.code_at_with(59, 30, digits),
                Err(TotpError::Parameters)
            ));
        }
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let rendered = format!("{:?}", secret());
        assert_eq!(rendered, "TotpSecret([REDACTED])");
        assert!(!rendered.contains("1234567890"));
    }
}
