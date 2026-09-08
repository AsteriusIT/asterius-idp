//! PKCE: the proof that redeems an authorization code — `S256`, and nothing
//! else.
//!
//! RFC 7636 defines two transformations. `plain` sends the verifier itself as
//! the challenge, so anything that reads the authorization request learns the
//! secret that redeems the code — attacker A3a in the FAPI 2.0 Attacker Model
//! §7.5, and the code injection of RFC 9700 §4.5. `S256` sends
//! `BASE64URL(SHA256(ASCII(code_verifier)))` instead (RFC 7636 §4.2), so
//! reading the request buys nothing without a preimage. FAPI 2.0 SP §5.3.2.2
//! item 5 requires it: an authorization server *"shall require PKCE \[RFC7636\]
//! with `S256` as the code challenge method"*.
//!
//! ADR-0002 makes that unconditional, and this module is shaped so it is not a
//! check somebody has to remember to run:
//!
//! * **There is no `plain`.** There is no `CodeChallengeMethod` enum here,
//!   because even a one-variant enum is a decision that can be made a second
//!   time. `S256` is the only spelling [`CodeChallenge::parse`] accepts, and
//!   every other value is an error — including the *absent* one, which RFC 7636
//!   §4.3 defines as meaning `plain`.
//! * **There is no absent challenge.** [`CodeChallenge`] is the only way to
//!   carry one and it cannot be empty, so a code issued without PKCE is not a
//!   state this crate can represent. That is RFC 9700 §4.8's downgrade attack
//!   closed by construction rather than by the check §4.8.2 asks for: there is
//!   no "was a challenge pushed?" flag for an attacker to clear.
//! * **The verifier is a secret and the challenge is not.** The challenge is
//!   the hash — RFC 7636 §4.2 exists precisely so it can be disclosed — and the
//!   verifier is the preimage an attacker is trying to guess. They therefore
//!   get different types, different `Debug` output, and different rules about
//!   what an error message may repeat back.
//! * **[`CodeChallenge::verify`] is the only way to relate the two.** Neither
//!   type implements `PartialEq`, and the transformation is private, so the
//!   comparison RFC 7636 §4.6 specifies cannot be written any way but the
//!   constant-time one.
//!
//! This module is pure: it decides whether a verifier proves a challenge, not
//! whether the code that carried the challenge is still redeemable. Consuming
//! the code, and revoking the whole grant when a replay is detected, belong to
//! the code store (`ast-a05.2`).

use asterius_domain::{Secret, ct_eq};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use std::fmt;

/// The only code challenge method this server implements (RFC 7636 §4.2).
///
/// Compared exactly, as the RFC spells it: `s256` is not this value, and a
/// case-insensitive match would accept a spelling no conforming client sends
/// while widening what an attacker may put in the parameter.
pub const S256: &str = "S256";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a PKCE parameter, or the proof it carries, was refused.
///
/// **No variant repeats the `code_verifier` back**, in whole or in part. The
/// rendered message reaches an `error_description` and the audit trail, and the
/// verifier is the one value in this exchange an attacker is trying to guess:
/// an error naming the character it tripped over is a per-position oracle, and
/// a cheaper one than the comparison [`ct_eq`] was chosen to protect. The
/// challenge is a digest and carries no such risk, so its errors may say what
/// was wrong with it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PkceError {
    /// No `code_challenge` was pushed.
    ///
    /// RFC 7636 §4.4.1: a server that requires PKCE and receives no
    /// `code_challenge` answers `invalid_request`.
    #[error("code_challenge is required")]
    ChallengeMissing,
    /// `code_challenge_method` was absent, or named something other than
    /// `S256`.
    ///
    /// Absent is a rejection and not a default. RFC 7636 §4.3 gives the
    /// parameter a default of `plain`, so honouring the default would mean
    /// accepting `plain` from every client that omits it — which is exactly the
    /// weaker alternative path ADR-0002 says must not exist.
    #[error("code_challenge_method must be S256")]
    MethodNotS256,
    /// The `code_challenge` was not 43 characters.
    ///
    /// `S256` is the base64url of a 32-byte digest, which is always exactly 43
    /// unpadded symbols. RFC 7636 §4.2's ABNF permits `43*128unreserved`
    /// because it also has to describe a `plain` challenge; with `plain` gone,
    /// anything but 43 is a value no verifier can ever produce.
    #[error("code_challenge must be {expected} characters, found {found}", expected = CodeChallenge::LEN)]
    ChallengeLength {
        /// How long the pushed challenge was.
        found: usize,
    },
    /// The `code_challenge` was 43 characters but is not the base64url encoding
    /// of a 32-byte digest.
    ///
    /// Refused at the pushed authorization request rather than at redemption:
    /// such a challenge cannot match any verifier, so accepting it would issue
    /// a code that is guaranteed to fail — and report that failure as
    /// `invalid_grant` at the token endpoint, where it reads like a client's
    /// verifier is wrong rather than like its encoder is.
    #[error("code_challenge is not the base64url encoding of a SHA-256 digest")]
    ChallengeEncoding,
    /// No `code_verifier` was presented at the token endpoint.
    ///
    /// RFC 6749 §5.2 `invalid_request` — a required parameter is missing —
    /// rather than the `invalid_grant` a wrong verifier gets. Absence is not a
    /// guess, and the client already knows what it did not send, so this
    /// distinction tells an attacker nothing they did not supply themselves.
    #[error("code_verifier is required")]
    VerifierMissing,
    /// The `code_verifier` was outside RFC 7636 §4.1's 43–128 characters.
    #[error("code_verifier must be {min} to {max} characters", min = CodeVerifier::MIN_LEN, max = CodeVerifier::MAX_LEN)]
    VerifierLength,
    /// The `code_verifier` contained something outside the unreserved set.
    #[error("code_verifier may only contain A-Z, a-z, 0-9, '-', '.', '_' and '~'")]
    VerifierCharacter,
    /// The verifier does not hash to the challenge (RFC 7636 §4.6).
    #[error("code_verifier does not match code_challenge")]
    Mismatch,
}

impl PkceError {
    /// The OAuth 2.0 error code this rejection is reported as.
    ///
    /// Every failure of the *proof* — a malformed verifier as much as a wrong
    /// one — is `invalid_grant` (RFC 7636 §4.6). Collapsing them is deliberate:
    /// a caller who could tell "your verifier is the wrong shape" from "your
    /// verifier is wrong" would have a free filter over the search space, and
    /// the shape is something they control and already know.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ChallengeMissing
            | Self::MethodNotS256
            | Self::ChallengeLength { .. }
            | Self::ChallengeEncoding
            | Self::VerifierMissing => "invalid_request",
            Self::VerifierLength | Self::VerifierCharacter | Self::Mismatch => "invalid_grant",
        }
    }
}

// ---------------------------------------------------------------------------
// The challenge
// ---------------------------------------------------------------------------

/// A `code_challenge` that is the base64url of a SHA-256 digest.
///
/// Holding one is the evidence that a pushed authorization request carried
/// PKCE with `S256`; there is no other constructor, so an authorization code
/// cannot be issued against a challenge nobody validated.
///
/// It deliberately does **not** implement `PartialEq`. `==` would compile into
/// the comparison of RFC 7636 §4.6 as a short-circuiting one, which is the
/// thing [`CodeChallenge::verify`] exists to avoid; removing the operator
/// covers the call sites nobody has written yet.
#[derive(Debug, Clone)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    /// How long an `S256` challenge is: 32 digest bytes in unpadded base64url.
    pub const LEN: usize = 43;

    /// The number of bytes a SHA-256 digest occupies.
    const DIGEST_LEN: usize = 32;

    /// Validates the `code_challenge` and `code_challenge_method` of a pushed
    /// authorization request (RFC 7636 §4.3, FAPI 2.0 SP §5.3.2.2 item 5).
    ///
    /// Both parameters are taken as [`Option`] rather than as `&str` so that
    /// "the client sent nothing" is a case this function answers, not a case a
    /// caller can forget to ask about. Both absences are errors.
    ///
    /// The same function re-validates a stored challenge on its way back out of
    /// the database: a row edited during an incident must fail to load rather
    /// than take part in a redemption (`ast-83p.3`).
    ///
    /// # Errors
    ///
    /// Returns [`PkceError`] naming the first rule broken. Every one of them is
    /// reported as `invalid_request`.
    // fuzz-target: pkce
    pub fn parse(challenge: Option<&str>, method: Option<&str>) -> Result<Self, PkceError> {
        let raw = challenge.ok_or(PkceError::ChallengeMissing)?;
        // The method is checked before the shape of the challenge, so that a
        // client sending `plain` is told about `plain` rather than about the
        // length of a challenge it computed the wrong way. A `plain` challenge
        // is the verifier, so it is 43 to 128 characters and would otherwise
        // often fail on its length instead.
        if method != Some(S256) {
            return Err(PkceError::MethodNotS256);
        }
        if raw.len() != Self::LEN {
            return Err(PkceError::ChallengeLength { found: raw.len() });
        }
        // Decoding rather than scanning the alphabet by hand: it checks the
        // characters, and it also rejects a 43rd symbol whose two unused bits
        // are not zero. That symbol cannot appear in the encoding of any
        // 32-byte digest, so a challenge carrying one is unredeemable by
        // construction.
        match URL_SAFE_NO_PAD.decode(raw) {
            Ok(digest) if digest.len() == Self::DIGEST_LEN => Ok(Self(raw.to_owned())),
            _ => Err(PkceError::ChallengeEncoding),
        }
    }

    /// The challenge as it is stored and as the client sent it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `verifier` is the preimage of this challenge — RFC 7636 §4.6.
    ///
    /// The comparison is [`ct_eq`]. A byte-by-byte comparison that stops at the
    /// first difference answers faster the fewer leading characters match,
    /// which turns one search over the whole verifier into a short search per
    /// character — against the single value that stands between a stolen
    /// authorization code and a token.
    ///
    /// # Errors
    ///
    /// Returns [`PkceError::Mismatch`], reported as `invalid_grant`.
    pub fn verify(&self, verifier: &CodeVerifier) -> Result<(), PkceError> {
        let derived = verifier.challenge();
        if ct_eq(self.0.as_bytes(), derived.0.as_bytes()) {
            Ok(())
        } else {
            Err(PkceError::Mismatch)
        }
    }
}

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

/// A `code_verifier` presented at the token endpoint.
///
/// Wrapped in a [`Secret`], so it prints `[REDACTED]`, is zeroed on drop, and
/// cannot be compared with `==`. Nothing hands the string back out: the only
/// thing this type does is hash itself, which is the only thing RFC 7636 §4.6
/// asks of it.
pub struct CodeVerifier(Secret<String>);

impl CodeVerifier {
    /// RFC 7636 §4.1: `code-verifier = 43*128unreserved`.
    pub const MIN_LEN: usize = 43;

    /// The other end of the same production.
    ///
    /// The ceiling is not cosmetic. The verifier is hashed on an unauthenticated
    /// path — anyone holding a code reaches it — so an unbounded one is work an
    /// attacker can ask for, and a verifier longer than the RFC permits is not
    /// one any conforming client produced.
    pub const MAX_LEN: usize = 128;

    /// Validates a presented `code_verifier` (RFC 7636 §4.1, §4.5).
    ///
    /// The range and the character set are enforced **before** the value is
    /// hashed, so nothing outside RFC 7636's production ever reaches the digest.
    ///
    /// # Errors
    ///
    /// Returns [`PkceError::VerifierMissing`] when the token request carried no
    /// verifier, and [`PkceError::VerifierLength`] or
    /// [`PkceError::VerifierCharacter`] when it carried one the specification
    /// does not describe. The latter two are reported as `invalid_grant`,
    /// indistinguishable from a verifier that is simply wrong.
    // fuzz-target: pkce
    pub fn parse(presented: Option<&str>) -> Result<Self, PkceError> {
        let raw = presented.ok_or(PkceError::VerifierMissing)?;
        // The character set is checked first so that the length below counts
        // characters and not UTF-8 bytes: every unreserved character is one
        // byte, so once the set holds the two numbers are the same one.
        if !raw.bytes().all(is_unreserved) {
            return Err(PkceError::VerifierCharacter);
        }
        if !(Self::MIN_LEN..=Self::MAX_LEN).contains(&raw.len()) {
            return Err(PkceError::VerifierLength);
        }
        Ok(Self(Secret::new(raw.to_owned())))
    }

    /// `BASE64URL(SHA256(ASCII(code_verifier)))` — RFC 7636 §4.2.
    ///
    /// Private on purpose. Exposing it would make
    /// `stored.as_str() == verifier.challenge().as_str()` a natural thing to
    /// write, and that is the short-circuiting comparison
    /// [`CodeChallenge::verify`] exists to be instead of.
    fn challenge(&self) -> CodeChallenge {
        // `parse` admitted only unreserved ASCII, so the bytes of the String
        // *are* the ASCII octets RFC 7636 §4.2 asks to be hashed. This is the
        // one place the verifier is exposed, and it is exposed to a hash.
        let digest = Sha256::digest(self.0.expose().as_bytes());
        CodeChallenge(URL_SAFE_NO_PAD.encode(digest))
    }
}

/// The unreserved set of RFC 3986 §2.3, which RFC 7636 §4.1 draws a verifier
/// from.
const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

impl fmt::Debug for CodeVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// ---------------------------------------------------------------------------
// The exchange
// ---------------------------------------------------------------------------

/// The whole of RFC 7636 §4.6: validate the presented `code_verifier` and check
/// it against the challenge the code was issued under.
///
/// The token endpoint calls this and nothing else, so there is no arrangement
/// of the two steps that skips the second one.
///
/// # Errors
///
/// Returns [`PkceError`]; consult [`PkceError::code`] for the OAuth error code
/// to report.
pub fn redeem(challenge: &CodeChallenge, presented: Option<&str>) -> Result<(), PkceError> {
    challenge.verify(&CodeVerifier::parse(presented)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B, the one worked example in the specification.
    const APPENDIX_B_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const APPENDIX_B_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn challenge(raw: &str) -> CodeChallenge {
        CodeChallenge::parse(Some(raw), Some(S256)).expect("a well-formed S256 challenge")
    }

    /// The vector from RFC 7636 Appendix B, so that this implementation of
    /// §4.2 is pinned to the specification's own arithmetic and not to itself.
    #[test]
    fn the_appendix_b_vector_transforms_and_verifies() {
        let verifier = CodeVerifier::parse(Some(APPENDIX_B_VERIFIER)).expect("a valid verifier");
        assert_eq!(verifier.challenge().as_str(), APPENDIX_B_CHALLENGE);
        assert_eq!(
            redeem(&challenge(APPENDIX_B_CHALLENGE), Some(APPENDIX_B_VERIFIER)),
            Ok(())
        );
    }

    /// FAPI 2.0 SP §5.3.2.2 item 5 with ADR-0002 behind it: there is no
    /// configuration under which a request without a challenge starts a flow.
    #[test]
    fn a_request_without_a_code_challenge_is_refused() {
        assert_eq!(
            CodeChallenge::parse(None, Some(S256)).err(),
            Some(PkceError::ChallengeMissing)
        );
        assert_eq!(
            CodeChallenge::parse(None, None).err(),
            Some(PkceError::ChallengeMissing)
        );
        assert_eq!(PkceError::ChallengeMissing.code(), "invalid_request");
    }

    /// RFC 7636 §4.3 defaults `code_challenge_method` to `plain`. Honouring
    /// that default — or silently reading an absent method as `S256` — would
    /// each be a way to run the flow the profile forbids.
    #[test]
    fn an_absent_method_is_refused_rather_than_defaulted_either_way() {
        assert_eq!(
            CodeChallenge::parse(Some(APPENDIX_B_CHALLENGE), None).err(),
            Some(PkceError::MethodNotS256)
        );
    }

    /// `plain` is not a method with a weaker setting; it is not a method.
    #[test]
    fn plain_is_not_a_method_this_server_implements() {
        for method in ["plain", "PLAIN", "s256", "S512", "", "S256 ", " S256"] {
            assert_eq!(
                CodeChallenge::parse(Some(APPENDIX_B_CHALLENGE), Some(method)).err(),
                Some(PkceError::MethodNotS256),
                "accepted code_challenge_method={method:?}"
            );
        }
    }

    /// A `plain` challenge *is* the verifier, so it is 43–128 characters of
    /// unreserved text. Every length but 43 is refused, which is most of them.
    #[test]
    fn a_challenge_that_is_not_43_characters_cannot_be_an_s256_challenge() {
        for raw in ["", "a", &"a".repeat(42), &"a".repeat(44), &"a".repeat(128)] {
            assert_eq!(
                CodeChallenge::parse(Some(raw), Some(S256)).err(),
                Some(PkceError::ChallengeLength { found: raw.len() }),
                "accepted a {}-character challenge",
                raw.len()
            );
        }
    }

    /// 43 characters is necessary and not sufficient: the value must be the
    /// encoding of a 32-byte digest, or no verifier will ever match it.
    #[test]
    fn a_challenge_that_is_not_the_encoding_of_a_digest_is_refused_when_it_is_pushed() {
        for raw in [
            // `.` and `~` are unreserved, so RFC 7636's ABNF admits them, but
            // base64url has no such symbols.
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c.",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c~",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw/cM",
            // A trailing symbol whose two unused bits are set: 43 base64url
            // symbols carry 258 bits, and a 32-byte digest fills 256 of them.
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN",
        ] {
            assert_eq!(
                CodeChallenge::parse(Some(raw), Some(S256)).err(),
                Some(PkceError::ChallengeEncoding),
                "accepted {raw:?}"
            );
        }
    }

    /// Whatever the store hands back has to be something this parser still
    /// accepts, or a code outlives the rules its challenge was admitted under.
    #[test]
    fn an_accepted_challenge_re_parses_to_itself() {
        let parsed = challenge(APPENDIX_B_CHALLENGE);
        assert_eq!(parsed.as_str(), APPENDIX_B_CHALLENGE);
        assert_eq!(
            challenge(parsed.as_str()).as_str(),
            parsed.as_str(),
            "a stored challenge did not survive being validated again"
        );
    }

    /// RFC 7636 §4.1 bounds the verifier at both ends. Nothing outside that
    /// production reaches SHA-256.
    #[test]
    fn a_verifier_outside_43_to_128_characters_is_refused_before_it_is_hashed() {
        for raw in [
            "",
            "short",
            &"a".repeat(42),
            &"a".repeat(129),
            &"a".repeat(4096),
        ] {
            assert_eq!(
                CodeVerifier::parse(Some(raw)).err(),
                Some(PkceError::VerifierLength),
                "accepted a {}-character verifier",
                raw.len()
            );
        }
        assert!(CodeVerifier::parse(Some(&"a".repeat(43))).is_ok());
        assert!(CodeVerifier::parse(Some(&"a".repeat(128))).is_ok());
    }

    /// The unreserved set, and only it. A verifier carrying `%` or a newline
    /// arrived through a transport that mangled it or from a client that
    /// invented its own alphabet; either way it is not the value that produced
    /// the stored challenge.
    #[test]
    fn a_verifier_outside_the_unreserved_set_is_refused() {
        let base = "a".repeat(42);
        for tail in ["+", "/", "=", "%", " ", "\n", "\0", "é", "\u{200b}"] {
            let raw = format!("{base}{tail}");
            assert_eq!(
                CodeVerifier::parse(Some(&raw)).err(),
                Some(PkceError::VerifierCharacter),
                "accepted a verifier ending in {tail:?}"
            );
        }
        assert!(
            CodeVerifier::parse(Some(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
            ))
            .is_ok(),
            "the full unreserved set must be accepted"
        );
    }

    #[test]
    fn a_token_request_with_no_verifier_at_all_is_refused() {
        assert_eq!(
            redeem(&challenge(APPENDIX_B_CHALLENGE), None),
            Err(PkceError::VerifierMissing)
        );
    }

    /// RFC 7636 §4.6: a verifier that does not hash to the challenge is
    /// `invalid_grant`, and so is one that could not be a verifier at all. A
    /// client cannot learn from the response which of the two it sent.
    #[test]
    fn a_malformed_verifier_and_a_wrong_one_are_reported_identically() {
        let stored = challenge(APPENDIX_B_CHALLENGE);
        let wrong = "a".repeat(43);
        let malformed = "a".repeat(10);

        let wrong_code = redeem(&stored, Some(&wrong))
            .expect_err("must not verify")
            .code();
        let malformed_code = redeem(&stored, Some(&malformed))
            .expect_err("must not verify")
            .code();
        assert_eq!(wrong_code, "invalid_grant");
        assert_eq!(malformed_code, "invalid_grant");
    }

    /// One character different is the case a short-circuiting comparison
    /// answers fastest, so it is the one worth naming.
    #[test]
    fn a_verifier_that_differs_in_one_character_does_not_verify() {
        let stored = challenge(APPENDIX_B_CHALLENGE);
        let mut near = APPENDIX_B_VERIFIER.to_owned();
        near.replace_range(0..1, "e");
        assert_eq!(redeem(&stored, Some(&near)), Err(PkceError::Mismatch));

        let mut far = APPENDIX_B_VERIFIER.to_owned();
        far.replace_range(42..43, "a");
        assert_eq!(redeem(&stored, Some(&far)), Err(PkceError::Mismatch));
    }

    /// A code issued to one client must not be redeemable with another
    /// client's verifier, which is the same statement as "distinct verifiers
    /// have distinct challenges".
    #[test]
    fn a_verifier_for_another_flow_does_not_redeem_this_challenge() {
        let other = "wJ8mZKzYq3TnR7bV1cX5dF0gH2jL4aS6uP-eW_iO9nQ";
        assert_ne!(other, APPENDIX_B_VERIFIER);
        assert_eq!(
            redeem(&challenge(APPENDIX_B_CHALLENGE), Some(other)),
            Err(PkceError::Mismatch)
        );
    }

    #[test]
    fn a_verifier_never_prints_itself() {
        let verifier = CodeVerifier::parse(Some(APPENDIX_B_VERIFIER)).expect("valid");
        assert_eq!(format!("{verifier:?}"), "[REDACTED]");
        assert!(!format!("{verifier:?}").contains(APPENDIX_B_VERIFIER));
    }

    /// The error text goes into `error_description` and into the audit trail.
    #[test]
    fn no_rejection_repeats_the_verifier_back() {
        let stored = challenge(APPENDIX_B_CHALLENGE);
        // Three shapes of secret, one per rejection path: too short, outside
        // the alphabet, and well-formed but wrong.
        for secret in [
            "sEcReT-tOo-ShOrT".to_owned(),
            format!("{}%", "sEcReT".repeat(8)),
            "sEcReT".repeat(8) + "-nOt-tHe-OnE",
        ] {
            let error = redeem(&stored, Some(&secret)).expect_err("none of these may verify");
            let rendered = format!("{error} {error:?}");
            assert!(
                !rendered.contains("sEcReT"),
                "a rejection repeated the code_verifier back: {rendered}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Properties
    //
    // The tables above pin the cases a reader can check against the RFC. These
    // check what has to hold for *every* verifier, which is where a comparison
    // or a transformation actually goes wrong.
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: 256,
            // A failing case is reproduced from the seed proptest prints;
            // CONTRIBUTING.md says a case found this way earns a named test in
            // the ordinary suite rather than a regressions file.
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    /// Exactly RFC 7636 §4.1's production.
    fn verifier() -> impl Strategy<Value = String> {
        "[A-Za-z0-9\\-._~]{43,128}"
    }

    proptest! {
        #![proptest_config(config())]

        /// The round trip, for every verifier the specification permits: what
        /// a client computes with §4.2 is what §4.6 accepts.
        #[test]
        fn every_permitted_verifier_redeems_the_challenge_it_produced(raw in verifier()) {
            let parsed = CodeVerifier::parse(Some(&raw)).map_err(|e| {
                TestCaseError::fail(format!("rejected a verifier the ABNF permits: {e}"))
            })?;
            let derived = parsed.challenge();
            prop_assert_eq!(derived.as_str().len(), CodeChallenge::LEN);

            // The challenge goes to storage as text and comes back through the
            // same parser a pushed one does.
            let stored = CodeChallenge::parse(Some(derived.as_str()), Some(S256))
                .map_err(|e| TestCaseError::fail(format!("a derived challenge was refused: {e}")))?;
            prop_assert_eq!(redeem(&stored, Some(&raw)), Ok(()));
        }

        /// Distinct verifiers must not share a challenge, or one flow's code
        /// would be redeemable with another flow's secret.
        #[test]
        fn two_different_verifiers_never_redeem_the_same_challenge(
            left in verifier(),
            right in verifier(),
        ) {
            prop_assume!(left != right);
            let stored = CodeChallenge::parse(
                Some(CodeVerifier::parse(Some(&left)).expect("valid").challenge().as_str()),
                Some(S256),
            )
            .expect("a derived challenge is well formed");
            prop_assert_eq!(redeem(&stored, Some(&right)), Err(PkceError::Mismatch));
        }

        /// Whatever arrives, the parsers answer rather than panic — and
        /// whatever they accept satisfies the invariants nothing re-checks.
        #[test]
        fn anything_accepted_satisfies_the_production_it_was_parsed_against(
            raw in ".{0,300}",
            method in proptest::option::of("[ -~]{0,8}"),
        ) {
            if let Ok(parsed) = CodeChallenge::parse(Some(&raw), method.as_deref()) {
                prop_assert_eq!(method.as_deref(), Some(S256));
                prop_assert_eq!(parsed.as_str().len(), CodeChallenge::LEN);
                prop_assert_eq!(parsed.as_str(), raw.as_str());
            }
            if let Ok(parsed) = CodeVerifier::parse(Some(&raw)) {
                prop_assert!((CodeVerifier::MIN_LEN..=CodeVerifier::MAX_LEN).contains(&raw.len()));
                prop_assert!(raw.bytes().all(is_unreserved));
                prop_assert_eq!(parsed.challenge().as_str().len(), CodeChallenge::LEN);
            }
        }
    }
}
