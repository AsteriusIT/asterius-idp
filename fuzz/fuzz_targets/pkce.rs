//! PKCE — RFC 7636 §4.1, §4.2, §4.3, §4.6; FAPI 2.0 SP §5.3.2.2 item 5;
//! RFC 9700 §4.8.
//!
//! The `code_verifier` is the single value standing between a stolen
//! authorization code and an access token, so "does not panic" is nowhere near
//! the property that matters. Random bytes are also almost never a verifier,
//! and never a *pair* that a broken comparison would confuse — so this target
//! builds near-misses from a small grammar (the RFC's own worked example with
//! one character changed, runs from alphabets that overlap the unreserved set,
//! challenges derived from the wrong verifier) and asserts, over each:
//!
//! * **`S256` is the only method.** Anything else — including the absent one,
//!   which RFC 7636 §4.3 defines as `plain` — is refused, whatever the
//!   challenge looks like.
//! * **An accepted challenge is the encoding of a 32-byte digest**, is exactly
//!   43 characters, is never rewritten on the way in, and re-parses to itself.
//! * **Redemption agrees with the RFC recomputed here.** The transformation is
//!   recomputed in this file from `sha2` and `base64` rather than by calling
//!   the code under test, so an oracle and its subject cannot share a mistake:
//!   `redeem` succeeds exactly when the verifier is inside RFC 7636 §4.1's
//!   production *and* its digest is the challenge.
//! * **Every well-formed verifier redeems its own challenge**, and no other
//!   string redeems it.
//! * **No rejection repeats the verifier back**, which would turn an
//!   `error_description` into the per-character oracle constant-time
//!   comparison exists to remove.
#![no_main]

use asterius_oidc::pkce::{CodeChallenge, CodeVerifier, PkceError, S256, redeem};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest as _, Sha256};

/// RFC 7636 Appendix B: the specification's own worked pair.
const APPENDIX_B_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// `BASE64URL(SHA256(ASCII(code_verifier)))`, restated from RFC 7636 §4.2
/// rather than taken from the implementation under test.
fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// RFC 7636 §4.1: `code-verifier = 43*128unreserved`, restated the same way.
fn is_a_verifier(raw: &str) -> bool {
    (43..=128).contains(&raw.len())
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// A structured generator: the fuzzer picks components, not characters.
struct Source<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Source<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// The next byte, wrapping round rather than running out: a short input
    /// still produces a whole case, it just repeats itself.
    fn byte(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let byte = self.bytes[self.at % self.bytes.len()];
        self.at = self.at.wrapping_add(1);
        byte
    }

    fn pick<T: Copy>(&mut self, choices: &[T]) -> T {
        choices[usize::from(self.byte()) % choices.len()]
    }

    /// A run of `len` characters drawn from one alphabet.
    ///
    /// The alphabets overlap the unreserved set deliberately: base64url is a
    /// strict subset of it, and base64 *standard* differs from base64url in
    /// exactly the two characters that decide whether a challenge decodes.
    fn run(&mut self, len: usize) -> String {
        const ALPHABETS: [&str; 5] = [
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
            "abc-._~",
            "aA0",
            " %\t\n\0\u{7f}",
        ];
        let alphabet: Vec<char> = self.pick(&ALPHABETS).chars().collect();
        (0..len)
            .map(|_| alphabet[usize::from(self.byte()) % alphabet.len()])
            .collect()
    }

    /// A verifier-shaped string, most of them near the boundaries of the
    /// production rather than uniformly random.
    fn verifier(&mut self) -> String {
        const LENGTHS: [usize; 9] = [0, 1, 42, 43, 44, 127, 128, 129, 200];
        match self.byte() % 5 {
            0 => APPENDIX_B_VERIFIER.to_owned(),
            // One character of the worked example changed: the case a
            // short-circuiting comparison answers fastest.
            1 => {
                let mut verifier = APPENDIX_B_VERIFIER.to_owned();
                let at = usize::from(self.byte()) % verifier.len();
                let replacement = self.pick(&["a", "-", "~", ".", "_", "0", "%"]);
                verifier.replace_range(at..=at, replacement);
                verifier
            }
            2 => {
                let len = self.pick(&LENGTHS);
                self.run(len)
            }
            3 => self.run(43),
            _ => String::from_utf8_lossy(self.bytes).into_owned(),
        }
    }

    /// A challenge-shaped string: derived from a verifier, derived and then
    /// damaged, or arbitrary.
    fn challenge(&mut self, verifier: &str) -> String {
        match self.byte() % 4 {
            0 => s256(verifier),
            1 => {
                let mut challenge = s256(verifier);
                let at = usize::from(self.byte()) % challenge.len();
                let replacement = self.pick(&["a", "-", "_", ".", "~", "+", "/", "N", ""]);
                challenge.replace_range(at..=at, replacement);
                challenge
            }
            2 => {
                let len = self.pick(&[0, 42, 43, 44, 128]);
                self.run(len)
            }
            _ => String::from_utf8_lossy(self.bytes).into_owned(),
        }
    }

    fn method(&mut self) -> Option<&'static str> {
        self.pick(&[
            Some(S256),
            Some(S256),
            Some("plain"),
            Some("s256"),
            Some("S256 "),
            Some("S384"),
            Some(""),
            None,
        ])
    }
}

fuzz_target!(|data: &[u8]| {
    let mut source = Source::new(data);
    let verifier = source.verifier();
    let other = source.verifier();
    let method = source.method();
    let challenge_raw = source.challenge(&verifier);

    // --- what a challenge is ------------------------------------------------

    // A rule that only holds sometimes is not a rule: PAR, the code store and
    // the token endpoint all have to reach the same answer for one string.
    let first = CodeChallenge::parse(Some(&challenge_raw), method);
    let again = CodeChallenge::parse(Some(&challenge_raw), method);
    assert_eq!(
        first.as_ref().err(),
        again.as_ref().err(),
        "parsing a code_challenge is not deterministic: {challenge_raw:?}"
    );
    assert!(
        CodeChallenge::parse(None, method).is_err(),
        "a request with no code_challenge started a flow"
    );

    let Ok(challenge) = first else {
        // Every way of refusing a pushed challenge is a client error in the
        // request, never a failed grant.
        let error = again.expect_err("both parses agreed on an error");
        assert_eq!(
            error.code(),
            "invalid_request",
            "a malformed code_challenge was reported as {error}"
        );
        return;
    };

    assert_eq!(
        method,
        Some(S256),
        "a challenge was accepted under method {method:?}"
    );
    assert_eq!(
        challenge.as_str(),
        challenge_raw,
        "a code_challenge was rewritten on the way in"
    );
    assert_eq!(
        challenge.as_str().len(),
        43,
        "an S256 challenge is the base64url of 32 bytes: {challenge_raw:?}"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.decode(challenge.as_str()).map(|d| d.len()),
        Ok(32),
        "an accepted challenge is not the encoding of a digest: {challenge_raw:?}"
    );
    // The accepted form is a fixed point, so a stored challenge re-validated on
    // its way out of the database comes back the same (`ast-83p.3`).
    assert_eq!(
        CodeChallenge::parse(Some(challenge.as_str()), Some(S256))
            .expect("an accepted challenge must re-parse")
            .as_str(),
        challenge.as_str(),
        "an accepted code_challenge did not re-parse to itself"
    );

    // --- what redemption is -------------------------------------------------

    assert_eq!(
        redeem(&challenge, None).expect_err("a token request with no verifier"),
        PkceError::VerifierMissing,
    );

    let outcome = redeem(&challenge, Some(&verifier));
    let should_redeem = is_a_verifier(&verifier) && s256(&verifier) == challenge.as_str();
    assert_eq!(
        outcome.is_ok(),
        should_redeem,
        "redemption disagrees with RFC 7636 §4.1 and §4.6 recomputed: \
         challenge {challenge_raw:?}, well formed {}, digest matches {}",
        is_a_verifier(&verifier),
        s256(&verifier) == challenge.as_str()
    );

    if let Err(error) = outcome {
        // A rejected proof is `invalid_grant`, whether the verifier was the
        // wrong shape or simply wrong: telling the two apart would hand an
        // attacker a free filter over the search space.
        assert_eq!(
            error.code(),
            "invalid_grant",
            "a failed proof was reported as {error}"
        );
        // The message reaches an error_description and the audit trail.
        if verifier.len() >= 16 {
            let rendered = format!("{error} {error:?}");
            assert!(
                !rendered.contains(&verifier),
                "a rejection repeated the code_verifier back: {rendered}"
            );
        }
    }

    // --- the round trip -----------------------------------------------------

    if is_a_verifier(&verifier) {
        let own = CodeChallenge::parse(Some(&s256(&verifier)), Some(S256))
            .expect("the digest of a well-formed verifier is a well-formed challenge");
        assert_eq!(
            redeem(&own, Some(&verifier)),
            Ok(()),
            "a verifier did not redeem the challenge it produced"
        );
        // Nothing else does. A second flow's verifier must not open this one.
        if other != verifier {
            assert!(
                redeem(&own, Some(&other)).is_err(),
                "another string redeemed a challenge it did not produce"
            );
        }
        // Parsing a verifier is deterministic too, and never panics on a value
        // this generator produced.
        assert!(CodeVerifier::parse(Some(&verifier)).is_ok());
    } else {
        assert!(
            CodeVerifier::parse(Some(&verifier)).is_err(),
            "a verifier outside 43*128unreserved was accepted"
        );
    }
});
