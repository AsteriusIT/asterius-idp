//! JWS compact serialisation (RFC 7515 §3.1, §7.1).
//!
//! ```text
//! BASE64URL(UTF8(header)) ‖ '.' ‖ BASE64URL(payload) ‖ '.' ‖ BASE64URL(signature)
//! ```
//!
//! Small, and worth writing carefully. Two rules do most of the work:
//!
//! **The header never chooses the algorithm.** RFC 8725 §3.1: a verifier
//! decides which algorithm applies from what it already knows — the registered
//! client metadata, or the key the `kid` resolves to — and then checks that the
//! header agrees. Reading `alg` out of the token and using it is the mistake
//! behind every `alg: none` and every RSA-key-as-HMAC-secret story.
//!
//! **Signing covers the encoded form, not the decoded one.** The signing input
//! is the exact ASCII of the first two segments. Re-encoding a parsed header to
//! check a signature would let two different byte strings share a signature.

use crate::{JoseError, SigningKey, VerifyingKey};
use asterius_domain::{CompactJws, Kid, SigningAlgorithm};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The JOSE header this server writes, and the subset it accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The signing algorithm.
    pub alg: String,
    /// The media type of the token (RFC 8725 §3.11).
    ///
    /// Required, never optional. `at+jwt`, `logout+jwt`, `dpop+jwt`,
    /// `secevent+jwt`: an explicit type is what stops a token minted for one
    /// purpose being presented as another.
    pub typ: String,
    /// Which key signed it.
    ///
    /// Optional on the way in: everything *this server issues* sets a `kid`,
    /// but a DPoP proof carries its key in `jwk` instead (RFC 9449 §4.2) and a
    /// request object may carry neither. A verifier that demanded `kid` would
    /// reject those before it could look at them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Critical header parameters (RFC 7515 §4.1.11).
    ///
    /// We never emit any. We reject every one we are offered, because `crit`
    /// means "fail if you do not understand this", and we do not understand any
    /// of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
}

/// A parsed but not yet verified JWS.
///
/// The name is the warning. Nothing in here has been checked against a key, so
/// the only safe thing to read before verification is [`Unverified::kid`] —
/// enough to look up which key should have signed it, and nothing more.
#[derive(Debug, Clone)]
pub struct Unverified {
    header: Header,
    payload: Vec<u8>,
    signature: Vec<u8>,
    signing_input: String,
}

impl Unverified {
    /// The `kid`, so a caller can find the key to check this with.
    #[must_use]
    pub fn kid(&self) -> Option<Kid> {
        self.header.kid.as_deref().map(Kid::new)
    }

    /// The header, for a caller that needs a field this type does not surface.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// The bytes the signature covers, for a caller verifying by hand.
    #[must_use]
    pub fn signing_input(&self) -> &str {
        &self.signing_input
    }

    /// The signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The payload, still unverified. Reading this before `verify` is a bug
    /// unless the caller is about to decide *which key* to verify with.
    #[must_use]
    pub fn unverified_payload(&self) -> &[u8] {
        &self.payload
    }

    /// The `alg` the token claims. Only for reporting a mismatch — never for
    /// choosing how to verify.
    #[must_use]
    pub fn claimed_alg(&self) -> &str {
        &self.header.alg
    }

    /// The `typ` the token claims.
    #[must_use]
    pub fn claimed_typ(&self) -> &str {
        &self.header.typ
    }

    /// Verifies against `key` and returns the payload.
    ///
    /// The algorithm is the key's. The header must agree with it, and the
    /// `typ` must be the one expected, or nothing is returned.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::InvalidSignature`] if the signature does not check
    /// out, or [`JoseError::UnexpectedHeader`] if `alg` or `typ` disagrees with
    /// what the caller required.
    pub fn verify(self, key: &VerifyingKey, expected_typ: &str) -> Result<Vec<u8>, JoseError> {
        // The header must agree with the key we are about to use. If it does
        // not, the token was made for something else, and continuing would mean
        // verifying it under an algorithm its author did not choose.
        if self.header.alg != key.algorithm().as_str() {
            return Err(JoseError::UnexpectedHeader {
                field: "alg",
                expected: key.algorithm().as_str().to_owned(),
                found: self.header.alg,
            });
        }
        if self.header.typ != expected_typ {
            return Err(JoseError::UnexpectedHeader {
                field: "typ",
                expected: expected_typ.to_owned(),
                found: self.header.typ,
            });
        }

        key.verify(self.signing_input.as_bytes(), &self.signature)?;
        Ok(self.payload)
    }
}

/// Signs `claims` into a compact JWS.
///
/// # Errors
///
/// Returns [`JoseError`] if the claims cannot be serialised or the key refuses.
pub fn sign(
    key: &SigningKey,
    kid: &Kid,
    typ: &str,
    claims: &Value,
) -> Result<CompactJws, JoseError> {
    let header = Header {
        alg: key.algorithm().as_str().to_owned(),
        typ: typ.to_owned(),
        kid: Some(kid.as_str().to_owned()),
        crit: None,
    };

    let header_json = serde_json::to_vec(&header).map_err(|_| JoseError::Serialisation)?;
    let payload_json = serde_json::to_vec(claims).map_err(|_| JoseError::Serialisation)?;

    let signing_input = format!("{}.{}", B64.encode(&header_json), B64.encode(&payload_json));
    let signature = key.sign(signing_input.as_bytes())?;

    Ok(CompactJws::new(format!(
        "{signing_input}.{}",
        B64.encode(signature)
    )))
}

/// Parses a compact JWS without verifying it.
///
/// # Errors
///
/// Returns [`JoseError::Malformed`] if the input is not three base64url
/// segments with a usable header, or [`JoseError::UnsupportedAlgorithm`] if the
/// header names an algorithm outside the allow-list.
// fuzz-target: jws_parse
pub fn parse(token: &str) -> Result<Unverified, JoseError> {
    // Exactly three segments. Two is a detached signature, five is a JWE, and
    // neither is something this function should quietly half-accept.
    let mut segments = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(JoseError::Malformed(
            "expected three '.'-separated segments",
        ));
    };

    if header_b64.is_empty() || signature_b64.is_empty() {
        return Err(JoseError::Malformed("empty header or signature segment"));
    }

    let header_bytes = B64
        .decode(header_b64)
        .map_err(|_| JoseError::Malformed("header is not base64url"))?;
    let payload = B64
        .decode(payload_b64)
        .map_err(|_| JoseError::Malformed("payload is not base64url"))?;
    let signature = B64
        .decode(signature_b64)
        .map_err(|_| JoseError::Malformed("signature is not base64url"))?;

    let header: Header = serde_json::from_slice(&header_bytes)
        .map_err(|_| JoseError::Malformed("header is not a JOSE header"))?;

    // RFC 7515 §4.1.11: `crit` means "reject if you do not understand these".
    // We understand none of them, so any `crit` at all is a rejection. An empty
    // `crit` array is also invalid per the RFC.
    if let Some(crit) = &header.crit {
        return Err(JoseError::UnsupportedCritical(crit.join(",")));
    }

    // Reject an algorithm outside the allow-list here, so a caller cannot be
    // handed a token whose `alg` is `none` and forget to look. This is a
    // *rejection*, not a selection: verification still uses the key's
    // algorithm, not this one.
    if SigningAlgorithm::parse(&header.alg).is_none() {
        return Err(JoseError::UnsupportedAlgorithm(header.alg));
    }

    let signing_input = format!("{header_b64}.{payload_b64}");
    Ok(Unverified {
        header,
        payload,
        signature,
        signing_input,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims() -> Value {
        json!({"iss": "https://as.example/t/demo", "sub": "alice", "exp": 1_760_000_300_i64})
    }

    fn signed(algorithm: SigningAlgorithm) -> (SigningKey, CompactJws) {
        let key = SigningKey::generate(algorithm).expect("generate");
        let jws = sign(&key, &Kid::new("k1"), "at+jwt", &claims()).expect("sign");
        (key, jws)
    }

    #[test]
    fn a_signed_token_round_trips_for_every_algorithm() {
        for algorithm in SigningAlgorithm::ALL {
            let (key, jws) = signed(algorithm);
            let payload = parse(jws.as_str())
                .expect("parse")
                .verify(&key.verifying_key().expect("public"), "at+jwt")
                .unwrap_or_else(|e| panic!("{algorithm} did not verify: {e}"));
            assert_eq!(
                serde_json::from_slice::<Value>(&payload).expect("json"),
                claims()
            );
        }
    }

    /// RFC 7515 §7.1: three segments, base64url, no padding.
    #[test]
    fn the_serialisation_is_three_unpadded_base64url_segments() {
        let (_, jws) = signed(SigningAlgorithm::EdDsa);
        let segments: Vec<&str> = jws.as_str().split('.').collect();
        assert_eq!(segments.len(), 3);
        for segment in &segments {
            assert!(!segment.is_empty());
            assert!(!segment.contains('='), "padding in {segment}");
            assert!(
                !segment.contains('+') && !segment.contains('/'),
                "not base64url: {segment}"
            );
        }
    }

    /// RFC 8725 §3.11: every token says what it is.
    #[test]
    fn every_token_carries_kid_alg_and_an_explicit_typ() {
        for algorithm in SigningAlgorithm::ALL {
            let (_, jws) = signed(algorithm);
            let header_b64 = jws.as_str().split('.').next().expect("header");
            let header: Value =
                serde_json::from_slice(&B64.decode(header_b64).expect("b64")).expect("json");
            assert_eq!(header["alg"], algorithm.as_str());
            assert_eq!(header["typ"], "at+jwt");
            assert_eq!(header["kid"], "k1");
            assert!(header.get("crit").is_none(), "crit must not be emitted");
        }
    }

    #[test]
    fn tampering_with_any_segment_breaks_verification() {
        for algorithm in SigningAlgorithm::ALL {
            let (key, jws) = signed(algorithm);
            let verifying = key.verifying_key().expect("public");
            let segments: Vec<&str> = jws.as_str().split('.').collect();

            // A different payload with the original signature.
            let forged_payload = B64.encode(br#"{"sub":"mallory"}"#);
            let forged = format!("{}.{forged_payload}.{}", segments[0], segments[2]);
            assert!(
                parse(&forged)
                    .expect("parses")
                    .verify(&verifying, "at+jwt")
                    .is_err(),
                "{algorithm} accepted a swapped payload"
            );

            // A single flipped bit anywhere in the signature.
            let mut signature = B64.decode(segments[2]).expect("b64");
            signature[0] ^= 0x01;
            let flipped = format!("{}.{}.{}", segments[0], segments[1], B64.encode(&signature));
            assert!(
                parse(&flipped)
                    .expect("parses")
                    .verify(&verifying, "at+jwt")
                    .is_err(),
                "{algorithm} accepted a flipped signature bit"
            );
        }
    }

    /// The attack RFC 8725 §3.1 and §3.2 exist to stop.
    #[test]
    fn a_token_cannot_nominate_its_own_algorithm() {
        let (key, jws) = signed(SigningAlgorithm::EdDsa);
        let segments: Vec<&str> = jws.as_str().split('.').collect();

        for hostile_alg in ["none", "HS256", "RS256", "ES256"] {
            let header = json!({"alg": hostile_alg, "typ": "at+jwt", "kid": "k1"});
            let forged = format!(
                "{}.{}.{}",
                B64.encode(serde_json::to_vec(&header).expect("json")),
                segments[1],
                segments[2]
            );

            match parse(&forged) {
                // Outside the allow-list: refused before a key is even fetched.
                Err(JoseError::UnsupportedAlgorithm(alg)) => assert_eq!(alg, hostile_alg),
                // Inside the allow-list but not this key's: refused on the
                // mismatch, because the key decides and the header must agree.
                Ok(unverified) => {
                    let error = unverified
                        .verify(&key.verifying_key().expect("public"), "at+jwt")
                        .expect_err("must not verify under a nominated algorithm");
                    assert!(
                        matches!(error, JoseError::UnexpectedHeader { field: "alg", .. }),
                        "{hostile_alg}: {error}"
                    );
                }
                Err(other) => panic!("{hostile_alg}: unexpected {other}"),
            }
        }
    }

    /// A token minted for one purpose must not be usable as another.
    #[test]
    fn a_token_of_the_wrong_type_is_refused() {
        let (key, jws) = signed(SigningAlgorithm::EdDsa);
        let error = parse(jws.as_str())
            .expect("parse")
            .verify(&key.verifying_key().expect("public"), "logout+jwt")
            .expect_err("an at+jwt must not pass as a logout+jwt");
        assert!(
            matches!(error, JoseError::UnexpectedHeader { field: "typ", .. }),
            "{error}"
        );
    }

    /// RFC 7515 §4.1.11: `crit` means fail if you do not understand it.
    #[test]
    fn any_critical_header_is_refused() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        for crit in [json!(["b64"]), json!(["exp"]), json!([])] {
            let header = json!({"alg": "EdDSA", "typ": "at+jwt", "kid": "k1", "crit": crit});
            let header_b64 = B64.encode(serde_json::to_vec(&header).expect("json"));
            let payload_b64 = B64.encode(b"{}");
            let signing_input = format!("{header_b64}.{payload_b64}");
            let signature = key.sign(signing_input.as_bytes()).expect("sign");
            let token = format!("{signing_input}.{}", B64.encode(signature));

            assert!(
                matches!(parse(&token), Err(JoseError::UnsupportedCritical(_))),
                "accepted crit={crit}"
            );
        }
    }

    /// Not three base64url segments is not a JWS, whatever else it might be.
    #[test]
    fn malformed_input_is_refused_rather_than_half_parsed() {
        for malformed in [
            "",
            ".",
            "..",
            "a.b",
            "a.b.c.d",
            "a.b.c.d.e",            // a JWE has five
            "!!!.b.c",              // not base64url
            "e30.e30.",             // empty signature
            ".e30.c2ln",            // empty header
            "bm90IGpzb24.e30.c2ln", // header is not JSON
            "eyJhIjoxfQ.e30.c2ln",  // JSON, but not a JOSE header
        ] {
            assert!(parse(malformed).is_err(), "accepted {malformed:?}");
        }
    }

    /// Signing covers the encoded bytes, so a header that re-encodes
    /// differently — a reordered or reformatted one — must not verify.
    #[test]
    fn verification_uses_the_encoded_header_not_a_re_encoded_one() {
        let (key, jws) = signed(SigningAlgorithm::EdDsa);
        let segments: Vec<&str> = jws.as_str().split('.').collect();

        // Same members, different byte order in the JSON object.
        let reordered = json!({"kid": "k1", "typ": "at+jwt", "alg": "EdDSA"});
        let forged = format!(
            "{}.{}.{}",
            B64.encode(serde_json::to_vec(&reordered).expect("json")),
            segments[1],
            segments[2]
        );
        assert!(
            parse(&forged)
                .expect("parses")
                .verify(&key.verifying_key().expect("public"), "at+jwt")
                .is_err(),
            "a re-encoded header verified against a signature over the original"
        );
    }

    #[test]
    fn the_kid_is_readable_before_verification_and_nothing_else_needs_to_be() {
        let (_, jws) = signed(SigningAlgorithm::Es256);
        let unverified = parse(jws.as_str()).expect("parse");
        assert_eq!(unverified.kid(), Some(Kid::new("k1")));
        assert_eq!(unverified.claimed_alg(), "ES256");
        assert_eq!(unverified.claimed_typ(), "at+jwt");
    }
}
