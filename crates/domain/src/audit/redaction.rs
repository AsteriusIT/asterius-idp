//! Keeping credentials out of the audit trail.
//!
//! An audit record is the one artefact that is deliberately kept for a long
//! time, copied into a SIEM, and read by people during an incident. It is
//! therefore the worst possible place for a live credential: a leaked audit
//! store would hand over exactly the tokens the trail exists to account for.
//!
//! Two mechanisms, because either alone is insufficient.
//!
//! **Typing.** A [`Detail`](super::Detail) value cannot hold a raw secret by
//! construction — recording *which* code or token an event concerns is done
//! with [`fingerprint`], which stores a digest. Correlation still works; the
//! value does not come back out.
//!
//! **Scanning.** Typing only helps where the author knew the value was
//! sensitive. Free text gets scanned for the shapes credentials actually take,
//! and anything matching is replaced before it reaches the database. This is
//! the net under the trapeze, not the trapeze.

use sha2::{Digest as _, Sha256};

/// The prefix a redacted value is replaced with, so a reader can tell the
/// difference between "nothing was recorded" and "something was removed".
pub const REDACTED: &str = "[redacted:";

/// What a scan recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Sensitive {
    /// Three base64url segments separated by dots: an access token, an ID
    /// Token, a client assertion, a DPoP proof, a logout token or a SET.
    Jwt,
    /// An `Authorization` or `DPoP` header value.
    AuthorizationHeader,
    /// A PEM block, which in this codebase means a private key.
    PemBlock,
    /// A long, high-entropy opaque string: an authorization code, a refresh
    /// token, a `request_uri`, a device code, a registration access token.
    OpaqueCredential,
}

impl Sensitive {
    /// The tag written into the replacement value.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Jwt => "jwt",
            Self::AuthorizationHeader => "authorization",
            Self::PemBlock => "pem",
            Self::OpaqueCredential => "credential",
        }
    }
}

/// The shortest opaque string treated as a credential.
///
/// FAPI 2.0 SP §5.4.1 requires at least 128 bits of entropy for credentials not
/// handled by end users. Base64url encodes 6 bits per character, so 128 bits is
/// 22 characters; 22 is therefore the shortest thing that could *be* one of our
/// credentials, and the threshold is set there.
const MIN_CREDENTIAL_LEN: usize = 22;

/// Recognises text that must not be stored.
///
/// Deliberately biased towards false positives: an over-redacted audit field
/// costs an investigator one lookup, while an under-redacted one costs a
/// credential. Callers that legitimately need a long opaque identifier in the
/// trail should record a [`fingerprint`] instead.
#[must_use]
pub fn classify(value: &str) -> Option<Sensitive> {
    let trimmed = value.trim();

    if trimmed.contains("-----BEGIN") {
        return Some(Sensitive::PemBlock);
    }

    let lowered = trimmed.to_ascii_lowercase();
    if lowered.starts_with("bearer ")
        || lowered.starts_with("dpop ")
        || lowered.starts_with("basic ")
    {
        return Some(Sensitive::AuthorizationHeader);
    }

    if is_jwt_shaped(trimmed) {
        return Some(Sensitive::Jwt);
    }

    if is_opaque_credential(trimmed) {
        return Some(Sensitive::OpaqueCredential);
    }

    None
}

/// Replaces credentials in `value`, whether the whole value is one or one is
/// buried inside it.
///
/// The embedded case is not an edge case — it is the common one. A credential
/// reaches a log through a `Debug` dump of a response struct, through
/// `warn!("redeeming code {code}")`, or inside an error message built by
/// `format!`. In each of those the credential is a substring, and a scanner
/// that only classified whole values would pass all three straight through.
///
/// Ordinary text is returned unchanged, so a client name, an error code or a
/// scope list survives.
#[must_use]
pub fn redact(value: &str) -> String {
    // The whole value being a credential is worth special-casing, because it
    // keeps the informative tag ("jwt", "credential") that says what was
    // removed.
    if let Some(kind) = classify(value) {
        // The digest is kept so that two events about the same credential can
        // still be correlated, which is most of why the value was being
        // recorded in the first place.
        return format!("{REDACTED}{}:{}]", kind.tag(), short_fingerprint(value));
    }
    redact_embedded(value)
}

/// Scans `value` for credential-shaped runs and replaces each one in place.
fn redact_embedded(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut token = String::new();

    for character in value.chars() {
        if is_token_character(character) {
            token.push(character);
        } else {
            flush(&mut out, &mut token);
            out.push(character);
        }
    }
    flush(&mut out, &mut token);
    out
}

/// Characters that can occur *inside* one credential.
///
/// `.` for a JWT's segment separators and `:` for a `request_uri` URN. `=` is
/// deliberately excluded: OAuth base64url is unpadded, and including it would
/// swallow `key=value` pairs into one token and redact ordinary fields.
fn is_token_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
}

fn flush(out: &mut String, token: &mut String) {
    if token.is_empty() {
        return;
    }
    match classify(token) {
        Some(kind) => {
            out.push_str(REDACTED);
            out.push_str(kind.tag());
            out.push(':');
            out.push_str(&short_fingerprint(token));
            out.push(']');
        }
        None => out.push_str(token),
    }
    token.clear();
}

/// A stable, non-reversible identifier for a secret.
///
/// SHA-256 over the exact bytes, hex-encoded. Two events naming the same code
/// produce the same fingerprint, so a trail can be followed end to end; the
/// code itself cannot be recovered from it.
///
/// This is not a password hash and must never be used as one: it is
/// unsalted and fast on purpose, because correlation requires determinism.
/// It is safe here only because the inputs are ≥128-bit random credentials
/// (FAPI 2.0 SP §5.4.1), which are not guessable by brute force.
#[must_use]
pub fn fingerprint(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// The first 16 hex characters of a [`fingerprint`], for inline use.
#[must_use]
fn short_fingerprint(secret: &str) -> String {
    fingerprint(secret)[..16].to_owned()
}

/// Three non-empty base64url segments separated by dots.
fn is_jwt_shaped(value: &str) -> bool {
    let mut segments = value.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    // A JWS with an empty signature is still a JWT — `alg: none` looks exactly
    // like this, and it is precisely the thing worth noticing in a log.
    !header.is_empty()
        && !payload.is_empty()
        && [header, payload]
            .iter()
            .all(|s| is_base64url(s) && s.len() >= 4)
        && (signature.is_empty() || is_base64url(signature))
}

/// A long, high-entropy token-shaped string with no structure suggesting prose.
fn is_opaque_credential(value: &str) -> bool {
    if value.len() < MIN_CREDENTIAL_LEN {
        return false;
    }
    // A URN-shaped `request_uri` carries its credential in the last segment.
    if let Some(tail) = value.rsplit(':').next()
        && value.starts_with("urn:")
        && tail.len() >= MIN_CREDENTIAL_LEN
        && is_base64url(tail)
    {
        return true;
    }
    if !is_base64url(value) {
        return false;
    }
    // Reject things that are merely long and dull: a scope list, a repeated
    // character, an identifier. A real credential uses most of its alphabet.
    distinct_characters(value) >= 12
}

/// Unpadded base64url, which is what JOSE and OAuth use (RFC 7515 §2).
///
/// `=` is excluded deliberately. Allowing padding would also make
/// `grant_type=authorization_code` look like one long high-entropy token, and
/// redacting that would make the logs useless while protecting nothing.
fn is_base64url(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn distinct_characters(value: &str) -> usize {
    let mut seen = [false; 128];
    let mut count = 0;
    for byte in value.bytes() {
        let index = usize::from(byte & 0x7f);
        if !seen[index] {
            seen[index] = true;
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real shapes, taken from the credentials this server issues and accepts.
    #[test]
    fn credentials_are_recognised() {
        let cases = [
            // A JWT access token / ID Token / client assertion / DPoP proof.
            (
                "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCJ9.eyJzdWIiOiJhbGljZSJ9.c2ln",
                Sensitive::Jwt,
            ),
            // `alg: none` — unsigned, and worth catching rather than logging.
            ("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.", Sensitive::Jwt),
            ("Bearer abc123", Sensitive::AuthorizationHeader),
            (
                "DPoP eyJhbGciOiJFUzI1NiJ9.e30.x",
                Sensitive::AuthorizationHeader,
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
                Sensitive::PemBlock,
            ),
            // An authorization code or refresh token: 256 bits, base64url.
            (
                "Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ",
                Sensitive::OpaqueCredential,
            ),
            // A PAR request_uri.
            (
                "urn:ietf:params:oauth:request_uri:Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5",
                Sensitive::OpaqueCredential,
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(classify(value), Some(expected), "missed {value:?}");
        }
    }

    /// The other half: fields that legitimately belong in the trail must
    /// survive, or the trail stops being useful and people stop reading it.
    #[test]
    fn ordinary_audit_fields_are_left_alone() {
        for value in [
            "openid profile email offline_access",
            "invalid_grant",
            "authorization_code",
            "https://rp.example/callback",
            "Acme Billing Service",
            "alice@example.com",
            "private_key_jwt",
            "ES256",
            "the client requested a scope it is not registered for",
            "2026-09-08T07:15:30Z",
            "demo",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert_eq!(classify(value), None, "over-redacted {value:?}");
        }
    }

    #[test]
    fn redaction_keeps_a_correlatable_digest_and_loses_the_value() {
        let code = "Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ";
        let redacted = redact(code);
        assert!(
            !redacted.contains(code),
            "the credential survived: {redacted}"
        );
        assert!(redacted.starts_with("[redacted:credential:"), "{redacted}");
        // Same credential, same marker: an investigator can still follow it.
        assert_eq!(redacted, redact(code));
        assert_ne!(
            redacted,
            redact("Xy8Jp1lMoQ6uS3vX0aB7cE2fG5iK9zR4tU-dV_hN1mP")
        );
    }

    #[test]
    fn a_fingerprint_is_stable_and_does_not_reveal_its_input() {
        let a = fingerprint("secret-value");
        assert_eq!(a, fingerprint("secret-value"));
        assert_ne!(a, fingerprint("secret-valuf"));
        assert_eq!(a.len(), 64);
        assert!(!a.contains("secret"));
    }

    /// The threshold is 128 bits of base64url, because that is the shortest
    /// thing FAPI 2.0 SP §5.4.1 allows a credential to be.
    #[test]
    fn the_length_threshold_matches_the_entropy_requirement() {
        assert_eq!(
            MIN_CREDENTIAL_LEN, 22,
            "128 bits at 6 bits per base64url character"
        );
        // 21 varied characters: below the floor, so not a credential of ours.
        assert_eq!(classify("Zx9Kq2mNpR7vT4wY1bC8d"), None);
        // 22: a credential.
        assert_eq!(
            classify("Zx9Kq2mNpR7vT4wY1bC8dF"),
            Some(Sensitive::OpaqueCredential)
        );
    }

    /// The three ways a credential actually reaches a log: a `Debug` dump, a
    /// formatted message, and an error string. All were leaking until the
    /// scanner learned to look inside a value rather than only at it.
    #[test]
    fn a_credential_buried_in_a_larger_string_is_found() {
        let code = "Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ";
        let jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCJ9.eyJzdWIiOiJhbGljZSJ9.c2ln";

        let cases = [
            format!("redeeming code {code}"),
            format!("TokenResponse {{ access_token: \"{jwt}\", token_type: \"DPoP\" }}"),
            format!("grant failed for {code}"),
            format!("[{jwt}]"),
        ];
        for case in cases {
            let redacted = redact(&case);
            assert!(
                !redacted.contains(code),
                "code survived in {case:?}: {redacted}"
            );
            assert!(
                !redacted.contains(jwt),
                "jwt survived in {case:?}: {redacted}"
            );
            assert!(redacted.contains("redacted:"), "no marker in {redacted}");
        }
    }

    /// The surrounding prose has to survive, or the log line stops being worth
    /// reading and the redaction has cost more than it saved.
    #[test]
    fn scanning_inside_a_string_leaves_the_rest_of_it_alone() {
        let redacted =
            redact("redeeming code Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ for client billing");
        assert!(redacted.starts_with("redeeming code "), "{redacted}");
        assert!(redacted.ends_with(" for client billing"), "{redacted}");
    }

    #[test]
    fn key_value_text_is_not_swallowed_into_one_token() {
        for value in [
            "grant_type=authorization_code",
            "error=invalid_grant scope=openid",
            "response_type=code&client_id=billing",
        ] {
            assert_eq!(redact(value), value, "over-redacted {value:?}");
        }
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = redact("Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ");
        assert_eq!(redact(&once), once, "a redacted value was redacted again");
    }
}
