//! Verification of an external OIDC provider's ID Token.
//!
//! RS256 belongs only to this inbound trust boundary. It is deliberately not
//! added to the algorithms that this server signs or advertises.

use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::Value;
use time::OffsetDateTime;

use crate::client_keys::{MAX_JWK_SET_BYTES, MAX_KEYS, has_private_members, verifying_key};
use asterius_domain::SigningAlgorithm;

/// Identity claims returned only after signature and OIDC checks succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpstreamIdToken {
    /// Provider-local stable subject identifier.
    pub subject: String,
    /// The token's issuance timestamp, in Unix seconds.
    pub issued_at: i64,
}

/// An upstream ID Token or key set failed validation. Details are withheld at
/// the login boundary so attackers cannot probe which part was almost valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamIdTokenError {
    /// The token or JWKS was invalid, or its claims did not match this login.
    #[error("upstream ID token verification failed")]
    Invalid,
}

/// Verifies an RS256, ES256 or PS256 ID Token against a trusted provider's JWKS.
///
/// The caller must obtain `jwks` from the configured provider through its
/// guarded fetch path. Header URLs and embedded keys are never followed.
/// OIDC Core permits an absent `typ` or `JWT`; other types are rejected.
///
/// # Errors
///
/// Returns [`UpstreamIdTokenError::Invalid`] for any invalid token or key set.
pub fn verify_upstream_id_token(
    token: &str,
    jwks: &[u8],
    expected_issuer: &str,
    client_id: &str,
    expected_nonce_digest: &str,
    now: OffsetDateTime,
) -> Result<VerifiedUpstreamIdToken, UpstreamIdTokenError> {
    let invalid = UpstreamIdTokenError::Invalid;
    if token.len() > asterius_domain::MAX_JWT_BYTES
        || jwks.is_empty()
        || jwks.len() > MAX_JWK_SET_BYTES
    {
        return Err(invalid);
    }
    let mut segments = token.split('.');
    let (Some(protected), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(invalid);
    };
    if protected.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(invalid);
    }
    let header: Value = serde_json::from_slice(&B64.decode(protected).map_err(|_| invalid)?)
        .map_err(|_| invalid)?;
    let header = header.as_object().ok_or(invalid)?;
    let algorithm = header.get("alg").and_then(Value::as_str).ok_or(invalid)?;
    let key_type = match algorithm {
        "RS256" | "PS256" => "RSA",
        "ES256" => "EC",
        _ => return Err(invalid),
    };
    if header.contains_key("crit")
        || header.contains_key("jwk")
        || header.contains_key("jku")
        || header.contains_key("x5u")
        || header.contains_key("x5c")
        || header.contains_key("b64")
        || header.get("typ").is_some_and(|typ| {
            !typ.as_str().is_some_and(|typ| {
                typ.eq_ignore_ascii_case("JWT") || typ.eq_ignore_ascii_case("application/JWT")
            })
        })
    {
        return Err(invalid);
    }
    let kid = header.get("kid").and_then(Value::as_str).ok_or(invalid)?;
    if kid.is_empty() || kid.len() > 128 || kid.chars().any(char::is_control) {
        return Err(invalid);
    }
    let signature = B64.decode(signature).map_err(|_| invalid)?;
    let document: Value = serde_json::from_slice(jwks).map_err(|_| invalid)?;
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty() && keys.len() <= MAX_KEYS)
        .ok_or(invalid)?;
    // A published private key poisons the set, even when it is not selected.
    if keys
        .iter()
        .filter_map(Value::as_object)
        .any(has_private_members)
    {
        return Err(invalid);
    }
    // A `kid` must identify exactly one published key. Trying each duplicate
    // would make a rotation or key substitution silently change which key was
    // trusted for this token.
    if keys
        .iter()
        .filter(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        .count()
        != 1
    {
        return Err(invalid);
    }
    let signing_input = format!("{protected}.{payload}");
    if !signature_verifies(
        keys,
        kid,
        key_type,
        algorithm,
        signing_input.as_bytes(),
        &signature,
    ) {
        return Err(invalid);
    }
    verify_claims(
        payload,
        expected_issuer,
        client_id,
        expected_nonce_digest,
        now,
    )
}

fn signature_verifies(
    keys: &[Value],
    kid: &str,
    key_type: &str,
    algorithm: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> bool {
    for key in keys {
        let Some(key) = key.as_object() else {
            continue;
        };
        if key.get("kid").and_then(Value::as_str) != Some(kid)
            || key.get("kty").and_then(Value::as_str) != Some(key_type)
            || key
                .get("alg")
                .is_some_and(|alg| alg.as_str() != Some(algorithm))
            || key
                .get("use")
                .is_some_and(|use_| use_.as_str() != Some("sig"))
            || key.get("key_ops").is_some_and(|ops| {
                !ops.as_array().is_some_and(|ops| {
                    !ops.is_empty() && ops.iter().all(|op| op.as_str() == Some("verify"))
                })
            })
        {
            continue;
        }
        let signature_valid = match algorithm {
            "RS256" => verify_rs256(key, signing_input, signature),
            "ES256" => verifying_key(SigningAlgorithm::Es256, key)
                .is_some_and(|key| key.verify(signing_input, signature).is_ok()),
            "PS256" => verifying_key(SigningAlgorithm::Ps256, key)
                .is_some_and(|key| key.verify(signing_input, signature).is_ok()),
            _ => false,
        };
        if signature_valid {
            return true;
        }
    }
    false
}

fn verify_claims(
    payload: &str,
    expected_issuer: &str,
    client_id: &str,
    expected_nonce_digest: &str,
    now: OffsetDateTime,
) -> Result<VerifiedUpstreamIdToken, UpstreamIdTokenError> {
    let invalid = UpstreamIdTokenError::Invalid;
    let claims: Value =
        serde_json::from_slice(&B64.decode(payload).map_err(|_| invalid)?).map_err(|_| invalid)?;
    let claims = claims.as_object().ok_or(invalid)?;
    if claims.get("iss").and_then(Value::as_str) != Some(expected_issuer) {
        return Err(invalid);
    }
    let nonce = claims.get("nonce").and_then(Value::as_str).ok_or(invalid)?;
    let nonce_digest = asterius_domain::sha256_hex(nonce.as_bytes());
    if !asterius_domain::ct_eq(nonce_digest.as_bytes(), expected_nonce_digest.as_bytes()) {
        return Err(invalid);
    }
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|sub| !sub.is_empty())
        .ok_or(invalid)?;
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(aud)) if !aud.is_empty() => vec![aud],
        Some(Value::Array(aud)) if !aud.is_empty() => aud
            .iter()
            .map(|aud| aud.as_str().filter(|aud| !aud.is_empty()).ok_or(invalid))
            .collect::<Result<_, _>>()?,
        _ => return Err(invalid),
    };
    if !audiences.contains(&client_id)
        || (audiences.len() > 1 && claims.get("azp").and_then(Value::as_str) != Some(client_id))
        || claims
            .get("azp")
            .is_some_and(|azp| azp.as_str() != Some(client_id))
    {
        return Err(invalid);
    }
    let now = now.unix_timestamp();
    let exp = claims.get("exp").and_then(Value::as_i64).ok_or(invalid)?;
    let issued_at = claims.get("iat").and_then(Value::as_i64).ok_or(invalid)?;
    if exp <= now
        || issued_at > now + 60
        || issued_at >= exp
        || claims
            .get("nbf")
            .is_some_and(|nbf| nbf.as_i64().is_none_or(|nbf| nbf > now + 60))
    {
        return Err(invalid);
    }
    Ok(VerifiedUpstreamIdToken {
        subject: subject.to_owned(),
        issued_at,
    })
}

fn verify_rs256(key: &serde_json::Map<String, Value>, message: &[u8], signature: &[u8]) -> bool {
    let (Some(n), Some(e)) = (
        key.get("n").and_then(Value::as_str),
        key.get("e").and_then(Value::as_str),
    ) else {
        return false;
    };
    let (Ok(n), Ok(e)) = (B64.decode(n), B64.decode(e)) else {
        return false;
    };
    if !(256..=1024).contains(&n.len())
        || n.first() == Some(&0)
        || e.is_empty()
        || e.len() > 8
        || e.first() == Some(&0)
    {
        return false;
    }
    RsaPublicKeyComponents { n, e }
        .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SigningKey, jws};
    use asterius_domain::Kid;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};
    use serde_json::json;

    const ISSUER: &str = "https://upstream.example";
    const CLIENT: &str = "client-one";
    const NONCE: &str = "unguessable-nonce";
    const NOW: i64 = 1_760_000_000;

    fn fixture(header: &Value, claims: &Value) -> (String, Value) {
        let pair = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).expect("RSA key");
        let public = pair.public_key();
        let jwk = json!({
            "kid": "k1", "kty": "RSA", "alg": "RS256", "use": "sig",
            "n": B64.encode(public.modulus().big_endian_without_leading_zero()),
            "e": B64.encode(public.exponent().big_endian_without_leading_zero()),
        });
        let signing_input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).expect("header")),
            B64.encode(serde_json::to_vec(&claims).expect("claims"))
        );
        let mut signature = vec![0; pair.public_modulus_len()];
        pair.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature,
        )
        .expect("signature");
        (format!("{signing_input}.{}", B64.encode(signature)), jwk)
    }

    fn claims() -> Value {
        json!({
            "iss": ISSUER, "sub": "alice", "aud": CLIENT,
            "nonce": NONCE, "iat": NOW, "exp": NOW + 300,
        })
    }

    fn check(token: &str, jwk: &Value) -> Result<VerifiedUpstreamIdToken, UpstreamIdTokenError> {
        verify_upstream_id_token(
            token,
            &serde_json::to_vec(&json!({"keys": [jwk]})).expect("JWKS"),
            ISSUER,
            CLIENT,
            &asterius_domain::sha256_hex(NONCE.as_bytes()),
            OffsetDateTime::from_unix_timestamp(NOW).expect("time"),
        )
    }

    #[test]
    fn valid_rs256_token_verifies() {
        let (token, jwk) = fixture(&json!({"alg": "RS256", "kid": "k1"}), &claims());
        assert_eq!(
            check(&token, &jwk).expect("valid"),
            VerifiedUpstreamIdToken {
                subject: "alice".to_owned(),
                issued_at: NOW
            }
        );
    }

    #[test]
    fn valid_es256_and_ps256_tokens_verify() {
        for algorithm in [SigningAlgorithm::Es256, SigningAlgorithm::Ps256] {
            let signer = SigningKey::generate(algorithm).expect("key");
            let token = jws::sign(&signer, &Kid::new("k1"), "JWT", &claims()).expect("token");
            let mut jwk = signer.public_jwk().expect("JWK");
            jwk["kid"] = json!("k1");
            assert_eq!(
                check(token.as_str(), &jwk).expect("valid"),
                VerifiedUpstreamIdToken {
                    subject: "alice".to_owned(),
                    issued_at: NOW,
                }
            );
        }
    }

    #[test]
    fn rejects_wrong_purpose_algorithm_and_key_metadata() {
        for header in [
            json!({"alg": "PS256", "kid": "k1"}),
            json!({"alg": "none", "kid": "k1"}),
            json!({"alg": "RS256", "kid": "k1", "typ": "at+jwt"}),
            json!({"alg": "RS256", "kid": "k1", "crit": []}),
            json!({"alg": "RS256", "kid": "wrong"}),
        ] {
            let (token, jwk) = fixture(&header, &claims());
            assert_eq!(check(&token, &jwk), Err(UpstreamIdTokenError::Invalid));
        }
        for (field, value) in [
            ("kty", json!("oct")),
            ("alg", json!("PS256")),
            ("use", json!("enc")),
            ("key_ops", json!(["encrypt"])),
        ] {
            let (token, mut jwk) = fixture(&json!({"alg": "RS256", "kid": "k1"}), &claims());
            jwk[field] = value;
            assert_eq!(check(&token, &jwk), Err(UpstreamIdTokenError::Invalid));
        }
    }

    #[test]
    fn rejects_changed_signature_and_oidc_claims() {
        let (token, jwk) = fixture(&json!({"alg": "RS256", "kid": "k1"}), &claims());
        let mut damaged = token.into_bytes();
        let last = damaged.last_mut().expect("signature");
        *last = if *last == b'A' { b'B' } else { b'A' };
        assert_eq!(
            check(std::str::from_utf8(&damaged).expect("ASCII"), &jwk),
            Err(UpstreamIdTokenError::Invalid)
        );
        for (field, value) in [
            ("iss", json!("https://wrong.example")),
            ("aud", json!("other-client")),
            ("nonce", json!("other-nonce")),
            ("exp", json!(NOW)),
            ("iat", json!(NOW + 61)),
            ("nbf", json!(NOW + 61)),
            ("sub", json!("")),
        ] {
            let mut claims = claims();
            claims[field] = value;
            let (token, jwk) = fixture(&json!({"alg": "RS256", "kid": "k1"}), &claims);
            assert_eq!(check(&token, &jwk), Err(UpstreamIdTokenError::Invalid));
        }
    }

    #[test]
    fn multiple_audiences_require_authorized_party() {
        let mut claims = claims();
        claims["aud"] = json!([CLIENT, "other-client"]);
        let (token, jwk) = fixture(&json!({"alg": "RS256", "kid": "k1"}), &claims);
        assert_eq!(check(&token, &jwk), Err(UpstreamIdTokenError::Invalid));
        claims["azp"] = json!(CLIENT);
        let (token, jwk) = fixture(&json!({"alg": "RS256", "kid": "k1"}), &claims);
        assert!(check(&token, &jwk).is_ok());
    }

    #[test]
    fn duplicate_kid_is_rejected_even_when_one_key_verifies() {
        let (token, jwk) = fixture(&json!({"alg": "RS256", "kid": "k1"}), &claims());
        let jwks = serde_json::to_vec(&json!({"keys": [jwk.clone(), jwk]})).expect("JWKS");
        assert_eq!(
            verify_upstream_id_token(
                &token,
                &jwks,
                ISSUER,
                CLIENT,
                &asterius_domain::sha256_hex(NONCE.as_bytes()),
                OffsetDateTime::from_unix_timestamp(NOW).expect("time"),
            ),
            Err(UpstreamIdTokenError::Invalid)
        );
    }
}
