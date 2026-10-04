//! Fresh proofs for one exact request; the DPoP key stays in memory.

use asterius_domain::outbound_scim::FailureCode;
use asterius_domain::{Secret, SigningAlgorithm};
use asterius_jose::{SigningKey, dpop::NormalisedUri};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

pub(super) fn proof(
    key: &SigningKey,
    method: &str,
    url: &str,
    token: Option<&Secret<String>>,
    nonce: Option<&str>,
) -> Result<Secret<String>, FailureCode> {
    if key.algorithm() != SigningAlgorithm::Es256 {
        return Err(FailureCode::CredentialUnavailable);
    }
    let uri = NormalisedUri::parse(url).map_err(|_| FailureCode::SourceProjectionInvalid)?;
    let header = serde_json::json!({"typ":"dpop+jwt","alg":key.algorithm().as_str(),"jwk":key.public_jwk().map_err(|_| FailureCode::CredentialUnavailable)?});
    let mut claims = serde_json::json!({"htm":method,"htu":uri.to_string(),"iat":OffsetDateTime::now_utc().unix_timestamp(),"jti":Uuid::new_v4().to_string()});
    if let Some(token) = token {
        claims["ath"] = serde_json::json!(B64.encode(Sha256::digest(token.expose().as_bytes())));
    }
    if let Some(nonce) = nonce {
        if nonce.len() > 512 || nonce.is_empty() {
            return Err(FailureCode::AuthenticationRefused);
        }
        claims["nonce"] = serde_json::json!(nonce);
    }
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).map_err(|_| FailureCode::CredentialUnavailable)?),
        B64.encode(serde_json::to_vec(&claims).map_err(|_| FailureCode::CredentialUnavailable)?)
    );
    let signature = key
        .sign(input.as_bytes())
        .map_err(|_| FailureCode::CredentialUnavailable)?;
    Ok(Secret::new(format!("{input}.{}", B64.encode(signature))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_jose::jws;
    #[test]
    fn resource_proof_has_exact_method_queryless_uri_hash_and_fresh_jti() {
        let key = SigningKey::generate(SigningAlgorithm::Es256).expect("key");
        let token = Secret::new("fixed-token".to_owned());
        let first = proof(
            &key,
            "GET",
            "https://target.example/scim/Users?filter=x",
            Some(&token),
            Some("nonce"),
        )
        .expect("proof");
        let second = proof(
            &key,
            "GET",
            "https://target.example/scim/Users?filter=x",
            Some(&token),
            Some("nonce"),
        )
        .expect("fresh");
        assert_ne!(first.expose(), second.expose());
        let verified = jws::parse(first.expose())
            .expect("JWS")
            .verify(&key.verifying_key().expect("public key"))
            .expect("signature");
        let claims: serde_json::Value = serde_json::from_slice(&verified).expect("claims");
        assert_eq!(claims["htm"], "GET");
        assert_eq!(claims["htu"], "https://target.example/scim/Users");
        assert_eq!(
            claims["ath"],
            B64.encode(Sha256::digest(token.expose().as_bytes()))
        );
        assert_eq!(claims["nonce"], "nonce");
    }
}
