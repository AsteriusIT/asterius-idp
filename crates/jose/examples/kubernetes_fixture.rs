//! Disposable synthetic identity fixtures signed by Asterius's actual JOSE provider.
//! Prints public keys and short-lived fictional tokens only; private keys stay in memory.

use asterius_domain::{Kid, SigningAlgorithm};
use asterius_jose::{SigningKey, jws};
use serde_json::{Value, json};
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let es256 = SigningKey::generate(SigningAlgorithm::Es256)?;
    let eddsa = SigningKey::generate(SigningAlgorithm::EdDsa)?;
    let kid = Kid::new("disposable-kubernetes-fixture");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = json!({"iss":"https://issuer.example/t/demo", "aud":"cluster-a-client", "sub":"fictional-user", "iat":now, "exp":now + 300, "group_ids":["group:00000000-0000-0000-0000-000000000001"]});
    let sign = |key: &SigningKey, value: &Value| {
        jws::sign(key, &kid, "JWT", value).map(|token| token.as_str().to_owned())
    };
    let valid = sign(&es256, &claims)?;
    let mut tokens = serde_json::Map::new();
    tokens.insert("valid".to_owned(), json!(valid));
    for (name, field, replacement) in [
        ("wrong_audience", "aud", json!("cluster-b-client")),
        ("wrong_issuer", "iss", json!("https://other.example")),
        ("expired", "exp", json!(now - 30)),
        ("excessive_lifetime", "exp", json!(now + 3600)),
        (
            "multiple_audiences",
            "aud",
            json!(["cluster-a-client", "cluster-b-client"]),
        ),
    ] {
        let mut modified = claims.clone();
        modified[field] = replacement;
        tokens.insert(name.to_owned(), json!(sign(&es256, &modified)?));
    }
    let mut absent_groups = claims.clone();
    if let Some(object) = absent_groups.as_object_mut() {
        object.remove("group_ids");
    }
    tokens.insert(
        "absent_groups".to_owned(),
        json!(sign(&es256, &absent_groups)?),
    );
    tokens.insert(
        "unsupported_algorithm".to_owned(),
        json!(sign(&eddsa, &claims)?),
    );
    let mut tampered = valid.into_bytes();
    if let Some(index) = tampered.iter().rposition(|byte| *byte == b'.')
        && let Some(first_signature_byte) = tampered.get_mut(index + 1)
    {
        *first_signature_byte = if *first_signature_byte == b'A' {
            b'B'
        } else {
            b'A'
        };
    }
    tokens.insert("tampered".to_owned(), json!(String::from_utf8(tampered)?));
    let mut approved_key_document = es256.public_jwk()?;
    approved_key_document["kid"] = json!(kid.as_str());
    let mut ed25519_public = eddsa.public_jwk()?;
    ed25519_public["kid"] = json!(kid.as_str());
    println!(
        "{}",
        serde_json::to_string(
            &json!({"jwks":{"keys":[approved_key_document, ed25519_public]}, "tokens":tokens})
        )?
    );
    Ok(())
}
