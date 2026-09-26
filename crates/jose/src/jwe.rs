//! A deliberately narrow RFC 7516 compact JWE issuer for nested signed JWTs.
//!
//! Only RSA-OAEP-256 and A256GCM are accepted. The caller signs first, then
//! encrypts for one explicitly designated RP encryption key. This module does
//! not resolve a `jwks_uri`; the guarded client-key fetcher must supply its
//! bounded document. Nothing here changes registration or advertises support.

use aws_lc_rs::aead::{AES_256_GCM, Aad, RandomizedNonceKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::rsa::{OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PublicEncryptingKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rsa::BigUint;
use rsa::RsaPublicKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// Signed assertion size limit before encryption; sufficient for UserInfo.
pub const MAX_ASSERTION_BYTES: usize = 64 * 1024;
const MAX_JWKS_BYTES: usize = 64 * 1024;
const MAX_KEYS: usize = 32;
const TAG_BYTES: usize = 16;

/// A local configuration or encryption failure. No key material is included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JweError {
    /// The supplied JWK Set or encryption key is invalid or ambiguous.
    #[error("no unique, eligible RSA-OAEP-256 encryption key")]
    Key,
    /// The signed assertion is empty or exceeds its bound.
    #[error("signed assertion size is invalid")]
    Assertion,
    /// The crypto provider could not encrypt the assertion.
    #[error("assertion encryption failed")]
    Encryption,
}

/// A public RP encryption key, separate from signing verification keys.
#[derive(Debug)]
pub struct Recipient {
    kid: String,
    key: OaepPublicEncryptingKey,
}

impl Recipient {
    /// Selects one key by `kid`. If no ID is configured, exactly one eligible
    /// encryption key must exist. A rotation with two eligible keys therefore
    /// fails closed until the operator selects one explicitly.
    pub fn from_jwks(document: &[u8], selected_kid: Option<&str>) -> Result<Self, JweError> {
        if document.is_empty() || document.len() > MAX_JWKS_BYTES {
            return Err(JweError::Key);
        }
        let value: Value = serde_json::from_slice(document).map_err(|_| JweError::Key)?;
        let keys = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(JweError::Key)?;
        if keys.is_empty() || keys.len() > MAX_KEYS {
            return Err(JweError::Key);
        }
        // A leaked private JWK poisons the whole document, even if another
        // public entry would otherwise be usable.
        if keys.iter().any(|key| {
            ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|name| key.get(*name).is_some())
        }) {
            return Err(JweError::Key);
        }
        let mut seen_ids = std::collections::HashSet::new();
        for id in keys
            .iter()
            .filter_map(|key| key.get("kid").and_then(Value::as_str))
        {
            if !seen_ids.insert(id) {
                return Err(JweError::Key);
            }
        }
        let mut candidates = keys.iter().filter(|key| {
            key.get("kty").and_then(Value::as_str) == Some("RSA")
                && key.get("use").and_then(Value::as_str) == Some("enc")
                && key
                    .get("alg")
                    .is_none_or(|alg| alg.as_str() == Some("RSA-OAEP-256"))
                && key.get("key_ops").is_none_or(|ops| {
                    ops.as_array().is_some_and(|ops| {
                        !ops.is_empty() && ops.iter().all(|op| op.as_str() == Some("wrapKey"))
                    })
                })
                && key.get("kid").and_then(Value::as_str).is_some_and(|kid| {
                    !kid.is_empty()
                        && kid.len() <= 128
                        && !kid.chars().any(char::is_control)
                        && selected_kid.is_none_or(|selected| selected == kid)
                })
        });
        let key = candidates.next().ok_or(JweError::Key)?;
        if candidates.next().is_some() {
            return Err(JweError::Key);
        }
        let kid = key
            .get("kid")
            .and_then(Value::as_str)
            .ok_or(JweError::Key)?;
        let n = key.get("n").and_then(Value::as_str).ok_or(JweError::Key)?;
        let e = key.get("e").and_then(Value::as_str).ok_or(JweError::Key)?;
        let modulus = B64.decode(n).map_err(|_| JweError::Key)?;
        let exponent = B64.decode(e).map_err(|_| JweError::Key)?;
        if modulus.len() < 256 || modulus.len() > 512 || exponent.is_empty() || exponent.len() > 8 {
            return Err(JweError::Key);
        }
        let rsa = RsaPublicKey::new(
            BigUint::from_bytes_be(&modulus),
            BigUint::from_bytes_be(&exponent),
        )
        .map_err(|_| JweError::Key)?;
        if !(2048..=4096).contains(&rsa.n().bits()) {
            return Err(JweError::Key);
        }
        let der = rsa.to_public_key_der().map_err(|_| JweError::Key)?;
        let public = PublicEncryptingKey::from_der(der.as_ref()).map_err(|_| JweError::Key)?;
        let key = OaepPublicEncryptingKey::new(public).map_err(|_| JweError::Key)?;
        Ok(Self {
            kid: kid.to_owned(),
            key,
        })
    }

    /// Encrypts a signed JWT as compact JWE. The protected header is AES-GCM
    /// additional authenticated data and identifies the RP's selected key.
    pub fn encrypt_signed_jwt(&self, signed_jwt: &str) -> Result<String, JweError> {
        if signed_jwt.is_empty() || signed_jwt.len() > MAX_ASSERTION_BYTES {
            return Err(JweError::Assertion);
        }
        // Syntax checking is not signature verification. The issuance path
        // must pass the JWS it just signed; this prevents a plain JSON string
        // from being mislabeled as a nested JWT by this primitive.
        crate::jws::parse(signed_jwt).map_err(|_| JweError::Assertion)?;
        let header = serde_json::to_vec(&json!({
            "alg": "RSA-OAEP-256", "enc": "A256GCM", "cty": "JWT", "kid": self.kid,
        }))
        .map_err(|_| JweError::Encryption)?;
        let encoded_header = B64.encode(header);
        let mut cek = Zeroizing::new([0_u8; 32]);
        SystemRandom::new()
            .fill(cek.as_mut())
            .map_err(|_| JweError::Encryption)?;
        let mut wrapped = vec![0_u8; self.key.ciphertext_size()];
        let encrypted_key = self
            .key
            .encrypt(&OAEP_SHA256_MGF1SHA256, cek.as_ref(), &mut wrapped, None)
            .map_err(|_| JweError::Encryption)?;
        let aes = RandomizedNonceKey::new(&AES_256_GCM, cek.as_ref())
            .map_err(|_| JweError::Encryption)?;
        let mut ciphertext = Vec::with_capacity(signed_jwt.len() + TAG_BYTES);
        ciphertext.extend_from_slice(signed_jwt.as_bytes());
        let nonce = aes
            .seal_in_place_append_tag(Aad::from(encoded_header.as_bytes()), &mut ciphertext)
            .map_err(|_| JweError::Encryption)?;
        let tag = ciphertext.split_off(signed_jwt.len());
        Ok(format!(
            "{}.{}.{}.{}.{}",
            encoded_header,
            B64.encode(encrypted_key),
            B64.encode(nonce.as_ref()),
            B64.encode(ciphertext),
            B64.encode(tag),
        ))
    }
}
