//! Key material: generation, import, export, signing and verification.
//!
//! Everything cryptographic here is aws-lc-rs. What this module adds is the
//! mapping between the algorithm allow-list and the primitives, the key-size
//! floors FAPI 2.0 SP §5.4.1 sets, and the JWK representation of a public key.

use crate::JoseError;
use asterius_domain::SigningAlgorithm;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ED25519, EcdsaKeyPair,
    Ed25519KeyPair, KeyPair as _, RSA_PSS_2048_8192_SHA256, RSA_PSS_SHA256, RsaKeyPair,
    UnparsedPublicKey,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};

/// RSA moduli smaller than this are refused (FAPI 2.0 SP §5.4.1).
pub const MIN_RSA_BITS: usize = 2048;

/// A private signing key.
///
/// Holds the parsed key pair and the PKCS#8 encoding it came from. The PKCS#8
/// is kept because that is what goes to storage — encrypted, in
/// `signing_keys.private_key_ciphertext` — and re-encoding a parsed key is a
/// way to end up with bytes that differ from the ones that were stored.
pub struct SigningKey {
    algorithm: SigningAlgorithm,
    pair: KeyPairKind,
    pkcs8: zeroize::Zeroizing<Vec<u8>>,
}

enum KeyPairKind {
    Ed25519(Box<Ed25519KeyPair>),
    Ecdsa(Box<EcdsaKeyPair>),
    Rsa(Box<RsaKeyPair>),
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key material, not even its length: a Debug of a key is
        // exactly the kind of line that ends up in an issue report.
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Generates a new key.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::KeyGeneration`] if the provider refuses.
    pub fn generate(algorithm: SigningAlgorithm) -> Result<Self, JoseError> {
        let rng = SystemRandom::new();
        // Generate as PKCS#8 first and parse that back, so the stored bytes and
        // the in-memory key are the same object by construction.
        let pkcs8: Vec<u8> = match algorithm {
            SigningAlgorithm::EdDsa => Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|_| JoseError::KeyGeneration(algorithm))?
                .as_ref()
                .to_vec(),
            SigningAlgorithm::Es256 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .map_err(|_| JoseError::KeyGeneration(algorithm))?
                    .as_ref()
                    .to_vec()
            }
            SigningAlgorithm::Ps256 => {
                let pair = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
                    .map_err(|_| JoseError::KeyGeneration(algorithm))?;
                aws_lc_rs::encoding::AsDer::<aws_lc_rs::encoding::Pkcs8V1Der<'static>>::as_der(
                    &pair,
                )
                .map_err(|_| JoseError::KeyGeneration(algorithm))?
                .as_ref()
                .to_vec()
            }
        };
        Self::from_pkcs8(algorithm, &pkcs8)
    }

    /// Imports a key from its PKCS#8 encoding.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::KeyRejected`] if the bytes are not a key of that
    /// algorithm, or [`JoseError::WeakKey`] if an RSA modulus is below
    /// [`MIN_RSA_BITS`].
    pub fn from_pkcs8(algorithm: SigningAlgorithm, pkcs8: &[u8]) -> Result<Self, JoseError> {
        let pair = match algorithm {
            SigningAlgorithm::EdDsa => KeyPairKind::Ed25519(Box::new(
                Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| JoseError::KeyRejected(algorithm))?,
            )),
            SigningAlgorithm::Es256 => KeyPairKind::Ecdsa(Box::new(
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
                    .map_err(|_| JoseError::KeyRejected(algorithm))?,
            )),
            SigningAlgorithm::Ps256 => {
                let pair =
                    RsaKeyPair::from_pkcs8(pkcs8).map_err(|_| JoseError::KeyRejected(algorithm))?;
                // FAPI 2.0 SP §5.4.1: RSA keys are at least 2048 bits. Checked
                // on import as well as on generation, because an operator
                // importing an old HSM key is exactly how a short one arrives.
                let bits = pair.public_modulus_len() * 8;
                if bits < MIN_RSA_BITS {
                    return Err(JoseError::WeakKey {
                        bits,
                        minimum: MIN_RSA_BITS,
                    });
                }
                KeyPairKind::Rsa(Box::new(pair))
            }
        };
        Ok(Self {
            algorithm,
            pair,
            pkcs8: zeroize::Zeroizing::new(pkcs8.to_vec()),
        })
    }

    /// The algorithm this key signs with.
    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// The PKCS#8 encoding, for encryption and storage.
    #[must_use]
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// Signs a message.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::Signing`] if the provider fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        let rng = SystemRandom::new();
        match &self.pair {
            KeyPairKind::Ed25519(pair) => Ok(pair.sign(message).as_ref().to_vec()),
            KeyPairKind::Ecdsa(pair) => Ok(pair
                .sign(&rng, message)
                .map_err(|_| JoseError::Signing)?
                .as_ref()
                .to_vec()),
            KeyPairKind::Rsa(pair) => {
                let mut signature = vec![0_u8; pair.public_modulus_len()];
                pair.sign(&RSA_PSS_SHA256, &rng, message, &mut signature)
                    .map_err(|_| JoseError::Signing)?;
                Ok(signature)
            }
        }
    }

    /// The public half, as a JWK (RFC 7517 §4).
    ///
    /// `kid` is not set here: the caller owns key identity, because a `kid`
    /// must be stable across restarts and is stored alongside the key.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::PublicKey`] if the public material cannot be read.
    pub fn public_jwk(&self) -> Result<Value, JoseError> {
        match &self.pair {
            KeyPairKind::Ed25519(pair) => Ok(json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": B64.encode(pair.public_key().as_ref()),
                "alg": "EdDSA",
                "use": "sig",
            })),
            KeyPairKind::Ecdsa(pair) => {
                // A P-256 public key is the uncompressed point 0x04 ‖ X ‖ Y,
                // and RFC 7518 §6.2.1.2 wants X and Y separately, each padded
                // to the coordinate length.
                let point = pair.public_key().as_ref();
                let (tag, coordinates) = point.split_first().ok_or(JoseError::PublicKey)?;
                if *tag != 0x04 || coordinates.len() != 64 {
                    return Err(JoseError::PublicKey);
                }
                let (x, y) = coordinates.split_at(32);
                Ok(json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": B64.encode(x),
                    "y": B64.encode(y),
                    "alg": "ES256",
                    "use": "sig",
                }))
            }
            KeyPairKind::Rsa(pair) => {
                let public = pair.public_key();
                Ok(json!({
                    "kty": "RSA",
                    "n": B64.encode(public.modulus().big_endian_without_leading_zero()),
                    "e": B64.encode(public.exponent().big_endian_without_leading_zero()),
                    "alg": "PS256",
                    "use": "sig",
                }))
            }
        }
    }

    /// The public half, as a verifying key.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::PublicKey`] if the public material cannot be read.
    pub fn verifying_key(&self) -> Result<VerifyingKey, JoseError> {
        let bytes = match &self.pair {
            KeyPairKind::Ed25519(pair) => pair.public_key().as_ref().to_vec(),
            KeyPairKind::Ecdsa(pair) => pair.public_key().as_ref().to_vec(),
            KeyPairKind::Rsa(pair) => aws_lc_rs::encoding::AsDer::<
                aws_lc_rs::encoding::PublicKeyX509Der<'static>,
            >::as_der(pair.public_key())
            .map_err(|_| JoseError::PublicKey)?
            .as_ref()
            .to_vec(),
        };
        Ok(VerifyingKey {
            algorithm: self.algorithm,
            bytes,
        })
    }
}

/// The public half of a signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    algorithm: SigningAlgorithm,
    bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Builds a verifying key from raw public material.
    ///
    /// The encoding is the one aws-lc-rs expects for the algorithm: raw 32
    /// bytes for Ed25519, an uncompressed point for P-256, X.509
    /// `SubjectPublicKeyInfo` DER for RSA.
    #[must_use]
    pub const fn new(algorithm: SigningAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// The algorithm this key verifies.
    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Verifies a signature.
    ///
    /// The algorithm comes from *this key*, never from the token being checked.
    /// That is RFC 8725 §3.1: the verifier decides which algorithm applies, so
    /// a token cannot nominate a weaker one — or a symmetric one, which is how
    /// a public key becomes an HMAC secret.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::InvalidSignature`] if the signature does not check
    /// out, for any reason. The reason is deliberately not reported.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        let result = match self.algorithm {
            SigningAlgorithm::EdDsa => {
                UnparsedPublicKey::new(&ED25519, &self.bytes).verify(message, signature)
            }
            SigningAlgorithm::Es256 => {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.bytes)
                    .verify(message, signature)
            }
            SigningAlgorithm::Ps256 => {
                UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &self.bytes)
                    .verify(message, signature)
            }
        };
        result.map_err(|_| JoseError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_permitted_algorithm_generates_signs_and_verifies() {
        for algorithm in SigningAlgorithm::ALL {
            let key = SigningKey::generate(algorithm).expect("generate");
            assert_eq!(key.algorithm(), algorithm);

            let message = b"the quick brown fox";
            let signature = key.sign(message).expect("sign");
            key.verifying_key()
                .expect("public key")
                .verify(message, &signature)
                .unwrap_or_else(|e| panic!("{algorithm} did not verify its own signature: {e}"));
        }
    }

    #[test]
    fn a_signature_over_different_bytes_does_not_verify() {
        for algorithm in SigningAlgorithm::ALL {
            let key = SigningKey::generate(algorithm).expect("generate");
            let signature = key.sign(b"original message").expect("sign");
            let verifying = key.verifying_key().expect("public key");
            assert!(
                verifying.verify(b"tampered message", &signature).is_err(),
                "{algorithm} verified a signature over different bytes"
            );
        }
    }

    /// Flipping any single bit of a signature must break it.
    #[test]
    fn tampering_with_any_byte_of_a_signature_breaks_it() {
        for algorithm in SigningAlgorithm::ALL {
            let key = SigningKey::generate(algorithm).expect("generate");
            let message = b"payload";
            let signature = key.sign(message).expect("sign");
            let verifying = key.verifying_key().expect("public key");

            for index in 0..signature.len() {
                let mut tampered = signature.clone();
                tampered[index] ^= 0x01;
                assert!(
                    verifying.verify(message, &tampered).is_err(),
                    "{algorithm} accepted a signature with byte {index} flipped"
                );
            }
        }
    }

    #[test]
    fn another_keys_signature_does_not_verify() {
        for algorithm in SigningAlgorithm::ALL {
            let mine = SigningKey::generate(algorithm).expect("generate");
            let theirs = SigningKey::generate(algorithm).expect("generate");
            let signature = theirs.sign(b"payload").expect("sign");
            assert!(
                mine.verifying_key()
                    .expect("public key")
                    .verify(b"payload", &signature)
                    .is_err(),
                "{algorithm} accepted another key's signature"
            );
        }
    }

    #[test]
    fn a_key_round_trips_through_its_pkcs8_encoding() {
        for algorithm in SigningAlgorithm::ALL {
            let original = SigningKey::generate(algorithm).expect("generate");
            let restored = SigningKey::from_pkcs8(algorithm, original.pkcs8()).expect("import");

            assert_eq!(
                original.public_jwk().expect("jwk"),
                restored.public_jwk().expect("jwk")
            );
            // A signature from the restored key verifies against the original's
            // public half, which is the property storage depends on.
            let signature = restored.sign(b"payload").expect("sign");
            original
                .verifying_key()
                .expect("public key")
                .verify(b"payload", &signature)
                .expect("restored key must be the same key");
        }
    }

    #[test]
    fn importing_a_key_as_the_wrong_algorithm_fails() {
        let ed25519 = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        for wrong in [SigningAlgorithm::Es256, SigningAlgorithm::Ps256] {
            assert!(
                SigningKey::from_pkcs8(wrong, ed25519.pkcs8()).is_err(),
                "an Ed25519 key was imported as {wrong}"
            );
        }
    }

    #[test]
    fn garbage_is_not_a_key() {
        for algorithm in SigningAlgorithm::ALL {
            assert!(SigningKey::from_pkcs8(algorithm, b"").is_err());
            assert!(SigningKey::from_pkcs8(algorithm, b"not a key at all").is_err());
            assert!(SigningKey::from_pkcs8(algorithm, &[0_u8; 64]).is_err());
        }
    }

    /// RFC 7517 §4 and RFC 7518 §6: the members each key type must carry.
    #[test]
    fn a_public_jwk_carries_the_members_its_key_type_requires() {
        let expected: [(SigningAlgorithm, &str, &[&str]); 3] = [
            (SigningAlgorithm::EdDsa, "OKP", &["crv", "x"]),
            (SigningAlgorithm::Es256, "EC", &["crv", "x", "y"]),
            (SigningAlgorithm::Ps256, "RSA", &["n", "e"]),
        ];

        for (algorithm, kty, members) in expected {
            let jwk = SigningKey::generate(algorithm)
                .expect("generate")
                .public_jwk()
                .expect("jwk");
            assert_eq!(jwk["kty"], kty, "{algorithm}");
            assert_eq!(jwk["alg"], algorithm.as_str());
            assert_eq!(jwk["use"], "sig");
            for member in members {
                assert!(
                    jwk.get(*member).is_some(),
                    "{algorithm} jwk has no {member}"
                );
            }
            // The private half must never appear.
            for private in ["d", "p", "q", "dp", "dq", "qi"] {
                assert!(
                    jwk.get(private).is_none(),
                    "{algorithm} jwk leaked {private}"
                );
            }
        }
    }

    #[test]
    fn ec_coordinates_are_the_right_length_and_the_point_tag_is_stripped() {
        let jwk = SigningKey::generate(SigningAlgorithm::Es256)
            .expect("generate")
            .public_jwk()
            .expect("jwk");
        for coordinate in ["x", "y"] {
            let raw = B64
                .decode(jwk[coordinate].as_str().expect("string"))
                .expect("base64url");
            assert_eq!(raw.len(), 32, "P-256 {coordinate} must be 32 bytes");
        }
    }

    /// FAPI 2.0 SP §5.4.1: RSA keys are at least 2048 bits.
    #[test]
    fn generated_rsa_keys_meet_the_size_floor() {
        let key = SigningKey::generate(SigningAlgorithm::Ps256).expect("generate");
        let jwk = key.public_jwk().expect("jwk");
        let modulus = B64
            .decode(jwk["n"].as_str().expect("string"))
            .expect("base64url");
        assert!(
            modulus.len() * 8 >= MIN_RSA_BITS,
            "modulus is {} bits",
            modulus.len() * 8
        );
    }

    #[test]
    fn debugging_a_key_does_not_print_its_material() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let rendered = format!("{key:?}");
        assert!(rendered.contains("EdDsa"));
        // Nothing that looks like key bytes.
        assert!(!rendered.contains("pkcs8"), "{rendered}");
        assert!(!rendered.contains('['), "{rendered}");
    }
}
