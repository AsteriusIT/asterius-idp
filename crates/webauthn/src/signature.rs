//! Verifying an authenticator's signature (WebAuthn L3 §7.2 step 20).
//!
//! This is the one place in the crate where arithmetic happens, and it does
//! none of it: the COSE key is turned into the shape `aws-lc-rs` accepts and
//! handed to `aws-lc-rs`. ADR-0004's rule is that this codebase owns encodings
//! and borrows primitives, and a signature check is entirely primitive.
//!
//! # The three shapes, and why each is spelled out
//!
//! * **ES256.** The COSE key holds `x` and `y`; `aws-lc-rs` wants a SEC 1
//!   uncompressed point, which is `0x04 || x || y`. The signature an
//!   authenticator produces is ASN.1 DER, not the fixed-width pair JWS uses —
//!   §6.5.6 says so, and picking the fixed variant here would refuse every
//!   real assertion.
//! * **EdDSA.** `x` is the 32-byte public key and the signature is 64 raw
//!   bytes. Nothing to reshape.
//! * **RS256.** `n` and `e` are big-endian components, which
//!   [`aws_lc_rs::signature::RsaPublicKeyComponents`] verifies with directly.
//!
//! # What is *not* checked here
//!
//! That the key is one this server accepted at registration. [`cose::parse`]
//! decided that, and the bytes verified here are the ones it stored — so a key
//! reaching this function has already been through the length and type rules.
//! Re-deriving them would be a second opinion, and two opinions about what a
//! key is are how one credential comes to have two spellings.

use crate::cose::{self, CoseAlgorithm, CredentialPublicKey};
use aws_lc_rs::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};

/// Why a signature was not accepted.
///
/// Two variants, and the caller reports one refusal for both: an assertion
/// that does not verify is an assertion that does not verify, and whether the
/// key would not load or the signature did not match is a distinction only a
/// log needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// The stored credential public key could not be read back.
    ///
    /// It passed [`cose::parse`] on the way in, so this is a corrupted row or
    /// a key written by something that is not this server — not an input an
    /// authenticator can produce.
    #[error("the stored credential public key could not be loaded")]
    UnusableKey,
    /// The signature is not this key's over these bytes.
    #[error("the assertion signature does not verify")]
    BadSignature,
}

/// Verifies `signature` over `message` with a credential public key.
///
/// `message` is `authenticatorData || SHA-256(clientDataJSON)` — assembled by
/// the caller, because those are bytes it holds and this function must not
/// re-derive either half.
///
/// # Errors
///
/// [`SignatureError`] if the key cannot be loaded or the signature does not
/// verify.
pub fn verify(
    key: &CredentialPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    match key.algorithm() {
        CoseAlgorithm::Es256 => {
            let (x, y) = cose::ec2_coordinates(key.encoded()).ok_or(SignatureError::UnusableKey)?;
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point)
                .verify(message, signature)
                .map_err(|_| SignatureError::BadSignature)
        }
        CoseAlgorithm::EdDsa => {
            let x = cose::okp_public_key(key.encoded()).ok_or(SignatureError::UnusableKey)?;
            UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(message, signature)
                .map_err(|_| SignatureError::BadSignature)
        }
        CoseAlgorithm::Rs256 => {
            let (n, e) = cose::rsa_components(key.encoded()).ok_or(SignatureError::UnusableKey)?;
            RsaPublicKeyComponents { n, e }
                .verify(
                    // The 2048-bit floor is `cose::parse`'s; this names the
                    // same one so a key that somehow got past it is refused
                    // here too rather than verified with a short modulus.
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    message,
                    signature,
                )
                .map_err(|_| SignatureError::BadSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};
    use ciborium::value::Value;

    /// A `COSE_Key` for an EC2 P-256 point.
    fn es256_key(point: &[u8]) -> CredentialPublicKey {
        let map = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(point[1..33].to_vec()),
            ),
            (
                Value::Integer((-3).into()),
                Value::Bytes(point[33..].to_vec()),
            ),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&map, &mut encoded).expect("a CBOR map encodes");
        cose::parse(&encoded).expect("a key this server accepts")
    }

    /// A `COSE_Key` for an Ed25519 public key.
    fn eddsa_key(public: &[u8]) -> CredentialPublicKey {
        let map = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(3.into()), Value::Integer((-8).into())),
            (Value::Integer((-1).into()), Value::Integer(6.into())),
            (Value::Integer((-2).into()), Value::Bytes(public.to_vec())),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&map, &mut encoded).expect("a CBOR map encodes");
        cose::parse(&encoded).expect("a key this server accepts")
    }

    #[test]
    fn an_es256_signature_over_the_signed_bytes_verifies() {
        // Arrange
        let random = SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &random)
                .expect("a generated key");
        let pair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            document.as_ref(),
        )
        .expect("the generated key parses");
        let key = es256_key(pair.public_key().as_ref());
        let message = b"authenticator data and a client data hash";
        let signed = pair.sign(&random, message).expect("a signature");

        // Act
        let outcome = verify(&key, message, signed.as_ref());

        // Assert
        assert_eq!(outcome, Ok(()));
    }

    #[test]
    fn an_es256_signature_over_other_bytes_does_not_verify() {
        // Arrange
        let random = SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &random)
                .expect("a generated key");
        let pair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            document.as_ref(),
        )
        .expect("the generated key parses");
        let key = es256_key(pair.public_key().as_ref());
        let signed = pair.sign(&random, b"one message").expect("a signature");

        // Act
        let outcome = verify(&key, b"another message", signed.as_ref());

        // Assert
        assert_eq!(outcome, Err(SignatureError::BadSignature));
    }

    #[test]
    fn an_eddsa_signature_over_the_signed_bytes_verifies() {
        // Arrange
        let document =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("a generated key");
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("the key parses");
        let key = eddsa_key(pair.public_key().as_ref());
        let message = b"authenticator data and a client data hash";
        let signed = pair.sign(message);

        // Act
        let outcome = verify(&key, message, signed.as_ref());

        // Assert
        assert_eq!(outcome, Ok(()));
    }
}
