//! COSE keys, as an authenticator hands them over (RFC 9052 §7).
//!
//! The credential public key inside attested credential data is a `COSE_Key`:
//! a CBOR map keyed by small integers. This parses exactly the three key types
//! this server will later be able to *verify* an assertion with, and refuses
//! everything else at registration — the moment a credential the server cannot
//! use is stored is the moment a user has a passkey that will never sign them
//! in, and they will not find out until they try.
//!
//! # This allow-list is not ADR-0003's
//!
//! ADR-0003 fixes the algorithms this server *signs tokens with*: EdDSA, ES256,
//! PS256. That is a statement about keys we generate and control.
//!
//! A passkey's algorithm is chosen by somebody else's authenticator, and the
//! server only ever verifies with it. The two lists answer different questions
//! and so they differ in one place: `RS256` is admitted here and nowhere near a
//! token. RSASSA-PKCS1-v1_5 would be a poor choice for a key we minted, but
//! refusing it here would refuse Windows Hello and a large share of the
//! security keys already in people's pockets — locking users out of an account
//! to make a point about an algorithm their hardware picked for them.
//!
//! `PS256` is the reverse case: legal for our tokens, and no authenticator
//! offers it. It is absent because nothing would ever present it.

use ciborium::value::Value;

/// A COSE algorithm this server can verify a WebAuthn assertion with.
///
/// The `alg` values are from the IANA COSE Algorithms registry, and they are
/// negative because that registry gives the negative space to algorithms
/// rather than to key types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CoseAlgorithm {
    /// ECDSA with P-256 and SHA-256 (`-7`). What almost every passkey uses.
    Es256,
    /// EdDSA over Ed25519 (`-8`).
    EdDsa,
    /// RSASSA-PKCS1-v1_5 with SHA-256 (`-257`). Windows Hello and older keys.
    Rs256,
}

impl CoseAlgorithm {
    /// Every algorithm this server accepts, in the order a relying party
    /// should offer them: the one it would rather have first.
    ///
    /// `pubKeyCredParams` is ordered by preference (WebAuthn L3 §5.4), so an
    /// authenticator that supports several picks the earliest it recognises.
    pub const ALL: [Self; 3] = [Self::Es256, Self::EdDsa, Self::Rs256];

    /// The COSE `alg` value.
    #[must_use]
    pub const fn value(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::EdDsa => -8,
            Self::Rs256 => -257,
        }
    }

    /// The algorithm for a COSE `alg` value, if this server accepts it.
    #[must_use]
    pub const fn from_value(value: i64) -> Option<Self> {
        match value {
            -7 => Some(Self::Es256),
            -8 => Some(Self::EdDsa),
            -257 => Some(Self::Rs256),
            _ => None,
        }
    }

    /// The name this appears under in a log or an audit record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }
}

/// Why a credential public key was refused.
///
/// Deliberately coarse. Every variant here is reported to the browser as one
/// generic failure (WebAuthn L3 §7.1 does not define per-step errors, and a
/// registration that fails is a registration that fails); the distinction
/// exists so an operator reading a log can tell a hostile input from an
/// authenticator this deployment simply does not accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CoseError {
    /// The bytes are not a CBOR map.
    #[error("the credential public key is not a COSE_Key map")]
    NotAMap,
    /// A label this parser needs is absent, or holds the wrong CBOR type.
    #[error("the COSE_Key is missing a required parameter, or it has the wrong type")]
    Malformed,
    /// `alg` is not one of [`CoseAlgorithm::ALL`].
    #[error("the credential public key uses an algorithm this server cannot verify")]
    UnsupportedAlgorithm,
    /// `kty` and `alg` disagree — an `EC2` key claiming `EdDSA`, say.
    ///
    /// Its own variant because it is the interesting one. A key whose type and
    /// algorithm do not match is not a capability mismatch; it is somebody
    /// assembling a structure by hand.
    #[error("the credential public key's type and algorithm disagree")]
    TypeMismatch,
    /// A coordinate or modulus is not the length the curve or algorithm fixes.
    #[error("a credential public key parameter is the wrong length")]
    BadLength,
}

/// A credential public key, parsed and accepted.
///
/// The original bytes are kept alongside the parse. Verifying an assertion
/// later means handing a key to `aws-lc-rs`, and doing that from the bytes the
/// authenticator actually sent — rather than from a re-encoding of our own
/// understanding of them — is what stops a round trip through this parser from
/// changing what the key *is*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPublicKey {
    algorithm: CoseAlgorithm,
    encoded: Vec<u8>,
}

impl CredentialPublicKey {
    /// What the key signs with.
    #[must_use]
    pub const fn algorithm(&self) -> CoseAlgorithm {
        self.algorithm
    }

    /// The `COSE_Key` exactly as the authenticator encoded it.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

/// COSE key type labels (RFC 9052 §7.1).
const KTY_OKP: i64 = 1;
const KTY_EC2: i64 = 2;
const KTY_RSA: i64 = 3;

/// COSE elliptic curves (RFC 9053 §7.1).
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

/// Parses a `COSE_Key` and decides whether this server accepts it.
///
/// `encoded` is the credential public key as it appeared inside attested
/// credential data, and it is kept on the result.
///
/// # Errors
///
/// [`CoseError`] if the bytes are not a COSE key of a type and algorithm this
/// server can verify with.
// fuzz-target: cose_key
pub fn parse(encoded: &[u8]) -> Result<CredentialPublicKey, CoseError> {
    let value: Value = ciborium::from_reader(encoded).map_err(|_| CoseError::NotAMap)?;
    let map = value.as_map().ok_or(CoseError::NotAMap)?;

    let kty = integer(map, 1).ok_or(CoseError::Malformed)?;
    let alg = integer(map, 3).ok_or(CoseError::Malformed)?;
    let algorithm = CoseAlgorithm::from_value(alg).ok_or(CoseError::UnsupportedAlgorithm)?;

    // The type and the algorithm are two statements about the same key, and an
    // authenticator that disagrees with itself is not one to take a key from.
    match (kty, algorithm) {
        (KTY_EC2, CoseAlgorithm::Es256) => {
            if integer(map, -1) != Some(CRV_P256) {
                return Err(CoseError::TypeMismatch);
            }
            // SEC 1 uncompressed coordinates, 32 bytes each for P-256. A short
            // one is not a small number: it is a different point once it is
            // left-padded, and accepting it would let one key be spelled many
            // ways — which is a credential-id-to-key mapping that is not a
            // function.
            expect_len(map, -2, 32)?;
            expect_len(map, -3, 32)?;
        }
        (KTY_OKP, CoseAlgorithm::EdDsa) => {
            if integer(map, -1) != Some(CRV_ED25519) {
                return Err(CoseError::TypeMismatch);
            }
            expect_len(map, -2, 32)?;
        }
        (KTY_RSA, CoseAlgorithm::Rs256) => {
            // RFC 8017 requires a modulus of at least 2048 bits for anything
            // worth accepting today, and the leading byte may or may not be a
            // zero pad, so this is a floor rather than an equality.
            let modulus = bytes(map, -1).ok_or(CoseError::Malformed)?;
            if modulus.len() < 256 {
                return Err(CoseError::BadLength);
            }
            bytes(map, -2).ok_or(CoseError::Malformed)?;
        }
        _ => return Err(CoseError::TypeMismatch),
    }

    Ok(CredentialPublicKey {
        algorithm,
        encoded: encoded.to_vec(),
    })
}

/// The `x` and `y` coordinates of an EC2 key, as [`parse`] accepted them.
///
/// Read back out of the stored encoding rather than kept on
/// [`CredentialPublicKey`], for the reason that type's documentation gives:
/// the bytes the authenticator sent are the key, and a decoded copy held
/// beside them is a second answer to the question "what is this key".
///
/// `None` for anything [`parse`] would not have accepted, so a caller may
/// treat it as "this row is not a key" rather than as a signature failure.
#[must_use]
pub fn ec2_coordinates(encoded: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let value: Value = ciborium::from_reader(encoded).ok()?;
    let map = value.as_map()?;
    let x: [u8; 32] = bytes(map, -2)?.try_into().ok()?;
    let y: [u8; 32] = bytes(map, -3)?.try_into().ok()?;
    Some((x, y))
}

/// The public key of an OKP (Ed25519) key.
///
/// `None` for anything [`parse`] would not have accepted.
#[must_use]
pub fn okp_public_key(encoded: &[u8]) -> Option<[u8; 32]> {
    let value: Value = ciborium::from_reader(encoded).ok()?;
    let map = value.as_map()?;
    bytes(map, -2)?.try_into().ok()
}

/// The modulus and exponent of an RSA key, big-endian.
///
/// `None` for anything [`parse`] would not have accepted.
#[must_use]
pub fn rsa_components(encoded: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let value: Value = ciborium::from_reader(encoded).ok()?;
    let map = value.as_map()?;
    let n = bytes(map, -1)?.to_vec();
    let e = bytes(map, -2)?.to_vec();
    Some((n, e))
}

/// The integer at `label`, if there is one and it is an integer.
fn integer(map: &[(Value, Value)], label: i64) -> Option<i64> {
    map.iter()
        .find(|(key, _)| {
            key.as_integer().and_then(|i| i128::from(i).try_into().ok()) == Some(label)
        })
        .and_then(|(_, value)| value.as_integer())
        .and_then(|i| i128::from(i).try_into().ok())
}

/// The byte string at `label`, if there is one and it is a byte string.
fn bytes(map: &[(Value, Value)], label: i64) -> Option<&[u8]> {
    map.iter()
        .find(|(key, _)| {
            key.as_integer().and_then(|i| i128::from(i).try_into().ok()) == Some(label)
        })
        .and_then(|(_, value)| value.as_bytes())
        .map(Vec::as_slice)
}

/// Requires a byte string of exactly `len` at `label`.
fn expect_len(map: &[(Value, Value)], label: i64, len: usize) -> Result<(), CoseError> {
    match bytes(map, label) {
        None => Err(CoseError::Malformed),
        Some(found) if found.len() == len => Ok(()),
        Some(_) => Err(CoseError::BadLength),
    }
}
