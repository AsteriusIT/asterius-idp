//! The key-encryption key: how a private signing key survives being written
//! down.
//!
//! A signing key in `signing_keys.private_key_ciphertext` is one database
//! backup away from being someone else's. FAPI 2.0 SP §6.8 ("Key Compromise")
//! is about limiting the blast radius when that happens; encrypting the private
//! half under a key that does *not* live in the database is what makes a leaked
//! dump useless on its own.
//!
//! [`Kek`] is the port. It is a trait rather than a concrete type because the
//! interesting implementations are outside this process — AWS KMS, GCP KMS,
//! Azure Key Vault, a PKCS#11 HSM — and those are network calls, which is why
//! it is `async` even though the local implementation never awaits anything.
//! [`LocalKek`] is the one implementation there is today: a 256-bit key read
//! from a file or an environment variable, for development and for single-box
//! deployments that have nowhere better to put it.
//!
//! The trait lives here and not in `asterius-domain` on purpose. No protocol
//! crate ever reaches a KEK: it is an implementation detail of *storing* a key,
//! sitting between the key repository and the cryptography, and the envelope it
//! produces is a JOSE-shaped thing. `asterius-domain` declares ports for what
//! protocol code depends on, and this is not that.
//!
//! # Nonces
//!
//! AES-256-GCM loses everything — confidentiality *and* authenticity — if one
//! nonce is used twice under one key (NIST SP 800-38D §8 states the uniqueness
//! requirement; Appendix A explains what breaks). Three things prevent it here,
//! and none of them is "we remembered to":
//!
//! 1. **There is no way to supply one.** [`LocalKek`] seals through
//!    aws-lc-rs's [`RandomizedNonceKey`], whose sealing operation takes no
//!    nonce argument: the provider draws a fresh 96-bit nonce from its RBG and
//!    returns the one it used. Our code physically cannot pass a nonce in, so
//!    it cannot pass the same one twice.
//! 2. **96 bits, from an RBG.** That is the RBG-based construction of
//!    SP 800-38D §8.2.2 at the recommended IV length (§5.2.1.1), whose
//!    accompanying bound (§8.3) is 2^32 sealings under one key. A KEK seals
//!    once per key rotation per tenant; a deployment reaching 2^32 rotations
//!    has other problems.
//! 3. **The database refuses a repeat anyway.** `signing_keys` carries a unique
//!    index on `(kek_id, private_key_nonce)`, so even a compromised RBG cannot
//!    quietly produce two rows under one nonce — the second insert fails.
//!
//! Nothing re-seals in place, either: rotation writes a new row rather than
//! updating one, so a given plaintext is sealed exactly once.
//!
//! # Binding
//!
//! The ciphertext is bound to the row it belongs in — tenant, `kid`, purpose
//! and algorithm — as additional authenticated data. Moving a row to another
//! tenant, relabelling a signing key as an encryption key, or pairing a
//! ciphertext with a different public key all produce a decryption failure
//! rather than a working key in the wrong place. See [`KeyBinding`].
//!
//! # What else is sealed here
//!
//! Not only key pairs. A [`TenantSecret`] is a secret a tenant holds exactly
//! one of and never rotates — today that is the pairwise salt, which is the
//! only thing standing between a leaked database and every `sub` in the tenant
//! being derivable by anyone who knows the algorithm (OIDC Core §8.1: a
//! pairwise Subject Identifier "MUST NOT be reversible by any party other than
//! the OpenID Provider"). It is key material in every sense that matters to
//! storage, so it is sealed through the same port, with the same key binding
//! discipline, rather than sitting in a settings column as configuration.

mod composite;

pub use composite::CompositeKek;

use crate::JoseError;
use asterius_domain::keys::{KeyPurpose, SigningAlgorithm};
use asterius_domain::{Kid, TenantId};
use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey};
use aws_lc_rs::hkdf;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use std::fmt;
use zeroize::Zeroizing;

/// The size of a key-encryption key, in bytes. AES-256.
pub const KEK_LEN: usize = 32;

/// The nonce length AES-GCM is used with here: 96 bits, per NIST SP 800-38D
/// §5.2.1.1's recommendation that implementations restrict support to it.
pub const NONCE_LEN: usize = 12;

/// The GCM authentication tag length, in bytes.
const TAG_LEN: usize = 16;

/// A tenant-wide secret that is not a key pair.
///
/// A signing key is identified by its own thumbprint, so [`KeyBinding::new`]
/// has a `kid` to bind. A tenant secret has no such identity — there is exactly
/// one of each per tenant, forever — so what distinguishes two of them is which
/// secret they are, and that is what this enum names. Adding a variant is how a
/// future tenant secret gets its own binding rather than borrowing this one:
/// two secrets sharing a binding would be interchangeable ciphertexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TenantSecret {
    /// The per-tenant pairwise salt, the input to every `sub` the tenant
    /// derives (OIDC Core §8.1).
    PairwiseSalt,
}

impl TenantSecret {
    /// Every secret this enum names, so a test can be exhaustive over them.
    pub const ALL: [Self; 1] = [Self::PairwiseSalt];

    /// The value that goes into the additional authenticated data.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PairwiseSalt => "pairwise-salt",
        }
    }
}

impl fmt::Display for TenantSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a piece of wrapped material is allowed to be.
///
/// This is the additional authenticated data. AES-GCM does not encrypt it, it
/// authenticates it: decryption succeeds only if the caller supplies exactly
/// the same binding that sealing did. So a ciphertext is not merely "a private
/// key", it is "the private key of *this* tenant, under *this* `kid`, for
/// *this* purpose and algorithm" — and a row edited to say anything else stops
/// decrypting.
///
/// That matters most for the purpose field. FAPI 2.0 SP §6.8 item 2 wants
/// single-purpose keys; binding the purpose into the ciphertext means a
/// signing key cannot be relabelled as an encryption key by an `UPDATE`.
///
/// Two shapes of binding exist, because two shapes of material are stored. A
/// private key ([`KeyBinding::new`]) is one row of `signing_keys` and is
/// identified by its `kid`; a tenant secret ([`KeyBinding::tenant_secret`]) is
/// the one row its tenant will ever have, and is identified by *which* secret
/// it is. They are kept apart by their labels rather than by field count, so
/// that no amount of choosing tenant ids, `kid`s or secret names can make one
/// encode to the bytes of the other — see [`KeyBinding::aad`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBinding<'a> {
    tenant: &'a TenantId,
    material: Material<'a>,
}

/// Which of the two binding shapes a [`KeyBinding`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Material<'a> {
    /// One row of `signing_keys`.
    PrivateKey {
        kid: &'a Kid,
        purpose: KeyPurpose,
        algorithm: SigningAlgorithm,
    },
    /// A secret a tenant holds exactly one of.
    TenantSecret(TenantSecret),
    /// A secret belonging to one row that a tenant has many of.
    ///
    /// Identified by *which* kind of secret and by the row's own identifier,
    /// so two rows of the same kind seal under different additional
    /// authenticated data.
    RowSecret { kind: RowSecret, row: &'a str },
}

/// A secret a tenant may hold many of, one per row.
///
/// Separate from [`TenantSecret`] because the binding needs a row identifier
/// as well as a tenant: "the tenant's pairwise salt" names a row on its own,
/// "an SSF push credential" does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RowSecret {
    /// The `authorization_header` a push receiver registered for one stream
    /// (RFC 8935 §2.2; SSF 1.0 §6.1.1). The row is the `stream_id`.
    SsfPushAuthorization,
    /// What a CIBA Core 1.0 §10.2 ping notification presents: the
    /// `auth_req_id` it carries in its body and the `client_notification_token`
    /// it carries as a bearer, sealed together for one backchannel
    /// authentication request. The row is the hex digest of the `auth_req_id`.
    CibaPing,
}

impl RowSecret {
    /// Every secret this enum names, so a test can be exhaustive over them.
    pub const ALL: [Self; 2] = [Self::SsfPushAuthorization, Self::CibaPing];

    /// The value that goes into the additional authenticated data.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SsfPushAuthorization => "ssf-push-authorization",
            Self::CibaPing => "ciba-ping",
        }
    }
}

impl fmt::Display for RowSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The label for a private key envelope. Unchanged since the first ciphertext
/// was written: changing it would make every stored signing key unopenable.
const KEY_LABEL: &[u8] = b"asterius.kek.v1";

/// The label for a per-row secret envelope.
///
/// A third space beside the two below, chosen so that no label is a prefix of
/// another: a reader of an envelope never has to guess which field layout
/// produced it, because a mismatched guess fails to authenticate.
const ROW_SECRET_LABEL: &[u8] = b"asterius.kek.row-secret.v1";

/// The label for a tenant secret envelope.
///
/// It differs from [`KEY_LABEL`] at byte 13 — `t` against `v`, both labels
/// being longer than that — so neither label is a prefix of the other and no
/// suffix can reconcile them. That is what makes the two field layouts safe to
/// use under one AEAD: the reader of an envelope never has to guess which
/// layout produced it, because a mismatched guess fails to authenticate.
const TENANT_SECRET_LABEL: &[u8] = b"asterius.kek.tenant-secret.v1";

impl<'a> KeyBinding<'a> {
    /// Binds a private key to the row it belongs in.
    #[must_use]
    pub const fn new(
        tenant: &'a TenantId,
        kid: &'a Kid,
        purpose: KeyPurpose,
        algorithm: SigningAlgorithm,
    ) -> Self {
        Self {
            tenant,
            material: Material::PrivateKey {
                kid,
                purpose,
                algorithm,
            },
        }
    }

    /// Binds a per-row secret to the tenant and the row that own it.
    ///
    /// The row is the point. An SSF push credential sealed for one stream and
    /// pasted into another stream's row would otherwise be presented to that
    /// stream's endpoint — a receiver would be handed another receiver's
    /// credential by a single `UPDATE`. With the identifier in the additional
    /// authenticated data the copy does not decrypt, so the delivery fails
    /// loudly instead of leaking.
    #[must_use]
    pub const fn row_secret(tenant: &'a TenantId, kind: RowSecret, row: &'a str) -> Self {
        Self {
            tenant,
            material: Material::RowSecret { kind, row },
        }
    }

    /// Binds a tenant-wide secret to the tenant that owns it.
    ///
    /// The tenant is the whole point. A pairwise salt copied from one tenant's
    /// row into another's would give both tenants one salt, and two tenants
    /// with one salt is two tenants whose `sub` values can be correlated by
    /// anyone holding it — the exact property pairwise subjects exist to deny
    /// (OIDC Core §8.1). Binding the tenant into the ciphertext makes the copy
    /// undecryptable instead of useful.
    #[must_use]
    pub const fn tenant_secret(tenant: &'a TenantId, secret: TenantSecret) -> Self {
        Self {
            tenant,
            material: Material::TenantSecret(secret),
        }
    }

    /// Names the row this binding belongs to, for a log line.
    ///
    /// Identifiers only, and every one of them is already public or already in
    /// a log: the tenant id is in the issuer URL, a `kid` is published in the
    /// JWK Set, and the purpose, algorithm and secret name are compiled-in
    /// constants. Nothing here is derived from the plaintext, which is what
    /// makes this safe to hand to `tracing` — see [`CompositeKek`], the one
    /// caller, which logs it when a row opens only under the previous KEK.
    #[must_use]
    pub fn row(&self) -> String {
        let tenant = self.tenant.as_str();
        match self.material {
            Material::PrivateKey {
                kid,
                purpose,
                algorithm,
            } => format!(
                "signing_keys[tenant={tenant}, kid={}, purpose={purpose}, alg={algorithm}]",
                kid.as_str()
            ),
            Material::TenantSecret(secret) => {
                format!("tenant_secret[tenant={tenant}, secret={secret}]")
            }
            // The row identifier is a `stream_id` — 128 bits this server drew
            // and handed to the receiver in a URL — so it is an identifier
            // like a `kid` and not derived from the plaintext.
            Material::RowSecret { kind, row } => {
                format!("row_secret[tenant={tenant}, secret={kind}, row={row}]")
            }
        }
    }

    /// The additional authenticated data this binding encodes.
    ///
    /// Length-prefixed, not delimited. Concatenating `tenant ‖ kid` with a
    /// separator would let `("a", "b:c")` and `("a:b", "c")` produce the same
    /// bytes, and an encoding where two different bindings collide is an
    /// encoding that authenticates neither. The leading label is domain
    /// separation: a future envelope format changes it rather than silently
    /// reinterpreting old ciphertexts, and the two labels here keep the
    /// private-key layout and the tenant-secret layout in separate spaces.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let tenant = self.tenant.as_str().as_bytes();
        match self.material {
            Material::PrivateKey {
                kid,
                purpose,
                algorithm,
            } => encode(
                KEY_LABEL,
                &[
                    tenant,
                    kid.as_str().as_bytes(),
                    purpose.as_str().as_bytes(),
                    algorithm.as_str().as_bytes(),
                ],
            ),
            Material::TenantSecret(secret) => {
                encode(TENANT_SECRET_LABEL, &[tenant, secret.as_str().as_bytes()])
            }
            Material::RowSecret { kind, row } => encode(
                ROW_SECRET_LABEL,
                &[tenant, kind.as_str().as_bytes(), row.as_bytes()],
            ),
        }
    }
}

/// A label followed by length-prefixed fields.
fn encode(label: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(label.len() + fields.iter().map(|f| f.len() + 4).sum::<usize>());
    aad.extend_from_slice(label);
    for field in fields {
        // A 32-bit length is more than any of these can reach: a tenant id is
        // capped at 64 bytes, a `kid` is a base64url SHA-256, and the rest are
        // compiled-in constants.
        let length = u32::try_from(field.len()).unwrap_or(u32::MAX);
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(field);
    }
    aad
}

/// Sealed material as it is stored: ciphertext, the nonce it was sealed under,
/// and which key-encryption key sealed it.
///
/// Every field goes into a column — `signing_keys` for a private key,
/// `tenant_pairwise_salts` for a salt. None of them is secret — that is the
/// point of the exercise — but the ciphertext is the whole plaintext, so this
/// type deliberately has no `Display` and its `Debug` prints lengths rather
/// than bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedKey {
    kek_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl WrappedKey {
    /// Rebuilds a wrapped secret from the three stored columns.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::Unwrap`] if the nonce is not [`NONCE_LEN`] bytes or
    /// the ciphertext is too short to carry an authentication tag. Both are
    /// checked here rather than at the AEAD, so a truncated row is rejected as
    /// malformed instead of as a decryption failure.
    pub fn from_parts(
        kek_id: impl Into<String>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Self, JoseError> {
        if nonce.len() != NONCE_LEN || ciphertext.len() <= TAG_LEN {
            return Err(JoseError::Unwrap);
        }
        Ok(Self {
            kek_id: kek_id.into(),
            nonce,
            ciphertext,
        })
    }

    /// Which key-encryption key sealed this.
    #[must_use]
    pub fn kek_id(&self) -> &str {
        &self.kek_id
    }

    /// The nonce, for the `private_key_nonce` column.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// The ciphertext with its authentication tag, for the
    /// `private_key_ciphertext` column.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Lengths, never bytes. A ciphertext in a bug report is not a
        // catastrophe on its own, but it is one KEK leak away from being one.
        f.debug_struct("WrappedKey")
            .field("kek_id", &self.kek_id)
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// A key-encryption key: the thing that is not in the database.
///
/// Implementations wrap and unwrap private key material. They do not generate,
/// parse or use it — a KEK sees an opaque byte string, which is what lets a
/// cloud KMS implement this without ever being told what a PKCS#8 blob is.
#[async_trait::async_trait]
pub trait Kek: fmt::Debug + Send + Sync {
    /// Identifies this key-encryption key, for the `kek_id` column.
    ///
    /// Stored with every ciphertext so that an operator rotating the KEK can
    /// tell which rows still need re-wrapping, and so that unwrapping under the
    /// wrong KEK is reported as a mismatch rather than as corruption.
    fn id(&self) -> &str;

    /// Encrypts private key material.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::Wrap`] if the provider refuses.
    async fn wrap(
        &self,
        binding: KeyBinding<'_>,
        plaintext: &[u8],
    ) -> Result<WrappedKey, JoseError>;

    /// Decrypts private key material.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::KekMismatch`] if the material was sealed under a
    /// different KEK, or [`JoseError::Unwrap`] if it does not authenticate
    /// under this one and this binding.
    async fn unwrap(
        &self,
        binding: KeyBinding<'_>,
        wrapped: &WrappedKey,
    ) -> Result<Zeroizing<Vec<u8>>, JoseError>;
}

/// A key-encryption key held in this process, read from a file or the
/// environment.
///
/// For development, for tests, and for a single-box deployment whose operator
/// has decided that a root-owned file mode 0400 is the right place for it. A
/// deployment with a KMS should use a KMS adapter instead: the whole value of
/// the port is that the key material can stay somewhere this process cannot
/// read it.
pub struct LocalKek {
    id: String,
    key: RandomizedNonceKey,
}

impl fmt::Debug for LocalKek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The id is derived from the material but does not reveal it; the
        // material itself is never printed, at any verbosity.
        f.debug_struct("LocalKek")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl LocalKek {
    /// The identifier stored alongside every ciphertext this KEK seals.
    ///
    /// Inherent as well as on the trait, so a caller holding a concrete
    /// `LocalKek` does not have to import [`Kek`] to read it.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Builds a KEK from raw key material.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::KekUnavailable`] unless the material is exactly
    /// [`KEK_LEN`] bytes. Shorter material is not stretched and longer material
    /// is not truncated: a KEK that is not 256 bits is a configuration mistake,
    /// and quietly hashing whatever was supplied into 32 bytes would turn a
    /// four-character password into something that looks like a key.
    pub fn from_bytes(material: &[u8]) -> Result<Self, JoseError> {
        if material.len() != KEK_LEN {
            return Err(JoseError::KekUnavailable {
                origin: "supplied material".to_owned(),
                reason: "a key-encryption key must be exactly 32 bytes (AES-256)",
            });
        }
        let key = RandomizedNonceKey::new(&AES_256_GCM, material).map_err(|_| {
            JoseError::KekUnavailable {
                origin: "supplied material".to_owned(),
                reason: "the provider refused the key",
            }
        })?;
        Ok(Self {
            id: derive_id(material),
            key,
        })
    }

    /// Builds a KEK from base64-encoded material, as `openssl rand -base64 32`
    /// prints it.
    ///
    /// Both the standard and the URL-safe alphabets are accepted, with or
    /// without padding, because an operator pasting a key out of a secret
    /// manager should not have to know which one produced it.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::KekUnavailable`] if the text is not base64 or does
    /// not decode to [`KEK_LEN`] bytes.
    pub fn from_base64(origin: &str, encoded: &str) -> Result<Self, JoseError> {
        let material = decode_secret(encoded).map_err(|reason| JoseError::KekUnavailable {
            origin: origin.to_owned(),
            reason,
        })?;
        Self::from_bytes(&material).map_err(|_| JoseError::KekUnavailable {
            origin: origin.to_owned(),
            reason: "did not decode to 32 bytes",
        })
    }

    /// Reads a base64 KEK out of an environment variable.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::KekUnavailable`] if the variable is unset, is not
    /// UTF-8, or does not hold a 32-byte base64 value. Absent is an error, not
    /// a reason to invent a key: a generated-on-boot KEK makes every key
    /// already in the database unreadable, which looks exactly like data loss.
    pub fn from_env(variable: &str) -> Result<Self, JoseError> {
        let material = read_secret_env(variable).map_err(|reason| JoseError::KekUnavailable {
            origin: variable.to_owned(),
            reason,
        })?;
        Self::from_bytes(&material)
    }

    /// Reads a base64 KEK out of a file.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::KekUnavailable`] if the file cannot be read or does
    /// not hold a 32-byte base64 value.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, JoseError> {
        let path = path.as_ref();
        let material = read_secret_file(path).map_err(|reason| JoseError::KekUnavailable {
            origin: path.display().to_string(),
            reason,
        })?;
        Self::from_bytes(&material)
    }

    /// Seals private key material.
    ///
    /// The nonce is not a parameter and never will be: aws-lc-rs draws it from
    /// its RBG inside this call and hands back the one it used. See the module
    /// documentation for why that is the whole nonce-reuse defence.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::Wrap`] if the provider refuses.
    pub fn seal(&self, binding: KeyBinding<'_>, plaintext: &[u8]) -> Result<WrappedKey, JoseError> {
        // Exact capacity, so appending the tag cannot reallocate and leave a
        // copy of the buffer behind on the heap for someone to find later.
        let mut in_out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        in_out.extend_from_slice(plaintext);

        let nonce = self
            .key
            .seal_in_place_append_tag(Aad::from(binding.aad()), &mut in_out)
            .map_err(|_| JoseError::Wrap)?;

        Ok(WrappedKey {
            kek_id: self.id.clone(),
            nonce: nonce.as_ref().to_vec(),
            ciphertext: in_out,
        })
    }

    /// Opens sealed private key material.
    ///
    /// Everything this reads comes out of a database row, which is exactly the
    /// place an attacker with SQL access edits. The AEAD is what makes that
    /// pointless: a row whose ciphertext, nonce, or binding has been touched
    /// fails to authenticate, and there is no partial result to act on.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::KekMismatch`] if the row names a different KEK, or
    /// [`JoseError::Unwrap`] if the bytes do not authenticate. Which of the
    /// several possible reasons applies is deliberately not reported.
    // fuzz-target: kek_unwrap
    pub fn open(
        &self,
        binding: KeyBinding<'_>,
        wrapped: &WrappedKey,
    ) -> Result<Zeroizing<Vec<u8>>, JoseError> {
        if wrapped.kek_id != self.id {
            return Err(JoseError::KekMismatch {
                stored: wrapped.kek_id.clone(),
                available: self.id.clone(),
            });
        }

        let nonce_bytes: [u8; NONCE_LEN] = wrapped
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| JoseError::Unwrap)?;

        let mut in_out = Zeroizing::new(wrapped.ciphertext.clone());
        let plaintext = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(binding.aad()),
                in_out.as_mut_slice(),
            )
            .map_err(|_| JoseError::Unwrap)?;

        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}

/// Derives the stored `kek_id` from the key material.
///
/// Derived rather than configured, so that changing the key changes the id
/// without anyone having to remember to. An operator who swaps the file and
/// keeps the name gets "these rows were wrapped under a different KEK" instead
/// of "cannot decrypt", which is the difference between a five-minute fix and
/// an outage postmortem.
///
/// It is an HKDF output rather than a plain hash of the key so that publishing
/// the id — it goes in a database column, and into log lines — reveals nothing
/// about the key beyond what a 64-bit tag of it must.
fn derive_id(material: &[u8]) -> String {
    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    let mut tag = [0_u8; 8];
    let derived = hkdf::Salt::new(hkdf::HKDF_SHA256, b"asterius.kek.id.v1")
        .extract(material)
        .expand(&[b"kek-id"], Len(tag.len()))
        .and_then(|okm| okm.fill(&mut tag));
    // HKDF cannot fail for a fixed 8-byte output; if the provider ever says
    // otherwise, an id nothing will match is better than a panic in a
    // constructor that runs at boot.
    if derived.is_err() {
        return "local:unavailable".to_owned();
    }
    format!("local:{}", B64.encode(tag))
}

#[async_trait::async_trait]
impl Kek for LocalKek {
    fn id(&self) -> &str {
        Self::id(self)
    }

    async fn wrap(
        &self,
        binding: KeyBinding<'_>,
        plaintext: &[u8],
    ) -> Result<WrappedKey, JoseError> {
        self.seal(binding, plaintext)
    }

    async fn unwrap(
        &self,
        binding: KeyBinding<'_>,
        wrapped: &WrappedKey,
    ) -> Result<Zeroizing<Vec<u8>>, JoseError> {
        self.open(binding, wrapped)
    }
}

// ---------------------------------------------------------------------------
// The secret parser, shared with the other secrets an operator supplies
// ---------------------------------------------------------------------------

/// Decodes a base64 32-byte secret, as `head -c 32 /dev/urandom | base64`
/// prints it.
///
/// The KEK's own parser, factored out so that a second secret an operator
/// supplies the same way — the shared DPoP nonce key, `ast-a05.11` — is read by
/// this code rather than by a second decoder with its own idea of what may be
/// pasted. Both alphabets, padded or not, surrounding whitespace trimmed: the
/// value comes out of a secret manager and which one produced it is not
/// something the operator should have to know.
///
/// The length is exact for the reason [`LocalKek::from_bytes`] is exact:
/// stretching short material would turn a four-character password into
/// something that looks like a key.
///
/// # Errors
///
/// Returns the reason, for the caller to attach to whatever names the origin —
/// a configuration key, a path, a variable. Only the caller knows what to call
/// it, and the origin is the half of the message that makes it actionable.
pub fn decode_secret(encoded: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let trimmed = encoded.trim();
    let material = B64
        .decode(trimmed)
        .or_else(|_| B64_STANDARD.decode(trimmed))
        .map(Zeroizing::new)
        .map_err(|_| "not valid base64")?;
    if material.len() != KEK_LEN {
        return Err("did not decode to 32 bytes");
    }
    Ok(material)
}

/// Reads a base64 32-byte secret out of an environment variable.
///
/// # Errors
///
/// Returns the reason. See [`decode_secret`] for why it is not an error type.
pub fn read_secret_env(variable: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let value = std::env::var(variable)
        .map(Zeroizing::new)
        .map_err(|_| "environment variable is unset or not UTF-8")?;
    decode_secret(&value)
}

/// Reads a base64 32-byte secret out of a file.
///
/// # Errors
///
/// Returns the reason. See [`decode_secret`] for why it is not an error type.
pub fn read_secret_file(
    path: impl AsRef<std::path::Path>,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let contents = std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|_| "cannot be read")?;
    decode_secret(&contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningKey;

    const A_KEK: [u8; KEK_LEN] = [0x42; KEK_LEN];
    const ANOTHER_KEK: [u8; KEK_LEN] = [0x43; KEK_LEN];

    fn kek() -> LocalKek {
        LocalKek::from_bytes(&A_KEK).expect("a 32-byte key is a valid KEK")
    }

    fn tenant() -> TenantId {
        TenantId::new("demo")
    }

    fn kid() -> Kid {
        Kid::new("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    }

    fn binding<'a>(tenant: &'a TenantId, kid: &'a Kid) -> KeyBinding<'a> {
        KeyBinding::new(tenant, kid, KeyPurpose::Signing, SigningAlgorithm::EdDsa)
    }

    #[test]
    fn a_private_key_survives_the_round_trip_through_its_ciphertext() {
        for algorithm in SigningAlgorithm::ALL {
            let key = SigningKey::generate(algorithm).expect("generate");
            let kek = kek();
            let (tenant, kid) = (tenant(), kid());
            let binding = KeyBinding::new(&tenant, &kid, KeyPurpose::Signing, algorithm);

            let wrapped = kek.seal(binding, key.pkcs8()).expect("seal");
            let opened = kek.open(binding, &wrapped).expect("open");
            assert_eq!(opened.as_slice(), key.pkcs8());

            // And the recovered bytes are still the key they came from.
            let restored = SigningKey::from_pkcs8(algorithm, &opened).expect("import");
            let signature = restored.sign(b"payload").expect("sign");
            key.verifying_key()
                .expect("public key")
                .verify(b"payload", &signature)
                .expect("the unwrapped key must be the key that was wrapped");
        }
    }

    /// The property the `private_key_ciphertext` column exists for: what is
    /// written down is not the key.
    #[test]
    fn the_ciphertext_does_not_contain_the_key_it_encrypts() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let (tenant, kid) = (tenant(), kid());
        let wrapped = kek()
            .seal(binding(&tenant, &kid), key.pkcs8())
            .expect("seal");

        assert_ne!(wrapped.ciphertext(), key.pkcs8());
        // Not even a window of it: the smallest run worth protecting is the
        // 32-byte Ed25519 seed.
        for window in key.pkcs8().windows(16) {
            assert!(
                !wrapped
                    .ciphertext()
                    .windows(16)
                    .any(|candidate| candidate == window),
                "a 16-byte run of the private key appears verbatim in the ciphertext"
            );
        }
        // The ciphertext carries the GCM tag on top of the plaintext.
        assert_eq!(wrapped.ciphertext().len(), key.pkcs8().len() + TAG_LEN);
    }

    /// NIST SP 800-38D §8: a nonce must never repeat under one key. The
    /// provider draws it, and this asserts that it actually varies — a
    /// constant nonce would pass every round-trip test in this file.
    #[test]
    fn every_sealing_uses_a_fresh_nonce() {
        let kek = kek();
        let (tenant, kid) = (tenant(), kid());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let wrapped = kek
                .seal(binding(&tenant, &kid), b"the same plaintext every time")
                .expect("seal");
            assert_eq!(wrapped.nonce().len(), NONCE_LEN);
            assert!(
                seen.insert(wrapped.nonce().to_vec()),
                "a nonce repeated under one key-encryption key"
            );
        }
    }

    /// Sealing the same plaintext twice must not produce the same ciphertext,
    /// or an observer of the table could tell which tenants share a key.
    #[test]
    fn sealing_the_same_bytes_twice_produces_different_ciphertext() {
        let kek = kek();
        let (tenant, kid) = (tenant(), kid());
        let first = kek.seal(binding(&tenant, &kid), b"payload").expect("seal");
        let second = kek.seal(binding(&tenant, &kid), b"payload").expect("seal");
        assert_ne!(first.ciphertext(), second.ciphertext());
    }

    /// Every byte of the stored row is authenticated, so an attacker with an
    /// `UPDATE` cannot substitute a private key of their choosing.
    #[test]
    fn altering_any_byte_of_the_stored_row_makes_it_unopenable() {
        let kek = kek();
        let (tenant, kid) = (tenant(), kid());
        let wrapped = kek
            .seal(binding(&tenant, &kid), b"private key material")
            .expect("seal");

        for index in 0..wrapped.ciphertext().len() {
            let mut tampered = wrapped.ciphertext().to_vec();
            tampered[index] ^= 0x01;
            let row = WrappedKey::from_parts(wrapped.kek_id(), wrapped.nonce().to_vec(), tampered)
                .expect("still well-formed");
            assert!(
                kek.open(binding(&tenant, &kid), &row).is_err(),
                "byte {index} of the ciphertext could be changed"
            );
        }

        for index in 0..NONCE_LEN {
            let mut tampered = wrapped.nonce().to_vec();
            tampered[index] ^= 0x01;
            let row =
                WrappedKey::from_parts(wrapped.kek_id(), tampered, wrapped.ciphertext().to_vec())
                    .expect("still well-formed");
            assert!(
                kek.open(binding(&tenant, &kid), &row).is_err(),
                "byte {index} of the nonce could be changed"
            );
        }
    }

    /// The binding is the reason a ciphertext cannot be moved. Each field of it
    /// must matter on its own.
    #[test]
    fn a_ciphertext_moved_to_another_row_does_not_open() {
        let kek = kek();
        let (alpha, beta) = (TenantId::new("alpha"), TenantId::new("beta"));
        let (mine, theirs) = (kid(), Kid::new("a-different-thumbprint"));
        let sealed = kek
            .seal(
                KeyBinding::new(&alpha, &mine, KeyPurpose::Signing, SigningAlgorithm::EdDsa),
                b"alpha's signing key",
            )
            .expect("seal");

        for (label, wrong) in [
            (
                "another tenant",
                KeyBinding::new(&beta, &mine, KeyPurpose::Signing, SigningAlgorithm::EdDsa),
            ),
            (
                "another kid",
                KeyBinding::new(
                    &alpha,
                    &theirs,
                    KeyPurpose::Signing,
                    SigningAlgorithm::EdDsa,
                ),
            ),
            (
                "the other purpose",
                KeyBinding::new(
                    &alpha,
                    &mine,
                    KeyPurpose::Encryption,
                    SigningAlgorithm::EdDsa,
                ),
            ),
            (
                "another algorithm",
                KeyBinding::new(&alpha, &mine, KeyPurpose::Signing, SigningAlgorithm::Es256),
            ),
        ] {
            assert!(
                matches!(kek.open(wrong, &sealed), Err(JoseError::Unwrap)),
                "a ciphertext opened under the binding of {label}"
            );
        }
    }

    /// An encoding where two different bindings produce the same bytes
    /// authenticates neither of them.
    #[test]
    fn two_different_bindings_never_encode_to_the_same_bytes() {
        let tenants = [
            TenantId::new("a"),
            TenantId::new("ab"),
            TenantId::new("a-b"),
        ];
        let kids = [Kid::new("b"), Kid::new("-b"), Kid::new("")];
        let mut seen = std::collections::HashSet::new();
        for tenant in &tenants {
            for kid in &kids {
                for purpose in KeyPurpose::ALL {
                    for algorithm in SigningAlgorithm::ALL {
                        let aad = KeyBinding::new(tenant, kid, purpose, algorithm).aad();
                        assert!(
                            seen.insert(aad),
                            "{tenant}/{kid}/{purpose}/{algorithm} collides with another binding"
                        );
                    }
                }
            }
        }
    }

    /// A tenant secret is bound to its tenant and to *which* secret it is. The
    /// tenant half is what stops a pairwise salt being copied from one tenant's
    /// row into another's — two tenants sharing a salt is two tenants whose
    /// `sub` values correlate, which is the one thing pairwise subjects exist
    /// to prevent (OIDC Core §8.1).
    #[test]
    fn a_tenant_secret_does_not_open_for_another_tenant() {
        let kek = kek();
        let (alpha, beta) = (TenantId::new("alpha"), TenantId::new("beta"));
        let mine = KeyBinding::tenant_secret(&alpha, TenantSecret::PairwiseSalt);
        let sealed = kek.seal(mine, &[0x5c; 32]).expect("seal");

        assert_eq!(
            kek.open(mine, &sealed).expect("open").as_slice(),
            &[0x5c; 32]
        );
        assert!(
            matches!(
                kek.open(
                    KeyBinding::tenant_secret(&beta, TenantSecret::PairwiseSalt),
                    &sealed
                ),
                Err(JoseError::Unwrap)
            ),
            "a tenant secret opened under another tenant's binding"
        );
    }

    /// The three binding shapes have different field counts, so they must not
    /// share an encoding space: a tenant secret must never be openable as a
    /// private key, nor a row secret as either, whatever the tenant id, `kid`,
    /// secret name or row identifier happens to be. The labels are what
    /// separate them, and they diverge inside the constant rather than relying
    /// on what follows.
    #[test]
    fn a_key_binding_and_a_tenant_secret_binding_never_collide() {
        // No label is a prefix of another.
        for (left, right) in [
            (KEY_LABEL, TENANT_SECRET_LABEL),
            (KEY_LABEL, ROW_SECRET_LABEL),
            (TENANT_SECRET_LABEL, ROW_SECRET_LABEL),
        ] {
            let at = left
                .iter()
                .zip(right)
                .position(|(a, b)| a != b)
                .expect("the labels must differ");
            assert!(at < left.len() && at < right.len());
        }

        // And exhaustively, over values chosen to be confusable.
        let tenants = [
            TenantId::new("a"),
            TenantId::new("ab"),
            TenantId::new("pairwise-salt"),
        ];
        let kids = [Kid::new(""), Kid::new("pairwise-salt"), Kid::new("sig")];
        let rows = ["", "sig", "ssf-push-authorization"];
        let mut seen = std::collections::HashSet::new();
        for tenant in &tenants {
            for secret in TenantSecret::ALL {
                assert!(
                    seen.insert(KeyBinding::tenant_secret(tenant, secret).aad()),
                    "{tenant}/{secret} collides with another binding"
                );
            }
            for kind in RowSecret::ALL {
                for row in rows {
                    assert!(
                        seen.insert(KeyBinding::row_secret(tenant, kind, row).aad()),
                        "{tenant}/{kind}/{row} collides with another binding"
                    );
                }
            }
            for kid in &kids {
                for purpose in KeyPurpose::ALL {
                    for algorithm in SigningAlgorithm::ALL {
                        assert!(
                            seen.insert(KeyBinding::new(tenant, kid, purpose, algorithm).aad()),
                            "{tenant}/{kid}/{purpose}/{algorithm} collides with another binding"
                        );
                    }
                }
            }
        }
    }

    /// The row identifier is authenticated, not merely stored beside the
    /// ciphertext: a push credential sealed for one stream must not open under
    /// another stream's binding, or one `UPDATE` hands a receiver another
    /// receiver's credential.
    #[test]
    fn a_row_secret_does_not_open_under_another_rows_binding() {
        // Arrange
        let tenant = tenant();
        let kek = kek();
        let sealed = kek
            .seal(
                KeyBinding::row_secret(&tenant, RowSecret::SsfPushAuthorization, "stream-a"),
                b"Bearer t",
            )
            .expect("seal");

        // Act
        let elsewhere = kek.open(
            KeyBinding::row_secret(&tenant, RowSecret::SsfPushAuthorization, "stream-b"),
            &sealed,
        );

        // Assert
        assert_eq!(
            kek.open(
                KeyBinding::row_secret(&tenant, RowSecret::SsfPushAuthorization, "stream-a"),
                &sealed
            )
            .expect("open")
            .as_slice(),
            b"Bearer t"
        );
        assert!(matches!(elsewhere, Err(JoseError::Unwrap)));
    }

    /// A salt is 256 bits, so its envelope is 256 bits plus a GCM tag — the
    /// exact length `tenant_pairwise_salts.salt_ciphertext` is constrained to.
    #[test]
    fn a_sealed_salt_is_exactly_the_length_the_schema_expects() {
        let tenant = tenant();
        let sealed = kek()
            .seal(
                KeyBinding::tenant_secret(&tenant, TenantSecret::PairwiseSalt),
                &[0x5c; 32],
            )
            .expect("seal");
        assert_eq!(sealed.ciphertext().len(), 32 + TAG_LEN);
        assert_eq!(sealed.nonce().len(), NONCE_LEN);
        // And the ciphertext is not the salt.
        assert!(!sealed.ciphertext().starts_with(&[0x5c; 16]));
    }

    #[test]
    fn material_sealed_under_one_kek_does_not_open_under_another() {
        let (tenant, kid) = (tenant(), kid());
        let sealed = kek()
            .seal(binding(&tenant, &kid), b"payload")
            .expect("seal");

        let other = LocalKek::from_bytes(&ANOTHER_KEK).expect("valid KEK");
        assert!(
            matches!(
                other.open(binding(&tenant, &kid), &sealed),
                Err(JoseError::KekMismatch { .. })
            ),
            "a different KEK should be reported as a mismatch, not as corruption"
        );

        // And when the id is forged to match, the cryptography still refuses.
        let forged = WrappedKey::from_parts(
            other.id(),
            sealed.nonce().to_vec(),
            sealed.ciphertext().to_vec(),
        )
        .expect("well-formed");
        assert!(matches!(
            other.open(binding(&tenant, &kid), &forged),
            Err(JoseError::Unwrap)
        ));
    }

    /// Two KEKs must not share an id, or a row would be unwrapped under the
    /// wrong key and reported as corruption.
    #[test]
    fn a_kek_id_follows_the_material_and_not_the_source() {
        let first = kek();
        assert_eq!(first.id(), kek().id(), "the same material, a different id");
        assert_ne!(
            first.id(),
            LocalKek::from_bytes(&ANOTHER_KEK).expect("valid").id(),
            "different material, the same id"
        );
        assert!(first.id().starts_with("local:"), "{}", first.id());
        // The id must not be the key, nor any prefix of it.
        assert!(!first.id().contains(&B64.encode(A_KEK)));
    }

    #[test]
    fn only_a_256_bit_key_is_accepted_as_a_kek() {
        for length in [0_usize, 1, 16, 24, 31, 33, 64] {
            let material = vec![0x11; length];
            assert!(
                LocalKek::from_bytes(&material).is_err(),
                "{length} bytes was accepted as a key-encryption key"
            );
        }
        assert!(LocalKek::from_bytes(&A_KEK).is_ok());
    }

    #[test]
    fn a_base64_kek_is_read_in_either_alphabet_and_nothing_else_is() {
        let material = [0xfb_u8; KEK_LEN];
        let expected = LocalKek::from_bytes(&material)
            .expect("valid")
            .id()
            .to_owned();

        for encoded in [
            B64.encode(material),
            B64_STANDARD.encode(material),
            format!("{}\n", B64.encode(material)),
        ] {
            assert_eq!(
                LocalKek::from_base64("test", &encoded).expect("valid").id(),
                expected
            );
        }

        for rejected in ["", "not base64!!", "c2hvcnQ=", &B64.encode([0_u8; 64])] {
            assert!(
                LocalKek::from_base64("test", rejected).is_err(),
                "accepted {rejected:?}"
            );
        }
    }

    /// A KEK that is absent must stop the process, not conjure a key: a
    /// generated-on-boot KEK makes every key already stored unreadable.
    #[test]
    fn an_absent_key_encryption_key_is_an_error_not_a_default() {
        let error = LocalKek::from_env("ASTERIUS_KEK_THAT_IS_NOT_SET").expect_err("must fail");
        assert!(matches!(error, JoseError::KekUnavailable { .. }));
        assert!(LocalKek::from_file("/nonexistent/asterius.kek").is_err());
    }

    #[test]
    fn a_truncated_or_malformed_row_is_rejected_before_the_aead_sees_it() {
        assert!(WrappedKey::from_parts("local:x", vec![0; NONCE_LEN - 1], vec![0; 64]).is_err());
        assert!(WrappedKey::from_parts("local:x", vec![0; NONCE_LEN + 1], vec![0; 64]).is_err());
        assert!(WrappedKey::from_parts("local:x", vec![0; NONCE_LEN], vec![]).is_err());
        // A ciphertext of exactly the tag length holds no plaintext at all.
        assert!(WrappedKey::from_parts("local:x", vec![0; NONCE_LEN], vec![0; TAG_LEN]).is_err());
        assert!(
            WrappedKey::from_parts("local:x", vec![0; NONCE_LEN], vec![0; TAG_LEN + 1]).is_ok()
        );
    }

    #[test]
    fn debugging_a_kek_or_a_wrapped_key_does_not_print_material() {
        let kek = kek();
        let rendered = format!("{kek:?}");
        assert!(rendered.contains("local:"), "{rendered}");
        assert!(!rendered.contains(&B64.encode(A_KEK)), "{rendered}");

        let (tenant, kid) = (tenant(), kid());
        let wrapped = kek.seal(binding(&tenant, &kid), b"payload").expect("seal");
        let rendered = format!("{wrapped:?}");
        assert!(rendered.contains("ciphertext_len"), "{rendered}");
        assert!(
            !rendered.contains(&format!("{:?}", wrapped.ciphertext())),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn the_async_port_and_the_local_implementation_agree() {
        let kek = kek();
        let (tenant, kid) = (tenant(), kid());
        let port: &dyn Kek = &kek;

        let wrapped = port
            .wrap(binding(&tenant, &kid), b"payload")
            .await
            .expect("wrap");
        assert_eq!(port.id(), kek.id());
        assert_eq!(wrapped.kek_id(), kek.id());
        let opened = port
            .unwrap(binding(&tenant, &kid), &wrapped)
            .await
            .expect("unwrap");
        assert_eq!(opened.as_slice(), b"payload");
    }
}
