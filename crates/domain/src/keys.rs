//! Signing algorithms, key identifiers, and the ports that reach a key.
//!
//! The algorithm set lives here rather than in the adapter because two crates
//! need to name it: `asterius-oidc` publishes it in discovery metadata, and
//! `asterius-jose` implements it. A protocol crate must not depend on an
//! adapter, so the vocabulary belongs in the middle. See
//! [ADR-0004](../../../docs/adr/0004-jose-on-aws-lc-rs.md).

use crate::TenantId;
use crate::audit::Actor;
use serde::{Deserialize, Serialize};
use std::fmt;
use time::{Duration, OffsetDateTime};

/// A signing algorithm this server will use.
///
/// The set is closed, and closed is the point. FAPI 2.0 SP §5.4.1 permits
/// exactly PS256, ES256 and EdDSA(Ed25519); RFC 8725 §3.1–3.2 says to fix the
/// permitted algorithms in advance rather than trusting a token's `alg` header.
/// An enum does both: `none` and `HS256` are not values that exist, so the
/// algorithm-confusion class of attack is unrepresentable rather than rejected
/// at runtime.
///
/// ADR-0003 records why RS256 is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    /// EdDSA over Ed25519. The default for everything this server issues.
    #[serde(rename = "EdDSA")]
    EdDsa,
    /// ECDSA over P-256 with SHA-256.
    #[serde(rename = "ES256")]
    Es256,
    /// RSASSA-PSS with SHA-256. The RSA option, for HSM estates that offer
    /// nothing else.
    #[serde(rename = "PS256")]
    Ps256,
}

impl SigningAlgorithm {
    /// Every permitted algorithm, in the order metadata should advertise them:
    /// the default first.
    pub const ALL: [Self; 3] = [Self::EdDsa, Self::Es256, Self::Ps256];

    /// The default for newly generated keys.
    pub const DEFAULT: Self = Self::EdDsa;

    /// The `alg` value, as it appears in a JOSE header and in metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::Ps256 => "PS256",
        }
    }

    /// Parses an `alg` value from a token header or from client metadata.
    ///
    /// Returns `None` for anything outside the allow-list — including `none`,
    /// `HS256` and `RS256`, which is the whole job.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.as_str() == value)
    }

    /// The JWK `kty` for keys of this algorithm (RFC 7517 §4.1).
    #[must_use]
    pub const fn key_type(self) -> &'static str {
        match self {
            Self::EdDsa => "OKP",
            Self::Es256 => "EC",
            Self::Ps256 => "RSA",
        }
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A key identifier: the JOSE `kid`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Kid(String);

impl Kid {
    /// Wraps a key identifier.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a key is in its life.
///
/// Rotation is a sequence of states rather than a swap, because a verifier that
/// cached the JWKS an hour ago must still be able to check a token signed an
/// hour ago. A key is published before it signs and stays published after it
/// stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyState {
    /// In the JWKS, not yet signing. Gives verifiers time to fetch it.
    Pending,
    /// The key new signatures are made with. At most one per algorithm.
    Active,
    /// No longer signing, still in the JWKS so existing tokens verify.
    Retiring,
    /// Gone from the JWKS. Kept only so its `kid` is never reused.
    Retired,
}

impl KeyState {
    /// The storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
        }
    }

    /// Whether a key in this state belongs in the published JWKS.
    #[must_use]
    pub const fn is_published(self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::Retiring)
    }

    /// Parses the storage spelling.
    ///
    /// Returns `None` for anything else. A row whose state nobody recognises
    /// must not load as a usable key: "unknown" is not a state a key can be in,
    /// and defaulting it to `retired` would hide a corrupted row while
    /// defaulting it to `active` would sign with one.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    /// Every state, in the order a key passes through them.
    pub const ALL: [Self; 4] = [Self::Pending, Self::Active, Self::Retiring, Self::Retired];
}

/// What a key may be used for.
///
/// FAPI 2.0 SP §6.8 item 2 asks for single-purpose keys: "single purpose keys
/// are recommended. For example, it is not recomended to use the same key for
/// signing and encryption." The reason is not hygiene, it is that a signing
/// oracle and a decryption oracle over one key pair combine into attacks that
/// neither offers alone.
///
/// The spellings are the JWK `use` values (RFC 7517 §4.2), so a stored purpose
/// and the `use` member of the published JWK are the same string and cannot
/// drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyPurpose {
    /// Signs and verifies. Every JWT this server issues.
    #[serde(rename = "sig")]
    Signing,
    /// Encrypts and decrypts. No key of this purpose exists yet — ADR-0004
    /// records that JWE is not implemented — but the distinction is stored
    /// from the start, because a purpose column added after the fact has to
    /// guess what the rows already in the table were for.
    #[serde(rename = "enc")]
    Encryption,
}

impl KeyPurpose {
    /// Every purpose.
    pub const ALL: [Self; 2] = [Self::Signing, Self::Encryption];

    /// The storage and JWK `use` spelling (RFC 7517 §4.2).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signing => "sig",
            Self::Encryption => "enc",
        }
    }

    /// Parses a `use` value. `None` for anything outside the two.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|purpose| purpose.as_str() == value)
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The public half of a signing key, as published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyRecord {
    /// Which tenant's key this is.
    pub tenant: TenantId,
    /// The key identifier.
    pub kid: Kid,
    /// The algorithm it signs with.
    pub algorithm: SigningAlgorithm,
    /// What it may be used for. A JWKS consumer reads this as the `use`
    /// member, and nothing may use a key for the other one.
    pub purpose: KeyPurpose,
    /// Where it is in its life.
    pub state: KeyState,
    /// The public key as a JWK, ready to serve in a JWKS.
    pub public_jwk: serde_json::Value,
    /// When it was created.
    pub created_at: OffsetDateTime,
}

/// Whether `records` hold a key that can sign `algorithm` right now.
///
/// The one question a registration document raises that
/// [`crate::ClientRegistration`] cannot answer: `id_token_signed_response_alg`
/// names an algorithm this *build* supports, and whether this *tenant* has an
/// active signing key for it is a fact about rows rather than about the
/// document. A client registered for an algorithm nobody can sign with is one
/// this server can never issue an ID token to, so both places that create a
/// client — `POST /register` and the admin API — ask this before writing, and
/// they ask it here so that they cannot come to different answers.
///
/// [`KeyState::Active`] and [`KeyPurpose::Signing`] specifically: a pending key
/// is published and not yet signing, and a retiring one is published and no
/// longer signing, so neither can back an ID token issued today.
#[must_use]
pub fn signs_with(records: &[PublicKeyRecord], algorithm: SigningAlgorithm) -> bool {
    records.iter().any(|record| {
        record.algorithm == algorithm
            && record.state == KeyState::Active
            && record.purpose == KeyPurpose::Signing
    })
}

/// A JWS in compact serialisation, ready to put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactJws(String);

impl CompactJws {
    /// Wraps an already-serialised JWS.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The serialisation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CompactJws {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Signs tokens for one tenant.
///
/// The port is deliberately narrow: a caller says what kind of token it is,
/// which algorithm the claims commit it to, and what is in it. It cannot
/// choose the key or the rest of the header. Every JWT this server issues
/// therefore carries a `kid`, an allow-listed `alg`, and an explicit `typ`
/// (RFC 8725 §3.11) without any call site having to remember.
#[async_trait::async_trait]
pub trait Signer: fmt::Debug + Send + Sync {
    /// Signs `claims` as a JWT of media type `typ`, under `algorithm`.
    ///
    /// `typ` is the explicit type header — `at+jwt` for an access token
    /// (RFC 9068 §2.1), `logout+jwt`, `dpop+jwt`, `secevent+jwt`. It is
    /// required, not optional, so that a token minted for one purpose cannot be
    /// presented as another.
    ///
    /// # Why the algorithm is the caller's to state
    ///
    /// For most tokens it does not matter which key signs, so long as the `kid`
    /// names it. For one it does, and that one is the ID token.
    ///
    /// OpenID Connect Dynamic Client Registration 1.0 §2 defines
    /// `id_token_signed_response_alg` as the "JWS `alg` algorithm \[JWA\]
    /// REQUIRED for signing the ID Token issued to this Client" — an obligation
    /// on the *server*, per client, settled at registration. OIDC Core §3.1.3.7
    /// item 7 is the client half of it: "The `alg` value SHOULD be the default
    /// of `RS256` or the algorithm sent by the Client in the
    /// `id_token_signed_response_alg` parameter during Registration."
    ///
    /// And §3.1.3.6 makes the claims themselves depend on the answer: `at_hash`
    /// is taken with "the hash algorithm used in the `alg` Header Parameter of
    /// the ID Token's JOSE Header". So a claims set built for `ES256` — whose
    /// `at_hash` is half a SHA-256 digest — and then signed with `EdDSA` is not
    /// merely signed with an unexpected key. It carries a value the client
    /// computes differently (half a SHA-512 digest, because Ed25519 is EdDSA
    /// instantiated with SHA-512 — RFC 8037 §3.1, RFC 8032 §5.1) and is
    /// entitled to reject.
    ///
    /// A signer that chose for itself could not be given that constraint, which
    /// is why it is a parameter rather than an implementation detail.
    ///
    /// `None` means the claims commit to nothing: any active key will do and
    /// the signer picks. That is the right answer for an access token, which
    /// says nothing about how it was signed and whose verifier is a resource
    /// server resolving the key from the published JWKS by `kid`.
    ///
    /// `None` is *not* a fallback for a `Some` that cannot be honoured. An
    /// access token and an ID token issued in the same response are two calls
    /// with two answers here, and may legitimately be signed under two
    /// different algorithms by two different keys — one is read by a resource
    /// server, the other by the client, and nothing requires them to agree.
    ///
    /// # Errors
    ///
    /// [`crate::DomainError::NoSigningKey`] if the tenant holds no active key
    /// of the requested algorithm — or, when `algorithm` is `None`, no active
    /// key at all. An implementation must never substitute a key of another
    /// algorithm: that is exactly the wrong-`at_hash` token this parameter
    /// exists to prevent, and it would surface as a client that cannot log
    /// anybody in rather than as an error anyone can see.
    ///
    /// Returns [`crate::DomainError`] otherwise if the signing operation fails.
    async fn sign(
        &self,
        tenant: &TenantId,
        algorithm: Option<SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<CompactJws, crate::DomainError>;
}

/// What one pass of the key lifecycle did.
///
/// Every field is a `kid` that changed state, so a caller — an admin endpoint,
/// a log line, the audit record — can say precisely what happened rather than
/// "rotated".
///
/// The vocabulary lives here rather than in the PostgreSQL adapter because
/// three crates name it: the adapter produces it, `asterius-admin-api` renders
/// it to the console, and the server's sweep logs it. An API crate must not
/// depend on an adapter, so the words belong in the middle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyRotation {
    /// A newly generated key, published but not yet signing. `None` when the
    /// pass only promoted and retired.
    pub created: Option<Kid>,
    /// A key promoted from `pending` to `active` in this pass.
    pub activated: Option<Kid>,
    /// The key that promotion displaced, now `retiring`.
    pub superseded: Option<Kid>,
    /// Keys that have left the JWKS in this pass.
    pub retired: Vec<Kid>,
}

impl KeyRotation {
    /// Whether this pass changed nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.created.is_none()
            && self.activated.is_none()
            && self.superseded.is_none()
            && self.retired.is_empty()
    }
}

/// A tenant's rotation policy.
///
/// Durations rather than the raw seconds a schema stores, because every use of
/// them is arithmetic against a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationSchedule {
    /// How often a new key is staged.
    pub rotation_period: Duration,
    /// How long a new key is published before it is allowed to sign.
    pub propagation_period: Duration,
    /// How long a key stays published after it stops signing.
    pub grace_period: Duration,
    /// When a key was last staged for this tenant, if ever.
    pub last_rotated_at: Option<OffsetDateTime>,
}

impl RotationSchedule {
    /// Whether a rotation is due at `now`.
    ///
    /// A tenant that has never rotated is always due: the first call is what
    /// creates its first key.
    #[must_use]
    pub fn is_due(&self, now: OffsetDateTime) -> bool {
        self.last_rotated_at
            .is_none_or(|last| last + self.rotation_period <= now)
    }
}

/// When a key an operator has just staged is allowed to start signing.
///
/// The default is not a preference, it is the safe half of OIDC Core §10.1.1: a
/// new key goes into the JWK Set first, and the signer "can begin using a new
/// key" only afterwards, so a verifier holding a JWK Set cached minutes ago
/// never meets a `kid` it has not seen. Publishing and signing in the same
/// instant means every verifier whose cache has not turned over rejects the
/// next token until it refetches.
///
/// [`Self::Immediate`] exists because the one case where that trade is worth
/// making is the case a console must serve: a key believed to be compromised
/// has to stop signing *now*, and a propagation period of correct signatures
/// from a leaked key is worse than a propagation period of verifiers refetching
/// a JWK Set they are required to refetch on an unknown `kid` anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Activation {
    /// The staged key waits out the tenant's propagation period. The default,
    /// and what the background sweep always does.
    #[default]
    OnSchedule,
    /// The staged key is promoted in the same call. The key it displaces stays
    /// published in `retiring`, so tokens it already signed keep verifying.
    Immediate,
}

/// Administering a tenant's keys: the operations behind a console's key screen.
///
/// Separate from [`KeyStore`], which is the read side every protocol endpoint
/// holds. **Nothing in this trait returns private key material and nothing
/// can**: [`PublicKeyRecord`] carries a public JWK and no other key bytes, and
/// there is no method here that yields a signing key. That is what the admin
/// API's "a private key never leaves the server" property rests on — a
/// consequence of the port's return types rather than of a handler remembering
/// to redact (OIDC Core §10.1.1, FAPI 2.0 SP §6.8).
#[async_trait::async_trait]
pub trait KeyAdministration: fmt::Debug + Send + Sync {
    /// Every key this tenant holds, in any state, including retired ones.
    ///
    /// Wider than [`KeyStore::published_keys`] on purpose: the JWKS must not
    /// contain a retired key, and an inventory that hid them would answer
    /// "where did that `kid` go?" with silence.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DomainError`] if the keys cannot be read.
    async fn inventory(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<PublicKeyRecord>, crate::DomainError>;

    /// This tenant's rotation policy for each algorithm it publishes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DomainError`] if a policy cannot be read.
    async fn schedules(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<(SigningAlgorithm, RotationSchedule)>, crate::DomainError>;

    /// Replaces the policy for one algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DomainError::Invalid`] if a period is not a positive
    /// whole number of seconds, or a storage failure.
    async fn set_schedule(
        &self,
        tenant: &TenantId,
        algorithm: SigningAlgorithm,
        schedule: RotationSchedule,
    ) -> Result<(), crate::DomainError>;

    /// Rotates now, whatever the schedule says.
    ///
    /// Stages a new key, promotes whatever is due and retires whatever has
    /// outlived its grace period. `activation` decides whether the key staged
    /// by *this* call also starts signing in it.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DomainError`] if the keys cannot be read or written.
    async fn rotate(
        &self,
        tenant: &TenantId,
        algorithm: SigningAlgorithm,
        activation: Activation,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<KeyRotation, crate::DomainError>;

    /// Takes one key out of the published set, naming it by `kid`.
    ///
    /// The active key is **not** retirable this way, and an implementation must
    /// refuse it with [`crate::DomainError::Conflict`]: retiring the only key
    /// an algorithm can sign with leaves a tenant unable to issue a token, and
    /// the operation that replaces an active key is [`Self::rotate`]. Every
    /// other state is retirable — a `pending` key staged by mistake never
    /// signed anything, and cutting a `retiring` key's grace short is an
    /// operator's deliberate choice about a key they no longer trust.
    ///
    /// # Errors
    ///
    /// [`crate::DomainError::NotFound`] if the tenant holds no such key,
    /// [`crate::DomainError::Conflict`] if it is the active one, or a storage
    /// failure.
    async fn retire(
        &self,
        tenant: &TenantId,
        kid: &Kid,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<KeyRotation, crate::DomainError>;
}

/// Holds a tenant's keys.
#[async_trait::async_trait]
pub trait KeyStore: fmt::Debug + Send + Sync {
    /// The keys a tenant publishes, in JWKS order.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DomainError`] if the keys cannot be read.
    async fn published_keys(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<PublicKeyRecord>, crate::DomainError>;

    /// The key a `kid` refers to, whatever its state.
    ///
    /// Retiring and retired keys must still resolve: a token signed yesterday
    /// is verified today.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DomainError`] if the key cannot be read.
    async fn public_key(
        &self,
        tenant: &TenantId,
        kid: &Kid,
    ) -> Result<Option<PublicKeyRecord>, crate::DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(algorithm: SigningAlgorithm, state: KeyState, purpose: KeyPurpose) -> PublicKeyRecord {
        PublicKeyRecord {
            tenant: TenantId::new("demo"),
            kid: Kid::new("k-1"),
            algorithm,
            purpose,
            state,
            public_jwk: serde_json::json!({"kty": "OKP"}),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// Only an active signing key can sign today. A pending key is published
    /// and not yet signing; a retiring one is published and no longer signing.
    /// A client registered against either would be one this server could never
    /// issue an ID token to.
    #[test]
    fn only_an_active_signing_key_makes_an_algorithm_signable() {
        // Arrange
        let cases = [
            (KeyState::Pending, KeyPurpose::Signing, false),
            (KeyState::Active, KeyPurpose::Signing, true),
            (KeyState::Retiring, KeyPurpose::Signing, false),
            (KeyState::Retired, KeyPurpose::Signing, false),
        ];

        for (state, purpose, expected) in cases {
            // Act
            let signable = signs_with(
                &[key(SigningAlgorithm::EdDsa, state, purpose)],
                SigningAlgorithm::EdDsa,
            );

            // Assert
            assert_eq!(signable, expected, "{state:?}/{purpose:?}");
        }
    }

    /// The algorithm asked about is the one answered about: an active EdDSA key
    /// does not make `ES256` signable.
    #[test]
    fn a_key_of_another_algorithm_does_not_answer_for_this_one() {
        // Arrange
        let records = [key(
            SigningAlgorithm::EdDsa,
            KeyState::Active,
            KeyPurpose::Signing,
        )];

        // Act / Assert
        assert!(signs_with(&records, SigningAlgorithm::EdDsa));
        assert!(!signs_with(&records, SigningAlgorithm::Es256));
        assert!(!signs_with(&[], SigningAlgorithm::EdDsa));
    }

    /// FAPI 2.0 SP §5.4.1 and ADR-0003: exactly three, and not the others.
    #[test]
    fn the_algorithm_set_is_exactly_what_the_profile_permits() {
        let names: Vec<&str> = SigningAlgorithm::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(names, ["EdDSA", "ES256", "PS256"]);
        assert_eq!(SigningAlgorithm::DEFAULT, SigningAlgorithm::EdDsa);
    }

    /// The parser is the allow-list. Everything an attacker would put in an
    /// `alg` header to downgrade a signature must fail to become a value.
    #[test]
    fn no_algorithm_outside_the_allow_list_can_be_named() {
        for rejected in [
            "none", "None", "NONE", // RFC 8725 §3.2
            "HS256", "HS384", "HS512", // symmetric: alg confusion with a public key
            "RS256", "RS384", "RS512", // ADR-0003
            "ES384", "ES512", "PS384", "PS512", // not profiled
            "EdDSA ", " EdDSA", "eddsa", "", "ES25 6",
        ] {
            assert_eq!(
                SigningAlgorithm::parse(rejected),
                None,
                "accepted {rejected:?}"
            );
        }
    }

    #[test]
    fn every_permitted_algorithm_round_trips_through_its_wire_name() {
        for alg in SigningAlgorithm::ALL {
            assert_eq!(SigningAlgorithm::parse(alg.as_str()), Some(alg));
            let json = serde_json::to_string(&alg).expect("serialise");
            assert_eq!(json, format!("\"{}\"", alg.as_str()));
            assert_eq!(
                serde_json::from_str::<SigningAlgorithm>(&json).expect("deserialise"),
                alg
            );
        }
    }

    #[test]
    fn each_algorithm_names_its_jwk_key_type() {
        assert_eq!(SigningAlgorithm::EdDsa.key_type(), "OKP");
        assert_eq!(SigningAlgorithm::Es256.key_type(), "EC");
        assert_eq!(SigningAlgorithm::Ps256.key_type(), "RSA");
    }

    /// A verifier that fetched the JWKS an hour ago must still be able to check
    /// a token signed an hour ago, so a key is published before and after it
    /// signs.
    #[test]
    fn a_key_is_published_before_and_after_it_signs() {
        assert!(KeyState::Pending.is_published());
        assert!(KeyState::Active.is_published());
        assert!(KeyState::Retiring.is_published());
        assert!(!KeyState::Retired.is_published());
    }

    /// A row whose state is not one of the four must not resolve to a state at
    /// all. Every default a reader could pick here is wrong in one direction:
    /// `active` signs with a key nobody vouched for, `retired` silently drops
    /// a key that tokens in the wild were signed by.
    #[test]
    fn a_state_outside_the_four_does_not_parse() {
        for state in KeyState::ALL {
            assert_eq!(KeyState::parse(state.as_str()), Some(state));
        }
        for rejected in ["", "ACTIVE", "active ", "revoked", "compromised", "null"] {
            assert_eq!(KeyState::parse(rejected), None, "accepted {rejected:?}");
        }
    }

    /// FAPI 2.0 SP §6.8 item 2: single-purpose keys. The two purposes are
    /// exactly the JWK `use` values (RFC 7517 §4.2), so the stored purpose and
    /// the published `use` member cannot disagree by construction.
    #[test]
    fn a_key_purpose_is_its_jwk_use_value_and_nothing_else() {
        assert_eq!(KeyPurpose::Signing.as_str(), "sig");
        assert_eq!(KeyPurpose::Encryption.as_str(), "enc");
        for purpose in KeyPurpose::ALL {
            assert_eq!(KeyPurpose::parse(purpose.as_str()), Some(purpose));
            assert_eq!(
                serde_json::to_string(&purpose).expect("serialise"),
                format!("\"{purpose}\"")
            );
        }
        // "both" is the state this enum exists to make unrepresentable.
        for rejected in ["", "both", "sig enc", "signature", "encryption", "SIG"] {
            assert_eq!(KeyPurpose::parse(rejected), None, "accepted {rejected:?}");
        }
    }

    /// A tenant that has never rotated must rotate on the first pass, or a
    /// freshly created tenant would sit without a signing key until somebody
    /// noticed.
    #[test]
    fn a_tenant_that_has_never_rotated_is_always_due() {
        // Arrange
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut schedule = RotationSchedule {
            rotation_period: Duration::days(90),
            propagation_period: Duration::minutes(15),
            grace_period: Duration::days(7),
            last_rotated_at: None,
        };

        // Act / Assert
        assert!(schedule.is_due(now));

        schedule.last_rotated_at = Some(now);
        assert!(!schedule.is_due(now + Duration::days(89)));
        assert!(schedule.is_due(now + Duration::days(90)));
    }

    #[test]
    fn an_empty_pass_is_reported_as_one() {
        assert!(KeyRotation::default().is_empty());
        assert!(
            !KeyRotation {
                created: Some(Kid::new("k")),
                ..KeyRotation::default()
            }
            .is_empty()
        );
        assert!(
            !KeyRotation {
                retired: vec![Kid::new("k")],
                ..KeyRotation::default()
            }
            .is_empty()
        );
    }

    /// OIDC Core §10.1.1 publishes a key before it signs. A caller that does
    /// not say which it wants must get the wait, because the alternative — a
    /// `kid` that appears and signs in the same instant — is refused by every
    /// verifier whose JWK Set cache has not turned over.
    #[test]
    fn a_rotation_that_does_not_ask_gets_the_propagation_period() {
        assert_eq!(Activation::default(), Activation::OnSchedule);
    }
}
