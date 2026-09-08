//! The user entity, the claims that describe them, and the subject identifiers
//! clients see them as.
//!
//! Three decisions shape this file.
//!
//! **Claims are a bag, not columns.** OIDC Core §5.1 names about twenty
//! standard claims, and every profile built on it adds more: Identity Assurance
//! projects `verified_claims` with a whole verification record per claim
//! (`ast-s36.5`), verifiable credentials arrive as claims asserted by somebody
//! else (`ast-s36.6`), and a tenant may carry claims nobody has standardised. A
//! column per claim would make each of those a migration. So a claim is a
//! [`Claim`] — a value, the [`ClaimSource`] that asserted it, and when it was
//! last verified — and the set of them is a [`ClaimSet`] living in one JSONB
//! column. `source` is what makes the model *issuer-agnostic*: a claim knows
//! whether this server, an operator, an import or **another issuer** put it
//! there, so an assertion from a wallet or an upstream OP does not need a new
//! shape to be stored in.
//!
//! Which claims a client actually receives is a different question — scopes,
//! the `claims` request parameter, `claims_locales` — and belongs to the claims
//! resolution service (`ast-1sk.4`). Nothing here decides what is released.
//!
//! **A `sub` is derived, not stored twice.** OIDC Core §8 defines two subject
//! identifier types, and §8.1 fixes what a pairwise one has to satisfy: not
//! reversible by anyone but the OpenID Provider, distinct for distinct sectors,
//! and deterministic. [`PairwiseSalt::derive_subject`] is a pure function of
//! the tenant salt and those two inputs, so the property can be tested without
//! a database and the same user in the same sector always lands on the same
//! `sub`. The salt is the receiver rather than a third argument: a caller that
//! can pass a salt is a caller that can pass the wrong one, and the first
//! derivation is the one that gets stored and handed to a relying party.
//!
//! **Every claim has one home.** A value that lives in a column does not also
//! live in the bag: [`ClaimName::parse`] refuses `email`, `email_verified` and
//! `updated_at` because [`User`] carries them, and refuses the claims the
//! authorization server mints for itself — `sub`, `iss`, `aud`, `acr`, `amr`
//! and the rest — because a bag able to hold a `sub` is a bag able to
//! impersonate somebody.

use crate::ids::{SubjectId, TenantId};
use crate::issuer::Issuer;
use crate::secret::Secret;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::client::{Client, SubjectType};

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// The local account identifier — OIDC Core §8.1's `local_account_id`.
///
/// A random UUID rather than a sequence, because it is an input to
/// [`PairwiseSalt::derive_subject`] and therefore, indirectly, to every `sub`
/// the deployment
/// issues. A sequence would make the local id guessable, which turns "recover
/// the user from a `sub`" into "confirm a guess" for anyone who ever obtains
/// the tenant salt; 122 random bits leave nothing to enumerate.
///
/// Distinct from [`SubjectId`] on purpose: this one never leaves the
/// deployment, and that one is all a client ever sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(Uuid);

impl UserId {
    /// Draws a new account identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wraps an identifier read back from a row.
    #[must_use]
    pub const fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// The identifier, for the `uuid` column it is stored in.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// The sixteen bytes, which is the form [`PairwiseSalt::derive_subject`]
    /// hashes.
    ///
    /// The raw bytes and not the hyphenated text: a UUID has several spellings
    /// and only one byte encoding, so hashing the bytes is what stops a
    /// formatting change from silently reassigning every subject.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

// ---------------------------------------------------------------------------
// The user
// ---------------------------------------------------------------------------

/// Whether an account may authenticate.
///
/// The three states are distinguishable to an operator and not to a caller: a
/// login form answers the same way for a disabled account, a locked one and a
/// wrong password, or it becomes an account-enumeration oracle. What the
/// distinction drives is what the operator has to do to undo it — a lock
/// expires or is cleared by the user, a disablement is an administrative act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    /// Can authenticate.
    Active,
    /// Switched off by an administrator.
    Disabled,
    /// Switched off by the system — too many failed attempts, a credential
    /// change in progress, a risk signal.
    Locked,
}

impl UserStatus {
    /// The value as stored in the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Locked => "locked",
        }
    }

    /// Parses a stored status.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            "locked" => Some(Self::Locked),
            _ => None,
        }
    }
}

/// An end user, in one tenant.
///
/// Deliberately not `#[non_exhaustive]`, for the reason given on
/// [`Tenant`](super::Tenant): adapters build entities from rows, and sealing
/// the struct would only push every adapter through a constructor taking the
/// same fields in the same order with less type checking.
///
/// `email` and `email_verified` are fields rather than claims because the
/// schema indexes them — `users_by_email` is unique per tenant over
/// `lower(email)`, which is what stops two accounts claiming one address. A
/// value the database has an opinion about cannot also be free-form JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct User {
    /// The tenant that owns this account. A user means nothing outside it.
    pub tenant: TenantId,
    /// The local account identifier: what OIDC Core §8.1 calls the
    /// `local_account_id`, and the only input to
    /// [`PairwiseSalt::derive_subject`] that identifies the person.
    pub id: UserId,
    /// The login identifier. Unique within the tenant.
    ///
    /// Not the same thing as the `preferred_username` claim, which is a display
    /// preference and may be changed, duplicated or absent.
    pub username: String,
    /// The address, when there is one.
    pub email: Option<String>,
    /// Whether the address has been proven (OIDC Core §5.1 `email_verified`).
    ///
    /// A separate field and not a property of the address, because an
    /// unverified address is still the address the user typed and still has to
    /// be unique.
    pub email_verified: bool,
    /// Whether the account may authenticate.
    pub status: UserStatus,
    /// Everything else known about the user.
    pub claims: ClaimSet,
    /// When the account was created.
    pub created_at: OffsetDateTime,
    /// When it was last modified. Projected as OIDC Core §5.1's `updated_at`.
    pub updated_at: OffsetDateTime,
}

impl User {
    /// Whether this account may complete an authentication.
    ///
    /// The caller must not report *which* of the three states it is in; see
    /// [`UserStatus`].
    #[must_use]
    pub fn can_authenticate(&self) -> bool {
        self.status == UserStatus::Active
    }
}

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// Why a claim, or the name of one, was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ClaimError {
    /// Empty, or longer than [`ClaimName::MAX_LEN`].
    #[error("a claim name must be 1 to {max} characters, found {found}", max = ClaimName::MAX_LEN)]
    NameLength {
        /// How long the offered name was.
        found: usize,
    },
    /// The name carries a control or bidirectional formatting character.
    #[error(
        "a claim name must not contain control, whitespace or bidirectional formatting characters (U+{0:04X})"
    )]
    NameCharacter(u32),
    /// The part after `#` is not a language tag (OIDC Core §5.2, BCP 47).
    #[error("the text after '#' in a claim name must be a BCP 47 language tag")]
    LanguageTag,
    /// The name is one the authorization server mints, or one [`User`] carries
    /// in a column of its own.
    #[error("the claim `{0}` is not one a user record may assert")]
    Reserved(&'static str),
    /// A claim whose value is `null`.
    #[error("a claim value must not be null; omit the claim instead")]
    NullValue,
}

/// Claims the authorization server issues about the exchange rather than about
/// the person, so a user record must never be able to assert one.
///
/// A bag that can hold a `sub` is a bag that can name another user; a bag that
/// can hold `aud` or `cnf` is a bag that can retarget a token. Every entry here
/// is a value some other part of the server computes and would then have to
/// defend against being overwritten — cheaper to make it unrepresentable.
/// OIDC Core §2 (ID Token), §3.1.3.6, RFC 7519 §4.1, RFC 7800 §3.1,
/// RFC 8693 §4.1.
const SERVER_ISSUED: &[&str] = &[
    "acr",
    "act",
    "amr",
    "at_hash",
    "aud",
    "auth_time",
    "azp",
    "c_hash",
    "client_id",
    "cnf",
    "exp",
    "iat",
    "iss",
    "jti",
    "may_act",
    "nbf",
    "nonce",
    "s_hash",
    "scope",
    "sid",
    "sub",
];

/// Claims [`User`] already carries in a field of its own.
///
/// Two places holding one value is two places that can disagree, and the
/// database has an opinion about these: `users_by_email` is a unique index, and
/// `updated_at` is maintained by a trigger. The claims service (`ast-1sk.4`)
/// projects them from the entity when a scope asks for them.
const HELD_IN_A_COLUMN: &[&str] = &["email", "email_verified", "updated_at"];

/// A claim name, optionally carrying an OIDC Core §5.2 language tag.
///
/// `family_name` and `family_name#ja-Kana-JP` are two names for two values that
/// are both stored: §5.2 makes the tag part of the member name rather than part
/// of the value, so the bag is keyed by the whole thing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ClaimName(String);

impl ClaimName {
    /// The longest a claim name may be, tag included.
    ///
    /// Not a specification limit — OIDC sets none — but a JSON member name is
    /// something an importer or an upstream issuer supplies, and an unbounded
    /// one is an unbounded row, an unbounded log line and an unbounded token.
    pub const MAX_LEN: usize = 128;

    /// The claims the authorization server issues about the exchange, which
    /// [`ClaimName::parse`] therefore refuses.
    ///
    /// Public because the refusal is only half of the guarantee. The other
    /// half belongs to whatever decides which claims a client receives — the
    /// claims resolution service in `asterius-oidc` (`ast-1sk.4`) — and a
    /// second hand-copied list there would be a second rule, drifting from
    /// this one the first time a name is added. A test in that crate walks
    /// this array, so "no request can produce a server-issued claim" is
    /// checked against the list itself rather than against a sample of it.
    pub const SERVER_ISSUED: &'static [&'static str] = SERVER_ISSUED;

    /// The claims [`User`] carries in a column, which [`ClaimName::parse`]
    /// also refuses — because two places holding one value is two places that
    /// can disagree.
    ///
    /// Public for the opposite reason to [`ClaimName::SERVER_ISSUED`]: these
    /// are releasable, and a claims service has to project them from the
    /// entity precisely *because* they are not in the bag. A service that did
    /// not know which those are would answer `email` with nothing.
    pub const HELD_IN_A_COLUMN: &'static [&'static str] = HELD_IN_A_COLUMN;

    /// The character OIDC Core §5.2 uses to introduce a language tag.
    const TAG_SEPARATOR: char = '#';

    /// Validates a claim name.
    ///
    /// Names arrive from an administrator, from a bulk import and from another
    /// issuer's assertion, so this is a parser over material the tenant does
    /// not necessarily control.
    ///
    /// A name is refused when it is empty or too long; when it carries a
    /// control, whitespace or bidirectional formatting character — a claim name
    /// is rendered on consent screens and written into logs, and a right-to-left
    /// override reorders what a human reads without changing a byte of what a
    /// program sees; when the text after `#` is not a language tag, so that a
    /// URI-shaped name with a fragment is an error rather than a silent
    /// misparse; and when it names something the server or the [`User`] record
    /// already owns.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`] describing the first rule broken. No variant
    /// repeats the offered name back, only the reserved constant it collided
    /// with.
    // fuzz-target: claim_name
    pub fn parse(raw: &str) -> Result<Self, ClaimError> {
        let length = raw.chars().count();
        if length == 0 || length > Self::MAX_LEN {
            return Err(ClaimError::NameLength { found: length });
        }
        if let Some(bad) = raw.chars().find(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        }) {
            return Err(ClaimError::NameCharacter(u32::from(bad)));
        }

        let (base, tag) = match raw.split_once(Self::TAG_SEPARATOR) {
            Some((base, tag)) => (base, Some(tag)),
            None => (raw, None),
        };
        if base.is_empty() {
            return Err(ClaimError::NameLength { found: 0 });
        }
        if tag.is_some_and(|tag| !is_language_tag(tag)) {
            return Err(ClaimError::LanguageTag);
        }
        if let Some(reserved) = SERVER_ISSUED
            .iter()
            .chain(HELD_IN_A_COLUMN)
            .find(|name| **name == base)
        {
            return Err(ClaimError::Reserved(reserved));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The whole name, tag included — the key the bag is stored under.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name without its language tag.
    #[must_use]
    pub fn base(&self) -> &str {
        match self.0.split_once(Self::TAG_SEPARATOR) {
            Some((base, _)) => base,
            None => &self.0,
        }
    }

    /// The BCP 47 language tag, when the name carries one (OIDC Core §5.2).
    #[must_use]
    pub fn language_tag(&self) -> Option<&str> {
        self.0.split_once(Self::TAG_SEPARATOR).map(|(_, tag)| tag)
    }
}

impl fmt::Display for ClaimName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A BCP 47 language tag in its basic shape: `[A-Za-z]{1,8}` subtags joined by
/// `-`, the rest alphanumeric (RFC 5646 §2.1).
///
/// Deliberately a shape check and not a registry lookup. What matters here is
/// that the suffix after `#` cannot be arbitrary text — so that a claim name
/// carrying a URI fragment is refused rather than silently read as a language —
/// not that `ja-Kana-JP` names a language somebody speaks.
fn is_language_tag(tag: &str) -> bool {
    let mut subtags = tag.split('-');
    let Some(primary) = subtags.next() else {
        return false;
    };
    if !(1..=8).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    subtags.all(|subtag| {
        (1..=8).contains(&subtag.len()) && subtag.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// Who asserted a claim.
///
/// This is the field that keeps the model issuer-agnostic. A claim this server
/// collected and a claim another issuer asserted are the same shape and live in
/// the same bag, distinguished by their source — which is what
/// `verified_claims` (`ast-s36.5`) and a verifiable credential (`ast-s36.6`)
/// need in order to be projected later without the row changing shape.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimSource {
    /// The end user provided it about themselves.
    Local,
    /// An administrator or a provisioning system set it.
    Admin,
    /// It came in a bulk migration from a previous provider.
    Import,
    /// Another issuer asserted it: an upstream OpenID Provider, a wallet, an
    /// identity verification provider.
    Issuer(Issuer),
}

impl ClaimSource {
    /// The stored spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Local => "local",
            Self::Admin => "admin",
            Self::Import => "import",
            Self::Issuer(issuer) => issuer.as_str(),
        }
    }

    /// Parses a stored source.
    ///
    /// `None` for anything that is neither one of the three local words nor a
    /// canonical issuer. The two cannot collide: an issuer is an https URL by
    /// [`Issuer::parse`], and `local` is not one.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local" => Some(Self::Local),
            "admin" => Some(Self::Admin),
            "import" => Some(Self::Import),
            other => Issuer::parse(other).ok().map(Self::Issuer),
        }
    }
}

impl Serialize for ClaimSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ClaimSource {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).ok_or_else(|| {
            // The value is a stored word or a canonical issuer, neither of
            // which is secret; naming it is what makes a hand-edited row
            // diagnosable.
            serde::de::Error::custom(format!("`{raw}` is not a claim source"))
        })
    }
}

/// One claim: a value, who says so, and when that was last checked.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Claim {
    value: serde_json::Value,
    source: ClaimSource,
    #[serde(with = "rfc3339", skip_serializing_if = "Option::is_none")]
    verified_at: Option<OffsetDateTime>,
}

impl Claim {
    /// Records a claim.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError::NullValue`] for a JSON `null`. OIDC Core §5.3.2
    /// says a claim that is not available is omitted rather than returned
    /// empty, so a stored `null` is a claim that exists and means nothing —
    /// and one an RP is entitled to read as "the provider asserts no value",
    /// which is not what an absent claim means.
    pub fn new(value: serde_json::Value, source: ClaimSource) -> Result<Self, ClaimError> {
        if value.is_null() {
            return Err(ClaimError::NullValue);
        }
        Ok(Self {
            value,
            source,
            verified_at: None,
        })
    }

    /// Records when this claim was last verified.
    #[must_use]
    pub fn verified(mut self, at: OffsetDateTime) -> Self {
        self.verified_at = Some(at);
        self
    }

    /// The value.
    #[must_use]
    pub const fn value(&self) -> &serde_json::Value {
        &self.value
    }

    /// Who asserted it.
    #[must_use]
    pub const fn source(&self) -> &ClaimSource {
        &self.source
    }

    /// When it was last verified, if it ever was.
    #[must_use]
    pub const fn verified_at(&self) -> Option<OffsetDateTime> {
        self.verified_at
    }
}

/// The stored shape of a [`Claim`], so that deserialising goes through
/// [`Claim::new`] instead of around it.
///
/// `deny_unknown_fields` on purpose. A stored claim carrying a member this
/// binary does not know about would be dropped on the next write of that row,
/// silently discarding — for instance — a verification record. Refusing to load
/// is the failure that can be noticed. Adding a member later is a code change
/// and not a migration, which is the compatibility this model was asked for.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredClaim {
    value: serde_json::Value,
    source: ClaimSource,
    #[serde(with = "rfc3339", default)]
    verified_at: Option<OffsetDateTime>,
}

impl<'de> Deserialize<'de> for Claim {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let stored = StoredClaim::deserialize(deserializer)?;
        let claim = Self::new(stored.value, stored.source).map_err(serde::de::Error::custom)?;
        Ok(match stored.verified_at {
            Some(at) => claim.verified(at),
            None => claim,
        })
    }
}

/// RFC 3339 for `Option<OffsetDateTime>`.
///
/// Hand-written because the workspace enables `time`'s `serde`, `formatting`
/// and `parsing` features but not `serde-well-known`; the alternative shape
/// `time` serialises by default is an array, which is not something anyone can
/// read in a `psql` session.
mod rfc3339 {
    use serde::{Deserialize as _, Deserializer, Serializer};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    // `&Option<T>` rather than `Option<&T>` because that is the signature
    // `#[serde(with = ...)]` calls.
    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(
        value: &Option<OffsetDateTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            None => serializer.serialize_none(),
            Some(at) => {
                serializer.serialize_str(&at.format(&Rfc3339).map_err(serde::ser::Error::custom)?)
            }
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| OffsetDateTime::parse(&text, &Rfc3339).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Everything known about a user that is not a column.
///
/// A `BTreeMap` rather than a `HashMap`: the bag is serialised into a JSONB
/// column and, later, into tokens, and an order that changes between processes
/// makes two identical claim sets look like two different ones.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ClaimSet(BTreeMap<ClaimName, Claim>);

impl ClaimSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a claim, returning whatever it replaced.
    pub fn insert(&mut self, name: ClaimName, claim: Claim) -> Option<Claim> {
        self.0.insert(name, claim)
    }

    /// Removes a claim, returning it.
    pub fn remove(&mut self, name: &ClaimName) -> Option<Claim> {
        self.0.remove(name)
    }

    /// One claim by its exact name, language tag included.
    #[must_use]
    pub fn get(&self, name: &ClaimName) -> Option<&Claim> {
        self.0.get(name)
    }

    /// Every claim, in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&ClaimName, &Claim)> {
        self.0.iter()
    }

    /// Every stored spelling of one claim: the untagged one and every language
    /// tagged variant (OIDC Core §5.2).
    ///
    /// The order is the map's, so it is stable; choosing between them is
    /// `claims_locales` resolution and belongs to `ast-1sk.4`.
    pub fn variants<'a>(
        &'a self,
        base: &'a str,
    ) -> impl Iterator<Item = (&'a ClaimName, &'a Claim)> {
        self.0.iter().filter(move |(name, _)| name.base() == base)
    }

    /// How many claims are stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for ClaimSet {
    /// Re-validates every name on the way out of storage.
    ///
    /// The same rule that guards the write guards the read, so a row edited by
    /// hand during an incident — a `sub` inserted into the bag, say — fails to
    /// load rather than reaching a token (`ast-83p.3`).
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let stored = BTreeMap::<String, Claim>::deserialize(deserializer)?;
        stored
            .into_iter()
            .map(|(name, claim)| {
                ClaimName::parse(&name)
                    .map(|name| (name, claim))
                    .map_err(serde::de::Error::custom)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(Self)
    }
}

// ---------------------------------------------------------------------------
// Subject identifiers
// ---------------------------------------------------------------------------

/// Why a subject identifier could not be derived.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SubjectError {
    /// The sector could not be read out of the client's registration.
    #[error("cannot determine the sector identifier: {0}")]
    Sector(&'static str),
    /// The salt a store handed back is not 256 bits.
    ///
    /// A short salt is not stretched and an absent one is not invented; see
    /// [`PairwiseSalt::from_storage`].
    #[error("the stored pairwise salt is not 256 bits")]
    Salt,
}

/// The sector a pairwise subject is calculated in — OIDC Core §8.1.
///
/// Two clients in one sector see one `sub` for a user; two clients in different
/// sectors see two, and nothing they can compare tells them it is the same
/// person. A public subject lives in the sentinel sector [`SectorIdentifier::PUBLIC`],
/// which is the empty string — the same sentinel the `subject_identifiers`
/// table uses, so both subject types are one row shape and `sub` is unique per
/// tenant either way.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectorIdentifier(String);

impl SectorIdentifier {
    /// The sector every public subject shares.
    ///
    /// Empty is safe as a sentinel because a real sector is a URL host, and a
    /// URL with no host is not one [`Url`] will produce for an https scheme.
    pub const PUBLIC: &'static str = "";

    /// The sector shared by every client that sees a public `sub`.
    #[must_use]
    pub fn public() -> Self {
        Self(Self::PUBLIC.to_owned())
    }

    /// The host component of a URL, which is what OIDC Core §8.1 makes the
    /// sector identifier.
    ///
    /// The host and nothing else: the path, the port and the scheme are not
    /// part of the sector, so `https://rp.example/a.json` and
    /// `https://rp.example/b.json` are one sector — which is the point of
    /// `sector_identifier_uri`, since a group of sites under one administration
    /// should see one `sub`.
    ///
    /// # Errors
    ///
    /// Returns [`SubjectError::Sector`] when the value is not a URL with a
    /// host.
    pub fn of_uri(uri: &str) -> Result<Self, SubjectError> {
        let url =
            Url::parse(uri).map_err(|_| SubjectError::Sector("value is not an absolute URL"))?;
        let host = url
            .host_str()
            .ok_or(SubjectError::Sector("URL has no host component"))?;
        // `Url` lower-cases the host of a special scheme, so the sector is
        // already in one spelling: two registrations differing only in case
        // must not become two sectors and two identities.
        Ok(Self(host.to_owned()))
    }

    /// Rebuilds a sector from the value stored in `subject_identifiers`.
    ///
    /// The sentinel `''` is the public sector; anything else must still be the
    /// host a URL parser produces. A hand-edited row carrying `RP.Example` or
    /// `rp.example/x` would otherwise be a second spelling of one sector, and
    /// therefore a second identity for the same person in the same place.
    ///
    /// # Errors
    ///
    /// Returns [`SubjectError::Sector`] when the stored value is neither the
    /// sentinel nor a canonical host.
    pub fn stored(raw: &str) -> Result<Self, SubjectError> {
        if raw == Self::PUBLIC {
            return Ok(Self::public());
        }
        let sector = Self::of_uri(&format!("https://{raw}/"))?;
        if sector.as_str() != raw {
            return Err(SubjectError::Sector(
                "stored sector is not the host a URL parser produces",
            ));
        }
        Ok(sector)
    }

    /// The sector this client's users are identified in — OIDC Core §8.1.
    ///
    /// A public client gets [`SectorIdentifier::public`]. A pairwise one gets
    /// the host of its `sector_identifier_uri`, or, when it registered none,
    /// the host of its single redirect URI — the case
    /// [`ClientMetadata`](super::ClientMetadata) already restricts to exactly
    /// one host, since §8.1 leaves the sector undefined for a client with
    /// several.
    ///
    /// # Errors
    ///
    /// Returns [`SubjectError::Sector`] when no host can be read, and — for a
    /// pairwise client whose only redirect URI is a loopback callback — when
    /// the host that would be used is one **every** native client shares. RFC
    /// 8252 §7.3 makes `127.0.0.1` and `[::1]` the redirect host of every
    /// native client there is, so deriving a sector from it would put them all
    /// in one sector and hand them a correlatable identifier while the
    /// registration says `pairwise`. Such a client has to name a
    /// `sector_identifier_uri`.
    pub fn of_client(client: &Client) -> Result<Self, SubjectError> {
        if client.registration.subject_type == SubjectType::Public {
            return Ok(Self::public());
        }
        if let Some(uri) = client.registration.sector_identifier_uri.as_deref() {
            return Self::of_uri(uri);
        }
        let redirect = client
            .registration
            .redirect_uris
            .first()
            .ok_or(SubjectError::Sector(
                "the client registered no redirect URI",
            ))?;
        let sector = Self::of_uri(redirect.as_str())?;
        if sector.is_shared_by_every_native_client() {
            return Err(SubjectError::Sector(
                "a loopback redirect URI is not a sector; register a sector_identifier_uri",
            ));
        }
        Ok(sector)
    }

    /// Whether this host is one RFC 8252 §7.3 gives to every native client.
    fn is_shared_by_every_native_client(&self) -> bool {
        self.0 == "localhost" || self.0 == "[::1]" || self.0.starts_with("127.")
    }

    /// The sector as it is stored.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the sentinel sector public subjects share.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.0 == Self::PUBLIC
    }
}

/// The per-tenant secret that makes a pairwise `sub` unguessable.
///
/// OIDC Core §8.1 requires that a pairwise Subject Identifier "MUST NOT be
/// reversible by any party other than the OpenID Provider". The sector is
/// public and the local account id is 122 bits of UUID, so what actually
/// carries that requirement is this: 256 bits nobody outside the deployment
/// holds, without which no amount of guessing produces a `sub` to compare
/// against.
///
/// It is a [`Secret`], so it prints `[REDACTED]`, is zeroed on drop, and cannot
/// be compared with `==`.
///
/// # It is never rotated
///
/// There is no `rotate`, no setter, and no way to replace the bytes of an
/// existing salt — not because rotation is hard, but because it is not a
/// meaningful operation. Every derived `sub` is written to
/// `subject_identifiers` and read back from there, so a new salt would not move
/// an identifier already issued; it would only mean that the same user in the
/// same sector derives *differently* if that row were ever lost. OIDC Core §8
/// says a Subject Identifier is "a locally unique and never reassigned
/// identifier within the Issuer for the End-User", and a `sub` that changes is
/// a relying party's account that vanishes. Recovering from a leaked salt is
/// therefore a reissue of every identifier in the tenant — a relying-party
/// migration — and not a rotation. A tenant's salt is generated once, at
/// creation, and the table it lives in refuses an `UPDATE` for the same reason
/// this type offers no way to ask for one.
pub struct PairwiseSalt(Secret<[u8; PairwiseSalt::LEN]>);

impl PairwiseSalt {
    /// How many bytes of salt. 256 bits, twice the FAPI 2.0 SP §5.4.1 floor for
    /// a credential the user never handles.
    pub const LEN: usize = 32;

    /// Draws a salt from the operating system CSPRNG.
    ///
    /// Called once per tenant, when the tenant is created. Every later use
    /// reads the stored one back.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; Self::LEN];
        // Carrying on after a failure here would derive every subject in the
        // tenant from a buffer of zeros, so there is nothing to fall back to.
        getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
        Self(Secret::new(bytes))
    }

    /// Rebuilds a salt from the plaintext a store decrypted.
    ///
    /// The length check is the point. A salt of any other length — an empty
    /// slice, a truncated row, a value somebody put there by hand — is refused
    /// rather than padded, stretched or hashed into shape. An empty or
    /// predictable salt would leave the derivation with no secret in it at all,
    /// and every `sub` in the deployment would then be computable by anyone who
    /// has read [`Self::derive_subject`]: the sector is public and the local
    /// account id sits in the database next to the answer.
    ///
    /// # Errors
    ///
    /// Returns [`SubjectError::Salt`] unless the material is exactly
    /// [`PairwiseSalt::LEN`] bytes.
    pub fn from_storage(material: &[u8]) -> Result<Self, SubjectError> {
        let bytes: [u8; Self::LEN] = material.try_into().map_err(|_| SubjectError::Salt)?;
        Ok(Self(Secret::new(bytes)))
    }

    /// Wraps a salt whose length the type system already proves.
    ///
    /// For a caller holding an array, and for tests that need a fixed salt to
    /// assert a particular `sub` against. Anywhere the length comes from a
    /// database column or a wire, use [`Self::from_storage`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(Secret::new(bytes))
    }

    /// The salt, for writing it to storage and for nothing else.
    ///
    /// Named rather than a `Deref` so that every call site is greppable, in the
    /// manner of [`Secret::expose`].
    #[must_use]
    pub const fn expose(&self) -> &[u8; Self::LEN] {
        self.0.expose()
    }

    /// Calculates the `sub` a user is known by in one sector — OIDC Core §8.1.
    ///
    /// §8.1 permits any algorithm with three properties, and gives
    /// `sub = SHA-256 ( sector_identifier || local_account_id || salt )` as the
    /// first of the three examples it offers. This is that, with the
    /// concatenation made **injective**:
    ///
    /// ```text
    /// sub = BASE64URL( SHA-256(
    ///           "asterius/pairwise-subject/v1"
    ///        ++ u64be(len(sector)) ++ sector
    ///        ++ u64be(16)          ++ user_id
    ///        ++ salt ) )
    /// ```
    ///
    /// The length prefixes are the difference that matters. Plain concatenation
    /// gives `("ab", "c")` and `("a", "bc")` the same bytes, so it does *not*
    /// guarantee §8.1's "Distinct Sector Identifier values MUST result in
    /// distinct Subject Identifier values" — it only makes a collision
    /// unlikely. Prefixed, two different pairs cannot produce one input, and
    /// the property rests on SHA-256 alone. The same reasoning produces the
    /// audit trail's canonical encoding (`ast-83p.11`), and it is why the salt
    /// goes last: everything before it is self-delimiting, so nothing can be
    /// shifted between fields.
    ///
    /// The three properties §8.1 requires:
    ///
    /// * **Not reversible by any party other than the provider.** The output is
    ///   a SHA-256 digest, and the input carries 256 secret bits. Recovering
    ///   the user from a `sub` means a preimage; confirming a *guessed* user
    ///   means holding the salt.
    /// * **Distinct sectors give distinct subjects.** Injective encoding, then
    ///   SHA-256.
    /// * **Deterministic.** A pure function of the salt and its two arguments —
    ///   no clock, no counter, no database.
    ///
    /// The result is 43 characters of unpadded base64url: URL- and JSON-safe
    /// with no escaping, and well inside the 255 ASCII characters OIDC Core
    /// allows a `sub`.
    ///
    /// Public subjects go through the same call with
    /// [`SectorIdentifier::public`], so a public `sub` does not expose the
    /// internal user id either, and one code path mints both.
    ///
    /// # Why the salt is the receiver and not an argument
    ///
    /// It was an argument once, and a function that takes the salt is a
    /// function a caller can hand the wrong salt to — a freshly generated one,
    /// an empty one, another tenant's. Every one of those mints a `sub` that
    /// looks entirely valid and is wrong permanently, because the first
    /// derivation is the one that gets written to `subject_identifiers` and
    /// handed to a relying party. As a method, the only way to derive is to
    /// already hold the salt, and the only ways to hold one are to have
    /// generated it at tenant creation or to have read it back out of the
    /// store.
    // fuzz-target: pairwise_subject
    #[must_use]
    pub fn derive_subject(&self, sector: &SectorIdentifier, user: UserId) -> SubjectId {
        let mut hasher = Sha256::new();
        hasher.update(SUBJECT_DOMAIN);
        let sector = sector.as_str().as_bytes();
        hasher.update(
            u64::try_from(sector.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(sector);
        let local = user.as_bytes();
        hasher.update(u64::try_from(local.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(local);
        // The salt is the last field and has a fixed length, so nothing after
        // it has to be delimited. This is the one place it is exposed, and it
        // is exposed to a hash.
        hasher.update(self.expose());
        SubjectId::new(URL_SAFE_NO_PAD.encode(hasher.finalize()))
    }
}

impl fmt::Debug for PairwiseSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Domain separation for [`PairwiseSalt::derive_subject`].
///
/// The server computes SHA-256 over several unrelated things — token digests,
/// audit records, this. A constant prefix unique to this computation means no
/// digest taken here can ever be mistaken for, or collide with, one taken
/// somewhere else, whatever the rest of the input turns out to be.
const SUBJECT_DOMAIN: &[u8] = b"asterius/pairwise-subject/v1";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn salt(byte: u8) -> PairwiseSalt {
        PairwiseSalt::from_bytes([byte; PairwiseSalt::LEN])
    }

    fn user(nibble: u128) -> UserId {
        UserId::new(uuid::Uuid::from_u128(nibble))
    }

    fn sector(host: &str) -> SectorIdentifier {
        SectorIdentifier::of_uri(&format!("https://{host}/sector.json")).expect("a sector")
    }

    fn name(raw: &str) -> ClaimName {
        ClaimName::parse(raw).unwrap_or_else(|e| panic!("{raw:?} should be a claim name: {e}"))
    }

    fn claim(value: serde_json::Value) -> Claim {
        Claim::new(value, ClaimSource::Local).expect("a non-null claim")
    }

    /// A registered client, built the way one actually arrives: through the
    /// registration validator, so a document these tests could not register is
    /// not a client these tests can ask about.
    fn client(document: &serde_json::Value) -> Client {
        let registration = crate::ClientRegistration::from_json(
            serde_json::to_vec(document).expect("serialise").as_slice(),
            crate::Capabilities::default(),
        )
        .expect("a valid registration");
        Client {
            tenant: TenantId::new("demo"),
            id: crate::ClientId::new("billing"),
            registration,
            status: crate::ClientStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    // -----------------------------------------------------------------------
    // Subject identifiers
    // -----------------------------------------------------------------------

    /// OIDC Core §8.1: "The algorithm MUST be deterministic."
    #[test]
    fn the_same_user_in_the_same_sector_always_gets_the_same_subject() {
        let subject = salt(7).derive_subject(&sector("rp.example"), user(1));
        assert_eq!(
            salt(7).derive_subject(&sector("rp.example"), user(1)),
            subject
        );
        // Across a freshly built salt holding the same bytes, because the salt
        // is read out of a row on every process start.
        let reloaded = PairwiseSalt::from_bytes(*salt(7).expose());
        assert_eq!(
            reloaded.derive_subject(&sector("rp.example"), user(1)),
            subject
        );
    }

    /// OIDC Core §8.1: "Distinct Sector Identifier values MUST result in
    /// distinct Subject Identifier values." This is the whole privacy claim of
    /// a pairwise subject: two relying parties comparing notes must not be able
    /// to tell that they are talking about one person.
    #[test]
    fn two_sectors_never_see_one_user_under_the_same_subject() {
        let salt = salt(7);
        let here = salt.derive_subject(&sector("rp.example"), user(1));
        let there = salt.derive_subject(&sector("other.example"), user(1));
        assert_ne!(here, there);
        // A public subject is its own sector, so it does not collide with a
        // pairwise one either.
        assert_ne!(
            salt.derive_subject(&SectorIdentifier::public(), user(1)),
            here
        );
    }

    #[test]
    fn two_users_in_one_sector_never_share_a_subject() {
        let salt = salt(7);
        assert_ne!(
            salt.derive_subject(&sector("rp.example"), user(1)),
            salt.derive_subject(&sector("rp.example"), user(2))
        );
    }

    /// Without this, a leaked database from tenant A would let its operator
    /// recognise the same person in tenant B.
    #[test]
    fn two_tenants_derive_different_subjects_for_the_same_user() {
        assert_ne!(
            salt(1).derive_subject(&sector("rp.example"), user(1)),
            salt(2).derive_subject(&sector("rp.example"), user(1))
        );
    }

    /// OIDC Core §8.1: "The Subject Identifier value MUST NOT be reversible by
    /// any party other than the OpenID Provider."
    #[test]
    fn a_subject_carries_neither_the_salt_nor_the_user_it_was_derived_from() {
        let salt = salt(0xAB);
        let subject = salt.derive_subject(&sector("rp.example"), user(0x1234_5678));
        assert!(!subject.as_str().contains("rp.example"));
        assert!(!subject.as_str().contains(&user(0x1234_5678).to_string()));
        let encoded = URL_SAFE_NO_PAD.encode(salt.expose());
        assert!(!subject.as_str().contains(&encoded));
    }

    /// OIDC Core §8 caps a `sub` at 255 ASCII characters, and it travels in a
    /// URL, a JSON string and a JWT payload.
    #[test]
    fn a_derived_subject_is_short_url_safe_and_needs_no_escaping() {
        let subject = salt(7).derive_subject(&sector("rp.example"), user(1));
        assert_eq!(subject.as_str().len(), 43);
        assert!(
            subject
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "left the base64url alphabet: {subject}"
        );
    }

    /// The injective encoding, stated as the case a plain concatenation gets
    /// wrong: `("ab", …)` and `("a", …)` must not be able to line up.
    #[test]
    fn a_sector_boundary_cannot_be_moved_into_the_next_field() {
        let salt = salt(7);
        let left = salt.derive_subject(&SectorIdentifier("ab".to_owned()), user(1));
        let right = salt.derive_subject(&SectorIdentifier("a".to_owned()), user(1));
        assert_ne!(left, right);
    }

    /// OIDC Core §8.1: the sector is the *host* component, so everything else
    /// about the URL is irrelevant — which is exactly what lets a group of
    /// sites share one `sub`.
    #[test]
    fn the_sector_is_the_host_and_nothing_else_about_the_url() {
        for uri in [
            "https://rp.example/sector.json",
            "https://rp.example/other.json",
            "https://rp.example:443/sector.json",
            "https://RP.Example/sector.json",
        ] {
            assert_eq!(
                SectorIdentifier::of_uri(uri).expect("a sector").as_str(),
                "rp.example",
                "{uri} produced a different sector"
            );
        }
    }

    #[test]
    fn a_value_with_no_host_is_not_a_sector() {
        for uri in ["", "not a url", "/sector.json", "urn:example:sector"] {
            assert!(
                SectorIdentifier::of_uri(uri).is_err(),
                "{uri:?} was accepted as a sector"
            );
        }
    }

    /// RFC 8252 §7.3 gives every native client the same loopback host, so a
    /// sector taken from one would put them all in one sector — a `sub` shared
    /// by every native client on the deployment, under a registration that says
    /// `pairwise`.
    #[test]
    fn a_loopback_redirect_host_is_refused_as_a_sector() {
        for host in ["127.0.0.1", "127.4.5.6", "localhost", "[::1]"] {
            let sector = SectorIdentifier::of_uri(&format!("http://{host}:51004/cb"))
                .expect("a host is a host");
            assert!(
                sector.is_shared_by_every_native_client(),
                "{host} was not recognised as a shared loopback host"
            );
        }
        assert!(!sector("rp.example").is_shared_by_every_native_client());
    }

    /// OIDC Core §8.1: with no `sector_identifier_uri`, the sector is the host
    /// of the registered redirect URI; with one, it is that URL's host, which
    /// is what lets a group of sites under one administration share a `sub`.
    #[test]
    fn a_clients_sector_is_the_one_oidc_core_8_1_names() {
        // A public client is in the sentinel sector, whatever it registered.
        assert!(
            SectorIdentifier::of_client(&client(&json!({
                "client_name": "Billing",
                "redirect_uris": ["https://rp.example/cb"],
                "jwks": {"keys": [{"kty": "OKP"}]},
            })))
            .expect("a public client has a sector")
            .is_public()
        );

        // Pairwise, no sector identifier: the host of the redirect URI.
        assert_eq!(
            SectorIdentifier::of_client(&client(&json!({
                "client_name": "Billing",
                "redirect_uris": ["https://rp.example/cb", "https://rp.example/cb2"],
                "jwks": {"keys": [{"kty": "OKP"}]},
                "subject_type": "pairwise",
            })))
            .expect("one host is a sector")
            .as_str(),
            "rp.example"
        );

        // With one, that URL's host — so two hosts under one administration
        // see one `sub`.
        assert_eq!(
            SectorIdentifier::of_client(&client(&json!({
                "client_name": "Billing",
                "redirect_uris": ["https://rp.example/cb", "https://other.example/cb"],
                "jwks": {"keys": [{"kty": "OKP"}]},
                "subject_type": "pairwise",
                "sector_identifier_uri": "https://group.example/sector.json",
            })))
            .expect("a named sector")
            .as_str(),
            "group.example"
        );
    }

    /// RFC 8252 §7.3 gives every native client the same loopback host, so
    /// OIDC Core §8.1's redirect-host rule would put them all in one sector —
    /// a shared, correlatable `sub` under a registration that says `pairwise`.
    /// Such a client has to name a sector of its own.
    #[test]
    fn a_pairwise_native_client_cannot_take_its_sector_from_a_loopback_callback() {
        let error = SectorIdentifier::of_client(&client(&json!({
            "client_name": "Desktop",
            "redirect_uris": ["http://127.0.0.1:51004/cb"],
            "jwks": {"keys": [{"kty": "OKP"}]},
            "application_type": "native",
            "subject_type": "pairwise",
        })))
        .expect_err("a loopback host is not a sector");
        assert!(
            error.to_string().contains("sector_identifier_uri"),
            "{error}"
        );

        // Naming one resolves it.
        assert_eq!(
            SectorIdentifier::of_client(&client(&json!({
                "client_name": "Desktop",
                "redirect_uris": ["http://127.0.0.1:51004/cb"],
                "jwks": {"keys": [{"kty": "OKP"}]},
                "application_type": "native",
                "subject_type": "pairwise",
                "sector_identifier_uri": "https://desktop.example/sector.json",
            })))
            .expect("a named sector")
            .as_str(),
            "desktop.example"
        );
    }

    /// The row is the record of which sector a `sub` belongs to, so a second
    /// spelling of one host would be a second identity for one person in one
    /// place.
    #[test]
    fn a_stored_sector_must_still_be_the_host_a_url_parser_produces() {
        assert_eq!(
            SectorIdentifier::stored("rp.example")
                .expect("a host")
                .as_str(),
            "rp.example"
        );
        assert!(
            SectorIdentifier::stored("")
                .expect("the sentinel")
                .is_public()
        );
        assert_eq!(
            SectorIdentifier::stored("[::1]")
                .expect("an address")
                .as_str(),
            "[::1]"
        );
        for bad in [
            "RP.Example",
            "rp.example/x",
            "rp.example:443",
            "rp example",
            "/",
        ] {
            assert!(
                SectorIdentifier::stored(bad).is_err(),
                "accepted the stored sector {bad:?}"
            );
        }
    }

    #[test]
    fn the_public_sentinel_is_the_empty_sector_the_schema_uses() {
        assert_eq!(SectorIdentifier::public().as_str(), "");
        assert!(SectorIdentifier::public().is_public());
        assert!(!sector("rp.example").is_public());
    }

    #[test]
    fn a_salt_never_prints_itself() {
        let salt = salt(0xCD);
        assert_eq!(format!("{salt:?}"), "[REDACTED]");
        assert!(!format!("{salt:?}").contains("cd"));
    }

    /// A salt that is not 256 bits is refused rather than repaired. An empty
    /// one is the case that matters: it would leave the derivation with no
    /// secret in it, and every `sub` in the deployment would be computable by
    /// anyone who knows the algorithm, since the sector is public and the local
    /// account id is stored beside the answer.
    #[test]
    fn a_stored_salt_that_is_not_256_bits_is_refused_not_stretched() {
        for length in [0_usize, 1, 8, 16, 31, 33, 64] {
            let material = vec![0x11; length];
            assert!(
                matches!(
                    PairwiseSalt::from_storage(&material),
                    Err(SubjectError::Salt)
                ),
                "{length} bytes was accepted as a pairwise salt"
            );
        }

        let material = [0x11_u8; PairwiseSalt::LEN];
        let recovered = PairwiseSalt::from_storage(&material).expect("32 bytes is a salt");
        assert_eq!(recovered.expose(), &material);
        // And it derives exactly what the same bytes derive through the
        // infallible constructor, so the two paths cannot diverge.
        assert_eq!(
            recovered.derive_subject(&sector("rp.example"), user(1)),
            PairwiseSalt::from_bytes(material).derive_subject(&sector("rp.example"), user(1))
        );
    }

    // -----------------------------------------------------------------------
    // Claims
    // -----------------------------------------------------------------------

    /// OIDC Core §5.1's standard claims are ordinary members of the bag: no
    /// column, no enum, no migration when the next profile adds twenty more.
    #[test]
    fn the_standard_claims_are_ordinary_members_of_the_bag() {
        let mut claims = ClaimSet::new();
        for standard in [
            "name",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "phone_number",
            "phone_number_verified",
            "address",
        ] {
            claims.insert(name(standard), claim(json!("value")));
        }
        assert_eq!(claims.len(), 16);
        assert_eq!(
            claims.get(&name("address")).map(Claim::value),
            Some(&json!("value"))
        );
    }

    /// OIDC Core §5.2: the language tag is part of the member name, so the
    /// tagged and untagged spellings are two claims and both are stored.
    #[test]
    fn a_language_tagged_claim_is_a_claim_of_its_own() {
        let tagged = name("family_name#ja-Kana-JP");
        assert_eq!(tagged.base(), "family_name");
        assert_eq!(tagged.language_tag(), Some("ja-Kana-JP"));
        assert_eq!(name("family_name").language_tag(), None);

        let mut claims = ClaimSet::new();
        claims.insert(name("family_name"), claim(json!("Kudo")));
        claims.insert(tagged, claim(json!("クドウ")));
        claims.insert(name("family_name#en"), claim(json!("Kudo")));
        assert_eq!(claims.len(), 3);
        assert_eq!(claims.variants("family_name").count(), 3);
        assert_eq!(claims.variants("given_name").count(), 0);
    }

    /// A URI-shaped claim name with a fragment is ambiguous under §5.2, so it
    /// is an error rather than a name silently read as carrying a language.
    #[test]
    fn a_suffix_that_is_not_a_language_tag_is_refused_rather_than_guessed_at() {
        for bad in [
            "https://claims.example/roles#nope!",
            "roles#",
            "roles#-en",
            "roles#toolongsubtag",
            "roles#en-",
            "roles#en--GB",
            "roles#123",
        ] {
            assert_eq!(
                ClaimName::parse(bad),
                Err(ClaimError::LanguageTag),
                "accepted {bad:?}"
            );
        }
        // A URI-shaped name without a fragment is fine: enterprise and IDA
        // claims are routinely spelled this way.
        assert_eq!(
            name("https://claims.example/roles").base(),
            "https://claims.example/roles"
        );
    }

    /// The bag must not be able to say who the user is. A stored `sub` would be
    /// an impersonation primitive the moment the claims service projected it.
    #[test]
    fn a_user_record_cannot_assert_a_claim_the_server_issues() {
        for reserved in [
            "sub", "iss", "aud", "exp", "iat", "acr", "amr", "cnf", "sid",
        ] {
            assert_eq!(
                ClaimName::parse(reserved),
                Err(ClaimError::Reserved(reserved)),
                "accepted {reserved:?}"
            );
            // A language tag does not launder it.
            assert_eq!(
                ClaimName::parse(&format!("{reserved}#en")),
                Err(ClaimError::Reserved(reserved))
            );
        }
    }

    /// Two homes for one value is two homes that can disagree, and the schema
    /// has an opinion about these three.
    #[test]
    fn a_claim_that_has_a_column_cannot_also_live_in_the_bag() {
        for held in ["email", "email_verified", "updated_at"] {
            assert_eq!(
                ClaimName::parse(held),
                Err(ClaimError::Reserved(held)),
                "accepted {held:?}"
            );
        }
    }

    /// A claim name is rendered on a consent screen and written into logs.
    #[test]
    fn a_claim_name_may_not_reorder_what_a_human_reads() {
        for (bad, expected) in [
            ("na\u{202e}me", '\u{202e}'),
            ("na\u{200f}me", '\u{200f}'),
            ("na\u{2066}me", '\u{2066}'),
            ("na\nme", '\n'),
            ("na\u{0}me", '\u{0}'),
            ("na me", ' '),
        ] {
            assert_eq!(
                ClaimName::parse(bad),
                Err(ClaimError::NameCharacter(u32::from(expected))),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn a_claim_name_is_bounded_at_both_ends() {
        assert_eq!(
            ClaimName::parse(""),
            Err(ClaimError::NameLength { found: 0 })
        );
        assert_eq!(
            ClaimName::parse("#en"),
            Err(ClaimError::NameLength { found: 0 }),
            "a name that is only a language tag names nothing"
        );
        let long = "a".repeat(ClaimName::MAX_LEN + 1);
        assert_eq!(
            ClaimName::parse(&long),
            Err(ClaimError::NameLength {
                found: ClaimName::MAX_LEN + 1
            })
        );
        assert!(ClaimName::parse(&"a".repeat(ClaimName::MAX_LEN)).is_ok());
    }

    /// OIDC Core §5.3.2: a claim that is not available is omitted. A stored
    /// `null` is neither absent nor a value.
    #[test]
    fn a_null_claim_value_is_refused_rather_than_stored_as_nothing() {
        assert_eq!(
            Claim::new(json!(null), ClaimSource::Local),
            Err(ClaimError::NullValue)
        );
        // Everything else JSON can hold is a claim, including the empty ones:
        // an empty string is a value the user typed.
        for value in [json!(""), json!(0), json!(false), json!([]), json!({})] {
            assert!(
                Claim::new(value.clone(), ClaimSource::Local).is_ok(),
                "{value}"
            );
        }
    }

    /// The source is what makes the model issuer-agnostic: a claim asserted by
    /// another issuer is the same shape as a local one.
    #[test]
    fn a_claim_records_which_issuer_asserted_it() {
        let upstream = Issuer::parse("https://op.example").expect("an issuer");
        let claim = Claim::new(json!("Alice"), ClaimSource::Issuer(upstream.clone()))
            .expect("a claim")
            .verified(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(claim.source(), &ClaimSource::Issuer(upstream));
        assert_eq!(claim.source().as_str(), "https://op.example");
        assert_eq!(claim.verified_at(), Some(OffsetDateTime::UNIX_EPOCH));

        for word in ["local", "admin", "import"] {
            assert_eq!(
                ClaimSource::parse(word).as_ref().map(ClaimSource::as_str),
                Some(word)
            );
        }
        assert_eq!(ClaimSource::parse("nonsense"), None);
        assert_eq!(
            ClaimSource::parse("http://op.example"),
            None,
            "an issuer must be https, so a plain word cannot become one"
        );
    }

    // -----------------------------------------------------------------------
    // Storage round trip
    // -----------------------------------------------------------------------

    /// The bag is one JSONB column, so its wire shape is part of the schema
    /// even though the schema does not describe it.
    #[test]
    fn a_claim_set_round_trips_through_the_json_it_is_stored_as() {
        let mut claims = ClaimSet::new();
        claims.insert(name("name"), claim(json!("Alice")));
        claims.insert(
            name("family_name#ja-Kana-JP"),
            Claim::new(json!("クドウ"), ClaimSource::Admin)
                .expect("a claim")
                .verified(OffsetDateTime::UNIX_EPOCH),
        );

        let encoded = serde_json::to_value(&claims).expect("serialise");
        assert_eq!(
            encoded,
            json!({
                "family_name#ja-Kana-JP": {
                    "value": "クドウ",
                    "source": "admin",
                    "verified_at": "1970-01-01T00:00:00Z"
                },
                "name": { "value": "Alice", "source": "local" }
            })
        );
        let decoded: ClaimSet = serde_json::from_value(encoded).expect("deserialise");
        assert_eq!(decoded, claims);
    }

    /// Rows get edited by hand during incidents. The rule that guards the write
    /// guards the read, so a bag that has grown a `sub` fails to load rather
    /// than reaching a token.
    #[test]
    fn a_hand_edited_claim_bag_fails_to_load_rather_than_reaching_a_token() {
        for hostile in [
            json!({ "sub": { "value": "victim", "source": "admin" } }),
            json!({ "email": { "value": "a@b.example", "source": "admin" } }),
            json!({ "na\u{202e}me": { "value": "x", "source": "admin" } }),
            json!({ "name": { "value": null, "source": "admin" } }),
            json!({ "name": { "value": "x", "source": "who-knows" } }),
            json!({ "name": { "value": "x", "source": "local", "evidence": {} } }),
            json!({ "name": { "value": "x" } }),
            json!({ "name": { "value": "x", "source": "local", "verified_at": "yesterday" } }),
        ] {
            assert!(
                serde_json::from_value::<ClaimSet>(hostile.clone()).is_err(),
                "loaded a claim bag that should have been refused: {hostile}"
            );
        }
    }

    #[test]
    fn a_user_status_survives_the_column_it_is_stored_in() {
        for status in [UserStatus::Active, UserStatus::Disabled, UserStatus::Locked] {
            assert_eq!(UserStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(UserStatus::parse("suspended"), None);
        assert_eq!(UserStatus::parse("ACTIVE"), None);
    }

    #[test]
    fn only_an_active_account_authenticates() {
        let mut user = User {
            tenant: TenantId::new("demo"),
            id: user(1),
            username: "alice".to_owned(),
            email: None,
            email_verified: false,
            status: UserStatus::Active,
            claims: ClaimSet::new(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(user.can_authenticate());
        for status in [UserStatus::Disabled, UserStatus::Locked] {
            user.status = status;
            assert!(!user.can_authenticate(), "{status:?} authenticated");
        }
    }

    // -----------------------------------------------------------------------
    // Properties
    //
    // The cases above are the ones a reader can check against OIDC Core §8.1.
    // These are what has to hold for every input, which is where a derivation
    // or an encoding actually goes wrong.
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: 256,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(config())]

        /// §8.1's three properties over generated inputs: deterministic,
        /// distinct sectors give distinct subjects, and the shape holds.
        #[test]
        fn the_derivation_is_deterministic_and_separates_every_sector(
            left_sector in "[a-z]{1,12}(\\.[a-z]{2,4})?",
            right_sector in "[a-z]{1,12}(\\.[a-z]{2,4})?",
            left_user in any::<u128>(),
            right_user in any::<u128>(),
            salt_byte in any::<u8>(),
        ) {
            let salt = salt(salt_byte);
            let left = SectorIdentifier(left_sector.clone());
            let right = SectorIdentifier(right_sector.clone());

            let subject = salt.derive_subject(&left, user(left_user));
            let again = salt.derive_subject(&left, user(left_user));
            prop_assert_eq!(again.as_str(), subject.as_str());
            prop_assert_eq!(subject.as_str().len(), 43);

            // Distinct inputs, distinct subject. The encoding is injective, so
            // an equality here would be a SHA-256 collision.
            if left_sector != right_sector || left_user != right_user {
                let other = salt.derive_subject(&right, user(right_user));
                prop_assert_ne!(other.as_str(), subject.as_str());
            }
        }

        /// Whatever a name is, `parse` answers rather than panicking, and
        /// whatever it accepts satisfies what the rest of the model assumes.
        #[test]
        fn an_accepted_claim_name_always_satisfies_the_rules_it_was_parsed_against(
            raw in ".{0,200}",
        ) {
            let Ok(parsed) = ClaimName::parse(&raw) else { return Ok(()) };
            prop_assert_eq!(parsed.as_str(), raw.as_str(), "a claim name was rewritten");
            prop_assert!(!parsed.base().is_empty());
            prop_assert!(!SERVER_ISSUED.contains(&parsed.base()));
            prop_assert!(!HELD_IN_A_COLUMN.contains(&parsed.base()));
            prop_assert!(!parsed.as_str().chars().any(|c| c.is_control() || c.is_whitespace()));
            if let Some(tag) = parsed.language_tag() {
                prop_assert!(is_language_tag(tag));
                prop_assert_eq!(format!("{}#{tag}", parsed.base()), raw);
            }
            // And it survives the column it is about to be stored in.
            let mut claims = ClaimSet::new();
            claims.insert(parsed, claim(json!("x")));
            let encoded = serde_json::to_value(&claims).expect("serialise");
            prop_assert_eq!(
                serde_json::from_value::<ClaimSet>(encoded).expect("deserialise"),
                claims
            );
        }
    }
}
