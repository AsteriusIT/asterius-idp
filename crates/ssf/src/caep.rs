//! The CAEP and RISC events this transmitter emits (`ast-0ju.8`).
//!
//! CAEP 1.0 (Final) §2 defines four claims every event may carry —
//! `event_timestamp`, `initiating_entity`, `reason_admin`, `reason_user` — and
//! §3 defines the event-specific ones. RISC 1.0 (Final) defines
//! `account-disabled` and `account-enabled`. [`crate::SecurityEvent`] is the
//! envelope those claims go in; this module is the *vocabulary*, and its job
//! is that a caller cannot spell a claim value the specification does not
//! define.
//!
//! | Event | Type URI | Event-specific claims |
//! |---|---|---|
//! | CAEP §3.1 session-revoked | [`SESSION_REVOKED`] | none |
//! | CAEP §3.3 credential-change | [`CREDENTIAL_CHANGE`] | `credential_type`, `change_type`, `friendly_name`, `x509_issuer`, `x509_serial`, `fido2_aaguid` |
//! | CAEP §3.4 assurance-level-change | [`ASSURANCE_LEVEL_CHANGE`] | `namespace`, `current_level`, `previous_level`, `change_direction` |
//! | RISC account-disabled | [`ACCOUNT_DISABLED`] | `reason` |
//! | RISC account-enabled | [`ACCOUNT_ENABLED`] | none |
//!
//! # Every value a receiver dispatches on is a closed set
//!
//! `initiating_entity`, `credential_type`, `change_type`, `change_direction`
//! and RISC's `reason` are enumerations in the specifications and enumerations
//! here. There is no constructor taking a `&str` for any of them: a receiver
//! that reads `"fido2_platform"` where the specification says `fido2-platform`
//! drops the event or, worse, files it under "unknown credential" — and a
//! transmitter that can emit the misspelling is one typo away from doing so.
//!
//! # `event_timestamp` is always present
//!
//! §2 makes it OPTIONAL. It is not optional here: [`EventDetails::at`] is the
//! only way to build the common claims, so an event without one cannot be
//! rendered. A receiver correlating a `session-revoked` with its own sign-in
//! log needs the instant the session ended, not the instant the outbox got
//! round to signing the SET, which is what `iat` says.
//!
//! # The free-text members are bounded
//!
//! `friendly_name`, `x509_issuer`, `x509_serial`, the two `reason_*` messages,
//! and the assurance `namespace` and levels are strings a caller supplies from
//! stored data. Each goes through [`text`], which refuses an empty value, a
//! value over [`MAX_TEXT_LEN`] characters, and a control character: a SET is
//! bounded at [`crate::MAX_SET_CLAIMS_BYTES`] and these members are the only
//! ones that could grow, and a control character in `reason_admin` is a line
//! injected into a receiver's log.

use crate::event::{EventUri, SecurityEvent};
use serde_json::{Map, Value};
use thiserror::Error;
use time::OffsetDateTime;

/// CAEP 1.0 §3.1: a session was revoked.
pub const SESSION_REVOKED: &str =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

/// CAEP 1.0 §3.3: a credential was created, revoked, updated or deleted.
pub const CREDENTIAL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";

/// CAEP 1.0 §3.4: the assurance level of a session changed.
pub const ASSURANCE_LEVEL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";

/// RISC 1.0: an account was disabled.
pub const ACCOUNT_DISABLED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

/// RISC 1.0: an account was enabled again.
pub const ACCOUNT_ENABLED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled";

/// Every event type URI this module can emit, in the order above.
///
/// This is what `events_supported` advertises
/// ([`crate::stream::SUPPORTED_EVENTS`]): a type is in this list because there
/// is code in this module that renders it, and for no other reason.
pub const EVENT_TYPES: [&str; 5] = [
    SESSION_REVOKED,
    CREDENTIAL_CHANGE,
    ASSURANCE_LEVEL_CHANGE,
    ACCOUNT_DISABLED,
    ACCOUNT_ENABLED,
];

/// The longest free-text member this module will emit, in characters.
///
/// The same bound as a subject identifier member
/// ([`crate::MAX_MEMBER_LEN`]): an identifier-sized string. A `reason_admin`
/// longer than this is prose, and prose belongs in the audit trail, not in a
/// token pushed to a third party.
pub const MAX_TEXT_LEN: usize = 255;

/// Why an event claim was refused.
///
/// The message names the member and never its value: `friendly_name` is a
/// string a person typed, and these strings reach a log.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CaepError {
    /// A free-text member was empty.
    #[error("the {0} member must not be empty")]
    Empty(&'static str),
    /// A free-text member was longer than [`MAX_TEXT_LEN`].
    #[error("the {member} member is {found} characters, maximum is {max}", max = MAX_TEXT_LEN)]
    TooLong {
        /// Which member.
        member: &'static str,
        /// How long it was.
        found: usize,
    },
    /// A free-text member carried a control character.
    ///
    /// A `reason_admin` is "intended for logging and auditing" (CAEP §2), so
    /// what goes in it is going to be written to somebody's log verbatim.
    #[error("the {0} member must not contain a control character")]
    Control(&'static str),
    /// A language tag was not one this module will emit.
    ///
    /// `reason_admin` and `reason_user` are objects keyed by BCP 47 tags. The
    /// tag is not validated against the registry — that is a table nobody
    /// should embed in a token issuer — but it is held to the shape of one:
    /// ASCII letters, digits and hyphens, one to 35 characters (RFC 5646 §2.1
    /// bounds a tag at 35 with all extensions present).
    #[error("a reason's language tag must be an ASCII language tag")]
    LanguageTag,
    /// The assurance levels before and after a change are the same.
    ///
    /// CAEP §3.4 is about a *change*; an event whose `previous_level` equals
    /// its `current_level` is a receiver told that nothing happened, with a
    /// `change_direction` that is then a lie either way.
    #[error("an assurance-level-change must name two different levels")]
    SameLevel,
}

/// Validates one free-text member.
///
/// Characters, not bytes, for the same reason as a subject identifier member:
/// a non-ASCII friendly name is legitimate and the bound is a guard against a
/// stored value that grew, not a wire limit.
// fuzz-target: ssf_caep_text
pub fn text(name: &'static str, value: &str) -> Result<String, CaepError> {
    if value.is_empty() {
        return Err(CaepError::Empty(name));
    }
    let found = value.chars().count();
    if found > MAX_TEXT_LEN {
        return Err(CaepError::TooLong {
            member: name,
            found,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(CaepError::Control(name));
    }
    Ok(value.to_owned())
}

/// Validates the shape of a BCP 47 language tag (RFC 5646 §2.1).
fn language_tag(value: &str) -> Result<String, CaepError> {
    const MAX_TAG_LEN: usize = 35;
    let well_formed = !value.is_empty()
        && value.len() <= MAX_TAG_LEN
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if well_formed {
        Ok(value.to_owned())
    } else {
        Err(CaepError::LanguageTag)
    }
}

/// CAEP §2's `initiating_entity`: who or what caused the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InitiatingEntity {
    /// An administrative action.
    Admin,
    /// The user themself.
    User,
    /// A policy evaluation, with nobody at the keyboard.
    Policy,
    /// The system: a rotation, an expiry, a sweep.
    System,
}

impl InitiatingEntity {
    /// The value, as §2 spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
            Self::Policy => "policy",
            Self::System => "system",
        }
    }
}

/// A localized message: CAEP §2's `reason_admin` and `reason_user` are objects
/// "with a BCP47 language tag as the key and the locale-specific ... message
/// as the value".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    language: String,
    message: String,
}

impl Reason {
    /// A message in one language.
    ///
    /// # Errors
    ///
    /// [`CaepError`] if the tag is not shaped like a language tag or the
    /// message is empty, oversized or carries a control character.
    pub fn new(language: &str, message: &str) -> Result<Self, CaepError> {
        Ok(Self {
            language: language_tag(language)?,
            message: text("reason", message)?,
        })
    }

    /// A message in English, which is what this server's own reasons are.
    ///
    /// # Errors
    ///
    /// As [`Reason::new`].
    pub fn english(message: &str) -> Result<Self, CaepError> {
        Self::new("en", message)
    }

    fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert(self.language.clone(), Value::from(self.message.as_str()));
        Value::Object(object)
    }
}

/// CAEP §2: the claims every event may carry.
///
/// Built from the instant the event happened, which is the one member that is
/// not optional here (see the module docs), then decorated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDetails {
    at: OffsetDateTime,
    initiating_entity: Option<InitiatingEntity>,
    reason_admin: Option<Reason>,
    reason_user: Option<Reason>,
}

impl EventDetails {
    /// The common claims of an event that happened at `when`.
    #[must_use]
    pub const fn at(when: OffsetDateTime) -> Self {
        Self {
            at: when,
            initiating_entity: None,
            reason_admin: None,
            reason_user: None,
        }
    }

    /// Sets `initiating_entity`.
    #[must_use]
    pub const fn initiated_by(mut self, entity: InitiatingEntity) -> Self {
        self.initiating_entity = Some(entity);
        self
    }

    /// Sets `reason_admin`: the message "intended for logging and auditing".
    #[must_use]
    pub fn reason_admin(mut self, reason: Reason) -> Self {
        self.reason_admin = Some(reason);
        self
    }

    /// Sets `reason_user`: the message "intended for display to the user".
    #[must_use]
    pub fn reason_user(mut self, reason: Reason) -> Self {
        self.reason_user = Some(reason);
        self
    }

    /// When the event happened.
    #[must_use]
    pub const fn when(&self) -> OffsetDateTime {
        self.at
    }

    fn decorate(&self, mut event: SecurityEvent) -> SecurityEvent {
        event = event.at(self.at);
        if let Some(entity) = self.initiating_entity {
            event = event.with("initiating_entity", Value::from(entity.as_str()));
        }
        if let Some(reason) = &self.reason_admin {
            event = event.with("reason_admin", reason.to_json());
        }
        if let Some(reason) = &self.reason_user {
            event = event.with("reason_user", reason.to_json());
        }
        event
    }
}

/// Parses one of this module's own URIs, which are constants and known good.
fn uri(constant: &'static str) -> EventUri {
    EventUri::parse(constant).expect("the event type URIs in this module are valid by inspection")
}

/// CAEP §3.1: `session-revoked`. No event-specific claims.
///
/// What names the session is the SET's `sub_id`: a complex subject with a
/// `user` and a `session` member ([`crate::ComplexSubject`]), which is how the
/// specification applies the event to one session rather than to every
/// session of the user.
#[must_use]
pub fn session_revoked(details: &EventDetails) -> SecurityEvent {
    details.decorate(SecurityEvent::new(uri(SESSION_REVOKED)))
}

/// CAEP §3.3's `credential_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CredentialType {
    /// A password.
    Password,
    /// A PIN.
    Pin,
    /// An X.509 certificate.
    X509,
    /// A FIDO2 platform authenticator: bound to the device it was made on.
    Fido2Platform,
    /// A FIDO2 roaming authenticator: a key that moves between devices.
    Fido2Roaming,
    /// A FIDO U2F authenticator.
    FidoU2f,
    /// A verifiable credential.
    VerifiableCredential,
    /// A phone reached by voice.
    PhoneVoice,
    /// A phone reached by SMS.
    PhoneSms,
    /// An authenticator app.
    App,
}

impl CredentialType {
    /// The value, as §3.3 spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Pin => "pin",
            Self::X509 => "x509",
            Self::Fido2Platform => "fido2-platform",
            Self::Fido2Roaming => "fido2-roaming",
            Self::FidoU2f => "fido-u2f",
            Self::VerifiableCredential => "verifiable-credential",
            Self::PhoneVoice => "phone-voice",
            Self::PhoneSms => "phone-sms",
            Self::App => "app",
        }
    }

    /// Which FIDO2 type a passkey is, from what WebAuthn told us.
    ///
    /// `attachment` is the `authenticatorAttachment` the browser reported at
    /// registration (WebAuthn L3 §5.1: `platform` or `cross-platform`), when
    /// it did. When it did not — an older browser, or a credential registered
    /// before the page sent it — the backup-eligible flag (WebAuthn L3 §6.1.3)
    /// stands in: a credential that *can* be synced is a platform passkey in
    /// every implementation shipped so far, and a security key cannot be.
    #[must_use]
    pub fn fido2(attachment: Option<&str>, backup_eligible: bool) -> Self {
        match attachment {
            Some("platform") => Self::Fido2Platform,
            Some("cross-platform") => Self::Fido2Roaming,
            _ if backup_eligible => Self::Fido2Platform,
            _ => Self::Fido2Roaming,
        }
    }
}

/// CAEP §3.3's `change_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeType {
    /// A credential was added.
    Create,
    /// A credential was revoked: it exists but may no longer be used.
    Revoke,
    /// A credential was changed for another of the same kind.
    Update,
    /// A credential was removed.
    Delete,
}

impl ChangeType {
    /// The value, as §3.3 spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Revoke => "revoke",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// CAEP §3.3: `credential-change`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialChange {
    credential_type: CredentialType,
    change_type: ChangeType,
    friendly_name: Option<String>,
    x509_issuer: Option<String>,
    x509_serial: Option<String>,
    fido2_aaguid: Option<String>,
}

impl CredentialChange {
    /// The two required members.
    #[must_use]
    pub const fn new(credential_type: CredentialType, change_type: ChangeType) -> Self {
        Self {
            credential_type,
            change_type,
            friendly_name: None,
            x509_issuer: None,
            x509_serial: None,
            fido2_aaguid: None,
        }
    }

    /// Sets `friendly_name`: the label the user gave the credential.
    ///
    /// # Errors
    ///
    /// [`CaepError`] if the name is empty, oversized or carries a control
    /// character.
    pub fn friendly_name(mut self, name: &str) -> Result<Self, CaepError> {
        self.friendly_name = Some(text("friendly_name", name)?);
        Ok(self)
    }

    /// Sets `x509_issuer` and `x509_serial` together: one without the other
    /// does not name a certificate.
    ///
    /// # Errors
    ///
    /// [`CaepError`] if either is empty, oversized or carries a control
    /// character.
    pub fn x509(mut self, issuer: &str, serial: &str) -> Result<Self, CaepError> {
        self.x509_issuer = Some(text("x509_issuer", issuer)?);
        self.x509_serial = Some(text("x509_serial", serial)?);
        Ok(self)
    }

    /// Sets `fido2_aaguid`: the authenticator model, as the AAGUID's hyphenated
    /// UUID form.
    #[must_use]
    pub fn fido2_aaguid(mut self, aaguid: uuid::Uuid) -> Self {
        self.fido2_aaguid = Some(aaguid.hyphenated().to_string());
        self
    }

    /// The event.
    #[must_use]
    pub fn into_event(self, details: &EventDetails) -> SecurityEvent {
        let mut event = SecurityEvent::new(uri(CREDENTIAL_CHANGE))
            .with(
                "credential_type",
                Value::from(self.credential_type.as_str()),
            )
            .with("change_type", Value::from(self.change_type.as_str()));
        for (name, value) in [
            ("friendly_name", self.friendly_name),
            ("x509_issuer", self.x509_issuer),
            ("x509_serial", self.x509_serial),
            ("fido2_aaguid", self.fido2_aaguid),
        ] {
            if let Some(value) = value {
                event = event.with(name, Value::from(value));
            }
        }
        details.decorate(event)
    }
}

/// CAEP §3.4's `change_direction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeDirection {
    /// The session is now more strongly authenticated.
    Increase,
    /// The session is now less strongly authenticated.
    Decrease,
}

impl ChangeDirection {
    /// The value, as §3.4 spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Increase => "increase",
            Self::Decrease => "decrease",
        }
    }
}

/// CAEP §3.4: `assurance-level-change`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssuranceLevelChange {
    namespace: String,
    current_level: String,
    previous_level: String,
    change_direction: ChangeDirection,
}

impl AssuranceLevelChange {
    /// All four members, which §3.4 makes REQUIRED.
    ///
    /// `namespace` says what vocabulary the two levels are in. For a session
    /// whose levels are this server's `acr` values, that is the tenant's
    /// issuer: the values are defined by the OP that assigns them, and a
    /// receiver that has seen them in an ID token's `acr` knows them by that
    /// issuer.
    ///
    /// # Errors
    ///
    /// [`CaepError`] if a member is empty, oversized or carries a control
    /// character, or if the two levels are the same.
    // fuzz-target: ssf_caep_assurance_level_change
    pub fn new(
        namespace: &str,
        current_level: &str,
        previous_level: &str,
        change_direction: ChangeDirection,
    ) -> Result<Self, CaepError> {
        let current_level = text("current_level", current_level)?;
        let previous_level = text("previous_level", previous_level)?;
        if current_level == previous_level {
            return Err(CaepError::SameLevel);
        }
        Ok(Self {
            namespace: text("namespace", namespace)?,
            current_level,
            previous_level,
            change_direction,
        })
    }

    /// The event.
    #[must_use]
    pub fn into_event(self, details: &EventDetails) -> SecurityEvent {
        let event = SecurityEvent::new(uri(ASSURANCE_LEVEL_CHANGE))
            .with("namespace", Value::from(self.namespace))
            .with("current_level", Value::from(self.current_level))
            .with("previous_level", Value::from(self.previous_level))
            .with(
                "change_direction",
                Value::from(self.change_direction.as_str()),
            );
        details.decorate(event)
    }
}

/// RISC 1.0's `reason` on `account-disabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisabledReason {
    /// The account was taken over.
    Hijacking,
    /// The account was one of a batch created by a bad actor.
    BulkAccount,
}

impl DisabledReason {
    /// The value, as RISC spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hijacking => "hijacking",
            Self::BulkAccount => "bulk-account",
        }
    }
}

/// RISC 1.0: `account-disabled`, with its optional `reason`.
///
/// `None` is the usual case: an administrator switched the account off and
/// said no more, and RISC's two reasons are both accusations this server has
/// no grounds to make on its own.
#[must_use]
pub fn account_disabled(details: &EventDetails, reason: Option<DisabledReason>) -> SecurityEvent {
    let mut event = SecurityEvent::new(uri(ACCOUNT_DISABLED));
    if let Some(reason) = reason {
        event = event.with("reason", Value::from(reason.as_str()));
    }
    details.decorate(event)
}

/// RISC 1.0: `account-enabled`. No event-specific claims.
#[must_use]
pub fn account_enabled(details: &EventDetails) -> SecurityEvent {
    details.decorate(SecurityEvent::new(uri(ACCOUNT_ENABLED)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subject::{ComplexSubject, SimpleSubject};
    use crate::{Set, StreamAudience, Txn};
    use asterius_domain::Issuer;
    use serde_json::json;

    fn at() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("a time")
    }

    /// Renders the event as the `events` claim of an issued SET, so the
    /// goldens below are what a receiver would read after verifying the JWS.
    fn issued(event: SecurityEvent) -> Value {
        let issuer = Issuer::parse("https://as.example/t/demo").expect("an issuer");
        let audience = StreamAudience::single("https://receiver.example").expect("an audience");
        let subject = SimpleSubject::iss_sub(&issuer, "u-1").expect("a subject");
        Set::about(subject)
            .reporting(event)
            .caused_by(Txn::generate())
            .issue(&issuer, &audience, at())
            .expect("a SET")
            .claims()
            .clone()
    }

    /// CAEP §2: `event_timestamp` is seconds since the epoch; every other
    /// common claim is present only when set.
    #[test]
    fn the_common_claims_render_as_caep_section_2_spells_them() {
        let details = EventDetails::at(at())
            .initiated_by(InitiatingEntity::Admin)
            .reason_admin(Reason::english("Suspicious sign-in").expect("a reason"))
            .reason_user(Reason::new("fr", "Connexion suspecte").expect("a reason"));

        let claims = issued(session_revoked(&details));

        assert_eq!(
            claims["events"][SESSION_REVOKED],
            json!({
                "event_timestamp": 1_760_000_000_i64,
                "initiating_entity": "admin",
                "reason_admin": {"en": "Suspicious sign-in"},
                "reason_user": {"fr": "Connexion suspecte"},
            })
        );
    }

    /// CAEP §3.1: no event-specific claims; the session is named by the
    /// complex `sub_id` (SSF 1.0 §3.3), and `event_timestamp` is always there.
    #[test]
    fn golden_session_revoked() {
        let issuer = Issuer::parse("https://as.example/t/demo").expect("an issuer");
        let subject = ComplexSubject::of_user(SimpleSubject::iss_sub(&issuer, "u-1").expect("sub"))
            .with_session(SimpleSubject::opaque("sid-1").expect("a sid"));
        let audience = StreamAudience::single("https://receiver.example").expect("an audience");

        let claims = Set::about(subject)
            .reporting(session_revoked(
                &EventDetails::at(at()).initiated_by(InitiatingEntity::User),
            ))
            .issue(&issuer, &audience, at())
            .expect("a SET")
            .claims()
            .clone();

        assert_eq!(
            claims["sub_id"],
            json!({
                "user": {"format": "iss_sub", "iss": "https://as.example/t/demo", "sub": "u-1"},
                "session": {"format": "opaque", "id": "sid-1"},
            })
        );
        assert_eq!(
            claims["events"],
            json!({
                SESSION_REVOKED: {
                    "event_timestamp": 1_760_000_000_i64,
                    "initiating_entity": "user",
                },
            })
        );
    }

    /// CAEP §3.3: a passkey created on a platform authenticator.
    #[test]
    fn golden_credential_change_for_a_new_passkey() {
        let aaguid = uuid::Uuid::parse_str("adce0002-35bc-c60a-648b-0b25f1f05503").expect("uuid");
        let change = CredentialChange::new(CredentialType::Fido2Platform, ChangeType::Create)
            .friendly_name("Laptop")
            .expect("a name")
            .fido2_aaguid(aaguid);

        let claims =
            issued(change.into_event(&EventDetails::at(at()).initiated_by(InitiatingEntity::User)));

        assert_eq!(
            claims["events"][CREDENTIAL_CHANGE],
            json!({
                "event_timestamp": 1_760_000_000_i64,
                "initiating_entity": "user",
                "credential_type": "fido2-platform",
                "change_type": "create",
                "friendly_name": "Laptop",
                "fido2_aaguid": "adce0002-35bc-c60a-648b-0b25f1f05503",
            })
        );
    }

    /// CAEP §3.3: the x509 members travel together, and the optional ones
    /// are absent rather than null.
    #[test]
    fn golden_credential_change_for_a_certificate() {
        let change = CredentialChange::new(CredentialType::X509, ChangeType::Revoke)
            .x509("CN=Example CA", "1234")
            .expect("a certificate");

        let claims = issued(change.into_event(&EventDetails::at(at())));

        assert_eq!(
            claims["events"][CREDENTIAL_CHANGE],
            json!({
                "event_timestamp": 1_760_000_000_i64,
                "credential_type": "x509",
                "change_type": "revoke",
                "x509_issuer": "CN=Example CA",
                "x509_serial": "1234",
            })
        );
    }

    /// CAEP §3.4: a step-up from a password to a passkey, in the tenant's
    /// own namespace.
    #[test]
    fn golden_assurance_level_change() {
        let change = AssuranceLevelChange::new(
            "https://as.example/t/demo",
            "urn:asterius:acr:passkey",
            "urn:asterius:acr:pwd",
            ChangeDirection::Increase,
        )
        .expect("a change");

        let claims =
            issued(change.into_event(&EventDetails::at(at()).initiated_by(InitiatingEntity::User)));

        assert_eq!(
            claims["events"][ASSURANCE_LEVEL_CHANGE],
            json!({
                "event_timestamp": 1_760_000_000_i64,
                "initiating_entity": "user",
                "namespace": "https://as.example/t/demo",
                "current_level": "urn:asterius:acr:passkey",
                "previous_level": "urn:asterius:acr:pwd",
                "change_direction": "increase",
            })
        );
    }

    /// RISC: `account-disabled` with and without its reason, and
    /// `account-enabled` with nothing but the common claims.
    #[test]
    fn golden_risc_account_events() {
        let details = EventDetails::at(at()).initiated_by(InitiatingEntity::Admin);

        let disabled = issued(account_disabled(&details, Some(DisabledReason::Hijacking)));
        assert_eq!(
            disabled["events"][ACCOUNT_DISABLED],
            json!({
                "event_timestamp": 1_760_000_000_i64,
                "initiating_entity": "admin",
                "reason": "hijacking",
            })
        );

        let plain = issued(account_disabled(&details, None));
        assert_eq!(
            plain["events"][ACCOUNT_DISABLED],
            json!({"event_timestamp": 1_760_000_000_i64, "initiating_entity": "admin"})
        );

        let enabled = issued(account_enabled(&details));
        assert_eq!(
            enabled["events"][ACCOUNT_ENABLED],
            json!({"event_timestamp": 1_760_000_000_i64, "initiating_entity": "admin"})
        );
    }

    /// Every SET carries `sub_id` (SSF 1.0 §3.1) — structural, but a golden
    /// per event type is what the acceptance criteria ask for.
    #[test]
    fn every_event_type_issues_with_a_sub_id_and_an_event_timestamp() {
        let details = EventDetails::at(at());
        let events = vec![
            session_revoked(&details),
            CredentialChange::new(CredentialType::Password, ChangeType::Update)
                .into_event(&details),
            AssuranceLevelChange::new("ns", "high", "low", ChangeDirection::Increase)
                .expect("a change")
                .into_event(&details),
            account_disabled(&details, None),
            account_enabled(&details),
        ];

        for (event, expected) in events.into_iter().zip(EVENT_TYPES) {
            assert_eq!(event.uri().as_str(), expected);
            let claims = issued(event);
            assert_eq!(claims["sub_id"]["format"], "iss_sub");
            assert_eq!(
                claims["events"][expected]["event_timestamp"],
                json!(1_760_000_000_i64)
            );
        }
    }

    #[test]
    fn the_supported_list_is_exactly_what_this_module_renders() {
        assert_eq!(
            crate::stream::SUPPORTED_EVENTS,
            &EVENT_TYPES[..],
            "an event type is advertised because there is code that emits it"
        );
        for uri in EVENT_TYPES {
            EventUri::parse(uri).expect("a valid event type URI");
        }
    }

    #[test]
    fn a_fido2_credential_type_follows_the_attachment_then_the_backup_flag() {
        assert_eq!(
            CredentialType::fido2(Some("platform"), false),
            CredentialType::Fido2Platform
        );
        assert_eq!(
            CredentialType::fido2(Some("cross-platform"), true),
            CredentialType::Fido2Roaming
        );
        assert_eq!(
            CredentialType::fido2(None, true),
            CredentialType::Fido2Platform
        );
        assert_eq!(
            CredentialType::fido2(Some("something-new"), false),
            CredentialType::Fido2Roaming
        );
    }

    #[test]
    fn free_text_members_are_bounded_and_control_free() {
        assert_eq!(
            text("friendly_name", ""),
            Err(CaepError::Empty("friendly_name"))
        );
        assert_eq!(
            text("friendly_name", &"x".repeat(MAX_TEXT_LEN + 1)),
            Err(CaepError::TooLong {
                member: "friendly_name",
                found: MAX_TEXT_LEN + 1,
            })
        );
        assert_eq!(
            text("reason", "line one\nline two"),
            Err(CaepError::Control("reason"))
        );
        assert_eq!(
            text("friendly_name", "Clé de Quentin").as_deref(),
            Ok("Clé de Quentin")
        );
    }

    #[test]
    fn a_reason_needs_a_language_tag_shaped_key() {
        assert_eq!(Reason::new("", "x").unwrap_err(), CaepError::LanguageTag);
        assert_eq!(
            Reason::new("en_US", "x").unwrap_err(),
            CaepError::LanguageTag
        );
        assert_eq!(Reason::new("-en", "x").unwrap_err(), CaepError::LanguageTag);
        assert_eq!(
            Reason::new(&"a".repeat(36), "x").unwrap_err(),
            CaepError::LanguageTag
        );
        assert!(Reason::new("zh-Hant-TW", "x").is_ok());
    }

    #[test]
    fn an_assurance_change_between_equal_levels_is_refused() {
        assert_eq!(
            AssuranceLevelChange::new("ns", "same", "same", ChangeDirection::Increase).unwrap_err(),
            CaepError::SameLevel
        );
    }
}
