//! Subject identifiers: RFC 9493, and the two formats SSF 1.0 adds.
//!
//! A subject identifier is a JSON object with a `format` member naming how the
//! rest of the object is to be read. RFC 9493 §3 defines the simple formats;
//! SSF 1.0 §3.3 defines the *complex* one, whose members are themselves simple
//! identifiers and which is how a single event says "this session, of this
//! user, on this device".
//!
//! Two rules run through the whole module.
//!
//! **A format is a closed set, not a string.** Nothing here takes a `format`
//! from a caller. A receiver that is handed an unknown format has to guess, and
//! a transmitter that can emit one has a spelling mistake away from an event
//! nobody can act on.
//!
//! **Members are validated where they are built.** Every free-text member goes
//! through `member`, which refuses an empty or oversized value, so a subject
//! identifier that exists is one whose members are all present and bounded.
//! An empty `id` in an `opaque` identifier is a subject that identifies
//! everybody.

use asterius_domain::{Issuer, PairwiseSalt, SectorIdentifier, SubjectId, UserId};
use serde_json::{Map, Value};
use thiserror::Error;

/// The longest a free-text member of a subject identifier may be.
///
/// OIDC Core §2 bounds a `sub` at 255 ASCII characters, and every member here
/// plays the same role: an identifier a receiver stores and compares. The
/// bound is on characters this server will *emit*, so it is a guard against a
/// stored attribute that grew without limit rather than a specification rule.
pub const MAX_MEMBER_LEN: usize = 255;

/// Why a subject identifier was refused.
///
/// The messages name the member and never interpolate its value: a subject
/// identifier is full of personal data, and these strings reach a log.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SubjectError {
    /// A member was empty. An identifier that identifies nobody in particular
    /// is worse than no identifier: the receiver acts on it.
    #[error("the {0} member of a subject identifier must not be empty")]
    Empty(&'static str),
    /// A member was longer than [`MAX_MEMBER_LEN`].
    #[error("the {member} member is {found} characters, maximum is {max}")]
    TooLong {
        /// Which member.
        member: &'static str,
        /// How long it was.
        found: usize,
        /// The bound.
        max: usize,
    },
    /// A member that must be a URI is not one.
    #[error("the {0} member must be an absolute URI")]
    NotAUri(&'static str),
}

/// Validates one free-text member of a subject identifier.
fn member(name: &'static str, value: &str) -> Result<String, SubjectError> {
    if value.is_empty() {
        return Err(SubjectError::Empty(name));
    }
    // Characters, not bytes: the bound is on what a receiver stores in a
    // column declared in characters, and a non-ASCII local part is legitimate.
    let found = value.chars().count();
    if found > MAX_MEMBER_LEN {
        return Err(SubjectError::TooLong {
            member: name,
            found,
            max: MAX_MEMBER_LEN,
        });
    }
    Ok(value.to_owned())
}

/// Validates a member that has to be an absolute URI.
fn uri_member(name: &'static str, value: &str) -> Result<String, SubjectError> {
    let value = member(name, value)?;
    // `Url::parse` accepts only absolute URLs, which is the requirement: a
    // relative reference has no meaning at a receiver that never saw a base.
    url::Url::parse(&value).map_err(|_| SubjectError::NotAUri(name))?;
    Ok(value)
}

/// A simple subject identifier: one format, a handful of string members.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SimpleSubject {
    /// RFC 9493 §3.2.1 `account`: an `acct:` URI.
    Account {
        /// The `uri` member.
        uri: String,
    },
    /// RFC 9493 §3.2.2 `email`.
    Email {
        /// The `email` member.
        email: String,
    },
    /// RFC 9493 §3.2.3 `iss_sub`: the pair an OpenID Provider already uses.
    ///
    /// This is the format that carries a `sub` — see
    /// [`SimpleSubject::pairwise_iss_sub`] for which `sub`.
    IssuerSubject {
        /// The `iss` member.
        iss: Issuer,
        /// The `sub` member.
        sub: String,
    },
    /// RFC 9493 §3.2.4 `opaque`: an identifier with no structure the receiver
    /// is meant to read.
    Opaque {
        /// The `id` member.
        id: String,
    },
    /// RFC 9493 §3.2.5 `phone_number`, in E.164 form.
    PhoneNumber {
        /// The `phone_number` member.
        phone_number: String,
    },
    /// RFC 9493 §3.2.7 `uri`.
    Uri {
        /// The `uri` member.
        uri: String,
    },
    /// SSF 1.0 §3.4 `jwt_id`: a JWT, named by its issuer and `jti`.
    JwtId {
        /// The `iss` member: who issued the JWT being referred to.
        iss: Issuer,
        /// The `jti` member.
        jti: String,
    },
    /// SSF 1.0 §3.5 `saml_assertion_id`.
    SamlAssertionId {
        /// The `issuer` member.
        issuer: String,
        /// The `assertion_id` member.
        assertion_id: String,
    },
}

impl SimpleSubject {
    /// An `account` identifier.
    ///
    /// # Errors
    ///
    /// [`SubjectError`] if `uri` is empty, oversized, or not an absolute URI.
    pub fn account(uri: &str) -> Result<Self, SubjectError> {
        Ok(Self::Account {
            uri: uri_member("uri", uri)?,
        })
    }

    /// An `email` identifier.
    ///
    /// # Errors
    ///
    /// [`SubjectError`] if the address is empty or oversized.
    pub fn email(email: &str) -> Result<Self, SubjectError> {
        Ok(Self::Email {
            email: member("email", email)?,
        })
    }

    /// An `iss_sub` identifier from an issuer and a subject this server minted.
    ///
    /// Prefer [`SimpleSubject::pairwise_iss_sub`] when the receiver is a
    /// client of this server: it is the constructor that cannot be given the
    /// wrong `sub`.
    ///
    /// # Errors
    ///
    /// [`SubjectError`] if `sub` is empty or oversized.
    pub fn iss_sub(iss: &Issuer, sub: &str) -> Result<Self, SubjectError> {
        Ok(Self::IssuerSubject {
            iss: iss.clone(),
            sub: member("sub", sub)?,
        })
    }

    /// The `iss_sub` identifier **this receiver** already knows the user by.
    ///
    /// A SET is delivered to a receiver, and a receiver of this server's
    /// signals is one of its clients. OIDC Core §8.1 makes a pairwise `sub` a
    /// function of the client's sector identifier, so the `sub` a receiver has
    /// seen in every ID token is the one derived under *its* sector — and any
    /// other `sub` names a user it has no record of. Worse, sending the
    /// public-sector `sub` to a pairwise receiver would hand it the correlation
    /// handle pairwise subjects exist to withhold, and would do it in a channel
    /// the user never sees.
    ///
    /// So the sector is a parameter and the derivation is the same
    /// [`PairwiseSalt::derive_subject`] that minted the `sub` in the ID token.
    /// A public receiver passes [`SectorIdentifier::public`] and gets the
    /// public subject through the same call.
    ///
    /// Infallible: a derived subject is 43 characters of base64url, which is
    /// within [`MAX_MEMBER_LEN`] by construction.
    #[must_use]
    pub fn pairwise_iss_sub(
        iss: &Issuer,
        salt: &PairwiseSalt,
        receiver_sector: &SectorIdentifier,
        user: UserId,
    ) -> Self {
        let sub: SubjectId = salt.derive_subject(receiver_sector, user);
        Self::IssuerSubject {
            iss: iss.clone(),
            sub: sub.as_str().to_owned(),
        }
    }

    /// An `opaque` identifier.
    ///
    /// # Errors
    ///
    /// [`SubjectError`] if `id` is empty or oversized.
    pub fn opaque(id: &str) -> Result<Self, SubjectError> {
        Ok(Self::Opaque {
            id: member("id", id)?,
        })
    }

    /// A `phone_number` identifier.
    ///
    /// # Errors
    ///
    /// [`SubjectError`] if the number is empty or oversized.
    pub fn phone_number(phone_number: &str) -> Result<Self, SubjectError> {
        Ok(Self::PhoneNumber {
            phone_number: member("phone_number", phone_number)?,
        })
    }

    /// A `uri` identifier.
    ///
    /// # Errors
    ///
    /// [`SubjectError`] if the URI is empty, oversized or not absolute.
    pub fn uri(uri: &str) -> Result<Self, SubjectError> {
        Ok(Self::Uri {
            uri: uri_member("uri", uri)?,
        })
    }

    /// A `jwt_id` identifier (SSF 1.0 §3.4).
    ///
    /// # Errors
    ///
    /// [`SubjectError`] if `jti` is empty or oversized.
    pub fn jwt_id(iss: &Issuer, jti: &str) -> Result<Self, SubjectError> {
        Ok(Self::JwtId {
            iss: iss.clone(),
            jti: member("jti", jti)?,
        })
    }

    /// A `saml_assertion_id` identifier (SSF 1.0 §3.5).
    ///
    /// # Errors
    ///
    /// [`SubjectError`] if either member is empty or oversized.
    pub fn saml_assertion_id(issuer: &str, assertion_id: &str) -> Result<Self, SubjectError> {
        Ok(Self::SamlAssertionId {
            issuer: member("issuer", issuer)?,
            assertion_id: member("assertion_id", assertion_id)?,
        })
    }

    /// The registered name of this format, as it appears in `format`.
    #[must_use]
    pub const fn format(&self) -> &'static str {
        match self {
            Self::Account { .. } => "account",
            Self::Email { .. } => "email",
            Self::IssuerSubject { .. } => "iss_sub",
            Self::Opaque { .. } => "opaque",
            Self::PhoneNumber { .. } => "phone_number",
            Self::Uri { .. } => "uri",
            Self::JwtId { .. } => "jwt_id",
            Self::SamlAssertionId { .. } => "saml_assertion_id",
        }
    }

    /// The identifier as the JSON object that goes on the wire.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("format".to_owned(), Value::from(self.format()));
        let mut put = |name: &str, value: &str| {
            object.insert(name.to_owned(), Value::from(value));
        };
        match self {
            Self::Account { uri } | Self::Uri { uri } => put("uri", uri),
            Self::Email { email } => put("email", email),
            Self::IssuerSubject { iss, sub } => {
                put("iss", iss.as_str());
                put("sub", sub);
            }
            Self::Opaque { id } => put("id", id),
            Self::PhoneNumber { phone_number } => put("phone_number", phone_number),
            Self::JwtId { iss, jti } => {
                put("iss", iss.as_str());
                put("jti", jti);
            }
            Self::SamlAssertionId {
                issuer,
                assertion_id,
            } => {
                put("issuer", issuer);
                put("assertion_id", assertion_id);
            }
        }
        Value::Object(object)
    }
}

/// A complex subject identifier (SSF 1.0 §3.3).
///
/// A JSON object whose members — `user`, `device`, `session`, `application`,
/// `tenant`, `org_unit`, `group` — are each a *simple* identifier. It carries
/// no `format` member of its own; the absence of one is how a receiver tells
/// the two apart.
///
/// **Non-empty by construction.** Every constructor names one member, and the
/// `with_*` methods only add. An empty complex subject would be a subject
/// identifier that identifies nothing while looking well-formed, and there is
/// no way to build one here.
///
/// **Not nested.** Members are [`SimpleSubject`], so a complex subject inside
/// a complex subject does not type-check.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComplexSubject {
    user: Option<SimpleSubject>,
    device: Option<SimpleSubject>,
    session: Option<SimpleSubject>,
    application: Option<SimpleSubject>,
    tenant: Option<SimpleSubject>,
    org_unit: Option<SimpleSubject>,
    group: Option<SimpleSubject>,
}

macro_rules! complex_member {
    ($field:ident, $start:ident, $with:ident, $what:literal) => {
        #[doc = concat!("A complex subject whose `", stringify!($field), "` is ", $what, ".")]
        #[must_use]
        pub fn $start(subject: SimpleSubject) -> Self {
            Self {
                $field: Some(subject),
                ..Self::default()
            }
        }

        #[doc = concat!("Adds or replaces the `", stringify!($field), "` member.")]
        #[must_use]
        pub fn $with(mut self, subject: SimpleSubject) -> Self {
            self.$field = Some(subject);
            self
        }
    };
}

impl ComplexSubject {
    complex_member!(user, of_user, with_user, "the person");
    complex_member!(device, of_device, with_device, "the device");
    complex_member!(session, of_session, with_session, "the session");
    complex_member!(
        application,
        of_application,
        with_application,
        "the application"
    );
    complex_member!(tenant, of_tenant, with_tenant, "the tenant");
    complex_member!(
        org_unit,
        of_org_unit,
        with_org_unit,
        "the organisation unit"
    );
    complex_member!(group, of_group, with_group, "the group");

    /// The identifier as the JSON object that goes on the wire.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        for (name, held) in [
            ("user", &self.user),
            ("device", &self.device),
            ("session", &self.session),
            ("application", &self.application),
            ("tenant", &self.tenant),
            ("org_unit", &self.org_unit),
            ("group", &self.group),
        ] {
            if let Some(subject) = held {
                object.insert(name.to_owned(), subject.to_json());
            }
        }
        Value::Object(object)
    }
}

/// Either kind of subject identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// One format and its members (RFC 9493 §3.2).
    Simple(SimpleSubject),
    /// Several simple identifiers describing one principal (SSF 1.0 §3.3).
    ///
    /// Boxed: a complex subject is seven optional simple ones, and an
    /// unboxed variant would make every `Subject` — nearly all of them
    /// simple — pay for the largest shape it could have taken.
    Complex(Box<ComplexSubject>),
}

impl Subject {
    /// The identifier as the JSON object that goes on the wire.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::Simple(simple) => simple.to_json(),
            Self::Complex(complex) => complex.to_json(),
        }
    }
}

impl From<SimpleSubject> for Subject {
    fn from(value: SimpleSubject) -> Self {
        Self::Simple(value)
    }
}

impl From<ComplexSubject> for Subject {
    fn from(value: ComplexSubject) -> Self {
        Self::Complex(Box::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn issuer() -> Issuer {
        Issuer::parse("https://as.example/t/demo").expect("an issuer")
    }

    /// RFC 9493 §3.2: every simple identifier names its format and carries
    /// exactly the members that format defines.
    #[test]
    fn each_simple_format_renders_its_registered_members() {
        let cases = [
            (
                SimpleSubject::account("acct:alice@example.com").expect("account"),
                json!({"format": "account", "uri": "acct:alice@example.com"}),
            ),
            (
                SimpleSubject::email("alice@example.com").expect("email"),
                json!({"format": "email", "email": "alice@example.com"}),
            ),
            (
                SimpleSubject::iss_sub(&issuer(), "abc").expect("iss_sub"),
                json!({"format": "iss_sub", "iss": "https://as.example/t/demo", "sub": "abc"}),
            ),
            (
                SimpleSubject::opaque("o-1").expect("opaque"),
                json!({"format": "opaque", "id": "o-1"}),
            ),
            (
                SimpleSubject::phone_number("+33123456789").expect("phone"),
                json!({"format": "phone_number", "phone_number": "+33123456789"}),
            ),
            (
                SimpleSubject::uri("https://example.com/u/1").expect("uri"),
                json!({"format": "uri", "uri": "https://example.com/u/1"}),
            ),
            (
                SimpleSubject::jwt_id(&issuer(), "jti-1").expect("jwt_id"),
                json!({"format": "jwt_id", "iss": "https://as.example/t/demo", "jti": "jti-1"}),
            ),
            (
                SimpleSubject::saml_assertion_id("https://idp.example", "a-1").expect("saml"),
                json!({
                    "format": "saml_assertion_id",
                    "issuer": "https://idp.example",
                    "assertion_id": "a-1",
                }),
            ),
        ];

        for (subject, expected) in cases {
            assert_eq!(subject.to_json(), expected, "{}", subject.format());
        }
    }

    #[test]
    fn an_empty_member_is_refused() {
        assert_eq!(
            SimpleSubject::opaque(""),
            Err(SubjectError::Empty("id")),
            "an opaque identifier of nobody"
        );
        assert_eq!(SimpleSubject::email(""), Err(SubjectError::Empty("email")));
        assert_eq!(
            SimpleSubject::iss_sub(&issuer(), ""),
            Err(SubjectError::Empty("sub"))
        );
    }

    #[test]
    fn an_oversized_member_is_refused() {
        let long = "a".repeat(MAX_MEMBER_LEN + 1);
        assert_eq!(
            SimpleSubject::opaque(&long),
            Err(SubjectError::TooLong {
                member: "id",
                found: MAX_MEMBER_LEN + 1,
                max: MAX_MEMBER_LEN,
            })
        );
        assert!(SimpleSubject::opaque(&"a".repeat(MAX_MEMBER_LEN)).is_ok());
    }

    #[test]
    fn a_uri_member_must_be_an_absolute_uri() {
        assert_eq!(
            SimpleSubject::uri("/relative"),
            Err(SubjectError::NotAUri("uri"))
        );
        assert_eq!(
            SimpleSubject::account("alice@example.com"),
            Err(SubjectError::NotAUri("uri"))
        );
    }

    /// OIDC Core §8.1: the `sub` a client knows is the one derived under its
    /// own sector. Sending any other one names a user the receiver never saw.
    #[test]
    fn the_pairwise_iss_sub_is_the_sub_that_receiver_already_holds() {
        let salt = PairwiseSalt::from_bytes([7; PairwiseSalt::LEN]);
        let user = UserId::generate();
        let receiver = SectorIdentifier::stored("rp.example").expect("a sector");

        let subject = SimpleSubject::pairwise_iss_sub(&issuer(), &salt, &receiver, user);

        assert_eq!(
            subject.to_json(),
            json!({
                "format": "iss_sub",
                "iss": issuer().as_str(),
                "sub": salt.derive_subject(&receiver, user).as_str(),
            })
        );
    }

    /// The correlation handle a pairwise subject exists to withhold.
    #[test]
    fn two_receivers_are_told_two_different_subs_for_one_user() {
        let salt = PairwiseSalt::from_bytes([7; PairwiseSalt::LEN]);
        let user = UserId::generate();

        let first = SimpleSubject::pairwise_iss_sub(
            &issuer(),
            &salt,
            &SectorIdentifier::stored("rp-one.example").expect("a sector"),
            user,
        );
        let second = SimpleSubject::pairwise_iss_sub(
            &issuer(),
            &salt,
            &SectorIdentifier::stored("rp-two.example").expect("a sector"),
            user,
        );
        let public =
            SimpleSubject::pairwise_iss_sub(&issuer(), &salt, &SectorIdentifier::public(), user);

        assert_ne!(first, second);
        assert_ne!(first, public);
        assert_ne!(second, public);
    }

    /// SSF 1.0 §3.3: members are simple identifiers, and there is no `format`.
    #[test]
    fn a_complex_subject_holds_simple_members_and_no_format() {
        let complex = ComplexSubject::of_user(SimpleSubject::opaque("u-1").expect("user"))
            .with_session(SimpleSubject::opaque("s-1").expect("session"))
            .with_device(SimpleSubject::opaque("d-1").expect("device"))
            .with_tenant(SimpleSubject::opaque("t-1").expect("tenant"));

        assert_eq!(
            complex.to_json(),
            json!({
                "user": {"format": "opaque", "id": "u-1"},
                "device": {"format": "opaque", "id": "d-1"},
                "session": {"format": "opaque", "id": "s-1"},
                "tenant": {"format": "opaque", "id": "t-1"},
            })
        );
    }

    #[test]
    fn a_complex_subject_always_has_at_least_one_member() {
        // Every constructor names a member; `Default` is private to this
        // module and only reachable through one of them.
        let subject = ComplexSubject::of_group(SimpleSubject::opaque("g-1").expect("group"));
        let Value::Object(members) = subject.to_json() else {
            panic!("a complex subject is an object");
        };
        assert_eq!(members.len(), 1);
    }
}
