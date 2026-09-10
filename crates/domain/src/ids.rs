//! Opaque identifier newtypes.
//!
//! Every tenant-scoped operation takes a [`TenantId`]; using distinct types for
//! each identifier keeps a client id from being passed where a subject is
//! expected, which is the cheapest available defence against cross-tenant and
//! cross-entity confusion bugs.

use serde::{Deserialize, Serialize};
use thiserror::Error;

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wraps an already-validated identifier.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Borrows the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

string_id!(
    /// Identifies a tenant. A tenant owns exactly one issuer.
    TenantId
);

/// Why a tenant identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TenantIdError {
    /// Empty, or longer than [`TenantId::MAX_LEN`].
    #[error("must be 1 to {max} characters, found {found}", max = TenantId::MAX_LEN)]
    Length {
        /// How long the offered identifier was.
        found: usize,
    },
    /// Contains something outside the permitted set.
    #[error("may only contain a-z, 0-9, '-' and '_', found {0:?}")]
    Character(char),
    /// Does not begin with a letter or a digit.
    #[error("must start with a letter or a digit")]
    Start,
}

impl TenantId {
    /// The longest a tenant identifier may be.
    pub const MAX_LEN: usize = 64;

    /// Validates a tenant identifier.
    ///
    /// A tenant id is not an internal key: it appears in the issuer
    /// (`https://host/t/{tenant}`), in every metadata document, and in the URL
    /// path of every request — which means it arrives from the network, in a
    /// position where a path segment is about to be built from it.
    ///
    /// The character set is therefore deliberately narrow. Lower-case ASCII
    /// alphanumerics, `-` and `_`, starting with an alphanumeric. `.` is
    /// excluded outright, which removes `..` traversal; `%` is excluded, which
    /// removes double-decoding tricks; upper case is excluded because issuers
    /// are compared case-sensitively and `Demo` and `demo` must not be able to
    /// exist as two tenants that look like one.
    ///
    /// # Errors
    ///
    /// Returns [`TenantIdError`] describing the first rule broken.
    pub fn parse(raw: &str) -> Result<Self, TenantIdError> {
        if raw.is_empty() || raw.len() > Self::MAX_LEN {
            return Err(TenantIdError::Length { found: raw.len() });
        }
        if let Some(bad) = raw
            .chars()
            .find(|c| !matches!(c, 'a'..='z' | '0'..='9' | '-' | '_'))
        {
            return Err(TenantIdError::Character(bad));
        }
        if !raw.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
            return Err(TenantIdError::Start);
        }
        Ok(Self(raw.to_owned()))
    }
}
string_id!(
    /// An OAuth 2.0 `client_id`.
    ClientId
);

impl ClientId {
    /// The prefix every `client_id` this server mints begins with.
    ///
    /// A full stop is not in the `base64url` alphabet (RFC 4648 §5) and not in
    /// the hexadecimal-and-hyphen shape of a UUID, so no identifier carrying it
    /// can collide with either spelling of a `sub` this server issues — a
    /// public one (a UUID) or a pairwise one (43 `base64url` symbols).
    ///
    /// That is FAPI 2.0 SP §6.7 taken literally: it warns that a client able to
    /// influence its `client_id` may have it "mistaken for an end-user subject
    /// identifier". The primary mitigation is that a client cannot influence
    /// this value at all — [`Self::mint`] takes no input — and the prefix makes
    /// the separation visible to a human reading a log rather than merely true.
    pub const MINTED_PREFIX: &'static str = "c.";

    /// Entropy in a minted `client_id`.
    ///
    /// A `client_id` is not a credential and RFC 7591 §3.2.1 does not ask for
    /// it to be unguessable. It is made unguessable anyway, because a
    /// sequential or derived identifier lets anyone who can reach `/register`
    /// enumerate the deployment's client list, and because `client_id` is what
    /// an authorization request names — a guessable one is the first half of
    /// impersonating a client at an endpoint that has not authenticated it yet.
    ///
    /// 128 bits is FAPI 2.0 SP §5.4.1's floor for credentials. Borrowing it
    /// here is a ceiling argument, not a floor one: whatever an identifier
    /// needs, it needs no more than what the profile demands of a secret.
    pub const MINTED_BITS: usize = 128;

    /// Draws a fresh `client_id`.
    ///
    /// Here rather than at either caller, because there are two — RFC 7591
    /// dynamic registration and the admin API's client screen — and a
    /// `client_id` minted with a different prefix or a different amount of
    /// entropy depending on which door it came through would make the shape
    /// above a coincidence rather than a rule.
    ///
    /// [`crate::OpaqueToken`] is the codebase's one CSPRNG path and its output
    /// is already unpadded `base64url` (RFC 4648 §5), which is what makes an
    /// identifier safe in a URL path, a form field and a JSON string without
    /// escaping. It is used for the draw and the encoding only: the value is
    /// public by design, so it is taken out of the wrapper immediately rather
    /// than carried around as something that must not be printed.
    #[must_use]
    pub fn mint() -> Self {
        let drawn = crate::OpaqueToken::generate_bits::<{ Self::MINTED_BITS }>();
        Self::new(format!("{}{}", Self::MINTED_PREFIX, drawn.expose()))
    }
}
string_id!(
    /// The `sub` claim value as seen by one client (public or pairwise).
    SubjectId
);
string_id!(
    /// A revocable grant that every issued token links back to.
    GrantId
);
string_id!(
    /// A browser session identifier, surfaced to clients as the `sid` claim.
    SessionId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_ids_accept_the_shapes_an_issuer_path_can_hold() {
        for good in [
            "demo",
            "acme-eu",
            "t1",
            "a",
            "tenant_2",
            "0",
            &"a".repeat(64),
        ] {
            assert!(TenantId::parse(good).is_ok(), "rejected {good:?}");
        }
    }

    /// The tenant id is spliced into a URL path, so everything that could make
    /// that dangerous is rejected before it gets there.
    #[test]
    fn tenant_ids_reject_anything_that_could_escape_a_path_segment() {
        for (bad, expected) in [
            ("", TenantIdError::Length { found: 0 }),
            ("..", TenantIdError::Character('.')),
            ("a.b", TenantIdError::Character('.')),
            ("a/b", TenantIdError::Character('/')),
            ("a%2fb", TenantIdError::Character('%')),
            ("a b", TenantIdError::Character(' ')),
            ("a?b", TenantIdError::Character('?')),
            ("a#b", TenantIdError::Character('#')),
            ("Demo", TenantIdError::Character('D')),
            ("-lead", TenantIdError::Start),
            ("_lead", TenantIdError::Start),
        ] {
            assert_eq!(TenantId::parse(bad), Err(expected), "accepted {bad:?}");
        }
        assert_eq!(
            TenantId::parse(&"a".repeat(65)),
            Err(TenantIdError::Length { found: 65 })
        );
    }

    #[test]
    fn ids_round_trip_through_string() {
        let tenant = TenantId::new("demo");
        assert_eq!(tenant.as_str(), "demo");
        assert_eq!(tenant.to_string(), "demo");
        assert_eq!(String::from(tenant), "demo");
    }

    #[test]
    fn ids_serialise_transparently() {
        let json = serde_json::to_string(&ClientId::new("c1")).expect("serialise");
        assert_eq!(json, "\"c1\"");
    }

    /// FAPI 2.0 SP §6.7: a `client_id` must not be mistakable for a subject
    /// identifier. The prefix is what a human reading a log sees, and it is
    /// outside both the `base64url` alphabet and a UUID's shape.
    #[test]
    fn a_minted_client_id_cannot_be_mistaken_for_a_subject_identifier() {
        // Arrange / Act
        let minted = ClientId::mint();

        // Assert
        assert!(minted.as_str().starts_with("c."), "{minted}");
        let drawn = &minted.as_str()[2..];
        assert!(
            drawn
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{minted} is not base64url after the prefix"
        );
        // 128 bits, unpadded base64url: 22 symbols.
        assert_eq!(drawn.len(), 22, "{minted}");
    }

    /// Two draws are two identifiers. A generator that repeated itself would
    /// make the second registration a collision the store refuses — or, worse,
    /// an overwrite if a caller ever used an upsert.
    #[test]
    fn two_minted_client_ids_differ() {
        assert_ne!(ClientId::mint(), ClientId::mint());
    }
}
