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
}
