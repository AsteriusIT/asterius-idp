//! Opaque identifier newtypes.
//!
//! Every tenant-scoped operation takes a [`TenantId`]; using distinct types for
//! each identifier keeps a client id from being passed where a subject is
//! expected, which is the cheapest available defence against cross-tenant and
//! cross-entity confusion bugs.

use serde::{Deserialize, Serialize};

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
