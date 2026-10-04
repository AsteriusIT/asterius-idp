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

/// A Client ID Metadata Document identifier (an absolute HTTPS document URL).
///
/// The original spelling is retained: CIMD identity comparisons are exact
/// string comparisons, and URL normalization must not merge two identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CimdClientId(String);

impl CimdClientId {
    /// Parses a URL suitable for use as a CIMD `client_id`.
    ///
    /// This intentionally adopts the draft's stricter MUST requirements and
    /// rejects query strings as well. It also rejects spellings that `Url`
    /// would normalize before fetching, so the fetched URL remains the exact
    /// identity being compared in metadata.
    pub fn parse(raw: &str) -> Result<Self, CimdClientIdError> {
        if raw.is_empty() || raw.len() > 2048 {
            return Err(CimdClientIdError::Length);
        }
        let url = url::Url::parse(raw).map_err(|_| CimdClientIdError::Url)?;
        if url.scheme() != "https" {
            return Err(CimdClientIdError::HttpsRequired);
        }
        if url.host_str().is_none_or(str::is_empty)
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(CimdClientIdError::Authority);
        }
        if url.fragment().is_some() {
            return Err(CimdClientIdError::Fragment);
        }
        if url.query().is_some() {
            return Err(CimdClientIdError::Query);
        }
        let path = raw
            .split_once("//")
            .map(|(_, rest)| rest)
            .and_then(|rest| rest.find('/').map(|index| &rest[index..]))
            .ok_or(CimdClientIdError::PathRequired)?;
        let segments = path.split('/').skip(1);
        for segment in segments {
            let decoded_dots = segment.replace("%2e", ".").replace("%2E", ".");
            if decoded_dots == "." || decoded_dots == ".." {
                return Err(CimdClientIdError::DotSegment);
            }
        }
        if url.path() == "/" || url.as_str() != raw {
            return Err(CimdClientIdError::NonCanonical);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Borrows the exact identifier spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CimdClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a CIMD URL identifier was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CimdClientIdError {
    /// The identifier is empty or too long.
    #[error("client_id length is invalid")]
    Length,
    /// The identifier is not an absolute URL.
    #[error("client_id must be an absolute URL")]
    Url,
    /// The identifier does not use HTTPS.
    #[error("client_id must use HTTPS")]
    HttpsRequired,
    /// The URL has no host or contains user information.
    #[error("client_id authority is invalid")]
    Authority,
    /// The URL has a fragment.
    #[error("client_id must not contain a fragment")]
    Fragment,
    /// Query strings are refused for CIMD identifiers.
    #[error("client_id must not contain a query")]
    Query,
    /// The URL has no non-root path.
    #[error("client_id must contain a path")]
    PathRequired,
    /// A dot or dot-dot path component is forbidden.
    #[error("client_id must not contain dot path components")]
    DotSegment,
    /// URL parser normalization would change the identifier spelling.
    #[error("client_id URL spelling is not canonical")]
    NonCanonical,
}

impl ClientId {
    /// Draws a fresh `client_id`.
    ///
    /// The server chooses a random UUID, so a registering client cannot choose
    /// a value that matches a user's subject. Existing identifiers remain
    /// readable while stored references are migrated during deployment.
    #[must_use]
    pub fn mint() -> Self {
        Self::new(uuid::Uuid::new_v4().to_string())
    }
}
string_id!(
    /// The `sub` claim value as seen by one client (public or pairwise).
    SubjectId
);
impl SubjectId {
    /// Draw a fresh, unlinkable subject for one authentication request.
    ///
    /// The Ephemeral Subject Identifier draft requires at most 2^-128 guessing
    /// probability and recommends 160 bits. A 256-bit OS CSPRNG draw also
    /// makes accidental reuse infeasible across workers and restarts. Callers
    /// must persist the result on the grant so refresh and UserInfo agree with
    /// the ID Token issued for that one authorization.
    #[must_use]
    pub fn mint_ephemeral() -> Self {
        let drawn = crate::OpaqueToken::generate_bits::<256>();
        Self::new(drawn.expose().to_owned())
    }
}

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

    /// Newly registered clients have a UUID-shaped public identifier.
    #[test]
    fn a_minted_client_id_is_a_uuid() {
        // Arrange / Act
        let minted = ClientId::mint();

        // Assert
        assert_eq!(
            uuid::Uuid::parse_str(minted.as_str())
                .expect("minted UUID")
                .get_version_num(),
            4
        );
    }

    /// Two draws are two identifiers. A generator that repeated itself would
    /// make the second registration a collision the store refuses — or, worse,
    /// an overwrite if a caller ever used an upsert.
    #[test]
    fn two_minted_client_ids_differ() {
        assert_ne!(ClientId::mint(), ClientId::mint());
    }
}
