//! The issuer identifier: a tenant's identity on the wire.

use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use url::Url;

/// A validated, canonical issuer identifier.
///
/// Clients compare `iss` values with **simple string comparison** (OIDC Core
/// §3.1.3.7, RFC 9207 §2.4), so two spellings of the same URL are two different
/// issuers as far as the ecosystem is concerned. Asterius therefore normalises
/// once, at the boundary, and stores only the canonical form: everything
/// downstream — metadata documents, `iss` claims, the `iss` response parameter,
/// audience checks — reads the same bytes.
///
/// Normalisation is deliberately conservative. It lowercases the scheme and
/// host and drops a default `:443`, because those are URL-equivalent by
/// RFC 3986 §6.2.3, and it strips a trailing `/` from the path so that
/// `https://as.example` and `https://as.example/` cannot both exist. It does
/// **not** touch case in the path: OIDC Discovery §3 says the identifier is
/// case sensitive, and a path is where a tenant name lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Issuer(String);

/// Why an issuer identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IssuerError {
    /// The string is not a URL at all.
    #[error("not a valid URL: {0}")]
    NotAUrl(String),
    /// The scheme is something other than `https`.
    #[error("scheme must be https, found {0:?}")]
    NotHttps(String),
    /// RFC 8414 §2 and OIDC Discovery §3 both forbid a query component.
    #[error("must not contain a query component")]
    HasQuery,
    /// RFC 8414 §2 and OIDC Discovery §3 both forbid a fragment component.
    #[error("must not contain a fragment component")]
    HasFragment,
    /// Credentials in the authority would end up in every metadata document.
    #[error("must not contain userinfo (user:password@)")]
    HasUserinfo,
    /// A URL with no host cannot identify an authorization server.
    #[error("must contain a host")]
    NoHost,
}

impl Issuer {
    /// Validates and canonicalises an issuer identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IssuerError`] if the value is not an https URL with a host and
    /// no query, fragment or userinfo component.
    pub fn parse(raw: &str) -> Result<Self, IssuerError> {
        let url = Url::parse(raw).map_err(|e| IssuerError::NotAUrl(e.to_string()))?;

        if url.scheme() != "https" {
            return Err(IssuerError::NotHttps(url.scheme().to_owned()));
        }
        if url.query().is_some() {
            return Err(IssuerError::HasQuery);
        }
        if url.fragment().is_some() {
            return Err(IssuerError::HasFragment);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(IssuerError::HasUserinfo);
        }
        let host = url.host_str().ok_or(IssuerError::NoHost)?;

        // `Url` has already lowercased the scheme and host and dropped a
        // default port; the only thing left is the trailing slash, which `Url`
        // insists on rendering for an empty path.
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        let path = url.path().trim_end_matches('/');

        Ok(Self(format!("https://{authority}{path}")))
    }

    /// The canonical identifier, as it appears in `iss` claims and metadata.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The authority: host, plus a port when it is not the default.
    ///
    /// This is what a request's `Host` header must match for the request to be
    /// speaking to this issuer.
    #[must_use]
    pub fn authority(&self) -> &str {
        let after_scheme = &self.0["https://".len()..];
        match after_scheme.find('/') {
            Some(slash) => &after_scheme[..slash],
            None => after_scheme,
        }
    }

    /// The path component, without a trailing slash. Empty when there is none.
    #[must_use]
    pub fn path(&self) -> &str {
        let after_scheme = &self.0["https://".len()..];
        match after_scheme.find('/') {
            Some(slash) => &after_scheme[slash..],
            None => "",
        }
    }
}

impl fmt::Display for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Issuer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(raw: &str) -> String {
        Issuer::parse(raw)
            .expect("should be accepted")
            .as_str()
            .to_owned()
    }

    // RFC 8414 §2: "a URL that uses the https scheme and has no query or
    // fragment components". OIDC Discovery §3 adds "contains scheme, host, and
    // optionally, port number and path components".
    #[test]
    fn accepts_the_shapes_the_specs_describe() {
        assert_eq!(canonical("https://as.example"), "https://as.example");
        assert_eq!(
            canonical("https://as.example:8443"),
            "https://as.example:8443"
        );
        assert_eq!(
            canonical("https://as.example/t/demo"),
            "https://as.example/t/demo"
        );
    }

    #[test]
    fn rejects_non_https_schemes() {
        assert_eq!(
            Issuer::parse("http://as.example"),
            Err(IssuerError::NotHttps("http".into()))
        );
        assert_eq!(
            Issuer::parse("ftp://as.example"),
            Err(IssuerError::NotHttps("ftp".into()))
        );
    }

    #[test]
    fn rejects_query_and_fragment() {
        assert_eq!(
            Issuer::parse("https://as.example?tenant=demo"),
            Err(IssuerError::HasQuery)
        );
        assert_eq!(
            Issuer::parse("https://as.example/t/demo#x"),
            Err(IssuerError::HasFragment)
        );
        // An empty query or fragment still counts: `?` alone is a query.
        assert_eq!(
            Issuer::parse("https://as.example?"),
            Err(IssuerError::HasQuery)
        );
        assert_eq!(
            Issuer::parse("https://as.example#"),
            Err(IssuerError::HasFragment)
        );
    }

    #[test]
    fn rejects_userinfo_and_hostless_urls() {
        assert_eq!(
            Issuer::parse("https://user:pw@as.example"),
            Err(IssuerError::HasUserinfo)
        );
        assert_eq!(
            Issuer::parse("https://user@as.example"),
            Err(IssuerError::HasUserinfo)
        );
        assert!(matches!(
            Issuer::parse("not a url"),
            Err(IssuerError::NotAUrl(_))
        ));
    }

    /// The trailing slash is the whole reason this type exists: `iss` is
    /// compared byte-for-byte, so both spellings must land on one.
    #[test]
    fn normalises_the_trailing_slash_consistently() {
        assert_eq!(
            canonical("https://as.example/"),
            canonical("https://as.example")
        );
        assert_eq!(
            canonical("https://as.example/t/demo/"),
            canonical("https://as.example/t/demo")
        );
        assert_eq!(canonical("https://as.example///"), "https://as.example");
    }

    #[test]
    fn normalises_url_equivalent_authorities_but_not_the_path() {
        assert_eq!(canonical("https://AS.Example"), "https://as.example");
        assert_eq!(canonical("HTTPS://as.example"), "https://as.example");
        // Default port is redundant (RFC 3986 §6.2.3).
        assert_eq!(
            canonical("https://as.example:443/t/demo"),
            "https://as.example/t/demo"
        );
        // Path case is significant (OIDC Discovery §3: case sensitive URL).
        assert_eq!(
            canonical("https://as.example/t/Demo"),
            "https://as.example/t/Demo"
        );
        assert_ne!(
            canonical("https://as.example/t/Demo"),
            canonical("https://as.example/t/demo")
        );
    }

    #[test]
    fn parsing_is_idempotent() {
        for raw in [
            "https://as.example/",
            "https://AS.Example:443/t/demo/",
            "https://as.example:8443/t/demo",
        ] {
            let once = canonical(raw);
            assert_eq!(canonical(&once), once, "not idempotent for {raw}");
        }
    }

    #[test]
    fn authority_and_path_split_the_identifier() {
        let issuer = Issuer::parse("https://as.example/t/demo").expect("valid");
        assert_eq!(issuer.authority(), "as.example");
        assert_eq!(issuer.path(), "/t/demo");

        let bare = Issuer::parse("https://as.example").expect("valid");
        assert_eq!(bare.authority(), "as.example");
        assert_eq!(bare.path(), "");

        let ported = Issuer::parse("https://as.example:8443/t/demo").expect("valid");
        assert_eq!(ported.authority(), "as.example:8443");
        assert_eq!(ported.path(), "/t/demo");
    }

    #[test]
    fn deserialisation_validates() {
        let ok: Issuer = serde_json::from_str("\"https://as.example/t/demo/\"").expect("valid");
        assert_eq!(ok.as_str(), "https://as.example/t/demo");
        let err = serde_json::from_str::<Issuer>("\"http://as.example\"").unwrap_err();
        assert!(err.to_string().contains("https"), "{err}");
    }
}
