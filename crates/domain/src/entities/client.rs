//! The client entity, and the validating parser that produces it.
//!
//! FAPI 2.0 SP §5.3.2.1 item 3: an authorization server "shall only support
//! confidential clients". ADR-0002 makes that unconditional — there is no
//! per-client profile to fall back to — which decides the shape of everything
//! below: **a weaker value is rejected, never replaced with a safe one.**
//!
//! Quietly upgrading a registration would leave the operator's records saying
//! one thing and the server doing another. A client registered with
//! `client_secret_basic` and silently stored as `private_key_jwt` cannot
//! authenticate at all, and the first anyone hears of it is a production
//! `invalid_client` that the registration record contradicts.
//!
//! The same reasoning applies to the defaults. RFC 7591 §2's defaults are the
//! 2015 OAuth defaults; where one of them names something this server does not
//! implement, the default here is the FAPI value and the RFC's value is an
//! error. Each such deviation is marked at the point where it is taken.

use crate::capabilities::{Capabilities, Feature};
use crate::keys::SigningAlgorithm;
use crate::{ClientId, TenantId};
use serde::Deserialize;
use std::collections::BTreeSet;
use thiserror::Error;
use time::OffsetDateTime;
use url::{Host, Url};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a client registration document was rejected.
///
/// The rendered message goes into the RFC 7591 §3.2.2 `error_description` and
/// into the audit trail, so **no variant interpolates a value taken from the
/// document** — only field names, indexes and counts. An `error_description`
/// that echoes its input is a reflection primitive in a response that some
/// deployments log verbatim, and a registration document is one of the few
/// places a caller can put a credential by mistake.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ClientMetadataError {
    /// The bytes are not a JSON object, or a field has the wrong JSON type.
    #[error("malformed registration document: {kind} at line {line}, column {column}")]
    Malformed {
        /// `syntax`, `type`, `eof` or `io` — `serde_json`'s classification.
        kind: &'static str,
        /// Line the parser stopped on, 1-based.
        line: usize,
        /// Column the parser stopped on, 1-based.
        column: usize,
    },
    /// A field this profile requires is absent or empty.
    #[error("{field} is required")]
    Missing {
        /// The metadata field, in its wire spelling.
        field: &'static str,
    },
    /// A field carries a value this profile does not permit.
    #[error("{field}: {reason}")]
    Rejected {
        /// The metadata field, in its wire spelling.
        field: &'static str,
        /// Why, in fixed text. Never contains a value from the document.
        reason: String,
    },
    /// A redirect URI was rejected. RFC 7591 §3.2.2 gives this its own code,
    /// because a client that gets `invalid_client_metadata` back has no way to
    /// tell that the redirect URI was the problem.
    #[error("redirect_uris[{index}]: {reason}")]
    RedirectUri {
        /// Which entry, counting from zero.
        index: usize,
        /// Why, in fixed text. Never contains the URI itself.
        reason: String,
    },
    /// A post-logout redirect URI was rejected — OIDC RP-Initiated Logout 1.0
    /// §3.1. It carries the same RFC 7591 §3.2.2 code as its authorization
    /// counterpart, because it is the same kind of value being refused for the
    /// same kind of reason, and a client told `invalid_client_metadata` would
    /// have to guess which member it was.
    #[error("post_logout_redirect_uris[{index}]: {reason}")]
    PostLogoutRedirectUri {
        /// Which entry, counting from zero.
        index: usize,
        /// Why, in fixed text. Never contains the URI itself.
        reason: String,
    },
    /// A software statement was presented and is not usable: not a JWS, the
    /// wrong `typ`, an unverifiable signature, expired, or claims that are not
    /// client metadata (RFC 7591 §2.3, §3.1.1).
    ///
    /// One variant for all of those, and RFC 7591 §3.2.2's
    /// `invalid_software_statement` for all of them: the statement is signed by
    /// a third party, and telling its *bearer* which key failed is telling
    /// somebody about an issuer they may have no relationship with.
    #[error("software_statement: {reason}")]
    InvalidSoftwareStatement {
        /// Why, in fixed text. Never contains anything from the statement.
        reason: &'static str,
    },
    /// A software statement was presented, is well formed, and was signed by an
    /// issuer this tenant does not trust — RFC 7591 §3.2.2's
    /// `unapproved_software_statement`.
    ///
    /// Distinct from the above because a client acts on the difference: an
    /// invalid statement is a bug in whatever minted it, an unapproved one is a
    /// conversation with the operator about who may vouch for clients here.
    #[error("software_statement: signed by an issuer this tenant does not trust")]
    UnapprovedSoftwareStatement,
}

impl ClientMetadataError {
    /// The RFC 7591 §3.2.2 error code the registration endpoint returns.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RedirectUri { .. } | Self::PostLogoutRedirectUri { .. } => "invalid_redirect_uri",
            // RFC 7591 §3.2.2's two software statement codes. Neither is
            // `invalid_client_metadata`: the document may be perfect and the
            // assertion about it not be.
            Self::InvalidSoftwareStatement { .. } => "invalid_software_statement",
            Self::UnapprovedSoftwareStatement => "unapproved_software_statement",
            _ => "invalid_client_metadata",
        }
    }

    /// The metadata field that was rejected, in its wire spelling.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => "<document>",
            Self::Missing { field } | Self::Rejected { field, .. } => field,
            Self::RedirectUri { .. } => "redirect_uris",
            Self::PostLogoutRedirectUri { .. } => "post_logout_redirect_uris",
            Self::InvalidSoftwareStatement { .. } | Self::UnapprovedSoftwareStatement => {
                "software_statement"
            }
        }
    }

    fn rejected(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Rejected {
            field,
            reason: reason.into(),
        }
    }

    /// The URL this field carries could not be dereferenced.
    ///
    /// The reason is fixed text: what actually went wrong — a refused address,
    /// a timeout, a 404 — is for the operator's log, and telling a registering
    /// client which of them it was would turn the endpoint into a probe for
    /// the network this server sits in.
    #[must_use]
    pub fn unreachable(field: &'static str) -> Self {
        Self::rejected(field, "could not be fetched")
    }

    fn needs(field: &'static str, feature: Feature) -> Self {
        Self::rejected(
            field,
            format!("requires the `{feature}` feature, which this deployment has not enabled"),
        )
    }
}

// ---------------------------------------------------------------------------
// Closed value sets
// ---------------------------------------------------------------------------

/// How a client authenticates at the token endpoint and every other endpoint
/// that requires client authentication.
///
/// The set is closed, and closed is the point: `client_secret_basic`,
/// `client_secret_post`, `client_secret_jwt` and `none` are not variants, so no
/// amount of configuration can produce a client that authenticates with a
/// shared secret or not at all (FAPI 2.0 SP §5.3.2.1 items 3 and 6, ADR-0002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TokenEndpointAuthMethod {
    /// Asymmetric client assertion (OIDC Core §9). The default here.
    PrivateKeyJwt,
    /// mTLS with a certificate issued by a trusted CA (RFC 8705 §2.1).
    TlsClientAuth,
    /// mTLS with a self-signed certificate matched against the client's own
    /// JWKS (RFC 8705 §2.2).
    SelfSignedTlsClientAuth,
}

impl TokenEndpointAuthMethod {
    /// Every permitted method, in the order metadata should advertise them.
    pub const ALL: [Self; 3] = [
        Self::PrivateKeyJwt,
        Self::TlsClientAuth,
        Self::SelfSignedTlsClientAuth,
    ];

    /// RFC 7591 §2 defaults this to `client_secret_basic`. That value does not
    /// exist here, so the default is the profile's floor instead — a client
    /// that says nothing gets the strongest method, not the historical one.
    pub const DEFAULT: Self = Self::PrivateKeyJwt;

    /// The wire spelling, as it appears in client metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::TlsClientAuth => "tls_client_auth",
            Self::SelfSignedTlsClientAuth => "self_signed_tls_client_auth",
        }
    }

    /// Parses a `token_endpoint_auth_method` value.
    ///
    /// Returns `None` for everything outside the allow-list, which is the whole
    /// job: `client_secret_basic`, `client_secret_post`, `client_secret_jwt`
    /// and `none` all land here.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == value)
    }

    /// Whether this method needs mTLS at the transport (RFC 8705 §2).
    #[must_use]
    pub const fn requires_mtls(self) -> bool {
        matches!(self, Self::TlsClientAuth | Self::SelfSignedTlsClientAuth)
    }
}

impl std::fmt::Display for TokenEndpointAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The one certificate field a `tls_client_auth` client is matched on.
///
/// RFC 8705 §2.1.2 registers five metadata parameters —
/// `tls_client_auth_subject_dn` and four `tls_client_auth_san_*` — and says of
/// them:
///
/// > … the client MUST use exactly one of the below metadata parameters to
/// > indicate the certificate subject value that the authorization server is
/// > to expect when authenticating the respective client.
///
/// "Exactly one" is why this is an enum and not five `Option<String>` fields on
/// the registration. A client that registered both a subject DN and a SAN would
/// leave the server choosing which one to match, and a server that chooses is a
/// server whose answer depends on the order its code happens to run in — the
/// certificate satisfying the weaker of the two is then a certificate that
/// authenticates. Making the second one unrepresentable removes the question.
///
/// The value is compared **byte for byte** against what the presented
/// certificate says (RFC 8705 §2.1: the expected value is "compared" to the
/// certificate's). There is no normalisation, no case folding and no wildcard:
/// each of those is a way for two different certificates to match one
/// registration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TlsClientAuthSubject {
    /// `tls_client_auth_subject_dn`: the certificate's subject distinguished
    /// name, in the RFC 4514 string form.
    SubjectDn(String),
    /// `tls_client_auth_san_dns`: a `dNSName` SAN entry.
    SanDns(String),
    /// `tls_client_auth_san_uri`: a `uniformResourceIdentifier` SAN entry.
    SanUri(String),
    /// `tls_client_auth_san_ip`: an `iPAddress` SAN entry, in its textual form.
    SanIp(String),
    /// `tls_client_auth_san_email`: an `rfc822Name` SAN entry.
    SanEmail(String),
}

impl TlsClientAuthSubject {
    /// Every metadata field this type can be built from, in RFC 8705 §2.1.2's
    /// order.
    ///
    /// The registration validator iterates this rather than naming the fields
    /// a second time, so "exactly one of these" is checked against the same
    /// list the type is built from.
    pub const FIELDS: [&'static str; 5] = [
        "tls_client_auth_subject_dn",
        "tls_client_auth_san_dns",
        "tls_client_auth_san_uri",
        "tls_client_auth_san_ip",
        "tls_client_auth_san_email",
    ];

    /// The longest value this server will store or compare.
    ///
    /// A DN is a name, not a document. The bound exists because the value is
    /// attacker-chosen at registration and compared on every token request;
    /// 1024 is far above any DN a CA issues and far below anything worth
    /// storing.
    pub const MAX_LEN: usize = 1024;

    /// Builds the subject from a field name and its value.
    ///
    /// Returns `None` for a field name outside [`FIELDS`], which is what makes
    /// a stored row naming an unknown field fail closed rather than silently
    /// match nothing.
    ///
    /// [`FIELDS`]: TlsClientAuthSubject::FIELDS
    #[must_use]
    pub fn from_field(field: &str, value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        match field {
            "tls_client_auth_subject_dn" => Some(Self::SubjectDn(value)),
            "tls_client_auth_san_dns" => Some(Self::SanDns(value)),
            "tls_client_auth_san_uri" => Some(Self::SanUri(value)),
            "tls_client_auth_san_ip" => Some(Self::SanIp(value)),
            "tls_client_auth_san_email" => Some(Self::SanEmail(value)),
            _ => None,
        }
    }

    /// The metadata field this value was registered under.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        match self {
            Self::SubjectDn(_) => "tls_client_auth_subject_dn",
            Self::SanDns(_) => "tls_client_auth_san_dns",
            Self::SanUri(_) => "tls_client_auth_san_uri",
            Self::SanIp(_) => "tls_client_auth_san_ip",
            Self::SanEmail(_) => "tls_client_auth_san_email",
        }
    }

    /// The registered value, as written.
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Self::SubjectDn(value)
            | Self::SanDns(value)
            | Self::SanUri(value)
            | Self::SanIp(value)
            | Self::SanEmail(value) => value,
        }
    }
}

/// A grant type a client may use.
///
/// Absent by construction: `implicit`, `password`, and anything else that
/// returns a token to a front channel or takes a user's password
/// (ADR-0002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GrantType {
    /// RFC 6749 §4.1, always through PAR (RFC 9126) here.
    AuthorizationCode,
    /// RFC 6749 §6. Not rotated; sender-constrained instead (SP §5.3.2.1).
    RefreshToken,
    /// RFC 6749 §4.4.
    ClientCredentials,
    /// RFC 8693 §2.1.
    TokenExchange,
    /// RFC 8628 §3.4.
    DeviceCode,
    /// CIBA Core 1.0 §10.1.
    Ciba,
}

impl GrantType {
    /// Every permitted grant type.
    pub const ALL: [Self; 6] = [
        Self::AuthorizationCode,
        Self::RefreshToken,
        Self::ClientCredentials,
        Self::TokenExchange,
        Self::DeviceCode,
        Self::Ciba,
    ];

    /// RFC 7591 §2's default for `grant_types`.
    pub const DEFAULT: [Self; 1] = [Self::AuthorizationCode];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
            Self::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
            Self::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            Self::Ciba => "urn:openid:params:grant-type:ciba",
        }
    }

    /// Parses a `grant_types` entry. `None` for anything outside the set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.as_str() == value)
    }

    /// The feature flag this grant needs, if any.
    ///
    /// Registering a client for a grant the deployment cannot perform produces
    /// a client that fails at first use with an error that points at the
    /// client rather than at the flag. ADR-0002's rule — a flag that is off
    /// must not be advertised — is applied here too: it is refused at
    /// registration.
    #[must_use]
    pub const fn required_feature(self) -> Option<Feature> {
        match self {
            Self::AuthorizationCode | Self::RefreshToken | Self::ClientCredentials => None,
            Self::TokenExchange => Some(Feature::TokenExchange),
            Self::DeviceCode => Some(Feature::DeviceFlow),
            Self::Ciba => Some(Feature::Ciba),
        }
    }

    /// Whether this grant reaches the authorization endpoint, and therefore
    /// needs a registered redirect URI (RFC 7591 §2.1).
    #[must_use]
    pub const fn uses_the_authorization_endpoint(self) -> bool {
        matches!(self, Self::AuthorizationCode)
    }
}

impl std::fmt::Display for GrantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OIDC Registration §2 `application_type`. Decides one thing here: whether a
/// loopback redirect URI over `http` is admissible (RFC 8252 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApplicationType {
    /// Runs on a server the operator controls. The default, per OIDC
    /// Registration §2.
    #[default]
    Web,
    /// Runs on the end user's device.
    Native,
}

impl ApplicationType {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
        }
    }

    /// Parses an `application_type` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "web" => Some(Self::Web),
            "native" => Some(Self::Native),
            _ => None,
        }
    }
}

/// OIDC Core §8 subject identifier type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubjectType {
    /// The same `sub` for every client. The default.
    #[default]
    Public,
    /// A `sub` per sector, so two clients cannot correlate a user by it.
    Pairwise,
}

impl SubjectType {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Pairwise => "pairwise",
        }
    }

    /// Parses a `subject_type` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Self::Public),
            "pairwise" => Some(Self::Pairwise),
            _ => None,
        }
    }
}

/// How a client's access tokens are bound to a key it holds.
///
/// Exactly one of the two, and that is the point twice over.
///
/// There is no `Neither` variant: FAPI 2.0 SP §5.3.2.1 requires
/// sender-constrained access tokens, so "this client gets bearer tokens" is not
/// a state this type can hold. RFC 9449 §5.2 (`dpop_bound_access_tokens`) and
/// RFC 8705 §3.4 (`tls_client_certificate_bound_access_tokens`) are the two
/// ways in, and the pair `false, false` is refused.
///
/// There is no `Both` variant either. A `cnf` carrying a `jkt` *and* an
/// `x5t#S256` is a token whose resource servers have to agree on whether one
/// or both must check out, and RFC 8705 §3.1 and RFC 9449 §6.1 each define
/// only their own member and say nothing about the other being present: the
/// token would be as strong as the weaker reading of it, which makes the
/// binding the verifier's decision rather than this server's. So a client
/// registers one method, and `true, true` is refused at registration — where
/// the client can still change its mind — rather than at the token endpoint,
/// where it already holds a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenBinding {
    /// DPoP proof of possession (RFC 9449). The default.
    #[default]
    Dpop,
    /// mTLS certificate binding (RFC 8705 §3), for a client that presents a
    /// certificate anyway and has no DPoP implementation.
    Certificate,
}

impl TokenBinding {
    /// Whether tokens for this client carry a `cnf.jkt` (RFC 9449 §6).
    #[must_use]
    pub const fn is_dpop_bound(self) -> bool {
        matches!(self, Self::Dpop)
    }

    /// Whether tokens for this client carry a `cnf.x5t#S256` (RFC 8705 §3.1).
    #[must_use]
    pub const fn is_certificate_bound(self) -> bool {
        matches!(self, Self::Certificate)
    }

    /// Builds the binding from the two RFC booleans, or explains the refusal.
    fn from_flags(dpop: bool, certificate: bool) -> Result<Self, ClientMetadataError> {
        match (dpop, certificate) {
            (true, false) => Ok(Self::Dpop),
            (false, true) => Ok(Self::Certificate),
            // A client asking for tokens bound to nothing. Such a token is a
            // bearer token, and a bearer token stolen from a log or a proxy is
            // usable by whoever finds it (Attacker Model §7.7, A5).
            (false, false) => Err(ClientMetadataError::rejected(
                "dpop_bound_access_tokens",
                "may only be false when tls_client_certificate_bound_access_tokens is true; \
                 this server does not issue bearer access tokens",
            )),
            // A client asking for both. See the type's own note: the token
            // would carry two confirmations and no rule about which of them a
            // resource server must honour.
            (true, true) => Err(ClientMetadataError::rejected(
                "tls_client_certificate_bound_access_tokens",
                "may only be true when dpop_bound_access_tokens is false; a client binds its \
                 access tokens by a DPoP key or by a certificate, not by both",
            )),
        }
    }
}

/// Where a client's public keys come from.
///
/// RFC 7591 §2: "The `jwks_uri` and `jwks` parameters MUST NOT both be present
/// in the same request or response." The `clients_exactly_one_key_source` check
/// in the baseline schema says the same thing, and adds that one of them must
/// be there: a confidential client with no key material cannot authenticate,
/// so a row without either is a row that describes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksSource {
    /// Keys given inline at registration.
    Inline(serde_json::Value),
    /// Keys fetched from the client. The fetch, its cache and its SSRF guard
    /// belong to `ast-mxc.5`; all that is checked here is the URL's shape.
    Uri(String),
}

/// Whether a client answers requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientStatus {
    /// Serving.
    #[default]
    Active,
    /// Suspended. Every request it makes fails client authentication.
    Disabled,
}

impl ClientStatus {
    /// The value as stored in the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    /// Parses the stored value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Redirect URIs
// ---------------------------------------------------------------------------

/// Why a redirect URI was refused.
///
/// Every variant renders as fixed text. The message reaches an RFC 7591 §3.2.2
/// `error_description` and the audit trail, and the value it describes came off
/// the network, so no variant carries a byte of it — which is why this is a
/// fieldless enum rather than the `String` the caller used to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
#[non_exhaustive]
pub enum RedirectUriError {
    /// The entry was the empty string.
    #[error("must not be empty")]
    Empty,
    /// Longer than [`RedirectUri::MAX_LEN`].
    #[error("must be at most {} bytes", RedirectUri::MAX_LEN)]
    TooLong,
    /// Not parseable as an absolute URI — a relative reference, for instance.
    #[error("must be an absolute URI")]
    NotAUrl,
    /// RFC 6749 §3.1.2 forbids a fragment on the redirection endpoint.
    #[error("must not contain a fragment component (RFC 6749 §3.1.2)")]
    HasFragment,
    /// Credentials in the authority.
    #[error("must not contain userinfo (user:password@)")]
    HasUserinfo,
    /// `https:///cb` and friends: a URL the parser accepts with no authority.
    #[error("must contain a host")]
    NoHost,
    /// A scheme other than `https`, or `http` on a client that is not native.
    #[error(
        "scheme must be https; http is admissible only for a loopback redirect on a \
         client with application_type=native (FAPI 2.0 SP §5.3.2.2 item 8)"
    )]
    NotHttps,
    /// `http` on a native client, but not on a loopback IP literal.
    #[error(
        "http is admissible only on 127.0.0.1 or [::1]; `localhost` resolves through \
         DNS (RFC 8252 §7.3, §8.3)"
    )]
    NotLoopback,
    /// The bytes are not the bytes a URL parser produces for them.
    #[error(
        "must already be in normalised form (RFC 3986 §6.2.2): register the URI exactly \
         as it will be requested, since matching is byte-exact (RFC 9700 §4.1.3)"
    )]
    NotNormalised,
}

/// A registered redirect URI, stored exactly as the client wrote it.
///
/// The bytes are kept unchanged on purpose. RFC 9700 §4.1.3 requires the
/// authorization server to "ensure that the two URIs are equal; see Section
/// 6.2.1 of \[RFC3986\], Simple String Comparison", so any normalisation applied
/// on the way in — lowercasing a host, adding a trailing slash, re-encoding a
/// path — silently changes what the client must send back, and the client finds
/// out at its first authorization request.
///
/// This type owns the comparison as well as the parse. [`is_registered`] is the
/// single function registration, PAR (`ast-gxh.1`) and the token endpoint
/// (`ast-a05.2`) all reach; [`parse`] decides what may enter the registered set
/// in the first place. Keeping both here is deliberate: a second, laxer notion
/// of "the same redirect URI" somewhere else in the server is exactly the bug
/// RFC 9700 §4.1 is about. ADR-0005 records why the set is still consulted
/// under PAR, which RFC 9126 §2.4 would permit us to skip.
///
/// [`is_registered`]: RedirectUri::is_registered
/// [`parse`]: RedirectUri::parse
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RedirectUri(String);

impl RedirectUri {
    /// The longest redirect URI accepted. Long enough for any real callback,
    /// short enough that a registration cannot be used to store a payload.
    pub const MAX_LEN: usize = 2048;

    /// The URI, byte for byte as registered.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The host this URI points at, lowercased by the URL parser.
    ///
    /// `None` only for a URI a parser can no longer read, which
    /// [`RedirectUri::parse`] makes unreachable for a value that entered
    /// through it — a stored row edited by hand is the remaining case, and
    /// "no host" is the safe answer there: a host allow-list
    /// ([`crate::RegistrationPolicy`]) refuses what it cannot name.
    #[must_use]
    pub fn host(&self) -> Option<String> {
        Url::parse(&self.0)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
    }

    /// Validates one redirect URI for a client of `application_type`.
    ///
    /// This decides **admissibility** — what a client may put in its registered
    /// set. [`RedirectUri::is_registered`] decides **equivalence** — what
    /// counts as the same URI later.
    ///
    /// The split is not cosmetic, and RFC 8252 §7.3 is why: the loopback port
    /// "MUST" be allowed to vary per request, so it cannot be settled here
    /// without either rewriting the registered bytes (which RFC 9700 §4.1.3
    /// forbids, since the bytes *are* the comparison) or storing a port-shaped
    /// wildcard (which is a pattern, and patterns are the thing RFC 9700 §4.1.3
    /// replaced). What *is* settled here is that only a native client may
    /// register a loopback `http` URI at all; the comparison then varies
    /// nothing but the port of a URI that already passed through here.
    ///
    /// # Errors
    ///
    /// Returns the [`RedirectUriError`] for the first rule broken. No variant
    /// contains the rejected URI.
    // fuzz-target: redirect_uri
    pub fn parse(raw: &str, application_type: ApplicationType) -> Result<Self, RedirectUriError> {
        if raw.is_empty() {
            return Err(RedirectUriError::Empty);
        }
        if raw.len() > Self::MAX_LEN {
            return Err(RedirectUriError::TooLong);
        }
        let url = Url::parse(raw).map_err(|_| RedirectUriError::NotAUrl)?;

        // RFC 6749 §3.1.2: "The endpoint URI MUST NOT include a fragment
        // component." The fragment never reaches the server, so a client that
        // registers one is registering a URI that cannot be matched.
        if url.fragment().is_some() {
            return Err(RedirectUriError::HasFragment);
        }
        // Credentials in the authority end up in the browser's address bar and
        // in every referrer header the callback page emits.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(RedirectUriError::HasUserinfo);
        }

        match url.scheme() {
            "https" => {
                // `Url` accepts `https:///path` and reports an empty host
                // rather than no host at all, so emptiness is checked and not
                // just presence.
                if url.host_str().is_none_or(str::is_empty) {
                    return Err(RedirectUriError::NoHost);
                }
            }
            // FAPI 2.0 SP §5.3.2.2 item 8: an authorization server "shall not
            // allow redirect URIs that use the "http" scheme except for native
            // clients that use loopback interface Redirection as described in
            // Section 7.3 of [RFC8252]". RFC 8252 §8.3 adds that `localhost` is
            // NOT RECOMMENDED even for that case, because it goes through name
            // resolution and can be pointed elsewhere by a hosts file, a DNS
            // answer or a client-side firewall — so only the IP literals pass.
            "http" => {
                if application_type != ApplicationType::Native {
                    return Err(RedirectUriError::NotHttps);
                }
                match url.host() {
                    Some(Host::Ipv4(address)) if address.is_loopback() => {}
                    Some(Host::Ipv6(address)) if address.is_loopback() => {}
                    _ => return Err(RedirectUriError::NotLoopback),
                }
            }
            // A private-use scheme can be claimed by any application on the
            // device (RFC 8252 §7.1), which makes the callback interceptable by
            // software the user did not install deliberately. RFC 8252 §8.4
            // classes such clients as public clients, and ADR-0002 has none —
            // so there is no client here a custom scheme could belong to.
            _ => return Err(RedirectUriError::NotHttps),
        }

        // The registered bytes must already be the bytes a URL parser produces.
        //
        // [`Issuer`] takes the other route and normalises, because an operator
        // writes an issuer once in a configuration file. A redirect URI cannot:
        // it is compared byte for byte (RFC 9700 §4.1.3), so normalising it
        // would change what the client has to send, and *not* normalising it
        // lets the registered string and the URL a browser actually requests
        // drift apart. `https:///cb` is the sharp example — WHATWG parsing
        // turns the empty authority into the host `cb`, so a registration that
        // reads as a path is a callback to a different origin entirely. The
        // same trap in IDN clothing: `https://пример.example/cb` is stored as
        // punycode by every browser, so registering the Unicode spelling would
        // register a string no request can ever carry.
        //
        // Refusing is the only option that leaves no gap: nothing is rewritten,
        // and nothing that would have to be rewritten is accepted.
        //
        // [`Issuer`]: crate::Issuer
        if url.as_str() != raw {
            return Err(RedirectUriError::NotNormalised);
        }

        Ok(Self(raw.to_owned()))
    }

    /// Whether `presented` is one of the `registered` redirect URIs.
    ///
    /// **This is the redirect-URI comparison.** Registration checks a new entry
    /// against the ones already there, PAR (`ast-gxh.1`) checks the pushed
    /// `redirect_uri` — which FAPI 2.0 SP §5.3.2.2 item 6 requires to be
    /// present — and the token endpoint (`ast-a05.2`) checks the one presented
    /// with the code. One function, so the three cannot drift.
    ///
    /// An empty registered set never matches. RFC 6749 §3.1.2.3 makes the
    /// comparison conditional on "if any redirection URIs were registered", and
    /// the empty set here means the client cannot reach the authorization
    /// endpoint at all — so the honest answer is no, not "anything goes".
    #[must_use]
    pub fn is_registered(
        registered: &[Self],
        presented: &str,
        application_type: ApplicationType,
    ) -> bool {
        registered
            .iter()
            .any(|uri| uri.matches(presented, application_type))
    }

    /// Whether `presented` is this redirect URI.
    ///
    /// The comparison is RFC 3986 §6.2.1 simple string comparison, as
    /// RFC 6749 §3.1.2.3 and RFC 9700 §4.1.3 both require. No prefix, no
    /// pattern, no case folding, no percent-decoding, no IDN equivalence: a
    /// trailing slash, a different path case, an added query parameter or the
    /// Unicode spelling of a punycode host are all different URIs.
    ///
    /// The single exception is RFC 8252 §7.3, and it is as narrow as the text:
    /// for a **native** client redirecting to a loopback IP literal over
    /// `http`, "the authorization server MUST allow any port to be specified at
    /// the time of the request", because the client takes an ephemeral port
    /// from the operating system per attempt. RFC 8252 §8.4 states the residue
    /// exactly — "an exact match is required except for the port URI component"
    /// — so the port is the only thing this varies. Scheme, host, path and
    /// query stay byte-exact; anything looser turns the exception into the
    /// wildcard RFC 9700 §4.1.3 exists to remove.
    #[must_use]
    pub fn matches(&self, presented: &str, application_type: ApplicationType) -> bool {
        // RFC 3986 §6.2.1. This runs first and unconditionally: the registered
        // side is already canonical, so an equal string is a canonical string,
        // and the loopback branch below never sees a URI that simply matched.
        if self.0 == presented {
            return true;
        }
        // The exception belongs to native clients only (FAPI 2.0 SP §5.3.2.2
        // item 8). A caller that does not know the client is native gets plain
        // string equality, which is the safe direction to fail in. The `parse`
        // call further down refuses an `http` URI for a non-native client too;
        // this is the first of the two gates on the same rule, and it is here
        // because a reader should not have to find the second one to know that
        // a web client has no exception.
        if application_type != ApplicationType::Native {
            return false;
        }
        // Only a registered loopback `http` URI has the exception at all; an
        // https registration has no `http://` prefix and stops here.
        let Some((host, rest)) = Self::loopback_parts(&self.0) else {
            return false;
        };
        // The presented URI must be one this server would itself have accepted
        // for registration. Without that, the port-agnostic branch would be
        // comparing a string nobody validated, and a non-canonical spelling the
        // registered side could never have had — `http://127.1/cb`,
        // `http://[0:0:0:0:0:0:0:1]/cb`, `http://127.0.0.1:8080/a/../cb` —
        // would reach the split below.
        if Self::parse(presented, application_type).is_err() {
            return false;
        }
        let Some((presented_host, presented_rest)) = Self::loopback_parts(presented) else {
            return false;
        };
        host == presented_host && rest == presented_rest
    }

    /// Splits a loopback `http` URI into its host and everything after the
    /// authority, discarding the port — the one component RFC 8252 §7.3 lets
    /// vary. Returns `None` for anything that is not of that shape.
    ///
    /// This is deliberately lexical rather than a second `Url::parse`. Parsing
    /// again to compare components would re-introduce normalisation on the
    /// comparison path, which is where it does the most damage: `..` segments
    /// resolved at compare time would let `http://127.0.0.1:1/a/../../cb` reach
    /// a callback registered as `/cb`. Splitting the canonical bytes cannot do
    /// that, because it never interprets them.
    fn loopback_parts(uri: &str) -> Option<(&str, &str)> {
        let after_scheme = uri.strip_prefix("http://")?;
        // A canonical `http` URL always renders a path, so the authority always
        // ends at a `/`. `?` and `#` cannot precede it.
        let authority_end = after_scheme.find('/')?;
        let (authority, rest) = after_scheme.split_at(authority_end);
        let host_end = if authority.starts_with('[') {
            // An IPv6 literal carries `:` inside its brackets, so the port
            // separator is the one after `]`, never the first one.
            authority.find(']')? + 1
        } else {
            authority.find(':').unwrap_or(authority.len())
        };
        let (host, port) = authority.split_at(host_end);
        // Everything after the host must be a port and nothing else: this is
        // what stops `127.0.0.1:1@evil.example` from being read as the loopback
        // host with a strange port.
        let port_only = match port.strip_prefix(':') {
            Some(digits) => !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
            None => port.is_empty(),
        };
        if !port_only {
            return None;
        }
        Some((host, rest))
    }
}

impl std::fmt::Display for RedirectUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// The registration document, as received
// ---------------------------------------------------------------------------

/// A client registration document, exactly as it arrived.
///
/// Every field is optional because RFC 7591 §2 makes every field optional; the
/// question of which combinations are admissible is [`ClientMetadata::validate`]
/// and not serde's. Unknown members are ignored rather than refused, which is
/// what RFC 7591 §3.2.1 expects of an authorization server that does not
/// implement an extension.
///
/// Deliberately not `#[non_exhaustive]`: the storage adapter rebuilds this
/// document from a row and puts it back through [`ClientMetadata::validate`],
/// so that a row is checked by the same code that checked the registration.
/// Sealing the struct would force that path through a builder instead, with
/// less type checking and a second place for a field to be forgotten.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ClientMetadata {
    /// Human-readable name, shown on the consent screen.
    pub client_name: Option<String>,
    /// OIDC Registration §2. `web` or `native`.
    pub application_type: Option<String>,
    /// RFC 7591 §2.
    pub token_endpoint_auth_method: Option<String>,
    /// RFC 7591 §2.
    pub redirect_uris: Option<Vec<String>>,
    /// OIDC RP-Initiated Logout 1.0 §3.1.
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// RFC 7591 §2.
    pub grant_types: Option<Vec<String>>,
    /// RFC 7591 §2.
    pub response_types: Option<Vec<String>>,
    /// RFC 7591 §2, space-delimited per RFC 6749 §3.3.
    pub scope: Option<String>,
    /// RFC 7591 §2. Mutually exclusive with `jwks_uri`.
    pub jwks: Option<serde_json::Value>,
    /// RFC 7591 §2. Mutually exclusive with `jwks`.
    pub jwks_uri: Option<String>,
    /// OIDC Registration §2.
    pub id_token_signed_response_alg: Option<String>,
    /// OIDC Registration §2.
    pub request_object_signing_alg: Option<String>,
    /// CIBA Core 1.0 §4.
    pub backchannel_authentication_request_signing_alg: Option<String>,
    /// OIDC Registration §2.
    pub subject_type: Option<String>,
    /// OIDC Registration §2, OIDC Core §8.1.
    pub sector_identifier_uri: Option<String>,
    /// RFC 9126 §6.
    pub require_pushed_authorization_requests: Option<bool>,
    /// RFC 9449 §5.2.
    pub dpop_bound_access_tokens: Option<bool>,
    /// RFC 8705 §3.4.
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// RFC 8705 §2.1.2. Exactly one of these five is registered, and only by a
    /// `tls_client_auth` client — see [`TlsClientAuthSubject`].
    pub tls_client_auth_subject_dn: Option<String>,
    /// RFC 8705 §2.1.2.
    pub tls_client_auth_san_dns: Option<String>,
    /// RFC 8705 §2.1.2.
    pub tls_client_auth_san_uri: Option<String>,
    /// RFC 8705 §2.1.2.
    pub tls_client_auth_san_ip: Option<String>,
    /// RFC 8705 §2.1.2.
    pub tls_client_auth_san_email: Option<String>,
    /// RFC 9396 §9.2.
    pub authorization_details_types: Option<Vec<String>>,
    /// FAPI 2.0 SP §5.2.2.1.1, RFC 8705 §5.
    pub use_mtls_endpoint_aliases: Option<bool>,
    /// OIDC Registration §2. Absent means OIDC Core §5.3.2's default, a plain
    /// JSON UserInfo response.
    pub userinfo_signed_response_alg: Option<String>,
}

// ---------------------------------------------------------------------------
// The registration document, validated
// ---------------------------------------------------------------------------

/// Client metadata that has been through [`ClientMetadata::validate`].
///
/// Every field here is a typed value the rest of the server may rely on without
/// re-checking: the auth method is one this deployment implements, the grant
/// types are enabled, the redirect URIs are https (or loopback on a native
/// client), the algorithms are on ADR-0003's list, and the access tokens are
/// bound to something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistration {
    /// Shown on the consent screen.
    pub client_name: String,
    /// OIDC Registration §2.
    pub application_type: ApplicationType,
    /// How the client authenticates.
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// RFC 8705 §2.1.2. `Some` exactly when the method is `tls_client_auth`.
    ///
    /// The invariant is established by [`ClientMetadata::validate`] and relied
    /// on by the authenticator: a PKI-mode client with no registered subject
    /// would be a client whose certificate is compared to nothing, which is a
    /// client any certificate authenticates.
    pub tls_client_auth_subject: Option<TlsClientAuthSubject>,
    /// Registered callbacks, in the order registered, compared byte-exactly.
    pub redirect_uris: Vec<RedirectUri>,
    /// Registered post-logout callbacks (OIDC RP-Initiated Logout 1.0 §3.1),
    /// in the order registered.
    ///
    /// Admissibility is [`RedirectUri::parse`]'s, the same gate the
    /// authorization callbacks pass — these are redirect targets too, and a
    /// second, laxer definition of an acceptable one is exactly what ADR-0005
    /// exists to prevent. Equivalence, however, is **not**
    /// [`RedirectUri::is_registered`]: see
    /// [`accepts_post_logout_redirect_uri`].
    ///
    /// [`accepts_post_logout_redirect_uri`]: ClientRegistration::accepts_post_logout_redirect_uri
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// What the client may ask for at the token endpoint.
    pub grant_types: BTreeSet<GrantType>,
    /// Scopes the client may request, from RFC 7591 §2's `scope` string.
    pub scopes: BTreeSet<String>,
    /// Resource indicators (RFC 8707) this client may name. Not settable from
    /// a registration document: the per-client audience allow-list is policy,
    /// and `ast-m9c.6` owns it.
    pub resources: BTreeSet<String>,
    /// Where the client's keys come from.
    pub jwks: JwksSource,
    /// OIDC Registration §2.
    pub id_token_signed_response_alg: SigningAlgorithm,
    /// OIDC Registration §2. `None` means the client registered no request
    /// objects; JAR is `ast-s36.1` and is not implemented.
    pub request_object_signing_alg: Option<SigningAlgorithm>,
    /// CIBA Core 1.0 §4. `None` unless the client registered one.
    pub backchannel_authentication_request_signing_alg: Option<SigningAlgorithm>,
    /// OIDC Core §8.
    pub subject_type: SubjectType,
    /// OIDC Core §8.1. Required when `subject_type` is pairwise and the
    /// redirect URIs span more than one host.
    pub sector_identifier_uri: Option<String>,
    /// What the client's access tokens are bound to.
    pub token_binding: TokenBinding,
    /// RFC 9396 §9.2. Which `authorization_details` types the client may use.
    pub authorization_details_types: BTreeSet<String>,
    /// FAPI 2.0 SP §5.2.2.1.1.
    pub use_mtls_endpoint_aliases: bool,
    /// OIDC Registration §2. `None` is OIDC Core §5.3.2's default: "the
    /// UserInfo Claims are returned as a UTF-8 encoded JSON object". `Some`
    /// makes `/userinfo` answer `application/jwt`, signed by this tenant —
    /// which is why registering one is checked against the tenant's keys
    /// (`register::unsignable`) as `id_token_signed_response_alg` is.
    pub userinfo_signed_response_alg: Option<SigningAlgorithm>,
}

impl ClientRegistration {
    /// The metadata members whose algorithm *this server* signs with, paired
    /// with what this registration put in them.
    ///
    /// A table rather than a line per field, and in the domain rather than at
    /// one endpoint, because two callers ask the same question of it: dynamic
    /// registration refuses a document whose tenant holds no key for one of
    /// these (`register::unsignable`), and the admin API refuses the same
    /// client at the console form (`asterius_admin_api::clients::check_signable`).
    /// Two lists would let one door create a client the other would have
    /// refused, which is the failure `ast-f7m.5` exists to prevent.
    ///
    /// `None` in the second position means the client registered no such
    /// member: nothing to check rather than something to refuse.
    /// `backchannel_authentication_request_signing_alg` is absent altogether
    /// because it names an algorithm the *client* signs with and this server
    /// only verifies, so it needs no key of ours.
    #[must_use]
    pub fn server_signed_algorithms(&self) -> [(&'static str, Option<SigningAlgorithm>); 3] {
        [
            // OIDC Registration §2. Always present — it has a profile default
            // — so this entry is never `None`.
            (
                "id_token_signed_response_alg",
                Some(self.id_token_signed_response_alg),
            ),
            // OIDC Core §5.3.2. `None` is the plain-JSON UserInfo response,
            // which needs no key at all (`ast-e89`).
            (
                "userinfo_signed_response_alg",
                self.userinfo_signed_response_alg,
            ),
            // OIDC Registration §2, and still `None` now that `ast-gxh.9` has
            // landed the JAR path. The direction is what decides the entry, not
            // whether the feature exists: this names the algorithm the *client*
            // signs its request objects with and this server verifies against
            // the client's own published keys, so there is no key of ours whose
            // absence could make the registration a promise this tenant cannot
            // keep. The row stays rather than becoming a comment, so that the
            // next reader sees the question was asked.
            ("request_object_signing_alg", None),
        ]
    }

    /// The only `response_types` value this server accepts (ADR-0002: no
    /// implicit flow, no hybrid flow, so `code` is the only response type that
    /// exists).
    pub const RESPONSE_TYPES: [&'static str; 1] = ["code"];

    /// RFC 9126 §6 `require_pushed_authorization_requests`, which is `true` for
    /// every client and cannot be set otherwise. PAR is the only way to start
    /// an authorization request (ADR-0002), so there is nothing for a `false`
    /// to select.
    pub const REQUIRE_PUSHED_AUTHORIZATION_REQUESTS: bool = true;

    /// The most redirect URIs one client may register.
    pub const MAX_REDIRECT_URIS: usize = 32;
    /// The most post-logout redirect URIs one client may register.
    pub const MAX_POST_LOGOUT_REDIRECT_URIS: usize = 32;
    /// The most scopes one client may register.
    pub const MAX_SCOPES: usize = 64;
    /// The longest a single scope token may be.
    pub const MAX_SCOPE_LEN: usize = 128;
    /// The most `authorization_details` types one client may register.
    pub const MAX_AUTHORIZATION_DETAILS_TYPES: usize = 32;
    /// The longest a client name may be.
    pub const MAX_CLIENT_NAME_LEN: usize = 200;

    /// Parses and validates a registration document.
    ///
    /// This is the entry point every caller reaches: dynamic client
    /// registration (`ast-m9c.4`), the admin API and the seed scripts all go
    /// through it, so there is one definition of an acceptable client rather
    /// than one per caller.
    ///
    /// # Errors
    ///
    /// Returns [`ClientMetadataError`], whose [`code`] is the RFC 7591 §3.2.2
    /// error code to return.
    ///
    /// [`code`]: ClientMetadataError::code
    // fuzz-target: client_metadata_json
    pub fn from_json(
        document: &[u8],
        capabilities: Capabilities,
    ) -> Result<Self, ClientMetadataError> {
        let metadata: ClientMetadata = serde_json::from_slice(document).map_err(|error| {
            // The message is deliberately dropped: `serde_json` renders the
            // offending value into it ("invalid type: string \"…\""), and that
            // value came from the network. The position is enough to fix a
            // document and carries nothing back out.
            ClientMetadataError::Malformed {
                kind: match error.classify() {
                    serde_json::error::Category::Io => "io",
                    serde_json::error::Category::Syntax => "syntax",
                    serde_json::error::Category::Data => "type",
                    serde_json::error::Category::Eof => "eof",
                },
                line: error.line(),
                column: error.column(),
            }
        })?;
        metadata.validate(capabilities)
    }

    /// The `sector_identifier_uri` this registration still owes a fetch, if
    /// any.
    ///
    /// `Some` only for a pairwise client that named one: a public client cannot
    /// carry the field at all ([`ClientMetadata::validate`] refuses it), and a
    /// pairwise client that named none takes its sector from its single
    /// redirect host, which it demonstrably controls already.
    #[must_use]
    pub fn sector_identifier_uri_to_verify(&self) -> Option<&str> {
        if self.subject_type == SubjectType::Pairwise {
            self.sector_identifier_uri.as_deref()
        } else {
            None
        }
    }

    /// Checks a fetched `sector_identifier_uri` document against this
    /// registration — OIDC Registration §5.
    ///
    /// The document is "a JSON file containing an array of `redirect_uri`
    /// values", and §5 requires the authorization server to verify that the
    /// `redirect_uris` registered here are *all* in it. That check is the only
    /// thing tying a client to the sector it names: without it any client may
    /// claim any sector, and two unrelated clients claiming one sector are
    /// handed the same `sub` for the same user — which is the correlation
    /// pairwise subjects exist to prevent, defeated for both of them.
    ///
    /// Comparison is byte-exact, as ADR-0005 makes it everywhere a redirect URI
    /// is compared: a document listing a URI that merely normalises to a
    /// registered one has not shown that the sector's owner knows about the
    /// registered one.
    ///
    /// This is pure — the fetching is `asterius_server::outbound` and ADR-0006
    /// governs it. The split is what keeps the rule testable without a socket.
    ///
    /// # Errors
    ///
    /// Returns [`ClientMetadataError::Rejected`] when the document is not a
    /// JSON array of strings, or omits any registered redirect URI.
    pub fn check_sector_identifier_document(
        &self,
        document: &[u8],
    ) -> Result<(), ClientMetadataError> {
        const FIELD: &str = "sector_identifier_uri";
        let listed: Vec<String> = serde_json::from_slice(document).map_err(|_| {
            ClientMetadataError::rejected(
                FIELD,
                "must serve a JSON array of redirect URI strings (OIDC Registration §5)",
            )
        })?;
        let listed: BTreeSet<&str> = listed.iter().map(String::as_str).collect();
        if self
            .redirect_uris
            .iter()
            .any(|uri| !listed.contains(uri.as_str()))
        {
            // Which URI is missing is not said: the answer is in the document
            // the client published, and repeating a registered redirect URI in
            // an error body is how a registration endpoint becomes a way to
            // read one back.
            return Err(ClientMetadataError::rejected(
                FIELD,
                "must list every registered redirect_uri (OIDC Registration §5)",
            ));
        }
        Ok(())
    }

    /// Whether the client may use `grant`.
    #[must_use]
    pub fn allows(&self, grant: GrantType) -> bool {
        self.grant_types.contains(&grant)
    }

    /// Whether `presented` is one of this client's registered redirect URIs.
    ///
    /// The callers are PAR (`ast-gxh.1`) and the token endpoint (`ast-a05.2`),
    /// and this exists so that neither of them has to remember to pass the
    /// application type — forgetting it would silently withdraw the
    /// RFC 8252 §7.3 loopback exception from every native client, which fails
    /// closed but breaks them all.
    ///
    /// See [`RedirectUri::is_registered`] for what "one of" means, and ADR-0005
    /// for why the set is consulted at all under PAR.
    #[must_use]
    pub fn accepts_redirect_uri(&self, presented: &str) -> bool {
        RedirectUri::is_registered(&self.redirect_uris, presented, self.application_type)
    }

    /// The registered `post_logout_redirect_uris`, as the owned strings §3
    /// compares.
    ///
    /// The end-session endpoint matches "byte for byte", with no exception at
    /// all — not even RFC 8252 §7.3's loopback port, which belongs to the
    /// authorization callback a native client cannot predict the port of and
    /// not to a logout link the same client writes down at build time. Handing
    /// out `&str` rather than `&[RedirectUri]` is what keeps that true: the
    /// caller cannot reach [`RedirectUri::is_registered`] and pick up the
    /// exception by accident.
    #[must_use]
    pub fn registered_post_logout_redirect_uris(&self) -> Vec<String> {
        self.post_logout_redirect_uris
            .iter()
            .map(|uri| uri.as_str().to_owned())
            .collect()
    }

    /// Whether `presented` is one of this client's registered post-logout
    /// redirect URIs — OIDC RP-Initiated Logout 1.0 §3, exact match.
    #[must_use]
    pub fn accepts_post_logout_redirect_uri(&self, presented: &str) -> bool {
        self.post_logout_redirect_uris
            .iter()
            .any(|uri| uri.as_str() == presented)
    }

    /// The `response_types` this registration implies.
    ///
    /// Derived, never stored as an independent fact. RFC 7591 §2.1 ties
    /// `response_types` to `grant_types`, and [`ClientMetadata::validate`]
    /// refuses a document where the two disagree — so a registration carrying
    /// its own copy would be a second place for the same answer to live, and
    /// the two would eventually differ.
    ///
    /// There are exactly two callers and they must not diverge: the storage
    /// adapter writing the `response_types` column, and dynamic client
    /// registration echoing the stored registration back (RFC 7591 §3.2.1). If
    /// the renderer and the writer computed this separately, a client could be
    /// told it registered `["code"]` while the row said otherwise.
    #[must_use]
    pub fn response_types(&self) -> &'static [&'static str] {
        if self
            .grant_types
            .iter()
            .any(|grant| grant.uses_the_authorization_endpoint())
        {
            &Self::RESPONSE_TYPES
        } else {
            &[]
        }
    }
}

impl ClientMetadata {
    /// Writes a registered subject back into the document it came from.
    ///
    /// The storage adapter's inverse of the private `tls_client_auth_subject`
    /// reader: a row holds the field name and the value in two columns, and
    /// this puts them back under the one member of the five they name, so the
    /// reloaded document goes through the same "exactly one" check as a
    /// document that arrived over the wire.
    pub fn set_tls_client_auth_subject(&mut self, subject: &TlsClientAuthSubject) {
        let value = Some(subject.value().to_owned());
        match subject {
            TlsClientAuthSubject::SubjectDn(_) => self.tls_client_auth_subject_dn = value,
            TlsClientAuthSubject::SanDns(_) => self.tls_client_auth_san_dns = value,
            TlsClientAuthSubject::SanUri(_) => self.tls_client_auth_san_uri = value,
            TlsClientAuthSubject::SanIp(_) => self.tls_client_auth_san_ip = value,
            TlsClientAuthSubject::SanEmail(_) => self.tls_client_auth_san_email = value,
        }
    }

    /// Validates the document against the FAPI 2.0 profile and this
    /// deployment's capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`ClientMetadataError`] describing the first rule broken. The
    /// order the rules run in is fixed rather than incidental: a document that
    /// breaks several of them must always be told about the same one, or two
    /// callers submitting the same document get two different diagnoses.
    pub fn validate(
        &self,
        capabilities: Capabilities,
    ) -> Result<ClientRegistration, ClientMetadataError> {
        let token_endpoint_auth_method = self.auth_method(capabilities)?;
        let tls_client_auth_subject =
            self.tls_client_auth_subject(token_endpoint_auth_method, capabilities)?;
        let application_type = self.application_type()?;
        let grant_types = self.grant_types(capabilities)?;
        self.check_response_types(&grant_types)?;
        let redirect_uris = self.redirect_uris(application_type, &grant_types)?;
        let post_logout_redirect_uris = self.post_logout_redirect_uris(application_type)?;
        let jwks = self.jwks()?;
        let (subject_type, sector_identifier_uri) = self.subject(&redirect_uris)?;
        let token_binding = self.token_binding(capabilities)?;

        self.check_par()?;
        let use_mtls_endpoint_aliases = self.mtls_endpoint_aliases(capabilities)?;

        Ok(ClientRegistration {
            client_name: self.client_name()?,
            application_type,
            token_endpoint_auth_method,
            tls_client_auth_subject,
            redirect_uris,
            post_logout_redirect_uris,
            grant_types,
            scopes: self.scopes()?,
            resources: BTreeSet::new(),
            jwks,
            id_token_signed_response_alg: match &self.id_token_signed_response_alg {
                Some(raw) => signing_algorithm("id_token_signed_response_alg", raw)?,
                None => SigningAlgorithm::DEFAULT,
            },
            request_object_signing_alg: self
                .request_object_signing_alg
                .as_deref()
                .map(|raw| signing_algorithm("request_object_signing_alg", raw))
                .transpose()?,
            backchannel_authentication_request_signing_alg: self
                .backchannel_authentication_request_signing_alg
                .as_deref()
                .map(|raw| signing_algorithm("backchannel_authentication_request_signing_alg", raw))
                .transpose()?,
            subject_type,
            sector_identifier_uri,
            token_binding,
            authorization_details_types: self.authorization_details_types()?,
            use_mtls_endpoint_aliases,
            userinfo_signed_response_alg: self
                .userinfo_signed_response_alg
                .as_deref()
                .map(|raw| signing_algorithm("userinfo_signed_response_alg", raw))
                .transpose()?,
        })
    }

    fn client_name(&self) -> Result<String, ClientMetadataError> {
        const FIELD: &str = "client_name";
        let name = self.client_name.as_deref().unwrap_or_default().trim();
        if name.is_empty() {
            // RFC 7591 §2 makes every field optional, and this is the one place
            // this server insists. The name is what the consent screen asks the
            // user to authorise; a client with no name produces a prompt that
            // names nobody, which is the shape a consent-phishing client wants.
            return Err(ClientMetadataError::Missing { field: FIELD });
        }
        if name.chars().count() > ClientRegistration::MAX_CLIENT_NAME_LEN {
            return Err(ClientMetadataError::rejected(
                FIELD,
                format!(
                    "must be at most {} characters",
                    ClientRegistration::MAX_CLIENT_NAME_LEN
                ),
            ));
        }
        // The name is rendered on the consent screen. Escaping is the template
        // layer's job, but escaping does not help against a right-to-left
        // override, which reorders the *displayed* text without changing a byte
        // of the markup — "Bank of Acme" and a reversed run of the same
        // characters look identical to the user being asked to consent.
        if let Some(bad) = name
            .chars()
            .find(|c| c.is_control() || matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        {
            return Err(ClientMetadataError::rejected(
                FIELD,
                format!(
                    "must not contain control or bidirectional formatting characters (U+{:04X})",
                    u32::from(bad)
                ),
            ));
        }
        Ok(name.to_owned())
    }

    fn auth_method(
        &self,
        capabilities: Capabilities,
    ) -> Result<TokenEndpointAuthMethod, ClientMetadataError> {
        const FIELD: &str = "token_endpoint_auth_method";
        let Some(raw) = self.token_endpoint_auth_method.as_deref() else {
            return Ok(TokenEndpointAuthMethod::DEFAULT);
        };
        // The rejected value is not echoed: it is one of the few fields a
        // caller mistakenly fills with a secret-bearing method name next to the
        // secret itself.
        let method = TokenEndpointAuthMethod::parse(raw).ok_or_else(|| {
            ClientMetadataError::rejected(
                FIELD,
                "must be private_key_jwt, tls_client_auth or self_signed_tls_client_auth; \
                 this server has no client secrets and does not accept unauthenticated \
                 clients (FAPI 2.0 SP §5.3.2.1 item 3)",
            )
        })?;
        if method.requires_mtls() && !capabilities.is_enabled(Feature::Mtls) {
            return Err(ClientMetadataError::needs(FIELD, Feature::Mtls));
        }
        Ok(method)
    }

    fn application_type(&self) -> Result<ApplicationType, ClientMetadataError> {
        match self.application_type.as_deref() {
            None => Ok(ApplicationType::default()),
            Some(raw) => ApplicationType::parse(raw).ok_or_else(|| {
                ClientMetadataError::rejected("application_type", "must be `web` or `native`")
            }),
        }
    }

    fn grant_types(
        &self,
        capabilities: Capabilities,
    ) -> Result<BTreeSet<GrantType>, ClientMetadataError> {
        const FIELD: &str = "grant_types";
        let Some(raw) = self.grant_types.as_deref() else {
            return Ok(GrantType::DEFAULT.into_iter().collect());
        };
        if raw.is_empty() {
            return Err(ClientMetadataError::Missing { field: FIELD });
        }
        let mut grants = BTreeSet::new();
        for entry in raw {
            let grant = GrantType::parse(entry).ok_or_else(|| {
                ClientMetadataError::rejected(
                    FIELD,
                    "contains a grant type this server does not implement; the set is \
                     authorization_code, refresh_token, client_credentials, token-exchange, \
                     device_code and ciba",
                )
            })?;
            if let Some(feature) = grant.required_feature()
                && !capabilities.is_enabled(feature)
            {
                return Err(ClientMetadataError::needs(FIELD, feature));
            }
            if !grants.insert(grant) {
                return Err(ClientMetadataError::rejected(
                    FIELD,
                    "must not repeat a grant type",
                ));
            }
        }
        Ok(grants)
    }

    /// RFC 7591 §2.1: `code` and `authorization_code` correspond, and a server
    /// "SHOULD take steps to ensure that a client cannot register itself into
    /// an inconsistent state".
    ///
    /// Here the correspondence is exact in both directions. `["code"]` is the
    /// only non-empty value this server accepts, because there is no implicit
    /// or hybrid flow for the other values to name (ADR-0002). An empty list is
    /// how a client that never reaches the authorization endpoint — a
    /// `client_credentials` client — says so, and RFC 7591 §2.1's table has no
    /// response type for that grant.
    fn check_response_types(
        &self,
        grants: &BTreeSet<GrantType>,
    ) -> Result<(), ClientMetadataError> {
        const FIELD: &str = "response_types";
        let uses_authorization_code = grants.contains(&GrantType::AuthorizationCode);
        let requests_code = match self.response_types.as_deref() {
            // RFC 7591 §2's default is ["code"], which is consistent with the
            // default grant_types. A client that named grant_types explicitly
            // and left response_types out gets the default read the same way.
            None => true,
            Some([]) => false,
            Some([only]) if only == ClientRegistration::RESPONSE_TYPES[0] => true,
            Some(_) => {
                return Err(ClientMetadataError::rejected(
                    FIELD,
                    "must be [\"code\"]; there is no implicit or hybrid flow here",
                ));
            }
        };

        match (!requests_code, uses_authorization_code) {
            (false, false) => Err(ClientMetadataError::rejected(
                FIELD,
                "is [\"code\"] but grant_types does not contain authorization_code \
                 (RFC 7591 §2.1)",
            )),
            (true, true) => Err(ClientMetadataError::rejected(
                FIELD,
                "is empty but grant_types contains authorization_code (RFC 7591 §2.1)",
            )),
            _ => Ok(()),
        }
    }

    fn redirect_uris(
        &self,
        application_type: ApplicationType,
        grants: &BTreeSet<GrantType>,
    ) -> Result<Vec<RedirectUri>, ClientMetadataError> {
        const FIELD: &str = "redirect_uris";
        let needed = grants.iter().any(|g| g.uses_the_authorization_endpoint());
        let raw = self.redirect_uris.as_deref().unwrap_or_default();

        if raw.is_empty() {
            if needed {
                return Err(ClientMetadataError::Missing { field: FIELD });
            }
            return Ok(Vec::new());
        }
        if !needed {
            // Dead configuration on a client that cannot reach the
            // authorization endpoint. It is refused rather than ignored because
            // adding `authorization_code` later would activate a callback list
            // nobody reviewed at the time it was added.
            return Err(ClientMetadataError::rejected(
                FIELD,
                "must be absent unless grant_types contains authorization_code",
            ));
        }
        if raw.len() > ClientRegistration::MAX_REDIRECT_URIS {
            return Err(ClientMetadataError::rejected(
                FIELD,
                format!(
                    "must contain at most {} entries",
                    ClientRegistration::MAX_REDIRECT_URIS
                ),
            ));
        }

        let mut uris: Vec<RedirectUri> = Vec::with_capacity(raw.len());
        for (index, entry) in raw.iter().enumerate() {
            let uri = RedirectUri::parse(entry, application_type).map_err(|error| {
                ClientMetadataError::RedirectUri {
                    index,
                    reason: error.to_string(),
                }
            })?;
            // The duplicate check is the same comparison the authorization
            // endpoint will make, not `Vec::contains`: two loopback entries
            // that differ only in their port are one entry as far as
            // RFC 8252 §7.3 is concerned, so registering both would put a
            // second, unreviewed spelling of one callback in the set.
            if RedirectUri::is_registered(&uris, uri.as_str(), application_type) {
                return Err(ClientMetadataError::RedirectUri {
                    index,
                    reason: "duplicates an earlier entry".to_owned(),
                });
            }
            uris.push(uri);
        }
        Ok(uris)
    }

    /// OIDC RP-Initiated Logout 1.0 §3.1 `post_logout_redirect_uris`.
    ///
    /// These are redirect targets, and the end-session endpoint sends a browser
    /// to one on a request that carries no client authentication at all — so
    /// they go through [`RedirectUri::parse`], the same gate the authorization
    /// callbacks pass. Writing a second, gentler check here is the mistake
    /// ADR-0005 exists to forbid: a `post_logout_redirect_uri` with a fragment,
    /// with userinfo in its authority, over plain `http`, or in a spelling no
    /// URL parser produces is exactly as dangerous after a logout as before an
    /// authorization, and rather more likely to be looked at less closely.
    ///
    /// Unlike `redirect_uris` this member is never *required*: §3.1 makes it
    /// optional, and a client that registers none simply cannot be redirected
    /// after a logout.
    fn post_logout_redirect_uris(
        &self,
        application_type: ApplicationType,
    ) -> Result<Vec<RedirectUri>, ClientMetadataError> {
        let raw = self
            .post_logout_redirect_uris
            .as_deref()
            .unwrap_or_default();
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        if raw.len() > ClientRegistration::MAX_POST_LOGOUT_REDIRECT_URIS {
            return Err(ClientMetadataError::rejected(
                "post_logout_redirect_uris",
                format!(
                    "must contain at most {} entries",
                    ClientRegistration::MAX_POST_LOGOUT_REDIRECT_URIS
                ),
            ));
        }

        let mut uris: Vec<RedirectUri> = Vec::with_capacity(raw.len());
        for (index, entry) in raw.iter().enumerate() {
            let uri = RedirectUri::parse(entry, application_type).map_err(|error| {
                ClientMetadataError::PostLogoutRedirectUri {
                    index,
                    reason: error.to_string(),
                }
            })?;
            // Byte equality, not `RedirectUri::is_registered`: §3's comparison
            // has no loopback-port exception, so two native entries differing
            // only in their port really are two distinct registrations here,
            // and refusing the second would refuse something usable.
            if uris.iter().any(|earlier| earlier.as_str() == uri.as_str()) {
                return Err(ClientMetadataError::PostLogoutRedirectUri {
                    index,
                    reason: "duplicates an earlier entry".to_owned(),
                });
            }
            uris.push(uri);
        }
        Ok(uris)
    }

    fn jwks(&self) -> Result<JwksSource, ClientMetadataError> {
        match (&self.jwks, &self.jwks_uri) {
            // RFC 7591 §2: "The jwks_uri and jwks parameters MUST NOT both be
            // present in the same request or response."
            (Some(_), Some(_)) => Err(ClientMetadataError::rejected(
                "jwks",
                "must not be given together with jwks_uri (RFC 7591 §2)",
            )),
            // Every client here is confidential and authenticates with a key,
            // whether a client assertion or a certificate matched against its
            // JWKS, so a client with no key source is a client that cannot
            // authenticate. The schema says the same thing in
            // `clients_exactly_one_key_source`.
            (None, None) => Err(ClientMetadataError::Missing { field: "jwks_uri" }),
            (Some(jwks), None) => {
                // Shape only. Whether the keys are usable — `kty`, `use`, the
                // RSA ≥ 2048 and EC ≥ 224 floors of FAPI 2.0 SP §5.4.1 — is
                // `ast-mxc.5`, which is also where they are turned into
                // verifiers.
                let keys = jwks
                    .get("keys")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| {
                        ClientMetadataError::rejected(
                            "jwks",
                            "must be a JSON object with a `keys` array (RFC 7517 §5)",
                        )
                    })?;
                if keys.is_empty() || !keys.iter().all(serde_json::Value::is_object) {
                    return Err(ClientMetadataError::rejected(
                        "jwks",
                        "`keys` must be a non-empty array of JWK objects (RFC 7517 §5)",
                    ));
                }
                Ok(JwksSource::Inline(jwks.clone()))
            }
            (None, Some(uri)) => {
                https_url("jwks_uri", uri)?;
                Ok(JwksSource::Uri(uri.clone()))
            }
        }
    }

    fn subject(
        &self,
        redirect_uris: &[RedirectUri],
    ) -> Result<(SubjectType, Option<String>), ClientMetadataError> {
        const FIELD: &str = "sector_identifier_uri";
        let subject_type = match self.subject_type.as_deref() {
            None => SubjectType::default(),
            Some(raw) => SubjectType::parse(raw).ok_or_else(|| {
                ClientMetadataError::rejected("subject_type", "must be `public` or `pairwise`")
            })?,
        };

        let sector = self.sector_identifier_uri.as_deref().map(str::trim);
        match (subject_type, sector) {
            (SubjectType::Public, Some(_)) => {
                // The sector identifier is only consulted when computing a
                // pairwise `sub` (OIDC Core §8.1). Stored against a public
                // client it is a value nothing reads — until someone flips
                // `subject_type` and it silently starts deciding identifiers.
                Err(ClientMetadataError::rejected(
                    FIELD,
                    "is only meaningful when subject_type is pairwise",
                ))
            }
            (SubjectType::Public, None) => Ok((subject_type, None)),
            (SubjectType::Pairwise, Some(uri)) => {
                // The document itself is fetched and checked against the
                // registered redirect URIs by
                // [`ClientRegistration::check_sector_identifier_document`],
                // over the ADR-0006 outbound path — I/O, so not here.
                https_url(FIELD, uri)?;
                Ok((subject_type, Some(uri.to_owned())))
            }
            (SubjectType::Pairwise, None) => {
                // OIDC Core §8.1: without a sector_identifier_uri the sector is
                // the host of the registered redirect URI, so more than one
                // host leaves the identifier undefined.
                let mut hosts = BTreeSet::new();
                for uri in redirect_uris {
                    if let Ok(url) = Url::parse(uri.as_str())
                        && let Some(host) = url.host_str()
                    {
                        hosts.insert(host.to_owned());
                    }
                }
                if hosts.len() > 1 {
                    return Err(ClientMetadataError::Missing { field: FIELD });
                }
                Ok((subject_type, None))
            }
        }
    }

    fn token_binding(
        &self,
        capabilities: Capabilities,
    ) -> Result<TokenBinding, ClientMetadataError> {
        const CERT_FIELD: &str = "tls_client_certificate_bound_access_tokens";
        // RFC 9449 §5.2 gives this a default of false. Here the default is true:
        // FAPI 2.0 SP §5.3.2.1 requires sender-constrained access tokens, and a
        // client that says nothing must not end up with the weaker of the two
        // readings.
        let dpop = self.dpop_bound_access_tokens.unwrap_or(true);
        let certificate = self
            .tls_client_certificate_bound_access_tokens
            .unwrap_or(false);
        if certificate && !capabilities.is_enabled(Feature::Mtls) {
            return Err(ClientMetadataError::needs(CERT_FIELD, Feature::Mtls));
        }
        TokenBinding::from_flags(dpop, certificate)
    }

    /// RFC 9126 §6 defaults `require_pushed_authorization_requests` to false.
    /// PAR is the only way to start an authorization request here (ADR-0002),
    /// so `false` is not a weaker setting, it is a request for a code path that
    /// does not exist — and answering it with a silent `true` would leave the
    /// client's own record claiming otherwise.
    fn check_par(&self) -> Result<(), ClientMetadataError> {
        if self.require_pushed_authorization_requests == Some(false) {
            return Err(ClientMetadataError::rejected(
                "require_pushed_authorization_requests",
                "must be true; the authorization endpoint accepts only a request_uri \
                 obtained from the pushed authorization request endpoint (RFC 9126 §2)",
            ));
        }
        Ok(())
    }

    /// RFC 8705 §2.1.2: exactly one `tls_client_auth_*` parameter, and only for
    /// a `tls_client_auth` client.
    ///
    /// Three rules, each of which is a way to end up with a certificate matched
    /// against nothing:
    ///
    /// 1. The fields need the `mtls` feature. Without it the deployment does
    ///    not advertise the methods and does not look at certificates, so
    ///    storing an expectation nobody will check is worse than refusing it —
    ///    the client's record would describe an authentication that cannot
    ///    happen.
    /// 2. A `tls_client_auth` client registers exactly one. None means every
    ///    certificate matches; two means the server picks.
    /// 3. Any other method registers none. `self_signed_tls_client_auth`
    ///    matches on the JWKS (§2.2) and `private_key_jwt` on a signature, so a
    ///    subject field there is a value that would never be read — and a
    ///    value that is never read is one an operator can believe is in force.
    fn tls_client_auth_subject(
        &self,
        method: TokenEndpointAuthMethod,
        capabilities: Capabilities,
    ) -> Result<Option<TlsClientAuthSubject>, ClientMetadataError> {
        let presented: Vec<(&'static str, &str)> = TlsClientAuthSubject::FIELDS
            .into_iter()
            .zip([
                self.tls_client_auth_subject_dn.as_deref(),
                self.tls_client_auth_san_dns.as_deref(),
                self.tls_client_auth_san_uri.as_deref(),
                self.tls_client_auth_san_ip.as_deref(),
                self.tls_client_auth_san_email.as_deref(),
            ])
            .filter_map(|(field, value)| value.map(|value| (field, value)))
            .collect();

        if let Some((field, _)) = presented.first()
            && !capabilities.is_enabled(Feature::Mtls)
        {
            return Err(ClientMetadataError::needs(field, Feature::Mtls));
        }

        if method != TokenEndpointAuthMethod::TlsClientAuth {
            return match presented.first() {
                None => Ok(None),
                Some((field, _)) => Err(ClientMetadataError::rejected(
                    field,
                    "is only registered by a tls_client_auth client; \
                     self_signed_tls_client_auth matches the certificate against the \
                     client's own JWKS instead (RFC 8705 §2.2)",
                )),
            };
        }

        let [(field, value)] = presented[..] else {
            // Both "none" and "more than one" are the same defect — the
            // document does not name one thing to compare against — and RFC
            // 8705 §2.1.2 states them as one requirement, so they get one
            // message naming the whole set.
            return Err(ClientMetadataError::rejected(
                TlsClientAuthSubject::FIELDS[0],
                "a tls_client_auth client must register exactly one of \
                 tls_client_auth_subject_dn, tls_client_auth_san_dns, \
                 tls_client_auth_san_uri, tls_client_auth_san_ip or \
                 tls_client_auth_san_email (RFC 8705 §2.1.2)",
            ));
        };

        // Trimmed only at the ends, and only to catch the empty value: the
        // comparison itself is byte-exact, so a value with interior whitespace
        // is stored as written and will match only a certificate that says the
        // same.
        if value.trim().is_empty() {
            return Err(ClientMetadataError::Missing { field });
        }
        if value.len() > TlsClientAuthSubject::MAX_LEN {
            return Err(ClientMetadataError::rejected(
                field,
                format!("must be at most {} bytes", TlsClientAuthSubject::MAX_LEN),
            ));
        }
        // A control character cannot appear in any of the five certificate
        // forms this is compared against, and a newline in a stored expectation
        // is the shape that breaks whatever renders it back out.
        if value.chars().any(char::is_control) {
            return Err(ClientMetadataError::rejected(
                field,
                "must not contain control characters",
            ));
        }

        Ok(TlsClientAuthSubject::from_field(field, value))
    }

    fn mtls_endpoint_aliases(
        &self,
        capabilities: Capabilities,
    ) -> Result<bool, ClientMetadataError> {
        const FIELD: &str = "use_mtls_endpoint_aliases";
        let requested = self.use_mtls_endpoint_aliases.unwrap_or(false);
        if requested && !capabilities.is_enabled(Feature::Mtls) {
            return Err(ClientMetadataError::needs(FIELD, Feature::Mtls));
        }
        Ok(requested)
    }

    /// RFC 6749 §3.3: `scope = scope-token *( SP scope-token )`, where a
    /// `scope-token` is `1*( %x21 / %x23-5B / %x5D-7E )` — printable ASCII
    /// without space, `"` or `\`.
    fn scopes(&self) -> Result<BTreeSet<String>, ClientMetadataError> {
        const FIELD: &str = "scope";
        let Some(raw) = self.scope.as_deref() else {
            return Ok(BTreeSet::new());
        };
        let mut scopes = BTreeSet::new();
        // Splitting on a single space, not on whitespace: a tab or a newline in
        // a scope string is a character the grammar does not allow, and reading
        // it as a separator would accept a document the grammar rejects.
        for token in raw.split(' ').filter(|t| !t.is_empty()) {
            if token.len() > ClientRegistration::MAX_SCOPE_LEN {
                return Err(ClientMetadataError::rejected(
                    FIELD,
                    format!(
                        "a scope token must be at most {} bytes",
                        ClientRegistration::MAX_SCOPE_LEN
                    ),
                ));
            }
            if !token
                .bytes()
                .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
            {
                return Err(ClientMetadataError::rejected(
                    FIELD,
                    "a scope token may only contain printable ASCII other than space, \
                     '\"' and '\\' (RFC 6749 §3.3)",
                ));
            }
            if !scopes.insert(token.to_owned()) {
                return Err(ClientMetadataError::rejected(
                    FIELD,
                    "must not repeat a scope",
                ));
            }
            if scopes.len() > ClientRegistration::MAX_SCOPES {
                return Err(ClientMetadataError::rejected(
                    FIELD,
                    format!(
                        "must contain at most {} scopes",
                        ClientRegistration::MAX_SCOPES
                    ),
                ));
            }
        }
        Ok(scopes)
    }

    /// RFC 9396 §9.2. Which types are meaningful is a per-tenant policy
    /// question (`ast-m9c.6`); what is checked here is that the list is a set
    /// of non-empty names.
    fn authorization_details_types(&self) -> Result<BTreeSet<String>, ClientMetadataError> {
        const FIELD: &str = "authorization_details_types";
        let Some(raw) = self.authorization_details_types.as_deref() else {
            return Ok(BTreeSet::new());
        };
        if raw.len() > ClientRegistration::MAX_AUTHORIZATION_DETAILS_TYPES {
            return Err(ClientMetadataError::rejected(
                FIELD,
                format!(
                    "must contain at most {} entries",
                    ClientRegistration::MAX_AUTHORIZATION_DETAILS_TYPES
                ),
            ));
        }
        let mut types = BTreeSet::new();
        for entry in raw {
            let name = entry.trim();
            if name.is_empty() || name.chars().any(char::is_control) {
                return Err(ClientMetadataError::rejected(
                    FIELD,
                    "each entry must be a non-empty name without control characters",
                ));
            }
            if !types.insert(name.to_owned()) {
                return Err(ClientMetadataError::rejected(
                    FIELD,
                    "must not repeat a type",
                ));
            }
        }
        Ok(types)
    }
}

/// Parses an `alg` from client metadata against ADR-0003's allow-list.
///
/// `none` fails here like any other unknown name, because it is not a variant
/// of [`SigningAlgorithm`] — which is what makes "the client picked the
/// algorithm used to check its own credentials" unrepresentable rather than
/// merely tested for (RFC 8725 §3.1–3.2).
fn signing_algorithm(
    field: &'static str,
    raw: &str,
) -> Result<SigningAlgorithm, ClientMetadataError> {
    SigningAlgorithm::parse(raw).ok_or_else(|| {
        ClientMetadataError::rejected(
            field,
            "must be EdDSA, ES256 or PS256 (FAPI 2.0 SP §5.4.1); `none` and RS256 are \
             not accepted",
        )
    })
}

/// Checks a metadata URL that Asterius will later dereference or compare.
fn https_url(field: &'static str, raw: &str) -> Result<(), ClientMetadataError> {
    let url = Url::parse(raw)
        .map_err(|_| ClientMetadataError::rejected(field, "must be an absolute URL"))?;
    if url.scheme() != "https" {
        return Err(ClientMetadataError::rejected(field, "scheme must be https"));
    }
    // `Url` accepts `https:///jwks` and reports an empty host rather than none.
    if url.host_str().is_none_or(str::is_empty) {
        return Err(ClientMetadataError::rejected(field, "must contain a host"));
    }
    if url.fragment().is_some() {
        return Err(ClientMetadataError::rejected(
            field,
            "must not contain a fragment component",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The aggregate
// ---------------------------------------------------------------------------

/// A registered client.
///
/// Deliberately not `#[non_exhaustive]`, for the same reason as [`Tenant`]:
/// adapters build entities from rows, and a sealed struct would only push every
/// adapter through a constructor taking the same fields in the same order, with
/// less type checking.
///
/// [`Tenant`]: crate::Tenant
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// The tenant that owns this client. A `client_id` is unique within a
    /// tenant and means nothing outside it.
    pub tenant: TenantId,
    /// The `client_id`.
    pub id: ClientId,
    /// The validated metadata.
    pub registration: ClientRegistration,
    /// Whether the client answers requests.
    pub status: ClientStatus,
    /// When the client was registered.
    pub created_at: OffsetDateTime,
    /// When the registration was last modified.
    pub updated_at: OffsetDateTime,
}

impl Client {
    /// Whether this client may authenticate and be issued tokens.
    ///
    /// A disabled client fails client authentication rather than being told it
    /// is disabled: the distinction is only useful to somebody probing which
    /// `client_id` values exist.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == ClientStatus::Active
    }

    /// Whether the client may use `grant`.
    #[must_use]
    pub fn allows(&self, grant: GrantType) -> bool {
        self.registration.allows(grant)
    }

    /// Whether `presented` is one of this client's registered redirect URIs.
    ///
    /// Being active is a separate question: a redirect URI is checked before
    /// the user agent is sent anywhere (RFC 6749 §3.1.2.4 forbids redirecting
    /// to an invalid one to report the error), and a disabled client fails
    /// client authentication instead.
    #[must_use]
    pub fn accepts_redirect_uri(&self, presented: &str) -> bool {
        self.registration.accepts_redirect_uri(presented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn caps(mtls: bool) -> Capabilities {
        Capabilities {
            mtls,
            ..Capabilities::default()
        }
    }

    fn everything_on() -> Capabilities {
        Capabilities {
            mtls: true,
            grant_management: true,
            ciba: true,
            device_flow: true,
            token_exchange: true,
            ssf: true,
            authzen: true,
            dpop_nonce: true,
            request_object: true,
            dynamic_client_registration: true,
        }
    }

    /// The smallest document this server accepts.
    fn minimal() -> serde_json::Value {
        json!({
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "jwks": {"keys": [{"kty": "OKP"}]},
        })
    }

    fn validate(document: &serde_json::Value) -> Result<ClientRegistration, ClientMetadataError> {
        validate_with(document, caps(false))
    }

    fn validate_with(
        document: &serde_json::Value,
        capabilities: Capabilities,
    ) -> Result<ClientRegistration, ClientMetadataError> {
        ClientRegistration::from_json(
            serde_json::to_vec(document).expect("serialise").as_slice(),
            capabilities,
        )
    }

    /// A document built from [`minimal`] with `field` set to `value`.
    fn with(field: &str, value: serde_json::Value) -> serde_json::Value {
        let mut document = minimal();
        document
            .as_object_mut()
            .expect("object")
            .insert(field.to_owned(), value);
        document
    }

    fn without(field: &str) -> serde_json::Value {
        let mut document = minimal();
        document.as_object_mut().expect("object").remove(field);
        document
    }

    fn rejection(document: &serde_json::Value) -> ClientMetadataError {
        validate(document).expect_err("should have been rejected")
    }

    // -----------------------------------------------------------------------
    // The happy path, and the defaults
    // -----------------------------------------------------------------------

    /// A document that says only what it must settles everything else by
    /// omission, and every omission lands on the FAPI value rather than on the
    /// RFC's historical one.
    #[test]
    fn a_client_that_registers_nothing_optional_gets_the_profile_defaults() {
        let client = validate(&minimal()).expect("minimal document is valid");
        assert_eq!(
            client.token_endpoint_auth_method,
            TokenEndpointAuthMethod::PrivateKeyJwt,
            "RFC 7591 §2's client_secret_basic default must not survive here"
        );
        assert_eq!(client.application_type, ApplicationType::Web);
        assert_eq!(
            client.grant_types,
            BTreeSet::from([GrantType::AuthorizationCode])
        );
        assert_eq!(client.subject_type, SubjectType::Public);
        assert_eq!(
            client.id_token_signed_response_alg,
            SigningAlgorithm::EdDsa,
            "ADR-0003 makes EdDSA the default"
        );
        assert_eq!(client.request_object_signing_alg, None);
        assert!(!client.use_mtls_endpoint_aliases);
        assert_eq!(
            client.token_binding,
            TokenBinding::Dpop,
            "RFC 9449 §5.2 defaults dpop_bound_access_tokens to false; the profile does not"
        );
        assert!(client.token_binding.is_dpop_bound());
        const { assert!(ClientRegistration::REQUIRE_PUSHED_AUTHORIZATION_REQUESTS) };
    }

    /// RFC 7591 §3.2.1: an authorization server ignores registration metadata
    /// it does not implement rather than refusing the registration.
    #[test]
    fn unknown_metadata_fields_are_ignored_rather_than_refused() {
        let document = with("software_version", json!("4.2"));
        assert!(validate(&document).is_ok());
        let document = with("logo_uri", json!("https://rp.example/logo.png"));
        assert!(validate(&document).is_ok());
    }

    /// Validation must not depend on anything but its inputs: the admin API,
    /// the registration endpoint and the seed scripts have to agree.
    #[test]
    fn validating_the_same_document_twice_gives_the_same_answer() {
        for document in [minimal(), with("scope", json!("openid profile"))] {
            assert_eq!(validate(&document), validate(&document));
        }
    }

    // -----------------------------------------------------------------------
    // Client authentication (FAPI 2.0 SP §5.3.2.1 items 3 and 6)
    // -----------------------------------------------------------------------

    /// FAPI 2.0 SP §5.3.2.1 item 3: "shall only support confidential clients".
    /// A shared secret is not a confidential-client credential this server has,
    /// and `none` is a public client by another name, so every one of them is
    /// an `invalid_client_metadata` rather than a downgrade.
    #[test]
    fn no_client_can_register_a_secret_based_or_absent_authentication_method() {
        for method in [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "none",
            "None",
            "private_key_jwt ",
            "PRIVATE_KEY_JWT",
            "",
        ] {
            let error = rejection(&with("token_endpoint_auth_method", json!(method)));
            assert_eq!(error.code(), "invalid_client_metadata", "{method}");
            assert_eq!(error.field(), "token_endpoint_auth_method", "{method}");
            assert!(
                !error.to_string().contains(method) || method.is_empty(),
                "the rejected value was echoed back: {error}"
            );
        }
    }

    /// The mTLS methods exist only where the deployment has switched mTLS on.
    /// Registering one against a deployment that cannot terminate mTLS produces
    /// a client that can never authenticate.
    #[test]
    fn the_mtls_authentication_methods_are_refused_unless_the_flag_is_on() {
        for method in ["tls_client_auth", "self_signed_tls_client_auth"] {
            let mut document = with("token_endpoint_auth_method", json!(method));
            // RFC 8705 §2.1.2: the PKI method needs a subject to match. Added
            // here so that what this test measures is the *flag* — a document
            // refused for a missing subject would pass the assertion below for
            // the wrong reason.
            if method == "tls_client_auth" {
                document
                    .as_object_mut()
                    .expect("object")
                    .insert("tls_client_auth_subject_dn".to_owned(), json!("CN=billing"));
            }
            let error = validate_with(&document, caps(false)).expect_err("mtls is off");
            assert_eq!(error.code(), "invalid_client_metadata");
            assert!(error.to_string().contains("mtls"), "{error}");

            let accepted = validate_with(&document, caps(true)).expect("mtls is on");
            assert_eq!(
                accepted.token_endpoint_auth_method,
                TokenEndpointAuthMethod::parse(method).expect("known method")
            );
        }
    }

    // -----------------------------------------------------------------------
    // Grant and response types (RFC 7591 §2.1)
    // -----------------------------------------------------------------------

    #[test]
    fn the_only_response_type_is_code() {
        for value in [
            json!(["token"]),
            json!(["id_token"]),
            json!(["code", "id_token"]),
            json!(["code id_token"]),
            json!(["code", "code"]),
            json!(["CODE"]),
        ] {
            let error = rejection(&with("response_types", value.clone()));
            assert_eq!(error.field(), "response_types", "{value}");
            assert_eq!(error.code(), "invalid_client_metadata", "{value}");
        }
        assert!(validate(&with("response_types", json!(["code"]))).is_ok());
    }

    /// RFC 7591 §2.1: `code` and `authorization_code` correspond, and the
    /// server must not let a client register itself into an inconsistent state.
    #[test]
    fn response_types_and_grant_types_must_agree_in_both_directions() {
        // code without authorization_code
        let error = rejection(&with("grant_types", json!(["client_credentials"])));
        assert_eq!(error.field(), "response_types");

        // authorization_code without code
        let mut document = minimal();
        let object = document.as_object_mut().expect("object");
        object.insert("grant_types".to_owned(), json!(["authorization_code"]));
        object.insert("response_types".to_owned(), json!([]));
        let error = rejection(&document);
        assert_eq!(error.field(), "response_types");

        // A client that reaches no authorization endpoint says so with an empty
        // response_types, which RFC 7591 §2.1's table agrees with.
        let mut machine = minimal();
        let object = machine.as_object_mut().expect("object");
        object.insert("grant_types".to_owned(), json!(["client_credentials"]));
        object.insert("response_types".to_owned(), json!([]));
        object.remove("redirect_uris");
        let client = validate(&machine).expect("a client_credentials client is valid");
        assert!(client.redirect_uris.is_empty());
        assert!(!client.allows(GrantType::AuthorizationCode));
    }

    #[test]
    fn grant_types_outside_the_profile_are_refused() {
        for value in [
            "implicit",
            "password",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:ietf:params:oauth:grant-type:saml2-bearer",
            "authorization_code ",
            "",
        ] {
            let error = rejection(&with("grant_types", json!([value, "authorization_code"])));
            assert_eq!(error.field(), "grant_types", "{value}");
        }
        assert_eq!(
            rejection(&with("grant_types", json!([]))).field(),
            "grant_types"
        );
        assert_eq!(
            rejection(&with(
                "grant_types",
                json!(["authorization_code", "authorization_code"])
            ))
            .field(),
            "grant_types"
        );
    }

    /// A grant behind a flag that is off is a grant the server cannot perform.
    /// Registering it produces a client that fails at first use, pointing at
    /// the client rather than at the flag.
    #[test]
    fn a_grant_type_behind_a_disabled_flag_is_refused_at_registration() {
        for (grant, feature) in [
            (
                "urn:ietf:params:oauth:grant-type:token-exchange",
                Feature::TokenExchange,
            ),
            (
                "urn:ietf:params:oauth:grant-type:device_code",
                Feature::DeviceFlow,
            ),
            ("urn:openid:params:grant-type:ciba", Feature::Ciba),
        ] {
            let document = with("grant_types", json!(["authorization_code", grant]));
            let error =
                validate_with(&document, Capabilities::default()).expect_err("the flag is off");
            assert_eq!(error.field(), "grant_types");
            assert!(error.to_string().contains(feature.as_str()), "{error}");

            let accepted = validate_with(&document, everything_on()).expect("the flag is on");
            assert!(accepted.allows(GrantType::parse(grant).expect("known grant")));
        }
    }

    // -----------------------------------------------------------------------
    // Redirect URIs — the part of ast-m9c.7 registration needs
    // -----------------------------------------------------------------------

    #[test]
    fn a_client_using_the_authorization_endpoint_must_register_a_redirect_uri() {
        let error = rejection(&without("redirect_uris"));
        assert_eq!(error.field(), "redirect_uris");
        assert_eq!(error.code(), "invalid_client_metadata");
        assert_eq!(
            rejection(&with("redirect_uris", json!([]))).field(),
            "redirect_uris"
        );
    }

    /// FAPI 2.0 SP §5.3.2.2 item 8 and RFC 9700 §4.1: https only, exact match,
    /// no room for a URI that resolves somewhere the operator did not intend.
    #[test]
    fn redirect_uris_are_https_and_carry_nothing_that_breaks_an_exact_match() {
        for (uri, why) in [
            ("http://rp.example/cb", "plain http on a web client"),
            ("http://localhost:8080/cb", "localhost resolves through DNS"),
            (
                "http://127.0.0.1:8080/cb",
                "loopback needs application_type=native",
            ),
            ("https://rp.example/cb#f", "fragment"),
            ("https://user:pw@rp.example/cb", "userinfo"),
            ("com.example.app:/oauth", "private-use scheme"),
            ("/cb", "relative reference"),
            ("https:///cb", "no host"),
            ("", "empty"),
        ] {
            let error = rejection(&with("redirect_uris", json!([uri])));
            assert_eq!(
                error.code(),
                "invalid_redirect_uri",
                "accepted {why}: {uri}"
            );
            assert_eq!(error.field(), "redirect_uris");
            assert!(
                !error.to_string().contains("rp.example"),
                "echoed the URI: {error}"
            );
        }
    }

    /// RFC 8252 §7.3: a native client may redirect to the loopback interface
    /// over http, because there is no transport to protect on a socket that
    /// never leaves the machine. Nothing else gains that exception.
    #[test]
    fn loopback_http_is_admissible_only_for_a_native_client() {
        for uri in [
            "http://127.0.0.1/cb",
            "http://127.0.0.1:51004/cb",
            "http://[::1]:51004/cb",
        ] {
            let mut document = with("redirect_uris", json!([uri]));
            assert_eq!(
                rejection(&document).code(),
                "invalid_redirect_uri",
                "{uri} was accepted on a web client"
            );
            document
                .as_object_mut()
                .expect("object")
                .insert("application_type".to_owned(), json!("native"));
            let client = validate(&document).unwrap_or_else(|e| panic!("{uri}: {e}"));
            assert_eq!(client.redirect_uris[0].as_str(), uri);
        }
        // Still not a licence for anything else on a native client.
        let mut document = with("redirect_uris", json!(["http://192.168.1.10/cb"]));
        document
            .as_object_mut()
            .expect("object")
            .insert("application_type".to_owned(), json!("native"));
        assert_eq!(rejection(&document).code(), "invalid_redirect_uri");
    }

    /// Comparison is byte-exact (RFC 9700 §4.1), so the registered bytes come
    /// back out unchanged — no lowercased host, no added trailing slash, no
    /// re-encoded path.
    #[test]
    fn a_registered_redirect_uri_is_stored_exactly_as_written() {
        for uri in [
            "https://rp.example/CB",
            "https://rp.example/a%2Fb",
            "https://rp.example:8443/cb?x=1",
            "https://rp.example/",
        ] {
            let client = validate(&with("redirect_uris", json!([uri])))
                .unwrap_or_else(|e| panic!("{uri}: {e}"));
            assert_eq!(
                client.redirect_uris[0].as_str(),
                uri,
                "the parser normalised a redirect URI"
            );
        }
    }

    /// The other half of never normalising: a URI that is not already in the
    /// form a URL parser produces is refused rather than rewritten, because
    /// rewriting it would change what the client must send and keeping it would
    /// let the registered string and the URL a browser requests differ.
    #[test]
    fn a_redirect_uri_that_is_not_already_normalised_is_refused() {
        for (uri, becomes) in [
            ("https://RP.Example/cb", "the host is lowercased"),
            ("https://rp.example", "a trailing slash is added"),
            ("https://rp.example:443/cb", "the default port is dropped"),
            ("https://rp.example/../cb", "the path is resolved"),
            ("https:///cb", "the empty authority makes `cb` the host"),
            ("https://пример.example/cb", "the IDN host becomes punycode"),
            ("https://rp.example/c b", "the space is percent-encoded"),
            ("https://rp.example/cb\u{0}", "the NUL is dropped"),
        ] {
            let error = rejection(&with("redirect_uris", json!([uri])));
            assert_eq!(
                error.code(),
                "invalid_redirect_uri",
                "accepted {uri}, where {becomes}"
            );
        }
    }

    #[test]
    fn redirect_uris_are_a_bounded_set_without_repeats() {
        let duplicated = json!(["https://rp.example/cb", "https://rp.example/cb"]);
        assert_eq!(
            rejection(&with("redirect_uris", duplicated)).code(),
            "invalid_redirect_uri"
        );
        let many: Vec<String> = (0..=ClientRegistration::MAX_REDIRECT_URIS)
            .map(|i| format!("https://rp.example/cb{i}"))
            .collect();
        assert_eq!(
            rejection(&with("redirect_uris", json!(many))).field(),
            "redirect_uris"
        );
    }

    /// A callback list on a client that cannot reach the authorization endpoint
    /// is configuration nobody re-reads when the grant list changes.
    #[test]
    fn a_client_that_never_redirects_may_not_register_a_redirect_uri() {
        let mut document = minimal();
        let object = document.as_object_mut().expect("object");
        object.insert("grant_types".to_owned(), json!(["client_credentials"]));
        object.insert("response_types".to_owned(), json!([]));
        assert_eq!(rejection(&document).field(), "redirect_uris");
    }

    // -----------------------------------------------------------------------
    // Post-logout redirect URIs (OIDC RP-Initiated Logout 1.0 §3.1)
    // -----------------------------------------------------------------------

    #[test]
    fn post_logout_redirect_uris_are_optional_and_default_to_none() {
        let client = validate(&minimal()).expect("a valid registration");

        assert!(client.post_logout_redirect_uris.is_empty());
        assert!(!client.accepts_post_logout_redirect_uri("https://rp.example/after-logout"));
    }

    #[test]
    fn a_registered_post_logout_redirect_uri_is_kept_byte_for_byte() {
        let client = validate(&with(
            "post_logout_redirect_uris",
            json!(["https://rp.example/after-logout?tenant=demo"]),
        ))
        .expect("a valid registration");

        assert_eq!(
            client.registered_post_logout_redirect_uris(),
            vec!["https://rp.example/after-logout?tenant=demo".to_owned()]
        );
    }

    /// The whole reason these go through [`RedirectUri::parse`]: a post-logout
    /// target is a redirect target, and the end-session endpoint takes no
    /// client authentication at all before honouring one.
    #[test]
    fn a_post_logout_redirect_uri_faces_the_same_gate_as_a_callback() {
        for uri in [
            "http://rp.example/after-logout",
            "https://rp.example/after-logout#f",
            "https://user:pw@rp.example/after-logout",
            "com.example.app:/after-logout",
            "https://rp.example/a/../after-logout",
            "not a url",
            "",
        ] {
            let error = rejection(&with("post_logout_redirect_uris", json!([uri])));
            assert_eq!(error.field(), "post_logout_redirect_uris", "{uri} passed");
            assert_eq!(error.code(), "invalid_redirect_uri", "{uri}");
        }
    }

    #[test]
    fn post_logout_redirect_uris_are_a_bounded_set_without_repeats() {
        let repeated = json!([
            "https://rp.example/after-logout",
            "https://rp.example/after-logout"
        ]);
        assert_eq!(
            rejection(&with("post_logout_redirect_uris", repeated)).field(),
            "post_logout_redirect_uris"
        );

        let too_many: Vec<String> = (0..=ClientRegistration::MAX_POST_LOGOUT_REDIRECT_URIS)
            .map(|n| format!("https://rp.example/after-logout/{n}"))
            .collect();
        assert_eq!(
            rejection(&with("post_logout_redirect_uris", json!(too_many))).field(),
            "post_logout_redirect_uris"
        );
    }

    /// §3 is an exact match with no exception, so the RFC 8252 §7.3 loopback
    /// port a native client's *callback* may vary is not varied here.
    #[test]
    fn a_native_clients_post_logout_port_does_not_vary() {
        let mut document = minimal();
        let object = document.as_object_mut().expect("object");
        object.insert("application_type".to_owned(), json!("native"));
        object.insert("redirect_uris".to_owned(), json!(["http://127.0.0.1:1/cb"]));
        object.insert(
            "post_logout_redirect_uris".to_owned(),
            json!(["http://127.0.0.1:51004/after-logout"]),
        );
        let client = validate(&document).expect("a valid native registration");

        assert!(client.accepts_post_logout_redirect_uri("http://127.0.0.1:51004/after-logout"));
        assert!(
            !client.accepts_post_logout_redirect_uri("http://127.0.0.1:51005/after-logout"),
            "a different port was treated as registered"
        );
        assert!(
            client.accepts_redirect_uri("http://127.0.0.1:51005/cb"),
            "the callback keeps its RFC 8252 §7.3 exception"
        );
    }

    // -----------------------------------------------------------------------
    // Redirect-URI matching (RFC 6749 §3.1.2.3, RFC 9700 §4.1.3, RFC 8252 §7.3)
    //
    // The comparison, rather than the registration check above. It is reached
    // at registration, at PAR (`ast-gxh.1`) and at the token endpoint
    // (`ast-a05.2`), so a hole here is a hole in all three.
    // -----------------------------------------------------------------------

    fn registered(uris: &[&str], application_type: ApplicationType) -> Vec<RedirectUri> {
        uris.iter()
            .map(|uri| {
                RedirectUri::parse(uri, application_type)
                    .unwrap_or_else(|e| panic!("{uri} should be registrable: {e}"))
            })
            .collect()
    }

    /// RFC 6749 §3.1.2.3: "the authorization server MUST compare the two URIs
    /// using simple string comparison as defined in [RFC3986] Section 6.2.1",
    /// and RFC 9700 §4.1.3 removes the alternatives. Each case below is a URI
    /// that some server somewhere treats as equivalent, and none of them is.
    #[test]
    fn a_presented_redirect_uri_that_differs_by_one_byte_does_not_match() {
        let set = registered(&["https://rp.example/cb"], ApplicationType::Web);
        assert!(RedirectUri::is_registered(
            &set,
            "https://rp.example/cb",
            ApplicationType::Web
        ));
        for (presented, why) in [
            ("https://rp.example/cb/", "trailing slash"),
            ("https://rp.example/CB", "path case"),
            ("https://RP.Example/cb", "host case"),
            ("HTTPS://rp.example/cb", "scheme case"),
            ("https://rp.example/cb?x=1", "added query"),
            ("https://rp.example/cb#f", "added fragment"),
            ("https://user:pw@rp.example/cb", "userinfo"),
            ("https://rp.example:443/cb", "explicit default port"),
            ("https://rp.example/cb/../cb", "a path that resolves to it"),
            ("https://rp.example/c", "a prefix of it"),
            ("https://rp.example/cbb", "it as a prefix"),
            ("https://rp.example.evil/cb", "a longer host"),
            ("https://evil.example/cb", "another host entirely"),
            ("http://rp.example/cb", "the http scheme"),
            ("https://rp.example/%63b", "a percent-encoded path"),
            ("//rp.example/cb", "a scheme-relative reference"),
            ("/cb", "a relative reference"),
            ("", "the empty string"),
        ] {
            assert!(
                !RedirectUri::is_registered(&set, presented, ApplicationType::Web),
                "matched on {why}: {presented}"
            );
            // The same string is not admissible even as a *native* client's
            // presentation: the loopback exception is about a port, not about
            // relaxing the comparison.
            assert!(
                !RedirectUri::is_registered(&set, presented, ApplicationType::Native),
                "matched on {why} once the client was native: {presented}"
            );
        }
    }

    /// An IDN host has two spellings and only one of them ever travels: a
    /// browser sends punycode. Registering the Unicode form is refused (it is
    /// not the form a URL parser produces), and presenting it does not match
    /// the punycode registration — RFC 3986 §6.2.1 knows nothing about IDNA.
    #[test]
    fn an_idn_host_matches_only_in_the_punycode_form_that_travels() {
        const UNICODE: &str = "https://пример.example/cb";
        const PUNYCODE: &str = "https://xn--e1afmkfd.example/cb";

        assert_eq!(
            RedirectUri::parse(UNICODE, ApplicationType::Web),
            Err(RedirectUriError::NotNormalised)
        );
        let set = registered(&[PUNYCODE], ApplicationType::Web);
        assert!(RedirectUri::is_registered(
            &set,
            PUNYCODE,
            ApplicationType::Web
        ));
        assert!(
            !RedirectUri::is_registered(&set, UNICODE, ApplicationType::Web),
            "the Unicode spelling matched a punycode registration"
        );
        // And the uppercase punycode spelling, which resolves identically in
        // DNS, is a different string here too.
        assert!(!RedirectUri::is_registered(
            &set,
            "https://XN--E1AFMKFD.example/cb",
            ApplicationType::Web
        ));
    }

    /// RFC 8252 §7.3: "The authorization server MUST allow any port to be
    /// specified at the time of the request for loopback IP redirect URIs, to
    /// accommodate clients that obtain an available ephemeral port from the
    /// operating system at the time of the request."
    #[test]
    fn a_native_clients_loopback_redirect_matches_on_any_port() {
        for base in ["http://127.0.0.1", "http://[::1]"] {
            let set = registered(&[&format!("{base}:51004/cb")], ApplicationType::Native);
            for presented in [
                format!("{base}/cb"),
                format!("{base}:1/cb"),
                format!("{base}:51004/cb"),
                format!("{base}:65535/cb"),
            ] {
                assert!(
                    RedirectUri::is_registered(&set, &presented, ApplicationType::Native),
                    "the port was not allowed to vary: {presented}"
                );
            }
        }
    }

    /// RFC 8252 §8.4 states the residue exactly: "the exception is loopback
    /// redirects, where an exact match is required except for the port URI
    /// component". Everything that is not the port stays byte-exact, or the
    /// exception becomes the wildcard RFC 9700 §4.1.3 exists to remove.
    #[test]
    fn the_loopback_exception_varies_the_port_and_nothing_else() {
        let set = registered(&["http://127.0.0.1:51004/cb"], ApplicationType::Native);
        for (presented, why) in [
            ("http://127.0.0.1:51004/CB", "path case"),
            ("http://127.0.0.1:51004/cb/", "trailing slash"),
            ("http://127.0.0.1:51004/cb?x=1", "added query"),
            ("http://127.0.0.1:51004/cb#f", "added fragment"),
            ("http://127.0.0.1:1/cb/../cb", "a path that resolves to it"),
            ("http://127.0.0.1:1/a/../cb", "a path that traverses to it"),
            ("http://[::1]:51004/cb", "the other loopback family"),
            ("http://127.0.0.2:51004/cb", "another address in 127/8"),
            (
                "http://localhost:51004/cb",
                "localhost, which resolves by DNS",
            ),
            ("https://127.0.0.1:51004/cb", "the https scheme"),
            ("http://127.1:51004/cb", "a short-form IPv4 literal"),
            (
                "http://user@127.0.0.1:51004/cb",
                "userinfo shaped like a port",
            ),
            (
                "http://127.0.0.1:51004@evil.example/cb",
                "the registered authority moved into the userinfo",
            ),
            ("http://127.0.0.1:/cb", "an empty port"),
            ("http://127.0.0.1:51004", "no path at all"),
            // RFC 8252 §7.3 allows any *port*, and these are not ports: no
            // browser can produce either spelling, so a match on one would
            // only ever come from something hand-built.
            (
                "http://127.0.0.1:99999/cb",
                "a number too large to be a port",
            ),
            ("http://127.0.0.1:051004/cb", "a port with a leading zero"),
        ] {
            assert!(
                !RedirectUri::is_registered(&set, presented, ApplicationType::Native),
                "the loopback exception matched on {why}: {presented}"
            );
        }
    }

    /// FAPI 2.0 SP §5.3.2.2 item 8 gives the exception to native clients only.
    /// A caller that does not know the client is native gets plain string
    /// equality, which fails closed.
    #[test]
    fn only_a_native_client_gets_the_loopback_port_exception() {
        let set = registered(&["http://127.0.0.1:51004/cb"], ApplicationType::Native);
        assert!(RedirectUri::is_registered(
            &set,
            "http://127.0.0.1:9999/cb",
            ApplicationType::Native
        ));
        assert!(
            !RedirectUri::is_registered(&set, "http://127.0.0.1:9999/cb", ApplicationType::Web),
            "a web client was given the loopback port exception"
        );
        // The identical string still matches, because that is not the
        // exception, it is RFC 3986 §6.2.1.
        assert!(RedirectUri::is_registered(
            &set,
            "http://127.0.0.1:51004/cb",
            ApplicationType::Web
        ));
    }

    /// The port varies for loopback and for nothing else. An https callback on
    /// a native client keeps its port, because RFC 8252 §7.3 is about a socket
    /// the operating system hands out on the device, not about ports.
    #[test]
    fn an_https_redirect_uri_never_gets_the_port_exception() {
        let set = registered(&["https://rp.example:8443/cb"], ApplicationType::Native);
        for presented in [
            "https://rp.example:9443/cb",
            "https://rp.example/cb",
            "https://rp.example:443/cb",
        ] {
            assert!(
                !RedirectUri::is_registered(&set, presented, ApplicationType::Native),
                "an https port varied: {presented}"
            );
        }
    }

    /// RFC 6749 §3.1.2.3 makes the comparison conditional on "if any
    /// redirection URIs were registered". An empty set here belongs to a client
    /// that cannot reach the authorization endpoint at all, so the answer is
    /// no — never "nothing was registered, so anything goes".
    #[test]
    fn an_empty_registered_set_matches_nothing() {
        for application_type in [ApplicationType::Web, ApplicationType::Native] {
            assert!(!RedirectUri::is_registered(
                &[],
                "https://rp.example/cb",
                application_type
            ));
            assert!(!RedirectUri::is_registered(&[], "", application_type));
        }
    }

    /// Every entry is consulted, not only the first: a client with several
    /// callbacks would otherwise find that only one of them works.
    #[test]
    fn every_entry_in_the_registered_set_is_compared() {
        let set = registered(
            &[
                "https://rp.example/cb",
                "https://rp.example/other",
                "https://alt.example/cb",
            ],
            ApplicationType::Web,
        );
        for presented in [
            "https://rp.example/cb",
            "https://rp.example/other",
            "https://alt.example/cb",
        ] {
            assert!(RedirectUri::is_registered(
                &set,
                presented,
                ApplicationType::Web
            ));
        }
        assert!(!RedirectUri::is_registered(
            &set,
            "https://alt.example/other",
            ApplicationType::Web
        ));
    }

    /// Registration uses the same comparison, so two loopback entries that
    /// differ only in their port are one registration. Accepting both would put
    /// a second, unreviewed spelling of one callback in the set and let
    /// `MAX_REDIRECT_URIS` be filled with port variants of a single URI.
    #[test]
    fn two_loopback_uris_that_differ_only_in_their_port_are_one_registration() {
        let mut document = with(
            "redirect_uris",
            json!(["http://127.0.0.1:51004/cb", "http://127.0.0.1:8080/cb"]),
        );
        document
            .as_object_mut()
            .expect("object")
            .insert("application_type".to_owned(), json!("native"));
        assert_eq!(rejection(&document).code(), "invalid_redirect_uri");

        // Different paths on the same loopback host stay two registrations.
        let mut document = with(
            "redirect_uris",
            json!(["http://127.0.0.1:51004/cb", "http://127.0.0.1:8080/other"]),
        );
        document
            .as_object_mut()
            .expect("object")
            .insert("application_type".to_owned(), json!("native"));
        assert_eq!(
            validate(&document)
                .expect("two callbacks")
                .redirect_uris
                .len(),
            2
        );
    }

    /// The convenience methods must ask the same question as the free
    /// function; a caller that forgot the application type would silently
    /// withdraw the loopback exception from every native client.
    #[test]
    fn a_client_answers_for_its_own_redirect_uris() {
        let mut document = with("redirect_uris", json!(["http://127.0.0.1:51004/cb"]));
        document
            .as_object_mut()
            .expect("object")
            .insert("application_type".to_owned(), json!("native"));
        let registration = validate(&document).expect("valid native client");
        assert!(registration.accepts_redirect_uri("http://127.0.0.1:1/cb"));
        assert!(!registration.accepts_redirect_uri("http://127.0.0.1:1/other"));

        let client = Client {
            tenant: TenantId::new("demo"),
            id: ClientId::new("billing"),
            registration,
            status: ClientStatus::Disabled,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        // Being disabled is a separate answer, given by client authentication.
        assert!(client.accepts_redirect_uri("http://127.0.0.1:1/cb"));
        assert!(!client.accepts_redirect_uri("https://rp.example/cb"));
    }

    // -----------------------------------------------------------------------
    // Algorithms (ADR-0003, FAPI 2.0 SP §5.4.1)
    // -----------------------------------------------------------------------

    /// OIDC Core §5.3.2: a client that registers no
    /// `userinfo_signed_response_alg` is served a JSON object, and one that
    /// registers an algorithm gets a signed JWT. The difference is carried by
    /// `Option`, so "unsigned" is not one of the algorithms.
    #[test]
    fn userinfo_signing_is_off_until_the_client_registers_an_algorithm() {
        let unsigned = validate(&minimal()).expect("a minimal document");
        assert_eq!(unsigned.userinfo_signed_response_alg, None);

        let signed = validate(&with("userinfo_signed_response_alg", json!("ES256")))
            .expect("a document naming an allowed algorithm");
        assert_eq!(
            signed.userinfo_signed_response_alg,
            Some(SigningAlgorithm::Es256)
        );
    }

    /// The client does not get to choose the algorithm used to check its own
    /// credentials, and `none` is not a value that exists.
    #[test]
    fn no_signing_algorithm_outside_the_allow_list_can_be_registered() {
        for field in [
            "id_token_signed_response_alg",
            "userinfo_signed_response_alg",
            "request_object_signing_alg",
            "backchannel_authentication_request_signing_alg",
        ] {
            for alg in [
                "none", "None", "HS256", "RS256", "ES384", "PS512", "eddsa", "",
            ] {
                let error = rejection(&with(field, json!(alg)));
                assert_eq!(error.field(), field, "{field} accepted {alg}");
                assert_eq!(error.code(), "invalid_client_metadata");
            }
            for alg in SigningAlgorithm::ALL {
                assert!(
                    validate(&with(field, json!(alg.as_str()))).is_ok(),
                    "{field} refused {alg}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Key material (RFC 7591 §2)
    // -----------------------------------------------------------------------

    /// RFC 7591 §2: "The `jwks_uri` and `jwks` parameters MUST NOT both be present
    /// in the same request or response." The schema's
    /// `clients_exactly_one_key_source` check adds that one of them must be.
    #[test]
    fn a_client_registers_exactly_one_key_source() {
        let both = with("jwks_uri", json!("https://rp.example/jwks"));
        assert_eq!(rejection(&both).code(), "invalid_client_metadata");

        let neither = without("jwks");
        assert_eq!(rejection(&neither).code(), "invalid_client_metadata");

        let mut uri_only = without("jwks");
        uri_only
            .as_object_mut()
            .expect("object")
            .insert("jwks_uri".to_owned(), json!("https://rp.example/jwks"));
        let client = validate(&uri_only).expect("a jwks_uri alone is valid");
        assert_eq!(
            client.jwks,
            JwksSource::Uri("https://rp.example/jwks".to_owned())
        );
    }

    #[test]
    fn a_jwks_uri_must_be_an_https_url_that_can_be_fetched() {
        let mut document = without("jwks");
        for uri in [
            "http://rp.example/jwks",
            "file:///etc/passwd",
            "https://rp.example/jwks#keys",
            "/jwks",
            "",
        ] {
            document
                .as_object_mut()
                .expect("object")
                .insert("jwks_uri".to_owned(), json!(uri));
            let error = rejection(&document);
            assert_eq!(error.field(), "jwks_uri", "accepted {uri}");
        }
    }

    #[test]
    fn an_inline_jwks_must_at_least_be_a_jwk_set() {
        for value in [
            json!({}),
            json!({"keys": []}),
            json!({"keys": "abc"}),
            json!([]),
            json!({"keys": ["abc"]}),
        ] {
            assert_eq!(
                rejection(&with("jwks", value.clone())).field(),
                "jwks",
                "{value}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Sender constraint (RFC 9449 §5.2, RFC 8705 §3.4)
    // -----------------------------------------------------------------------

    /// FAPI 2.0 SP §5.3.2.1: access tokens are sender-constrained. Turning DPoP
    /// off is admissible only when certificate binding takes over; turning both
    /// off asks for a bearer token, which this server does not issue.
    #[test]
    fn access_tokens_are_always_bound_to_something_the_client_holds() {
        let mut document = with("dpop_bound_access_tokens", json!(false));
        let error = rejection(&document);
        assert_eq!(error.field(), "dpop_bound_access_tokens");
        assert_eq!(error.code(), "invalid_client_metadata");

        document.as_object_mut().expect("object").insert(
            "tls_client_certificate_bound_access_tokens".to_owned(),
            json!(true),
        );
        let error = validate_with(&document, caps(false)).expect_err("mtls is off");
        assert_eq!(error.field(), "tls_client_certificate_bound_access_tokens");

        let client = validate_with(&document, caps(true)).expect("mtls is on");
        assert_eq!(client.token_binding, TokenBinding::Certificate);
        assert!(!client.token_binding.is_dpop_bound());
        assert!(client.token_binding.is_certificate_bound());
    }

    /// RFC 8705 §3.4 and RFC 9449 §5.2 each define their own member and
    /// neither says what a token bound by both means. A client registers one
    /// method, so that no resource server has to decide which half of a `cnf`
    /// it is obliged to check.
    #[test]
    fn a_client_binds_its_tokens_one_way_and_not_two() {
        let mut document = with("dpop_bound_access_tokens", json!(true));
        document.as_object_mut().expect("object").insert(
            "tls_client_certificate_bound_access_tokens".to_owned(),
            json!(true),
        );
        let error = validate_with(&document, caps(true)).expect_err("two bindings");
        assert_eq!(error.field(), "tls_client_certificate_bound_access_tokens");
        assert_eq!(error.code(), "invalid_client_metadata");
    }

    // -----------------------------------------------------------------------
    // PAR (RFC 9126 §6)
    // -----------------------------------------------------------------------

    /// RFC 9126 §6 defaults this to false. Accepting a `false` and then
    /// requiring PAR anyway would leave the client's own record contradicting
    /// the server, so it is refused.
    #[test]
    fn a_client_cannot_register_out_of_pushed_authorization_requests() {
        let error = rejection(&with("require_pushed_authorization_requests", json!(false)));
        assert_eq!(error.field(), "require_pushed_authorization_requests");
        assert!(validate(&with("require_pushed_authorization_requests", json!(true))).is_ok());
        assert!(validate(&minimal()).is_ok());
    }

    // -----------------------------------------------------------------------
    // Subject types (OIDC Core §8.1)
    // -----------------------------------------------------------------------

    /// OIDC Core §8.1: without a `sector_identifier_uri` the sector is the host
    /// of the registered redirect URI, so redirect URIs spanning several hosts
    /// leave a pairwise `sub` undefined.
    #[test]
    fn a_pairwise_client_with_several_redirect_hosts_must_name_its_sector() {
        let mut document = with("subject_type", json!("pairwise"));
        document.as_object_mut().expect("object").insert(
            "redirect_uris".to_owned(),
            json!(["https://a.rp.example/cb", "https://b.rp.example/cb"]),
        );
        let error = rejection(&document);
        assert_eq!(error.field(), "sector_identifier_uri");

        document.as_object_mut().expect("object").insert(
            "sector_identifier_uri".to_owned(),
            json!("https://rp.example/sector.json"),
        );
        let client = validate(&document).expect("a named sector resolves it");
        assert_eq!(client.subject_type, SubjectType::Pairwise);
        assert_eq!(
            client.sector_identifier_uri.as_deref(),
            Some("https://rp.example/sector.json")
        );

        // One host needs no sector identifier.
        let single = with("subject_type", json!("pairwise"));
        assert!(validate(&single).is_ok());
    }

    #[test]
    fn a_sector_identifier_is_refused_where_nothing_would_read_it() {
        let error = rejection(&with(
            "sector_identifier_uri",
            json!("https://rp.example/sector.json"),
        ));
        assert_eq!(error.field(), "sector_identifier_uri");

        let mut insecure = with("subject_type", json!("pairwise"));
        insecure.as_object_mut().expect("object").insert(
            "sector_identifier_uri".to_owned(),
            json!("http://rp.example/sector.json"),
        );
        assert_eq!(rejection(&insecure).field(), "sector_identifier_uri");
    }

    /// Builds the pairwise registration whose sector document the tests below
    /// judge: two redirect hosts, so the sector must be named rather than
    /// inferred.
    fn pairwise_across_two_hosts() -> ClientRegistration {
        let mut document = with("subject_type", json!("pairwise"));
        let object = document.as_object_mut().expect("object");
        object.insert(
            "redirect_uris".to_owned(),
            json!(["https://a.rp.example/cb", "https://b.rp.example/cb"]),
        );
        object.insert(
            "sector_identifier_uri".to_owned(),
            json!("https://rp.example/sector.json"),
        );
        validate(&document).expect("a pairwise client naming its sector")
    }

    /// OIDC Registration §5: the document must list every registered redirect
    /// URI, which is the only evidence the client controls the sector it named.
    #[test]
    fn a_sector_document_listing_every_redirect_uri_is_accepted() {
        let registration = pairwise_across_two_hosts();
        let document = json!(["https://a.rp.example/cb", "https://b.rp.example/cb"]).to_string();

        let outcome = registration.check_sector_identifier_document(document.as_bytes());

        assert!(outcome.is_ok(), "{outcome:?}");
    }

    /// A document may cover more clients than this one; extra entries are the
    /// normal case for a sector shared by several registrations.
    #[test]
    fn a_sector_document_may_list_redirect_uris_this_client_did_not_register() {
        let registration = pairwise_across_two_hosts();
        let document = json!([
            "https://a.rp.example/cb",
            "https://b.rp.example/cb",
            "https://c.rp.example/cb"
        ])
        .to_string();

        let outcome = registration.check_sector_identifier_document(document.as_bytes());

        assert!(outcome.is_ok(), "{outcome:?}");
    }

    /// The failure this whole check exists for: a client naming a sector whose
    /// owner never listed its callback.
    #[test]
    fn a_sector_document_omitting_a_registered_redirect_uri_is_refused() {
        let registration = pairwise_across_two_hosts();
        let document = json!(["https://a.rp.example/cb"]).to_string();

        let error = registration
            .check_sector_identifier_document(document.as_bytes())
            .expect_err("an incomplete document must be refused");

        assert_eq!(error.field(), "sector_identifier_uri");
        assert_eq!(error.code(), "invalid_client_metadata");
    }

    /// ADR-0005 compares redirect URIs byte for byte, and a sector document is
    /// no place to relax it: a trailing slash is a different callback.
    #[test]
    fn a_sector_document_must_match_a_redirect_uri_byte_for_byte() {
        let registration = pairwise_across_two_hosts();
        let document = json!(["https://a.rp.example/cb/", "https://b.rp.example/cb"]).to_string();

        let error = registration
            .check_sector_identifier_document(document.as_bytes())
            .expect_err("a near miss must be refused");

        assert_eq!(error.field(), "sector_identifier_uri");
    }

    /// Anything but an array of strings — an HTML error page, an object, a
    /// list of numbers — is not the document §5 describes.
    #[test]
    fn a_sector_document_that_is_not_an_array_of_strings_is_refused() {
        let registration = pairwise_across_two_hosts();
        for body in [b"<!doctype html>".as_slice(), b"{}", b"[1, 2]", b"[]", b""] {
            let error = registration
                .check_sector_identifier_document(body)
                .expect_err("must be refused");
            assert_eq!(error.field(), "sector_identifier_uri");
        }
    }

    /// Only a pairwise client that named a sector owes a fetch: a public one
    /// cannot carry the field, and a pairwise one without it takes the sector
    /// from the single redirect host it already proved it controls.
    #[test]
    fn only_a_pairwise_client_that_named_a_sector_owes_a_fetch() {
        assert_eq!(
            pairwise_across_two_hosts().sector_identifier_uri_to_verify(),
            Some("https://rp.example/sector.json")
        );
        assert_eq!(
            validate(&with("subject_type", json!("pairwise")))
                .expect("one redirect host")
                .sector_identifier_uri_to_verify(),
            None
        );
        assert_eq!(
            validate(&minimal())
                .expect("a public client")
                .sector_identifier_uri_to_verify(),
            None
        );
    }

    #[test]
    fn subject_type_and_application_type_take_only_their_defined_values() {
        assert_eq!(
            rejection(&with("subject_type", json!("PAIRWISE"))).field(),
            "subject_type"
        );
        assert_eq!(
            rejection(&with("application_type", json!("service"))).field(),
            "application_type"
        );
    }

    // -----------------------------------------------------------------------
    // Scopes, names and other free text
    // -----------------------------------------------------------------------

    /// RFC 6749 §3.3: `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`. A tab is
    /// not a separator and a quote is not a scope character.
    #[test]
    fn scope_is_parsed_by_the_grammar_and_not_by_splitting_on_whitespace() {
        let client = validate(&with("scope", json!("openid  profile email")))
            .expect("extra spaces are empty tokens");
        assert_eq!(
            client.scopes,
            BTreeSet::from([
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned()
            ])
        );
        for bad in [
            "openid\tprofile",
            "openid\nprofile",
            "open\"id",
            "open\\id",
            "openid é",
            "openid openid",
        ] {
            assert_eq!(
                rejection(&with("scope", json!(bad))).field(),
                "scope",
                "{bad}"
            );
        }
    }

    /// The name is what the consent screen asks the user to authorise. A
    /// right-to-left override reorders what the user reads without changing a
    /// byte of the markup, so escaping downstream does not help.
    #[test]
    fn a_client_name_that_could_misrepresent_the_consent_prompt_is_refused() {
        for name in [
            "",
            "   ",
            "Acme\u{202e}kcatta",
            "Acme\u{200f}",
            "Acme\u{0000}",
            "Acme\nInc",
        ] {
            let error = rejection(&with("client_name", json!(name)));
            assert_eq!(error.field(), "client_name", "{name:?}");
        }
        assert_eq!(rejection(&without("client_name")).field(), "client_name");
        let long = "a".repeat(ClientRegistration::MAX_CLIENT_NAME_LEN + 1);
        assert_eq!(
            rejection(&with("client_name", json!(long))).field(),
            "client_name"
        );
        // Non-ASCII names are ordinary, and must not be collateral damage.
        assert!(validate(&with("client_name", json!("Société Générale"))).is_ok());
    }

    #[test]
    fn authorization_details_types_are_a_bounded_set_of_names() {
        let client = validate(&with(
            "authorization_details_types",
            json!(["payment_initiation", "account_information"]),
        ))
        .expect("valid");
        assert_eq!(client.authorization_details_types.len(), 2);

        for value in [
            json!([""]),
            json!(["  "]),
            json!(["a\u{0000}b"]),
            json!(["payment", "payment"]),
        ] {
            assert_eq!(
                rejection(&with("authorization_details_types", value.clone())).field(),
                "authorization_details_types",
                "{value}"
            );
        }
        let many: Vec<String> = (0..=ClientRegistration::MAX_AUTHORIZATION_DETAILS_TYPES)
            .map(|i| format!("type{i}"))
            .collect();
        assert_eq!(
            rejection(&with("authorization_details_types", json!(many))).field(),
            "authorization_details_types"
        );
    }

    // -----------------------------------------------------------------------
    // RFC 8705 §2.1.2: the certificate subject a tls_client_auth client is
    // matched on.
    // -----------------------------------------------------------------------

    /// A document for a `tls_client_auth` client with one subject field set.
    fn pki_client(field: &str, value: &str) -> serde_json::Value {
        let mut document = with("token_endpoint_auth_method", json!("tls_client_auth"));
        document
            .as_object_mut()
            .expect("object")
            .insert(field.to_owned(), json!(value));
        document
    }

    /// RFC 8705 §2.1.2: "the client MUST use exactly one of the below metadata
    /// parameters". Each of the five, on its own, registers.
    #[test]
    fn a_pki_client_registers_exactly_one_subject_field() {
        for field in TlsClientAuthSubject::FIELDS {
            // Arrange
            let document = pki_client(field, "expected-value");

            // Act
            let registration = validate_with(&document, caps(true))
                .unwrap_or_else(|e| panic!("{field} was refused: {e}"));

            // Assert
            let subject = registration
                .tls_client_auth_subject
                .expect("a tls_client_auth client carries its subject");
            assert_eq!(subject.field(), field);
            assert_eq!(subject.value(), "expected-value");
        }
    }

    /// None, and more than one, are the same defect: nothing the certificate
    /// can be compared against, or two things and a choice.
    #[test]
    fn a_pki_client_that_registers_none_or_two_subject_fields_is_refused() {
        // Arrange
        let none = with("token_endpoint_auth_method", json!("tls_client_auth"));
        let mut two = pki_client("tls_client_auth_subject_dn", "CN=billing");
        two.as_object_mut()
            .expect("object")
            .insert("tls_client_auth_san_dns".to_owned(), json!("rp.example"));

        // Act
        let no_field = validate_with(&none, caps(true)).expect_err("nothing to compare against");
        let both = validate_with(&two, caps(true)).expect_err("two things to compare against");

        // Assert
        for error in [no_field, both] {
            assert_eq!(error.code(), "invalid_client_metadata");
            assert!(
                TlsClientAuthSubject::FIELDS.contains(&error.field()),
                "{error}"
            );
        }
    }

    /// RFC 8705 §2.2 matches a self-signed client against its own JWKS, so a
    /// subject field there would never be read.
    #[test]
    fn only_a_tls_client_auth_client_may_register_a_subject_field() {
        for method in ["self_signed_tls_client_auth", "private_key_jwt"] {
            for field in TlsClientAuthSubject::FIELDS {
                // Arrange
                let mut document = with("token_endpoint_auth_method", json!(method));
                document
                    .as_object_mut()
                    .expect("object")
                    .insert(field.to_owned(), json!("expected-value"));

                // Act
                let error = validate_with(&document, caps(true))
                    .expect_err("the field belongs to tls_client_auth only");

                // Assert
                assert_eq!(error.field(), field, "{method}");
            }
        }
    }

    /// Without the flag the methods do not exist, so neither does an
    /// expectation about a certificate nobody will look at.
    #[test]
    fn the_subject_fields_need_the_mtls_flag() {
        for field in TlsClientAuthSubject::FIELDS {
            // Arrange: a `private_key_jwt` client, so the only thing the
            // deployment can object to is the field itself.
            let document = with(field, json!("expected-value"));

            // Act
            let error = validate_with(&document, caps(false)).expect_err("mtls is off");

            // Assert
            assert_eq!(error.field(), field);
            assert!(error.to_string().contains("mtls"), "{error}");
        }
    }

    /// The value is compared byte for byte against a certificate, so an empty
    /// one matches a certificate that says nothing and an oversized one is a
    /// document, not a name.
    #[test]
    fn a_subject_value_must_be_a_non_empty_bounded_line() {
        for value in [
            String::new(),
            "   ".to_owned(),
            "CN=a\nCN=b".to_owned(),
            "x".repeat(TlsClientAuthSubject::MAX_LEN + 1),
        ] {
            // Arrange
            let document = pki_client("tls_client_auth_subject_dn", &value);

            // Act
            let error = validate_with(&document, caps(true)).expect_err("not a usable expectation");

            // Assert
            assert_eq!(error.field(), "tls_client_auth_subject_dn");
        }
    }

    #[test]
    fn mtls_endpoint_aliases_need_the_mtls_flag() {
        let document = with("use_mtls_endpoint_aliases", json!(true));
        assert_eq!(
            validate_with(&document, caps(false))
                .expect_err("mtls is off")
                .field(),
            "use_mtls_endpoint_aliases"
        );
        assert!(
            validate_with(&document, caps(true))
                .expect("mtls is on")
                .use_mtls_endpoint_aliases
        );
    }

    // -----------------------------------------------------------------------
    // The document itself
    // -----------------------------------------------------------------------

    /// The parser takes bytes off the network, so it must fail rather than
    /// panic on anything — and it must not carry the input back out in the
    /// error, which becomes an RFC 7591 §3.2.2 `error_description`.
    #[test]
    fn a_malformed_document_is_refused_without_echoing_itself() {
        for document in [
            &b""[..],
            b"null",
            b"[]",
            b"{",
            b"{\"client_name\": }",
            b"{\"redirect_uris\": \"https://rp.example/cb\"}",
            b"{\"dpop_bound_access_tokens\": \"yes\"}",
            &[0xff, 0xfe][..],
        ] {
            let error = ClientRegistration::from_json(document, caps(false))
                .expect_err("should have been refused");
            assert_eq!(error.code(), "invalid_client_metadata");
            let rendered = error.to_string();
            assert!(
                !rendered.contains("rp.example") && !rendered.contains("yes"),
                "the document was echoed back: {rendered}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // The aggregate
    // -----------------------------------------------------------------------

    #[test]
    fn a_disabled_client_is_not_active() {
        let client = Client {
            tenant: TenantId::new("demo"),
            id: ClientId::new("billing"),
            registration: validate(&minimal()).expect("valid"),
            status: ClientStatus::Disabled,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(!client.is_active());
        assert!(client.allows(GrantType::AuthorizationCode));
        assert!(!client.allows(GrantType::ClientCredentials));
    }

    #[test]
    fn every_closed_set_round_trips_through_its_wire_spelling() {
        for method in TokenEndpointAuthMethod::ALL {
            assert_eq!(
                TokenEndpointAuthMethod::parse(method.as_str()),
                Some(method)
            );
        }
        for grant in GrantType::ALL {
            assert_eq!(GrantType::parse(grant.as_str()), Some(grant));
        }
        for application in [ApplicationType::Web, ApplicationType::Native] {
            assert_eq!(
                ApplicationType::parse(application.as_str()),
                Some(application)
            );
        }
        for subject in [SubjectType::Public, SubjectType::Pairwise] {
            assert_eq!(SubjectType::parse(subject.as_str()), Some(subject));
        }
        for status in [ClientStatus::Active, ClientStatus::Disabled] {
            assert_eq!(ClientStatus::parse(status.as_str()), Some(status));
        }
    }

    // -----------------------------------------------------------------------
    // Properties
    //
    // The tables above pin the cases a reader can check against the
    // specification. These check what has to hold for *every* document, which
    // is where a validator with a dozen interacting fields actually goes wrong.
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: 256,
            // A failing case is reproduced from the seed proptest prints.
            // Writing a regressions file into the source tree is not this
            // project's convention: CONTRIBUTING.md says a case found this way
            // earns a named test in the ordinary suite.
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    fn scope_token() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_:]{2,10}"
    }

    fn application_type() -> impl Strategy<Value = ApplicationType> {
        proptest::sample::select(vec![ApplicationType::Web, ApplicationType::Native])
    }

    /// URI-shaped strings, canonical and not, https and not.
    ///
    /// The pieces are chosen so that near-misses are common rather than rare:
    /// two spellings of the same IPv4 literal, two spellings of the same IDN
    /// host, a default port that a parser drops, a path that resolves to
    /// another path. Random bytes would almost never produce a pair that the
    /// comparison has to keep apart.
    fn uri_shape() -> impl Strategy<Value = String> {
        let scheme =
            proptest::sample::select(vec!["https", "http", "HTTPS", "com.example.app", "ftp"]);
        let userinfo = proptest::sample::select(vec!["", "user@", "user:pw@"]);
        let host = proptest::sample::select(vec![
            "rp.example",
            "RP.Example",
            "127.0.0.1",
            "127.0.0.2",
            "127.1",
            "[::1]",
            "[0:0:0:0:0:0:0:1]",
            "localhost",
            "192.168.1.10",
            "xn--e1afmkfd.example",
            "пример.example",
            "",
        ]);
        let port = prop_oneof![
            Just(String::new()),
            Just(":443".to_owned()),
            Just(":80".to_owned()),
            Just(":".to_owned()),
            (1_u16..=65535).prop_map(|port| format!(":{port}")),
        ];
        let path = proptest::sample::select(vec![
            "", "/", "/cb", "/CB", "/cb/", "/a%2Fb", "/a%2fb", "/../cb", "/a/./b", "/c b",
        ]);
        let query = proptest::sample::select(vec!["", "?", "?x=1", "?X=1"]);
        let fragment = proptest::sample::select(vec!["", "#", "#f"]);
        (scheme, userinfo, host, port, path, query, fragment).prop_map(
            |(scheme, userinfo, host, port, path, query, fragment)| {
                format!("{scheme}://{userinfo}{host}{port}{path}{query}{fragment}")
            },
        )
    }

    /// Redirect URIs a client could plausibly register, already normalised.
    fn redirect_uri() -> impl Strategy<Value = String> {
        (
            "[a-z]{3,10}",
            "[a-z0-9]{1,8}",
            proptest::option::of(1024_u16..=65535),
        )
            .prop_map(|(host, path, port)| match port {
                Some(port) => format!("https://{host}.example:{port}/{path}"),
                None => format!("https://{host}.example/{path}"),
            })
    }

    /// A document that satisfies every rule, built only from permitted values.
    fn valid_document() -> impl Strategy<Value = serde_json::Value> {
        (
            "[A-Z][a-z]{2,15}",
            proptest::collection::btree_set(redirect_uri(), 1..4),
            (any::<bool>(), any::<bool>(), any::<bool>()),
            proptest::collection::btree_set(scope_token(), 0..4),
            proptest::sample::select(SigningAlgorithm::ALL.to_vec()),
            proptest::option::of(proptest::sample::select(SigningAlgorithm::ALL.to_vec())),
            proptest::collection::btree_set("[a-z_]{3,12}", 0..3),
            any::<bool>(),
        )
            .prop_map(
                |(
                    name,
                    uris,
                    (refresh, credentials, explicit),
                    scopes,
                    id_alg,
                    request_alg,
                    rar,
                    inline_keys,
                )| {
                    let mut grants = vec!["authorization_code"];
                    if refresh {
                        grants.push("refresh_token");
                    }
                    if credentials {
                        grants.push("client_credentials");
                    }
                    let mut document = serde_json::Map::new();
                    document.insert("client_name".to_owned(), json!(name));
                    document.insert(
                        "redirect_uris".to_owned(),
                        json!(uris.into_iter().collect::<Vec<_>>()),
                    );
                    document.insert("grant_types".to_owned(), json!(grants));
                    if explicit {
                        document.insert("response_types".to_owned(), json!(["code"]));
                    }
                    if !scopes.is_empty() {
                        document.insert(
                            "scope".to_owned(),
                            json!(scopes.into_iter().collect::<Vec<_>>().join(" ")),
                        );
                    }
                    if inline_keys {
                        document.insert("jwks".to_owned(), json!({"keys": [{"kty": "OKP"}]}));
                    } else {
                        document.insert("jwks_uri".to_owned(), json!("https://rp.example/jwks"));
                    }
                    document.insert(
                        "id_token_signed_response_alg".to_owned(),
                        json!(id_alg.as_str()),
                    );
                    if let Some(alg) = request_alg {
                        document
                            .insert("request_object_signing_alg".to_owned(), json!(alg.as_str()));
                    }
                    if !rar.is_empty() {
                        document.insert(
                            "authorization_details_types".to_owned(),
                            json!(rar.into_iter().collect::<Vec<_>>()),
                        );
                    }
                    serde_json::Value::Object(document)
                },
            )
    }

    /// Values the profile forbids, paired with the field they belong to.
    fn forbidden() -> Vec<(&'static str, serde_json::Value)> {
        vec![
            ("token_endpoint_auth_method", json!("client_secret_basic")),
            ("token_endpoint_auth_method", json!("client_secret_post")),
            ("token_endpoint_auth_method", json!("client_secret_jwt")),
            ("token_endpoint_auth_method", json!("none")),
            ("response_types", json!(["token"])),
            ("response_types", json!(["code", "id_token"])),
            ("grant_types", json!(["implicit"])),
            ("grant_types", json!(["password"])),
            ("id_token_signed_response_alg", json!("none")),
            ("id_token_signed_response_alg", json!("RS256")),
            ("userinfo_signed_response_alg", json!("none")),
            ("userinfo_signed_response_alg", json!("RS256")),
            ("request_object_signing_alg", json!("HS256")),
            ("require_pushed_authorization_requests", json!(false)),
            ("dpop_bound_access_tokens", json!(false)),
            ("subject_type", json!("public_pairwise")),
            ("application_type", json!("service")),
            ("scope", json!("openid\tprofile")),
            ("client_name", json!("")),
        ]
    }

    proptest! {
        #![proptest_config(config())]

        /// The generator only emits documents every rule permits, so a
        /// rejection here is a rule firing on something it should not.
        #[test]
        fn every_document_built_only_from_permitted_values_is_accepted(
            document in valid_document(),
        ) {
            let encoded = serde_json::to_vec(&document).expect("serialise");
            let client = ClientRegistration::from_json(&encoded, everything_on())
                .map_err(|e| TestCaseError::fail(format!("rejected a valid document: {e}")))?;

            prop_assert!(client.allows(GrantType::AuthorizationCode));
            prop_assert_eq!(client.token_binding, TokenBinding::Dpop);
            prop_assert_eq!(client.application_type, ApplicationType::Web);
            prop_assert_eq!(client.subject_type, SubjectType::Public);

            // Byte for byte, in the order registered: RFC 9700 §4.1 matching is
            // a string comparison, so both are part of the contract.
            let registered: Vec<&str> =
                client.redirect_uris.iter().map(RedirectUri::as_str).collect();
            let submitted: Vec<&str> = document["redirect_uris"]
                .as_array()
                .expect("array")
                .iter()
                .map(|value| value.as_str().expect("string"))
                .collect();
            prop_assert_eq!(registered, submitted);
        }

        /// Every rejection rule fires whatever else the document says: one
        /// forbidden value is enough, and the error names the field that
        /// carried it.
        #[test]
        fn a_forbidden_value_is_rejected_whatever_else_the_document_says(
            document in valid_document(),
            (field, value) in proptest::sample::select(forbidden()),
        ) {
            let mut document = document;
            document.as_object_mut().expect("object").insert(field.to_owned(), value);
            let encoded = serde_json::to_vec(&document).expect("serialise");
            let error = ClientRegistration::from_json(&encoded, everything_on())
                .err()
                .ok_or_else(|| {
                    TestCaseError::fail(format!("{field} accepted a forbidden value"))
                })?;
            prop_assert_eq!(error.field(), field);
            prop_assert_eq!(error.code(), "invalid_client_metadata");
        }

        /// Whatever it is handed, the parser answers rather than panicking —
        /// and whatever it accepts satisfies the invariants the rest of the
        /// server never re-checks.
        #[test]
        fn an_accepted_document_always_satisfies_the_profile(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
            mtls in any::<bool>(),
        ) {
            let capabilities = if mtls { everything_on() } else { Capabilities::default() };
            let Ok(client) = ClientRegistration::from_json(&bytes, capabilities) else {
                return Ok(());
            };
            prop_assert!(
                client.token_binding.is_dpop_bound() || client.token_binding.is_certificate_bound(),
                "an accepted client would be issued bearer access tokens"
            );
            prop_assert!(
                !client.token_endpoint_auth_method.requires_mtls() || mtls,
                "an mTLS authentication method survived with the flag off"
            );
            prop_assert!(!client.use_mtls_endpoint_aliases || mtls);
            prop_assert!(SigningAlgorithm::ALL.contains(&client.id_token_signed_response_alg));
            for grant in &client.grant_types {
                prop_assert!(
                    grant.required_feature().is_none_or(|f| capabilities.is_enabled(f)),
                    "a grant behind a disabled flag survived"
                );
            }
            for uri in &client.redirect_uris {
                prop_assert!(
                    uri.as_str().starts_with("https://")
                        || (client.application_type == ApplicationType::Native
                            && uri.as_str().starts_with("http://")),
                    "an http redirect URI survived on a client that is not native"
                );
            }
            if client.redirect_uris.is_empty() {
                prop_assert!(!client.allows(GrantType::AuthorizationCode));
            }
        }

        /// Switching a feature on must never turn an acceptable client into an
        /// unacceptable one: an operator enabling mTLS would otherwise
        /// invalidate registrations that were fine the day before.
        #[test]
        fn enabling_every_feature_never_rejects_a_client_that_was_already_valid(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            if ClientRegistration::from_json(&bytes, Capabilities::default()).is_ok() {
                prop_assert!(ClientRegistration::from_json(&bytes, everything_on()).is_ok());
            }
        }

        /// **Normalisation is never applied.** The whole design rests on this:
        /// RFC 9700 §4.1.3 makes the registered bytes the comparison, so a
        /// parser that rewrote them would change what the client must send,
        /// and one that kept a form a browser rewrites would compare a string
        /// no request can carry. Stated both ways — what is accepted comes back
        /// unchanged, and what a URL parser would rewrite is refused.
        #[test]
        fn a_redirect_uri_is_never_normalised_on_the_way_in(
            raw in uri_shape(),
            application_type in application_type(),
        ) {
            // A refusal is a refusal, never a quiet correction, so there is
            // nothing to assert on that branch: the only way a rewritten URI
            // could escape is by being accepted.
            if let Ok(uri) = RedirectUri::parse(&raw, application_type) {
                prop_assert_eq!(
                    uri.as_str(),
                    raw.as_str(),
                    "the parser rewrote a redirect URI"
                );
                // And the accepted form is a fixed point, so a stored URI put
                // back through the validator survives (`ast-83p.3`).
                let again = RedirectUri::parse(uri.as_str(), application_type);
                prop_assert_eq!(again.as_ref().map(RedirectUri::as_str), Ok(raw.as_str()));
            }
            if let Ok(url) = Url::parse(&raw)
                && url.as_str() != raw
            {
                prop_assert!(
                    RedirectUri::parse(&raw, application_type).is_err(),
                    "a URI a URL parser rewrites was accepted as registered"
                );
            }
        }

        /// A registered URI matches itself, whatever it is. Reflexivity is not
        /// free here: the loopback branch splits strings by hand, and a
        /// splitter that disagreed with the byte-exact branch would break every
        /// native client on the first request.
        #[test]
        fn every_registered_redirect_uri_matches_itself(
            raw in uri_shape(),
            application_type in application_type(),
        ) {
            let Ok(uri) = RedirectUri::parse(&raw, application_type) else {
                return Ok(());
            };
            prop_assert!(uri.matches(uri.as_str(), application_type));
            prop_assert!(RedirectUri::is_registered(
                std::slice::from_ref(&uri),
                uri.as_str(),
                application_type,
            ));
        }

        /// The only pair of different strings that may match is the
        /// RFC 8252 §7.3 one: a native client's loopback callback on another
        /// port. Everything else about the two URIs is byte-equal, which is
        /// what keeps the exception from being a pattern.
        #[test]
        fn a_match_between_different_strings_can_only_be_a_loopback_port(
            registered_raw in uri_shape(),
            presented in uri_shape(),
            application_type in application_type(),
        ) {
            let Ok(uri) = RedirectUri::parse(&registered_raw, application_type) else {
                return Ok(());
            };
            if !uri.matches(&presented, application_type) || uri.as_str() == presented {
                return Ok(());
            }
            prop_assert_eq!(application_type, ApplicationType::Native);
            prop_assert!(uri.as_str().starts_with("http://"));
            prop_assert!(
                RedirectUri::parse(&presented, application_type).is_ok(),
                "a URI that could not be registered was matched: {}",
                presented
            );
            let (host, rest) = RedirectUri::loopback_parts(uri.as_str())
                .ok_or_else(|| TestCaseError::fail("the registered URI is not loopback"))?;
            let (presented_host, presented_rest) = RedirectUri::loopback_parts(&presented)
                .ok_or_else(|| TestCaseError::fail("the presented URI is not loopback"))?;
            prop_assert_eq!(host, presented_host, "a match crossed to another host");
            prop_assert_eq!(rest, presented_rest, "a match changed more than the port");
        }

        /// RFC 8252 §7.3 over the whole port range, rather than the handful of
        /// ports a table can list: any port matches, and the path it is glued
        /// to still does not.
        #[test]
        fn a_loopback_registration_matches_every_port_but_only_its_own_path(
            host in proptest::sample::select(vec!["127.0.0.1", "127.0.0.2", "[::1]"]),
            path in "/[a-z]{1,8}",
            other_path in "/[a-z]{1,8}",
            // Port 80 is the `http` default, which a URL parser drops — so it
            // is not a *spelling* a redirect URI may carry, registered or
            // presented, and `parse` refuses it either way.
            registered_port in proptest::option::of(
                (1_u16..=65535).prop_filter("80 is dropped as the default port", |p| *p != 80)
            ),
            presented_port in proptest::option::of(
                (1_u16..=65535).prop_filter("80 is dropped as the default port", |p| *p != 80)
            ),
        ) {
            let rendered = |port: Option<u16>| {
                port.map_or_else(String::new, |port| format!(":{port}"))
            };
            let base = format!("http://{host}{}{path}", rendered(registered_port));
            let uri = RedirectUri::parse(&base, ApplicationType::Native)
                .map_err(|e| TestCaseError::fail(format!("{base}: {e}")))?;

            let same_path = format!("http://{host}{}{path}", rendered(presented_port));
            prop_assert!(
                uri.matches(&same_path, ApplicationType::Native),
                "the port was not allowed to vary: {} against {}",
                same_path,
                base
            );
            // A web client gets string equality and nothing more, whatever the
            // registered URI happens to look like.
            prop_assert_eq!(
                uri.matches(&same_path, ApplicationType::Web),
                same_path == base,
                "a web client was given the loopback port exception"
            );
            if other_path != path {
                let other = format!("http://{host}{}{other_path}", rendered(presented_port));
                prop_assert!(
                    !uri.matches(&other, ApplicationType::Native),
                    "the port exception carried the path with it: {}",
                    other
                );
            }
        }

        /// No prefix, suffix or containment relation is ever enough. This is
        /// the attack RFC 9700 §4.1.1 describes, and the reason §4.1.3 replaced
        /// pattern matching with string equality.
        #[test]
        fn extending_or_truncating_a_registered_uri_never_matches_it(
            base in redirect_uri(),
            extra in "[a-zA-Z0-9/?=&%._~-]{1,10}",
            application_type in application_type(),
        ) {
            let uri = RedirectUri::parse(&base, application_type)
                .map_err(|e| TestCaseError::fail(format!("{base}: {e}")))?;
            let extended = format!("{base}{extra}");
            let prefixed = format!("{extra}{base}");
            let truncated = &base[..base.len() - 1];
            prop_assert!(!uri.matches(&extended, application_type));
            prop_assert!(!uri.matches(&prefixed, application_type));
            prop_assert!(!uri.matches(truncated, application_type));
        }

        /// The rendered error becomes an RFC 7591 §3.2.2 `error_description`
        /// and an audit detail, so it must not carry the document back out.
        #[test]
        fn a_rejection_never_repeats_a_value_taken_from_the_document(
            document in valid_document(),
            (field, _) in proptest::sample::select(forbidden()),
            marker in "[A-Za-z]{12}",
        ) {
            let mut document = document;
            let object = document.as_object_mut().expect("object");
            object.insert("client_name".to_owned(), json!(format!("Acme {marker}")));
            object.insert(field.to_owned(), json!(marker.clone()));
            let encoded = serde_json::to_vec(&document).expect("serialise");
            if let Err(error) = ClientRegistration::from_json(&encoded, everything_on()) {
                prop_assert!(
                    !error.to_string().contains(marker.as_str()),
                    "the document was echoed into the error: {}",
                    error
                );
            }
        }
    }
}
