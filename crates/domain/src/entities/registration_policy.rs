//! The per-tenant registration policy — RFC 7591 §5's answer, as data.
//!
//! [`ClientRegistration::from_json`] decides what a *well-formed* client is for
//! this deployment: the algorithm allow-list, ADR-0005's redirect URI rules,
//! the auth methods FAPI 2.0 permits. That decision is the same for every
//! tenant of a binary, because it is a property of the profile.
//!
//! This module decides the other half: what a *permitted* client is for one
//! tenant. A tenant that onboards agents wants `client_credentials` and nothing
//! else; a tenant that onboards browser applications wants callbacks on its own
//! hosts and no others. Neither is a statement about the protocol, and neither
//! belongs in a binary an operator has to rebuild.
//!
//! # It is data, never code
//!
//! The policy is a JSON document stored on the tenant row and validated against
//! a schema before it is read. There is no expression language, no predicate
//! supplied by a tenant, and no place a tenant-authored string is evaluated:
//! every rule here is a set membership or a boolean, and the worst a malformed
//! document can do is be refused. The schema is
//! [`crate::JsonSchema`] — the subset `ast-gxh.6` already ships for
//! `authorization_details` — rather than a second validator written here,
//! because two schema validators in one binary are two different opinions about
//! what `"additionalProperties": false` means.
//!
//! # Evaluation is total
//!
//! [`RegistrationPolicy::evaluate`] takes a validated [`ClientRegistration`]
//! and returns the first rule it broke. It allocates nothing that depends on
//! the document, indexes nothing, and cannot panic: it is reached from an
//! endpoint that may be unauthenticated, so "deterministic and total" is a
//! security property and not a nicety. `fuzz/fuzz_targets/registration_policy`
//! asserts it on arbitrary bytes.
//!
//! # What a refusal tells the caller
//!
//! `invalid_client_metadata` and a fixed sentence naming the field — never the
//! value, for the reason [`ClientMetadataError`] gives. The *rule* that failed
//! is a stable identifier ([`RuleId`]) which goes into the audit trail, so an
//! operator can tell "everybody is failing the host allow-list" from "somebody
//! is probing", and a client learns neither.

use crate::entities::authorization_details::Schema;
use crate::entities::client::{
    ClientMetadataError, ClientRegistration, GrantType, JwksSource, TokenEndpointAuthMethod,
};
use serde_json::Value;
use std::collections::BTreeSet;
use time::Duration;

/// The most entries any one allow-list in a policy may hold.
///
/// A policy is written by an administrator and read on every registration, so
/// the bound is about keeping evaluation cheap rather than about abuse. Sixty
/// four hosts, scopes or resources is more than any tenant this server has met.
pub const MAX_LIST_ENTRIES: usize = 64;

/// The longest single entry — a host, a scope, a resource, an issuer.
pub const MAX_ENTRY_LEN: usize = 256;

/// The most trusted software statement issuers one tenant may configure.
///
/// Each is a signing authority over this tenant's registrations (RFC 7591
/// §2.3), so the list is short by design: an operator who cannot name the four
/// issuers they trust does not know who can register clients here.
pub const MAX_SOFTWARE_STATEMENT_ISSUERS: usize = 8;

/// The largest policy document this server will read.
pub const MAX_POLICY_BYTES: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// Who may register
// ---------------------------------------------------------------------------

/// Who a tenant lets register a client.
///
/// The same three postures the deployment picks in `asterius.toml`
/// (`asterius_server::http::register::RegistrationPolicy`), expressed per
/// tenant. The two are combined by [`RegistrationMode::narrowest`], never
/// replaced: a tenant may close what the deployment opened and may not open
/// what the deployment closed, which is the rule
/// [`crate::TenantSettings`] states for every other flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistrationMode {
    /// Nobody. The endpoint is neither advertised nor mounted for this tenant.
    Closed,
    /// Callers holding an initial access token (RFC 7591 §3).
    InitialAccessToken,
    /// Anybody. RFC 7591 §3's SHOULD.
    Open,
}

impl RegistrationMode {
    /// Every mode, from the most restrictive to the least.
    pub const ALL: [Self; 3] = [Self::Closed, Self::InitialAccessToken, Self::Open];

    /// The configuration spelling, as written in `asterius.toml` and in the
    /// stored policy document.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::InitialAccessToken => "initial_access_token",
            Self::Open => "open",
        }
    }

    /// Reads a mode name, or `None` for a spelling this build does not know.
    ///
    /// Strict, for the reason [`crate::Feature::from_key`] is: a stored mode
    /// that quietly fell back to a default is a posture an operator believes is
    /// in force and is not.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == value)
    }

    /// The more restrictive of two modes.
    ///
    /// [`Ord`] on this enum is the permissiveness order — `Closed` sorts first
    /// — so this is `min`, written out because "narrowest" is what the call
    /// sites mean and `min` on a security posture reads like an arithmetic
    /// accident.
    #[must_use]
    pub fn narrowest(self, other: Self) -> Self {
        if self <= other { self } else { other }
    }

    /// Whether this tenant serves the registration endpoint at all.
    #[must_use]
    pub const fn is_open_at_all(self) -> bool {
        !matches!(self, Self::Closed)
    }
}

// ---------------------------------------------------------------------------
// The rules
// ---------------------------------------------------------------------------

/// Which key material a tenant demands of a registering client.
///
/// `Any` is the profile's own rule — [`ClientRegistration`] already refuses a
/// document with neither `jwks` nor `jwks_uri`, and refuses one with both (RFC
/// 7591 §2) — so this narrows rather than adds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum JwksRequirement {
    /// Either form. The default.
    #[default]
    Any,
    /// An inline `jwks` only: the tenant does not want this server fetching a
    /// URL a client chose (RFC 7591 §5).
    Inline,
    /// A `jwks_uri` only: the tenant wants rotation without re-registration.
    Uri,
}

impl JwksRequirement {
    /// Every value, in the order the schema lists them.
    pub const ALL: [Self; 3] = [Self::Any, Self::Inline, Self::Uri];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Inline => "inline",
            Self::Uri => "uri",
        }
    }

    /// Reads a spelling, or `None`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// Whether a source satisfies this requirement.
    #[must_use]
    pub const fn accepts(self, source: &JwksSource) -> bool {
        match (self, source) {
            (Self::Any, _)
            | (Self::Inline, JwksSource::Inline(_))
            | (Self::Uri, JwksSource::Uri(_)) => true,
            (Self::Inline, JwksSource::Uri(_)) | (Self::Uri, JwksSource::Inline(_)) => false,
        }
    }
}

/// An issuer whose software statements this tenant believes.
///
/// A software statement is a JWT that *overrides* the plain metadata of the
/// request (RFC 7591 §2.3), so an entry here is a party that can register
/// clients in this tenant with metadata the requester never asked for. That is
/// a root of trust, and it is why the list is per tenant, short, and carries an
/// explicit JWKS URL rather than discovering one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SoftwareStatementIssuer {
    /// The exact `iss` the statement must carry.
    pub issuer: String,
    /// Where this issuer's public keys are published.
    ///
    /// Fetched through `asterius_server::outbound` — ADR-0006's single outbound
    /// path — like every other URL this server dereferences.
    pub jwks_uri: String,
}

/// What a tenant demands of software statements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SoftwareStatementRule {
    /// Whether a registration without a software statement is refused.
    required: bool,
    /// The issuers this tenant trusts. Empty with `required` set means no
    /// registration can succeed, which [`RegistrationPolicy::from_json`]
    /// refuses rather than storing.
    issuers: Vec<SoftwareStatementIssuer>,
}

impl SoftwareStatementRule {
    /// Whether a registration must carry a statement.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.required
    }

    /// The trusted issuers.
    #[must_use]
    pub fn issuers(&self) -> &[SoftwareStatementIssuer] {
        &self.issuers
    }

    /// The trusted issuer with this `iss`, if any.
    #[must_use]
    pub fn issuer(&self, iss: &str) -> Option<&SoftwareStatementIssuer> {
        // Byte-exact: an issuer identifier is compared as a string (RFC 7591
        // §2.3 defers to the JWT's `iss`, and OIDC Discovery §4.3 makes issuer
        // comparison exact), and a case-insensitive match here would trust a
        // host the operator did not write.
        self.issuers.iter().find(|known| known.issuer == iss)
    }

    /// Whether this tenant accepts software statements at all.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        !self.issuers.is_empty()
    }
}

/// A rule a registration broke.
///
/// A closed set, because it becomes an audit detail: an operator filters on it
/// and a metric is labelled with it, and a `String` here would be a cardinality
/// leak the moment somebody interpolated a field name into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RuleId {
    /// The `token_endpoint_auth_method` is not on this tenant's list.
    AuthMethod,
    /// A `grant_types` entry is not on this tenant's list.
    GrantType,
    /// A `scope` value is not on this tenant's list.
    Scope,
    /// A resource (RFC 8707 audience) is not on this tenant's list.
    Resource,
    /// A redirect URI's host is not on this tenant's list.
    RedirectHost,
    /// The client's keys are not published the way this tenant demands.
    JwksSource,
    /// The registration carried no software statement and this tenant requires
    /// one.
    SoftwareStatementRequired,
    /// The initial access token has registered as many clients as it may.
    ClientQuota,
}

impl RuleId {
    /// Every rule, so a test can assert each has an identifier and a sentence.
    pub const ALL: [Self; 8] = [
        Self::AuthMethod,
        Self::GrantType,
        Self::Scope,
        Self::Resource,
        Self::RedirectHost,
        Self::JwksSource,
        Self::SoftwareStatementRequired,
        Self::ClientQuota,
    ];

    /// The stable identifier that reaches the audit trail.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthMethod => "auth_method_not_allowed",
            Self::GrantType => "grant_type_not_allowed",
            Self::Scope => "scope_not_allowed",
            Self::Resource => "resource_not_allowed",
            Self::RedirectHost => "redirect_host_not_allowed",
            Self::JwksSource => "jwks_source_not_allowed",
            Self::SoftwareStatementRequired => "software_statement_required",
            Self::ClientQuota => "client_quota_exhausted",
        }
    }

    /// The metadata field the refusal is reported against.
    #[must_use]
    pub const fn field(self) -> &'static str {
        match self {
            Self::AuthMethod => "token_endpoint_auth_method",
            Self::GrantType => "grant_types",
            Self::Scope => "scope",
            Self::Resource => "resources",
            Self::RedirectHost => "redirect_uris",
            Self::JwksSource => "jwks",
            Self::SoftwareStatementRequired | Self::ClientQuota => "software_statement",
        }
    }

    /// The sentence a client is told, in fixed text.
    ///
    /// Names the rule and never the value: a registration document is one of
    /// the few places a caller can put a credential by mistake, and this
    /// endpoint may be reachable before authentication.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::AuthMethod => {
                "this tenant's registration policy does not allow that client authentication method"
            }
            Self::GrantType => {
                "this tenant's registration policy does not allow one of the requested grant types"
            }
            Self::Scope => {
                "this tenant's registration policy does not allow one of the requested scopes"
            }
            Self::Resource => {
                "this tenant's registration policy does not allow one of the requested resources"
            }
            Self::RedirectHost => {
                "this tenant's registration policy does not allow one of the redirect URI hosts"
            }
            Self::JwksSource => {
                "this tenant's registration policy requires the client's keys to be published differently"
            }
            Self::SoftwareStatementRequired => {
                "this tenant's registration policy requires a software statement"
            }
            Self::ClientQuota => {
                "this initial access token has registered as many clients as it may"
            }
        }
    }
}

/// A registration this tenant's policy refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyViolation {
    /// Which rule.
    pub rule: RuleId,
}

impl PolicyViolation {
    /// The refusal for one rule.
    #[must_use]
    pub const fn new(rule: RuleId) -> Self {
        Self { rule }
    }

    /// The RFC 7591 §3.2.2 error this becomes on the wire.
    ///
    /// Always `invalid_client_metadata`, whichever rule failed — §3.2.2's list
    /// has no code for "your document is fine and this tenant does not want
    /// it", and inventing one would be a code no client library knows. The rule
    /// goes to the audit trail instead.
    #[must_use]
    pub fn to_metadata_error(self) -> ClientMetadataError {
        ClientMetadataError::Rejected {
            field: self.rule.field(),
            reason: self.rule.reason().to_owned(),
        }
    }
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.rule.as_str())
    }
}

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

/// One tenant's registration policy.
///
/// Every allow-list is an [`Option`], and the distinction matters: `None` is
/// "this tenant has no opinion", which admits whatever the profile admits, and
/// `Some(set)` is a closed list — including `Some(empty)`, which admits
/// nothing. A policy that meant "empty means anything" would turn a typo into
/// an open door.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrationPolicy {
    mode: Option<RegistrationMode>,
    auth_methods: Option<BTreeSet<TokenEndpointAuthMethod>>,
    grant_types: Option<BTreeSet<GrantType>>,
    scopes: Option<BTreeSet<String>>,
    resources: Option<BTreeSet<String>>,
    redirect_uri_hosts: Option<BTreeSet<String>>,
    jwks: JwksRequirement,
    software_statement: SoftwareStatementRule,
    max_clients_per_initial_access_token: Option<u32>,
    unused_client_expiry: Option<Duration>,
}

impl RegistrationPolicy {
    /// The preset for onboarding agents (`E11_01`).
    ///
    /// An agent is a client with no browser, no user at the keyboard and no
    /// callback: it authenticates with a key and asks for `client_credentials`.
    /// The preset says exactly that, and adds the two rules an agent fleet
    /// needs and a human-operated client does not — a software statement from
    /// somebody who vouched for the agent, and an expiry for the ones that
    /// never come back.
    ///
    /// It carries **no** issuer list, because a root of trust cannot be a
    /// default: a tenant that selects this profile must name the issuers it
    /// believes, and [`RegistrationPolicy::from_json`] refuses a document that
    /// requires a statement without naming one.
    #[must_use]
    pub fn agent_profile() -> Self {
        Self {
            mode: Some(RegistrationMode::InitialAccessToken),
            auth_methods: Some(BTreeSet::from([
                TokenEndpointAuthMethod::PrivateKeyJwt,
                TokenEndpointAuthMethod::TlsClientAuth,
                TokenEndpointAuthMethod::SelfSignedTlsClientAuth,
            ])),
            grant_types: Some(BTreeSet::from([GrantType::ClientCredentials])),
            scopes: None,
            resources: None,
            // No callback at all: the grant list has nothing that reaches the
            // authorization endpoint, so an agent registering a redirect URI is
            // registering something it cannot use.
            redirect_uri_hosts: Some(BTreeSet::new()),
            jwks: JwksRequirement::Any,
            software_statement: SoftwareStatementRule {
                required: true,
                issuers: Vec::new(),
            },
            max_clients_per_initial_access_token: Some(DEFAULT_AGENT_CLIENT_QUOTA),
            unused_client_expiry: Some(DEFAULT_AGENT_UNUSED_EXPIRY),
        }
    }

    /// The name of a preset, or `None` for a spelling this build does not know.
    fn profile(name: &str) -> Option<Self> {
        match name {
            "agent" => Some(Self::agent_profile()),
            _ => None,
        }
    }

    /// This tenant's registration mode, or `None` where it has no opinion.
    #[must_use]
    pub const fn mode(&self) -> Option<RegistrationMode> {
        self.mode
    }

    /// The mode in force, given what the deployment configured.
    ///
    /// A tenant that named no mode gets the deployment's — the same rule
    /// [`crate::TenantSettings::effective_capabilities`] follows for every
    /// other flag, and the reason a tenant row written before this feature
    /// existed does not silently close its own registration endpoint. A tenant
    /// that named one gets the narrower of the two: `closed` here closes the
    /// endpoint, `open` here does not open one the operator gated.
    #[must_use]
    pub fn effective_mode(&self, deployment: RegistrationMode) -> RegistrationMode {
        match self.mode {
            None => deployment,
            Some(mode) => mode.narrowest(deployment),
        }
    }

    /// What this tenant demands of software statements.
    #[must_use]
    pub const fn software_statement(&self) -> &SoftwareStatementRule {
        &self.software_statement
    }

    /// How many clients one initial access token may register, if capped.
    #[must_use]
    pub const fn max_clients_per_initial_access_token(&self) -> Option<u32> {
        self.max_clients_per_initial_access_token
    }

    /// How long a client may go unused before it is expired, if at all.
    #[must_use]
    pub const fn unused_client_expiry(&self) -> Option<Duration> {
        self.unused_client_expiry
    }

    /// Evaluates a registration against this policy.
    ///
    /// Total and deterministic: every branch is a set lookup on values that are
    /// already parsed, there is no indexing, no arithmetic and no allocation
    /// that depends on the document. The order rules are checked in is fixed so
    /// that the same document always names the same rule — an operator chasing
    /// a refusal must not get a different answer on a retry.
    ///
    /// # Errors
    ///
    /// The first [`PolicyViolation`] found.
    // fuzz-target: registration_policy
    pub fn evaluate(&self, registration: &ClientRegistration) -> Result<(), PolicyViolation> {
        if let Some(allowed) = &self.auth_methods
            && !allowed.contains(&registration.token_endpoint_auth_method)
        {
            return Err(PolicyViolation::new(RuleId::AuthMethod));
        }
        if let Some(allowed) = &self.grant_types
            && !registration.grant_types.iter().all(|g| allowed.contains(g))
        {
            return Err(PolicyViolation::new(RuleId::GrantType));
        }
        if let Some(allowed) = &self.scopes
            && !registration
                .scopes
                .iter()
                .all(|scope| allowed.contains(scope))
        {
            return Err(PolicyViolation::new(RuleId::Scope));
        }
        if let Some(allowed) = &self.resources
            && !registration
                .resources
                .iter()
                .all(|resource| allowed.contains(resource))
        {
            return Err(PolicyViolation::new(RuleId::Resource));
        }
        if let Some(allowed) = &self.redirect_uri_hosts
            && !registration.redirect_uris.iter().all(|uri| {
                // A URI whose host cannot be read is refused rather than
                // skipped: `RedirectUri::host` returns `None` only for bytes a
                // parser can no longer read, and "cannot be named" must not
                // mean "is allowed".
                uri.host()
                    .is_some_and(|host| allowed.contains(host.as_str()))
            })
        {
            return Err(PolicyViolation::new(RuleId::RedirectHost));
        }
        if !self.jwks.accepts(&registration.jwks) {
            return Err(PolicyViolation::new(RuleId::JwksSource));
        }
        Ok(())
    }

    /// Whether a registration that presented no software statement may proceed.
    ///
    /// Separate from [`RegistrationPolicy::evaluate`] because the statement is
    /// a property of the *request*, not of the metadata: evaluation runs on the
    /// merged document, by which point the statement has already been consumed.
    ///
    /// # Errors
    ///
    /// [`RuleId::SoftwareStatementRequired`] when the tenant demands one.
    pub const fn check_software_statement_present(
        &self,
        presented: bool,
    ) -> Result<(), PolicyViolation> {
        if self.software_statement.required && !presented {
            return Err(PolicyViolation::new(RuleId::SoftwareStatementRequired));
        }
        Ok(())
    }

    /// Whether an initial access token that has already registered `registered`
    /// clients may register another.
    ///
    /// # Errors
    ///
    /// [`RuleId::ClientQuota`] at or above the cap. Saturating, so a count that
    /// somehow exceeds a `u32` refuses rather than wrapping into permission.
    pub const fn check_client_quota(&self, registered: u64) -> Result<(), PolicyViolation> {
        if let Some(max) = self.max_clients_per_initial_access_token
            && registered >= max as u64
        {
            return Err(PolicyViolation::new(RuleId::ClientQuota));
        }
        Ok(())
    }

    /// The JSON Schema the stored document is validated against.
    ///
    /// A `&'static str` parsed on demand rather than a `LazyLock<Schema>`,
    /// because a policy is read when a tenant's settings are loaded and not per
    /// request, and a parse that can be shown to succeed in a test is easier to
    /// reason about than a global.
    #[must_use]
    pub fn schema_document() -> Value {
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "profile": { "type": "string", "enum": ["agent"] },
                "mode": { "type": "string", "enum": ["closed", "initial_access_token", "open"] },
                "token_endpoint_auth_methods": {
                    "type": "array",
                    "maxItems": MAX_LIST_ENTRIES,
                    "items": { "type": "string", "maxLength": MAX_ENTRY_LEN }
                },
                "grant_types": {
                    "type": "array",
                    "maxItems": MAX_LIST_ENTRIES,
                    "items": { "type": "string", "maxLength": MAX_ENTRY_LEN }
                },
                "scopes": {
                    "type": "array",
                    "maxItems": MAX_LIST_ENTRIES,
                    "items": { "type": "string", "maxLength": MAX_ENTRY_LEN }
                },
                "resources": {
                    "type": "array",
                    "maxItems": MAX_LIST_ENTRIES,
                    "items": { "type": "string", "maxLength": MAX_ENTRY_LEN }
                },
                "redirect_uri_hosts": {
                    "type": "array",
                    "maxItems": MAX_LIST_ENTRIES,
                    "items": { "type": "string", "maxLength": MAX_ENTRY_LEN }
                },
                "jwks": { "type": "string", "enum": ["any", "inline", "uri"] },
                "software_statement": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "required": { "type": "boolean" },
                        "issuers": {
                            "type": "array",
                            "maxItems": MAX_SOFTWARE_STATEMENT_ISSUERS,
                            "items": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["issuer", "jwks_uri"],
                                "properties": {
                                    "issuer": { "type": "string", "maxLength": MAX_ENTRY_LEN },
                                    "jwks_uri": { "type": "string", "maxLength": MAX_ENTRY_LEN }
                                }
                            }
                        }
                    }
                },
                "max_clients_per_initial_access_token": { "type": "integer" },
                "unused_client_expiry_seconds": { "type": "integer" }
            }
        })
    }

    /// Reads a stored policy document.
    ///
    /// An absent or `null` document is a tenant that has never expressed an
    /// opinion, which is [`RegistrationPolicy::default`] — every list `None`,
    /// and the mode `Closed`, because a tenant row written before this existed
    /// cannot have consented to an open registration endpoint.
    ///
    /// The document is checked against [`RegistrationPolicy::schema_document`]
    /// first, so the reads below are about *meaning* — an unknown grant type, a
    /// negative quota — rather than about shape.
    ///
    /// # Errors
    ///
    /// [`RegistrationPolicyError`] for a document this server did not write or
    /// would not have accepted.
    // fuzz-target: registration_policy
    pub fn from_json(value: Option<&Value>) -> Result<Self, RegistrationPolicyError> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        if value.is_null() {
            return Ok(Self::default());
        }

        let schema = Schema::parse(&Self::schema_document())
            .map_err(|_| RegistrationPolicyError::SchemaUnusable)?;
        if !schema.accepts(value) {
            return Err(RegistrationPolicyError::SchemaRejected);
        }
        // `accepts` has just established this.
        let object = value
            .as_object()
            .ok_or(RegistrationPolicyError::SchemaRejected)?;

        let mut policy = match object.get("profile").and_then(Value::as_str) {
            None => Self::default(),
            Some(name) => Self::profile(name)
                .ok_or_else(|| RegistrationPolicyError::UnknownProfile(name.to_owned()))?,
        };

        if let Some(mode) = object.get("mode").and_then(Value::as_str) {
            policy.mode = Some(
                RegistrationMode::parse(mode)
                    .ok_or_else(|| RegistrationPolicyError::UnknownMode(mode.to_owned()))?,
            );
        }

        if let Some(values) = strings(object.get("token_endpoint_auth_methods"))? {
            let mut methods = BTreeSet::new();
            for name in values {
                methods.insert(
                    TokenEndpointAuthMethod::parse(&name)
                        .ok_or(RegistrationPolicyError::UnknownAuthMethod)?,
                );
            }
            policy.auth_methods = Some(methods);
        }
        if let Some(values) = strings(object.get("grant_types"))? {
            let mut grants = BTreeSet::new();
            for name in values {
                grants.insert(
                    GrantType::parse(&name).ok_or(RegistrationPolicyError::UnknownGrantType)?,
                );
            }
            policy.grant_types = Some(grants);
        }
        if let Some(values) = strings(object.get("scopes"))? {
            policy.scopes = Some(values.into_iter().collect());
        }
        if let Some(values) = strings(object.get("resources"))? {
            policy.resources = Some(values.into_iter().collect());
        }
        if let Some(values) = strings(object.get("redirect_uri_hosts"))? {
            policy.redirect_uri_hosts = Some(values.into_iter().collect());
        }
        if let Some(kind) = object.get("jwks").and_then(Value::as_str) {
            policy.jwks = JwksRequirement::parse(kind)
                .ok_or(RegistrationPolicyError::UnknownJwksRequirement)?;
        }

        if let Some(rule) = object.get("software_statement") {
            policy.software_statement = software_statement_rule(rule)?;
        }

        if let Some(max) = object.get("max_clients_per_initial_access_token") {
            let max = max
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(RegistrationPolicyError::NotAPositiveCount(
                    "max_clients_per_initial_access_token",
                ))?;
            policy.max_clients_per_initial_access_token = Some(max);
        }
        if let Some(seconds) = object.get("unused_client_expiry_seconds") {
            let seconds = seconds.as_i64().filter(|value| *value > 0).ok_or(
                RegistrationPolicyError::NotAPositiveCount("unused_client_expiry_seconds"),
            )?;
            policy.unused_client_expiry = Some(Duration::seconds(seconds));
        }

        // A tenant that requires a statement and trusts nobody to sign one has
        // written a policy under which no registration can ever succeed.
        // Refused here rather than at the first registration, because this is
        // the moment an administrator is watching.
        if policy.software_statement.required && policy.software_statement.issuers.is_empty() {
            return Err(RegistrationPolicyError::NoTrustedIssuer);
        }

        Ok(policy)
    }

    /// The policy as it is stored on the tenant row.
    ///
    /// Written out in full rather than as a diff against a preset, for the
    /// reason [`crate::TenantSettings::to_json`] gives: changing a preset in
    /// this file must never silently change what an existing tenant does. A
    /// document that came in naming `"profile": "agent"` therefore comes back
    /// out as the rules that profile meant on the day it was saved.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut document = serde_json::json!({
            "jwks": self.jwks.as_str(),
            "software_statement": {
                "required": self.software_statement.required,
                "issuers": self
                    .software_statement
                    .issuers
                    .iter()
                    .map(|issuer| serde_json::json!({
                        "issuer": issuer.issuer,
                        "jwks_uri": issuer.jwks_uri,
                    }))
                    .collect::<Vec<_>>(),
            },
        });
        let object = document
            .as_object_mut()
            .expect("the document above is a JSON object");
        if let Some(mode) = self.mode {
            object.insert("mode".to_owned(), Value::from(mode.as_str()));
        }
        if let Some(methods) = &self.auth_methods {
            object.insert(
                "token_endpoint_auth_methods".to_owned(),
                methods.iter().map(|m| m.as_str()).collect(),
            );
        }
        if let Some(grants) = &self.grant_types {
            object.insert(
                "grant_types".to_owned(),
                grants.iter().map(|g| g.as_str()).collect(),
            );
        }
        if let Some(scopes) = &self.scopes {
            object.insert(
                "scopes".to_owned(),
                scopes.iter().map(String::as_str).collect(),
            );
        }
        if let Some(resources) = &self.resources {
            object.insert(
                "resources".to_owned(),
                resources.iter().map(String::as_str).collect(),
            );
        }
        if let Some(hosts) = &self.redirect_uri_hosts {
            object.insert(
                "redirect_uri_hosts".to_owned(),
                hosts.iter().map(String::as_str).collect(),
            );
        }
        if let Some(max) = self.max_clients_per_initial_access_token {
            object.insert(
                "max_clients_per_initial_access_token".to_owned(),
                Value::from(max),
            );
        }
        if let Some(expiry) = self.unused_client_expiry {
            object.insert(
                "unused_client_expiry_seconds".to_owned(),
                Value::from(expiry.whole_seconds()),
            );
        }
        document
    }
}

/// How many clients one initial access token may register under the `agent`
/// profile.
///
/// A fleet, not a deployment: an operator onboarding more than this has a
/// provisioning system and can issue a second token, and the cap is what turns
/// a leaked token from "unbounded clients" into "twenty five rows and an audit
/// trail full of them".
pub const DEFAULT_AGENT_CLIENT_QUOTA: u32 = 25;

/// How long an agent client may go unused before it expires, under the `agent`
/// profile: thirty days.
///
/// Agents are provisioned in bulk and abandoned in bulk. A client that has
/// never authenticated in a month is one nobody will miss, and every one that
/// stays is a live credential with a key attached.
pub const DEFAULT_AGENT_UNUSED_EXPIRY: Duration = Duration::days(30);

/// Reads an optional array of strings.
fn strings(value: Option<&Value>) -> Result<Option<Vec<String>>, RegistrationPolicyError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(entries)) => {
            let mut out = Vec::with_capacity(entries.len());
            for entry in entries {
                let text = entry
                    .as_str()
                    .ok_or(RegistrationPolicyError::SchemaRejected)?;
                out.push(text.to_owned());
            }
            Ok(Some(out))
        }
        Some(_) => Err(RegistrationPolicyError::SchemaRejected),
    }
}

/// Reads the `software_statement` member, whose shape the schema has checked.
fn software_statement_rule(
    value: &Value,
) -> Result<SoftwareStatementRule, RegistrationPolicyError> {
    let object = value
        .as_object()
        .ok_or(RegistrationPolicyError::SchemaRejected)?;
    let required = match object.get("required") {
        None | Some(Value::Null) => false,
        Some(flag) => flag
            .as_bool()
            .ok_or(RegistrationPolicyError::SchemaRejected)?,
    };
    let mut issuers = Vec::new();
    if let Some(Value::Array(entries)) = object.get("issuers") {
        for entry in entries {
            let entry = entry
                .as_object()
                .ok_or(RegistrationPolicyError::SchemaRejected)?;
            let issuer = entry
                .get("issuer")
                .and_then(Value::as_str)
                .ok_or(RegistrationPolicyError::SchemaRejected)?;
            let jwks_uri = entry
                .get("jwks_uri")
                .and_then(Value::as_str)
                .ok_or(RegistrationPolicyError::SchemaRejected)?;
            // Both are URLs this server will either compare against a JWT's
            // `iss` or hand to the outbound adapter. `https` is required of
            // both for the reason ADR-0006 gives: the adapter refuses anything
            // else anyway, and an operator should find that out here.
            if !issuer.starts_with("https://") || !jwks_uri.starts_with("https://") {
                return Err(RegistrationPolicyError::IssuerNotHttps);
            }
            issuers.push(SoftwareStatementIssuer {
                issuer: issuer.to_owned(),
                jwks_uri: jwks_uri.to_owned(),
            });
        }
    }
    Ok(SoftwareStatementRule { required, issuers })
}

/// Why a stored policy document was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrationPolicyError {
    /// The document does not match the policy schema.
    #[error("the registration policy does not match the policy schema")]
    SchemaRejected,
    /// The policy schema itself does not parse — a bug in this file, asserted
    /// against by a test, and never a consequence of anything a tenant wrote.
    #[error("the registration policy schema is not a schema this server can use")]
    SchemaUnusable,
    /// A preset this build does not ship.
    #[error("unknown registration profile: {0}")]
    UnknownProfile(String),
    /// A registration mode this build does not know.
    #[error("unknown registration mode: {0}")]
    UnknownMode(String),
    /// A `token_endpoint_auth_methods` entry outside the profile's allow-list.
    #[error(
        "the registration policy allows a client authentication method this profile does not \
         (FAPI 2.0 SP §5.3.2.1 items 3 and 6)"
    )]
    UnknownAuthMethod,
    /// A `grant_types` entry this server does not implement.
    #[error("the registration policy allows a grant type this server does not implement")]
    UnknownGrantType,
    /// A `jwks` value that is not `any`, `inline` or `uri`.
    #[error("the registration policy names a key publication rule this server does not know")]
    UnknownJwksRequirement,
    /// A count that is not a positive whole number.
    #[error("`{0}` must be a positive whole number")]
    NotAPositiveCount(&'static str),
    /// A software statement issuer whose URLs are not https.
    #[error("a software statement issuer and its jwks_uri must both be https URLs")]
    IssuerNotHttps,
    /// A policy that requires a software statement and trusts no issuer.
    #[error(
        "the registration policy requires a software statement but names no trusted issuer, \
         so no registration could ever succeed"
    )]
    NoTrustedIssuer,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::client::{ApplicationType, RedirectUri, SubjectType, TokenBinding};
    use crate::keys::SigningAlgorithm;

    /// A registration that every default policy admits, which each test then
    /// spoils in exactly one way.
    fn registration() -> ClientRegistration {
        ClientRegistration {
            client_name: "test".to_owned(),
            application_type: ApplicationType::Web,
            token_endpoint_auth_method: TokenEndpointAuthMethod::PrivateKeyJwt,
            tls_client_auth_subject: None,
            redirect_uris: vec![
                RedirectUri::parse("https://app.example.com/cb", ApplicationType::Web)
                    .expect("a valid https callback"),
            ],
            post_logout_redirect_uris: Vec::new(),
            grant_types: BTreeSet::from([GrantType::AuthorizationCode]),
            scopes: BTreeSet::from(["openid".to_owned()]),
            resources: BTreeSet::new(),
            jwks: JwksSource::Uri("https://app.example.com/jwks".to_owned()),
            id_token_signed_response_alg: SigningAlgorithm::Es256,
            request_object_signing_alg: None,
            backchannel_authentication_request_signing_alg: None,
            subject_type: SubjectType::Public,
            sector_identifier_uri: None,
            token_binding: TokenBinding::Dpop,
            authorization_details_types: BTreeSet::new(),
            use_mtls_endpoint_aliases: false,
            userinfo_signed_response_alg: None,
        }
    }

    fn policy(document: &serde_json::Value) -> RegistrationPolicy {
        RegistrationPolicy::from_json(Some(document)).expect("the document is a valid policy")
    }

    /// The schema this module validates against has to be one the shipped
    /// validator can read — otherwise every policy is refused for a reason no
    /// tenant caused.
    #[test]
    fn the_policy_schema_parses() {
        // Arrange
        let document = RegistrationPolicy::schema_document();

        // Act
        let outcome = Schema::parse(&document);

        // Assert
        assert!(outcome.is_ok(), "{outcome:?}");
    }

    /// The acceptance criterion: the policy is data validated against a schema,
    /// so a member nobody defined is refused rather than ignored.
    #[test]
    fn an_unknown_member_is_refused() {
        // Arrange
        let document = serde_json::json!({ "allow_everything": true });

        // Act
        let outcome = RegistrationPolicy::from_json(Some(&document));

        // Assert
        assert_eq!(outcome, Err(RegistrationPolicyError::SchemaRejected));
    }

    #[test]
    fn an_absent_document_is_the_default_policy() {
        assert_eq!(
            RegistrationPolicy::from_json(None),
            Ok(RegistrationPolicy::default())
        );
    }

    /// A tenant row written before this feature existed named no mode, and must
    /// keep serving whatever the deployment configured.
    #[test]
    fn a_tenant_with_no_policy_takes_the_deployments_mode() {
        // Arrange
        let policy = RegistrationPolicy::default();

        // Act
        let effective = policy.effective_mode(RegistrationMode::Open);

        // Assert
        assert_eq!(effective, RegistrationMode::Open);
    }

    /// The `ast-0qv` criterion: a tenant closes its own endpoint whatever the
    /// deployment does.
    #[test]
    fn a_tenant_that_says_closed_closes_its_endpoint() {
        // Arrange
        let policy = policy(&serde_json::json!({ "mode": "closed" }));

        // Act
        let effective = policy.effective_mode(RegistrationMode::Open);

        // Assert
        assert_eq!(effective, RegistrationMode::Closed);
        assert!(!effective.is_open_at_all());
    }

    /// And cannot open one the operator gated.
    #[test]
    fn a_tenant_that_says_open_cannot_widen_a_gated_deployment() {
        // Arrange
        let policy = policy(&serde_json::json!({ "mode": "open" }));

        // Act
        let effective = policy.effective_mode(RegistrationMode::InitialAccessToken);

        // Assert
        assert_eq!(effective, RegistrationMode::InitialAccessToken);
    }

    #[test]
    fn a_default_policy_admits_an_ordinary_registration() {
        assert_eq!(
            RegistrationPolicy::default().evaluate(&registration()),
            Ok(())
        );
    }

    #[test]
    fn an_auth_method_outside_the_list_is_refused() {
        // Arrange
        let policy = policy(&serde_json::json!({
            "token_endpoint_auth_methods": ["tls_client_auth"]
        }));

        // Act
        let outcome = policy.evaluate(&registration());

        // Assert
        assert_eq!(
            outcome,
            Err(PolicyViolation::new(RuleId::AuthMethod)),
            "private_key_jwt is not on the list"
        );
    }

    #[test]
    fn a_grant_type_outside_the_list_is_refused() {
        // Arrange
        let policy = policy(&serde_json::json!({ "grant_types": ["client_credentials"] }));

        // Act
        let outcome = policy.evaluate(&registration());

        // Assert
        assert_eq!(outcome, Err(PolicyViolation::new(RuleId::GrantType)));
    }

    #[test]
    fn a_scope_outside_the_list_is_refused() {
        // Arrange
        let policy = policy(&serde_json::json!({ "scopes": ["profile"] }));

        // Act
        let outcome = policy.evaluate(&registration());

        // Assert
        assert_eq!(outcome, Err(PolicyViolation::new(RuleId::Scope)));
    }

    #[test]
    fn a_resource_outside_the_list_is_refused() {
        // Arrange
        let policy = policy(&serde_json::json!({ "resources": ["https://api.example.com"] }));
        let mut registration = registration();
        registration
            .resources
            .insert("https://other.example.com".to_owned());

        // Act
        let outcome = policy.evaluate(&registration);

        // Assert
        assert_eq!(outcome, Err(PolicyViolation::new(RuleId::Resource)));
    }

    #[test]
    fn a_redirect_host_outside_the_list_is_refused() {
        // Arrange
        let policy = policy(&serde_json::json!({ "redirect_uri_hosts": ["trusted.example.com"] }));

        // Act
        let outcome = policy.evaluate(&registration());

        // Assert
        assert_eq!(outcome, Err(PolicyViolation::new(RuleId::RedirectHost)));
    }

    #[test]
    fn a_redirect_host_on_the_list_is_admitted() {
        // Arrange
        let policy = policy(&serde_json::json!({ "redirect_uri_hosts": ["app.example.com"] }));

        // Act
        let outcome = policy.evaluate(&registration());

        // Assert
        assert_eq!(outcome, Ok(()));
    }

    /// An empty allow-list is a closed list, not an absent one: the difference
    /// between "this tenant registers no callbacks" and "this tenant has no
    /// opinion" is the difference between a rule and an open door.
    #[test]
    fn an_empty_host_list_admits_no_callback() {
        // Arrange
        let policy = policy(&serde_json::json!({ "redirect_uri_hosts": [] }));

        // Act
        let outcome = policy.evaluate(&registration());

        // Assert
        assert_eq!(outcome, Err(PolicyViolation::new(RuleId::RedirectHost)));
    }

    #[test]
    fn a_tenant_that_demands_inline_keys_refuses_a_jwks_uri() {
        // Arrange
        let policy = policy(&serde_json::json!({ "jwks": "inline" }));

        // Act
        let outcome = policy.evaluate(&registration());

        // Assert
        assert_eq!(outcome, Err(PolicyViolation::new(RuleId::JwksSource)));
    }

    #[test]
    fn a_tenant_that_demands_a_jwks_uri_refuses_inline_keys() {
        // Arrange
        let policy = policy(&serde_json::json!({ "jwks": "uri" }));
        let mut registration = registration();
        registration.jwks = JwksSource::Inline(serde_json::json!({ "keys": [] }));

        // Act
        let outcome = policy.evaluate(&registration);

        // Assert
        assert_eq!(outcome, Err(PolicyViolation::new(RuleId::JwksSource)));
    }

    /// The refusal reaches the wire as RFC 7591 §3.2.2's
    /// `invalid_client_metadata`, with a description that names the field and
    /// no value from the document.
    #[test]
    fn a_violation_becomes_invalid_client_metadata() {
        // Arrange
        let violation = PolicyViolation::new(RuleId::RedirectHost);

        // Act
        let error = violation.to_metadata_error();

        // Assert
        assert_eq!(error.code(), "invalid_client_metadata");
        assert_eq!(error.field(), "redirect_uris");
    }

    /// The rule id is what the audit trail carries, so every rule needs one and
    /// no two may share it.
    #[test]
    fn every_rule_has_its_own_identifier() {
        // Arrange
        let ids: BTreeSet<&str> = RuleId::ALL.iter().map(|rule| rule.as_str()).collect();

        // Assert
        assert_eq!(ids.len(), RuleId::ALL.len());
    }

    #[test]
    fn a_tenant_cannot_widen_the_deployments_mode() {
        // Arrange
        let deployment = RegistrationMode::InitialAccessToken;

        // Act
        let effective = RegistrationMode::Open.narrowest(deployment);

        // Assert
        assert_eq!(effective, RegistrationMode::InitialAccessToken);
    }

    #[test]
    fn a_tenant_can_close_what_the_deployment_opened() {
        assert_eq!(
            RegistrationMode::Closed.narrowest(RegistrationMode::Open),
            RegistrationMode::Closed
        );
    }

    /// RFC 7591 §2.3 makes a software statement a signed assertion whose values
    /// override the request's, so requiring one without naming who may sign it
    /// is a policy under which nothing can register.
    #[test]
    fn requiring_a_statement_without_an_issuer_is_refused() {
        // Arrange
        let document = serde_json::json!({ "software_statement": { "required": true } });

        // Act
        let outcome = RegistrationPolicy::from_json(Some(&document));

        // Assert
        assert_eq!(outcome, Err(RegistrationPolicyError::NoTrustedIssuer));
    }

    #[test]
    fn a_missing_statement_is_refused_when_one_is_required() {
        // Arrange
        let policy = policy(&serde_json::json!({
            "software_statement": {
                "required": true,
                "issuers": [{
                    "issuer": "https://vouch.example.com",
                    "jwks_uri": "https://vouch.example.com/jwks"
                }]
            }
        }));

        // Act
        let outcome = policy.check_software_statement_present(false);

        // Assert
        assert_eq!(
            outcome,
            Err(PolicyViolation::new(RuleId::SoftwareStatementRequired))
        );
    }

    #[test]
    fn an_issuer_that_is_not_https_is_refused() {
        // Arrange
        let document = serde_json::json!({
            "software_statement": {
                "issuers": [{ "issuer": "http://vouch.example.com", "jwks_uri": "https://x.example.com/jwks" }]
            }
        });

        // Act
        let outcome = RegistrationPolicy::from_json(Some(&document));

        // Assert
        assert_eq!(outcome, Err(RegistrationPolicyError::IssuerNotHttps));
    }

    #[test]
    fn the_quota_refuses_the_client_after_the_last_one() {
        // Arrange
        let policy = policy(&serde_json::json!({ "max_clients_per_initial_access_token": 2 }));

        // Act & Assert
        assert_eq!(policy.check_client_quota(1), Ok(()));
        assert_eq!(
            policy.check_client_quota(2),
            Err(PolicyViolation::new(RuleId::ClientQuota))
        );
    }

    #[test]
    fn no_quota_admits_any_count() {
        assert_eq!(
            RegistrationPolicy::default().check_client_quota(u64::MAX),
            Ok(())
        );
    }

    /// The `agent` preset (`E11_01`): a key, `client_credentials`, no callback,
    /// a vouching issuer and an expiry.
    #[test]
    fn the_agent_profile_allows_only_client_credentials() {
        // Arrange
        let policy = RegistrationPolicy::agent_profile();

        // Act
        let outcome = policy.evaluate(&registration());

        // Assert
        assert_eq!(
            outcome,
            Err(PolicyViolation::new(RuleId::GrantType)),
            "an authorization_code client is not an agent"
        );
    }

    #[test]
    fn the_agent_profile_requires_a_software_statement() {
        assert!(
            RegistrationPolicy::agent_profile()
                .software_statement()
                .is_required()
        );
    }

    #[test]
    fn the_agent_profile_expires_unused_clients() {
        assert_eq!(
            RegistrationPolicy::agent_profile().unused_client_expiry(),
            Some(DEFAULT_AGENT_UNUSED_EXPIRY)
        );
    }

    /// Selecting a profile and then naming the issuers it demands is the
    /// intended way to use it, and has to produce a policy that stores.
    #[test]
    fn the_agent_profile_stores_once_an_issuer_is_named() {
        // Arrange
        let document = serde_json::json!({
            "profile": "agent",
            "software_statement": {
                "required": true,
                "issuers": [{
                    "issuer": "https://vouch.example.com",
                    "jwks_uri": "https://vouch.example.com/jwks"
                }]
            }
        });

        // Act
        let policy = RegistrationPolicy::from_json(Some(&document))
            .expect("the agent profile with an issuer is a valid policy");

        // Assert
        assert_eq!(
            policy.grant_types,
            Some(BTreeSet::from([GrantType::ClientCredentials]))
        );
        assert_eq!(policy.mode(), Some(RegistrationMode::InitialAccessToken));
    }

    /// A stored policy is written out in full, so a preset that changes in this
    /// file never changes what an existing tenant does.
    #[test]
    fn a_policy_round_trips_through_its_stored_form() {
        // Arrange
        let document = serde_json::json!({
            "profile": "agent",
            "mode": "open",
            "scopes": ["agent:read"],
            "software_statement": {
                "required": true,
                "issuers": [{
                    "issuer": "https://vouch.example.com",
                    "jwks_uri": "https://vouch.example.com/jwks"
                }]
            }
        });
        let policy = RegistrationPolicy::from_json(Some(&document)).expect("a valid policy");

        // Act
        let reread = RegistrationPolicy::from_json(Some(&policy.to_json()))
            .expect("what this server wrote, this server reads");

        // Assert
        assert_eq!(reread, policy);
    }

    #[test]
    fn an_unknown_grant_type_in_a_policy_is_refused() {
        // Arrange
        let document = serde_json::json!({ "grant_types": ["password"] });

        // Act
        let outcome = RegistrationPolicy::from_json(Some(&document));

        // Assert
        assert_eq!(outcome, Err(RegistrationPolicyError::UnknownGrantType));
    }

    #[test]
    fn a_client_secret_auth_method_in_a_policy_is_refused() {
        // Arrange
        let document =
            serde_json::json!({ "token_endpoint_auth_methods": ["client_secret_basic"] });

        // Act
        let outcome = RegistrationPolicy::from_json(Some(&document));

        // Assert
        assert_eq!(outcome, Err(RegistrationPolicyError::UnknownAuthMethod));
    }

    #[test]
    fn a_negative_expiry_is_refused() {
        // Arrange
        let document = serde_json::json!({ "unused_client_expiry_seconds": -1 });

        // Act
        let outcome = RegistrationPolicy::from_json(Some(&document));

        // Assert
        assert_eq!(
            outcome,
            Err(RegistrationPolicyError::NotAPositiveCount(
                "unused_client_expiry_seconds"
            ))
        );
    }
}
