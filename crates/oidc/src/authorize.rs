//! The authorization request: what a client may ask for, and what it may not.
//!
//! Every authorization request in this server arrives at exactly one place —
//! the pushed authorization request endpoint (RFC 9126), because ADR-0002
//! makes PAR the only way to start a flow. So this is the single validator,
//! run once, at push time, against a request that has already been
//! authenticated. Nothing later re-parses it: `/authorize` looks up what was
//! stored here.
//!
//! That is the design decision worth stating. RFC 9126 §2.1 lets the AS
//! validate at push time; FAPI 2.0 SP §5.3.2.2 items 2–4 make PAR mandatory
//! and require client authentication on it. Together they mean an
//! authorization request is checked **while an authenticated client is on the
//! other end of the connection**, so a rejection can be an honest error
//! response rather than a redirect — the AS never has to decide whether it is
//! safe to bounce an error back to a URI it has not validated.
//!
//! # Why parameters are rejected rather than ignored
//!
//! An unknown or malformed parameter is refused, not dropped. A client that
//! sends `response_type=code%20id_token` and gets a plain `code` flow has been
//! given something it did not ask for, and its security analysis is now wrong.
//! The same goes for a `request` object this server cannot process: silently
//! ignoring it means honouring the *query* parameters an attacker could see
//! and modify, which is exactly what JAR exists to prevent.

use asterius_domain::entities::client::{ClientRegistration, RedirectUri};
use asterius_domain::{
    AuthorizationDetails, InvalidAuthorizationDetails, InvalidTarget, ResourceIdentifier,
};
use std::collections::BTreeSet;

use crate::claims::{ClaimsLocales, ClaimsRequest, ClaimsRequestError};
use crate::form::{Duplicated, Parameters};
use crate::grant_management::{
    GrantManagement, GrantManagementError, Policy as GrantManagementPolicy,
};
use crate::pkce::{CodeChallenge, PkceError};

/// The only `response_type` this server implements.
///
/// ADR-0002: no implicit flow, no hybrid flow. FAPI 2.0 SP §5.3.2.2 item 1
/// requires the value to be `code`, and since nothing else is offered there is
/// no negotiation to get wrong.
pub const RESPONSE_TYPE: &str = "code";

/// The longest `state` this server will accept.
///
/// `state` is opaque and echoed back, so its only cost is storage — but it is
/// storage an unauthenticated-at-the-time party chose the size of, and it is
/// held until the request expires. Generous enough for a signed value, small
/// enough that a million pushes is not a problem.
pub const MAX_STATE_LEN: usize = 512;

/// The longest `nonce` this server will accept.
///
/// FAPI 2.0 SP §5.3.2.2 item 14 requires supporting values *up to 64
/// characters*, which is a floor on what must be accepted, not a ceiling on
/// what may be. This is the ceiling, comfortably above the requirement.
pub const MAX_NONCE_LEN: usize = 256;

/// The longest `login_hint` this server will accept.
///
/// It names a login identifier — an address, a phone number, an account name —
/// and it is shown to a person. 128 bytes is longer than any address in use
/// and short enough that the value cannot become a message.
pub const MAX_LOGIN_HINT_LEN: usize = 128;

/// The longest `id_token_hint` this server will accept.
///
/// The same bound RP-Initiated Logout's hint carries
/// ([`crate::logout::MAX_ID_TOKEN_HINT_BYTES`]), and the same reason: it is a
/// signed token this server issued, so its size is one this server chose,
/// with room for a key set that grew.
pub const MAX_ID_TOKEN_HINT_LEN: usize = crate::logout::MAX_ID_TOKEN_HINT_BYTES;

/// The most `resource` indicators one request may name (RFC 8707).
pub const MAX_RESOURCES: usize = 8;

/// The most `acr_values` a request may name.
///
/// `acr_values` is a preference list, and a preference list a person could not
/// hold in their head is not a preference — it is a way of making this server
/// walk a policy ladder once per entry. Sixteen is more rungs than any tenant
/// this server has met, so the bound refuses nothing a real client sends.
pub const MAX_ACR_VALUES: usize = 16;

/// The most scope tokens one request may name.
pub const MAX_SCOPES: usize = 64;

/// Why an authorization request was refused.
///
/// The variants map to the OAuth error codes of RFC 6749 §4.1.2.1 and OIDC
/// Core §3.1.2.6 through [`AuthorizationError::code`]. They are finer-grained
/// than the codes because an operator reading a log needs to know *which*
/// parameter, and the client only ever sees the code and a description that
/// does not quote its input back.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthorizationError {
    /// A parameter appeared more than once.
    ///
    /// RFC 6749 §3.1: request parameters "MUST NOT be included more than
    /// once". A server that takes the first, or the last, is a server whose
    /// choice an attacker can rely on — and two intermediaries that choose
    /// differently is how a request gets validated as one thing and executed
    /// as another.
    #[error("parameter {0} appeared more than once")]
    DuplicateParameter(String),
    /// A required parameter is absent.
    #[error("missing required parameter {0}")]
    Missing(&'static str),
    /// A parameter is present but unusable.
    #[error("parameter {0} is not valid")]
    Invalid(&'static str),
    /// `response_type` is not `code`.
    #[error("unsupported response_type")]
    UnsupportedResponseType,
    /// `response_mode` is not one this server implements.
    ///
    /// `invalid_request` rather than a mode-specific code: OAuth 2.0 Multiple
    /// Response Type Encoding Practices registers no error for it, and §2.1
    /// leaves an unsupported mode as a malformed request. Refused *here*, at
    /// the push, so the client learns it over an authenticated connection
    /// instead of a browser being sent somewhere it cannot be answered.
    #[error("response_mode: {0}")]
    ResponseMode(#[from] UnsupportedResponseMode),
    /// `redirect_uri` is not one this client registered.
    #[error("redirect_uri is not registered for this client")]
    UnregisteredRedirectUri,
    /// A requested scope is not one this client registered.
    #[error("scope is not permitted for this client")]
    ScopeNotPermitted,
    /// PKCE was missing or wrong (RFC 7636, FAPI 2.0 SP §5.3.2.2 item 5).
    #[error("PKCE: {0}")]
    Pkce(#[from] PkceError),
    /// The `claims` parameter is malformed or oversized (OIDC Core §5.5).
    ///
    /// Only its *shape* is refused here. A member naming a claim this server
    /// will not release is ignored rather than rejected, which is what §5.5
    /// asks for — see [`ClaimsRequest::parse`].
    #[error("claims: {0}")]
    Claims(#[from] ClaimsRequestError),
    /// A `request` parameter reached a tenant that does not accept one.
    ///
    /// Not "this server cannot do JAR": it can, behind
    /// [`Feature::RequestObject`](asterius_domain::Feature::RequestObject),
    /// and a tenant with the flag on never gets here because the object has
    /// already become the parameters being validated.
    #[error("request objects are not supported")]
    RequestObjectNotSupported,
    /// `request_uri` in a *pushed* request (RFC 9126 §2.1).
    #[error("request_uri must not be present in a pushed authorization request")]
    RequestUriNotAllowed,
    /// `prompt=none` alongside another value.
    #[error("prompt=none cannot be combined with other values")]
    ConflictingPrompt,
    /// A `prompt` value this tenant does not offer.
    ///
    /// Today that is `create` and only `create` (OpenID Connect Prompt Create
    /// 1.0 §3): the four values of OIDC Core §3.1.2.1 are answered by every
    /// tenant. Kept apart from [`Self::Invalid`] because the two say different
    /// things to a client — one spelled a value wrong, the other asked for
    /// something this deployment does not do — and because the second is
    /// exactly what `prompt_values_supported` already told it.
    #[error("prompt value is not supported by this tenant")]
    UnsupportedPrompt,
    /// The `client_id` parameter is not the authenticated client.
    #[error("client_id does not match the authenticated client")]
    ClientMismatch,
    /// A `resource` value this server will not honour (RFC 8707 §2.2).
    ///
    /// Its own variant rather than [`Self::Invalid`] because RFC 8707 §2
    /// registers its own error code for it: a client that sent a resource
    /// indicator this deployment does not serve has made a different mistake
    /// from one that misspelled a parameter, and `invalid_target` is what tells
    /// it so — a client library reading `invalid_request` would go looking for
    /// a typo in a value that is spelled correctly.
    #[error("resource: {0}")]
    InvalidTarget(#[from] asterius_domain::InvalidTarget),
    /// An `authorization_details` this server will not honour (RFC 9396 §5).
    ///
    /// Its own variant rather than [`Self::Invalid`], for the same reason
    /// [`Self::InvalidTarget`] is: RFC 9396 §5 registers its own error code,
    /// and a client told `invalid_request` would go looking for a typo in a
    /// parameter that is spelled correctly and simply asks for something it may
    /// not have.
    #[error("authorization_details: {0}")]
    InvalidAuthorizationDetails(#[from] asterius_domain::InvalidAuthorizationDetails),
    /// `grant_id` or `grant_management_action` was refused (Grant Management
    /// ID1 §5.4, §7.1).
    ///
    /// Its own variant rather than [`Self::Invalid`] because the draft
    /// registers `invalid_grant_id` for one of its cases, and because the
    /// vocabulary is still moving: keeping the clauses in
    /// [`crate::grant_management`] means a change to the draft does not
    /// reach into this enum.
    #[error("grant management: {0}")]
    GrantManagement(#[from] GrantManagementError),
}

impl From<Duplicated> for AuthorizationError {
    fn from(error: Duplicated) -> Self {
        Self::DuplicateParameter(error.0)
    }
}

impl AuthorizationError {
    /// The OAuth 2.0 error code (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::ScopeNotPermitted => "invalid_scope",
            // OIDC Core §3.1.2.6 defines this for an AS that does not support
            // the `request` parameter. Saying so is better than
            // `invalid_request`, which would send a client looking for a typo.
            Self::RequestObjectNotSupported => "request_not_supported",
            Self::ClientMismatch => "invalid_client",
            // RFC 8707 §2: "invalid_target" is the code for a resource
            // indicator the authorization server will not honour, at the
            // authorization endpoint as at the token endpoint.
            Self::InvalidTarget(_) => asterius_domain::InvalidTarget::CODE,
            // RFC 9396 §5: "invalid_authorization_details" is the code for an
            // `authorization_details` the authorization server will not
            // honour, at the authorization endpoint as at the token endpoint.
            Self::InvalidAuthorizationDetails(_) => {
                asterius_domain::InvalidAuthorizationDetails::CODE
            }
            // Grant Management ID1 §5.4 registers `invalid_grant_id` and names
            // `invalid_request` for the rest; the module that owns the clauses
            // decides which, so the code and the clause cannot drift apart.
            Self::GrantManagement(failure) => failure.code(),
            _ => "invalid_request",
        }
    }
}

/// How `prompt` was spelled (OIDC Core §3.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Prompt {
    /// Do not display any interactive UI.
    None,
    /// Reauthenticate, whatever the session says.
    Login,
    /// Ask for consent again.
    Consent,
    /// Let the user pick an account.
    SelectAccount,
    /// Start at account creation rather than at sign-in.
    ///
    /// OpenID Connect Prompt Create 1.0 §3. Not one of OIDC Core's four
    /// values, and only accepted when the tenant offers self-service
    /// registration — see [`AuthorizationPolicy::prompt_create`].
    Create,
}

impl Prompt {
    /// Every value this server can parse, in the order the enum declares them.
    pub const ALL: [Self; 5] = [
        Self::None,
        Self::Login,
        Self::Consent,
        Self::SelectAccount,
        Self::Create,
    ];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Login => "login",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
            Self::Create => "create",
        }
    }

    /// Parses one `prompt` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == value)
    }

    /// Parses the whole `prompt` parameter (OIDC Core §3.1.2.1).
    ///
    /// The parameter is a space-delimited list, and the specification adds one
    /// combination rule: `none` "MUST NOT be present with any other value".
    /// `none` means *do not interact* and every other value means *interact*,
    /// so a request carrying both asks for two mutually exclusive responses;
    /// guessing which the client meant would be answering a request nobody
    /// made. Refused at the push, where an authenticated client is on the
    /// connection to read the reason — a browser sent to the redirect URI with
    /// `invalid_request` would be a worse way to say the same thing.
    ///
    /// `create` is accepted only when `policy` says the tenant offers
    /// registration. Prompt Create §4 leaves the handling of an unsupported
    /// value to the OP; this server refuses it as `invalid_request` rather
    /// than ignoring it, because a client that asked to enrol a *new* user and
    /// got a sign-in page for an existing one has been answered with something
    /// it did not ask for. The same tenant that refuses it omits `create` from
    /// `prompt_values_supported`, so a client reading the discovery document
    /// never sends it.
    ///
    /// # Errors
    ///
    /// [`AuthorizationError::Invalid`] for an unknown value,
    /// [`AuthorizationError::UnsupportedPrompt`] for one this tenant does not
    /// offer, and [`AuthorizationError::ConflictingPrompt`] for `none`
    /// alongside anything else.
    // fuzz-target: authorization_hints
    pub fn parse_list(
        raw: Option<&str>,
        policy: AuthorizationPolicy,
    ) -> Result<BTreeSet<Self>, AuthorizationError> {
        let mut prompts = BTreeSet::new();
        for token in raw.unwrap_or_default().split_whitespace() {
            let prompt = Self::parse(token).ok_or(AuthorizationError::Invalid("prompt"))?;
            if !policy.offers(prompt) {
                return Err(AuthorizationError::UnsupportedPrompt);
            }
            prompts.insert(prompt);
        }
        // "none" means "do not interact"; combined with "login" it means both
        // do and do not interact. There is no reading of that which is safe to
        // guess.
        if prompts.contains(&Self::None) && prompts.len() > 1 {
            return Err(AuthorizationError::ConflictingPrompt);
        }
        Ok(prompts)
    }
}

/// The tenant-shaped decisions an authorization request is validated against.
///
/// Everything here is a property of the *deployment*, not of the request and
/// not of the client, and every field is the conservative answer by default: a
/// tenant that has configured nothing offers no registration, and so refuses
/// `prompt=create`. Passed in rather than read from a global, so that
/// [`validate`] stays a pure function of its inputs and so that the one place
/// a tenant's answer is decided is the caller that already knows the tenant.
///
/// # The extension point `ast-2vk.7` will use
///
/// ACR is deliberately absent. Which `acr` values a tenant can produce, and
/// what a request naming one should cost, is the step-up story — this type is
/// where that policy belongs, next to the flag it already carries, and
/// [`crate::decision`] is where it will be consulted. Nothing here decides it
/// today: `acr_values` is carried through validation untouched, which is what
/// OIDC Core §3.1.2.1 asks of a voluntary parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct AuthorizationPolicy {
    /// Whether this tenant offers self-service registration.
    ///
    /// `false` by default, and false is the honest answer for a deployment
    /// with no registration screen: OpenID Connect Prompt Create 1.0 §4 makes
    /// the OP responsible for what an unsupported `prompt=create` does, and a
    /// server with nowhere to send the user cannot honour it.
    pub prompt_create: bool,
    /// What this tenant does with `grant_id` and `grant_management_action`
    /// (Grant Management ID1 §5.2, §7.1).
    ///
    /// Off by default, which is a tenant that ignores both parameters — see
    /// [`GrantManagementPolicy::supported`].
    pub grant_management: GrantManagementPolicy,
}

impl AuthorizationPolicy {
    /// The policy of a tenant that offers registration, or does not.
    ///
    /// The constructor exists because the type is `#[non_exhaustive]`: a caller
    /// outside this crate cannot write the literal, which is what keeps adding
    /// a field from silently changing what every deployment answers. A new
    /// field arrives with its own conservative default and its own named way to
    /// turn on.
    #[must_use]
    pub const fn new(prompt_create: bool) -> Self {
        Self {
            prompt_create,
            grant_management: GrantManagementPolicy::new(false, false),
        }
    }

    /// The same policy with a Grant Management posture attached.
    ///
    /// A builder rather than a second argument to [`Self::new`], for the reason
    /// [`asterius_domain::TenantSettings::with_registration`] gives: the policy
    /// has already been decided by the caller that read the tenant's flags, and
    /// widening a signature every existing caller passes a default to would
    /// make the two look equally consequential. The default stays "this tenant
    /// does not offer it".
    #[must_use]
    pub const fn with_grant_management(mut self, grant_management: GrantManagementPolicy) -> Self {
        self.grant_management = grant_management;
        self
    }

    /// Whether this tenant offers a `prompt` value at all.
    ///
    /// Only `create` is conditional. OIDC Core §3.1.2.1's four values are part
    /// of the core protocol and every tenant answers them — with an error
    /// response where it must, which is still an answer.
    #[must_use]
    pub const fn offers(self, prompt: Prompt) -> bool {
        match prompt {
            Prompt::Create => self.prompt_create,
            Prompt::None | Prompt::Login | Prompt::Consent | Prompt::SelectAccount => true,
        }
    }

    /// The `prompt_values_supported` this tenant advertises (Prompt Create §4).
    ///
    /// Rendered from [`Self::offers`] rather than written out a second time, so
    /// a tenant cannot advertise a value its own validator refuses.
    #[must_use]
    pub fn prompt_values_supported(&self) -> Vec<&'static str> {
        Prompt::ALL
            .into_iter()
            .filter(|prompt| self.offers(*prompt))
            .map(Prompt::as_str)
            .collect()
    }
}

/// How the authorization response is delivered (OAuth 2.0 Multiple Response
/// Type Encoding Practices §2.1).
///
/// Two spellings, and they are the two this server advertises in
/// `response_modes_supported`. A `response_mode` is part of what the client
/// asked for, so an unrecognised one is refused rather than defaulted to
/// `query`: a client that spelled `form_post` wrong and got a query response
/// would be told nothing, and would sit waiting for a POST that never comes.
///
/// # Why `fragment` is not here
///
/// It has no meaning for this server, and this is the interoperability note
/// `ast-gxh.5` asks for. §2.1 defines `fragment` as the default for the
/// implicit and hybrid flows, and ADR-0002 implements neither: the only
/// `response_type` is `code`, and a fragment is by definition *not* sent to the
/// server the browser navigates to, so a client would have to run script to
/// recover the code from it. That is the shape RFC 9700 §2.1.2 tells
/// implementers to move away from, and the one thing this server's pages are
/// built not to need.
///
/// So a client library that sends `response_mode=fragment` alongside
/// `response_type=code` — some do, copying a hybrid-flow example — gets
/// `invalid_request` at the pushed authorization request endpoint, with an
/// authenticated client on the connection to read it. Silently answering in
/// `query` would be the worse of the two failures: the client's own security
/// analysis says the code never reached its server, and it just did.
/// Deliberately *not* `#[non_exhaustive]`, unlike the error types around it.
/// The delivery site matches on this value to decide what an authorization
/// response even is, and a wildcard arm there would answer a mode nobody had
/// implemented yet by silently sending a query response. Adding a variant
/// should break that match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseMode {
    /// Appended to the `redirect_uri`'s query string, in a 303.
    ///
    /// The default for `response_type=code` (§2.1), and so the mode of every
    /// request that names none.
    #[default]
    Query,
    /// Posted from a server-rendered page to the `redirect_uri`.
    ///
    /// OAuth 2.0 Form Post Response Mode §2. Chosen by clients whose callback
    /// wants the response in a body rather than in a URL — where it would land
    /// in the browser history, in a `Referer`, and in every access log on the
    /// way.
    FormPost,
}

impl ResponseMode {
    /// Every value this server can parse, in the order the enum declares them.
    ///
    /// The discovery document's `response_modes_supported` is rendered from
    /// this rather than written out a second time (`ast-iko`): what the server
    /// advertises and what [`Self::parse`] accepts are then the same list by
    /// construction.
    pub const ALL: [Self; 2] = [Self::Query, Self::FormPost];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::FormPost => "form_post",
        }
    }

    /// Parses a `response_mode` parameter.
    ///
    /// Exact, case-sensitive comparison against the two values this server
    /// implements. §2.1 registers response modes as case-sensitive strings, so
    /// `Form_Post` is a different value rather than a typo to forgive — and a
    /// server that folded case here would accept a spelling its own metadata
    /// does not advertise.
    ///
    /// # Errors
    ///
    /// [`UnsupportedResponseMode`] for `fragment`, for a registered mode this
    /// server does not implement, and for anything else at all.
    // fuzz-target: response_mode
    pub fn parse(raw: &str) -> Result<Self, UnsupportedResponseMode> {
        match raw {
            "query" => Ok(Self::Query),
            "form_post" => Ok(Self::FormPost),
            _ => Err(UnsupportedResponseMode),
        }
    }
}

/// A `response_mode` this server does not implement.
///
/// One variant, because the client learns one thing: the mode it named is not
/// available. Which modes *are* is what the discovery document answers, and it
/// already does — `response_modes_supported` is in every tenant's metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("response_mode is not one this server supports")]
pub struct UnsupportedResponseMode;

/// An authorization request that has passed every check.
///
/// Construction is the proof: there is no way to build one except through
/// [`validate`], so a value of this type is a request that may be stored and
/// later executed.
///
/// No `PartialEq`, because [`CodeChallenge`] has none. That is `ast-gxh.3`'s
/// decision and a good one: `verify` is the only way to relate a challenge to
/// a verifier, and it compares in constant time, so a short-circuiting `==`
/// cannot be written even by accident. Deriving equality here would hand that
/// back through the containing struct.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// The client that pushed it, taken from client authentication rather than
    /// from the `client_id` parameter.
    pub client_id: String,
    /// Where the user agent will be sent. Required and exactly registered.
    pub redirect_uri: String,
    /// How the response reaches that URI (`ast-gxh.5`).
    ///
    /// Decided here, at push time, because it decides what the *response* is —
    /// a 303 or a rendered page — and the code that sends it should read a
    /// value that was validated rather than re-parse a parameter. A request
    /// that named no mode carries [`ResponseMode::Query`], which is what §2.1
    /// says `response_type=code` means.
    pub response_mode: ResponseMode,
    /// Requested scopes, deduplicated and ordered.
    pub scopes: BTreeSet<String>,
    /// The PKCE challenge. Not optional: FAPI 2.0 SP §5.3.2.2 item 5.
    pub code_challenge: CodeChallenge,
    /// `state`, echoed back untouched.
    pub state: Option<String>,
    /// `nonce`, bound into the `id_token`.
    pub nonce: Option<String>,
    /// Requested prompts.
    pub prompts: BTreeSet<Prompt>,
    /// `max_age`, in seconds.
    pub max_age: Option<u32>,
    /// Requested ACR values, in preference order.
    pub acr_values: Vec<String>,
    /// `login_hint`, passed to the interaction.
    ///
    /// A value the *client* chose and the *user* will read, so what may be in
    /// it is bounded here — see [`parse_login_hint`].
    pub login_hint: Option<String>,
    /// `id_token_hint`, as the client sent it (OIDC Core §3.1.2.1).
    ///
    /// Only its compact-serialisation shape is checked here, because deciding
    /// whether it verifies needs this tenant's keys and this validator has no
    /// I/O. The signature, `iss` and `aud` are checked by the caller before
    /// the request is stored — `asterius_server::http::id_token_hint` — and
    /// what is carried onward is the `sub` it named, never this string.
    pub id_token_hint: Option<String>,
    /// RFC 8707 resource indicators.
    pub resources: BTreeSet<String>,
    /// The RFC 9396 §2 `authorization_details`, parsed and bounded.
    ///
    /// Parsed here, for the reason `claims` gives: this is the one place an
    /// authorization request is validated, and what is stored on the grant
    /// should be the thing that was checked. What is *not* decided here is
    /// whether this tenant has registered the types named or whether each
    /// element satisfies its type's schema — both need the registry, so both
    /// need I/O, and the pushed authorization request endpoint does them a
    /// moment later with the same error code.
    pub authorization_details: AuthorizationDetails,
    /// RFC 9449 §10: the thumbprint the issued code is bound to.
    pub dpop_jkt: Option<String>,
    /// The OIDC Core §5.5 `claims` request, parsed. Empty when the client sent
    /// none, which is the same request as sending `{}`.
    ///
    /// Parsed here rather than at issuance because this is the one place an
    /// authorization request is validated (see the module documentation), and
    /// because what is stored on the grant should be the thing that was
    /// checked. Re-parsing a raw string at the token endpoint would be a
    /// second parser with a second set of bounds.
    pub claims: ClaimsRequest,
    /// The OIDC Core §5.2 `claims_locales` preference, in the order the client
    /// gave it. Empty when the client expressed none.
    ///
    /// Carried on the request — and from there onto the grant — rather than
    /// read at issuance, because it is a property of *this* authorization. A
    /// token request arriving an hour later has no `claims_locales` parameter
    /// and no business inventing one, and a refresh must keep answering in the
    /// language the authorization asked for.
    pub claims_locales: ClaimsLocales,
    /// Whether `openid` was requested, which is what makes this OIDC rather
    /// than plain OAuth.
    pub openid: bool,
    /// What Grant Management ID1 §5.2's two parameters asked for, if anything.
    ///
    /// `None` is an ordinary authorization — including every request that
    /// reached a tenant with the feature off, whatever it carried, because
    /// [`crate::grant_management::parse`] ignores both parameters there.
    ///
    /// What this does *not* say is whether the `grant_id` names a grant that
    /// exists, belongs to this client, or belongs to the person who will sign
    /// in. All three need a lookup, and the last one needs a person; the
    /// pushed-request endpoint does the first two and the interaction that
    /// completes the flow does the third.
    pub grant_management: Option<GrantManagement>,
}

/// Validates a pushed authorization request.
///
/// `client_id` is the *authenticated* client, from client authentication —
/// never from the `client_id` form parameter. The parameter is checked against
/// it, but it is not the source of truth: a request is executed as whoever
/// proved they were, not as whoever the form says.
///
/// # Errors
///
/// Returns the first [`AuthorizationError`] that applies.
// fuzz-target: par_form
pub fn validate(
    params: &Parameters,
    client_id: &str,
    registration: &ClientRegistration,
    policy: AuthorizationPolicy,
) -> Result<AuthorizationRequest, AuthorizationError> {
    // RFC 9126 §2.1: "The `request_uri` authorization request parameter is one
    // exception, and it MUST NOT be provided." A pushed request that carries
    // one is trying to chain a reference this server issued into a new push.
    if params.present("request_uri") {
        return Err(AuthorizationError::RequestUriNotAllowed);
    }
    // A `request` object never reaches this validator: the pushed request
    // endpoint unwraps it first, and what arrives here are the *object's*
    // parameters (`asterius_oidc::request_object`). So one still being present
    // means the tenant does not accept request objects — and it is refused
    // rather than ignored, because ignoring it would honour exactly the
    // parameters the object exists to protect (RFC 9101 §4).
    if params.present("request") {
        return Err(AuthorizationError::RequestObjectNotSupported);
    }

    // The `client_id` parameter, when present, must agree with the client that
    // authenticated. RFC 9126 §2.1 notes that client authentication parameters
    // are "not germane to the authorization request itself"; this is the one
    // place the two views of identity must be reconciled.
    if let Some(presented) = params.get("client_id")?
        && presented != client_id
    {
        return Err(AuthorizationError::ClientMismatch);
    }

    // FAPI 2.0 SP §5.3.2.2 item 1.
    match params.get("response_type")? {
        Some(RESPONSE_TYPE) => {}
        Some(_) => return Err(AuthorizationError::UnsupportedResponseType),
        None => return Err(AuthorizationError::Missing("response_type")),
    }

    // OAuth 2.0 Multiple Response Type Encoding Practices §2.1. Absent means
    // `query`, which is what §2.1 defines as the default for this
    // `response_type`; `fragment` and every unregistered spelling are refused
    // rather than defaulted — see [`ResponseMode`] for why.
    let response_mode = match params.get("response_mode")? {
        Some(raw) => ResponseMode::parse(raw)?,
        None => ResponseMode::default(),
    };

    // FAPI 2.0 SP §5.3.2.2 item 6: required in a pushed request. RFC 6749
    // §3.1.2.3 would let it be omitted when exactly one is registered; the
    // profile withdraws that, and a required parameter is one less case.
    let redirect_uri = params
        .get("redirect_uri")?
        .ok_or(AuthorizationError::Missing("redirect_uri"))?;
    if !RedirectUri::is_registered(
        &registration.redirect_uris,
        redirect_uri,
        registration.application_type,
    ) {
        // Never a redirect. RFC 6749 §4.1.2.1: an invalid redirect URI is
        // reported to the client directly, because bouncing the error to an
        // unvalidated URI is the open redirector the rule exists to close.
        return Err(AuthorizationError::UnregisteredRedirectUri);
    }

    // FAPI 2.0 SP §5.3.2.2 item 5, via RFC 7636 §4.3.
    let code_challenge = CodeChallenge::parse(
        params.get("code_challenge")?,
        params.get("code_challenge_method")?,
    )?;

    let scopes = parse_scopes(params.get("scope")?, registration)?;
    let openid = scopes.contains("openid");

    let state = bounded(params.get("state")?, MAX_STATE_LEN, "state")?;
    let nonce = bounded(params.get("nonce")?, MAX_NONCE_LEN, "nonce")?;

    let prompts = Prompt::parse_list(params.get("prompt")?, policy)?;

    let max_age = parse_max_age(params.get("max_age")?)?;

    let acr_values = parse_acr_values(params.get("acr_values")?);

    let login_hint = parse_login_hint(params.get("login_hint")?)?;
    let id_token_hint = parse_id_token_hint(params.get("id_token_hint")?)?;

    let resources = parse_resources(params.multi("resource"), registration)?;

    // RFC 9396 §3. Shape, limits and the client's own §9.2 allow-list; the
    // registry and the per-type schemas are the caller's, a moment later.
    let authorization_details =
        parse_authorization_details(params.get("authorization_details")?, registration)?;

    // OIDC Core §5.5. Bounded and shape-checked here; what it *releases* is
    // `claims::resolve`, run against the grant rather than against this
    // request, because a request is what was asked for and a grant is what was
    // agreed to.
    let claims = params
        .get("claims")?
        .map(ClaimsRequest::parse)
        .transpose()?
        .unwrap_or_default();

    // OIDC Core §5.2. Never an error: a language preference is a hint about
    // presentation, and `ClaimsLocales::parse` drops what it cannot read so a
    // client that misspells a tag gets the fallback rather than a refusal.
    let claims_locales = ClaimsLocales::parse(params.get("claims_locales")?);

    // RFC 9449 §10. Validated as a JWK thumbprint's shape only; binding it to
    // an actual proof is `ast-a05.4`.
    let dpop_jkt = params
        .get("dpop_jkt")?
        .map(|raw| {
            // A base64url SHA-256 thumbprint: 43 characters, no padding.
            if raw.len() == 43 && raw.bytes().all(is_base64url) {
                Ok(raw.to_owned())
            } else {
                Err(AuthorizationError::Invalid("dpop_jkt"))
            }
        })
        .transpose()?;

    // Grant Management ID1 §5.2 and §5.4. Parsed last of the request's own
    // parameters because §7.1's "an action is required" is a statement about
    // the whole request: a malformed one should be told what is malformed
    // before it is told what is missing.
    let grant_management = crate::grant_management::parse(
        params.get("grant_management_action")?,
        params.get("grant_id")?,
        policy.grant_management,
    )?;

    Ok(AuthorizationRequest {
        client_id: client_id.to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        response_mode,
        scopes,
        code_challenge,
        state,
        nonce,
        prompts,
        max_age,
        acr_values,
        login_hint,
        id_token_hint,
        resources,
        authorization_details,
        dpop_jkt,
        claims,
        claims_locales,
        openid,
        grant_management,
    })
}

/// Checks a length bound without copying until it passes.
fn bounded(
    value: Option<&str>,
    limit: usize,
    name: &'static str,
) -> Result<Option<String>, AuthorizationError> {
    match value {
        None => Ok(None),
        Some(v) if v.len() <= limit => Ok(Some(v.to_owned())),
        Some(_) => Err(AuthorizationError::Invalid(name)),
    }
}

/// RFC 6749 §3.3: `scope` is space-delimited, and every value must be one the
/// client registered.
fn parse_scopes(
    raw: Option<&str>,
    registration: &ClientRegistration,
) -> Result<BTreeSet<String>, AuthorizationError> {
    let mut scopes = BTreeSet::new();
    for token in raw.unwrap_or_default().split_whitespace() {
        // A client may only ask for what it registered for. Checking at push
        // time means an over-broad request is refused to the client rather
        // than trimmed silently, which would issue a token the client believes
        // is broader than it is.
        if !registration.scopes.contains(token) {
            return Err(AuthorizationError::ScopeNotPermitted);
        }
        scopes.insert(token.to_owned());
        if scopes.len() > MAX_SCOPES {
            return Err(AuthorizationError::Invalid("scope"));
        }
    }
    Ok(scopes)
}

/// Parses `max_age` (OIDC Core §3.1.2.1).
///
/// "Maximum Authentication Age... Specifies the allowable elapsed time in
/// seconds since the last time the End-User was actively authenticated." The
/// value is a non-negative integer of seconds, and that is the whole grammar:
/// digits, nothing else. `-1`, `+5`, `1e3`, `5s`, ` 5` and an empty value are
/// all refused rather than coerced, because every one of them would otherwise
/// have to be *guessed* into a number, and a guess here decides how old an
/// authentication may be.
///
/// `u32::from_str` is not enough on its own: it accepts a leading `+`, so
/// `+0` and `0` would be the same request written two ways, and only one of
/// them is a value the specification defines.
///
/// # Zero is a value, not an absence
///
/// `max_age=0` means the allowable elapsed time is zero seconds, so any
/// authentication that happened before this request is too old and the user
/// must be actively re-authenticated. It is the strictest request a client can
/// make, and reading it as "no constraint" — which is what a
/// `NonZeroU32`-shaped API or an `unwrap_or(0)` invites — would turn the
/// strictest request into the weakest. `None` is the absence; `Some(0)` is the
/// demand. [`asterius_domain::Session::needs_reauthentication`] is where the
/// comparison lives, and it compares strictly: elapsed *greater than* zero is
/// too old.
///
/// # Errors
///
/// [`AuthorizationError::Invalid`] for anything that is not a run of ASCII
/// digits denoting a value a `u32` can hold. The upper bound is not a policy —
/// a `max_age` of a hundred years and one of forty are the same request in
/// practice — it is a refusal to store a number this server cannot compare.
// fuzz-target: authorization_hints
pub fn parse_max_age(raw: Option<&str>) -> Result<Option<u32>, AuthorizationError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AuthorizationError::Invalid("max_age"));
    }
    raw.parse::<u32>()
        .map(Some)
        .map_err(|_| AuthorizationError::Invalid("max_age"))
}

/// Parses `login_hint` (OIDC Core §3.1.2.1).
///
/// "Hint to the Authorization Server about the login identifier the End-User
/// might use to log in" — an email address, a phone number, an account name.
///
/// # Why this one is checked more closely than the other strings
///
/// Because of where it ends up. `state` and `nonce` are echoed to the client
/// that sent them; `login_hint` is put in front of a **person**, in a field on
/// the sign-in page, and the party who chose it is the relying party rather
/// than the user reading it. That makes it the one request parameter a client
/// can use to write on this server's own pages, and the page is where a user
/// decides whether to trust what they are looking at.
///
/// Escaping is not enough by itself and is not this function's job — the
/// templates escape every interpolation, and `ast-o4u.1` made the same call
/// for the logout confirmation page. What this adds is that the value cannot
/// *look* like anything but a login identifier:
///
/// * bounded to [`MAX_LOGIN_HINT_LEN`], so it cannot be a paragraph of prose;
/// * no C0 or C1 control characters, so it cannot smuggle a line break into a
///   log line or a header;
/// * no bidirectional formatting characters, so it cannot reorder the text
///   around it — the trick that makes `moc.elpmaxe@ecila` read as an address
///   at a domain the user trusts (Unicode UAX #9, and the same rule
///   [`asterius_domain::ClaimName`] applies to a claim name).
///
/// A value that breaks those rules is refused at the push rather than
/// sanitised, because a client that sent one has not asked for a hint.
///
/// # Errors
///
/// [`AuthorizationError::Invalid`] naming `login_hint`.
// fuzz-target: authorization_hints
pub fn parse_login_hint(raw: Option<&str>) -> Result<Option<String>, AuthorizationError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let refused =
        raw.is_empty() || raw.len() > MAX_LOGIN_HINT_LEN || raw.chars().any(is_display_unsafe);
    if refused {
        return Err(AuthorizationError::Invalid("login_hint"));
    }
    Ok(Some(raw.to_owned()))
}

/// Characters that must not reach a page through a request parameter.
///
/// The C0 and C1 control ranges, and the Unicode bidirectional formatting
/// characters of UAX #9 §2.
/// The `acr_values` parameter, as a preference list (OIDC Core §3.1.2.1).
///
/// "Space-separated string that specifies the `acr` values that the
/// Authorization Server is being requested to use ... with the values appearing
/// in order of preference." Three things follow, and all three are here rather
/// than at the four call sites that would otherwise each decide them.
///
/// * **Order is preserved.** It is the request's own statement of preference,
///   and a set would throw it away.
/// * **Repeats collapse.** A value named twice is named once; the second
///   mention cannot make it more preferred than the first.
/// * **It is bounded** ([`MAX_ACR_VALUES`]), and the excess is *dropped* rather
///   than refused. This is a voluntary parameter: OIDC Core §3.1.2.1 makes
///   honouring it a "MAY", so a request carrying a thousand class names is
///   answered at whatever context the authentication reaches — which is what a
///   request naming none gets, and what a request naming a thousand unmeetable
///   ones would have got anyway. An `invalid_request` here would refuse a
///   request the specification says may simply not be fulfilled.
///
/// An *essential* `acr` does not come through here at all: it arrives inside
/// `claims` (§5.5.1.1), where a bound of this kind would change an error into a
/// silence. See [`crate::claims`].
#[must_use]
// fuzz-target: authorization_hints
pub fn parse_acr_values(raw: Option<&str>) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    for value in raw.unwrap_or_default().split_whitespace() {
        if values.len() == MAX_ACR_VALUES {
            break;
        }
        if !values.iter().any(|seen| seen == value) {
            values.push(value.to_owned());
        }
    }
    values
}

const fn is_display_unsafe(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{200E}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// Parses `id_token_hint` (OIDC Core §3.1.2.1).
///
/// "ID Token previously issued by the Authorization Server being passed as a
/// hint about the End-User's current or past authenticated session with the
/// Client... If the End-User identified by the ID Token is logged in or is
/// logged in by the request, then the Authorization Server returns a positive
/// response; otherwise, it SHOULD return an error, such as `login_required`."
///
/// Shape only, here: three non-empty base64url segments separated by dots,
/// which is JWS Compact Serialization (RFC 7515 §7.1) and the only form an ID
/// token takes. Whether it *verifies* is a question about this tenant's keys,
/// and this module has no I/O — the caller checks it before the request is
/// stored, and OIDC Core's "MUST be validated" is enforced there.
///
/// Checking the shape anyway is worth the few lines: it is what stops eight
/// kilobytes of arbitrary bytes being written to the database and handed to a
/// JWS parser later, and it means a client that sent an access token or a raw
/// subject by mistake learns so while it is still on the connection.
///
/// # Errors
///
/// [`AuthorizationError::Invalid`] naming `id_token_hint`.
// fuzz-target: authorization_hints
pub fn parse_id_token_hint(raw: Option<&str>) -> Result<Option<String>, AuthorizationError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.len() > MAX_ID_TOKEN_HINT_LEN || !is_compact_jws(raw) {
        return Err(AuthorizationError::Invalid("id_token_hint"));
    }
    Ok(Some(raw.to_owned()))
}

/// RFC 7515 §7.1: `BASE64URL(header) || '.' || BASE64URL(payload) || '.' ||
/// BASE64URL(signature)`, with no padding and nothing else in it.
fn is_compact_jws(raw: &str) -> bool {
    let mut segments = raw.split('.');
    let three = [segments.next(), segments.next(), segments.next()];
    if segments.next().is_some() {
        return false;
    }
    three.into_iter().all(|segment| {
        // The signature of an unsecured JWS is empty (RFC 7515 §6), and this
        // server accepts no such token: an `alg: none` hint is a string that
        // anybody can write, and a shape check that let one through would be
        // deciding it is worth parsing.
        segment.is_some_and(|segment| !segment.is_empty() && segment.bytes().all(is_base64url))
    })
}

/// RFC 9396 §3: the `authorization_details` parameter of an authorization
/// request.
///
/// Two gates here, as with `resource`, and the third is the caller's. The
/// *shape and the limits* are [`AuthorizationDetails::parse`], the one parser
/// this server has for the job. The *permission* is the client's RFC 9396 §9.2
/// `authorization_details_types`: an empty registration means "no types
/// permitted" rather than "all of them", for the reason an empty `resources`
/// means no audiences — a client that has not been registered for a type must
/// not be able to name one, and §9.2's list is the registration that says which
/// ones it may.
///
/// What is **not** checked here is whether this tenant has registered the type
/// and whether the element satisfies that type's schema; both need the registry
/// and so need I/O, and the pushed authorization request endpoint does them a
/// moment later with the same `invalid_authorization_details`.
fn parse_authorization_details(
    raw: Option<&str>,
    registration: &ClientRegistration,
) -> Result<AuthorizationDetails, AuthorizationError> {
    let Some(raw) = raw else {
        return Ok(AuthorizationDetails::default());
    };
    let details = AuthorizationDetails::parse(raw)?;
    for name in details.types() {
        if !registration.authorization_details_types.contains(name) {
            return Err(AuthorizationError::InvalidAuthorizationDetails(
                InvalidAuthorizationDetails,
            ));
        }
    }
    Ok(details)
}

/// RFC 8707 §2.1: the `resource` parameters of an authorization request.
///
/// Two gates, and a value must pass both. The *shape* is
/// [`ResourceIdentifier::parse`] — an absolute, fragment-free URI, the one
/// parser this server has for the job, shared with the token endpoint so that
/// the two cannot disagree about what a resource indicator is. The *permission*
/// is the client's own allow-list: an empty one means "no resource indicators
/// permitted" rather than "all of them", because a client that has not been
/// granted an audience must not be able to name one.
///
/// What is **not** checked here is whether this tenant has registered the
/// resource server, which needs the registry and so needs I/O; the pushed
/// authorization request endpoint does that a moment later, and answers with
/// the same `invalid_target`.
fn parse_resources(
    values: &[String],
    registration: &ClientRegistration,
) -> Result<BTreeSet<String>, AuthorizationError> {
    if values.len() > MAX_RESOURCES {
        return Err(AuthorizationError::InvalidTarget(InvalidTarget));
    }
    let mut resources = BTreeSet::new();
    for raw in values {
        let identifier = ResourceIdentifier::parse(raw)?;
        if !registration.resources.contains(identifier.as_str()) {
            return Err(AuthorizationError::InvalidTarget(InvalidTarget));
        }
        resources.insert(identifier.as_str().to_owned());
    }
    Ok(resources)
}

/// Base64url alphabet, unpadded.
const fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

#[cfg(test)]
mod tests {
    /// OIDC Core §3.1.2.1: `acr_values` is "space-separated ... in order of
    /// preference". Order survives, a repeat does not become a second
    /// preference, and nothing is invented.
    #[test]
    fn acr_values_keep_their_order_and_lose_their_repeats() {
        let parsed = super::parse_acr_values(Some("  gold\tsilver\n gold bronze "));

        assert_eq!(parsed, vec!["gold", "silver", "bronze"]);
    }

    /// The parameter is voluntary (§3.1.2.1: the OP "MAY" honour it), so an
    /// over-long list is truncated rather than refused: the request is still
    /// answerable, at whatever context the authentication reaches.
    #[test]
    fn an_unbounded_acr_values_list_is_truncated_rather_than_refused() {
        let many = (0..super::MAX_ACR_VALUES + 20)
            .map(|index| format!("urn:example:{index}"))
            .collect::<Vec<_>>()
            .join(" ");

        let parsed = super::parse_acr_values(Some(&many));

        assert_eq!(parsed.len(), super::MAX_ACR_VALUES);
        assert_eq!(parsed[0], "urn:example:0");
    }

    #[test]
    fn an_absent_acr_values_asks_for_nothing() {
        assert!(super::parse_acr_values(None).is_empty());
        assert!(super::parse_acr_values(Some("   ")).is_empty());
    }

    use super::*;
    use asterius_domain::Capabilities;
    use serde_json::json;

    const CLIENT: &str = "billing";
    const REDIRECT: &str = "https://rp.example/cb";
    // RFC 7636 Appendix B's worked challenge.
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn registration() -> ClientRegistration {
        ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": "Billing",
                "redirect_uris": [REDIRECT],
                "grant_types": ["authorization_code"],
                "scope": "openid profile payments",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }))
            .expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration")
    }

    fn base() -> Vec<(String, String)> {
        vec![
            ("response_type".into(), "code".into()),
            ("redirect_uri".into(), REDIRECT.into()),
            ("code_challenge".into(), CHALLENGE.into()),
            ("code_challenge_method".into(), "S256".into()),
            ("scope".into(), "openid profile".into()),
        ]
    }

    /// A tenant that has configured nothing, which is the default everywhere.
    fn policy() -> AuthorizationPolicy {
        AuthorizationPolicy::default()
    }

    fn with(extra: &[(&str, &str)]) -> Result<AuthorizationRequest, AuthorizationError> {
        with_policy(extra, policy())
    }

    fn with_policy(
        extra: &[(&str, &str)],
        policy: AuthorizationPolicy,
    ) -> Result<AuthorizationRequest, AuthorizationError> {
        let mut pairs = base();
        for (k, v) in extra {
            pairs.push(((*k).to_owned(), (*v).to_owned()));
        }
        validate(
            &Parameters::from_pairs(pairs),
            CLIENT,
            &registration(),
            policy,
        )
    }

    fn without(name: &str) -> Result<(), AuthorizationError> {
        let pairs: Vec<_> = base().into_iter().filter(|(k, _)| k != name).collect();
        outcome(pairs)
    }

    /// The verdict alone.
    ///
    /// `AuthorizationRequest` has no `PartialEq` — see its documentation — so
    /// assertions compare `Result<(), _>`. Discarding the success value is
    /// exactly right for the rejection tests, which are about *whether* and
    /// *why*, never about what would have been built.
    fn outcome(pairs: Vec<(String, String)>) -> Result<(), AuthorizationError> {
        validate(
            &Parameters::from_pairs(pairs),
            CLIENT,
            &registration(),
            policy(),
        )
        .map(|_| ())
    }

    /// Like [`with`], discarding the success value.
    fn refuse(extra: &[(&str, &str)]) -> Result<(), AuthorizationError> {
        with(extra).map(|_| ())
    }

    /// The base parameters with one replaced.
    fn replacing(name: &str, value: &str) -> Result<(), AuthorizationError> {
        let pairs: Vec<_> = base()
            .into_iter()
            .filter(|(k, _)| k != name)
            .chain([(name.to_owned(), value.to_owned())])
            .collect();
        outcome(pairs)
    }

    #[test]
    fn a_conforming_request_is_accepted() {
        let request = with(&[("state", "abc"), ("nonce", "n-0")]).expect("must accept");
        assert_eq!(request.client_id, CLIENT);
        assert_eq!(request.redirect_uri, REDIRECT);
        assert_eq!(request.state.as_deref(), Some("abc"));
        assert!(request.openid);
        assert_eq!(
            request.scopes,
            ["openid", "profile"].map(ToOwned::to_owned).into()
        );
    }

    /// RFC 6749 §3.1: no parameter twice.
    ///
    /// The attack this closes is parameter pollution: two intermediaries that
    /// disagree about which copy counts turn one request into two different
    /// ones, validated as the harmless reading and executed as the other.
    #[test]
    fn a_repeated_parameter_is_refused_rather_than_resolved() {
        for name in [
            "response_type",
            "redirect_uri",
            "scope",
            "state",
            "code_challenge",
            "client_id",
            "prompt",
        ] {
            let mut pairs = base();
            // Two copies, the second harmless-looking.
            pairs.push((name.to_owned(), "code".to_owned()));
            pairs.push((name.to_owned(), "code".to_owned()));
            let result = outcome(pairs);
            assert_eq!(
                result,
                Err(AuthorizationError::DuplicateParameter(name.to_owned())),
                "{name} was resolved rather than refused"
            );
        }
    }

    /// RFC 9126 §2.1.
    #[test]
    fn a_pushed_request_may_not_carry_a_request_uri() {
        assert_eq!(
            refuse(&[("request_uri", "urn:ietf:params:oauth:request_uri:abc")]),
            Err(AuthorizationError::RequestUriNotAllowed)
        );
    }

    /// Ignoring a `request` object would honour the query parameters it exists
    /// to protect. A tenant that *accepts* request objects never reaches this:
    /// the pushed request endpoint has already replaced the parameters with the
    /// object's own (`ast-gxh.9`).
    #[test]
    fn a_request_object_is_refused_not_ignored() {
        let error = refuse(&[("request", "eyJhbGciOiJub25lIn0..")]).expect_err("must refuse");
        assert_eq!(error, AuthorizationError::RequestObjectNotSupported);
        assert_eq!(error.code(), "request_not_supported");
    }

    /// ADR-0002 and FAPI 2.0 SP §5.3.2.2 item 1.
    #[test]
    fn only_the_code_response_type_exists() {
        for wrong in [
            "token",
            "id_token",
            "code id_token",
            "code token",
            "id_token token",
            "none",
            "CODE",
            "code ",
        ] {
            assert_eq!(
                replacing("response_type", wrong),
                Err(AuthorizationError::UnsupportedResponseType),
                "accepted response_type {wrong:?}"
            );
        }
    }

    /// §2.1: `query` is what `response_type=code` means when nothing is said.
    #[test]
    fn a_request_naming_no_response_mode_is_a_query_response() {
        // --- Arrange / Act ---
        let request = with(&[]).expect("the base request is valid");

        // --- Assert ---
        assert_eq!(request.response_mode, ResponseMode::Query);
    }

    #[test]
    fn form_post_is_accepted_and_carried_onto_the_request() {
        // --- Arrange / Act ---
        let request = with(&[("response_mode", "form_post")]).expect("a supported mode");

        // --- Assert ---
        assert_eq!(request.response_mode, ResponseMode::FormPost);
    }

    /// The acceptance criterion of `ast-gxh.5`, at the endpoint it names.
    ///
    /// `fragment` is refused rather than answered in `query`, because a client
    /// that asked for a mode and got another has been told nothing and will
    /// look for the response somewhere it is not.
    #[test]
    fn fragment_and_every_unknown_mode_are_invalid_request() {
        for refused in [
            "fragment",
            "web_message",
            "form_post.jwt",
            "query.jwt",
            // Case-sensitive: §2.1 registers the values as they are spelled.
            "FORM_POST",
            "Query",
            " form_post",
            "form_post ",
            "",
        ] {
            // --- Act ---
            let outcome = refuse(&[("response_mode", refused)]);

            // --- Assert ---
            assert_eq!(
                outcome,
                Err(AuthorizationError::ResponseMode(UnsupportedResponseMode)),
                "accepted response_mode {refused:?}"
            );
            assert_eq!(
                outcome.expect_err("refused").code(),
                "invalid_request",
                "{refused:?}"
            );
        }
    }

    /// RFC 6749 §3.1 again, for the parameter this ticket adds.
    #[test]
    fn a_repeated_response_mode_is_refused_rather_than_resolved() {
        // --- Arrange ---
        let mut pairs = base();
        pairs.push(("response_mode".into(), "query".into()));
        pairs.push(("response_mode".into(), "form_post".into()));

        // --- Act / Assert ---
        assert_eq!(
            outcome(pairs),
            Err(AuthorizationError::DuplicateParameter(
                "response_mode".to_owned()
            ))
        );
    }

    /// The parser and the spelling agree in both directions, so a mode stored
    /// as a string and read back is the mode that was validated.
    #[test]
    fn every_mode_round_trips_through_its_wire_spelling() {
        for mode in [ResponseMode::Query, ResponseMode::FormPost] {
            assert_eq!(ResponseMode::parse(mode.as_str()), Ok(mode));
        }
    }

    /// FAPI 2.0 SP §5.3.2.2 item 6.
    #[test]
    fn redirect_uri_is_required_even_when_only_one_is_registered() {
        assert_eq!(
            without("redirect_uri"),
            Err(AuthorizationError::Missing("redirect_uri"))
        );
    }

    /// ADR-0005: exact string comparison, and no redirect on failure.
    #[test]
    fn a_redirect_uri_that_is_not_exactly_registered_is_refused() {
        for wrong in [
            "https://rp.example/cb/",
            "https://rp.example/cb?x=1",
            "https://rp.example/CB",
            "https://rp.example:443/cb",
            "https://rp.example/cb#f",
            "http://rp.example/cb",
            "https://attacker.example/cb",
            "https://rp.example.attacker.example/cb",
            "",
        ] {
            assert_eq!(
                replacing("redirect_uri", wrong),
                Err(AuthorizationError::UnregisteredRedirectUri),
                "accepted redirect_uri {wrong:?}"
            );
        }
    }

    /// FAPI 2.0 SP §5.3.2.2 item 5.
    #[test]
    fn pkce_is_required_and_must_be_s256() {
        assert!(matches!(
            without("code_challenge"),
            Err(AuthorizationError::Pkce(_))
        ));

        assert!(matches!(
            replacing("code_challenge_method", "plain"),
            Err(AuthorizationError::Pkce(_))
        ));
    }

    #[test]
    fn a_client_may_only_request_scopes_it_registered() {
        assert_eq!(
            replacing("scope", "openid admin"),
            Err(AuthorizationError::ScopeNotPermitted)
        );
        // Trimmed rather than refused would be worse: the client would believe
        // it holds `admin` and design around it.
        assert_eq!(
            replacing("scope", "admin"),
            Err(AuthorizationError::ScopeNotPermitted)
        );
    }

    #[test]
    fn the_client_id_parameter_must_agree_with_the_authenticated_client() {
        assert_eq!(
            refuse(&[("client_id", "someone-else")]),
            Err(AuthorizationError::ClientMismatch)
        );
        assert!(with(&[("client_id", CLIENT)]).is_ok());
    }

    /// OIDC Core §3.1.2.1.
    #[test]
    fn prompt_none_cannot_be_combined() {
        for combined in [
            "none login",
            "login none",
            "none consent",
            "none select_account",
        ] {
            assert_eq!(
                refuse(&[("prompt", combined)]),
                Err(AuthorizationError::ConflictingPrompt),
                "accepted prompt {combined:?}"
            );
        }
        assert!(with(&[("prompt", "login consent")]).is_ok());
        assert!(with(&[("prompt", "none")]).is_ok());
    }

    #[test]
    fn an_unknown_prompt_value_is_refused() {
        assert_eq!(
            refuse(&[("prompt", "login sudo")]),
            Err(AuthorizationError::Invalid("prompt"))
        );
    }

    /// FAPI 2.0 SP §5.3.2.2 item 14 is a floor on what must be accepted.
    #[test]
    fn a_nonce_of_sixty_four_characters_is_accepted() {
        let nonce = "n".repeat(64);
        assert!(with(&[("nonce", &nonce)]).is_ok());

        let too_long = "n".repeat(MAX_NONCE_LEN + 1);
        assert_eq!(
            refuse(&[("nonce", &too_long)]),
            Err(AuthorizationError::Invalid("nonce"))
        );
    }

    #[test]
    fn an_oversized_state_is_refused() {
        let state = "s".repeat(MAX_STATE_LEN + 1);
        assert_eq!(
            refuse(&[("state", &state)]),
            Err(AuthorizationError::Invalid("state"))
        );
    }

    #[test]
    fn max_age_must_be_a_non_negative_integer() {
        assert_eq!(with(&[("max_age", "0")]).expect("zero").max_age, Some(0));
        for wrong in [
            "-1",
            "1.5",
            "",
            "abc",
            "99999999999999999999",
            // Accepted by `u32::from_str` and by nothing in §3.1.2.1: a
            // non-negative integer is written without a sign.
            "+5",
            " 5",
            "5 ",
            "1e3",
            "5s",
            // Not ASCII digits, however much they look like them.
            "٥",
        ] {
            assert_eq!(
                refuse(&[("max_age", wrong)]),
                Err(AuthorizationError::Invalid("max_age")),
                "accepted max_age {wrong:?}"
            );
        }
    }

    /// §3.1.2.1 again: absence and zero are different requests. `None` asks for
    /// nothing; `Some(0)` demands an authentication that has just happened.
    #[test]
    fn an_absent_max_age_is_not_the_same_as_zero() {
        assert_eq!(parse_max_age(None), Ok(None));
        assert_eq!(parse_max_age(Some("0")), Ok(Some(0)));
    }

    /// Prompt Create §4: a value this tenant does not offer is refused, and the
    /// refusal names the reason rather than looking like a typo.
    #[test]
    fn prompt_create_is_refused_unless_the_tenant_offers_registration() {
        assert_eq!(
            refuse(&[("prompt", "create")]),
            Err(AuthorizationError::UnsupportedPrompt)
        );

        let offered = AuthorizationPolicy::new(true);
        let request = with_policy(&[("prompt", "create")], offered).expect("offered");
        assert!(request.prompts.contains(&Prompt::Create));
    }

    /// A tenant advertises exactly what it accepts.
    #[test]
    fn prompt_values_supported_matches_what_is_accepted() {
        assert_eq!(
            AuthorizationPolicy::default().prompt_values_supported(),
            ["none", "login", "consent", "select_account"]
        );
        assert_eq!(
            AuthorizationPolicy::new(true).prompt_values_supported(),
            ["none", "login", "consent", "select_account", "create"]
        );
    }

    /// `login_hint` is chosen by a client and read by a person, so what may be
    /// in it is bounded: no controls, no bidirectional overrides, no essays.
    #[test]
    fn a_login_hint_that_could_rewrite_a_page_is_refused() {
        assert_eq!(
            with(&[("login_hint", "alice@example.test")])
                .expect("an ordinary hint")
                .login_hint
                .as_deref(),
            Some("alice@example.test")
        );
        let long = "a".repeat(MAX_LOGIN_HINT_LEN + 1);
        for wrong in [
            "",
            // A line break in a value that reaches a log line and a page.
            "alice\nSign in to continue",
            "alice\u{0}",
            // UAX #9: the override that makes an address read as another.
            "alice\u{202E}moc.elpmaxe@",
            &long,
        ] {
            assert_eq!(
                refuse(&[("login_hint", wrong)]),
                Err(AuthorizationError::Invalid("login_hint")),
                "accepted login_hint {wrong:?}"
            );
        }
    }

    /// The hint is an ID token, so it has an ID token's shape. Whether it
    /// *verifies* is the caller's question — see `parse_id_token_hint`.
    #[test]
    fn an_id_token_hint_must_be_a_compact_jws() {
        let hint = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1LTEifQ.c2ln";
        assert_eq!(
            with(&[("id_token_hint", hint)])
                .expect("a well-shaped hint")
                .id_token_hint
                .as_deref(),
            Some(hint)
        );
        let long = "a.b.".to_owned() + &"c".repeat(MAX_ID_TOKEN_HINT_LEN);
        for wrong in [
            "", "a.b", "a.b.c.d", // An unsecured JWS: a token anybody can write.
            "a.b.", ".b.c", "a.b.c=", "a b.c.d", &long,
        ] {
            assert_eq!(
                refuse(&[("id_token_hint", wrong)]),
                Err(AuthorizationError::Invalid("id_token_hint")),
                "accepted id_token_hint {wrong:?}"
            );
        }
    }

    /// RFC 9396 §2: an `authorization_details` that is not a JSON array of
    /// objects each carrying a string `type` is
    /// `invalid_authorization_details`, and RFC 9396 §5 is the code.
    #[test]
    fn a_malformed_authorization_details_is_invalid_authorization_details() {
        for wrong in [
            "not json",
            "{}",
            r#"{"type":"payments"}"#,
            "[7]",
            "[{}]",
            r#"[{"type":7}]"#,
            r#"[{"type":"payments","locations":"https://api.example/"}]"#,
        ] {
            assert_eq!(
                refuse(&[("authorization_details", wrong)]),
                Err(AuthorizationError::InvalidAuthorizationDetails(
                    InvalidAuthorizationDetails
                )),
                "accepted authorization_details {wrong:?}"
            );
        }
        assert_eq!(
            AuthorizationError::InvalidAuthorizationDetails(InvalidAuthorizationDetails).code(),
            "invalid_authorization_details"
        );
    }

    /// RFC 9396 §9.2: `authorization_details_types` is the client's list of
    /// types, and a client that registered none may name none.
    #[test]
    fn a_type_the_client_did_not_register_is_refused() {
        let details = r#"[{"type":"payment_initiation"}]"#;
        assert_eq!(
            refuse(&[("authorization_details", details)]),
            Err(AuthorizationError::InvalidAuthorizationDetails(
                InvalidAuthorizationDetails
            ))
        );

        let mut registration = registration();
        registration
            .authorization_details_types
            .insert("payment_initiation".to_owned());
        let pairs: Vec<(String, String)> = base()
            .into_iter()
            .chain([("authorization_details".to_owned(), details.to_owned())])
            .collect();
        let request = validate(
            &Parameters::from_pairs(pairs),
            CLIENT,
            &registration,
            policy(),
        )
        .expect("a registered type");
        assert_eq!(
            request.authorization_details.to_json(),
            vec![json!({"type": "payment_initiation"})]
        );
    }

    /// A request that sends no `authorization_details` carries none, which is
    /// not the same as carrying something empty that a later reader has to
    /// interpret.
    #[test]
    fn no_authorization_details_is_an_empty_request() {
        let request = with(&[]).expect("the base request");
        assert!(request.authorization_details.is_empty());
    }

    /// RFC 8707 §2.2: a `resource` this server will not honour is
    /// `invalid_target`, and the per-client allow-list is one of the reasons it
    /// might not.
    #[test]
    fn a_resource_the_client_was_not_granted_is_invalid_target() {
        // The fixture registers none, so every indicator is refused. An empty
        // allow-list must mean "none", not "all".
        for wrong in [
            "https://api.example/",
            "https://api.example/#frag",
            "not-a-uri",
        ] {
            assert_eq!(
                refuse(&[("resource", wrong)]),
                Err(AuthorizationError::InvalidTarget(InvalidTarget)),
                "accepted resource {wrong:?}"
            );
        }
    }

    /// RFC 8707 §2: "an absolute URI […] MUST NOT include a fragment
    /// component". A relative URI and a fragment are refused even when the
    /// spelling is on the client's allow-list, because a value the allow-list
    /// holds and the parser refuses is a value nothing could ever match.
    #[test]
    fn a_fragment_or_a_relative_uri_is_invalid_target_whatever_the_client_registered() {
        for wrong in ["https://api.example/v1#section", "/v1/accounts", ""] {
            let mut registration = registration();
            registration.resources.insert(wrong.to_owned());
            let pairs: Vec<(String, String)> = base()
                .into_iter()
                .chain([("resource".to_owned(), wrong.to_owned())])
                .collect();
            assert_eq!(
                validate(
                    &Parameters::from_pairs(pairs),
                    CLIENT,
                    &registration,
                    policy()
                )
                .map(|_| ()),
                Err(AuthorizationError::InvalidTarget(InvalidTarget)),
                "accepted resource {wrong:?}"
            );
        }
    }

    /// RFC 8707 §2: "Multiple `resource` parameters MAY be used". They are, and
    /// the request carries every one of them.
    #[test]
    fn several_resources_are_all_carried_onto_the_request() {
        let first = "https://api.example/v1";
        let second = "https://reports.example/";
        let mut registration = registration();
        registration.resources.insert(first.to_owned());
        registration.resources.insert(second.to_owned());
        let pairs: Vec<(String, String)> = base()
            .into_iter()
            .chain([
                ("resource".to_owned(), first.to_owned()),
                ("resource".to_owned(), second.to_owned()),
            ])
            .collect();
        let request = validate(
            &Parameters::from_pairs(pairs),
            CLIENT,
            &registration,
            policy(),
        )
        .expect("two registered resources");
        assert_eq!(
            request.resources,
            [first.to_owned(), second.to_owned()]
                .into_iter()
                .collect::<BTreeSet<String>>()
        );
    }

    /// RFC 8707 §2.2 registers `invalid_target`, and a client library that read
    /// `invalid_request` would go looking for a typo it does not have.
    #[test]
    fn a_refused_resource_carries_the_error_code_rfc_8707_registers() {
        assert_eq!(
            AuthorizationError::InvalidTarget(InvalidTarget).code(),
            "invalid_target"
        );
    }

    #[test]
    fn a_dpop_thumbprint_must_look_like_one() {
        let jkt = "a".repeat(43);
        assert_eq!(
            with(&[("dpop_jkt", &jkt)]).expect("valid").dpop_jkt,
            Some(jkt)
        );
        for wrong in ["", "a", &"a".repeat(42), &"a".repeat(44), &"+".repeat(43)] {
            assert_eq!(
                refuse(&[("dpop_jkt", wrong)]),
                Err(AuthorizationError::Invalid("dpop_jkt")),
                "accepted dpop_jkt {wrong:?}"
            );
        }
    }

    #[test]
    fn error_codes_are_the_ones_the_specifications_name() {
        assert_eq!(
            AuthorizationError::UnsupportedResponseType.code(),
            "unsupported_response_type"
        );
        assert_eq!(
            AuthorizationError::ScopeNotPermitted.code(),
            "invalid_scope"
        );
        assert_eq!(
            AuthorizationError::RequestObjectNotSupported.code(),
            "request_not_supported"
        );
        assert_eq!(AuthorizationError::ClientMismatch.code(), "invalid_client");
        assert_eq!(
            AuthorizationError::UnregisteredRedirectUri.code(),
            "invalid_request"
        );
    }

    /// A rejection must not quote the client's input back: an
    /// `error_description` echoing a parameter is a reflection primitive, and
    /// on an endpoint that has just refused a redirect URI it would be an
    /// especially unhelpful one.
    #[test]
    fn a_rejection_does_not_echo_the_offending_value() {
        let error = refuse(&[("state", &"s".repeat(MAX_STATE_LEN + 1))]).expect_err("refused");
        assert!(!error.to_string().contains("ssss"), "{error}");

        let error = replacing("redirect_uri", "https://attacker.example/cb").expect_err("refused");
        assert!(!error.to_string().contains("attacker.example"), "{error}");

        // And a `claims` parameter, which is the one parameter that is a whole
        // JSON document the client wrote.
        let error = refuse(&[("claims", r#"{"userinfo":"a-secret-looking-string"}"#)])
            .expect_err("refused");
        assert!(!error.to_string().contains("a-secret-looking"), "{error}");
    }

    /// The `claims` parameter is parsed once, here, and what is stored is what
    /// was checked (OIDC Core §5.5).
    ///
    /// The interesting half is the split between ignoring and refusing. A
    /// member naming a claim this server will not release — `sub` — is
    /// dropped, because §5.5 says unrecognised members are ignored and because
    /// refusing would let a client map the reserved list by bisection. A
    /// member whose *shape* is wrong is refused, because a client that sent
    /// one has misunderstood the parameter and would otherwise walk away with
    /// a narrower authorization than it thinks it has.
    #[test]
    fn the_claims_parameter_is_parsed_and_a_reserved_name_in_it_is_ignored() {
        let request = with(&[(
            "claims",
            r#"{"id_token":{"sub":{"value":"somebody-else"},"given_name":null}}"#,
        )])
        .expect("a well-shaped claims parameter");
        assert_eq!(
            request
                .claims
                .id_token()
                .keys()
                .map(crate::claims::ReleasableClaim::as_str)
                .collect::<Vec<_>>(),
            ["given_name"]
        );

        // Absent is the same request as `{}`.
        assert!(with(&[]).expect("no claims parameter").claims.is_empty());
        assert!(
            with(&[("claims", "{}")])
                .expect("an empty claims parameter")
                .claims
                .is_empty()
        );

        // Shape errors reach the client as `invalid_request` (RFC 6749
        // §4.1.2.1), which is what a malformed parameter is.
        for malformed in ["not json", "[]", r#"{"userinfo":"name"}"#] {
            let error = refuse(&[("claims", malformed)]).expect_err("refused");
            assert!(
                matches!(error, AuthorizationError::Claims(_)),
                "{malformed:?} gave {error:?}"
            );
            assert_eq!(error.code(), "invalid_request");
        }

        // RFC 6749 §3.1: a parameter must not appear twice, and `claims` is
        // not the exception `resource` is.
        let mut pairs = base();
        pairs.push(("claims".to_owned(), "{}".to_owned()));
        pairs.push((
            "claims".to_owned(),
            r#"{"id_token":{"name":null}}"#.to_owned(),
        ));
        assert!(matches!(
            validate(
                &Parameters::from_pairs(pairs),
                CLIENT,
                &registration(),
                policy()
            ),
            Err(AuthorizationError::DuplicateParameter(_))
        ));
    }

    /// OIDC Core §5.2. Read here so that the preference travels with the
    /// authorization it was expressed in, and never refused: a language
    /// preference is a hint about presentation, so a client that misspells a
    /// tag gets the fallback rather than an error page.
    #[test]
    fn claims_locales_is_parsed_in_preference_order_and_never_refuses() {
        let request = with(&[("claims_locales", "ja-Kana-JP fr-CA fr")])
            .expect("a well-shaped claims_locales");
        assert_eq!(
            request.claims_locales.preferences(),
            ["ja-Kana-JP", "fr-CA", "fr"]
        );

        // A tag that is not shaped like one is dropped, and the rest stand.
        let salvaged =
            with(&[("claims_locales", "fr_CA en")]).expect("a misspelled tag is not an error");
        assert_eq!(salvaged.claims_locales.preferences(), ["en"]);

        // Absent is the same as expressing no preference.
        assert!(
            with(&[])
                .expect("no claims_locales")
                .claims_locales
                .is_empty()
        );
    }
}
