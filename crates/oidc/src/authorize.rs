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
use std::collections::BTreeSet;

use crate::claims::{ClaimsLocales, ClaimsRequest, ClaimsRequestError};
use crate::form::{Duplicated, Parameters};
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

/// The most `resource` indicators one request may name (RFC 8707).
pub const MAX_RESOURCES: usize = 8;

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
    /// A `request` or `request_uri` parameter was present.
    #[error("request objects are not supported")]
    RequestObjectNotSupported,
    /// `request_uri` in a *pushed* request (RFC 9126 §2.1).
    #[error("request_uri must not be present in a pushed authorization request")]
    RequestUriNotAllowed,
    /// `prompt=none` alongside another value.
    #[error("prompt=none cannot be combined with other values")]
    ConflictingPrompt,
    /// The `client_id` parameter is not the authenticated client.
    #[error("client_id does not match the authenticated client")]
    ClientMismatch,
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
}

impl Prompt {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Login => "login",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
        }
    }

    /// Parses one `prompt` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [Self::None, Self::Login, Self::Consent, Self::SelectAccount]
            .into_iter()
            .find(|p| p.as_str() == value)
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
    pub login_hint: Option<String>,
    /// RFC 8707 resource indicators.
    pub resources: BTreeSet<String>,
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
) -> Result<AuthorizationRequest, AuthorizationError> {
    // RFC 9126 §2.1: "The `request_uri` authorization request parameter is one
    // exception, and it MUST NOT be provided." A pushed request that carries
    // one is trying to chain a reference this server issued into a new push.
    if params.present("request_uri") {
        return Err(AuthorizationError::RequestUriNotAllowed);
    }
    // JAR (RFC 9101) is `ast-s36.1`. Until it exists, a `request` object is
    // refused rather than ignored — ignoring it would mean honouring the query
    // parameters the object was there to protect.
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

    let prompts = parse_prompts(params.get("prompt")?)?;

    let max_age = params
        .get("max_age")?
        .map(|raw| {
            raw.parse::<u32>()
                .map_err(|_| AuthorizationError::Invalid("max_age"))
        })
        .transpose()?;

    let acr_values = params
        .get("acr_values")?
        .map(|raw| raw.split_whitespace().map(ToOwned::to_owned).collect())
        .unwrap_or_default();

    let login_hint = bounded(params.get("login_hint")?, MAX_STATE_LEN, "login_hint")?;

    let resources = parse_resources(params.multi("resource"), registration)?;

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
        resources,
        dpop_jkt,
        claims,
        claims_locales,
        openid,
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

/// OIDC Core §3.1.2.1: `prompt` is a space-delimited list, and `none` must not
/// appear with anything else.
fn parse_prompts(raw: Option<&str>) -> Result<BTreeSet<Prompt>, AuthorizationError> {
    let mut prompts = BTreeSet::new();
    for token in raw.unwrap_or_default().split_whitespace() {
        let prompt = Prompt::parse(token).ok_or(AuthorizationError::Invalid("prompt"))?;
        prompts.insert(prompt);
    }
    // "none" means "do not interact"; combined with "login" it means both do
    // and do not interact. There is no reading of that which is safe to guess.
    if prompts.contains(&Prompt::None) && prompts.len() > 1 {
        return Err(AuthorizationError::ConflictingPrompt);
    }
    Ok(prompts)
}

/// RFC 8707 §2: each `resource` is an absolute URI without a fragment.
fn parse_resources(
    values: &[String],
    registration: &ClientRegistration,
) -> Result<BTreeSet<String>, AuthorizationError> {
    if values.len() > MAX_RESOURCES {
        return Err(AuthorizationError::Invalid("resource"));
    }
    let mut resources = BTreeSet::new();
    for raw in values {
        // "The URI MUST NOT include a fragment component." A fragment never
        // reaches a server, so two resource indicators differing only there
        // name one resource while looking like two.
        if raw.contains('#') {
            return Err(AuthorizationError::Invalid("resource"));
        }
        let parsed = url::Url::parse(raw).map_err(|_| AuthorizationError::Invalid("resource"))?;
        if !parsed.has_host() || parsed.cannot_be_a_base() {
            return Err(AuthorizationError::Invalid("resource"));
        }
        // The per-client allow-list is `ast-m9c.6`. Until a client has one,
        // an empty set means "no resource indicators permitted" rather than
        // "all of them": a client that has not been granted an audience must
        // not be able to name one.
        if !registration.resources.contains(raw) {
            return Err(AuthorizationError::Invalid("resource"));
        }
        resources.insert(raw.clone());
    }
    Ok(resources)
}

/// Base64url alphabet, unpadded.
const fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

#[cfg(test)]
mod tests {
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

    fn with(extra: &[(&str, &str)]) -> Result<AuthorizationRequest, AuthorizationError> {
        let mut pairs = base();
        for (k, v) in extra {
            pairs.push(((*k).to_owned(), (*v).to_owned()));
        }
        validate(&Parameters::from_pairs(pairs), CLIENT, &registration())
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
        validate(&Parameters::from_pairs(pairs), CLIENT, &registration()).map(|_| ())
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
    /// to protect.
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
        for wrong in ["-1", "1.5", "", "abc", "99999999999999999999"] {
            assert_eq!(
                refuse(&[("max_age", wrong)]),
                Err(AuthorizationError::Invalid("max_age")),
                "accepted max_age {wrong:?}"
            );
        }
    }

    /// RFC 8707 §2, and the per-client allow-list that is not built yet.
    #[test]
    fn a_resource_the_client_was_not_granted_is_refused() {
        // The fixture registers none, so every indicator is refused. An empty
        // allow-list must mean "none", not "all".
        for wrong in [
            "https://api.example/",
            "https://api.example/#frag",
            "not-a-uri",
        ] {
            assert_eq!(
                refuse(&[("resource", wrong)]),
                Err(AuthorizationError::Invalid("resource")),
                "accepted resource {wrong:?}"
            );
        }
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
            validate(&Parameters::from_pairs(pairs), CLIENT, &registration()),
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
