//! Client-Initiated Backchannel Authentication (CIBA Core 1.0): the request,
//! its validation and its acknowledgement.
//!
//! CIBA turns the authorization request inside out. There is no browser, no
//! redirect and no user agent: a client posts a *backchannel authentication
//! request* naming a person, and the person is asked on some device of their
//! own, minutes later and out of band. This module is the part of that which
//! is pure — the parameters of §7.1, the validation of §7.2 and the
//! `auth_req_id` of §7.3 — and it deliberately knows nothing about users,
//! keys or storage: resolving a hint to an account and verifying a signature
//! need a tenant's database and are the server crate's, so that everything
//! here can be fuzzed on a string.
//!
//! # What this endpoint does that no other endpoint here does
//!
//! It **names a person the caller has not spoken to**. Every other flow in
//! this server starts with the user in front of a browser; this one starts
//! with a client asserting who the user is, and the only thing standing
//! between an authenticated client and "make a pending approval land on that
//! person's phone" is [`validate`] plus the hint resolution the caller does
//! afterwards. That is why a hint that resolves to nobody is answered with
//! CIBA's own `unknown_user_id` and nothing more (see `docs/threat-model.md`),
//! and why the request is recorded as *pending* rather than acted on.
//!
//! # Push is not a mode here
//!
//! CIBA §10.3's push delivery posts the tokens themselves to a client-supplied
//! URL. FAPI-CIBA forbids it, and so does this server — at registration
//! ([`asterius_domain::TokenDeliveryMode`] has no `push` to parse into) and
//! again here, where a client whose registration somehow carried one is
//! refused with `unauthorized_client` rather than served.
//!
//! # Two shapes of request, one validator
//!
//! §7.1 sends the parameters in the form. §7.1.1 sends them as claims of a
//! signed JWT and forbids "any authentication request parameter" outside it.
//! Both end in the same [`Parameters`] and the same [`validate`], because a
//! second validator for the signed shape is a second set of rules and the one
//! that drifts is never the one being read.

use asterius_domain::entities::client::{ClientRegistration, TokenDeliveryMode};
use asterius_domain::{AuthorizationDetails, OpaqueToken, sha256_hex};
use std::collections::BTreeSet;
use time::Duration;

use crate::form::{Duplicated, Parameters};
use crate::grant_management::{self, GrantManagement};

/// Bits of entropy in an `auth_req_id`.
///
/// §7.3: "the `auth_req_id` ... MUST contain sufficient entropy" and §16
/// settles the number at 128. This draws the 256 every other bearer value in
/// this codebase draws, which is above the floor rather than at it.
pub const AUTH_REQ_ID_BITS: usize = 256;

/// The longest a pending backchannel authentication may stay pending.
///
/// Five minutes. §7.3 leaves `expires_in` to the OP; a pending CIBA request is
/// a notification waiting on somebody's phone, and every second it stays live
/// is a second in which the person may approve something they have forgotten
/// asking for. A `requested_expiry` may only *shorten* it.
pub const MAX_LIFETIME: Duration = Duration::seconds(300);

/// The shortest lifetime a `requested_expiry` may ask for.
///
/// Thirty seconds, which is about how long it takes to unlock a phone. A
/// client asking for less has asked for a request nobody could answer, and a
/// server that granted it would produce an `expired_token` every time.
pub const MIN_LIFETIME: Duration = Duration::seconds(30);

/// §7.3's `interval`, in poll and ping mode alike.
///
/// Five seconds, the same value the device flow advertises and the same one
/// RFC 8628 §3.5 makes the default — so a client that ignores the member and
/// a client that honours it poll at the same rate.
pub const POLL_INTERVAL: Duration = Duration::seconds(5);

/// The longest `client_notification_token` §7.1 permits: "MUST be ... no
/// longer than 1024 characters".
pub const MAX_NOTIFICATION_TOKEN_CHARS: usize = 1024;

/// The shortest `client_notification_token` this server accepts.
///
/// §7.1 asks for "sufficient entropy", which §16 puts at 128 bits. Twenty-two
/// characters is 128 bits base64url-encoded, so this is the shortest string
/// that *could* carry the entropy required. It is a floor on the length, not a
/// measurement of entropy — nothing can measure the entropy of one string —
/// but it refuses the `token`, the `1234` and the client id that would
/// otherwise be sent here and later believed to authenticate a notification.
pub const MIN_NOTIFICATION_TOKEN_CHARS: usize = 22;

/// The longest `binding_message` (§7.1).
///
/// Sixty-four characters. §7.1 has no number — it says the value "SHOULD be
/// relatively short and use a limited set of plain text characters" — and this
/// is the bound the acceptance criterion sets: long enough for a transaction
/// reference, short enough to be read off a lock screen next to the
/// consumption device's copy of the same string.
pub const MAX_BINDING_MESSAGE_CHARS: usize = 64;

/// The most scopes one request may name, as at every other endpoint here.
const MAX_SCOPES: usize = 64;

/// The most `acr_values` one request may name.
///
/// Space-delimited and ordered by preference (OIDC Core §3.1.2.1); a request
/// naming more than this is not expressing a preference, it is filling a
/// buffer.
const MAX_ACR_VALUES: usize = 16;

/// The longest hint value this server will read.
///
/// A `login_hint` is an address or a username, and an `id_token_hint` or a
/// `login_hint_token` is a JWT. Sixteen kilobytes is the whole body limit, so
/// this is a bound on the *field* — it keeps a megabyte of `login_hint` from
/// being trimmed, lower-cased and looked up before anything refuses it.
const MAX_HINT_CHARS: usize = 4096;

/// A freshly minted `auth_req_id` and the digest to store (§7.3).
///
/// The value reaches exactly two places: the acknowledgement, and — as a
/// digest — the database. The same treatment a device code gets, for the same
/// reason: whoever holds this string is who the token endpoint will answer.
pub struct MintedAuthReqId {
    value: OpaqueToken,
    digest: String,
}

impl MintedAuthReqId {
    /// Mints an `auth_req_id`.
    #[must_use]
    pub fn generate() -> Self {
        let value = OpaqueToken::generate_bits::<AUTH_REQ_ID_BITS>();
        let digest = sha256_hex(value.expose().as_bytes());
        Self { value, digest }
    }

    /// The value to put in the acknowledgement.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.value.expose()
    }

    /// The value to store.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl std::fmt::Debug for MintedAuthReqId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedAuthReqId")
            .field("value", &"[REDACTED]")
            .field("digest", &self.digest)
            .finish()
    }
}

/// A value that could not be an `auth_req_id` this server minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not an auth_req_id")]
pub struct MalformedAuthReqId;

/// Turns a presented `auth_req_id` into the digest to look up.
///
/// §7.3 constrains the charset itself: the value "MUST only contain characters
/// in the set `A-Z`, `a-z`, `0-9`, `.`, `-` and `_`". So a shape check here is
/// the specification's own rule rather than an invention, and it stands in
/// front of the database: a poll with a value that could not have been minted
/// costs a comparison rather than a query, which matters at an endpoint whose
/// whole protocol is polling.
///
/// # Errors
///
/// [`MalformedAuthReqId`] when the value could not have been issued here.
pub fn auth_req_id_digest_of(presented: &str) -> Result<String, MalformedAuthReqId> {
    let expected = AUTH_REQ_ID_BITS.div_ceil(6);
    if presented.len() != expected || !presented.bytes().all(is_auth_req_id_byte) {
        return Err(MalformedAuthReqId);
    }
    Ok(sha256_hex(presented.as_bytes()))
}

/// §7.3's charset: `A-Z`, `a-z`, `0-9`, `.`, `-`, `_`.
///
/// The `.` is in the set and not in what [`OpaqueToken`] draws; that is the
/// right way round. A minted value is a subset of what the specification
/// permits, and the acceptance is written from the specification so that a
/// later change of encoding does not silently narrow what a client may present.
const fn is_auth_req_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_'
}

/// Which of §7.1's three hints the request carried.
///
/// Exactly one, which the type is what guarantees: §7.1 says "exactly one of
/// the hints MUST be provided", and an enum cannot hold two. The value is
/// carried unresolved — turning it into a user needs a tenant's directory and
/// its keys — and it is *never* logged: a `login_hint` is an address and an
/// `id_token_hint` is a token.
#[derive(Clone, PartialEq, Eq)]
pub enum Hint {
    /// §7.1's `login_hint`: "a hint to the OpenID Provider regarding the end
    /// user for whom authentication is being requested". An address or a
    /// username here, resolved by the tenant's directory.
    Login(String),
    /// §7.1's `id_token_hint`: an ID token this server issued, whose `sub`
    /// names the user.
    IdToken(String),
    /// §7.1's `login_hint_token`: "a token containing information identifying
    /// the end user", minted by somebody else — §14 requires the OP to know
    /// which issuers it will take one from.
    LoginToken(String),
}

impl Hint {
    /// The parameter this hint arrived in, for a refusal record.
    #[must_use]
    pub const fn parameter(&self) -> &'static str {
        match self {
            Self::Login(_) => "login_hint",
            Self::IdToken(_) => "id_token_hint",
            Self::LoginToken(_) => "login_hint_token",
        }
    }

    /// The value, for the caller that resolves it.
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Self::Login(value) | Self::IdToken(value) | Self::LoginToken(value) => value,
        }
    }
}

impl std::fmt::Debug for Hint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A hint identifies a person to anybody who reads it. The *parameter*
        // is diagnosable; the value is not, and a debug line is exactly where
        // an address ends up in a log by accident.
        f.debug_struct("Hint")
            .field("parameter", &self.parameter())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// A backchannel authentication request, validated (§7.1, §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BackchannelRequest {
    /// The scopes, already narrowed to the client's registration and
    /// containing `openid` (§7.1: "`scope` ... MUST contain `openid`").
    pub scopes: BTreeSet<String>,
    /// RFC 9396 §3's rich authorization, already checked against the client's
    /// §9.2 allow-list.
    pub authorization_details: AuthorizationDetails,
    /// The one hint the request carried.
    pub hint: Hint,
    /// §7.1's `acr_values`, in the order of preference the client wrote.
    pub acr_values: Vec<String>,
    /// §7.1's `binding_message`, shown on both devices so a person can see
    /// that the thing on their phone is the thing in front of them.
    pub binding_message: Option<String>,
    /// §7.1.2's `user_code`, as presented. Never logged; verifying it is the
    /// caller's, and this server has no store to verify one against yet.
    pub user_code: Option<String>,
    /// §7.1's `requested_expiry`, clamped into [`MIN_LIFETIME`]..=[`MAX_LIFETIME`].
    ///
    /// This is the lifetime the acknowledgement will carry, so a client
    /// reading `expires_in` reads what was granted rather than what it asked
    /// for.
    pub expires_in: Duration,
    /// §7.1's `client_notification_token`, required in ping mode. Stored as a
    /// digest by the caller: it is the credential the *notification* will
    /// carry, so a database copy must not yield it.
    pub client_notification_token: Option<String>,
    /// Grant Management ID1 §5.4's pair, where the tenant offers it.
    pub grant_management: Option<GrantManagement>,
}

/// What the tenant and the client between them permit.
///
/// Assembled by the caller from the registration and the tenant's settings, so
/// that [`validate`] takes a decision rather than making one about
/// configuration it cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RequestPolicy {
    /// How the client is registered to be answered. `None` is a client with no
    /// CIBA registration at all, which is `unauthorized_client`.
    pub delivery_mode: Option<TokenDeliveryMode>,
    /// §4's `backchannel_user_code_parameter`: whether this client sends one.
    pub user_code_parameter: bool,
    /// Grant Management's own policy, which decides whether §5.4's parameters
    /// are read or ignored.
    pub grant_management: grant_management::Policy,
}

impl RequestPolicy {
    /// The policy of a client as it is registered.
    #[must_use]
    pub const fn of(
        registration: &ClientRegistration,
        grant_management: grant_management::Policy,
    ) -> Self {
        Self {
            delivery_mode: registration.backchannel_token_delivery_mode,
            user_code_parameter: registration.backchannel_user_code_parameter,
            grant_management,
        }
    }
}

/// Why a backchannel authentication request was refused (§13).
///
/// One variant per error code the specification names, plus the parameter that
/// provoked it where there is one. The codes are §13's own, and the mapping to
/// a status is §13's too: everything here is a 400 except `invalid_client`,
/// which client authentication owns and never reaches this validator, and
/// `access_denied`, which is a policy refusal rather than a malformed request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CibaError {
    /// §13's `invalid_request`, with the parameter at fault.
    #[error("{0} is missing, malformed or not permitted here")]
    Invalid(&'static str),
    /// RFC 6749 §3.1: a parameter sent twice is not a parameter with a value.
    #[error("{0} was sent more than once")]
    Duplicated(String),
    /// §7.1: "exactly one of the hints MUST be provided".
    #[error("exactly one of login_hint, id_token_hint or login_hint_token is required")]
    HintCount,
    /// §13's `invalid_scope`, which §7.1's "MUST contain `openid`" is the
    /// commonest cause of.
    #[error("the requested scope is not one this client may have")]
    InvalidScope,
    /// §13's `unauthorized_client`: no CIBA grant, or a delivery mode this
    /// server does not answer in.
    #[error("this client may not make a backchannel authentication request")]
    UnauthorizedClient,
    /// §13's `invalid_binding_message`.
    #[error(
        "binding_message is longer than {MAX_BINDING_MESSAGE_CHARS} characters or contains \
             something other than letters, digits and spaces"
    )]
    InvalidBindingMessage,
    /// §13's `missing_user_code`: the client is registered to send one and did
    /// not.
    #[error("this client is registered to send a user_code")]
    MissingUserCode,
    /// §13's `invalid_user_code`.
    #[error("the user_code was not accepted")]
    InvalidUserCode,
    /// §13's `unknown_user_id`: the hint named nobody here. Raised by the
    /// caller, which is what holds the directory.
    #[error("the hint does not identify a user")]
    UnknownUserId,
    /// §13's `expired_login_hint_token`.
    #[error("the login_hint_token has expired")]
    ExpiredLoginHintToken,
    /// §13's `access_denied`: a request this server will not make of this
    /// person, whatever it says.
    #[error("this request will not be put to the user")]
    AccessDenied,
}

impl CibaError {
    /// The `error` member of the response (§13).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::Duplicated(_) | Self::HintCount => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::InvalidBindingMessage => "invalid_binding_message",
            Self::MissingUserCode => "missing_user_code",
            Self::InvalidUserCode => "invalid_user_code",
            Self::UnknownUserId => "unknown_user_id",
            Self::ExpiredLoginHintToken => "expired_login_hint_token",
            Self::AccessDenied => "access_denied",
        }
    }

    /// The HTTP status the code is returned with (§13).
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            // §13: "`access_denied` ... HTTP 403". Everything else this
            // validator can produce is a bad request.
            Self::AccessDenied => 403,
            _ => 400,
        }
    }
}

impl From<Duplicated> for CibaError {
    fn from(duplicated: Duplicated) -> Self {
        Self::Duplicated(duplicated.0)
    }
}

impl From<asterius_domain::InvalidAuthorizationDetails> for CibaError {
    fn from(_: asterius_domain::InvalidAuthorizationDetails) -> Self {
        Self::Invalid("authorization_details")
    }
}

impl From<grant_management::GrantManagementError> for CibaError {
    fn from(_: grant_management::GrantManagementError) -> Self {
        // Grant Management ID1 §5.4's refusals are all `invalid_request`, and
        // CIBA §13 has no code of its own for them.
        Self::Invalid("grant_management_action")
    }
}

/// Every parameter §7.1 and §7.1.1 call an "authentication request parameter".
///
/// §7.1.1: when the request is a signed JWT, these "MUST NOT be present ...
/// outside the JWT". The list is here rather than at the call site because it
/// is the *same* list [`validate`] reads, so a parameter added to one is
/// refused outside the JWT by the other.
pub const AUTHENTICATION_PARAMETERS: [&str; 11] = [
    "scope",
    "client_notification_token",
    "acr_values",
    "login_hint_token",
    "id_token_hint",
    "login_hint",
    "binding_message",
    "user_code",
    "requested_expiry",
    "authorization_details",
    "grant_management_action",
];

/// Which shape of request arrived (§7.1 against §7.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    /// §7.1: the parameters are the form.
    Direct,
    /// §7.1.1: the parameters are the claims of this JWT, and the form carries
    /// nothing else that could contradict them.
    Signed(String),
}

/// Decides whether the body is a §7.1 request or a §7.1.1 signed one.
///
/// Three rules, and all three are about *contradiction* rather than about
/// syntax:
///
/// * A client that registered a `backchannel_authentication_request_signing_alg`
///   has said its requests are signed, so an unsigned one is refused rather
///   than accepted as a lesser form of the same thing (§7.1.1).
/// * A client that registered no algorithm cannot send a signed request:
///   there is no algorithm to insist on, and accepting one would mean
///   verifying a JWT with whatever `alg` it nominated.
/// * A signed request whose form *also* carries an authentication parameter is
///   refused whole. §7.1.1 says so in as many words, and the reason is the one
///   every request-object specification gives: a parameter outside the
///   signature is a parameter the signature does not cover.
///
/// `request_uri` is refused outright. CIBA defines no such parameter, and
/// honouring one would make this endpoint fetch a URL a client chose.
///
/// # Errors
///
/// [`CibaError::Invalid`] naming the parameter that made the body
/// contradictory.
pub fn submission(
    params: &Parameters,
    registration: &ClientRegistration,
) -> Result<Submission, CibaError> {
    if params.present("request_uri") {
        return Err(CibaError::Invalid("request_uri"));
    }
    let signed = params.get("request")?.filter(|value| !value.is_empty());
    let registered_alg = registration.backchannel_authentication_request_signing_alg;

    match (signed, registered_alg) {
        (None, None) => Ok(Submission::Direct),
        // A registration and a request that disagree about whether requests
        // are signed, in either direction. One refusal for both: telling a
        // client which way round it got it wrong says nothing it cannot read
        // off its own registration.
        (None, Some(_)) | (Some(_), None) => Err(CibaError::Invalid("request")),
        (Some(jwt), Some(_)) => {
            // §7.1.1: "MUST NOT be present ... outside the JWT".
            for name in AUTHENTICATION_PARAMETERS {
                if params.present(name) {
                    return Err(CibaError::Invalid("request"));
                }
            }
            Ok(Submission::Signed(jwt.to_owned()))
        }
    }
}

/// Validates a backchannel authentication request (§7.1, §7.2).
///
/// `params` is either the posted form (§7.1) or the claims of a verified
/// signed request rendered as parameters (§7.1.1) — the same rules apply to
/// both, which is the point of taking [`Parameters`] rather than either.
///
/// `client_id` is the *authenticated* client. FAPI-CIBA admits no public
/// client and this server authenticates every CIBA request, so a `client_id`
/// parameter is checked against the authenticated one and never believed.
///
/// §7.2's steps are followed in its order, with one deviation stated here:
/// `unauthorized_client` is decided first, before anything about the request
/// is read. A client with no CIBA registration is told what is wrong with
/// *it*, rather than being told what is wrong with a request it was never
/// entitled to make.
///
/// §7.2 step 6: "the OpenID Provider MUST ignore unrecognized request
/// parameters". Nothing here refuses a parameter for being unknown; the two
/// parameters that *are* refused (`request_uri`, and a `request` that
/// contradicts the registration) are refused by [`submission`] for being
/// recognised and wrong.
///
/// # Errors
///
/// The first [`CibaError`] that applies, with §13's code on it.
// fuzz-target: ciba_form
pub fn validate(
    params: &Parameters,
    client_id: &str,
    registration: &ClientRegistration,
    policy: RequestPolicy,
) -> Result<BackchannelRequest, CibaError> {
    // §13's `unauthorized_client`, and FAPI-CIBA's refusal of push. A
    // registration with no delivery mode is a client that did not register for
    // CIBA at all; one whose mode does not notify and does not poll is a
    // combination this server does not answer in.
    let Some(delivery_mode) = policy.delivery_mode else {
        return Err(CibaError::UnauthorizedClient);
    };
    if !registration
        .grant_types
        .contains(&asterius_domain::entities::client::GrantType::Ciba)
    {
        return Err(CibaError::UnauthorizedClient);
    }

    if let Some(presented) = params.get("client_id")?
        && presented != client_id
    {
        return Err(CibaError::Invalid("client_id"));
    }

    let hint = hint_of(params)?;
    let scopes = scopes_of(params, registration)?;
    let authorization_details = authorization_details_of(params, registration)?;
    let acr_values = acr_values_of(params)?;
    let binding_message = binding_message_of(params)?;
    let user_code = user_code_of(params, policy.user_code_parameter)?;
    let expires_in = expires_in_of(params)?;
    let client_notification_token = notification_token_of(params, delivery_mode)?;
    let grant_management = grant_management::parse(
        params.get("grant_management_action")?,
        params.get("grant_id")?,
        policy.grant_management,
    )?;

    Ok(BackchannelRequest {
        scopes,
        authorization_details,
        hint,
        acr_values,
        binding_message,
        user_code,
        expires_in,
        client_notification_token,
        grant_management,
    })
}

/// §7.1: "exactly one of the hints MUST be provided".
fn hint_of(params: &Parameters) -> Result<Hint, CibaError> {
    // An empty value is an absent parameter (RFC 6749 §3.1), which matters
    // here more than elsewhere: a form encoder that writes `login_hint=` for a
    // value its caller left unset would otherwise be sending two hints, one of
    // them empty, and be refused for it.
    let candidates = [
        params
            .get("login_hint")?
            .filter(|value| !value.is_empty())
            .map(|value| Hint::Login(value.to_owned())),
        params
            .get("id_token_hint")?
            .filter(|value| !value.is_empty())
            .map(|value| Hint::IdToken(value.to_owned())),
        params
            .get("login_hint_token")?
            .filter(|value| !value.is_empty())
            .map(|value| Hint::LoginToken(value.to_owned())),
    ];
    let mut found = candidates.into_iter().flatten();
    let (Some(hint), None) = (found.next(), found.next()) else {
        // Zero and two are the same refusal: telling a client which of the two
        // it managed would not help it, and §7.1 states the rule as one.
        return Err(CibaError::HintCount);
    };
    if hint.value().len() > MAX_HINT_CHARS {
        return Err(CibaError::Invalid("login_hint"));
    }
    Ok(hint)
}

/// §7.1: "`scope` ... MUST contain `openid`", and every scope must be one the
/// client registered.
fn scopes_of(
    params: &Parameters,
    registration: &ClientRegistration,
) -> Result<BTreeSet<String>, CibaError> {
    let mut scopes = BTreeSet::new();
    for token in params.get("scope")?.unwrap_or_default().split_whitespace() {
        // Refused rather than trimmed, as at every other endpoint: a client is
        // never handed an authorization narrower than the one it believes it
        // asked for.
        if !registration.scopes.contains(token) {
            return Err(CibaError::InvalidScope);
        }
        if scopes.len() == MAX_SCOPES {
            return Err(CibaError::InvalidScope);
        }
        scopes.insert(token.to_owned());
    }
    if !scopes.contains("openid") {
        // §13 gives `invalid_scope` for "the requested scope is invalid",
        // which is what a CIBA request without `openid` is: CIBA is an
        // OpenID Connect flow and there is no OAuth-only reading of it.
        return Err(CibaError::InvalidScope);
    }
    Ok(scopes)
}

/// RFC 9396 §3, narrowed to the client's registered types (§9.2).
fn authorization_details_of(
    params: &Parameters,
    registration: &ClientRegistration,
) -> Result<AuthorizationDetails, CibaError> {
    let Some(raw) = params.get("authorization_details")? else {
        return Ok(AuthorizationDetails::default());
    };
    let details = AuthorizationDetails::parse(raw)?;
    for name in details.types() {
        if !registration.authorization_details_types.contains(name) {
            return Err(CibaError::Invalid("authorization_details"));
        }
    }
    Ok(details)
}

/// §7.1's `acr_values`: space-delimited, most preferred first.
fn acr_values_of(params: &Parameters) -> Result<Vec<String>, CibaError> {
    let mut values = Vec::new();
    for value in params
        .get("acr_values")?
        .unwrap_or_default()
        .split_whitespace()
    {
        if values.len() == MAX_ACR_VALUES {
            return Err(CibaError::Invalid("acr_values"));
        }
        // Repeats are dropped rather than refused: `a a b` expresses the same
        // preference as `a b`, and refusing it would fail a request over a
        // duplicate in a list whose meaning is an order.
        let value = value.to_owned();
        if !values.contains(&value) {
            values.push(value);
        }
    }
    Ok(values)
}

/// §7.1's `binding_message`, against §13's `invalid_binding_message`.
///
/// The rule is deliberately narrow: letters, digits and spaces, and at most
/// [`MAX_BINDING_MESSAGE_CHARS`] of them. §7.1 asks for "a limited set of
/// plain text characters" and gives the reason — the value is *rendered on
/// two devices*, one of them an authentication device this server does not
/// control. A message carrying newlines, bidirectional overrides or combining
/// marks is one that can be made to display differently in the two places it
/// is compared, which defeats the only thing it is for.
///
/// Unicode letters and digits are accepted, not only ASCII: refusing `Facture
/// 42` or a Japanese reference would make the parameter unusable outside
/// English for no security gain.
fn binding_message_of(params: &Parameters) -> Result<Option<String>, CibaError> {
    let Some(message) = params
        .get("binding_message")?
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if message.chars().count() > MAX_BINDING_MESSAGE_CHARS {
        return Err(CibaError::InvalidBindingMessage);
    }
    if !message
        .chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || c == '-')
    {
        return Err(CibaError::InvalidBindingMessage);
    }
    Ok(Some(message.to_owned()))
}

/// §7.1.2's `user_code`.
///
/// Two of §13's codes live here, and a third answer that is neither. A client
/// registered with `backchannel_user_code_parameter` and sending nothing is
/// `missing_user_code`. A client sending a code it was not registered to send
/// is `invalid_user_code` rather than an ignored parameter: it believes the
/// person will be challenged, and a server that silently dropped the code
/// would put an unchallenged approval in front of them.
///
/// A code that *is* expected is only shape-checked here. Verifying it needs a
/// per-user secret, and this deployment has none — see the module note and
/// `docs/threat-model.md`. The caller is what refuses it.
fn user_code_of(params: &Parameters, expected: bool) -> Result<Option<String>, CibaError> {
    let presented = params.get("user_code")?.filter(|value| !value.is_empty());
    match (presented, expected) {
        (None, false) => Ok(None),
        (None, true) => Err(CibaError::MissingUserCode),
        (Some(_), false) => Err(CibaError::InvalidUserCode),
        (Some(code), true) => {
            // A shape bound in front of whatever verifies it, so that a
            // megabyte is refused before it is compared.
            if code.chars().count() > MAX_BINDING_MESSAGE_CHARS
                || code.chars().any(char::is_control)
            {
                return Err(CibaError::InvalidUserCode);
            }
            Ok(Some(code.to_owned()))
        }
    }
}

/// §7.1's `requested_expiry`, clamped rather than obeyed.
///
/// "A positive integer allowing the client to request the `expires_in` value".
/// A *request*: the acknowledgement's `expires_in` is never longer than
/// [`MAX_LIFETIME`], so a client asking for an hour gets five minutes and is
/// told so, and one asking for two seconds gets [`MIN_LIFETIME`] rather than a
/// request that expires before the phone finishes vibrating.
///
/// A `requested_expiry` that is not a positive integer is `invalid_request`
/// rather than an ignored parameter: a client that sent `600s` meant something
/// by it, and the difference between what it meant and what it would silently
/// have got is the whole lifetime of a pending approval.
fn expires_in_of(params: &Parameters) -> Result<Duration, CibaError> {
    let Some(raw) = params
        .get("requested_expiry")?
        .filter(|value| !value.is_empty())
    else {
        return Ok(MAX_LIFETIME);
    };
    let seconds: i64 = raw
        .parse()
        .map_err(|_| CibaError::Invalid("requested_expiry"))?;
    if seconds <= 0 {
        return Err(CibaError::Invalid("requested_expiry"));
    }
    Ok(Duration::seconds(seconds).clamp(MIN_LIFETIME, MAX_LIFETIME))
}

/// §7.1's `client_notification_token`: "REQUIRED if the Client is registered
/// to use Ping ... otherwise, it MUST NOT be provided".
fn notification_token_of(
    params: &Parameters,
    delivery_mode: TokenDeliveryMode,
) -> Result<Option<String>, CibaError> {
    let presented = params
        .get("client_notification_token")?
        .filter(|value| !value.is_empty());
    match (presented, delivery_mode.notifies_the_client()) {
        (None, false) => Ok(None),
        // Missing where §7.1 makes it REQUIRED, or present where §7.1 says it
        // "MUST NOT be provided". The second is refused rather than dropped: a
        // poll client is never called back, so a token it sent is a credential
        // nothing would ever present — and one a later switch to ping would
        // start presenting without anybody reviewing it.
        (None, true) | (Some(_), false) => Err(CibaError::Invalid("client_notification_token")),
        (Some(token), true) => {
            let length = token.chars().count();
            if !(MIN_NOTIFICATION_TOKEN_CHARS..=MAX_NOTIFICATION_TOKEN_CHARS).contains(&length) {
                return Err(CibaError::Invalid("client_notification_token"));
            }
            // §10.2 sends it in an `Authorization: Bearer` header, so it has
            // to be one: RFC 6750 §2.1's `token68` alphabet, and nothing that
            // could split a header.
            if !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
            {
                return Err(CibaError::Invalid("client_notification_token"));
            }
            Ok(Some(token.to_owned()))
        }
    }
}

// ---------------------------------------------------------------------------
// §10: token delivery
// ---------------------------------------------------------------------------

/// How much a `slow_down` raises the interval (§11: "at least 5 seconds").
///
/// The device flow's constant, by name rather than by value copied: a client
/// that implements RFC 8628 and CIBA polls both with one loop, and the two
/// flows telling it two different numbers would be a bug it could not see.
pub const SLOW_DOWN_INCREMENT: Duration = crate::device::SLOW_DOWN_INCREMENT;

/// How many `slow_down` answers a client is given before polling too fast is
/// `invalid_request` and it "MUST stop polling".
///
/// §11 makes `slow_down` "a variant of `authorization_pending`" — the request
/// is still live and the client should carry on, slower. A client that has
/// been told three times and still polls inside its interval is not slow to
/// adjust; it is not adjusting, and every further `slow_down` is a poll it
/// makes at a rate this server has already refused. Three is arbitrary in the
/// way any ceiling is, and it is small: at five seconds a step, three raises
/// cover a client whose clock or scheduler is coarse by up to fifteen seconds.
pub const MAX_SLOW_DOWNS: u32 = 3;

/// The interval past which polling too fast is no longer answered with
/// `slow_down` (§10.1, §11).
///
/// [`POLL_INTERVAL`] plus [`MAX_SLOW_DOWNS`] increments — twenty seconds. The
/// store compares a row's *current* interval against this before raising it:
/// a row already at the ceiling that is polled inside its interval is a client
/// that has ignored every `slow_down` it was given, and is told to stop.
pub const POLL_CEILING: Duration = Duration::seconds(20);

/// §10.1's token request, reduced to what the store is asked about.
///
/// Only the digest: the presented `auth_req_id` is a bearer credential and this
/// is the value that lives on in a log line or an error. `Debug` is derived
/// because there is nothing here that should not render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest {
    /// The SHA-256 of the presented `auth_req_id`, hex, as the row was stored.
    pub auth_req_id_digest: String,
}

/// Why a §10.1 token request could not be read.
///
/// Three variants, two codes. The first two are about the *form* — a
/// parameter missing or repeated — and are RFC 6749 §5.2's `invalid_request`.
/// The third is about the *credential*: a value outside §7.3's charset or of a
/// length this server never mints is "an `auth_req_id` that is invalid", which
/// §11 answers with `invalid_grant`. The distinction matters because a client
/// acts on the code: `invalid_request` says fix the request, `invalid_grant`
/// says the request was fine and the credential is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenRequestError {
    /// §10.1: `auth_req_id` is REQUIRED and was not sent.
    #[error("auth_req_id is required")]
    MissingAuthReqId,
    /// RFC 6749 §3.2: sent more than once.
    #[error("auth_req_id was sent more than once")]
    DuplicateAuthReqId,
    /// Not a value this server could have minted (§7.3's charset and this
    /// server's length).
    #[error("the auth_req_id is not valid")]
    Malformed,
}

impl TokenRequestError {
    /// The RFC 6749 §5.2 / CIBA §11 error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingAuthReqId | Self::DuplicateAuthReqId => "invalid_request",
            Self::Malformed => "invalid_grant",
        }
    }
}

/// Reads a §10.1 token request.
///
/// The grant type has already been dispatched by the token endpoint; what is
/// left is the one parameter this grant defines. The shape check is
/// [`auth_req_id_digest_of`]'s, so a value that could not have been issued here
/// costs a comparison and never a query — at an endpoint whose protocol is
/// polling, that is the difference between a cheap refusal and a table scan a
/// client can trigger at will.
///
/// # Errors
///
/// [`TokenRequestError`], with the code a client should act on.
// fuzz-target: ciba_token_request
pub fn token_request(params: &Parameters) -> Result<TokenRequest, TokenRequestError> {
    let presented = params
        .get("auth_req_id")
        .map_err(|_| TokenRequestError::DuplicateAuthReqId)?
        .filter(|value| !value.is_empty())
        .ok_or(TokenRequestError::MissingAuthReqId)?;
    let auth_req_id_digest =
        auth_req_id_digest_of(presented).map_err(|_| TokenRequestError::Malformed)?;
    Ok(TokenRequest { auth_req_id_digest })
}

/// §10.2's callback body: a JSON object holding the `auth_req_id` and nothing
/// else.
///
/// Nothing else on purpose. The ping "tells the Client that the authentication
/// result is ready"; the result itself is fetched from the token endpoint,
/// authenticated and proof-bound. A body that carried more would be push
/// delivery (§10.3) — the mode FAPI-CIBA forbids and this server does not
/// register.
#[must_use]
pub fn ping_body(auth_req_id: &str) -> String {
    serde_json::json!({ "auth_req_id": auth_req_id }).to_string()
}

/// §10.2's `Authorization` header: the `client_notification_token` "as a
/// bearer token".
///
/// The token was checked against RFC 6750 §2.1's `token68` alphabet when the
/// request was accepted ([`validate`]), so the value built here is a header
/// value by construction.
#[must_use]
pub fn ping_authorization(client_notification_token: &str) -> String {
    format!("Bearer {client_notification_token}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::Capabilities;
    use serde_json::json;

    const CLIENT: &str = "agent";

    fn registration_json(extra: &serde_json::Value) -> ClientRegistration {
        let mut document = json!({
            "client_name": "Agent",
            "redirect_uris": [],
            "grant_types": ["urn:openid:params:grant-type:ciba"],
            "response_types": [],
            "scope": "openid profile payments",
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            "backchannel_token_delivery_mode": "poll",
        });
        let object = document.as_object_mut().expect("object");
        for (key, value) in extra.as_object().expect("object") {
            object.insert(key.clone(), value.clone());
        }
        ClientRegistration::from_json(
            &serde_json::to_vec(&document).expect("the fixture serialises"),
            // CIBA is behind a flag, and a registration naming the grant is
            // refused where the flag is off — the parity `ast-o0t.3` bought,
            // which a fixture must respect rather than route around.
            Capabilities {
                ciba: true,
                ..Capabilities::default()
            },
        )
        .expect("the fixture registers")
    }

    fn registration() -> ClientRegistration {
        registration_json(&json!({}))
    }

    fn policy_of(registration: &ClientRegistration) -> RequestPolicy {
        RequestPolicy::of(registration, grant_management::Policy::default())
    }

    fn params(pairs: &[(&str, &str)]) -> Parameters {
        Parameters::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    /// A request with everything §7.1 makes mandatory and nothing else.
    fn minimal() -> Vec<(&'static str, &'static str)> {
        vec![("scope", "openid"), ("login_hint", "person@example.test")]
    }

    fn check(
        pairs: &[(&str, &str)],
        registration: &ClientRegistration,
    ) -> Result<BackchannelRequest, CibaError> {
        validate(
            &params(pairs),
            CLIENT,
            registration,
            policy_of(registration),
        )
    }

    /// §7.1 and §7.2: the smallest request the specification permits is
    /// accepted, and the lifetime it gets is the tenant's maximum.
    #[test]
    fn a_minimal_request_is_accepted_with_the_default_lifetime() {
        // Arrange
        let registration = registration();

        // Act
        let request = check(&minimal(), &registration).expect("a §7.1 request");

        // Assert
        assert_eq!(request.hint, Hint::Login("person@example.test".to_owned()));
        assert!(request.scopes.contains("openid"));
        assert_eq!(request.expires_in, MAX_LIFETIME);
        assert_eq!(request.client_notification_token, None);
    }

    /// §7.1: "exactly one of the hints MUST be provided".
    #[test]
    fn zero_or_two_hints_are_refused() {
        // Arrange
        let registration = registration();
        let none = [("scope", "openid")];
        let two = [
            ("scope", "openid"),
            ("login_hint", "person@example.test"),
            ("id_token_hint", "eyJ.a.b"),
        ];
        let three = [
            ("scope", "openid"),
            ("login_hint", "person@example.test"),
            ("id_token_hint", "eyJ.a.b"),
            ("login_hint_token", "eyJ.c.d"),
        ];

        // Act & Assert
        for pairs in [none.as_slice(), two.as_slice(), three.as_slice()] {
            assert_eq!(check(pairs, &registration), Err(CibaError::HintCount));
        }
    }

    /// RFC 6749 §3.1: an empty parameter is an omitted one, so `login_hint=`
    /// beside a real `id_token_hint` is one hint rather than two.
    #[test]
    fn an_empty_hint_parameter_is_an_absent_one() {
        // Arrange
        let registration = registration();
        let pairs = [
            ("scope", "openid"),
            ("login_hint", ""),
            ("id_token_hint", "eyJ.a.b"),
        ];

        // Act
        let request = check(&pairs, &registration).expect("one hint");

        // Assert
        assert_eq!(request.hint, Hint::IdToken("eyJ.a.b".to_owned()));
    }

    /// §7.1: "`scope` ... MUST contain `openid`".
    #[test]
    fn a_scope_without_openid_is_invalid_scope() {
        // Arrange
        let registration = registration();
        let pairs = [("scope", "profile"), ("login_hint", "person@example.test")];

        // Act & Assert
        assert_eq!(check(&pairs, &registration), Err(CibaError::InvalidScope));
        assert_eq!(CibaError::InvalidScope.code(), "invalid_scope");
    }

    /// An unregistered scope is refused rather than trimmed away.
    #[test]
    fn an_unregistered_scope_is_refused_rather_than_dropped() {
        // Arrange
        let registration = registration();
        let pairs = [
            ("scope", "openid banking"),
            ("login_hint", "person@example.test"),
        ];

        // Act & Assert
        assert_eq!(check(&pairs, &registration), Err(CibaError::InvalidScope));
    }

    /// §13's `unauthorized_client`: a client with no CIBA registration.
    #[test]
    fn a_client_without_the_ciba_grant_is_unauthorized() {
        // Arrange
        let registration = ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": "Ordinary",
                "redirect_uris": ["https://rp.example/cb"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "scope": "openid",
                "token_endpoint_auth_method": "private_key_jwt",
                "token_endpoint_auth_signing_alg": "ES256",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }))
            .expect("the fixture serialises"),
            Capabilities::default(),
        )
        .expect("the fixture registers");

        // Act
        let refusal = check(&minimal(), &registration);

        // Assert
        assert_eq!(refusal, Err(CibaError::UnauthorizedClient));
        assert_eq!(CibaError::UnauthorizedClient.code(), "unauthorized_client");
    }

    /// FAPI-CIBA: push is not a delivery mode here. It cannot be registered,
    /// so a policy carrying no mode is what a client that somehow held one
    /// would present as — and that is `unauthorized_client`, not a request
    /// this server tries to answer.
    #[test]
    fn a_client_with_no_delivery_mode_is_unauthorized() {
        // Arrange
        let registration = registration();
        let policy = RequestPolicy {
            delivery_mode: None,
            ..policy_of(&registration)
        };

        // Act
        let refusal = validate(&params(&minimal()), CLIENT, &registration, policy);

        // Assert
        assert_eq!(refusal, Err(CibaError::UnauthorizedClient));
    }

    /// §7.1: `client_notification_token` is REQUIRED in ping mode.
    #[test]
    fn ping_without_a_notification_token_is_invalid_request() {
        // Arrange
        let registration = registration_json(&json!({
            "backchannel_token_delivery_mode": "ping",
            "backchannel_client_notification_endpoint": "https://rp.example/ciba",
        }));

        // Act
        let refusal = check(&minimal(), &registration);

        // Assert
        assert_eq!(
            refusal,
            Err(CibaError::Invalid("client_notification_token"))
        );
        assert_eq!(
            CibaError::Invalid("client_notification_token").code(),
            "invalid_request"
        );
    }

    /// §7.1: the token is at most 1024 characters and carries at least 128
    /// bits, which twenty-two base64url characters is the shortest form of.
    #[test]
    fn a_notification_token_is_bounded_at_both_ends() {
        // Arrange
        let registration = registration_json(&json!({
            "backchannel_token_delivery_mode": "ping",
            "backchannel_client_notification_endpoint": "https://rp.example/ciba",
        }));
        let long = "a".repeat(MAX_NOTIFICATION_TOKEN_CHARS + 1);
        let short = "a".repeat(MIN_NOTIFICATION_TOKEN_CHARS - 1);
        let at_the_floor = "a".repeat(MIN_NOTIFICATION_TOKEN_CHARS);

        // Act & Assert
        for value in [long.as_str(), short.as_str(), "not a token68 value"] {
            let mut pairs = minimal();
            pairs.push(("client_notification_token", value));
            assert_eq!(
                check(&pairs, &registration),
                Err(CibaError::Invalid("client_notification_token")),
                "accepted {value:?}"
            );
        }

        let mut pairs = minimal();
        pairs.push(("client_notification_token", &at_the_floor));
        assert_eq!(
            check(&pairs, &registration)
                .expect("the floor itself is acceptable")
                .client_notification_token,
            Some(at_the_floor)
        );
    }

    /// §7.1: in poll mode the token "MUST NOT be provided". Refused rather
    /// than dropped — a client that sent one believes it will be called back.
    #[test]
    fn a_poll_client_may_not_send_a_notification_token() {
        // Arrange
        let registration = registration();
        let token = "a".repeat(32);
        let mut pairs = minimal();
        pairs.push(("client_notification_token", &token));

        // Act & Assert
        assert_eq!(
            check(&pairs, &registration),
            Err(CibaError::Invalid("client_notification_token"))
        );
    }

    /// §13's `invalid_binding_message`, both halves of the rule.
    #[test]
    fn a_binding_message_is_short_and_plain() {
        // Arrange
        let registration = registration();
        let too_long = "a".repeat(MAX_BINDING_MESSAGE_CHARS + 1);

        // Act & Assert
        for value in [
            too_long.as_str(),
            "line\nbreak",
            "bidi\u{202e}override",
            "punctuation!",
            "tab\there",
        ] {
            let mut pairs = minimal();
            pairs.push(("binding_message", value));
            assert_eq!(
                check(&pairs, &registration),
                Err(CibaError::InvalidBindingMessage),
                "accepted {value:?}"
            );
        }

        for value in ["Facture 42", "W4B-2xy", "請求書 42"] {
            let mut pairs = minimal();
            pairs.push(("binding_message", value));
            assert_eq!(
                check(&pairs, &registration)
                    .expect("a plain message")
                    .binding_message
                    .as_deref(),
                Some(value)
            );
        }
    }

    /// §13's `missing_user_code` and `invalid_user_code`.
    #[test]
    fn the_user_code_follows_the_registration_in_both_directions() {
        // Arrange
        let expecting = registration_json(&json!({"backchannel_user_code_parameter": true}));
        let not_expecting = registration();

        // Act & Assert
        assert_eq!(
            check(&minimal(), &expecting),
            Err(CibaError::MissingUserCode)
        );

        let mut pairs = minimal();
        pairs.push(("user_code", "1234"));
        assert_eq!(
            check(&pairs, &not_expecting),
            Err(CibaError::InvalidUserCode)
        );
        assert_eq!(
            check(&pairs, &expecting)
                .expect("a code the client was registered to send")
                .user_code
                .as_deref(),
            Some("1234")
        );
    }

    /// §7.1: `requested_expiry` shortens the lifetime and never lengthens it.
    #[test]
    fn requested_expiry_is_clamped_rather_than_obeyed() {
        // Arrange
        let registration = registration();
        let cases = [
            ("60", Duration::seconds(60)),
            ("3600", MAX_LIFETIME),
            ("1", MIN_LIFETIME),
        ];

        // Act & Assert
        for (requested, expected) in cases {
            let mut pairs = minimal();
            pairs.push(("requested_expiry", requested));
            assert_eq!(
                check(&pairs, &registration)
                    .expect("a positive integer")
                    .expires_in,
                expected,
                "requested_expiry={requested}"
            );
            assert!(expected <= MAX_LIFETIME, "over the tenant maximum");
        }

        for bad in ["0", "-30", "600s", "", " 60", "9999999999999999999999"] {
            let mut pairs = minimal();
            pairs.push(("requested_expiry", bad));
            if bad.is_empty() {
                assert_eq!(
                    check(&pairs, &registration)
                        .expect("an empty parameter is an absent one")
                        .expires_in,
                    MAX_LIFETIME
                );
            } else {
                assert_eq!(
                    check(&pairs, &registration),
                    Err(CibaError::Invalid("requested_expiry")),
                    "accepted requested_expiry={bad}"
                );
            }
        }
    }

    /// RFC 6749 §3.1: a repeated parameter is refused rather than resolved.
    #[test]
    fn a_repeated_parameter_is_refused() {
        // Arrange
        let registration = registration();
        let pairs = [
            ("scope", "openid"),
            ("scope", "openid profile"),
            ("login_hint", "person@example.test"),
        ];

        // Act & Assert
        assert_eq!(
            check(&pairs, &registration),
            Err(CibaError::Duplicated("scope".to_owned()))
        );
    }

    /// The authenticated client is the client; the parameter may only agree.
    #[test]
    fn a_client_id_naming_somebody_else_is_refused() {
        // Arrange
        let registration = registration();
        let mut pairs = minimal();
        pairs.push(("client_id", "somebody-else"));

        // Act & Assert
        assert_eq!(
            check(&pairs, &registration),
            Err(CibaError::Invalid("client_id"))
        );
    }

    /// §7.2 step 6: "the OpenID Provider MUST ignore unrecognized request
    /// parameters".
    #[test]
    fn an_unrecognised_parameter_is_ignored() {
        // Arrange
        let registration = registration();
        let mut pairs = minimal();
        pairs.push(("something_invented", "value"));

        // Act
        let request = check(&pairs, &registration).expect("an unknown parameter is ignored");

        // Assert
        assert_eq!(request.hint, Hint::Login("person@example.test".to_owned()));
    }

    /// §7.1.1: a client that registered a signing algorithm sends signed
    /// requests, and one that did not cannot send one.
    #[test]
    fn the_shape_of_the_request_follows_the_registration() {
        // Arrange
        let signing = registration_json(&json!({
            "backchannel_authentication_request_signing_alg": "ES256",
        }));
        let plain = registration();

        // Act & Assert
        assert_eq!(
            submission(&params(&minimal()), &plain).expect("an unsigned request"),
            Submission::Direct
        );
        assert_eq!(
            submission(&params(&minimal()), &signing),
            Err(CibaError::Invalid("request"))
        );
        assert_eq!(
            submission(&params(&[("request", "eyJ.a.b")]), &plain),
            Err(CibaError::Invalid("request"))
        );
        assert_eq!(
            submission(&params(&[("request", "eyJ.a.b")]), &signing).expect("a signed request"),
            Submission::Signed("eyJ.a.b".to_owned())
        );
    }

    /// §7.1.1: "any ... authentication request parameter ... MUST NOT be
    /// present outside the JWT".
    #[test]
    fn an_authentication_parameter_outside_a_signed_request_is_refused() {
        // Arrange
        let signing = registration_json(&json!({
            "backchannel_authentication_request_signing_alg": "ES256",
        }));

        // Act & Assert
        for name in AUTHENTICATION_PARAMETERS {
            let pairs = [("request", "eyJ.a.b"), (name, "anything")];
            assert_eq!(
                submission(&params(&pairs), &signing),
                Err(CibaError::Invalid("request")),
                "{name} was accepted beside a signed request"
            );
        }
    }

    /// CIBA defines no `request_uri`, and this endpoint dereferences nothing.
    #[test]
    fn a_request_uri_is_refused_at_an_endpoint_that_fetches_nothing() {
        // Arrange
        let registration = registration();

        // Act & Assert
        assert_eq!(
            submission(
                &params(&[("request_uri", "https://rp.example/o")]),
                &registration
            ),
            Err(CibaError::Invalid("request_uri"))
        );
    }

    /// §7.3: at least 128 bits, from a charset the specification names.
    #[test]
    fn an_auth_req_id_is_wide_enough_and_in_the_permitted_charset() {
        // Arrange
        const { assert!(AUTH_REQ_ID_BITS >= 128, "below CIBA §7.3's floor") };

        for _ in 0..32 {
            // Act
            let minted = MintedAuthReqId::generate();

            // Assert
            assert!(
                minted.expose().bytes().all(is_auth_req_id_byte),
                "outside §7.3's charset: {}",
                minted.expose()
            );
            assert_ne!(minted.expose(), minted.digest());
            assert_eq!(
                auth_req_id_digest_of(minted.expose()).expect("its own shape check"),
                minted.digest()
            );
        }
    }

    /// A value that could not have been minted costs a comparison, not a
    /// query.
    #[test]
    fn a_malformed_auth_req_id_is_refused_before_any_lookup() {
        // Arrange
        let minted = MintedAuthReqId::generate();
        let too_short = &minted.expose()[1..];
        let outside_the_charset = format!("{}!", &minted.expose()[1..]);

        // Act & Assert
        for value in ["", too_short, outside_the_charset.as_str()] {
            assert_eq!(
                auth_req_id_digest_of(value),
                Err(MalformedAuthReqId),
                "accepted {value:?}"
            );
        }
    }

    /// A hint is a person's identity. It does not go in a log line.
    #[test]
    fn a_hint_is_redacted_in_debug_output() {
        // Arrange
        let hint = Hint::Login("person@example.test".to_owned());

        // Act
        let rendered = format!("{hint:?}");

        // Assert
        assert!(!rendered.contains("person@example.test"), "{rendered}");
        assert!(rendered.contains("login_hint"), "{rendered}");
    }

    /// §13's codes and statuses, as the specification writes them.
    #[test]
    fn every_error_carries_its_specified_code_and_status() {
        // Arrange
        let cases = [
            (CibaError::Invalid("scope"), "invalid_request", 400),
            (CibaError::HintCount, "invalid_request", 400),
            (CibaError::InvalidScope, "invalid_scope", 400),
            (CibaError::UnauthorizedClient, "unauthorized_client", 400),
            (
                CibaError::InvalidBindingMessage,
                "invalid_binding_message",
                400,
            ),
            (CibaError::MissingUserCode, "missing_user_code", 400),
            (CibaError::InvalidUserCode, "invalid_user_code", 400),
            (CibaError::UnknownUserId, "unknown_user_id", 400),
            (
                CibaError::ExpiredLoginHintToken,
                "expired_login_hint_token",
                400,
            ),
            (CibaError::AccessDenied, "access_denied", 403),
        ];

        // Act & Assert
        for (error, code, status) in cases {
            assert_eq!(error.code(), code);
            assert_eq!(error.status(), status, "{code}");
        }
    }

    // ----- §10.1: the token request -----------------------------------------

    fn token_params(pairs: &[(&str, &str)]) -> Parameters {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Parameters::from_pairs(pairs)
    }

    /// §10.1: `auth_req_id` is REQUIRED. A request without one is malformed,
    /// and says so with `invalid_request` rather than with a code about a
    /// credential that was never presented.
    #[test]
    fn a_token_request_without_an_auth_req_id_is_invalid_request() {
        // Arrange
        let params = token_params(&[("grant_type", "urn:openid:params:grant-type:ciba")]);

        // Act
        let refused = token_request(&params).expect_err("no auth_req_id");

        // Assert
        assert_eq!(refused, TokenRequestError::MissingAuthReqId);
        assert_eq!(refused.code(), "invalid_request");
    }

    /// RFC 6749 §3.2: a parameter sent twice is a malformed request, and the
    /// parser must not pick one of the two values.
    #[test]
    fn a_token_request_with_two_auth_req_ids_is_invalid_request() {
        // Arrange
        let minted = MintedAuthReqId::generate();
        let params = token_params(&[
            ("auth_req_id", minted.expose()),
            ("auth_req_id", minted.expose()),
        ]);

        // Act
        let refused = token_request(&params).expect_err("two auth_req_ids");

        // Assert
        assert_eq!(refused, TokenRequestError::DuplicateAuthReqId);
        assert_eq!(refused.code(), "invalid_request");
    }

    /// §11: a value that "is invalid" is `invalid_grant`, and a value this
    /// server could not have minted is decided without a query — it is the
    /// same shape check every poll pays.
    #[test]
    fn a_token_request_with_a_malformed_auth_req_id_is_invalid_grant() {
        // Arrange
        let params = token_params(&[("auth_req_id", "not/an/auth_req_id")]);

        // Act
        let refused = token_request(&params).expect_err("malformed");

        // Assert
        assert_eq!(refused, TokenRequestError::Malformed);
        assert_eq!(refused.code(), "invalid_grant");
    }

    /// A minted value parses back to the digest that was stored for it, which
    /// is the whole round trip the token endpoint depends on.
    #[test]
    fn a_minted_auth_req_id_parses_to_its_own_digest() {
        // Arrange
        let minted = MintedAuthReqId::generate();
        let params = token_params(&[("auth_req_id", minted.expose())]);

        // Act
        let request = token_request(&params).expect("a minted value parses");

        // Assert
        assert_eq!(request.auth_req_id_digest, minted.digest());
    }

    /// The parser never renders the value it was handed: a `TokenRequest` in
    /// a log line is a digest, not a credential.
    #[test]
    fn a_parsed_token_request_does_not_render_the_auth_req_id() {
        // Arrange
        let minted = MintedAuthReqId::generate();
        let params = token_params(&[("auth_req_id", minted.expose())]);
        let request = token_request(&params).expect("parses");

        // Act
        let rendered = format!("{request:?}");

        // Assert
        assert!(!rendered.contains(minted.expose()));
    }

    // ----- §10.1, §11: the polling policy ------------------------------------

    /// §11's `slow_down` raises the interval by "at least 5 seconds", and the
    /// increment here is the same one the device flow uses, so a client that
    /// implements both polls both the same way.
    #[test]
    fn slow_down_adds_five_seconds() {
        assert_eq!(SLOW_DOWN_INCREMENT, Duration::seconds(5));
        assert_eq!(SLOW_DOWN_INCREMENT, crate::device::SLOW_DOWN_INCREMENT);
    }

    /// The ceiling is where `slow_down` stops being the answer and
    /// `invalid_request` starts: exactly `MAX_SLOW_DOWNS` increments above the
    /// advertised interval, so the three numbers cannot drift apart.
    #[test]
    fn the_poll_ceiling_is_the_interval_plus_the_permitted_slow_downs() {
        assert_eq!(
            POLL_CEILING,
            POLL_INTERVAL + SLOW_DOWN_INCREMENT * MAX_SLOW_DOWNS
        );
        assert_eq!(POLL_CEILING, Duration::seconds(20));
    }

    // ----- §10.2: the ping callback -------------------------------------------

    /// §10.2: "a JSON object ... containing the `auth_req_id`" and nothing
    /// else. A callback that carried scopes or a subject would be a token
    /// response by another name, which is push delivery — the mode this server
    /// refuses.
    #[test]
    fn the_ping_body_is_the_auth_req_id_and_nothing_else() {
        // Arrange
        let minted = MintedAuthReqId::generate();

        // Act
        let body = ping_body(minted.expose());

        // Assert
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(
            parsed,
            serde_json::json!({ "auth_req_id": minted.expose() })
        );
    }

    /// §10.2: the callback "MUST use the `client_notification_token` as a
    /// bearer token in the `Authorization` header".
    #[test]
    fn the_ping_authorization_is_the_notification_token_as_a_bearer() {
        assert_eq!(
            ping_authorization("8d67dc78-7faa-4d41-aabd-67707b374255"),
            "Bearer 8d67dc78-7faa-4d41-aabd-67707b374255"
        );
    }
}
