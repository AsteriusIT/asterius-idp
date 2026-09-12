//! Token introspection: the request, and what an answer may say (RFC 7662).
//!
//! # The endpoint's whole difficulty is in one sentence
//!
//! RFC 7662 §2.2, the note under the response definition:
//!
//! > If the introspection call is properly authorized but the token is not
//! > active, does not exist on this server, or the protected resource is not
//! > allowed to introspect this particular token, then the authorization
//! > server MUST return an introspection response with the `active` field set
//! > to `false`.
//!
//! Three different facts, one answer. §4 says why: "an attacker could use
//! this endpoint to determine whether a token is valid" — an endpoint that
//! distinguished "expired" from "not yours" from "never existed" is an oracle
//! that turns a stolen or guessed string into a verdict. So the only thing a
//! caller may learn is whether *this caller* holds an authorization to know
//! about *this token*, and even that is spelled as `active: false`.
//!
//! §2.3 keeps one refusal separate: a caller that is not authenticated or not
//! authorized to call the endpoint **at all** gets an HTTP 401 and no body.
//! That is a statement about the caller, not about a token, and it leaks
//! nothing.
//!
//! # What is decided here, and what is not
//!
//! Here: whether the request is well formed (§2.1), and — given a set of
//! verified claims and a decision about whether the caller may be told —
//! which members the response carries (§2.2, RFC 9449 §6.2, RFC 8693 §4).
//! Nothing in this file touches a key, a clock or a database.
//!
//! Not here: the client authentication, the signature check, the denylist and
//! grant reads, and the "is this caller a resource server for this audience"
//! question. Those need I/O and live in
//! `asterius_server::http::introspection`.
//!
//! # Why the response is built from a claim list rather than a struct
//!
//! §2.2's members are, with two exceptions, the access token's own claims
//! under the same names: `scope`, `client_id`, `sub`, `aud`, `iss`, `exp`,
//! `iat`, `nbf`, `jti`. RFC 9449 §6.2 adds `cnf` and RFC 8693 §4 adds `act` —
//! again the token's own. A struct would mean parsing every one of them into
//! a typed field and writing it back out, which is a second representation of
//! a value this server signed: a token whose `aud` is an array would have to
//! be re-rendered, and a re-rendering that differs from the signed bytes is a
//! resource server making an authorization decision on a value the issuer did
//! not assert.
//!
//! So [`describe`] *projects*: it copies the members it is allowed to copy,
//! exactly as they were signed, and adds the two that are not claims —
//! `active` and `token_type`. A claim not on the list is not copied, which is
//! what keeps a future claim from being published to a resource server by
//! accident.

use crate::form::Parameters;
use crate::revocation::TokenTypeHint;
use serde_json::{Map, Value};

/// The longest `token` this endpoint will look at.
///
/// The same bound the revocation endpoint uses, and for the same reason: the
/// two take the same values from the same kind of caller, and a value that is
/// too long to revoke is too long to introspect.
pub const MAX_TOKEN_LEN: usize = crate::revocation::MAX_TOKEN_LEN;

/// The `token_type` §2.2 says an active access token has.
///
/// "Bearer", as RFC 6749 §7.1 registers it — not `DPoP`. RFC 9449 §6.2 adds
/// `cnf` to the response and does not change `token_type`: a resource server
/// learns the binding from `cnf`, which is the value that was signed, and a
/// `token_type` that varied with the binding would be a second, unsigned
/// statement about it.
pub const BEARER: &str = "Bearer";

/// Why an introspection request was refused before any token was looked at.
///
/// Short, like [`crate::revocation::RevocationError`], and for a stronger
/// reason: §2.2's note collapses every fact *about a token* into
/// `active: false`, so the only refusals left are the ones that say the
/// request was not a request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IntrospectionError {
    /// A parameter was sent twice. RFC 6749 §3.2's rule, which §2.1 inherits
    /// by defining its request as a form post to the same profile.
    #[error("parameter {0} appeared more than once")]
    Duplicated(String),
    /// `token` is REQUIRED (§2.1).
    #[error("token is required")]
    MissingToken,
    /// A `token` longer than this endpoint reads.
    #[error("token is longer than this endpoint accepts")]
    TokenTooLong,
}

impl IntrospectionError {
    /// The OAuth error code (§2.3, which uses RFC 6749 §5.2's shape).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        "invalid_request"
    }

    /// The HTTP status. A 400 for everything a caller can fix; §2.3's 401 is
    /// about the *caller* and is never produced from this type.
    #[must_use]
    pub const fn status(&self) -> u16 {
        400
    }

    /// The caller-facing description: a constant per variant, never the
    /// request echoed back.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Duplicated(_) => "a parameter was sent more than once",
            Self::MissingToken => "token is required",
            Self::TokenTooLong => "token is too long",
        }
    }
}

/// A well-formed introspection request (§2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectionRequest<'a> {
    /// The value to describe, exactly as it arrived.
    pub token: &'a str,
    /// What the caller called it. §2.1 makes `token_type_hint` OPTIONAL and
    /// says the server "MUST extend its search" when the hint does not find
    /// it, so this never narrows anything — it is a label for the trail.
    pub hint: TokenTypeHint,
}

/// Reads the request body's parameters (§2.1).
///
/// # Errors
///
/// [`IntrospectionError::Duplicated`] when a parameter was sent twice,
/// [`IntrospectionError::MissingToken`] when `token` is absent or empty, and
/// [`IntrospectionError::TokenTooLong`] past [`MAX_TOKEN_LEN`].
// fuzz-target: introspection_request
pub fn parse(params: &Parameters) -> Result<IntrospectionRequest<'_>, IntrospectionError> {
    let token = params
        .get("token")
        .map_err(|duplicated| IntrospectionError::Duplicated(duplicated.0))?
        .ok_or(IntrospectionError::MissingToken)?;
    if token.is_empty() {
        // Named the parameter and gave it nothing. §2.1 does not describe
        // that, and answering `active: false` would spend a store round trip
        // on a request that carries no token to look up.
        return Err(IntrospectionError::MissingToken);
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(IntrospectionError::TokenTooLong);
    }
    let hint = params
        .get("token_type_hint")
        .map_err(|duplicated| IntrospectionError::Duplicated(duplicated.0))?;

    Ok(IntrospectionRequest {
        token,
        hint: TokenTypeHint::of(hint),
    })
}

/// The members [`describe`] copies out of a verified access token.
///
/// §2.2 defines `scope`, `client_id`, `username`, `token_type`, `exp`, `iat`,
/// `nbf`, `sub`, `aud`, `iss` and `jti`. `username` is absent from this list
/// on purpose: §2.2 calls it "a human-readable identifier for the resource
/// owner who authorized this token", and this server does not put one in an
/// access token. Reading a user row to add it would hand every registered
/// resource server a directory lookup keyed by a token — and the `sub` is
/// already the identifier a resource server is meant to key by (OIDC Core
/// §5.3.4). A deployment that wants `username` has to decide that
/// deliberately; this one does not answer a question it was not asked.
///
/// `token_type` is not here either: it is not a claim of the token, it is
/// asserted by this server, and [`describe`] writes [`BEARER`].
///
/// Beyond §2.2:
///
/// * `cnf` — RFC 9449 §6.2: the `cnf` claim with its `jkt` member is returned
///   in the introspection response, so a resource server that did not verify
///   the token itself still learns it is sender-constrained rather than
///   bearer. Omitting it would let such a resource server accept a
///   DPoP-bound token from whoever stole it.
/// * `act` and `scope` — RFC 8693 §4.1 and §4.2 define them for the
///   introspection response of a delegated token, which is where the actor
///   chain becomes visible to the resource server acting on it.
/// * `authorization_details` — RFC 9396 §9.2: the response carries the
///   authorization details a token conveys, and for a rich authorization
///   request they, and not `scope`, are the authority.
const PROJECTED: &[&str] = &[
    "act",
    "aud",
    "authorization_details",
    "client_id",
    "cnf",
    "exp",
    "iat",
    "iss",
    "jti",
    "nbf",
    "scope",
    "sub",
];

/// The private member naming the grant a token was minted under.
///
/// Not in [`PROJECTED`], because it is not published on the same terms. It is
/// a stable correlator for one authorization, and a tenant decides whether a
/// third-party resource server may hold one — the same decision `ast-txw`
/// made for the access token claim, taken again here rather than inherited,
/// and settled the same way: this member is emitted when, and only when, the
/// tenant puts the claim in the token. A deployment that withholds the claim
/// from the token and then hands it over at this endpoint would have spent
/// the decision without making it.
const GRANT_ID: &str = "grant_id";

/// The answer to an introspection request (§2.2).
///
/// A type rather than a bare `Value`, so that the inactive answer cannot be
/// built by forgetting a field: [`Self::inactive`] is the only constructor
/// that takes nothing, and it is what every "not active, not yours, never
/// existed" path returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectionResponse(Map<String, Value>);

impl IntrospectionResponse {
    /// §2.2's `active: false`, and nothing else.
    ///
    /// One value for the three cases the note collapses — expired or revoked,
    /// never issued here, and issued but none of this caller's business — so
    /// that no caller can tell them apart by reading the body. `active` is
    /// the only REQUIRED member and every other member is OPTIONAL, so this
    /// is a complete response.
    #[must_use]
    pub fn inactive() -> Self {
        let mut members = Map::new();
        members.insert("active".to_owned(), Value::Bool(false));
        Self(members)
    }

    /// The response as JSON (§2.2: `application/json`).
    #[must_use]
    pub fn into_json(self) -> Value {
        Value::Object(self.0)
    }

    /// Whether this response says the token is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.0.get("active") == Some(&Value::Bool(true))
    }

    /// The member names this response carries, for a test or a trail entry.
    #[must_use]
    pub fn members(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

/// Builds §2.2's response for a token this caller is allowed to be told about.
///
/// `claims` is the **verified** claim set: the caller of this function has
/// already checked the signature, the `typ`, the issuer and the expiry, and
/// has already established that this caller may learn about this token. This
/// function does not re-decide any of that — it cannot, it has no keys and no
/// clock — it decides only *which members are published*.
///
/// `grant_id` says whether the tenant exposes the private `grant_id` member;
/// see `GRANT_ID`.
///
/// A claim that is not on `PROJECTED` is dropped. That is the property
/// worth having: this server signs claims into access tokens that a resource
/// server has no business being handed by name — and the next one it learns
/// to sign is dropped here too, without anybody remembering to drop it.
#[must_use]
pub fn describe(claims: &Value, grant_id: bool) -> IntrospectionResponse {
    let mut members = Map::new();
    // §2.2: "active — REQUIRED. Boolean indicator of whether or not the
    // presented token is currently active." Written first and from here, so
    // that no claim of the token can decide it.
    members.insert("active".to_owned(), Value::Bool(true));
    members.insert("token_type".to_owned(), Value::String(BEARER.to_owned()));

    for name in PROJECTED {
        if let Some(value) = claims.get(*name) {
            // Copied, never re-rendered: the bytes a resource server acts on
            // are the bytes this server signed.
            members.insert((*name).to_owned(), value.clone());
        }
    }
    if let Some(value) = claims.get(GRANT_ID).filter(|_| grant_id) {
        members.insert(GRANT_ID.to_owned(), value.clone());
    }

    IntrospectionResponse(members)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params(pairs: &[(&str, &str)]) -> Parameters {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Parameters::from_pairs(owned)
    }

    /// §2.1: `token` is REQUIRED.
    #[test]
    fn a_request_without_a_token_is_not_a_request() {
        // Arrange
        let params = params(&[("token_type_hint", "access_token")]);

        // Act
        let parsed = parse(&params);

        // Assert
        assert_eq!(parsed.unwrap_err(), IntrospectionError::MissingToken);
    }

    /// A named parameter with nothing in it is the same refusal: there is no
    /// token to look up, so there is no store round trip to spend.
    #[test]
    fn an_empty_token_is_missing() {
        // Arrange
        let params = params(&[("token", "")]);

        // Act
        let parsed = parse(&params);

        // Assert
        assert_eq!(parsed.unwrap_err(), IntrospectionError::MissingToken);
    }

    /// RFC 6749 §3.2: a parameter sent twice makes the request ambiguous, and
    /// this endpoint must not pick one.
    #[test]
    fn a_duplicated_token_is_refused() {
        // Arrange
        let params = params(&[("token", "one"), ("token", "two")]);

        // Act
        let parsed = parse(&params);

        // Assert
        assert_eq!(
            parsed.unwrap_err(),
            IntrospectionError::Duplicated("token".to_owned())
        );
    }

    /// The bound is on the parser, before anything is hashed or decoded.
    #[test]
    fn a_token_past_the_bound_is_refused() {
        // Arrange
        let long = "t".repeat(MAX_TOKEN_LEN + 1);
        let params = params(&[("token", long.as_str())]);

        // Act
        let parsed = parse(&params);

        // Assert
        assert_eq!(parsed.unwrap_err(), IntrospectionError::TokenTooLong);
    }

    /// §2.1: the hint is a hint. An unknown one does not fail the request.
    #[test]
    fn an_unknown_hint_does_not_fail_the_request() {
        // Arrange
        let params = params(&[("token", "abc"), ("token_type_hint", "pigeon")]);

        // Act
        let parsed = parse(&params).expect("a well-formed request");

        // Assert
        assert_eq!(parsed.token, "abc");
        assert_eq!(parsed.hint, TokenTypeHint::Unrecognised);
    }

    /// §2.2: `active` is the only REQUIRED member, and the inactive answer
    /// carries nothing else — not a reason, not a hint, not an `exp`.
    #[test]
    fn the_inactive_answer_says_only_that_it_is_inactive() {
        // Arrange / Act
        let response = IntrospectionResponse::inactive();

        // Assert
        assert!(!response.is_active());
        assert_eq!(response.into_json(), json!({ "active": false }));
    }

    /// §2.2 plus RFC 9449 §6.2 and RFC 8693 §4: the members a resource server
    /// needs to act on the token it was handed.
    #[test]
    fn an_active_answer_carries_the_members_the_specs_define() {
        // Arrange
        let claims = json!({
            "iss": "https://as.example/t/demo",
            "aud": ["https://api.example/accounts"],
            "sub": "8f1a0d6a",
            "client_id": "billing",
            "scope": "accounts openid",
            "exp": 1_700_000_600_i64,
            "iat": 1_700_000_000_i64,
            "nbf": 1_700_000_000_i64,
            "jti": "BwcHBwcHBwcHBwcHBwcHBw",
            "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
            "act": { "sub": "service@example.test" },
            "authorization_details": [{ "type": "payment_initiation" }],
        });

        // Act
        let response = describe(&claims, false);

        // Assert
        let json = response.into_json();
        assert_eq!(json["active"], json!(true));
        assert_eq!(json["token_type"], json!(BEARER));
        for member in [
            "iss",
            "aud",
            "sub",
            "client_id",
            "scope",
            "exp",
            "iat",
            "nbf",
            "jti",
            "cnf",
            "act",
            "authorization_details",
        ] {
            assert_eq!(json[member], claims[member], "{member} was not projected");
        }
    }

    /// An `aud` array is handed over as an array. Re-rendering it as a string
    /// would be this server asserting something the signature does not cover.
    #[test]
    fn a_multi_valued_audience_is_copied_and_not_flattened() {
        // Arrange
        let claims = json!({ "aud": ["https://a.example", "https://b.example"] });

        // Act
        let json = describe(&claims, false).into_json();

        // Assert
        assert_eq!(json["aud"], claims["aud"]);
    }

    /// The projection is a list and not a copy of the token: a claim nobody
    /// decided to publish is not published.
    #[test]
    fn a_claim_outside_the_list_is_not_published() {
        // Arrange: `roles` is signed into access tokens (`ast-095`) and is not
        // an RFC 7662 §2.2 member.
        let claims = json!({ "sub": "ada", "roles": ["admin"], "amr": ["pwd"] });

        // Act
        let json = describe(&claims, false).into_json();

        // Assert
        assert!(json.get("roles").is_none(), "{json}");
        assert!(json.get("amr").is_none(), "{json}");
        assert_eq!(json["sub"], json!("ada"));
    }

    /// `ast-txw`: the grant correlator is a tenant's decision, and this
    /// endpoint takes it rather than making a second one.
    #[test]
    fn the_grant_id_follows_the_tenant_switch() {
        // Arrange
        let claims = json!({ "sub": "ada", "grant_id": "g-1" });

        // Act
        let withheld = describe(&claims, false).into_json();
        let exposed = describe(&claims, true).into_json();

        // Assert
        assert!(withheld.get("grant_id").is_none(), "{withheld}");
        assert_eq!(exposed["grant_id"], json!("g-1"));
    }

    /// A token that carries no `grant_id` gains no member from the switch
    /// being on: the response says what the token says.
    #[test]
    fn the_switch_invents_no_grant_id() {
        // Arrange
        let claims = json!({ "sub": "ada" });

        // Act
        let json = describe(&claims, true).into_json();

        // Assert
        assert!(json.get("grant_id").is_none(), "{json}");
    }

    /// §2.2: `username` is a member this deployment does not answer, and no
    /// claim may be projected into it — a token carrying `username` must not
    /// turn into a directory answer.
    #[test]
    fn no_username_is_published() {
        // Arrange
        let claims = json!({ "sub": "ada", "username": "ada@example.test" });

        // Act
        let json = describe(&claims, false).into_json();

        // Assert
        assert!(json.get("username").is_none(), "{json}");
    }

    /// `token_type` is this server's assertion and not the token's: a token
    /// claiming one cannot change what the response says.
    #[test]
    fn the_token_cannot_choose_its_own_token_type() {
        // Arrange
        let claims = json!({ "token_type": "N_A", "sub": "ada" });

        // Act
        let json = describe(&claims, false).into_json();

        // Assert
        assert_eq!(json["token_type"], json!(BEARER));
    }

    /// `active` is not projectable either: a token carrying `active: false`
    /// must not produce a response that contradicts itself.
    #[test]
    fn the_token_cannot_choose_whether_it_is_active() {
        // Arrange
        let claims = json!({ "active": false, "sub": "ada" });

        // Act
        let response = describe(&claims, true);

        // Assert
        assert!(response.is_active());
        assert_eq!(response.into_json()["active"], json!(true));
    }
}
