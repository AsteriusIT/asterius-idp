//! Token Exchange — RFC 8693.
//!
//! An agent holds a token and wants another one: narrower, audienced somewhere
//! else, and carrying the record that *it* is the party acting. That is the
//! whole of §2.1, and everything in this module exists to keep the second
//! token weaker than the first.
//!
//! # Narrowing only, and what that rules out
//!
//! RFC 8693 §1 describes exchange as producing a token "with different
//! properties" — which admits widening, and this server does not. Every
//! dimension is a subset relation, decided here or by the caller against the
//! values this module extracts:
//!
//! * **scope** ⊆ the subject token's scopes ∩ what the actor may hold;
//! * **audience / resource** ⊆ what the subject token's authorization already
//!   named, filtered by the tenant's registry (`invalid_target`, §2.2.2);
//! * **lifetime** ≤ what is left of the subject token;
//! * **the actor** is recorded, never dropped — see [`extend_chain`].
//!
//! A widening exchange is not a feature that was left out: it is the one shape
//! of this grant that turns a token into a bigger token, and a server that can
//! do it once can do it in a loop.
//!
//! # What v1 refuses outright
//!
//! * `requested_token_type` naming anything but an access token
//!   ([`ACCESS_TOKEN`]). §2.1 makes the parameter OPTIONAL and lets the server
//!   choose; refusing a *named* other type is honest, where silently issuing an
//!   access token to a client that asked for a SAML assertion is not.
//! * `actor_token`. §2.1 makes it OPTIONAL and this server derives the actor
//!   from client authentication instead: the authenticated client is the party
//!   that proved a key on *this* request, and a second, separately-obtained
//!   actor token would let a client name an actor it is not. Refused rather
//!   than ignored, because a client that sent one and got a token naming
//!   somebody else has no way to tell.
//! * A refresh token in the response. §2.2.1 makes it OPTIONAL; an exchanged
//!   token is a delegation, and a long-lived credential that renews a
//!   delegation without the delegator being present is the thing §5 warns
//!   about.
//!
//! # `act` and `may_act`
//!
//! §4.1 puts the current actor outermost and prior actors nested inside it, so
//! a resource server reading `act.client_id` is reading who is acting *now*.
//! [`extend_chain`] is the only thing that adds an actor and the only place the
//! depth bound is applied.
//!
//! §4.4's `may_act` is the subject token's own statement about who may act for
//! it. When it is there it decides, and [`may_act_authorizes`] refuses
//! anything it cannot fully check — a constraint this build does not
//! understand is a constraint it must not declare satisfied.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::form::Parameters;

// ---------------------------------------------------------------------------
// Token type identifiers (RFC 8693 §3)
// ---------------------------------------------------------------------------

/// `urn:ietf:params:oauth:token-type:access_token` (§3).
pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
/// `urn:ietf:params:oauth:token-type:refresh_token` (§3).
pub const REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
/// `urn:ietf:params:oauth:token-type:id_token` (§3).
pub const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
/// `urn:ietf:params:oauth:token-type:jwt` (§3).
pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// The largest `subject_token` this endpoint will look at.
///
/// The token endpoint caps the whole body at 16 KiB; this is the share one
/// parameter may take. A JWT access token this server issues is a few hundred
/// bytes, and the cap exists so that a caller cannot make the signature
/// verification below do work proportional to whatever it felt like sending.
pub const MAX_SUBJECT_TOKEN_BYTES: usize = 8 * 1024;

/// What kind of token was presented as the subject (§3).
///
/// Three of §3's identifiers and no more. `refresh_token` is absent because a
/// refresh token is not a statement about anybody — it is a credential — and
/// the SAML ones because this server does not issue or verify SAML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectTokenType {
    /// An access token this server issued (RFC 9068, `at+jwt`).
    AccessToken,
    /// An ID token this server issued (OIDC Core §2).
    IdToken,
    /// A JWT, which for this server is one of the two above.
    Jwt,
}

impl SubjectTokenType {
    /// The identifier this variant is spelled with (§3).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessToken => ACCESS_TOKEN,
            Self::IdToken => ID_TOKEN,
            Self::Jwt => JWT,
        }
    }

    /// Reads §3's identifier, or `None` for one this grant does not accept.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            ACCESS_TOKEN => Some(Self::AccessToken),
            ID_TOKEN => Some(Self::IdToken),
            JWT => Some(Self::Jwt),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an exchange request was not read (§2.2.2).
///
/// §2.2.2 gives this grant `invalid_request` and `invalid_target`, and refers
/// the rest to RFC 6749 §5.2. Every variant here maps to one of those two: a
/// failure that needs the *token* — expired, revoked, not ours — is
/// `invalid_grant` and is the caller's to raise, because it needs a key set
/// and a clock that this module deliberately does not have.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExchangeError {
    /// A parameter RFC 6749 §3.2 allows once appeared twice.
    #[error("parameter {0} appeared more than once")]
    Duplicated(String),
    /// `subject_token` is absent. §2.1 makes it REQUIRED.
    #[error("missing subject_token")]
    MissingSubjectToken,
    /// `subject_token` is longer than [`MAX_SUBJECT_TOKEN_BYTES`].
    #[error("the subject_token is too large")]
    SubjectTokenTooLarge,
    /// `subject_token_type` is absent. §2.1 makes it REQUIRED.
    #[error("missing subject_token_type")]
    MissingSubjectTokenType,
    /// `subject_token_type` names a type this grant does not exchange.
    #[error("unsupported subject_token_type")]
    UnsupportedSubjectTokenType,
    /// `requested_token_type` names anything but an access token.
    #[error("unsupported requested_token_type")]
    UnsupportedRequestedTokenType,
    /// `actor_token` or `actor_token_type` was sent. See the module docs.
    #[error("actor_token is not accepted; the actor is the authenticated client")]
    ActorTokenRefused,
    /// A `resource` or `audience` value is not a resource identifier, or there
    /// are more of them than an authorization request may carry.
    #[error("the requested target cannot be honoured")]
    Target,
}

impl ExchangeError {
    /// The OAuth 2.0 error code (RFC 8693 §2.2.2, RFC 6749 §5.2).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Target => "invalid_target",
            _ => "invalid_request",
        }
    }
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// A well-formed token exchange request (§2.1).
///
/// Shape only. Nothing here has been verified, authorized or narrowed: the
/// subject token is a string that arrived, and the targets are identifiers
/// that parse. Constructing one says the request can be *reasoned about*, not
/// that it will be granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeRequest<'a> {
    /// §2.1: "REQUIRED. A security token that represents the identity of the
    /// party on behalf of whom the request is being made."
    pub subject_token: &'a str,
    /// §2.1: "REQUIRED. An identifier […] that indicates the type of the
    /// security token in the `subject_token` parameter."
    pub subject_token_type: SubjectTokenType,
    /// §2.1's `scope`, unparsed. RFC 6749 §3.3's space-delimited list, and an
    /// absent one means "everything the subject token already had".
    pub scope: Option<&'a str>,
    /// §2.1's `audience` and `resource`, together.
    ///
    /// One set because this server answers them with one mechanism: RFC 8707's
    /// registry of resource servers, whose identifiers are absolute URIs. §2.1
    /// allows a logical `audience` name that is not a URI, and this server has
    /// nowhere to resolve one — a name it cannot resolve is a name it cannot
    /// bound the token to, which is `invalid_target`.
    pub targets: BTreeSet<String>,
}

/// Reads a token exchange request (§2.1).
///
/// Total: every input either produces a request or one of [`ExchangeError`]'s
/// refusals, and no input panics.
///
/// # Errors
///
/// The first [`ExchangeError`] that applies, in the order the parameters are
/// listed in §2.1 — the required ones before the optional ones, so that a
/// request missing `subject_token` is told that rather than being told about
/// an `audience` it may not have meant to send.
// fuzz-target: token_exchange_form
pub fn parse(params: &Parameters) -> Result<ExchangeRequest<'_>, ExchangeError> {
    let one = |name: &str| {
        params
            .get(name)
            .map_err(|error| ExchangeError::Duplicated(error.0))
    };

    let subject_token = one("subject_token")?.ok_or(ExchangeError::MissingSubjectToken)?;
    if subject_token.is_empty() {
        return Err(ExchangeError::MissingSubjectToken);
    }
    if subject_token.len() > MAX_SUBJECT_TOKEN_BYTES {
        return Err(ExchangeError::SubjectTokenTooLarge);
    }

    let raw_type = one("subject_token_type")?.ok_or(ExchangeError::MissingSubjectTokenType)?;
    let subject_token_type =
        SubjectTokenType::parse(raw_type).ok_or(ExchangeError::UnsupportedSubjectTokenType)?;

    // §2.1 makes `requested_token_type` OPTIONAL, with the server choosing
    // when it is absent. This server chooses an access token — the only thing
    // it mints from this grant — and refuses any other *named* type rather
    // than quietly substituting.
    if let Some(requested) = one("requested_token_type")?
        && requested != ACCESS_TOKEN
    {
        return Err(ExchangeError::UnsupportedRequestedTokenType);
    }

    if params.present("actor_token") || params.present("actor_token_type") {
        return Err(ExchangeError::ActorTokenRefused);
    }

    let scope = one("scope")?;

    // `audience` and `resource` are both repeatable — §2.1 says so for
    // `audience`, RFC 8707 §2 for `resource` — so neither is a duplicate
    // parameter, and two spellings of one identifier collapse into one member.
    let mut targets = BTreeSet::new();
    let requested: Vec<&String> = params
        .multi("audience")
        .iter()
        .chain(params.multi("resource"))
        .collect();
    if requested.len() > crate::authorize::MAX_RESOURCES {
        return Err(ExchangeError::Target);
    }
    for raw in requested {
        let identifier =
            asterius_domain::ResourceIdentifier::parse(raw).map_err(|_| ExchangeError::Target)?;
        targets.insert(identifier.as_str().to_owned());
    }

    Ok(ExchangeRequest {
        subject_token,
        subject_token_type,
        scope,
        targets,
    })
}

// ---------------------------------------------------------------------------
// Delegation (§4.1)
// ---------------------------------------------------------------------------

/// Why a delegation could not be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DelegationError {
    /// The chain would be deeper than the agent's policy allows.
    #[error("the delegation chain is deeper than this client's policy permits")]
    TooDeep,
    /// The stored chain is not a list of actor objects. A fact about a row
    /// this server wrote, so it is never described to a client.
    #[error("the stored actor chain is not a chain of actors")]
    Malformed,
}

impl DelegationError {
    /// The OAuth 2.0 error code (RFC 8693 §2.2.2).
    ///
    /// Both are `invalid_request`: the client asked for a delegation this
    /// server will not make, and the depth is a property of the request it
    /// sent rather than of the token it presented.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        "invalid_request"
    }
}

/// Adds `actor` to a delegation chain (§4.1).
///
/// > The `act` claim … The outermost `act` claim represents the current actor
/// > while nested `act` claims represent prior actors.
///
/// The chain is stored on the grant with the *current* actor first, which is
/// the order `AccessToken`'s renderer folds into nested `act` claims. So
/// adding an actor puts it at the front: an agent exchanging a token that
/// already names an actor becomes the party acting now, and the party that was
/// acting becomes a prior actor.
///
/// `max_depth` is the agent policy's `max_delegation_depth`, counted in
/// actors: a chain of one is the first delegation, so a policy of one permits
/// an agent to act for a user and permits nothing further.
///
/// # Errors
///
/// [`DelegationError::TooDeep`] when the resulting chain would exceed
/// `max_depth`, and [`DelegationError::Malformed`] when the stored chain is
/// not a list of objects — which is a row this server did not write.
pub fn extend_chain(
    previous: &[Value],
    actor: &str,
    max_depth: u8,
) -> Result<Vec<Value>, DelegationError> {
    if !previous.iter().all(Value::is_object) {
        return Err(DelegationError::Malformed);
    }
    let depth = previous.len().saturating_add(1);
    if depth > usize::from(max_depth) {
        return Err(DelegationError::TooDeep);
    }

    let mut chain = Vec::with_capacity(depth);
    let mut current = Map::new();
    // The actor is a client of this tenant, so `client_id` is the identity
    // claim that names it. §4.1's examples use `sub`; a `sub` here would be a
    // second spelling of a principal — and a `client_id` cannot be mistaken
    // for a subject identifier of this server (FAPI 2.0 SP §6.7, and
    // `ClientId::MINTED_PREFIX`), which is exactly the confusion an `act`
    // claim must not create.
    current.insert("client_id".to_owned(), Value::String(actor.to_owned()));
    chain.push(Value::Object(current));
    chain.extend_from_slice(previous);
    Ok(chain)
}

// ---------------------------------------------------------------------------
// may_act (§4.4)
// ---------------------------------------------------------------------------

/// Whether the subject token's `may_act` admits `actor` (§4.4).
///
/// > `may_act` … A claim that asserts that a party is authorized to become the
/// > actor and act on behalf of the subject.
///
/// Absent is not a refusal — §4.4 makes the claim OPTIONAL, and the policy
/// checks around this one decide the absent case. Present, it decides, and it
/// decides restrictively: the claim must be an object, it must be non-empty,
/// and *every* member must be one this build knows how to check and must match
/// the actor. An unrecognised member is a constraint the subject token's
/// issuer meant to impose, and a build that skipped it would be declaring a
/// condition satisfied that it never evaluated.
///
/// `client_id` and `sub` are the two members checked, both against the acting
/// client's identifier: this server's own tokens for a client put the
/// `client_id` in `sub` (RFC 9068 §2.2), so the two spellings name the same
/// party here.
#[must_use]
pub fn may_act_authorizes(may_act: Option<&Value>, actor: &str) -> bool {
    let Some(value) = may_act else {
        return true;
    };
    let Some(members) = value.as_object() else {
        return false;
    };
    if members.is_empty() {
        return false;
    }
    members.iter().all(|(name, value)| {
        matches!(name.as_str(), "client_id" | "sub") && value.as_str() == Some(actor)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params(pairs: &[(&str, &str)]) -> Parameters {
        Parameters::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<Vec<_>>(),
        )
    }

    fn minimal() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", "header.payload.signature"),
            ("subject_token_type", ACCESS_TOKEN),
        ]
    }

    #[test]
    fn the_two_required_parameters_are_enough() {
        // Arrange.
        let params = params(&minimal());

        // Act.
        let request = parse(&params).expect("a §2.1 request");

        // Assert.
        assert_eq!(request.subject_token, "header.payload.signature");
        assert_eq!(request.subject_token_type, SubjectTokenType::AccessToken);
        assert_eq!(request.scope, None);
        assert!(request.targets.is_empty());
    }

    #[test]
    fn a_request_without_a_subject_token_is_refused() {
        // Arrange: §2.1 makes it REQUIRED.
        let params = params(&[("subject_token_type", ACCESS_TOKEN)]);

        // Act.
        let error = parse(&params).expect_err("no subject token");

        // Assert.
        assert_eq!(error, ExchangeError::MissingSubjectToken);
        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn a_request_without_a_subject_token_type_is_refused() {
        // Arrange: §2.1 makes it REQUIRED, and a token whose type the server
        // guesses is a token verified under the wrong policy.
        let params = params(&[("subject_token", "a.b.c")]);

        // Act.
        let error = parse(&params).expect_err("no subject token type");

        // Assert.
        assert_eq!(error, ExchangeError::MissingSubjectTokenType);
    }

    #[test]
    fn a_refresh_token_is_not_a_subject_this_grant_exchanges() {
        // Arrange: §3 lists the identifier; a refresh token is a credential
        // and not a statement about a party.
        let mut pairs = minimal();
        pairs[2] = ("subject_token_type", REFRESH_TOKEN);

        // Act.
        let params = params(&pairs);
        let error = parse(&params).expect_err("a refresh token is not a subject");

        // Assert.
        assert_eq!(error, ExchangeError::UnsupportedSubjectTokenType);
    }

    #[test]
    fn the_three_accepted_subject_token_types_are_read() {
        for (raw, expected) in [
            (ACCESS_TOKEN, SubjectTokenType::AccessToken),
            (ID_TOKEN, SubjectTokenType::IdToken),
            (JWT, SubjectTokenType::Jwt),
        ] {
            // Arrange.
            let mut pairs = minimal();
            pairs[2] = ("subject_token_type", raw);

            // Act.
            let params = params(&pairs);
            let request = parse(&params).expect("an accepted type");

            // Assert.
            assert_eq!(request.subject_token_type, expected);
            assert_eq!(expected.as_str(), raw);
        }
    }

    #[test]
    fn asking_for_anything_but_an_access_token_is_refused() {
        // Arrange: v1 mints one kind of token (§2.1).
        let mut pairs = minimal();
        pairs.push(("requested_token_type", ID_TOKEN));

        // Act.
        let params = params(&pairs);
        let error = parse(&params).expect_err("v1 issues access tokens");

        // Assert.
        assert_eq!(error, ExchangeError::UnsupportedRequestedTokenType);
        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn asking_for_an_access_token_by_name_is_the_same_as_not_asking() {
        // Arrange.
        let mut pairs = minimal();
        pairs.push(("requested_token_type", ACCESS_TOKEN));

        // Act.
        let params = params(&pairs);
        let request = parse(&params).expect("the type this grant issues");

        // Assert.
        assert_eq!(request.subject_token_type, SubjectTokenType::AccessToken);
    }

    #[test]
    fn an_actor_token_is_refused_rather_than_ignored() {
        // Arrange: the actor is the authenticated client, so a request naming
        // another one must not silently get a token naming the client.
        let mut pairs = minimal();
        pairs.push(("actor_token", "x.y.z"));

        // Act.
        let params = params(&pairs);
        let error = parse(&params).expect_err("the actor is not the client's to choose");

        // Assert.
        assert_eq!(error, ExchangeError::ActorTokenRefused);
    }

    #[test]
    fn an_audience_and_a_resource_become_one_set_of_targets() {
        // Arrange: §2.1's `audience` and RFC 8707 §2's `resource`, including
        // one identifier spelled twice.
        let mut pairs = minimal();
        pairs.push(("audience", "https://api.example/"));
        pairs.push(("resource", "https://api.example/"));
        pairs.push(("resource", "https://reports.example/"));

        // Act.
        let params = params(&pairs);
        let request = parse(&params).expect("two targets");

        // Assert.
        assert_eq!(
            request.targets,
            BTreeSet::from([
                "https://api.example/".to_owned(),
                "https://reports.example/".to_owned()
            ])
        );
    }

    #[test]
    fn a_target_that_is_not_a_resource_identifier_is_invalid_target() {
        // Arrange: §2.2.2 gives this grant `invalid_target` for exactly this.
        let mut pairs = minimal();
        pairs.push(("audience", "the-billing-service"));

        // Act.
        let params = params(&pairs);
        let error = parse(&params).expect_err("a name this server cannot resolve");

        // Assert.
        assert_eq!(error, ExchangeError::Target);
        assert_eq!(error.code(), "invalid_target");
    }

    #[test]
    fn a_duplicated_single_valued_parameter_is_refused() {
        // Arrange: RFC 6749 §3.2. `scope` is not repeatable.
        let mut pairs = minimal();
        pairs.push(("scope", "a"));
        pairs.push(("scope", "b"));

        // Act.
        let params = params(&pairs);
        let error = parse(&params).expect_err("RFC 6749 §3.2");

        // Assert.
        assert_eq!(error, ExchangeError::Duplicated("scope".to_owned()));
    }

    #[test]
    fn an_oversized_subject_token_is_refused_on_length() {
        // Arrange.
        let huge = "a".repeat(MAX_SUBJECT_TOKEN_BYTES + 1);
        let params = params(&[
            ("subject_token", huge.as_str()),
            ("subject_token_type", ACCESS_TOKEN),
        ]);

        // Act.
        let error = parse(&params).expect_err("bounded before it is parsed");

        // Assert.
        assert_eq!(error, ExchangeError::SubjectTokenTooLarge);
    }

    #[test]
    fn the_current_actor_is_the_first_element_of_the_chain() {
        // Arrange: §4.1 — the outermost `act` is the current actor. The stored
        // chain is current-first, and `AccessToken` folds it outermost-first.
        let previous = vec![json!({ "client_id": "c.first" })];

        // Act.
        let chain = extend_chain(&previous, "c.second", 4).expect("within the bound");

        // Assert.
        assert_eq!(
            chain,
            vec![
                json!({ "client_id": "c.second" }),
                json!({ "client_id": "c.first" })
            ]
        );
    }

    #[test]
    fn the_first_delegation_is_a_chain_of_one() {
        // Arrange: a subject token with no actor, under the default policy of
        // one hop.
        // Act.
        let chain = extend_chain(&[], "c.agent", 1).expect("one hop is permitted");

        // Assert.
        assert_eq!(chain, vec![json!({ "client_id": "c.agent" })]);
    }

    #[test]
    fn a_chain_deeper_than_the_policy_is_refused() {
        // Arrange: a policy of one, and a token that already names an actor.
        let previous = vec![json!({ "client_id": "c.first" })];

        // Act.
        let error = extend_chain(&previous, "c.second", 1).expect_err("one hop and no more");

        // Assert.
        assert_eq!(error, DelegationError::TooDeep);
        assert_eq!(error.code(), "invalid_request");
    }

    #[test]
    fn a_stored_chain_that_is_not_a_chain_of_actors_is_refused() {
        // Arrange: a row this server did not write.
        let previous = vec![json!("c.first")];

        // Act.
        let error = extend_chain(&previous, "c.second", 8).expect_err("not an actor");

        // Assert.
        assert_eq!(error, DelegationError::Malformed);
    }

    #[test]
    fn an_absent_may_act_leaves_the_decision_to_policy() {
        // Arrange, Act, Assert: §4.4 makes the claim OPTIONAL.
        assert!(may_act_authorizes(None, "c.agent"));
    }

    #[test]
    fn a_may_act_naming_the_actor_authorizes_it() {
        // Arrange.
        let may_act = json!({ "client_id": "c.agent" });

        // Act, Assert.
        assert!(may_act_authorizes(Some(&may_act), "c.agent"));
    }

    #[test]
    fn a_may_act_naming_somebody_else_refuses_the_actor() {
        // Arrange.
        let may_act = json!({ "client_id": "c.other" });

        // Act, Assert.
        assert!(!may_act_authorizes(Some(&may_act), "c.agent"));
    }

    #[test]
    fn a_may_act_this_build_cannot_fully_check_refuses_the_actor() {
        // Arrange: the actor matches, and a second member names a condition
        // this build has no way to evaluate. Declaring it satisfied would be
        // inventing an authorization.
        let may_act = json!({ "client_id": "c.agent", "tenant": "other" });

        // Act, Assert.
        assert!(!may_act_authorizes(Some(&may_act), "c.agent"));
    }

    #[test]
    fn a_may_act_that_is_not_an_object_refuses_the_actor() {
        // Arrange: §4.4 makes it a JSON object.
        for value in [
            json!("c.agent"),
            json!([{ "client_id": "c.agent" }]),
            json!({}),
        ] {
            // Act, Assert.
            assert!(
                !may_act_authorizes(Some(&value), "c.agent"),
                "{value} was read as an authorization"
            );
        }
    }
}
