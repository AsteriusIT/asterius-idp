//! The AuthZEN Authorization API 1.0 wire format: what a PEP sends, and what a
//! PDP answers (`ast-pj0.1`).
//!
//! Authorization API 1.0 (Final, 2026-01-12) §6.1 gives the Access Evaluation
//! request four members — `subject`, `action` and `resource` REQUIRED, and
//! `context` OPTIONAL — over the information model of §5, and §6.2 makes the
//! response §5.5's Decision. This module is the translation between those
//! bytes and [`asterius_domain::policy`], and nothing else: no I/O, no
//! credential, no HTTP. `crate::http::access_evaluation` in the server crate is
//! the endpoint; the evaluation itself is
//! [`asterius_domain::ports::PolicyEngine`].
//!
//! # Why the wire format is not the model
//!
//! [`parse_evaluation`] produces a domain [`EvaluationRequest`] whose subject
//! carries **no groups, no roles and no grants**, because those are facts the
//! PEP does not get to assert: the endpoint resolves them from this server's
//! own store and attaches them afterwards. A parser that could fill them in
//! would be a parser through which a caller could claim membership of the
//! `finance` group by typing it. `asterius_domain::policy::request` documents
//! the split, and `docs/threat-model.md` carries the row.
//!
//! # Every bound is applied here, and before the work
//!
//! §11.7 asks a PDP to protect itself from "request payload size, the number of
//! requests, invalid JSON, nested JSON attacks, or memory consumption". The
//! number of requests is the endpoint's rate limiter
//! ([`asterius_domain::LimitedEndpoint::AccessEvaluation`]); the rest are here:
//!
//! * [`MAX_REQUEST_BYTES`] is checked against the raw body, before a parser is
//!   handed it — a bound applied after parsing is a bound applied after the
//!   work;
//! * [`MAX_DEPTH`] bounds the nesting of the whole document, walked with an
//!   explicit stack so that a deep document cannot be answered with a native
//!   one;
//! * the per-property bounds (`MAX_PROPERTIES`, `MAX_PROPERTY_DEPTH`,
//!   `MAX_PROPERTY_NODES`) are the domain's, applied by
//!   [`Properties::from_json`] as each bag is built.
//!
//! # I-JSON, and the duplicate member
//!
//! §11.5 asks for the I-JSON profile (RFC 7493) and, in particular, for member
//! names that are unique within an object (§2.3). `serde_json` keeps the *last*
//! of a repeated member and says nothing, so a document carrying `"id"` twice
//! would be evaluated against whichever copy happened to come second — a
//! difference of opinion between the PEP that wrote the request, an audit trail
//! that read the first, and a proxy in between. [`parse_evaluation`] refuses it
//! instead: a request that means two things is not a request.
//!
//! Nulls are omitted rather than written out on the way back (§11.5 again),
//! which is [`asterius_domain::policy::DecisionContext::to_json`]'s rule and is
//! kept here for the envelope around it.

use std::fmt;

use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};

use asterius_domain::policy::{
    Action, Context, Decision, EvaluationRequest, Properties, RequestError, Resource, Subject,
};

/// The scope a PEP's access token must carry to ask for a decision.
///
/// One scope for the whole Authorization API rather than one per endpoint:
/// §6.1's evaluation, §7's boxcar (`ast-pj0.2`) and §9's searches
/// (`ast-pj0.6`) are the same authority asked in three shapes — "this PEP may
/// put questions to the PDP" — and a deployment that wanted to separate them
/// would be separating things a PEP needs together to enforce one API call.
///
/// Namespaced with a dot, like `admin.policies:read`, so it cannot collide
/// with a scope a tenant's own resource server registers.
pub const SCOPE_EVALUATE: &str = "authzen.evaluate";

/// The largest evaluation request this PDP reads, in bytes (§11.7).
///
/// Sixty-four kibibytes. An evaluation is three short entities and a bag of
/// attributes about one subject and one resource; the interop suite's largest
/// request is under a kilobyte. What this bound is really for is the request
/// that is not an evaluation at all — a megabyte of nested arrays aimed at the
/// parser — and it is the same number the rule document's parser uses, because
/// an operator should not have to remember two.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// How deep the request document may nest (§11.7's "nested JSON attacks").
///
/// Sixteen. The request's own shape reaches three (`subject` → `properties` →
/// a value), and a property value is separately bounded at
/// [`asterius_domain::policy::request::MAX_PROPERTY_DEPTH`], so this is the
/// outer envelope rather than the working limit.
pub const MAX_DEPTH: usize = 16;

/// Why a request will not be read.
///
/// Every variant is §10.1.2's 400: the specification's error body is "an error
/// message string", and [`fmt::Display`] is that string. A refusal here is
/// never an authorization outcome — a request the PDP will not read has no
/// decision, which is precisely what distinguishes it from the deny that is a
/// 200 with `decision: false`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthzenError {
    /// Past [`MAX_REQUEST_BYTES`].
    #[error("the request body is longer than {MAX_REQUEST_BYTES} bytes")]
    TooLong,
    /// Past [`MAX_DEPTH`].
    #[error("the request nests deeper than {MAX_DEPTH} levels")]
    TooDeep,
    /// Not JSON, or not I-JSON: the message is the parser's.
    ///
    /// §10.1.1: "The top-level element of all request and response bodies MUST
    /// be a JSON object."
    #[error("the request body is not a JSON object: {0}")]
    Malformed(String),
    /// A member §5 or §6.1 makes REQUIRED is absent (§10.1.1).
    #[error("{0} is required")]
    Missing(&'static str),
    /// A member is present with a type the information model does not give it.
    #[error("{0} is not of the type the information model gives it")]
    WrongType(&'static str),
    /// The request is well-formed and outside the bounds the evaluator accepts.
    #[error(transparent)]
    Request(#[from] RequestError),
}

/// Reads an Access Evaluation request (§6.1).
///
/// The subject carries only what the PEP said about it; the endpoint resolves
/// the rest. See the module documentation.
///
/// Unknown members are ignored wherever they appear — §10.1.1: "To ensure
/// forward compatibility, receivers MUST ignore unknown fields present in
/// request or response bodies" — and no member's position is read, because
/// §10.1.1 also forbids assuming an order.
///
/// # Errors
///
/// [`AuthzenError`], which is always §10.1.2's 400 and whose `Display` is the
/// error message string that body carries.
// fuzz-target: authzen_request
pub fn parse_evaluation(body: &[u8]) -> Result<EvaluationRequest, AuthzenError> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(AuthzenError::TooLong);
    }
    let parsed: Value = unique_members(body)?;
    // Before the members are looked for, and on the document rather than on
    // each bag: what §11.7's nested payload costs is the walk, and a walk that
    // started at `subject` would already have paid for the nesting under
    // `context`.
    if depth_of(&parsed) > MAX_DEPTH {
        return Err(AuthzenError::TooDeep);
    }
    let document = parsed.as_object().ok_or_else(|| {
        AuthzenError::Malformed("the top-level element is not an object".to_owned())
    })?;

    let subject = entity(document, "subject")?;
    let action = entity(document, "action")?;
    let resource = entity(document, "resource")?;

    let subject = Subject::new(
        member(subject, "subject.type")?,
        member(subject, "subject.id")?,
        properties(subject, "subject.properties")?,
    )?;
    let action = Action::new(
        member(action, "action.name")?,
        properties(action, "action.properties")?,
    )?;
    let resource = Resource::new(
        member(resource, "resource.type")?,
        member(resource, "resource.id")?,
        properties(resource, "resource.properties")?,
    )?;

    // §6.1: `context` is OPTIONAL, and §5.4 makes it a bag of environment
    // attributes rather than an entity — there is no `type` or `id` to read, so
    // its members *are* the properties.
    let context = match document.get("context") {
        None | Some(Value::Null) => Properties::empty(),
        Some(Value::Object(members)) => Properties::new(members.clone())?,
        Some(_) => return Err(AuthzenError::WrongType("context")),
    };

    Ok(EvaluationRequest::new(
        subject,
        action,
        resource,
        Context::new(context),
    ))
}

/// §6.2's response: §5.5's Decision, and nothing else.
///
/// `context` is omitted when the decision carries none, rather than written as
/// an empty object: §5.5 makes it OPTIONAL and §11.5 asks for absent members to
/// be left out. A `decision` is always present, because §5.5 makes it REQUIRED
/// and a PEP reading a response with no `decision` has been told nothing.
#[must_use]
pub fn decision_response(decision: &Decision) -> Value {
    let mut object = Map::new();
    object.insert("decision".to_owned(), json!(decision.permit()));
    let context = decision.context().to_json();
    let empty = context.as_object().is_none_or(Map::is_empty);
    if !empty {
        object.insert("context".to_owned(), context);
    }
    Value::Object(object)
}

/// What the PDP answers when it could not take a decision at all (§10.1.2).
///
/// A **deny**, not a 500. §10.1.2 keeps its status codes for "an error
/// condition relating to the request or its processing", and a policy store
/// this server could not read is neither: the request was good and the PEP is
/// entitled to an answer it can enforce. The answer that is safe to enforce is
/// `false` — an enforcement point told "the PDP is broken" has no rule about
/// what to do next, and the two things it might invent are "fail open" and "let
/// the user through while we fix it".
///
/// The `error` member in the context is how the PEP tells this apart from a
/// policy that simply does not admit it, so that it can alert rather than show
/// somebody a permission dialogue. Its `status` is 500 because that is the
/// class of failure it stands for; the message is fixed and describes nothing
/// about this deployment's state, which an unauthenticated-by-policy caller has
/// not earned. The trail carries the real reason.
#[must_use]
pub fn engine_failure_response() -> Value {
    json!({
        "decision": false,
        "context": {
            "error": {
                "status": 500,
                "message": "the policy decision point could not take this decision",
            }
        }
    })
}

/// One of §6.1's three REQUIRED entities, as an object.
fn entity<'a>(
    document: &'a Map<String, Value>,
    name: &'static str,
) -> Result<&'a Map<String, Value>, AuthzenError> {
    match document.get(name) {
        None | Some(Value::Null) => Err(AuthzenError::Missing(name)),
        Some(Value::Object(members)) => Ok(members),
        Some(_) => Err(AuthzenError::WrongType(name)),
    }
}

/// A REQUIRED string member of an entity, named as the caller will report it.
///
/// `field` is the dotted spelling — `subject.id` — because that is what the
/// error message has to say for a PEP to find it: §10.1.1 requires the 400 and
/// leaves the body a message string, and "id is required" would not say which
/// entity's.
fn member<'a>(
    entity: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, AuthzenError> {
    let key = field.split('.').next_back().unwrap_or(field);
    match entity.get(key) {
        None | Some(Value::Null) => Err(AuthzenError::Missing(field)),
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(AuthzenError::WrongType(field)),
    }
}

/// §5's OPTIONAL `properties`, which is an object whenever it is there at all.
///
/// A `properties` of another type is refused rather than read as no attributes.
/// The domain's [`Properties::from_json`] takes the lenient reading, because at
/// that layer there is nobody to tell; here there is, and a PEP that sent an
/// array where the model has an object is a PEP whose request means something
/// other than what this server would have evaluated.
fn properties(
    entity: &Map<String, Value>,
    field: &'static str,
) -> Result<Properties, AuthzenError> {
    let key = field.split('.').next_back().unwrap_or(field);
    match entity.get(key) {
        None | Some(Value::Null) => Ok(Properties::empty()),
        Some(Value::Object(members)) => Ok(Properties::new(members.clone())?),
        Some(_) => Err(AuthzenError::WrongType(field)),
    }
}

/// How deep a value nests, counted with an explicit stack.
///
/// Iterative on purpose: this runs on a document an unauthenticated-by-policy
/// caller composed, and a recursive measurement would be bounded by the Rust
/// stack rather than by [`MAX_DEPTH`]. The parser's own recursion is bounded by
/// `serde_json`'s limit before this is reached.
fn depth_of(value: &Value) -> usize {
    let mut deepest = 0;
    let mut pending = vec![(value, 1_usize)];
    while let Some((value, depth)) = pending.pop() {
        deepest = deepest.max(depth);
        // Nothing below a level already over the bound changes the answer: the
        // caller only compares against MAX_DEPTH, and walking on would let a
        // document buy work with nesting the answer no longer depends on.
        if depth > MAX_DEPTH {
            return depth;
        }
        match value {
            Value::Array(items) => pending.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(members) => {
                pending.extend(members.values().map(|member| (member, depth + 1)));
            }
            _ => {}
        }
    }
    deepest
}

/// Parses `body` into a [`Value`], refusing an object with a repeated member.
///
/// RFC 7493 §2.3, as §11.5 asks for. See the module documentation for why the
/// last-one-wins that `serde_json` would otherwise do is not an option here.
fn unique_members(body: &[u8]) -> Result<Value, AuthzenError> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let parsed = IJson::deserialize(&mut deserializer)
        .and_then(|value| deserializer.end().map(|()| value))
        .map_err(|error| AuthzenError::Malformed(error.to_string()))?;
    Ok(parsed.0)
}

/// A [`Value`] that refuses duplicate member names as it is built.
struct IJson(Value);

impl<'de> Deserialize<'de> for IJson {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(IJsonVisitor)
    }
}

struct IJsonVisitor;

impl<'de> Visitor<'de> for IJsonVisitor {
    type Value = IJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value whose object members are unique")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(IJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(IJson(json!(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(IJson(json!(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E> {
        Ok(IJson(json!(value)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(IJson(Value::String(value.to_owned())))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(IJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(IJson(Value::Null))
    }

    fn visit_some<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(IJson(item)) = sequence.next_element()? {
            items.push(item);
        }
        Ok(IJson(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut members = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            let IJson(value) = map.next_value()?;
            if members.insert(name.clone(), value).is_some() {
                return Err(de::Error::custom(format!(
                    "the member `{name}` appears twice"
                )));
            }
        }
        Ok(IJson(Value::Object(members)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::policy::RuleSet;

    /// §6.1's own example, which is the shape every test below varies.
    fn request() -> Value {
        json!({
            "subject": {"type": "user", "id": "alice@example.com"},
            "resource": {"type": "account", "id": "123"},
            "action": {"name": "can_read"},
        })
    }

    fn parse(document: &Value) -> Result<EvaluationRequest, AuthzenError> {
        parse_evaluation(&serde_json::to_vec(document).expect("a JSON body"))
    }

    /// §6.1: three REQUIRED entities, read into §5's model.
    #[test]
    fn the_specifications_own_example_parses_into_the_model() {
        // Arrange
        let mut document = request();
        document["action"]["properties"] = json!({"method": "GET"});
        document["context"] = json!({"time": "1985-10-26T01:22-07:00"});

        // Act
        let parsed = parse(&document).expect("§6.1's example");

        // Assert
        assert_eq!(parsed.subject.kind(), "user");
        assert_eq!(parsed.subject.id(), "alice@example.com");
        assert_eq!(parsed.action.name(), "can_read");
        assert_eq!(parsed.resource.kind(), "account");
        assert_eq!(parsed.resource.id(), "123");
        assert_eq!(
            parsed.action.properties().get("method"),
            Some(&json!("GET"))
        );
        assert_eq!(
            parsed.context.properties().get("time"),
            Some(&json!("1985-10-26T01:22-07:00"))
        );
    }

    /// The property the whole endpoint rests on: a PEP describes the subject,
    /// it does not get to say what the subject *holds*.
    #[test]
    fn a_parsed_subject_holds_nothing_the_pep_claimed() {
        // Arrange: a request asserting every fact the engine resolves itself.
        let mut document = request();
        document["subject"]["properties"] =
            json!({"groups": ["finance"], "roles": ["admin"], "acr": "urn:acr:passkey"});

        // Act
        let parsed = parse(&document).expect("a well-formed request");

        // Assert
        assert!(parsed.subject.groups().is_empty(), "a PEP claimed a group");
        assert!(
            parsed.subject.grants().is_empty(),
            "a PEP claimed an authorization"
        );
        assert!(
            !parsed.subject.holds_role(
                None,
                &asterius_domain::RoleName::parse("admin").expect("a role name")
            ),
            "a PEP claimed a role"
        );
        assert_eq!(parsed.context.acr(), None, "a PEP claimed an acr");
    }

    /// §10.1.1: "If a required attribute in the information model is omitted,
    /// the server MUST return a Bad Request error."
    #[test]
    fn every_required_member_is_required() {
        for (removed, expected) in [
            ("subject", AuthzenError::Missing("subject")),
            ("action", AuthzenError::Missing("action")),
            ("resource", AuthzenError::Missing("resource")),
        ] {
            // Arrange
            let mut document = request();
            document
                .as_object_mut()
                .expect("an object")
                .remove(removed)
                .expect("the member was there");

            // Act / Assert
            assert_eq!(parse(&document).unwrap_err(), expected);
        }
    }

    /// §5.1 and §5.3 make `type` and `id` REQUIRED, §5.2 makes `name` REQUIRED.
    #[test]
    fn every_required_member_of_an_entity_is_required() {
        for (entity, field, expected) in [
            ("subject", "type", "subject.type"),
            ("subject", "id", "subject.id"),
            ("action", "name", "action.name"),
            ("resource", "type", "resource.type"),
            ("resource", "id", "resource.id"),
        ] {
            // Arrange
            let mut document = request();
            document[entity]
                .as_object_mut()
                .expect("an entity")
                .remove(field)
                .expect("the member was there");

            // Act / Assert
            assert_eq!(
                parse(&document).unwrap_err(),
                AuthzenError::Missing(expected)
            );
        }
    }

    /// §10.1.1: "receivers MUST ignore unknown fields present in request
    /// bodies".
    #[test]
    fn unknown_members_are_ignored_wherever_they_appear() {
        // Arrange
        let mut document = request();
        document["evaluations_semantic"] = json!("execute_all");
        document["subject"]["unheard_of"] = json!({"nested": [1, 2, 3]});
        document["action"]["unheard_of"] = json!(true);
        document["resource"]["unheard_of"] = json!(null);

        // Act
        let parsed = parse(&document).expect("unknown members are ignored");

        // Assert
        assert_eq!(parsed.subject.id(), "alice@example.com");
        assert!(parsed.subject.properties().is_empty());
    }

    /// §10.1.1: no ordering may be assumed. The same members, written in the
    /// other order, are the same request.
    #[test]
    fn member_order_is_not_read() {
        // Arrange
        let forwards = br#"{"subject":{"type":"user","id":"a"},"action":{"name":"r"},"resource":{"type":"t","id":"1"}}"#;
        let backwards = br#"{"resource":{"id":"1","type":"t"},"action":{"name":"r"},"subject":{"id":"a","type":"user"}}"#;

        // Act
        let first = parse_evaluation(forwards).expect("a request");
        let second = parse_evaluation(backwards).expect("the same request");

        // Assert
        assert_eq!(first, second);
    }

    /// A member of the wrong type is a 400 and not a silently empty value: a
    /// subject whose `id` is a number names nobody.
    #[test]
    fn a_member_of_the_wrong_type_is_refused() {
        // Arrange
        let mut document = request();
        document["subject"]["id"] = json!(42);

        // Act / Assert
        assert_eq!(
            parse(&document).unwrap_err(),
            AuthzenError::WrongType("subject.id")
        );
    }

    /// §5: `properties` is an object. An array is not one.
    #[test]
    fn properties_that_are_not_an_object_are_refused() {
        // Arrange
        let mut document = request();
        document["resource"]["properties"] = json!(["confidential"]);

        // Act / Assert
        assert_eq!(
            parse(&document).unwrap_err(),
            AuthzenError::WrongType("resource.properties")
        );
    }

    /// §11.7: payload size, applied to the bytes rather than to the parse.
    #[test]
    fn a_body_over_the_size_bound_is_refused() {
        // Arrange
        let mut document = request();
        document["resource"]["properties"] = json!({"blob": "x".repeat(MAX_REQUEST_BYTES)});
        let body = serde_json::to_vec(&document).expect("a JSON body");

        // Act / Assert
        assert!(body.len() > MAX_REQUEST_BYTES);
        assert_eq!(parse_evaluation(&body).unwrap_err(), AuthzenError::TooLong);
    }

    /// §11.7's "nested JSON attacks": depth is bounded for the document as a
    /// whole, whatever member the nesting is under.
    #[test]
    fn a_document_nested_past_the_bound_is_refused() {
        // Arrange
        let mut nest = json!("leaf");
        for _ in 0..MAX_DEPTH {
            nest = json!([nest]);
        }
        let mut document = request();
        document["context"] = json!({"deep": nest});

        // Act / Assert
        assert_eq!(parse(&document).unwrap_err(), AuthzenError::TooDeep);
    }

    /// The bound is on the document, so a body that is nothing but nesting is
    /// refused before any member is looked for.
    #[test]
    fn nesting_alone_is_refused_before_the_required_members_are_missed() {
        // Arrange
        let mut nest = json!(0);
        for _ in 0..(MAX_DEPTH + 4) {
            nest = json!({"a": nest});
        }
        let body = serde_json::to_vec(&nest).expect("a JSON body");

        // Act / Assert
        assert_eq!(parse_evaluation(&body).unwrap_err(), AuthzenError::TooDeep);
    }

    /// RFC 7493 §2.3, as §11.5 asks for: a repeated member is a request that
    /// means two things.
    #[test]
    fn a_repeated_member_is_refused_rather_than_resolved() {
        // Arrange: the second `id` is the one `serde_json` would have kept.
        let body = br#"{"subject":{"type":"user","id":"alice","id":"mallory"},
                        "action":{"name":"can_read"},
                        "resource":{"type":"account","id":"123"}}"#;

        // Act
        let refused = parse_evaluation(body).unwrap_err();

        // Assert
        let AuthzenError::Malformed(message) = &refused else {
            panic!("a repeated member was not refused: {refused:?}");
        };
        assert!(message.contains("`id` appears twice"), "{message}");
    }

    /// §10.1.1: the top-level element MUST be a JSON object.
    #[test]
    fn a_body_that_is_not_an_object_is_refused() {
        for body in [
            b"[]".as_slice(),
            b"\"a string\"".as_slice(),
            b"null".as_slice(),
            b"not json at all".as_slice(),
            b"".as_slice(),
        ] {
            // Act / Assert
            assert!(
                matches!(
                    parse_evaluation(body),
                    Err(AuthzenError::Malformed(_) | AuthzenError::WrongType(_))
                ),
                "accepted {:?} as a request",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// Trailing content is not a second request: a body that parses and then
    /// carries more bytes is malformed.
    #[test]
    fn a_body_with_trailing_content_is_refused() {
        // Arrange
        let mut body = serde_json::to_vec(&request()).expect("a JSON body");
        body.extend_from_slice(b"{\"subject\":{}}");

        // Act / Assert
        assert!(matches!(
            parse_evaluation(&body),
            Err(AuthzenError::Malformed(_))
        ));
    }

    /// §6.2 and §5.5: `decision` is the REQUIRED member, and the context a
    /// permit carries is the rule that produced it — which is what makes a
    /// permit explainable to whoever has to answer for it later.
    ///
    /// A decision whose context is *empty* would omit the member rather than
    /// write `{}` (§11.5). Every decision this engine produces names a rule or
    /// carries a reason, so that branch is not reachable from here; it exists
    /// because a second [`Decision`] source —
    /// an external PDP behind the same port — would be.
    #[test]
    fn a_permit_carries_the_rule_that_produced_it() {
        // Arrange
        let policy =
            RuleSet::parse(r#"{"version": 1, "rules": [{"id": "r", "effect": "permit"}]}"#)
                .expect("a catalogue");
        let decision = policy.evaluate(&parse(&request()).expect("a request"));

        // Act
        let rendered = decision_response(&decision);

        // Assert
        assert_eq!(rendered, json!({"decision": true, "context": {"id": "r"}}));
    }

    /// §5.5.1: a deny carries its explanation, and the response is still a 200
    /// shape — `decision: false` and a context.
    #[test]
    fn a_deny_carries_its_context() {
        // Arrange
        let policy = RuleSet::parse(
            r#"{"version": 1, "rules": [{"id": "no-writes", "effect": "deny",
                 "reason_admin": "writes are refused", "acr_values": ["urn:acr:passkey"]}]}"#,
        )
        .expect("a catalogue");
        let decision = policy.evaluate(&parse(&request()).expect("a request"));

        // Act
        let rendered = decision_response(&decision);

        // Assert
        assert_eq!(rendered["decision"], json!(false));
        assert_eq!(rendered["context"]["id"], json!("no-writes"));
        assert_eq!(
            rendered["context"]["reason_admin"],
            json!({"en": "writes are refused"})
        );
        assert_eq!(
            rendered["context"]["acr_values"],
            json!(["urn:acr:passkey"])
        );
    }

    /// §10.1.2: a PDP that could not decide still answers 200 with a deny, and
    /// says so in the context so that a PEP can alert instead of enforcing a
    /// policy that was never read.
    #[test]
    fn a_failure_is_a_deny_that_says_it_is_one() {
        // Act
        let rendered = engine_failure_response();

        // Assert
        assert_eq!(rendered["decision"], json!(false));
        assert_eq!(rendered["context"]["error"]["status"], json!(500));
        assert!(rendered["context"]["error"]["message"].is_string());
    }
}
