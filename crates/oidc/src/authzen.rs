//! The AuthZEN Authorization API 1.0 wire format: what a PEP sends, and what a
//! PDP answers (`ast-pj0.1`, `ast-pj0.2`).
//!
//! Authorization API 1.0 (Final, 2026-01-12) §6.1 gives the Access Evaluation
//! request four members — `subject`, `action` and `resource` REQUIRED, and
//! `context` OPTIONAL — over the information model of §5, and §6.2 makes the
//! response §5.5's Decision. §7 boxcars that request: an `evaluations` array
//! of the same objects, each one free to override the top-level entities that
//! serve as its defaults, answered by an array of Decisions in the same order.
//! This module is the translation between those bytes and
//! [`asterius_domain::policy`], and nothing else: no I/O, no
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
//!   [`Properties::from_json`] as each bag is built;
//! * [`MAX_EVALUATIONS`] bounds §7's array, which is the one member of this
//!   format whose length is a multiplier on the *work* rather than on the
//!   parse: one request, one rate-limiter token, and as many policy walks as
//!   the array is long.
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
    /// §8: a member that would name the entity being searched for is present,
    /// and §8 says that member is the one a search omits.
    #[error("{0} must be omitted from a search request: it is what the search is for")]
    NotSearchable(&'static str),
    /// §8.2: the page token is not one this PDP minted.
    #[error("the page token is not one this policy decision point issued")]
    PageToken,
    /// §8.2: "the parameters of the request must be identical" between pages.
    #[error(
        "the page token was issued for a different search request: the parameters of a          paginated request must be identical between pages"
    )]
    PageChanged,
    /// §8.2's `page.limit` is not a count.
    #[error("page.limit must be a positive integer")]
    PageLimit,
    /// §7.1's array holds more than [`MAX_EVALUATIONS`] requests.
    #[error("the evaluations array holds more than {MAX_EVALUATIONS} requests")]
    TooMany,
    /// `options.evaluations_semantic` is not one of §7.1.2.1's three values.
    #[error(
        "options.evaluations_semantic is not one of execute_all, deny_on_first_deny          or permit_on_first_permit"
    )]
    UnknownSemantic,
    /// One evaluation of §7.1's array will not be read, and the whole request
    /// is refused with it (§7.1.1: a required entity missing from an item *and*
    /// from the defaults is not an evaluation this PDP can take a decision on).
    ///
    /// The index is in the message because a PEP that boxcarred a hundred
    /// requests and got "action is required" back has been told nothing it can
    /// act on.
    #[error("evaluations[{index}]: {error}")]
    Item {
        /// Where in the request's array, counting from zero.
        index: usize,
        /// Why that evaluation will not be read.
        error: Box<AuthzenError>,
    },
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
    let document = read_document(body)?;
    // The document is its own defaults: §6.1's request is §7.1's request with
    // an array of one, and the two must not be able to read `subject` twice.
    evaluation(&document, &document)
}

/// The most evaluations §7.1's array may carry in one request.
///
/// A hundred, as a constant rather than a setting. Every other bound in this
/// module is about *parsing* a document, and an operator tuning one is tuning
/// how much text a PEP may send; this one is about how many policy walks a
/// single rate-limiter token buys, and the answer that is safe to give a
/// deployment is the same everywhere: enough that boxcarring is worth doing —
/// a page of documents, a menu of actions — and few enough that the endpoint's
/// worst case stays within the same order of magnitude as its typical one.
///
/// This is the number that makes the "one request, one token" charge in
/// `crate::http` honest: the amplification a PEP can buy with one token is
/// bounded by this, and `docs/threat-model.md` carries the row. Raise it and
/// the limiter's budget has to be divided by the same factor.
pub const MAX_EVALUATIONS: usize = 100;

/// How §7.1.2.1 says the array is to be executed.
///
/// Three values, and no room for a fourth: a PEP that names something else
/// gets [`AuthzenError::UnknownSemantic`] rather than the default, because a
/// short circuit silently executed in full is a bill the PEP did not agree to,
/// and a semantic from a later revision read as `execute_all` would be a
/// response a PEP interprets as something this PDP never did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvaluationsSemantic {
    /// "Execute all of the requests (potentially in parallel), return all of
    /// the results." The default (§7.1.2.1).
    #[default]
    ExecuteAll,
    /// "Deny on first denial (or failure) … This essentially works like the
    /// `&&` operator in programming languages."
    DenyOnFirstDeny,
    /// "Permit on first permit … the converse short-circuiting semantic,
    /// working like the `||` operator."
    PermitOnFirstPermit,
}

impl EvaluationsSemantic {
    /// The value as §7.1.2.1 spells it, which is also what the trail records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecuteAll => "execute_all",
            Self::DenyOnFirstDeny => "deny_on_first_deny",
            Self::PermitOnFirstPermit => "permit_on_first_permit",
        }
    }
}

/// An Access Evaluations request (§7.1), with every default already merged.
///
/// The merge happens in the parser and not at the endpoint on purpose: what
/// reaches [`asterius_domain::ports::PolicyEngine`] is a list of ordinary
/// [`EvaluationRequest`]s, each one complete, so the evaluator has no idea it
/// is in a boxcar and no rule can depend on which shape the PEP chose to write.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct EvaluationsRequest {
    /// The requests, in the order the PEP wrote them — which is the order
    /// §7.2 requires the decisions to come back in.
    ///
    /// Never empty: an absent or empty array is §6.1's single request, and
    /// that is one evaluation rather than none.
    pub evaluations: Vec<EvaluationRequest>,
    /// Which of §7.1.2.1's semantics to execute under.
    pub semantic: EvaluationsSemantic,
    /// Whether the PEP actually sent an `evaluations` array.
    ///
    /// §7.1: "If an evaluations array is NOT present or is empty, the Access
    /// Evaluations Request behaves in a backwards-compatible manner with the
    /// (single) Access Evaluation API Request." The *response* shape differs —
    /// §6.2's Decision rather than §7.2's array — so the endpoint has to know
    /// which of the two it was asked, and it cannot tell from a list of one.
    pub boxcar: bool,
}

/// Reads an Access Evaluations request (§7.1), defaults and all.
///
/// Every evaluation comes back complete: §7.1.1's top-level `subject`,
/// `action`, `resource` and `context` are applied to each item that does not
/// name its own, and an entity named by an item replaces the default **whole**
/// rather than merging member by member — §7.1.1 speaks of a key overriding a
/// key, and a subject merged from two places would be a principal neither side
/// wrote down.
///
/// # Errors
///
/// [`AuthzenError`], which is always §10.1.2's 400 for the *whole* request.
/// A per-evaluation *failure to decide* is not one of these: §7.2.1 makes that
/// a `decision: false` with an `error` in that item's context, which is
/// [`engine_failure_response`] and is the endpoint's business, not the
/// parser's.
// fuzz-target: authzen_evaluations
pub fn parse_evaluations(body: &[u8]) -> Result<EvaluationsRequest, AuthzenError> {
    let document = read_document(body)?;
    let semantic = semantic_of(&document)?;

    let items = match document.get("evaluations") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => Some(items),
        Some(_) => return Err(AuthzenError::WrongType("evaluations")),
    };
    let Some(items) = items.filter(|items| !items.is_empty()) else {
        // §7.1's backwards-compatible shape: the document itself is the one
        // request, read exactly as `parse_evaluation` reads it.
        return Ok(EvaluationsRequest {
            evaluations: vec![evaluation(&document, &document)?],
            semantic,
            boxcar: false,
        });
    };
    // §11.7, and before anything is built: the length is known from the parse,
    // so a thousand-request array costs the refusal rather than a thousand
    // entity constructions.
    if items.len() > MAX_EVALUATIONS {
        return Err(AuthzenError::TooMany);
    }

    let mut evaluations = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let at = |error: AuthzenError| AuthzenError::Item {
            index,
            error: Box::new(error),
        };
        let Value::Object(item) = item else {
            return Err(at(AuthzenError::WrongType("evaluations")));
        };
        evaluations.push(evaluation(item, &document).map_err(at)?);
    }

    Ok(EvaluationsRequest {
        evaluations,
        semantic,
        boxcar: true,
    })
}

/// §7.2's response: the decisions, in the order they were asked.
///
/// The top-level `decision` is omitted — §7.2: "In case the evaluations array
/// is present, it is RECOMMENDED that the decision key of the response be
/// omitted" — because there is no single decision to report and any value
/// written there would be one a careless PEP could enforce.
///
/// Each element is whatever the endpoint made of that evaluation:
/// [`decision_response`] for a decision taken, [`engine_failure_response`] for
/// §7.2.1's per-item error.
#[must_use]
pub fn evaluations_response(decisions: Vec<Value>) -> Value {
    let mut object = Map::new();
    object.insert("evaluations".to_owned(), Value::Array(decisions));
    Value::Object(object)
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

/// The bytes as a JSON object, with §11.7's and §11.5's bounds applied.
///
/// Every bound is on the *document*: what a nested payload costs is the walk,
/// and a walk that started at `subject` would already have paid for the
/// nesting under `context` — or, in a boxcar, under the ninety-ninth
/// evaluation.
pub(crate) fn read_document(body: &[u8]) -> Result<Map<String, Value>, AuthzenError> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(AuthzenError::TooLong);
    }
    let parsed: Value = unique_members(body)?;
    if depth_of(&parsed) > MAX_DEPTH {
        return Err(AuthzenError::TooDeep);
    }
    match parsed {
        Value::Object(document) => Ok(document),
        _ => Err(AuthzenError::Malformed(
            "the top-level element is not an object".to_owned(),
        )),
    }
}

/// One §6.1 request, read from `item` and completed from `defaults` (§7.1.1).
///
/// For a single request the two are the same map, which is the whole of the
/// relationship between §6.1 and §7.1: one evaluation with itself for defaults.
fn evaluation(
    item: &Map<String, Value>,
    defaults: &Map<String, Value>,
) -> Result<EvaluationRequest, AuthzenError> {
    let subject = entity(item, defaults, "subject")?;
    let action = entity(item, defaults, "action")?;
    let resource = entity(item, defaults, "resource")?;

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
    // its members *are* the properties. §7.1.1 gives it a default like the
    // others.
    let context = match specified(item, defaults, "context") {
        None => Properties::empty(),
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

/// §7.1.2.1's semantic, or `execute_all` where the PEP named none.
fn semantic_of(document: &Map<String, Value>) -> Result<EvaluationsSemantic, AuthzenError> {
    // §7.1.2 makes `options` an object and leaves it open for options this
    // revision does not define, which §10.1.1's "ignore unknown fields" covers.
    let options = match document.get("options") {
        None | Some(Value::Null) => return Ok(EvaluationsSemantic::default()),
        Some(Value::Object(members)) => members,
        Some(_) => return Err(AuthzenError::WrongType("options")),
    };
    match options.get("evaluations_semantic") {
        None | Some(Value::Null) => Ok(EvaluationsSemantic::default()),
        Some(Value::String(named)) => match named.as_str() {
            "execute_all" => Ok(EvaluationsSemantic::ExecuteAll),
            "deny_on_first_deny" => Ok(EvaluationsSemantic::DenyOnFirstDeny),
            "permit_on_first_permit" => Ok(EvaluationsSemantic::PermitOnFirstPermit),
            _ => Err(AuthzenError::UnknownSemantic),
        },
        Some(_) => Err(AuthzenError::WrongType("options.evaluations_semantic")),
    }
}

/// A member as the item gave it, or as the defaults did (§7.1.1).
///
/// A member written as `null` counts as not written: §11.5 asks senders to
/// omit absent members rather than spell them out, so reading `null` as an
/// override would make the two spellings of "I have nothing to say here" mean
/// opposite things.
fn specified<'a>(
    item: &'a Map<String, Value>,
    defaults: &'a Map<String, Value>,
    name: &'static str,
) -> Option<&'a Value> {
    item.get(name)
        .or_else(|| defaults.get(name))
        .filter(|value| !value.is_null())
}

/// One of §6.1's three REQUIRED entities, from the item or its default.
fn entity<'a>(
    item: &'a Map<String, Value>,
    defaults: &'a Map<String, Value>,
    name: &'static str,
) -> Result<&'a Map<String, Value>, AuthzenError> {
    match specified(item, defaults, name) {
        None => Err(AuthzenError::Missing(name)),
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
pub(crate) fn member<'a>(
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
pub(crate) fn properties(
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

    fn parse_many(document: &Value) -> Result<EvaluationsRequest, AuthzenError> {
        parse_evaluations(&serde_json::to_vec(document).expect("a JSON body"))
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

    // ---- §7: the boxcar -------------------------------------------------

    /// §7.1's first example: three requests, each carrying every entity, and
    /// no defaults at all.
    #[test]
    fn three_requests_that_share_nothing_parse_into_three_evaluations() {
        // Arrange
        let document = json!({
            "evaluations": [
                {"subject": {"type": "user", "id": "alice@example.com"},
                 "action": {"name": "can_read"},
                 "resource": {"type": "document", "id": "boxcarring.md"},
                 "context": {"time": "2024-05-31T15:22-07:00"}},
                {"subject": {"type": "user", "id": "alice@example.com"},
                 "action": {"name": "can_read"},
                 "resource": {"type": "document", "id": "subject-search.md"},
                 "context": {"time": "2024-05-31T15:22-07:00"}},
                {"subject": {"type": "user", "id": "alice@example.com"},
                 "action": {"name": "can_read"},
                 "resource": {"type": "document", "id": "resource-search.md"},
                 "context": {"time": "2024-05-31T15:22-07:00"}},
            ]
        });

        // Act
        let parsed = parse_many(&document).expect("§7.1's example");

        // Assert
        assert!(parsed.boxcar, "an evaluations array is a boxcar request");
        assert_eq!(parsed.semantic, EvaluationsSemantic::ExecuteAll);
        let resources: Vec<&str> = parsed
            .evaluations
            .iter()
            .map(|evaluation| evaluation.resource.id())
            .collect();
        assert_eq!(
            resources,
            ["boxcarring.md", "subject-search.md", "resource-search.md"],
            "§7.2: the decisions come back in the order they were asked"
        );
    }

    /// §7.1.1: "The top-level subject, action, resource, and context keys
    /// provide default values for each object in the evaluations array."
    #[test]
    fn a_top_level_entity_is_the_default_for_every_evaluation() {
        // Arrange: §7.1.1's second example.
        let document = json!({
            "subject": {"type": "user", "id": "alice@example.com"},
            "context": {"time": "2024-05-31T15:22-07:00"},
            "evaluations": [
                {"action": {"name": "can_read"},
                 "resource": {"type": "document", "id": "boxcarring.md"}},
                {"action": {"name": "can_read"},
                 "resource": {"type": "document", "id": "subject-search.md"}},
            ]
        });

        // Act
        let parsed = parse_many(&document).expect("§7.1.1's example");

        // Assert
        for evaluation in &parsed.evaluations {
            assert_eq!(evaluation.subject.id(), "alice@example.com");
            assert_eq!(evaluation.action.name(), "can_read");
            assert_eq!(
                evaluation.context.properties().get("time"),
                Some(&json!("2024-05-31T15:22-07:00"))
            );
        }
    }

    /// §7.1.1: "Any of these keys specified within an individual evaluation
    /// object overrides the corresponding top-level default." The third
    /// request of §7.1.1's last example asks a different action.
    #[test]
    fn an_evaluation_overrides_the_default_it_names() {
        // Arrange
        let document = json!({
            "subject": {"type": "user", "id": "alice@example.com"},
            "action": {"name": "can_read"},
            "evaluations": [
                {"resource": {"type": "document", "id": "boxcarring.md"}},
                {"action": {"name": "can_edit"},
                 "resource": {"type": "document", "id": "resource-search.md"}},
            ]
        });

        // Act
        let parsed = parse_many(&document).expect("§7.1.1's example");

        // Assert
        assert_eq!(parsed.evaluations[0].action.name(), "can_read");
        assert_eq!(parsed.evaluations[1].action.name(), "can_edit");
    }

    /// An override replaces the default entity **whole**: §7.1.1 speaks of a
    /// key overriding a key, not of members merging into one. A subject that
    /// was merged member by member would let an evaluation name an `id` while
    /// silently keeping the default's `type`, and the request would be about a
    /// principal neither the PEP nor the PDP wrote down.
    #[test]
    fn an_override_replaces_the_default_entity_rather_than_merging_into_it() {
        // Arrange
        let document = json!({
            "subject": {"type": "user", "id": "alice@example.com",
                        "properties": {"department": "sales"}},
            "action": {"name": "can_read"},
            "resource": {"type": "document", "id": "1"},
            "evaluations": [{"subject": {"type": "machine", "id": "bot-1"}}],
        });

        // Act
        let parsed = parse_many(&document).expect("a boxcar request");

        // Assert
        assert_eq!(parsed.evaluations[0].subject.kind(), "machine");
        assert_eq!(parsed.evaluations[0].subject.id(), "bot-1");
        assert!(
            parsed.evaluations[0].subject.properties().is_empty(),
            "a default's properties survived an override"
        );
    }

    /// §7.1.1: "Because subject, action, and resource are required for a valid
    /// evaluation, any of these keys omitted from an evaluation object MUST be
    /// provided as a top-level key." Missing from both is §10.1.1's 400 for
    /// the whole request, and the message names the evaluation it was missing
    /// from.
    #[test]
    fn an_entity_missing_from_an_evaluation_and_from_the_defaults_is_refused() {
        // Arrange
        let document = json!({
            "subject": {"type": "user", "id": "alice@example.com"},
            "evaluations": [
                {"action": {"name": "can_read"},
                 "resource": {"type": "document", "id": "1"}},
                {"resource": {"type": "document", "id": "2"}},
            ]
        });

        // Act
        let refused = parse_many(&document).unwrap_err();

        // Assert
        let AuthzenError::Item { index, error } = &refused else {
            panic!("a missing action was not refused: {refused:?}");
        };
        assert_eq!(*index, 1);
        assert_eq!(**error, AuthzenError::Missing("action"));
        assert!(refused.to_string().contains("evaluations[1]"), "{refused}");
    }

    /// §7.1: "If an evaluations array is NOT present or is empty, the Access
    /// Evaluations Request behaves in a backwards-compatible manner with the
    /// (single) Access Evaluation API Request."
    #[test]
    fn an_absent_or_empty_array_is_the_single_request_of_section_six() {
        for document in [request(), {
            let mut document = request();
            document["evaluations"] = json!([]);
            document
        }] {
            // Act
            let parsed = parse_many(&document).expect("§7.1's compatible shape");

            // Assert
            assert!(!parsed.boxcar, "an empty array became a boxcar request");
            assert_eq!(parsed.evaluations.len(), 1);
            assert_eq!(parsed.evaluations[0].resource.id(), "123");
        }
    }

    /// §7.1.2.1: three semantics, named exactly, with `execute_all` the
    /// default "so an evaluations request without the
    /// `options.evaluations_semantic` flag will execute using this semantic".
    #[test]
    fn every_semantic_of_the_options_object_is_read() {
        for (written, expected) in [
            (None, EvaluationsSemantic::ExecuteAll),
            (Some("execute_all"), EvaluationsSemantic::ExecuteAll),
            (
                Some("deny_on_first_deny"),
                EvaluationsSemantic::DenyOnFirstDeny,
            ),
            (
                Some("permit_on_first_permit"),
                EvaluationsSemantic::PermitOnFirstPermit,
            ),
        ] {
            // Arrange
            let mut document = request();
            if let Some(written) = written {
                document["options"] =
                    json!({"evaluations_semantic": written, "another_option": "value"});
            }

            // Act
            let parsed = parse_many(&document).expect("a request");

            // Assert
            assert_eq!(parsed.semantic, expected, "{written:?}");
            assert_eq!(parsed.semantic.as_str(), expected.as_str());
        }
    }

    /// A semantic this PDP does not implement is a 400 rather than a silent
    /// `execute_all`: a PEP that asked for a short circuit and got every
    /// evaluation executed has been charged for work it did not want, and one
    /// that asked for a semantic from a later revision would read the answer
    /// as though this PDP had honoured it.
    #[test]
    fn an_unknown_semantic_is_refused_rather_than_defaulted() {
        // Arrange
        let mut document = request();
        document["options"] = json!({"evaluations_semantic": "permit_on_first_deny"});

        // Act / Assert
        assert_eq!(
            parse_many(&document).unwrap_err(),
            AuthzenError::UnknownSemantic
        );
    }

    /// `options` is an object (§7.1.2) and `evaluations_semantic` a string
    /// (§7.1.2.1); neither is read as absent when it is something else.
    #[test]
    fn an_options_member_of_the_wrong_type_is_refused() {
        // Arrange
        let mut wrong_options = request();
        wrong_options["options"] = json!(["execute_all"]);
        let mut wrong_semantic = request();
        wrong_semantic["options"] = json!({"evaluations_semantic": 1});

        // Act / Assert
        assert_eq!(
            parse_many(&wrong_options).unwrap_err(),
            AuthzenError::WrongType("options")
        );
        assert_eq!(
            parse_many(&wrong_semantic).unwrap_err(),
            AuthzenError::WrongType("options.evaluations_semantic")
        );
    }

    /// §7.1's array holds objects, "each typed as the object as defined in the
    /// Access Evaluation Request".
    #[test]
    fn an_evaluation_that_is_not_an_object_is_refused() {
        // Arrange
        let mut document = request();
        document["evaluations"] = json!([{"resource": {"type": "d", "id": "1"}}, "not an object"]);

        // Act
        let refused = parse_many(&document).unwrap_err();

        // Assert
        assert!(
            matches!(&refused, AuthzenError::Item { index: 1, error }
                     if **error == AuthzenError::WrongType("evaluations")),
            "{refused:?}"
        );
    }

    /// And the array itself is an array.
    #[test]
    fn an_evaluations_member_that_is_not_an_array_is_refused() {
        // Arrange
        let mut document = request();
        document["evaluations"] = json!({"0": {"resource": {"type": "d", "id": "1"}}});

        // Act / Assert
        assert_eq!(
            parse_many(&document).unwrap_err(),
            AuthzenError::WrongType("evaluations")
        );
    }

    /// §11.7: the array is bounded, and the bound is checked against its
    /// length before a single evaluation is built.
    #[test]
    fn an_array_longer_than_the_bound_is_refused() {
        // Arrange
        let item = json!({"resource": {"type": "document", "id": "1"}});
        let mut document = request();
        document["evaluations"] = json!(vec![item.clone(); MAX_EVALUATIONS]);
        let mut one_too_many = document.clone();
        one_too_many["evaluations"] = json!(vec![item; MAX_EVALUATIONS + 1]);

        // Act / Assert
        assert_eq!(
            parse_many(&document)
                .expect("the bound itself is allowed")
                .evaluations
                .len(),
            MAX_EVALUATIONS
        );
        assert_eq!(
            parse_many(&one_too_many).unwrap_err(),
            AuthzenError::TooMany
        );
    }

    /// The bounds of §11.7 are the document's, and a boxcar is a document: a
    /// body over the size bound is refused whatever it holds.
    #[test]
    fn the_payload_bounds_are_the_same_ones_the_single_request_has() {
        // Arrange
        let mut document = request();
        document["evaluations"] = json!([{"resource": {"type": "d", "id": "1",
            "properties": {"blob": "x".repeat(MAX_REQUEST_BYTES)}}}]);
        let body = serde_json::to_vec(&document).expect("a JSON body");
        let mut nest = json!("leaf");
        for _ in 0..MAX_DEPTH {
            nest = json!([nest]);
        }
        let mut deep = request();
        deep["evaluations"] = json!([{"context": {"deep": nest}}]);

        // Act / Assert
        assert_eq!(parse_evaluations(&body).unwrap_err(), AuthzenError::TooLong);
        assert_eq!(parse_many(&deep).unwrap_err(), AuthzenError::TooDeep);
    }

    /// A PEP asserts nothing here either: the defaults go through the same
    /// entity parser, so a group claimed at the top level of a boxcar is no
    /// more a fact than one claimed in a single request.
    #[test]
    fn a_boxcar_subject_holds_nothing_the_pep_claimed() {
        // Arrange
        let mut document = request();
        document["subject"]["properties"] = json!({"groups": ["finance"]});
        document["evaluations"] = json!([{"resource": {"type": "d", "id": "1"}}]);

        // Act
        let parsed = parse_many(&document).expect("a boxcar request");

        // Assert
        assert!(parsed.evaluations[0].subject.groups().is_empty());
        assert!(parsed.evaluations[0].subject.grants().is_empty());
        assert_eq!(parsed.evaluations[0].context.acr(), None);
    }

    /// §7.2: an `evaluations` array in request order, and — "In case the
    /// evaluations array is present, it is RECOMMENDED that the decision key
    /// of the response be omitted" — no top-level `decision`.
    #[test]
    fn the_response_is_an_array_in_request_order_with_no_top_level_decision() {
        // Arrange
        let decisions = vec![
            json!({"decision": true}),
            engine_failure_response(),
            json!({"decision": false, "context": {"id": "viewer"}}),
        ];

        // Act
        let rendered = evaluations_response(decisions);

        // Assert
        assert!(
            rendered.get("decision").is_none(),
            "§7.2 recommends omitting the top-level decision"
        );
        let evaluations = rendered["evaluations"].as_array().expect("an array");
        assert_eq!(evaluations.len(), 3);
        assert_eq!(evaluations[0], json!({"decision": true}));
        assert_eq!(evaluations[1]["context"]["error"]["status"], json!(500));
        assert_eq!(evaluations[2]["context"]["id"], json!("viewer"));
    }
}
