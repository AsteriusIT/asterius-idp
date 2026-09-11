//! The rule language: a tenant's policy, as data.
//!
//! [ADR-0011] decides that the built-in PDP evaluates a small declarative model
//! rather than a policy language. This module is that model — the document an
//! administrator writes, the schema it is held to, and nothing that evaluates
//! it (that is [`super::engine`]).
//!
//! # The document
//!
//! ```json
//! {
//!   "version": 1,
//!   "rules": [
//!     {
//!       "id": "deny-unverified-payments",
//!       "effect": "deny",
//!       "subject_type": "user",
//!       "resource_type": "payment",
//!       "actions": ["initiate"],
//!       "when": { "not": { "acr_at_least": "urn:asterius:acr:passkey-uv" } },
//!       "reason_admin": "payment initiation requires a phishing-resistant login",
//!       "reason_user": "Please sign in again with your passkey.",
//!       "acr_values": ["urn:asterius:acr:passkey-uv"]
//!     }
//!   ]
//! }
//! ```
//!
//! Every member but `id` and `effect` is optional. An absent `subject_type`,
//! `resource_type` or `actions` matches anything; an absent `when` is a rule
//! that matches whenever its heads do.
//!
//! # The conditions, and why there are exactly these
//!
//! The set is closed, and each member is a fact this `IdP` owns rather than a
//! general-purpose operator:
//!
//! | Condition | Reads |
//! |---|---|
//! | `all`, `any`, `not` | other conditions |
//! | `attribute` with `equals` or `in` | `properties` of the subject, resource, action or context |
//! | `group` | the groups the server holds the subject in |
//! | `role` | the application roles the subject holds (`ast-095`) |
//! | `grant` | the subject's active grants: resource indicators, scopes, RAR type and actions (`ast-uwv.2`) |
//! | `acr_at_least` | the session's `acr`, against the tenant's ladder |
//!
//! There is no arithmetic, no string manipulation, no dereferencing of one
//! resource through another and no way to name a second request. That is the
//! decision in [ADR-0011], not an unfinished implementation: every one of those
//! would be a way for a tenant's document to cost unbounded work in a shared
//! process, and the ones that are genuinely needed arrive as named conditions
//! with a bound each.
//!
//! # Bounded at parse time, total at evaluation time
//!
//! Rule count, condition count, nesting depth and every string are checked
//! here, once. What comes out is a value that [`super::engine`] can walk
//! without a single fallible step — which is what lets `evaluate` return a
//! [`super::Decision`] rather than a `Result`, and what stops an
//! authorization outcome from ever being a parse failure.
//!
//! [ADR-0011]: https://github.com/AsteriusIT/asterius-idp/blob/main/docs/adr/0011-a-declarative-rule-model-for-the-built-in-pdp.md

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::{ClientId, RoleName, RoleOwner};

/// The only document version this build reads.
///
/// A number and not a range: a document from a newer build is refused rather
/// than read with the members this one happens to recognise, because the
/// members it would skip are the ones that deny something.
pub const VERSION: u64 = 1;

/// The most rules one tenant's document may carry.
pub const MAX_RULES: usize = 128;

/// The most condition nodes one rule may carry, counting `all`/`any`/`not`.
pub const MAX_CONDITIONS: usize = 64;

/// How deep `all`, `any` and `not` may nest.
///
/// Checked as the parser descends, so the recursion below is bounded by a
/// constant of this module rather than by the input.
pub const MAX_DEPTH: usize = 8;

/// The most values one `in` test may list.
pub const MAX_VALUES: usize = 64;

/// The most action names one rule may name.
pub const MAX_ACTIONS: usize = 32;

/// The most step-up hints one rule may carry.
pub const MAX_ACR_HINTS: usize = 8;

/// The longest rule id, type name, attribute name or literal string, in bytes.
pub const MAX_STRING: usize = 256;

/// The longest reason, in bytes.
///
/// A reason is rendered to an administrator and — for `reason_user` — possibly
/// to a person. It is a sentence, not a document.
pub const MAX_REASON: usize = 512;

/// The largest document this parser will read, in bytes.
///
/// The admin API bounds the request body as well; this bound is the one that
/// also applies to a row read back from the database.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// Why a document is not a policy.
///
/// Every variant names the path it was found at where one exists, because the
/// console editor (`ast-f7m.9`) reports the place and not only the reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyDocumentError {
    /// Longer than [`MAX_DOCUMENT_BYTES`].
    #[error("a policy document may not exceed {MAX_DOCUMENT_BYTES} bytes")]
    TooLarge,
    /// Not JSON at all.
    #[error("a policy document is not JSON: {0}")]
    NotJson(String),
    /// Not an object, or `rules` is not an array.
    #[error("a policy document is malformed: {0}")]
    Malformed(&'static str),
    /// A `version` this build does not read.
    #[error("a policy document declares version {0}, and this build reads {VERSION}")]
    Version(u64),
    /// More than [`MAX_RULES`] rules.
    #[error("a policy document may not carry more than {MAX_RULES} rules")]
    TooManyRules,
    /// The same rule id twice: which one denied would depend on order.
    #[error("the rule id {0} appears twice")]
    DuplicateRule(String),
    /// A rule id, type, name or literal that is empty, over-long or not a
    /// string.
    #[error("{path}: {reason}")]
    Value {
        /// Where in the document, as a dotted path.
        path: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// An `effect` that is neither `permit` nor `deny`.
    #[error("{0}: effect must be \"permit\" or \"deny\"")]
    Effect(String),
    /// A condition object naming no condition this build knows, or more than
    /// one.
    #[error("{path}: {reason}")]
    Condition {
        /// Where in the document.
        path: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// Conditions nested deeper than [`MAX_DEPTH`].
    #[error("{0}: conditions nest deeper than {MAX_DEPTH}")]
    TooDeep(String),
    /// More than [`MAX_CONDITIONS`] condition nodes in one rule.
    #[error("{0}: a rule may not carry more than {MAX_CONDITIONS} conditions")]
    TooManyConditions(String),
}

impl PolicyDocumentError {
    fn value(path: impl Into<String>, reason: &'static str) -> Self {
        Self::Value {
            path: path.into(),
            reason,
        }
    }

    fn condition(path: impl Into<String>, reason: &'static str) -> Self {
        Self::Condition {
            path: path.into(),
            reason,
        }
    }
}

/// A rule's identifier, as the decision reports it.
///
/// Its own type rather than a `String` so that a decision context cannot be
/// handed a reason where it expects an id. Named `PolicyRuleId` and not
/// `RuleId` because [`crate::RuleId`] is already the software-statement rule of
/// the registration policy, and two `RuleId`s in one crate root is a mistake
/// waiting to be made.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyRuleId(String);

impl PolicyRuleId {
    /// Parses an id: non-empty, at most [`MAX_STRING`] bytes, no control
    /// characters and no whitespace.
    ///
    /// Bounded the way an `acr` value is, and for the same reason: it is echoed
    /// in a decision context that a PEP logs.
    ///
    /// # Errors
    ///
    /// [`PolicyDocumentError::Value`] naming `path`.
    pub fn parse(path: &str, raw: &str) -> Result<Self, PolicyDocumentError> {
        if raw.is_empty() || raw.len() > MAX_STRING {
            return Err(PolicyDocumentError::value(
                path,
                "a rule id is empty or over-long",
            ));
        }
        if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(PolicyDocumentError::value(
                path,
                "a rule id carries whitespace or a control character",
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The id as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PolicyRuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Allow, unless a `deny` also matches.
    Permit,
    /// Refuse, whatever else matches.
    Deny,
}

impl Effect {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permit => "permit",
            Self::Deny => "deny",
        }
    }
}

/// Which bag an `attribute` condition reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The subject's `properties` (§5.1).
    Subject,
    /// The resource's `properties` (§5.3).
    Resource,
    /// The action's `properties` (§5.2).
    Action,
    /// The context's `properties` (§5.4).
    Context,
}

impl Source {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Resource => "resource",
            Self::Action => "action",
            Self::Context => "context",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "subject" => Some(Self::Subject),
            "resource" => Some(Self::Resource),
            "action" => Some(Self::Action),
            "context" => Some(Self::Context),
            _ => None,
        }
    }
}

/// How an attribute is compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeTest {
    /// Strict JSON equality.
    Equals(Value),
    /// Set membership. True when the attribute *is* one of the listed values,
    /// and also when the attribute is an array sharing at least one element
    /// with them — "the subject's `departments` include one of these" and "the
    /// subject's `department` is one of these" are the same question asked of
    /// a single-valued and a multi-valued attribute.
    In(Vec<Value>),
}

/// What the subject must hold for a `grant` condition to be true.
///
/// Every member is optional and every member present must match *the same*
/// grant: "an active grant for this resource carrying a `payment_initiation`
/// detail that permits `initiate`" is one authorization, not three facts
/// gathered from three of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantMatch {
    /// An RFC 8707 resource indicator the grant must be bound to.
    pub resource: Option<GrantResource>,
    /// A scope the grant must carry.
    pub scope: Option<String>,
    /// An RFC 9396 `authorization_details` type the grant must carry.
    pub detail_type: Option<String>,
    /// An action that element must permit (§2.2's `actions`).
    ///
    /// Read against the element matched by `detail_type` when both are given,
    /// so "type T permitting action A" cannot be satisfied by a type-T element
    /// and some other element's action.
    pub action: Option<String>,
    /// The client the grant must have been issued to.
    pub client: Option<ClientId>,
}

/// Which resource indicator a `grant` condition demands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantResource {
    /// A literal indicator, as written in the rule.
    Literal(String),
    /// `"$resource.id"`: the id of the resource *this request* is about.
    ///
    /// The one substitution in the language. It exists because the useful rule
    /// is "holds a grant for the thing being asked about", and writing it
    /// without a substitution would mean one rule per resource.
    TheResource,
}

/// One condition.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Condition {
    /// True when every child is true. An empty `all` is true.
    All(Vec<Condition>),
    /// True when any child is true. An empty `any` is false.
    Any(Vec<Condition>),
    /// True when the child is false.
    Not(Box<Condition>),
    /// A test on one attribute of one entity.
    Attribute {
        /// Which bag.
        of: Source,
        /// Which member of it.
        name: String,
        /// How it is compared.
        test: AttributeTest,
    },
    /// The subject is held in this group.
    Group(String),
    /// The subject holds this application role, from this owner or from any.
    Role {
        /// `None` means "from any catalogue".
        owner: Option<RoleOwner>,
        /// The role.
        name: RoleName,
    },
    /// The subject holds an active grant matching every member given.
    Grant(GrantMatch),
    /// The session's `acr` is at or above this rung of the tenant's ladder.
    AcrAtLeast(String),
}

/// One rule: what it matches, and what it does about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The identifier a decision reports.
    pub id: PolicyRuleId,
    /// Permit or deny.
    pub effect: Effect,
    /// The subject `type` this rule is about, or any.
    pub subject_type: Option<String>,
    /// The resource `type` this rule is about, or any.
    pub resource_type: Option<String>,
    /// The action names this rule is about, or any when empty.
    pub actions: BTreeSet<String>,
    /// The condition, or `None` for a rule whose heads are the whole test.
    pub when: Option<Condition>,
    /// §5.5.1's `reason_admin`: why, in the operator's terms.
    pub reason_admin: Option<String>,
    /// §5.5.1's `reason_user`: why, in terms that may be shown to a person.
    pub reason_user: Option<String>,
    /// The `acr` values that would satisfy a step-up, for a deny a PEP can act
    /// on (§5.5.1).
    pub acr_values: Vec<String>,
}

/// A tenant's policy: an ordered list of rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// A policy with no rules, which denies everything.
    ///
    /// What a tenant that has never written one evaluates as, and the reason
    /// the PDP is safe on the day it is mounted.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self { rules: Vec::new() }
    }

    /// Parses a document.
    ///
    /// # Errors
    ///
    /// [`PolicyDocumentError`] for anything that is not a document this build
    /// reads, naming the path where one exists.
    // fuzz-target: policy_document
    pub fn parse(raw: &str) -> Result<Self, PolicyDocumentError> {
        if raw.len() > MAX_DOCUMENT_BYTES {
            return Err(PolicyDocumentError::TooLarge);
        }
        let value: Value = serde_json::from_str(raw)
            .map_err(|error| PolicyDocumentError::NotJson(error.to_string()))?;
        Self::from_json(&value)
    }

    /// Validates an already-parsed document.
    ///
    /// # Errors
    ///
    /// [`PolicyDocumentError`] as [`Self::parse`].
    pub fn from_json(document: &Value) -> Result<Self, PolicyDocumentError> {
        let object = document
            .as_object()
            .ok_or(PolicyDocumentError::Malformed("it is not an object"))?;

        match object.get("version") {
            Some(Value::Number(number)) => {
                let version = number
                    .as_u64()
                    .ok_or(PolicyDocumentError::Malformed("version is not an integer"))?;
                if version != VERSION {
                    return Err(PolicyDocumentError::Version(version));
                }
            }
            Some(_) => return Err(PolicyDocumentError::Malformed("version is not a number")),
            None => return Err(PolicyDocumentError::Malformed("it declares no version")),
        }

        let entries = object
            .get("rules")
            .and_then(Value::as_array)
            .ok_or(PolicyDocumentError::Malformed("rules is not an array"))?;
        if entries.len() > MAX_RULES {
            return Err(PolicyDocumentError::TooManyRules);
        }

        let mut rules = Vec::with_capacity(entries.len());
        let mut seen = BTreeSet::new();
        for (index, entry) in entries.iter().enumerate() {
            let rule = parse_rule(index, entry)?;
            if !seen.insert(rule.id.clone()) {
                return Err(PolicyDocumentError::DuplicateRule(rule.id.to_string()));
            }
            rules.push(rule);
        }

        Ok(Self { rules })
    }

    /// The rules, in the order they were written.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Whether the policy denies everything by having nothing to say.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The document, as it would be stored.
    ///
    /// Round-trips: `from_json(&set.to_json()) == Ok(set)` for every value this
    /// type can hold, which the property test asserts. That is what makes the
    /// admin API's read-modify-write safe — a console that fetches, edits one
    /// rule and puts the document back must not silently drop what this build
    /// understood.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "version": VERSION,
            "rules": self.rules.iter().map(rule_to_json).collect::<Vec<_>>(),
        })
    }
}

fn parse_rule(index: usize, entry: &Value) -> Result<Rule, PolicyDocumentError> {
    let path = format!("rules[{index}]");
    let object = entry
        .as_object()
        .ok_or_else(|| PolicyDocumentError::value(&path, "a rule is not an object"))?;

    let id = match object.get("id") {
        Some(Value::String(raw)) => PolicyRuleId::parse(&format!("{path}.id"), raw)?,
        _ => {
            return Err(PolicyDocumentError::value(
                &path,
                "a rule carries no string id",
            ));
        }
    };

    let effect = match object.get("effect").and_then(Value::as_str) {
        Some("permit") => Effect::Permit,
        Some("deny") => Effect::Deny,
        _ => return Err(PolicyDocumentError::Effect(path)),
    };

    let subject_type = optional_string(object, "subject_type", &path)?;
    let resource_type = optional_string(object, "resource_type", &path)?;

    let actions = match object.get("actions") {
        None | Some(Value::Null) => BTreeSet::new(),
        Some(Value::Array(items)) => {
            if items.len() > MAX_ACTIONS {
                return Err(PolicyDocumentError::value(
                    format!("{path}.actions"),
                    "more action names than a rule may name",
                ));
            }
            let mut names = BTreeSet::new();
            for (position, item) in items.iter().enumerate() {
                names.insert(bounded_string(
                    item,
                    &format!("{path}.actions[{position}]"),
                    "an action name",
                )?);
            }
            names
        }
        Some(_) => {
            return Err(PolicyDocumentError::value(
                format!("{path}.actions"),
                "actions is not an array",
            ));
        }
    };

    let mut budget = MAX_CONDITIONS;
    let when = match object.get("when") {
        None | Some(Value::Null) => None,
        Some(value) => Some(parse_condition(
            value,
            &format!("{path}.when"),
            1,
            &mut budget,
        )?),
    };

    let reason_admin = optional_reason(object, "reason_admin", &path)?;
    let reason_user = optional_reason(object, "reason_user", &path)?;

    let acr_values = match object.get("acr_values") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            if items.len() > MAX_ACR_HINTS {
                return Err(PolicyDocumentError::value(
                    format!("{path}.acr_values"),
                    "more step-up hints than a rule may carry",
                ));
            }
            items
                .iter()
                .enumerate()
                .map(|(position, item)| {
                    bounded_string(
                        item,
                        &format!("{path}.acr_values[{position}]"),
                        "an acr value",
                    )
                })
                .collect::<Result<Vec<_>, _>>()?
        }
        Some(_) => {
            return Err(PolicyDocumentError::value(
                format!("{path}.acr_values"),
                "acr_values is not an array",
            ));
        }
    };

    Ok(Rule {
        id,
        effect,
        subject_type,
        resource_type,
        actions,
        when,
        reason_admin,
        reason_user,
        acr_values,
    })
}

fn optional_string(
    object: &Map<String, Value>,
    member: &str,
    path: &str,
) -> Result<Option<String>, PolicyDocumentError> {
    match object.get(member) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(bounded_string(
            value,
            &format!("{path}.{member}"),
            "a name",
        )?)),
    }
}

fn optional_reason(
    object: &Map<String, Value>,
    member: &str,
    path: &str,
) -> Result<Option<String>, PolicyDocumentError> {
    match object.get(member) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => {
            if raw.is_empty() || raw.len() > MAX_REASON {
                return Err(PolicyDocumentError::value(
                    format!("{path}.{member}"),
                    "a reason is empty or longer than the bound",
                ));
            }
            if raw.chars().any(char::is_control) {
                return Err(PolicyDocumentError::value(
                    format!("{path}.{member}"),
                    "a reason carries a control character",
                ));
            }
            Ok(Some(raw.clone()))
        }
        Some(_) => Err(PolicyDocumentError::value(
            format!("{path}.{member}"),
            "a reason is not a string",
        )),
    }
}

/// A non-empty, bounded, control-free string, or the reason it is not one.
fn bounded_string(
    value: &Value,
    path: &str,
    what: &'static str,
) -> Result<String, PolicyDocumentError> {
    let raw = value
        .as_str()
        .ok_or_else(|| PolicyDocumentError::value(path, "it is not a string"))?;
    if raw.is_empty() || raw.len() > MAX_STRING {
        return Err(PolicyDocumentError::value(
            path,
            "it is empty or longer than the bound",
        ));
    }
    if raw.chars().any(char::is_control) {
        return Err(PolicyDocumentError::value(
            path,
            "it carries a control character",
        ));
    }
    let _ = what;
    Ok(raw.to_owned())
}

/// Parses one condition.
///
/// `depth` is checked before descending and `budget` is spent per node, so this
/// recursion is bounded by [`MAX_DEPTH`] and [`MAX_CONDITIONS`] whatever the
/// input looks like.
fn parse_condition(
    value: &Value,
    path: &str,
    depth: usize,
    budget: &mut usize,
) -> Result<Condition, PolicyDocumentError> {
    if depth > MAX_DEPTH {
        return Err(PolicyDocumentError::TooDeep(path.to_owned()));
    }
    if *budget == 0 {
        return Err(PolicyDocumentError::TooManyConditions(path.to_owned()));
    }
    *budget -= 1;

    let object = value
        .as_object()
        .ok_or_else(|| PolicyDocumentError::condition(path, "a condition is not an object"))?;
    if object.len() != 1 {
        return Err(PolicyDocumentError::condition(
            path,
            "a condition object names exactly one condition",
        ));
    }
    let (name, body) = object
        .iter()
        .next()
        .ok_or_else(|| PolicyDocumentError::condition(path, "a condition object is empty"))?;

    match name.as_str() {
        "all" | "any" => {
            let items = body.as_array().ok_or_else(|| {
                PolicyDocumentError::condition(path, "all and any take an array of conditions")
            })?;
            let mut children = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                children.push(parse_condition(
                    item,
                    &format!("{path}.{name}[{index}]"),
                    depth + 1,
                    budget,
                )?);
            }
            Ok(if name == "all" {
                Condition::All(children)
            } else {
                Condition::Any(children)
            })
        }
        "not" => Ok(Condition::Not(Box::new(parse_condition(
            body,
            &format!("{path}.not"),
            depth + 1,
            budget,
        )?))),
        "attribute" => parse_attribute(body, &format!("{path}.attribute")),
        "group" => Ok(Condition::Group(bounded_string(
            body,
            &format!("{path}.group"),
            "a group name",
        )?)),
        "role" => parse_role(body, &format!("{path}.role")),
        "grant" => parse_grant(body, &format!("{path}.grant")),
        "acr_at_least" => Ok(Condition::AcrAtLeast(bounded_string(
            body,
            &format!("{path}.acr_at_least"),
            "an acr value",
        )?)),
        _ => Err(PolicyDocumentError::condition(
            path,
            "no condition of that name exists",
        )),
    }
}

fn parse_attribute(body: &Value, path: &str) -> Result<Condition, PolicyDocumentError> {
    let object = body
        .as_object()
        .ok_or_else(|| PolicyDocumentError::condition(path, "attribute takes an object"))?;

    let of = object
        .get("of")
        .and_then(Value::as_str)
        .and_then(Source::parse)
        .ok_or_else(|| {
            PolicyDocumentError::condition(path, "of must be subject, resource, action or context")
        })?;

    let name = bounded_string(
        object
            .get("name")
            .ok_or_else(|| PolicyDocumentError::condition(path, "attribute names no name"))?,
        &format!("{path}.name"),
        "an attribute name",
    )?;

    let test = match (object.get("equals"), object.get("in")) {
        (Some(expected), None) => {
            bounded_literal(expected, &format!("{path}.equals"))?;
            AttributeTest::Equals(expected.clone())
        }
        (None, Some(values)) => {
            let items = values.as_array().ok_or_else(|| {
                PolicyDocumentError::condition(path, "in takes an array of values")
            })?;
            if items.len() > MAX_VALUES {
                return Err(PolicyDocumentError::condition(
                    path,
                    "in lists more values than the bound allows",
                ));
            }
            for (index, item) in items.iter().enumerate() {
                bounded_literal(item, &format!("{path}.in[{index}]"))?;
            }
            AttributeTest::In(items.clone())
        }
        _ => {
            return Err(PolicyDocumentError::condition(
                path,
                "attribute takes exactly one of equals and in",
            ));
        }
    };

    Ok(Condition::Attribute { of, name, test })
}

/// A literal a rule may compare against: a scalar, bounded if it is a string.
///
/// Objects and arrays are refused. An `equals` against a nested structure is a
/// comparison whose cost is the size of what the PEP sent, and one whose result
/// depends on member order in a way nobody writing a rule would predict.
fn bounded_literal(value: &Value, path: &str) -> Result<(), PolicyDocumentError> {
    match value {
        Value::String(raw) => {
            if raw.len() > MAX_STRING {
                return Err(PolicyDocumentError::value(path, "a literal is over-long"));
            }
            if raw.chars().any(char::is_control) {
                return Err(PolicyDocumentError::value(
                    path,
                    "a literal carries a control character",
                ));
            }
            Ok(())
        }
        Value::Bool(_) | Value::Number(_) | Value::Null => Ok(()),
        Value::Array(_) | Value::Object(_) => Err(PolicyDocumentError::value(
            path,
            "a literal must be a string, a number, a boolean or null",
        )),
    }
}

fn parse_role(body: &Value, path: &str) -> Result<Condition, PolicyDocumentError> {
    let object = body
        .as_object()
        .ok_or_else(|| PolicyDocumentError::condition(path, "role takes an object"))?;

    let raw = bounded_string(
        object
            .get("name")
            .ok_or_else(|| PolicyDocumentError::condition(path, "role names no name"))?,
        &format!("{path}.name"),
        "a role name",
    )?;
    // The same parser the catalogue and the token builder use (`ast-095`): a
    // rule must not be able to name a role this server would never mint.
    let name = RoleName::parse(&raw).map_err(|_| {
        PolicyDocumentError::value(format!("{path}.name"), "it is not an application role name")
    })?;

    let owner = match object.get("owner") {
        None | Some(Value::Null) => None,
        Some(Value::String(raw)) if raw == "tenant" => Some(RoleOwner::Tenant),
        Some(value) => {
            let client = bounded_string(value, &format!("{path}.owner"), "a client id")?;
            Some(RoleOwner::Client(ClientId::new(client)))
        }
    };

    Ok(Condition::Role { owner, name })
}

fn parse_grant(body: &Value, path: &str) -> Result<Condition, PolicyDocumentError> {
    let object = body
        .as_object()
        .ok_or_else(|| PolicyDocumentError::condition(path, "grant takes an object"))?;
    if object.is_empty() {
        return Err(PolicyDocumentError::condition(
            path,
            "grant names nothing to match",
        ));
    }
    for member in object.keys() {
        if !matches!(
            member.as_str(),
            "resource" | "scope" | "detail_type" | "action" | "client"
        ) {
            return Err(PolicyDocumentError::condition(
                path,
                "grant takes resource, scope, detail_type, action and client",
            ));
        }
    }

    let member = |name: &str| -> Result<Option<String>, PolicyDocumentError> {
        match object.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => Ok(Some(bounded_string(
                value,
                &format!("{path}.{name}"),
                "a value",
            )?)),
        }
    };

    let resource = member("resource")?.map(|raw| {
        if raw == "$resource.id" {
            GrantResource::TheResource
        } else {
            GrantResource::Literal(raw)
        }
    });

    Ok(Condition::Grant(GrantMatch {
        resource,
        scope: member("scope")?,
        detail_type: member("detail_type")?,
        action: member("action")?,
        client: member("client")?.map(ClientId::new),
    }))
}

fn rule_to_json(rule: &Rule) -> Value {
    let mut object = Map::new();
    object.insert("id".to_owned(), json!(rule.id.as_str()));
    object.insert("effect".to_owned(), json!(rule.effect.as_str()));
    if let Some(kind) = &rule.subject_type {
        object.insert("subject_type".to_owned(), json!(kind));
    }
    if let Some(kind) = &rule.resource_type {
        object.insert("resource_type".to_owned(), json!(kind));
    }
    if !rule.actions.is_empty() {
        object.insert(
            "actions".to_owned(),
            json!(rule.actions.iter().collect::<Vec<_>>()),
        );
    }
    if let Some(condition) = &rule.when {
        object.insert("when".to_owned(), condition_to_json(condition));
    }
    if let Some(reason) = &rule.reason_admin {
        object.insert("reason_admin".to_owned(), json!(reason));
    }
    if let Some(reason) = &rule.reason_user {
        object.insert("reason_user".to_owned(), json!(reason));
    }
    if !rule.acr_values.is_empty() {
        object.insert("acr_values".to_owned(), json!(rule.acr_values));
    }
    Value::Object(object)
}

fn condition_to_json(condition: &Condition) -> Value {
    match condition {
        Condition::All(children) => {
            json!({ "all": children.iter().map(condition_to_json).collect::<Vec<_>>() })
        }
        Condition::Any(children) => {
            json!({ "any": children.iter().map(condition_to_json).collect::<Vec<_>>() })
        }
        Condition::Not(child) => json!({ "not": condition_to_json(child) }),
        Condition::Attribute { of, name, test } => {
            let mut body = Map::new();
            body.insert("of".to_owned(), json!(of.as_str()));
            body.insert("name".to_owned(), json!(name));
            match test {
                AttributeTest::Equals(value) => {
                    body.insert("equals".to_owned(), value.clone());
                }
                AttributeTest::In(values) => {
                    body.insert("in".to_owned(), Value::Array(values.clone()));
                }
            }
            json!({ "attribute": Value::Object(body) })
        }
        Condition::Group(name) => json!({ "group": name }),
        Condition::Role { owner, name } => {
            let mut body = Map::new();
            body.insert("name".to_owned(), json!(name.as_str()));
            match owner {
                None => {}
                Some(RoleOwner::Tenant) => {
                    body.insert("owner".to_owned(), json!("tenant"));
                }
                Some(RoleOwner::Client(client)) => {
                    body.insert("owner".to_owned(), json!(client.as_str()));
                }
            }
            json!({ "role": Value::Object(body) })
        }
        Condition::Grant(matcher) => {
            let mut body = Map::new();
            match &matcher.resource {
                None => {}
                Some(GrantResource::TheResource) => {
                    body.insert("resource".to_owned(), json!("$resource.id"));
                }
                Some(GrantResource::Literal(raw)) => {
                    body.insert("resource".to_owned(), json!(raw));
                }
            }
            if let Some(scope) = &matcher.scope {
                body.insert("scope".to_owned(), json!(scope));
            }
            if let Some(detail_type) = &matcher.detail_type {
                body.insert("detail_type".to_owned(), json!(detail_type));
            }
            if let Some(action) = &matcher.action {
                body.insert("action".to_owned(), json!(action));
            }
            if let Some(client) = &matcher.client {
                body.insert("client".to_owned(), json!(client.as_str()));
            }
            json!({ "grant": Value::Object(body) })
        }
        Condition::AcrAtLeast(value) => json!({ "acr_at_least": value }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(rules: &str) -> String {
        format!(r#"{{"version": 1, "rules": {rules}}}"#)
    }

    #[test]
    fn an_empty_document_is_a_policy_that_denies_everything() {
        // Arrange / Act
        let parsed = RuleSet::parse(&document("[]")).expect("a valid document");

        // Assert
        assert!(parsed.is_empty());
    }

    #[test]
    fn a_document_without_a_version_is_refused() {
        assert_eq!(
            RuleSet::parse(r#"{"rules": []}"#).unwrap_err(),
            PolicyDocumentError::Malformed("it declares no version")
        );
    }

    /// A newer document is refused rather than read with the members this
    /// build happens to know: the ones it would skip are the ones that deny.
    #[test]
    fn a_document_from_a_newer_build_is_refused() {
        assert_eq!(
            RuleSet::parse(r#"{"version": 2, "rules": []}"#).unwrap_err(),
            PolicyDocumentError::Version(2)
        );
    }

    #[test]
    fn a_rule_needs_an_effect_this_build_knows() {
        // Arrange / Act
        let refused = RuleSet::parse(&document(r#"[{"id": "r", "effect": "maybe"}]"#));

        // Assert
        assert_eq!(
            refused.unwrap_err(),
            PolicyDocumentError::Effect("rules[0]".to_owned())
        );
    }

    #[test]
    fn two_rules_with_one_id_are_refused() {
        // Arrange
        let raw = document(r#"[{"id": "r", "effect": "deny"}, {"id": "r", "effect": "permit"}]"#);

        // Act / Assert
        assert_eq!(
            RuleSet::parse(&raw).unwrap_err(),
            PolicyDocumentError::DuplicateRule("r".to_owned())
        );
    }

    #[test]
    fn a_condition_object_naming_two_conditions_is_refused() {
        // Arrange
        let raw = document(
            r#"[{"id": "r", "effect": "permit", "when": {"group": "a", "acr_at_least": "b"}}]"#,
        );

        // Act
        let refused = RuleSet::parse(&raw).unwrap_err();

        // Assert
        assert!(matches!(refused, PolicyDocumentError::Condition { .. }));
    }

    #[test]
    fn an_unknown_condition_is_refused() {
        // Arrange
        let raw = document(r#"[{"id": "r", "effect": "permit", "when": {"eval": "1+1"}}]"#);

        // Act
        let refused = RuleSet::parse(&raw).unwrap_err();

        // Assert
        assert_eq!(
            refused,
            PolicyDocumentError::Condition {
                path: "rules[0].when".to_owned(),
                reason: "no condition of that name exists",
            }
        );
    }

    /// The bound that keeps the evaluator's recursion a constant of this
    /// module.
    #[test]
    fn conditions_nested_past_the_bound_are_refused() {
        // Arrange
        let mut when = r#"{"group": "g"}"#.to_owned();
        for _ in 0..MAX_DEPTH {
            when = format!(r#"{{"not": {when}}}"#);
        }
        let raw = document(&format!(
            r#"[{{"id": "r", "effect": "permit", "when": {when}}}]"#
        ));

        // Act
        let refused = RuleSet::parse(&raw).unwrap_err();

        // Assert
        assert!(matches!(refused, PolicyDocumentError::TooDeep(_)));
    }

    #[test]
    fn a_rule_with_more_conditions_than_the_budget_is_refused() {
        // Arrange
        let children = (0..=MAX_CONDITIONS)
            .map(|index| format!(r#"{{"group": "g{index}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let raw = document(&format!(
            r#"[{{"id": "r", "effect": "permit", "when": {{"any": [{children}]}}}}]"#
        ));

        // Act
        let refused = RuleSet::parse(&raw).unwrap_err();

        // Assert
        assert!(matches!(refused, PolicyDocumentError::TooManyConditions(_)));
    }

    #[test]
    fn a_document_beyond_the_byte_bound_is_refused_before_it_is_parsed() {
        // Arrange
        let raw = " ".repeat(MAX_DOCUMENT_BYTES + 1);

        // Act / Assert
        assert_eq!(
            RuleSet::parse(&raw).unwrap_err(),
            PolicyDocumentError::TooLarge
        );
    }

    #[test]
    fn an_attribute_condition_takes_exactly_one_test() {
        // Arrange
        let raw = document(
            r#"[{"id": "r", "effect": "permit", "when":
                 {"attribute": {"of": "subject", "name": "a", "equals": 1, "in": [1]}}}]"#,
        );

        // Act / Assert
        assert!(matches!(
            RuleSet::parse(&raw).unwrap_err(),
            PolicyDocumentError::Condition { .. }
        ));
    }

    /// An `equals` against an object is a comparison whose cost and whose
    /// result both depend on what the PEP sent.
    #[test]
    fn a_literal_may_not_be_a_structure() {
        // Arrange
        let raw = document(
            r#"[{"id": "r", "effect": "permit", "when":
                 {"attribute": {"of": "subject", "name": "a", "equals": {"b": 1}}}}]"#,
        );

        // Act / Assert
        assert!(matches!(
            RuleSet::parse(&raw).unwrap_err(),
            PolicyDocumentError::Value { .. }
        ));
    }

    #[test]
    fn a_role_condition_parses_the_name_the_catalogue_would() {
        // Arrange
        let raw = document(
            r#"[{"id": "r", "effect": "permit", "when": {"role": {"name": "NOT A NAME"}}}]"#,
        );

        // Act / Assert
        assert!(matches!(
            RuleSet::parse(&raw).unwrap_err(),
            PolicyDocumentError::Value { .. }
        ));
    }

    #[test]
    fn a_grant_condition_refuses_a_member_it_does_not_know() {
        // Arrange
        let raw =
            document(r#"[{"id": "r", "effect": "permit", "when": {"grant": {"audience": "x"}}}]"#);

        // Act / Assert
        assert!(matches!(
            RuleSet::parse(&raw).unwrap_err(),
            PolicyDocumentError::Condition { .. }
        ));
    }

    #[test]
    fn the_resource_substitution_is_recognised() {
        // Arrange
        let raw = document(
            r#"[{"id": "r", "effect": "permit",
                 "when": {"grant": {"resource": "$resource.id"}}}]"#,
        );

        // Act
        let parsed = RuleSet::parse(&raw).expect("a valid document");

        // Assert
        let Some(Condition::Grant(matcher)) = &parsed.rules()[0].when else {
            panic!("expected a grant condition");
        };
        assert_eq!(matcher.resource, Some(GrantResource::TheResource));
    }

    #[test]
    fn a_full_rule_round_trips_through_json() {
        // Arrange
        let raw = document(
            r#"[{
                "id": "step-up-for-payments",
                "effect": "deny",
                "subject_type": "user",
                "resource_type": "payment",
                "actions": ["initiate"],
                "when": {"all": [
                    {"not": {"acr_at_least": "urn:acr:passkey"}},
                    {"any": [
                        {"group": "contractors"},
                        {"role": {"name": "operator", "owner": "tenant"}},
                        {"attribute": {"of": "context", "name": "country", "in": ["FR", "BE"]}},
                        {"grant": {"resource": "$resource.id", "detail_type": "payment_initiation",
                                   "action": "initiate", "scope": "payments", "client": "c.42"}}
                    ]}
                ]},
                "reason_admin": "rule 12 denied it",
                "reason_user": "Please sign in with your passkey.",
                "acr_values": ["urn:acr:passkey"]
            }]"#,
        );
        let parsed = RuleSet::parse(&raw).expect("a valid document");

        // Act
        let again = RuleSet::from_json(&parsed.to_json()).expect("a document it wrote itself");

        // Assert
        assert_eq!(again, parsed);
    }
}
