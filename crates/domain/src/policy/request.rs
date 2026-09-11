//! What a decision is about: Authorization API 1.0 §5's information model,
//! plus the facts only this `IdP` can supply.
//!
//! §5 names four things — a subject, an action, a resource and a context — and
//! gives the first three the same shape: a `type`, an `id` and an optional
//! `properties` object (an action has a `name` instead of a type and an id).
//! [`Subject`], [`Action`], [`Resource`] and [`Context`] are those four, and
//! they are deliberately not a re-spelling of the wire format: `properties`
//! here is a bag the *PEP* filled in, and everything a PEP must not be able to
//! claim is a separate field.
//!
//! # Which fields a caller may be trusted with
//!
//! A PEP is a relying party. It is authenticated (`ast-pj0.1` binds it to a
//! DPoP token) but it is not this server, and a request is a *question*, not a
//! statement of fact. So:
//!
//! * `properties` on any of the three entities is whatever the PEP sent. A rule
//!   may match on it — that is what makes "the document this PEP is protecting
//!   is marked confidential" expressible — but the rules that decide authority
//!   do not have to.
//! * [`Subject::groups`], [`Subject::roles`], [`Subject::grants`] and
//!   [`Context::acr`] are **resolved by this server** from its own store. There
//!   is no constructor that takes them from a request body, and the conditions
//!   that read them (`group`, `role`, `grant`, `acr_at_least`) are therefore
//!   conditions a PEP cannot satisfy by asserting something.
//!
//! `docs/threat-model.md` carries the same split as a row, because it is the
//! property the whole engine rests on.
//!
//! # Bounded once, at the edge
//!
//! [`Properties`] is validated on construction — member count, key length,
//! nesting depth — so evaluation never walks an unbounded structure and never
//! has to fail. A megabyte of nested arrays is refused where it arrives,
//! which is the only place that can answer it with a 400.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::entities::application_role::HeldRoles;
use crate::{ClientId, Grant, GrantStatus, RoleName, RoleOwner};
use time::OffsetDateTime;

/// The most members one `properties` object may carry.
///
/// Sixty-four is more attributes than any rule catalogue reads and far fewer
/// than a payload. The bound is on the *request*, so it is a limit on what a
/// PEP can make the evaluator walk.
pub const MAX_PROPERTIES: usize = 64;

/// The longest property name, in bytes.
pub const MAX_PROPERTY_NAME: usize = 128;

/// How deep a property value may nest.
///
/// A JSON value arrives already parsed, so this is not about the parser's own
/// recursion: it bounds the walk [`Properties::new`] makes and, with
/// [`MAX_PROPERTY_NODES`], the work one `equals` against an object can cost.
pub const MAX_PROPERTY_DEPTH: usize = 8;

/// The most JSON nodes one property value may hold.
pub const MAX_PROPERTY_NODES: usize = 256;

/// The longest entity type, id or action name, in bytes.
pub const MAX_IDENTIFIER: usize = 256;

/// The most active grants a subject is described by.
///
/// A person with more live authorizations than this to one client already has
/// a grant-management problem; a decision must not become quadratic because of
/// it.
pub const MAX_GRANTS: usize = 64;

/// Why a request will not be accepted.
///
/// Refused at the edge rather than carried into evaluation: an evaluator that
/// can fail is an evaluator whose failure mode is an authorization outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError {
    /// More than [`MAX_PROPERTIES`] members.
    #[error("a properties object may not carry more than {MAX_PROPERTIES} members")]
    TooManyProperties,
    /// A member name that is empty or longer than [`MAX_PROPERTY_NAME`].
    #[error("a property name is empty or longer than {MAX_PROPERTY_NAME} bytes")]
    PropertyName,
    /// A value nested deeper than [`MAX_PROPERTY_DEPTH`].
    #[error("the property {0} nests deeper than {MAX_PROPERTY_DEPTH}")]
    PropertyDepth(String),
    /// A value holding more than [`MAX_PROPERTY_NODES`] nodes.
    #[error("the property {0} holds more than {MAX_PROPERTY_NODES} values")]
    PropertySize(String),
    /// A type, id or action name that is empty or over-long.
    ///
    /// §5 makes `type` and `id` REQUIRED on a subject and a resource and `name`
    /// REQUIRED on an action, so an empty one is a request that does not name
    /// what it is asking about.
    #[error("{0} is empty or longer than {MAX_IDENTIFIER} bytes")]
    Identifier(&'static str),
    /// More than [`MAX_GRANTS`] active grants.
    #[error("a subject may not be described by more than {MAX_GRANTS} grants")]
    TooManyGrants,
}

/// A bag of attributes, as §5's `properties`.
///
/// Ordered, so that two equal bags render identically and a golden test of a
/// decision is stable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Properties(BTreeMap<String, Value>);

impl Properties {
    /// Nothing supplied.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// Validates and takes a bag.
    ///
    /// # Errors
    ///
    /// [`RequestError`] for a bag outside the bounds this module documents.
    pub fn new<K: Into<String>, I: IntoIterator<Item = (K, Value)>>(
        members: I,
    ) -> Result<Self, RequestError> {
        let members: BTreeMap<String, Value> =
            members.into_iter().map(|(k, v)| (k.into(), v)).collect();
        Self::validate(&members)?;
        Ok(Self(members))
    }

    /// Takes the members of a JSON object, or nothing for any other value.
    ///
    /// A `properties` that is not an object is not an error at this layer: §5
    /// defines it as an object and `ast-pj0.1` refuses anything else with a
    /// 400, which is where a caller can be told. Here it is simply no
    /// attributes.
    ///
    /// # Errors
    ///
    /// [`RequestError`] for an object outside the documented bounds.
    pub fn from_json(value: &Value) -> Result<Self, RequestError> {
        match value.as_object() {
            Some(members) => Self::new(members.clone()),
            None => Ok(Self::empty()),
        }
    }

    fn validate(members: &BTreeMap<String, Value>) -> Result<(), RequestError> {
        if members.len() > MAX_PROPERTIES {
            return Err(RequestError::TooManyProperties);
        }
        for (name, value) in members {
            if name.is_empty() || name.len() > MAX_PROPERTY_NAME {
                return Err(RequestError::PropertyName);
            }
            let mut nodes = 0usize;
            measure(value, 1, &mut nodes).map_err(|overrun| overrun.named(name))?;
        }
        Ok(())
    }

    /// One attribute, or `None` if the bag does not carry it.
    ///
    /// An absent attribute is not an error anywhere in this module: a condition
    /// that reads one is simply false, which is what keeps evaluation total.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }

    /// Whether nothing was supplied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every member, in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.0.iter()
    }

    /// The bag as a JSON object.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Object(
            self.0
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<Map<String, Value>>(),
        )
    }
}

/// A depth or size overrun, before it knows which property it belongs to.
enum Overrun {
    Depth,
    Size,
}

impl Overrun {
    fn named(self, property: &str) -> RequestError {
        match self {
            Self::Depth => RequestError::PropertyDepth(property.to_owned()),
            Self::Size => RequestError::PropertySize(property.to_owned()),
        }
    }
}

/// Walks a value, counting nodes and refusing one that nests too deep.
///
/// Recursive, and bounded by [`MAX_PROPERTY_DEPTH`] *before* it recurses, so
/// the depth of the Rust stack this can reach is a constant of this module and
/// not a function of the input.
fn measure(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), Overrun> {
    *nodes += 1;
    if *nodes > MAX_PROPERTY_NODES {
        return Err(Overrun::Size);
    }
    match value {
        Value::Array(items) => {
            if depth >= MAX_PROPERTY_DEPTH {
                return Err(Overrun::Depth);
            }
            for item in items {
                measure(item, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(members) => {
            if depth >= MAX_PROPERTY_DEPTH {
                return Err(Overrun::Depth);
            }
            for member in members.values() {
                measure(member, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Checks a `type`, an `id` or an action `name`.
fn identifier(field: &'static str, raw: &str) -> Result<String, RequestError> {
    if raw.is_empty() || raw.len() > MAX_IDENTIFIER {
        return Err(RequestError::Identifier(field));
    }
    Ok(raw.to_owned())
}

/// Who is asking (§5.1), as this server resolved them.
///
/// `kind` is §5.1's `type` — spelled `kind` because `type` is a keyword — and
/// `id` its `id`. The three fields below `properties` are this `IdP`'s own answer
/// about the account and are never read off a request; see the module
/// documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    kind: String,
    id: String,
    properties: Properties,
    groups: BTreeSet<String>,
    roles: HeldRoles,
    grants: Vec<ActiveGrant>,
}

impl Subject {
    /// A subject naming nothing this server resolved: a type, an id, and
    /// whatever the PEP said about it.
    ///
    /// # Errors
    ///
    /// [`RequestError::Identifier`] for an empty or over-long `type` or `id`.
    pub fn new(kind: &str, id: &str, properties: Properties) -> Result<Self, RequestError> {
        Ok(Self {
            kind: identifier("subject.type", kind)?,
            id: identifier("subject.id", id)?,
            properties,
            groups: BTreeSet::new(),
            roles: HeldRoles::empty(),
            grants: Vec::new(),
        })
    }

    /// Attaches the groups this server holds the subject in.
    #[must_use]
    pub fn with_groups<I: IntoIterator<Item = String>>(mut self, groups: I) -> Self {
        self.groups = groups.into_iter().collect();
        self
    }

    /// Attaches the application roles the subject holds (`ast-095`).
    #[must_use]
    pub fn with_roles(mut self, roles: HeldRoles) -> Self {
        self.roles = roles;
        self
    }

    /// Attaches the subject's active authorizations (`ast-uwv.2`).
    ///
    /// # Errors
    ///
    /// [`RequestError::TooManyGrants`] beyond [`MAX_GRANTS`].
    pub fn with_grants<I: IntoIterator<Item = ActiveGrant>>(
        mut self,
        grants: I,
    ) -> Result<Self, RequestError> {
        let grants: Vec<_> = grants.into_iter().collect();
        if grants.len() > MAX_GRANTS {
            return Err(RequestError::TooManyGrants);
        }
        self.grants = grants;
        Ok(self)
    }

    /// §5.1's `type`.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// §5.1's `id`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// §5.1's `properties`, as the PEP sent them.
    #[must_use]
    pub const fn properties(&self) -> &Properties {
        &self.properties
    }

    /// The groups this server holds the subject in.
    #[must_use]
    pub const fn groups(&self) -> &BTreeSet<String> {
        &self.groups
    }

    /// The application roles the subject holds.
    #[must_use]
    pub const fn roles(&self) -> &HeldRoles {
        &self.roles
    }

    /// The subject's active authorizations.
    #[must_use]
    pub fn grants(&self) -> &[ActiveGrant] {
        &self.grants
    }

    /// Whether the subject holds `name` from `owner`, or from any owner when
    /// `owner` is `None`.
    #[must_use]
    pub fn holds_role(&self, owner: Option<&RoleOwner>, name: &RoleName) -> bool {
        match owner {
            Some(RoleOwner::Tenant) => self.roles.tenant.contains(name),
            Some(RoleOwner::Client(client)) => self
                .roles
                .clients
                .get(client)
                .is_some_and(|held| held.contains(name)),
            None => {
                self.roles.tenant.contains(name)
                    || self.roles.clients.values().any(|held| held.contains(name))
            }
        }
    }
}

/// One live authorization, reduced to the facts a rule may ask about.
///
/// Built from a [`Grant`] by [`ActiveGrant::of`], which is the only thing that
/// decides "active": a rule saying "holds an active grant" must not be able to
/// disagree with [`Grant::status`] about what that means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveGrant {
    /// The client the authorization was granted to.
    pub client: ClientId,
    /// RFC 6749 §3.3 scopes.
    pub scopes: BTreeSet<String>,
    /// RFC 8707 resource indicators the authorization is audience-bound to.
    pub resources: BTreeSet<String>,
    /// RFC 9396 `authorization_details`, reduced to type, actions and
    /// locations.
    pub details: Vec<DetailFact>,
}

impl ActiveGrant {
    /// The facts of `grant`, or `None` if it is not active at `now`.
    ///
    /// `None` rather than a flag on the value: a rule reasons about
    /// authorizations that *exist*, and a pending, expired or revoked grant is
    /// not one of them. Filtering here means no condition can forget to check.
    #[must_use]
    pub fn of(grant: &Grant, now: OffsetDateTime) -> Option<Self> {
        if grant.status(now) != GrantStatus::Active {
            return None;
        }
        Some(Self {
            client: grant.client.clone(),
            scopes: grant.scopes.clone(),
            resources: grant.resources.clone(),
            details: grant
                .authorization_details
                .iter()
                .map(DetailFact::of)
                .collect(),
        })
    }
}

/// One `authorization_details` element, as a rule sees it (RFC 9396 §2.2).
///
/// `type`, `actions` and `locations` and nothing else: the type's own
/// vocabulary is its schema's business, and a rule language that could reach
/// into it would be one that has to understand every registered type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetailFact {
    /// §2's REQUIRED `type`. Empty for an element that carries none, which is
    /// an element no `detail_type` condition can match.
    pub detail_type: String,
    /// §2.2's `actions`.
    pub actions: BTreeSet<String>,
    /// §2.2's `locations`.
    pub locations: BTreeSet<String>,
}

impl DetailFact {
    /// Reads one stored element.
    ///
    /// Total on purpose: the column holds what RFC 9396 validation accepted,
    /// and a member of an unexpected type here is an absent fact rather than a
    /// decision that cannot be taken.
    #[must_use]
    pub fn of(element: &Value) -> Self {
        let strings = |member: &str| -> BTreeSet<String> {
            element
                .get(member)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            detail_type: element
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            actions: strings("actions"),
            locations: strings("locations"),
        }
    }
}

/// What is being attempted (§5.2): a `name`, and optional `properties`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    name: String,
    properties: Properties,
}

impl Action {
    /// An action.
    ///
    /// # Errors
    ///
    /// [`RequestError::Identifier`] for an empty or over-long name.
    pub fn new(name: &str, properties: Properties) -> Result<Self, RequestError> {
        Ok(Self {
            name: identifier("action.name", name)?,
            properties,
        })
    }

    /// §5.2's `name`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// §5.2's `properties`.
    #[must_use]
    pub const fn properties(&self) -> &Properties {
        &self.properties
    }
}

/// What is being acted on (§5.3): a `type`, an `id` and optional `properties`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    kind: String,
    id: String,
    properties: Properties,
}

impl Resource {
    /// A resource.
    ///
    /// # Errors
    ///
    /// [`RequestError::Identifier`] for an empty or over-long `type` or `id`.
    pub fn new(kind: &str, id: &str, properties: Properties) -> Result<Self, RequestError> {
        Ok(Self {
            kind: identifier("resource.type", kind)?,
            id: identifier("resource.id", id)?,
            properties,
        })
    }

    /// §5.3's `type`.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// §5.3's `id`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// §5.3's `properties`.
    #[must_use]
    pub const fn properties(&self) -> &Properties {
        &self.properties
    }
}

/// The environment of the request (§5.4), plus the one environmental fact this
/// server owns: how strongly the person authenticated.
///
/// # Why the ladder travels with the request
///
/// "`acr` at least *L*" is not a comparison between two strings. A tenant's
/// authentication contexts are an *ordered ladder* ([`crate::AcrPolicy`]),
/// weakest first, and "at least" means "at or above on that ladder". The
/// evaluator is a pure function of its inputs — it holds no repository and
/// reads no row — so the ladder is an input: [`Context::acr`] carries the value
/// the session reached and [`Context::ladder`] the tenant's order at the moment
/// the request was resolved.
///
/// A required value that is not on the ladder makes the condition false rather
/// than an error. That is the fail-closed direction: a rule naming a context
/// the tenant no longer publishes stops admitting anybody instead of admitting
/// everybody.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Context {
    acr: Option<String>,
    ladder: Vec<String>,
    properties: Properties,
}

impl Context {
    /// A context carrying only the PEP's properties.
    #[must_use]
    pub fn new(properties: Properties) -> Self {
        Self {
            acr: None,
            ladder: Vec::new(),
            properties,
        }
    }

    /// Attaches the `acr` the session reached, and the tenant's ladder to read
    /// it against, weakest first.
    #[must_use]
    pub fn with_acr<I: IntoIterator<Item = String>>(
        mut self,
        acr: Option<String>,
        ladder: I,
    ) -> Self {
        self.acr = acr;
        self.ladder = ladder.into_iter().collect();
        self
    }

    /// The `acr` the session reached, if any.
    #[must_use]
    pub fn acr(&self) -> Option<&str> {
        self.acr.as_deref()
    }

    /// The tenant's ladder, weakest first.
    #[must_use]
    pub fn ladder(&self) -> &[String] {
        &self.ladder
    }

    /// §5.4's properties.
    #[must_use]
    pub const fn properties(&self) -> &Properties {
        &self.properties
    }

    /// Whether the session's `acr` is at or above `required` on the ladder.
    ///
    /// False when either value is off the ladder, or when no `acr` was
    /// reached — a session that authenticated in no published context does not
    /// satisfy a demand for one.
    #[must_use]
    pub fn acr_at_least(&self, required: &str) -> bool {
        let rank = |value: &str| self.ladder.iter().position(|rung| rung == value);
        match (self.acr.as_deref().and_then(rank), rank(required)) {
            (Some(held), Some(wanted)) => held >= wanted,
            _ => false,
        }
    }
}

/// One question for the PDP: §6.1's `subject`, `action`, `resource` and
/// `context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationRequest {
    /// Who is asking.
    pub subject: Subject,
    /// What they are attempting.
    pub action: Action,
    /// What they are attempting it on.
    pub resource: Resource,
    /// The environment it is attempted in.
    pub context: Context,
}

impl EvaluationRequest {
    /// A request.
    #[must_use]
    pub const fn new(
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context,
    ) -> Self {
        Self {
            subject,
            action,
            resource,
            context,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn subject() -> Subject {
        Subject::new("user", "alice", Properties::empty()).expect("a valid subject")
    }

    #[test]
    fn a_subject_carries_its_type_and_id() {
        // Arrange / Act
        let subject = subject();

        // Assert
        assert_eq!(subject.kind(), "user");
        assert_eq!(subject.id(), "alice");
    }

    #[test]
    fn an_empty_subject_id_is_refused() {
        // Arrange / Act
        let refused = Subject::new("user", "", Properties::empty());

        // Assert
        assert_eq!(refused.unwrap_err(), RequestError::Identifier("subject.id"));
    }

    #[test]
    fn a_properties_bag_beyond_the_bound_is_refused() {
        // Arrange
        let members: Vec<(String, Value)> = (0..=MAX_PROPERTIES)
            .map(|index| (format!("p{index}"), json!(index)))
            .collect();

        // Act
        let refused = Properties::new(members);

        // Assert
        assert_eq!(refused.unwrap_err(), RequestError::TooManyProperties);
    }

    #[test]
    fn a_property_nested_too_deeply_is_refused() {
        // Arrange
        let mut value = json!("leaf");
        for _ in 0..MAX_PROPERTY_DEPTH {
            value = json!([value]);
        }

        // Act
        let refused = Properties::new([("deep", value)]);

        // Assert
        assert_eq!(
            refused.unwrap_err(),
            RequestError::PropertyDepth("deep".to_owned())
        );
    }

    #[test]
    fn a_property_with_too_many_nodes_is_refused() {
        // Arrange
        let wide: Vec<Value> = (0..=MAX_PROPERTY_NODES).map(|i| json!(i)).collect();

        // Act
        let refused = Properties::new([("wide", Value::Array(wide))]);

        // Assert
        assert_eq!(
            refused.unwrap_err(),
            RequestError::PropertySize("wide".to_owned())
        );
    }

    #[test]
    fn properties_that_are_not_an_object_are_no_attributes_at_all() {
        // Arrange / Act
        let properties = Properties::from_json(&json!("not an object")).expect("no attributes");

        // Assert
        assert!(properties.is_empty());
    }

    /// The whole point of the ladder: "at least" is an order, not a string
    /// comparison.
    #[test]
    fn acr_at_least_reads_the_tenants_ladder() {
        // Arrange
        let context = Context::new(Properties::empty()).with_acr(
            Some("urn:acr:passkey".to_owned()),
            ["urn:acr:password".to_owned(), "urn:acr:passkey".to_owned()],
        );

        // Act / Assert
        assert!(context.acr_at_least("urn:acr:password"));
        assert!(context.acr_at_least("urn:acr:passkey"));
    }

    #[test]
    fn a_weaker_acr_does_not_satisfy_a_stronger_demand() {
        // Arrange
        let context = Context::new(Properties::empty()).with_acr(
            Some("urn:acr:password".to_owned()),
            ["urn:acr:password".to_owned(), "urn:acr:passkey".to_owned()],
        );

        // Act / Assert
        assert!(!context.acr_at_least("urn:acr:passkey"));
    }

    /// Fail closed: a rule naming a context the tenant does not publish admits
    /// nobody.
    #[test]
    fn an_acr_off_the_ladder_satisfies_nothing() {
        // Arrange
        let context = Context::new(Properties::empty()).with_acr(
            Some("urn:acr:other".to_owned()),
            ["urn:acr:password".to_owned()],
        );

        // Act / Assert
        assert!(!context.acr_at_least("urn:acr:password"));
        assert!(!context.acr_at_least("urn:acr:unknown"));
    }

    #[test]
    fn a_session_with_no_acr_satisfies_nothing() {
        // Arrange
        let context =
            Context::new(Properties::empty()).with_acr(None, ["urn:acr:password".to_owned()]);

        // Act / Assert
        assert!(!context.acr_at_least("urn:acr:password"));
    }

    #[test]
    fn a_role_is_held_from_one_owner_only() {
        // Arrange
        let mut roles = HeldRoles::empty();
        roles
            .tenant
            .insert(RoleName::parse("auditor").expect("a name"));
        let subject = subject().with_roles(roles);
        let auditor = RoleName::parse("auditor").expect("a name");

        // Act / Assert
        assert!(subject.holds_role(Some(&RoleOwner::Tenant), &auditor));
        assert!(subject.holds_role(None, &auditor));
        assert!(!subject.holds_role(Some(&RoleOwner::Client(ClientId::new("c.1"))), &auditor));
    }

    #[test]
    fn an_authorization_detail_reduces_to_type_actions_and_locations() {
        // Arrange
        let element = json!({
            "type": "payment_initiation",
            "actions": ["initiate", "status"],
            "locations": ["https://api.example/payments"],
            "instructedAmount": { "currency": "EUR", "amount": "123.50" },
        });

        // Act
        let fact = DetailFact::of(&element);

        // Assert
        assert_eq!(fact.detail_type, "payment_initiation");
        assert!(fact.actions.contains("initiate"));
        assert!(fact.locations.contains("https://api.example/payments"));
    }

    #[test]
    fn a_detail_whose_members_are_the_wrong_shape_is_an_absent_fact() {
        // Arrange / Act
        let fact = DetailFact::of(&json!({ "type": 7, "actions": "initiate" }));

        // Assert
        assert_eq!(fact, DetailFact::default());
    }
}
