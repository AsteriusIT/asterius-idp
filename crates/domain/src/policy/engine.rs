//! Evaluation: from a [`RuleSet`] and a request to a decision.
//!
//! # The three properties, and where each comes from
//!
//! **Deterministic.** Rules are walked in document order and every collection
//! read is ordered (`BTreeSet`, `Vec`). No hash iteration, no clock, no I/O, no
//! randomness: two replicas handed the same document and the same request
//! return the same decision, including the same explanation.
//!
//! **Total.** [`RuleSet::evaluate`] returns a [`Decision`] and not a `Result`.
//! Everything that could fail was refused at parse time
//! ([`super::document`]) or at request construction ([`super::request`]); what
//! is left — an attribute the request does not carry, an `acr` off the ladder,
//! a grant condition matching nothing — is a condition that is **false**. Deny
//! is therefore the outcome of ignorance, which is the direction an
//! authorization engine has to fail in.
//!
//! **Explainable.** A decision names the rule that produced it and carries
//! Authorization API 1.0 §5.5.1's `reason_admin`, `reason_user` and, on a deny
//! a PEP can act on, the `acr_values` that would satisfy a step-up.
//!
//! # Deny wins, and default is deny
//!
//! Every rule is considered. If any `deny` matches, the decision is that deny —
//! the *first* one in document order, so an administrator reading the document
//! top to bottom reads the explanation they will get. Only if none does is the
//! first matching `permit` the decision. A request that matches nothing at all
//! is denied with no rule named, which is also what an empty document does to
//! everything.
//!
//! A `permit` written after a `deny` therefore cannot overturn it. That is the
//! opposite of a firewall's first-match-wins and it is deliberate: a rule that
//! withdraws access must not be defeatable by a rule appended below it, which
//! is the accident an administrator makes when they add an exception.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::policy::document::{
    AttributeTest, Condition, Effect, GrantMatch, GrantResource, PolicyRuleId, Rule, RuleSet,
    Source,
};
use crate::policy::request::{ActiveGrant, EvaluationRequest, Properties};
use crate::ports::PolicyStore;
use crate::{DomainError, TenantId};

/// What the PDP answers (§5.5): a boolean, and the context that explains it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    permit: bool,
    context: DecisionContext,
}

impl Decision {
    /// §5.5's `decision`.
    #[must_use]
    pub const fn permit(&self) -> bool {
        self.permit
    }

    /// §5.5's `context`.
    #[must_use]
    pub const fn context(&self) -> &DecisionContext {
        &self.context
    }

    /// The deny a request that matched nothing gets.
    ///
    /// `reason_admin` says which of the two silences it was — a document with
    /// no rule for this request, or no document at all — because they are
    /// different operator problems. `reason_user` is deliberately not set:
    /// see [`DecisionContext`].
    #[must_use]
    pub fn default_deny(reason_admin: &'static str) -> Self {
        Self {
            permit: false,
            context: DecisionContext {
                rule: None,
                reason_admin: Some(reason_admin.to_owned()),
                reason_user: None,
                acr_values: Vec::new(),
            },
        }
    }

    fn from_rule(rule: &Rule) -> Self {
        Self {
            permit: rule.effect == Effect::Permit,
            context: DecisionContext {
                rule: Some(rule.id.clone()),
                reason_admin: rule.reason_admin.clone(),
                reason_user: rule.reason_user.clone(),
                acr_values: rule.acr_values.clone(),
            },
        }
    }
}

/// §5.5.1's decision context: why, and what would change the answer.
///
/// # Two reasons, and why they are not one
///
/// §5.5.1's example carries `reason_admin` and `reason_user` side by side, and
/// the split is the useful part. `reason_admin` is for whoever administers the
/// policy: it may name the rule, the attribute and the value, because its
/// reader is already allowed to read the document. `reason_user` is a sentence
/// that may be shown to the person who was refused, and everything in it is a
/// disclosure — "you are not in the `finance` group" tells an attacker that
/// the group exists and that membership is what stands between them and the
/// resource.
///
/// So a rule's `reason_user` is written by the administrator and never derived
/// from the request, and a default deny carries none at all. `ast-pj0.1`
/// renders both, and `docs/threat-model.md` carries the row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionContext {
    rule: Option<PolicyRuleId>,
    reason_admin: Option<String>,
    reason_user: Option<String>,
    acr_values: Vec<String>,
}

impl DecisionContext {
    /// The rule that decided, or `None` for a default deny.
    #[must_use]
    pub const fn rule(&self) -> Option<&PolicyRuleId> {
        self.rule.as_ref()
    }

    /// Why, for an operator.
    #[must_use]
    pub fn reason_admin(&self) -> Option<&str> {
        self.reason_admin.as_deref()
    }

    /// Why, in terms that may be shown to the person refused.
    #[must_use]
    pub fn reason_user(&self) -> Option<&str> {
        self.reason_user.as_deref()
    }

    /// The `acr` values that would satisfy a step-up, strongest intent first as
    /// the rule wrote them.
    #[must_use]
    pub fn acr_values(&self) -> &[String] {
        &self.acr_values
    }

    /// The context as §5.5.1 renders it.
    ///
    /// The reasons are objects keyed by language tag, as the specification's
    /// examples show; this build writes one tag, `en`, because a rule carries
    /// one string. `acr_values` is this deployment's own member, spelled as the
    /// parameter a client would send to fix the problem (OIDC Core §3.1.2.1),
    /// which is what makes the hint actionable by a PEP that has to start an
    /// authentication.
    ///
    /// Members that are absent are omitted rather than written as `null`:
    /// Authorization API 1.0 §11.5 asks for I-JSON and for nulls to be left
    /// out.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        if let Some(rule) = &self.rule {
            object.insert("id".to_owned(), json!(rule.as_str()));
        }
        if let Some(reason) = &self.reason_admin {
            object.insert("reason_admin".to_owned(), json!({ "en": reason }));
        }
        if let Some(reason) = &self.reason_user {
            object.insert("reason_user".to_owned(), json!({ "en": reason }));
        }
        if !self.acr_values.is_empty() {
            object.insert("acr_values".to_owned(), json!(self.acr_values));
        }
        Value::Object(object)
    }
}

impl RuleSet {
    /// Decides one request.
    ///
    /// Total: every input has a decision, and deny is what ignorance produces.
    /// See the module documentation for the order the rules are read in.
    #[must_use]
    // fuzz-target: policy_evaluation
    pub fn evaluate(&self, request: &EvaluationRequest) -> Decision {
        let mut permit: Option<&Rule> = None;
        for rule in self.rules() {
            if !matches(rule, request) {
                continue;
            }
            match rule.effect {
                Effect::Deny => return Decision::from_rule(rule),
                Effect::Permit => {
                    if permit.is_none() {
                        permit = Some(rule);
                    }
                }
            }
        }
        permit.map_or_else(
            || Decision::default_deny("no rule of this tenant's policy matched the request"),
            Decision::from_rule,
        )
    }
}

/// Whether a rule is about this request at all, and whether its condition
/// holds.
fn matches(rule: &Rule, request: &EvaluationRequest) -> bool {
    if let Some(kind) = &rule.subject_type
        && kind != request.subject.kind()
    {
        return false;
    }
    if let Some(kind) = &rule.resource_type
        && kind != request.resource.kind()
    {
        return false;
    }
    if !rule.actions.is_empty() && !rule.actions.contains(request.action.name()) {
        return false;
    }
    rule.when
        .as_ref()
        .is_none_or(|condition| holds(condition, request))
}

/// Whether one condition holds.
///
/// Recursive, and bounded by the parser: `MAX_DEPTH` was enforced on the way
/// in, so this cannot be driven deeper than a constant of
/// [`super::document`] whatever a tenant writes.
fn holds(condition: &Condition, request: &EvaluationRequest) -> bool {
    match condition {
        Condition::All(children) => children.iter().all(|child| holds(child, request)),
        Condition::Any(children) => children.iter().any(|child| holds(child, request)),
        Condition::Not(child) => !holds(child, request),
        Condition::Attribute { of, name, test } => {
            let bag: &Properties = match of {
                Source::Subject => request.subject.properties(),
                Source::Resource => request.resource.properties(),
                Source::Action => request.action.properties(),
                Source::Context => request.context.properties(),
            };
            bag.get(name).is_some_and(|value| compare(value, test))
        }
        Condition::Group(group) => request.subject.groups().contains(group),
        Condition::Role { owner, name } => request.subject.holds_role(owner.as_ref(), name),
        Condition::Grant(matcher) => request
            .subject
            .grants()
            .iter()
            .any(|grant| grant_matches(matcher, grant, request)),
        Condition::AcrAtLeast(required) => request.context.acr_at_least(required),
    }
}

/// Compares one attribute value against one test.
///
/// `In` is true when the value *is* one of the listed ones, and when the value
/// is an array sharing an element with them. Both readings are the same
/// question — "is this attribute one of these?" — asked of a single-valued and
/// of a multi-valued attribute, and a rule author should not have to know which
/// shape a PEP chose for `departments`.
fn compare(value: &Value, test: &AttributeTest) -> bool {
    match test {
        AttributeTest::Equals(expected) => value == expected,
        AttributeTest::In(expected) => match value {
            Value::Array(items) => items.iter().any(|item| expected.contains(item)),
            scalar => expected.contains(scalar),
        },
    }
}

/// Whether one active grant satisfies every member the rule named.
///
/// The `detail_type` and `action` members are read against **one** element:
/// "an authorization detail of type T permitting action A" is a statement about
/// a single element of RFC 9396's array, and satisfying it from two would
/// permit an action the client was never granted on that type.
fn grant_matches(matcher: &GrantMatch, grant: &ActiveGrant, request: &EvaluationRequest) -> bool {
    if let Some(client) = &matcher.client
        && &grant.client != client
    {
        return false;
    }
    if let Some(resource) = &matcher.resource {
        let wanted = match resource {
            GrantResource::Literal(raw) => raw.as_str(),
            GrantResource::TheResource => request.resource.id(),
        };
        if !grant.resources.iter().any(|held| held == wanted) {
            return false;
        }
    }
    if let Some(scope) = &matcher.scope
        && !grant.scopes.contains(scope)
    {
        return false;
    }
    match (&matcher.detail_type, &matcher.action) {
        (None, None) => true,
        (Some(detail_type), None) => grant
            .details
            .iter()
            .any(|detail| &detail.detail_type == detail_type),
        (None, Some(action)) => grant
            .details
            .iter()
            .any(|detail| detail.actions.contains(action)),
        (Some(detail_type), Some(action)) => grant
            .details
            .iter()
            .any(|detail| &detail.detail_type == detail_type && detail.actions.contains(action)),
    }
}

/// The built-in PDP: [ADR-0011]'s declarative engine behind the port.
///
/// Holds a [`PolicyStore`] and nothing else. The *decision* is still a pure
/// function of a document and a request — the store is read before evaluation
/// begins, never during it — so everything the module documentation claims
/// about determinism survives having a repository in the struct.
///
/// # Fail closed, in two different ways
///
/// A tenant with **no document** is not an error: it is a tenant that has not
/// written a policy, and it denies everything with a `reason_admin` that says
/// so. A store that **cannot be read** is a [`DomainError`], propagated rather
/// than turned into a deny here, because the endpoint is where "the PDP is
/// broken" has to be told apart from "the answer is no" — §10.1.2 gives it a
/// 200 with `decision: false` and an error in the context, and it audits it.
///
/// [ADR-0011]: https://github.com/AsteriusIT/asterius-idp/blob/main/docs/adr/0011-a-declarative-rule-model-for-the-built-in-pdp.md
#[derive(Debug, Clone)]
pub struct DeclarativeEngine {
    policies: Arc<dyn PolicyStore>,
}

impl DeclarativeEngine {
    /// An engine reading the tenants' documents from `policies`.
    #[must_use]
    pub const fn new(policies: Arc<dyn PolicyStore>) -> Self {
        Self { policies }
    }
}

#[async_trait::async_trait]
impl crate::ports::PolicyEngine for DeclarativeEngine {
    async fn evaluate(
        &self,
        tenant: &TenantId,
        request: &EvaluationRequest,
    ) -> Result<Decision, DomainError> {
        let stored = self.policies.load(tenant).await?;
        Ok(stored.map_or_else(
            || Decision::default_deny("this tenant has no policy document"),
            |policy| policy.rules.evaluate(request),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::application_role::HeldRoles;
    use crate::policy::request::{Action, Context, DetailFact, Resource, Subject};
    use crate::{ClientId, RoleName};
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn rules(json: &str) -> RuleSet {
        RuleSet::parse(&format!(r#"{{"version": 1, "rules": {json}}}"#)).expect("a valid catalogue")
    }

    fn request() -> EvaluationRequest {
        EvaluationRequest::new(
            Subject::new("user", "alice", Properties::empty()).expect("a subject"),
            Action::new("can_read", Properties::empty()).expect("an action"),
            Resource::new("account", "acct-1", Properties::empty()).expect("a resource"),
            Context::default(),
        )
    }

    #[test]
    fn an_empty_policy_denies_everything() {
        // Arrange
        let policy = RuleSet::deny_all();

        // Act
        let decision = policy.evaluate(&request());

        // Assert
        assert!(!decision.permit());
        assert!(decision.context().rule().is_none());
    }

    #[test]
    fn a_request_matching_no_rule_is_denied() {
        // Arrange
        let policy = rules(r#"[{"id": "r", "effect": "permit", "actions": ["can_write"]}]"#);

        // Act / Assert
        assert!(!policy.evaluate(&request()).permit());
    }

    #[test]
    fn a_matching_permit_permits() {
        // Arrange
        let policy = rules(
            r#"[{"id": "read-accounts", "effect": "permit",
                 "subject_type": "user", "resource_type": "account",
                 "actions": ["can_read"]}]"#,
        );

        // Act
        let decision = policy.evaluate(&request());

        // Assert
        assert!(decision.permit());
        assert_eq!(
            decision.context().rule().map(PolicyRuleId::as_str),
            Some("read-accounts")
        );
    }

    /// The rule the whole ordering exists for: an exception appended below a
    /// deny must not overturn it.
    #[test]
    fn an_explicit_deny_wins_however_it_is_ordered() {
        // Arrange
        let deny_first =
            rules(r#"[{"id": "d", "effect": "deny"}, {"id": "p", "effect": "permit"}]"#);
        let permit_first =
            rules(r#"[{"id": "p", "effect": "permit"}, {"id": "d", "effect": "deny"}]"#);

        // Act / Assert
        for policy in [deny_first, permit_first] {
            let decision = policy.evaluate(&request());
            assert!(!decision.permit());
            assert_eq!(
                decision.context().rule().map(PolicyRuleId::as_str),
                Some("d")
            );
        }
    }

    #[test]
    fn a_rule_about_another_subject_type_does_not_match() {
        // Arrange
        let policy = rules(r#"[{"id": "r", "effect": "permit", "subject_type": "agent"}]"#);

        // Act / Assert
        assert!(!policy.evaluate(&request()).permit());
    }

    #[test]
    fn an_attribute_equality_reads_the_named_bag() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit",
                 "when": {"attribute": {"of": "resource", "name": "owner", "equals": "alice"}}}]"#,
        );
        let mut request = request();
        request.resource = Resource::new(
            "account",
            "acct-1",
            Properties::new([("owner", json!("alice"))]).expect("properties"),
        )
        .expect("a resource");

        // Act / Assert
        assert!(policy.evaluate(&request).permit());
    }

    #[test]
    fn an_attribute_the_request_does_not_carry_is_false_and_not_an_error() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit",
                 "when": {"attribute": {"of": "subject", "name": "absent", "equals": 1}}}]"#,
        );

        // Act / Assert
        assert!(!policy.evaluate(&request()).permit());
    }

    #[test]
    fn set_membership_reads_a_scalar_and_a_list_the_same_way() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit",
                 "when": {"attribute": {"of": "subject", "name": "department",
                                        "in": ["finance", "legal"]}}}]"#,
        );
        let scalar = Properties::new([("department", json!("legal"))]).expect("properties");
        let list =
            Properties::new([("department", json!(["sales", "legal"]))]).expect("properties");

        // Act / Assert
        for properties in [scalar, list] {
            let mut request = request();
            request.subject = Subject::new("user", "alice", properties).expect("a subject");
            assert!(policy.evaluate(&request).permit());
        }
    }

    #[test]
    fn a_group_condition_reads_the_groups_this_server_resolved() {
        // Arrange
        let policy = rules(r#"[{"id": "r", "effect": "permit", "when": {"group": "finance"}}]"#);
        let mut request = request();
        request.subject = request.subject.clone().with_groups(["finance".to_owned()]);

        // Act / Assert
        assert!(policy.evaluate(&request).permit());
    }

    #[test]
    fn a_role_condition_distinguishes_the_catalogue_it_came_from() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit",
                 "when": {"role": {"name": "approver", "owner": "c.42"}}}]"#,
        );
        let approver = RoleName::parse("approver").expect("a name");

        let mut tenant_only = HeldRoles::empty();
        tenant_only.tenant.insert(approver.clone());
        let mut from_the_client = HeldRoles::empty();
        from_the_client
            .clients
            .entry(ClientId::new("c.42"))
            .or_default()
            .insert(approver);

        // Act / Assert
        let mut request = request();
        request.subject = request.subject.clone().with_roles(tenant_only);
        assert!(!policy.evaluate(&request).permit());

        request.subject = request.subject.clone().with_roles(from_the_client);
        assert!(policy.evaluate(&request).permit());
    }

    fn grant_for(resource: &str, detail_type: &str, action: &str) -> ActiveGrant {
        ActiveGrant {
            client: ClientId::new("c.42"),
            scopes: BTreeSet::from(["payments".to_owned()]),
            resources: BTreeSet::from([resource.to_owned()]),
            details: vec![DetailFact {
                detail_type: detail_type.to_owned(),
                actions: BTreeSet::from([action.to_owned()]),
                locations: BTreeSet::new(),
            }],
        }
    }

    /// The acceptance criterion in the ticket's own words: "the subject holds
    /// an active grant for resource R with `authorization_details` of type T and
    /// action A".
    #[test]
    fn a_grant_condition_matches_resource_type_and_action_on_one_grant() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit",
                 "when": {"grant": {"resource": "$resource.id",
                                    "detail_type": "payment_initiation",
                                    "action": "initiate"}}}]"#,
        );
        let mut request = request();
        request.resource = Resource::new(
            "payment",
            "https://api.example/payments",
            Properties::empty(),
        )
        .expect("a resource");
        request.subject = request
            .subject
            .clone()
            .with_grants([grant_for(
                "https://api.example/payments",
                "payment_initiation",
                "initiate",
            )])
            .expect("grants");

        // Act / Assert
        assert!(policy.evaluate(&request).permit());
    }

    #[test]
    fn a_grant_for_another_resource_does_not_match() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit",
                 "when": {"grant": {"resource": "$resource.id"}}}]"#,
        );
        let mut request = request();
        request.subject = request
            .subject
            .clone()
            .with_grants([grant_for("https://elsewhere.example", "t", "a")])
            .expect("grants");

        // Act / Assert
        assert!(!policy.evaluate(&request).permit());
    }

    /// Type and action have to be satisfied by one element, not gathered from
    /// two.
    #[test]
    fn a_detail_type_and_an_action_are_read_off_the_same_element() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit",
                 "when": {"grant": {"detail_type": "payment_initiation", "action": "delete"}}}]"#,
        );
        let mut grant = grant_for("https://api.example", "payment_initiation", "initiate");
        grant.details.push(DetailFact {
            detail_type: "account_information".to_owned(),
            actions: BTreeSet::from(["delete".to_owned()]),
            locations: BTreeSet::new(),
        });
        let mut request = request();
        request.subject = request
            .subject
            .clone()
            .with_grants([grant])
            .expect("grants");

        // Act / Assert
        assert!(!policy.evaluate(&request).permit());
    }

    #[test]
    fn a_deny_carries_its_reasons_and_its_step_up_hint() {
        // Arrange
        let policy = rules(
            r#"[{"id": "step-up", "effect": "deny",
                 "when": {"not": {"acr_at_least": "urn:acr:passkey"}},
                 "reason_admin": "rule step-up: acr below urn:acr:passkey",
                 "reason_user": "Please sign in with your passkey.",
                 "acr_values": ["urn:acr:passkey"]}]"#,
        );
        let mut request = request();
        request.context = Context::default().with_acr(
            Some("urn:acr:password".to_owned()),
            ["urn:acr:password".to_owned(), "urn:acr:passkey".to_owned()],
        );

        // Act
        let decision = policy.evaluate(&request);

        // Assert
        assert!(!decision.permit());
        assert_eq!(
            decision.context().reason_user(),
            Some("Please sign in with your passkey.")
        );
        assert_eq!(decision.context().acr_values(), ["urn:acr:passkey"]);
    }

    /// §5.5.1's shape, and §11.5's "omit nulls".
    #[test]
    fn a_decision_context_renders_reasons_as_language_tagged_objects() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "deny", "reason_admin": "because",
                 "acr_values": ["urn:acr:passkey"]}]"#,
        );

        // Act
        let rendered = policy.evaluate(&request()).context().to_json();

        // Assert
        assert_eq!(
            rendered,
            json!({
                "id": "r",
                "reason_admin": { "en": "because" },
                "acr_values": ["urn:acr:passkey"],
            })
        );
    }

    /// A default deny says nothing to the person refused: there is no rule
    /// whose author decided what they may be told.
    #[test]
    fn a_default_deny_carries_no_user_facing_reason() {
        // Arrange / Act
        let decision = RuleSet::deny_all().evaluate(&request());

        // Assert
        assert!(decision.context().reason_user().is_none());
        assert!(decision.context().reason_admin().is_some());
    }

    // -----------------------------------------------------------------------
    // The golden catalogue
    // -----------------------------------------------------------------------

    /// One catalogue exercising every condition the language has, with the
    /// decision each request must get.
    ///
    /// A golden rather than a dozen more unit tests: it is the artefact an
    /// administrator would actually write, and the table below is what the
    /// console's test bench (`ast-f7m.9`) will show. A change to evaluation
    /// order, to deny precedence or to any condition's meaning moves one of
    /// these rows, which is the point.
    const CATALOGUE: &str = r#"[
        {
            "id": "deny-suspended",
            "effect": "deny",
            "when": {"attribute": {"of": "subject", "name": "status", "equals": "suspended"}},
            "reason_admin": "the account is suspended",
            "reason_user": "This account is not active."
        },
        {
            "id": "deny-payments-without-passkey",
            "effect": "deny",
            "resource_type": "payment",
            "actions": ["initiate"],
            "when": {"not": {"acr_at_least": "urn:acr:passkey"}},
            "reason_admin": "payment initiation requires a phishing-resistant login",
            "reason_user": "Please sign in again with your passkey.",
            "acr_values": ["urn:acr:passkey"]
        },
        {
            "id": "permit-payment-with-grant",
            "effect": "permit",
            "subject_type": "user",
            "resource_type": "payment",
            "actions": ["initiate"],
            "when": {"grant": {"resource": "$resource.id",
                               "detail_type": "payment_initiation",
                               "action": "initiate"}}
        },
        {
            "id": "permit-finance-reads",
            "effect": "permit",
            "resource_type": "account",
            "actions": ["can_read"],
            "when": {"any": [
                {"group": "finance"},
                {"role": {"name": "auditor", "owner": "tenant"}}
            ]}
        }
    ]"#;

    fn catalogue() -> RuleSet {
        rules(CATALOGUE)
    }

    #[test]
    fn golden_a_suspended_account_is_denied_whatever_else_holds() {
        // Arrange
        let policy = catalogue();
        let mut request = request();
        request.subject = Subject::new(
            "user",
            "alice",
            Properties::new([("status", json!("suspended"))]).expect("properties"),
        )
        .expect("a subject")
        .with_groups(["finance".to_owned()]);

        // Act
        let decision = policy.evaluate(&request);

        // Assert
        assert!(!decision.permit());
        assert_eq!(
            decision.context().rule().map(PolicyRuleId::as_str),
            Some("deny-suspended")
        );
    }

    #[test]
    fn golden_finance_reads_an_account() {
        // Arrange
        let policy = catalogue();
        let mut request = request();
        request.subject = request.subject.clone().with_groups(["finance".to_owned()]);

        // Act
        let decision = policy.evaluate(&request);

        // Assert
        assert!(decision.permit());
        assert_eq!(
            decision.context().rule().map(PolicyRuleId::as_str),
            Some("permit-finance-reads")
        );
    }

    #[test]
    fn golden_a_payment_without_the_right_acr_is_denied_with_a_step_up_hint() {
        // Arrange
        let policy = catalogue();
        let mut request = request();
        request.action = Action::new("initiate", Properties::empty()).expect("an action");
        request.resource = Resource::new(
            "payment",
            "https://api.example/payments",
            Properties::empty(),
        )
        .expect("a resource");
        request.context = Context::default().with_acr(
            Some("urn:acr:password".to_owned()),
            ["urn:acr:password".to_owned(), "urn:acr:passkey".to_owned()],
        );
        request.subject = request
            .subject
            .clone()
            .with_grants([grant_for(
                "https://api.example/payments",
                "payment_initiation",
                "initiate",
            )])
            .expect("grants");

        // Act
        let decision = policy.evaluate(&request);

        // Assert
        assert!(!decision.permit());
        assert_eq!(decision.context().acr_values(), ["urn:acr:passkey"]);
    }

    #[test]
    fn golden_the_same_payment_with_a_passkey_is_permitted() {
        // Arrange
        let policy = catalogue();
        let mut request = request();
        request.action = Action::new("initiate", Properties::empty()).expect("an action");
        request.resource = Resource::new(
            "payment",
            "https://api.example/payments",
            Properties::empty(),
        )
        .expect("a resource");
        request.context = Context::default().with_acr(
            Some("urn:acr:passkey".to_owned()),
            ["urn:acr:password".to_owned(), "urn:acr:passkey".to_owned()],
        );
        request.subject = request
            .subject
            .clone()
            .with_grants([grant_for(
                "https://api.example/payments",
                "payment_initiation",
                "initiate",
            )])
            .expect("grants");

        // Act
        let decision = policy.evaluate(&request);

        // Assert
        assert!(decision.permit());
        assert_eq!(
            decision.context().rule().map(PolicyRuleId::as_str),
            Some("permit-payment-with-grant")
        );
    }

    /// The same payment without the grant: the deny does not fire (the `acr`
    /// is high enough) and no permit matches, so it is a default deny.
    #[test]
    fn golden_a_payment_with_no_grant_falls_through_to_the_default_deny() {
        // Arrange
        let policy = catalogue();
        let mut request = request();
        request.action = Action::new("initiate", Properties::empty()).expect("an action");
        request.resource = Resource::new(
            "payment",
            "https://api.example/payments",
            Properties::empty(),
        )
        .expect("a resource");
        request.context = Context::default().with_acr(
            Some("urn:acr:passkey".to_owned()),
            ["urn:acr:password".to_owned(), "urn:acr:passkey".to_owned()],
        );

        // Act
        let decision = policy.evaluate(&request);

        // Assert
        assert!(!decision.permit());
        assert!(decision.context().rule().is_none());
    }

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    /// Arbitrary strings, kept in the shape a request can hold: non-empty and
    /// bounded, because the constructors refuse anything else and a generator
    /// that spent its budget there would test the bound rather than the
    /// evaluator.
    fn identifier() -> impl Strategy<Value = String> {
        "[a-z$.:/_-]{1,24}"
    }

    fn scalar() -> impl Strategy<Value = Value> {
        prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::from),
            any::<i32>().prop_map(Value::from),
            identifier().prop_map(Value::from),
        ]
    }

    fn properties() -> impl Strategy<Value = Properties> {
        proptest::collection::vec((identifier(), scalar()), 0..8)
            .prop_map(|members| Properties::new(members).expect("a bounded bag"))
    }

    fn arbitrary_request() -> impl Strategy<Value = EvaluationRequest> {
        (
            (identifier(), identifier(), properties()),
            (identifier(), properties()),
            (identifier(), identifier(), properties()),
            (
                proptest::option::of(identifier()),
                proptest::collection::vec(identifier(), 0..4),
                properties(),
            ),
            proptest::collection::vec(identifier(), 0..4),
        )
            .prop_map(
                |(
                    (subject_type, subject_id, subject_properties),
                    (action, action_properties),
                    (resource_type, resource_id, resource_properties),
                    (acr, ladder, context_properties),
                    groups,
                )| {
                    let subject = Subject::new(&subject_type, &subject_id, subject_properties)
                        .expect("a bounded subject")
                        .with_groups(groups);
                    EvaluationRequest::new(
                        subject,
                        Action::new(&action, action_properties).expect("a bounded action"),
                        Resource::new(&resource_type, &resource_id, resource_properties)
                            .expect("a bounded resource"),
                        Context::new(context_properties).with_acr(acr, ladder),
                    )
                },
            )
    }

    proptest! {
        /// Totality: the evaluator answers, whatever it is asked.
        #[test]
        fn evaluation_never_panics(request in arbitrary_request()) {
            let _ = catalogue().evaluate(&request);
            let _ = RuleSet::deny_all().evaluate(&request);
        }

        /// Determinism: the same question, twice, is the same answer —
        /// including the same explanation.
        #[test]
        fn evaluation_is_deterministic(request in arbitrary_request()) {
            let policy = catalogue();
            prop_assert_eq!(policy.evaluate(&request), policy.evaluate(&request));
        }

        /// A policy with no rules permits nothing, whatever the request says
        /// about itself. The property a PEP's safety rests on the day a tenant
        /// is created.
        #[test]
        fn an_empty_policy_permits_nothing(request in arbitrary_request()) {
            prop_assert!(!RuleSet::deny_all().evaluate(&request).permit());
        }

        /// A catalogue's decisions survive the document it round-trips
        /// through, which is what the admin API's read-modify-write relies on.
        #[test]
        fn a_round_tripped_catalogue_decides_the_same_way(request in arbitrary_request()) {
            let policy = catalogue();
            let again = RuleSet::from_json(&policy.to_json()).expect("a document it wrote itself");
            prop_assert_eq!(policy.evaluate(&request), again.evaluate(&request));
        }
    }
}
