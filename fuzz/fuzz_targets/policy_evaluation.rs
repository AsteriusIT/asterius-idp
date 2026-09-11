//! Deciding a request against a tenant's policy (`ast-pj0.4`, ADR-0011).
//!
//! `policy_document` varies the *document*; this target varies the
//! **request** — the half an attacker actually controls. A PEP composes it
//! from a subject, an action, a resource and a context (Authorization API 1.0
//! §5), and everything in `properties` is whatever that PEP sent.
//!
//! Properties:
//!
//! * **Total.** Every request has a decision. There is no input that panics
//!   and none that makes the evaluator fail, because a failure here would be
//!   an authorization outcome decided by an error path.
//! * **Deterministic.** The same request, twice, is the same decision and the
//!   same explanation. Two replicas must not disagree about whether somebody
//!   may move money.
//! * **An empty policy permits nothing.** The property a deployment's safety
//!   rests on the day a tenant is created, whatever a PEP claims about the
//!   request.
//! * **A PEP cannot assert its way past a group, a role or an `acr`.** The
//!   catalogue below permits only on facts this server resolves; the request
//!   generator fills `properties` freely and leaves those facts empty, so any
//!   permit at all would be a PEP-asserted authority.
//! * **A decision's explanation is one of the document's own.** A reason or an
//!   `acr_values` hint that no rule wrote would be information leaving the
//!   engine that nobody put in it.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::policy::{
    Action, Context, EvaluationRequest, Properties, Resource, RuleSet, Subject,
};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// A catalogue exercising every condition the language has.
///
/// A constant rather than a generated document: the question here is what a
/// *request* can make of a fixed policy, which is the shape of the real
/// system — an administrator writes the rules, and a PEP asks the questions.
const CATALOGUE: &str = r#"{
    "version": 1,
    "rules": [
        {"id": "deny-suspended", "effect": "deny",
         "when": {"attribute": {"of": "subject", "name": "status", "equals": "suspended"}},
         "reason_admin": "the account is suspended",
         "reason_user": "This account is not active."},
        {"id": "deny-without-passkey", "effect": "deny", "resource_type": "payment",
         "when": {"not": {"acr_at_least": "urn:acr:passkey"}},
         "acr_values": ["urn:acr:passkey"]},
        {"id": "permit-finance", "effect": "permit",
         "when": {"any": [
            {"group": "finance"},
            {"role": {"name": "auditor", "owner": "tenant"}},
            {"grant": {"resource": "$resource.id", "detail_type": "payment_initiation",
                       "action": "initiate"}}
         ]}},
        {"id": "permit-self", "effect": "permit", "actions": ["can_read"],
         "when": {"all": [
            {"attribute": {"of": "resource", "name": "owner", "equals": "alice"}},
            {"attribute": {"of": "context", "name": "country", "in": ["FR", "BE"]}}
         ]}}
    ]
}"#;

/// A property value a PEP could plausibly send.
#[derive(Arbitrary, Debug, Clone)]
enum Scalar {
    Null,
    Bool(bool),
    Int(i64),
    Text(String),
    List(Vec<String>),
}

impl From<Scalar> for Value {
    fn from(scalar: Scalar) -> Self {
        match scalar {
            Scalar::Null => Self::Null,
            Scalar::Bool(value) => Self::from(value),
            Scalar::Int(value) => Self::from(value),
            Scalar::Text(value) => Self::from(value),
            Scalar::List(values) => Self::from(values),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Case {
    subject_type: String,
    subject_id: String,
    subject_properties: Vec<(String, Scalar)>,
    action: String,
    action_properties: Vec<(String, Scalar)>,
    resource_type: String,
    resource_id: String,
    resource_properties: Vec<(String, Scalar)>,
    context_properties: Vec<(String, Scalar)>,
    /// What the PEP would like this server to believe the session reached.
    /// The request builder puts it in `properties`, where it belongs, and
    /// never on the ladder — which is the point of the test.
    claimed_acr: String,
}

fn properties(members: Vec<(String, Scalar)>) -> Option<Properties> {
    Properties::new(
        members
            .into_iter()
            .map(|(name, value)| (name, Value::from(value))),
    )
    .ok()
}

fuzz_target!(|case: Case| {
    let catalogue =
        RuleSet::parse(CATALOGUE).expect("the catalogue is a document this build reads");

    let Some(subject_properties) = properties(case.subject_properties) else {
        return;
    };
    let Some(action_properties) = properties(case.action_properties) else {
        return;
    };
    let Some(resource_properties) = properties(case.resource_properties) else {
        return;
    };
    let Some(mut context_members) = properties(case.context_properties).map(|bag| {
        bag.iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Vec<_>>()
    }) else {
        return;
    };
    // The claim a PEP would make if it could: an `acr` in the property bag.
    context_members.push(("acr".to_owned(), Value::from(case.claimed_acr)));
    let Ok(context_properties) = Properties::new(context_members) else {
        return;
    };

    let (Ok(subject), Ok(action), Ok(resource)) = (
        Subject::new(&case.subject_type, &case.subject_id, subject_properties),
        Action::new(&case.action, action_properties),
        Resource::new(&case.resource_type, &case.resource_id, resource_properties),
    ) else {
        return;
    };

    // No groups, no roles, no grants and no `acr`: everything this server
    // resolves is absent, so only what the PEP said is on the table.
    let request =
        EvaluationRequest::new(subject, action, resource, Context::new(context_properties));

    let decision = catalogue.evaluate(&request);
    assert_eq!(
        decision,
        catalogue.evaluate(&request),
        "the same question was answered twice differently"
    );

    assert!(
        !RuleSet::deny_all().evaluate(&request).permit(),
        "an empty policy permitted something"
    );

    if decision.permit() {
        // The only permit reachable without a group, a role or a grant is the
        // one written over `properties` — and reaching it means the PEP sent
        // the owner and the country the rule names, which is the tenant's own
        // decision to trust that PEP rather than an assertion of authority.
        let id = decision
            .context()
            .rule()
            .expect("a permit without a rule behind it");
        assert_eq!(
            id.as_str(),
            "permit-self",
            "a request permitted through a fact this server did not resolve"
        );
    }

    // Nothing comes out of the explanation that no rule put in.
    let context = decision.context();
    if let Some(id) = context.rule() {
        let rule = catalogue
            .rules()
            .iter()
            .find(|rule| &rule.id == id)
            .expect("the decision named a rule the catalogue does not hold");
        assert_eq!(context.reason_admin(), rule.reason_admin.as_deref());
        assert_eq!(context.reason_user(), rule.reason_user.as_deref());
        assert_eq!(context.acr_values(), rule.acr_values.as_slice());
    } else {
        assert!(
            context.reason_user().is_none(),
            "a default deny told the person something no administrator wrote"
        );
    }
});
