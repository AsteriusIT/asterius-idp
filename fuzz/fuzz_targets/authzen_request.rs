//! The AuthZEN Access Evaluation request — Authorization API 1.0 §5, §6.1,
//! §10.1.1, §11.5, §11.7 (`ast-pj0.1`).
//!
//! This is the only parser at the policy decision point, and everything behind
//! it decides who reaches what: a document a policy enforcement point composed
//! becomes a subject, an action and a resource that a tenant's rules are walked
//! against. Five properties matter, and each is a way that breaks.
//!
//! * **The bounds hold, and hold first.** At most `MAX_REQUEST_BYTES` of body
//!   and `MAX_DEPTH` levels of nesting (§11.7), applied before the members are
//!   looked for — a request that is nothing but nesting must cost the walk and
//!   not the policy.
//! * **What is accepted has the shape §5 names.** A non-empty `type` and `id`
//!   on the subject and the resource, a non-empty `name` on the action. A
//!   request naming nobody is not a request.
//! * **A PEP asserts nothing.** Whatever the fuzzer sends, the parsed subject
//!   holds no group, no role and no grant, and the context carries no `acr`:
//!   those are resolved by the endpoint from this server's own rows, and a
//!   parser that could fill one in would be a privilege escalation spelled as a
//!   property.
//! * **Parsing is total and deterministic.** No input panics, and the same
//!   bytes always give the same answer — including the refusal, whose message
//!   is what §10.1.2's 400 carries.
//! * **Evaluation stays total over whatever survives.** An accepted request is
//!   fed to the built-in engine, which must decide rather than panic, and decide
//!   the same way twice.
#![no_main]

use asterius_domain::policy::RuleSet;
use asterius_oidc::authzen::{
    AuthzenError, MAX_DEPTH, MAX_REQUEST_BYTES, decision_response, parse_evaluation,
};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// A catalogue exercising every kind of condition, so that an accepted request
/// is walked rather than dismissed by the rule heads.
fn catalogue() -> RuleSet {
    RuleSet::parse(
        r#"{"version": 1, "rules": [
            {"id": "deny-locked", "effect": "deny",
             "when": {"attribute": {"of": "resource", "name": "locked", "equals": true}}},
            {"id": "read-own", "effect": "permit",
             "subject_type": "user", "resource_type": "account",
             "actions": ["can_read", "can_read_todos"],
             "when": {"all": [
                {"any": [{"group": "finance"},
                         {"role": {"name": "auditor", "owner": "tenant"}},
                         {"attribute": {"of": "subject", "name": "department",
                                        "in": ["sales", "legal"]}}]},
                {"not": {"acr_at_least": "urn:asterius:acr:passkey-uv"}},
                {"grant": {"scope": "accounts.read", "detail_type": "payment_initiation"}}]}}
        ]}"#,
    )
    .expect("a fixed catalogue")
}

/// The deepest a value nests, counting containers.
fn depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(members) => 1 + members.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

fuzz_target!(|data: &[u8]| {
    let parsed = parse_evaluation(data);

    // Deterministic: the same bytes give the same answer, every time.
    match (&parsed, &parse_evaluation(data)) {
        (Ok(first), Ok(second)) => assert_eq!(first, second, "two parses disagreed"),
        (Err(first), Err(second)) => assert_eq!(first, second, "two refusals disagreed"),
        _ => panic!("the same bytes were both accepted and refused"),
    }

    let request = match parsed {
        Ok(request) => request,
        Err(error) => {
            // §10.1.2's body is an error message string, so every refusal has
            // to have one.
            assert!(
                !error.to_string().is_empty(),
                "a refusal with no message to put in the 400"
            );
            // The two bounds are reported as themselves rather than as a
            // generic parse failure, because an operator reading a PEP's logs
            // has to be able to tell "too big" from "malformed".
            if data.len() > MAX_REQUEST_BYTES {
                assert_eq!(error, AuthzenError::TooLong);
            }
            return;
        }
    };

    // §11.7: the bounds were applied, whatever else happened.
    assert!(
        data.len() <= MAX_REQUEST_BYTES,
        "accepted {} bytes",
        data.len()
    );

    // §5: an accepted request names what it is asking about.
    assert!(!request.subject.kind().is_empty());
    assert!(!request.subject.id().is_empty());
    assert!(!request.action.name().is_empty());
    assert!(!request.resource.kind().is_empty());
    assert!(!request.resource.id().is_empty());

    // Nothing the PEP sent became a fact about authority.
    assert!(request.subject.groups().is_empty(), "a PEP claimed a group");
    assert!(
        request.subject.grants().is_empty(),
        "a PEP claimed an authorization"
    );
    assert!(
        request.subject.roles().tenant.is_empty() && request.subject.roles().clients.is_empty(),
        "a PEP claimed a role"
    );
    assert!(request.context.acr().is_none(), "a PEP claimed an acr");
    assert!(
        request.context.ladder().is_empty(),
        "a PEP claimed an authentication ladder"
    );

    // §11.7 again, from the other side: everything that survived is within the
    // nesting bound, property bags included.
    for bag in [
        request.subject.properties(),
        request.action.properties(),
        request.resource.properties(),
        request.context.properties(),
    ] {
        for (_, value) in bag.iter() {
            assert!(
                depth(value) < MAX_DEPTH,
                "accepted a property {} levels deep",
                depth(value)
            );
        }
    }

    // Evaluation is total and deterministic over anything that got this far,
    // and §6.2's response is a `decision` whatever it decided.
    let policy = catalogue();
    let decision = policy.evaluate(&request);
    assert_eq!(
        decision,
        policy.evaluate(&request),
        "two evaluations of one request disagreed"
    );
    let rendered = decision_response(&decision);
    assert_eq!(rendered["decision"], Value::Bool(decision.permit()));
});
