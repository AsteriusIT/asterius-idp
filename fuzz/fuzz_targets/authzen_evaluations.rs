//! The AuthZEN Access Evaluations request — Authorization API 1.0 §7.1,
//! §7.1.1, §7.1.2.1, §10.1.1, §11.5, §11.7 (`ast-pj0.2`).
//!
//! §7's boxcar is the one place in this PDP where a single document becomes
//! *many* authorization questions, and where one question's data can reach
//! another's: §7.1.1's defaults are merged into every evaluation that did not
//! name its own. That merge is what this target is for. Six properties:
//!
//! * **The bounds hold, and hold first.** `MAX_REQUEST_BYTES` of body,
//!   `MAX_DEPTH` of nesting and `MAX_EVALUATIONS` of array (§11.7) — the last
//!   one being the bound on *work* rather than on parsing, since one accepted
//!   array is one rate-limiter token and as many policy walks as it is long.
//! * **Every accepted evaluation is a complete §6.1 request.** A non-empty
//!   `type` and `id` on the subject and the resource, a non-empty `name` on
//!   the action, whether they came from the item or from the defaults
//!   (§7.1.1). An evaluation naming nobody is not a request.
//! * **A default is only ever a default.** An item that named its own entity
//!   is decided about *that* entity: nothing merges member by member, so no
//!   evaluation can end up naming a subject that appears nowhere in the
//!   document.
//! * **A PEP asserts nothing**, at the top level or in an item: no group, no
//!   role, no grant, no `acr`. Those are resolved by the endpoint from this
//!   server's own rows, and a parser that could fill one in would be a
//!   privilege escalation spelled as a property.
//! * **§7.1's compatible shape is one request.** An absent or empty
//!   `evaluations` array parses to exactly one evaluation, and to the same one
//!   [`parse_evaluation`] reads — the two entry points must not disagree about
//!   what a §6.1 document says.
//! * **Parsing is total and deterministic**, and evaluation stays total over
//!   whatever survives: every accepted evaluation is decided rather than
//!   panicked on, and decided the same way twice.
#![no_main]

use asterius_domain::policy::RuleSet;
use asterius_oidc::authzen::{
    AuthzenError, EvaluationsSemantic, MAX_DEPTH, MAX_EVALUATIONS, MAX_REQUEST_BYTES,
    decision_response, evaluations_response, parse_evaluation, parse_evaluations,
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
            {"id": "read-public", "effect": "permit",
             "subject_type": "user", "resource_type": "document",
             "actions": ["read", "can_read"],
             "when": {"all": [
                {"any": [{"group": "finance"},
                         {"attribute": {"of": "resource", "name": "public", "equals": true}}]},
                {"not": {"acr_at_least": "urn:asterius:acr:passkey-uv"}}]}}
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

/// Whether the document carries a non-empty §7.1 array, read independently of
/// the parser so that `boxcar` is checked against the bytes rather than
/// against the answer the parser already gave.
fn carries_an_array(data: &[u8]) -> Option<usize> {
    let document: Value = serde_json::from_slice(data).ok()?;
    let items = document.get("evaluations")?.as_array()?;
    (!items.is_empty()).then_some(items.len())
}

fuzz_target!(|data: &[u8]| {
    let parsed = parse_evaluations(data);

    // Deterministic: the same bytes give the same answer, every time.
    match (&parsed, &parse_evaluations(data)) {
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
    assert!(
        request.evaluations.len() <= MAX_EVALUATIONS,
        "accepted {} evaluations",
        request.evaluations.len()
    );
    assert!(
        !request.evaluations.is_empty(),
        "an accepted request with nothing to decide"
    );

    // §7.1: the array decides the shape, and the shape decides the response.
    match carries_an_array(data) {
        Some(length) => {
            assert!(request.boxcar, "an evaluations array was not read as one");
            assert_eq!(
                request.evaluations.len(),
                length,
                "the answer would not line up with the request (§7.2)"
            );
        }
        None => {
            assert!(!request.boxcar, "a single request became a boxcar");
            assert_eq!(request.evaluations.len(), 1);
            // …and it is the very request §6.1's parser reads.
            assert_eq!(
                parse_evaluation(data).expect("§6.1 reads what §7.1 read"),
                request.evaluations[0],
                "the two entry points disagreed about one document"
            );
        }
    }

    // §7.1.2.1: exactly one of three semantics, and `execute_all` unless the
    // PEP named another.
    assert!(matches!(
        request.semantic,
        EvaluationsSemantic::ExecuteAll
            | EvaluationsSemantic::DenyOnFirstDeny
            | EvaluationsSemantic::PermitOnFirstPermit
    ));

    let policy = catalogue();
    let mut rendered = Vec::with_capacity(request.evaluations.len());
    for evaluation in &request.evaluations {
        // §5, after §7.1.1's merge: every evaluation names what it asks about.
        assert!(!evaluation.subject.kind().is_empty());
        assert!(!evaluation.subject.id().is_empty());
        assert!(!evaluation.action.name().is_empty());
        assert!(!evaluation.resource.kind().is_empty());
        assert!(!evaluation.resource.id().is_empty());

        // Nothing the PEP sent became a fact about authority — in an item or
        // in the defaults it was merged from.
        assert!(
            evaluation.subject.groups().is_empty(),
            "a PEP claimed a group"
        );
        assert!(
            evaluation.subject.grants().is_empty(),
            "a PEP claimed an authorization"
        );
        assert!(
            evaluation.subject.roles().tenant.is_empty()
                && evaluation.subject.roles().clients.is_empty(),
            "a PEP claimed a role"
        );
        assert!(evaluation.context.acr().is_none(), "a PEP claimed an acr");
        assert!(
            evaluation.context.ladder().is_empty(),
            "a PEP claimed an authentication ladder"
        );

        // §11.7 again, from the other side: everything that survived is within
        // the nesting bound, property bags included.
        for bag in [
            evaluation.subject.properties(),
            evaluation.action.properties(),
            evaluation.resource.properties(),
            evaluation.context.properties(),
        ] {
            for (_, value) in bag.iter() {
                assert!(
                    depth(value) < MAX_DEPTH,
                    "accepted a property {} levels deep",
                    depth(value)
                );
            }
        }

        // Evaluation is total and deterministic over anything that got this
        // far, and §5.5's `decision` is there whatever it decided.
        let decision = policy.evaluate(evaluation);
        assert_eq!(
            decision,
            policy.evaluate(evaluation),
            "two evaluations of one request disagreed"
        );
        let answer = decision_response(&decision);
        assert_eq!(answer["decision"], Value::Bool(decision.permit()));
        rendered.push(answer);
    }

    // §7.2: an array in request order, and no top-level decision.
    let asked = rendered.len();
    let response = evaluations_response(rendered);
    assert_eq!(
        response["evaluations"].as_array().map(Vec::len),
        Some(asked)
    );
    assert!(response.get("decision").is_none());
});
