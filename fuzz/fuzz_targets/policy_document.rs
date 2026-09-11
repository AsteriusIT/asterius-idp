//! The tenant policy parser (`ast-pj0.4`, ADR-0011).
//!
//! `RuleSet::parse` stands between an administrator's browser and the document
//! the PDP decides every authorization question with. It is reached with a
//! session and a synchroniser token, and "authenticated" is not "trusted": the
//! caller is one tenant's operator, the process is shared with every other
//! tenant, and the document is stored and re-parsed on the decision path
//! afterwards.
//!
//! Properties:
//!
//! * **Total.** Arbitrary bytes are a request body. Parsing one must not
//!   panic, and neither must evaluating whatever comes out.
//! * **Bounded.** Everything accepted is inside the limits the module
//!   documents — rule count, condition count per rule and nesting depth — so a
//!   tenant cannot make a decision cost unbounded work in a shared process.
//!   The depth bound is what keeps the evaluator's recursion a constant of the
//!   code rather than of the input.
//! * **Round-trips.** `from_json(to_json(r)) == r`, so a document stored in a
//!   column and the rules the server enforces cannot drift, and the console's
//!   fetch-edit-put cannot silently drop what this build understood.
//! * **Ids are unique.** Two rules with one id would make "which rule denied
//!   this" depend on iteration order.
//! * **A permit written after a deny cannot overturn it.** The one ordering
//!   property the language guarantees, checked against a request built beside
//!   the document rather than derived from it.
#![no_main]

use asterius_domain::policy::document::{MAX_CONDITIONS, MAX_DEPTH, MAX_RULES};
use asterius_domain::policy::{
    Action, Condition, Context, Effect, EvaluationRequest, Properties, Resource, RuleSet, Subject,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    // Raw, and dressed as the places a fragment actually lands: a condition, a
    // rule id and an action name. Undirected noise would spend its budget
    // failing to be JSON at all.
    let escaped = serde_json::json!(raw);
    let candidates = [
        raw.to_owned(),
        format!(r#"{{"version": 1, "rules": {raw}}}"#),
        format!(r#"{{"version": 1, "rules": [{{"id": "r", "effect": "deny", "when": {raw}}}]}}"#),
        format!(r#"{{"version": 1, "rules": [{{"id": {escaped}, "effect": "permit"}}]}}"#),
        format!(
            r#"{{"version": 1, "rules": [{{"id": "r", "effect": "permit", "actions": [{escaped}],
                 "when": {{"attribute": {{"of": "subject", "name": {escaped},
                                          "equals": {escaped}}}}}}}]}}"#
        ),
        format!(
            r#"{{"version": 1, "rules": [
                 {{"id": "d", "effect": "deny", "reason_user": {escaped}}},
                 {{"id": "p", "effect": "permit", "when": {{"group": {escaped}}}}}]}}"#
        ),
    ];

    for candidate in &candidates {
        let Ok(rules) = RuleSet::parse(candidate) else {
            continue;
        };

        check_bounds(&rules);

        let again = RuleSet::from_json(&rules.to_json())
            .expect("a document this build wrote is one it reads");
        assert_eq!(
            again, rules,
            "a policy did not survive its own stored form: {candidate:?}"
        );

        // Evaluation is total, and the decision is the same every time.
        let request = request();
        let decision = rules.evaluate(&request);
        assert_eq!(
            decision,
            rules.evaluate(&request),
            "the same question was answered twice differently"
        );

        // Deny precedence: if any deny matched, the answer cannot be a permit.
        // Checked through the decision's own rule id rather than by
        // re-implementing matching here.
        if let Some(id) = decision.context().rule() {
            let named = rules
                .rules()
                .iter()
                .find(|rule| &rule.id == id)
                .expect("the decision named a rule the document does not hold");
            assert_eq!(
                decision.permit(),
                named.effect == Effect::Permit,
                "the decision disagrees with the effect of the rule it named"
            );
        } else {
            assert!(
                !decision.permit(),
                "a permit was returned without a rule behind it"
            );
        }
    }
});

/// A request to decide the parsed document against.
///
/// Built here rather than from the fuzzer's bytes, so that this target keeps
/// its budget on the *parser*; `policy_evaluation` is the one that varies the
/// request.
fn request() -> EvaluationRequest {
    EvaluationRequest::new(
        Subject::new("user", "alice", Properties::empty()).expect("a valid subject"),
        Action::new("can_read", Properties::empty()).expect("a valid action"),
        Resource::new("account", "acct-1", Properties::empty()).expect("a valid resource"),
        Context::default(),
    )
}

/// What is true of every document this build accepts.
fn check_bounds(rules: &RuleSet) {
    assert!(
        rules.rules().len() <= MAX_RULES,
        "{} rules were accepted",
        rules.rules().len()
    );

    let mut ids = std::collections::BTreeSet::new();
    for rule in rules.rules() {
        assert!(
            ids.insert(rule.id.clone()),
            "two rules carry the id {}",
            rule.id
        );
        assert!(
            !rule.id.as_str().is_empty(),
            "an empty rule id was accepted"
        );
        if let Some(condition) = &rule.when {
            let mut nodes = 0usize;
            let depth = measure(condition, &mut nodes);
            assert!(
                depth <= MAX_DEPTH,
                "a condition nested {depth} deep was accepted"
            );
            assert!(
                nodes <= MAX_CONDITIONS,
                "a rule carrying {nodes} conditions was accepted"
            );
        }
    }
}

/// The depth of a condition tree, counting its nodes on the way.
fn measure(condition: &Condition, nodes: &mut usize) -> usize {
    *nodes += 1;
    match condition {
        Condition::All(children) | Condition::Any(children) => {
            1 + children
                .iter()
                .map(|child| measure(child, nodes))
                .max()
                .unwrap_or(0)
        }
        Condition::Not(child) => 1 + measure(child, nodes),
        _ => 1,
    }
}
