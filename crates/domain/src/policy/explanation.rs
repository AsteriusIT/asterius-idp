//! Bounded administrator diagnostics over one immutable policy snapshot.
//!
//! No request value, policy literal, attribute name, group name, grant, or
//! reason is copied into a trace. Paths refer only to condition positions.
//! The normal engine neither computes nor serializes these diagnostics.

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::engine::{holds, matches};
use super::{Condition, EvaluationRequest, StoredPolicy};

/// Across all rules, not per rule. Truncation never changes the decision.
pub const MAX_TRACE_NODES: usize = 256;

/// The canonical content revision, independent of wall-clock precision.
#[must_use]
pub fn revision(rules: &super::RuleSet) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(rules.to_json().to_string().as_bytes()))
    )
}

/// Evaluate a snapshot only for an already-authorized administrative caller.
/// This produces diagnostics, never an access credential or persisted grant.
#[must_use]
pub fn evaluate(
    policy: Option<&StoredPolicy>,
    request: &EvaluationRequest,
    enforcement_point: &'static str,
) -> super::Decision {
    let decision = policy.map_or_else(
        || super::Decision::default_deny("this tenant has no policy document"),
        |stored| stored.rules.evaluate(request),
    );
    decision.with_explanation(explain(policy, request, enforcement_point))
}

/// Identifies the exact document used, including a default-deny absence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionExplanation {
    pub policy_revision: Option<String>,
    pub policy_updated_at: Option<String>,
    pub enforcement_point: &'static str,
    pub rules: Vec<RuleExplanation>,
    pub truncated: bool,
}

/// A rule's selector and condition outcomes, in document order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleExplanation {
    pub id: String,
    pub effect: &'static str,
    pub applicable: bool,
    pub matched: bool,
    pub conditions: Vec<ConditionExplanation>,
}

/// `matched` preserves the engine's boolean semantics, while `missing`
/// distinguishes unavailable context from a present value that was false.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConditionExplanation {
    pub path: String,
    pub kind: &'static str,
    pub matched: bool,
    pub missing: bool,
}

/// Explain after facts have been resolved for the same tenant and snapshot.
#[must_use]
pub fn explain(
    policy: Option<&StoredPolicy>,
    request: &EvaluationRequest,
    enforcement_point: &'static str,
) -> DecisionExplanation {
    let mut explanation = DecisionExplanation {
        policy_revision: None,
        policy_updated_at: None,
        enforcement_point,
        rules: Vec::new(),
        truncated: false,
    };
    let Some(policy) = policy else {
        return explanation;
    };
    // RuleSet serialization uses canonical ordered maps and document order;
    // unlike timestamps, the digest identifies the actual evaluated content.
    explanation.policy_revision = Some(revision(&policy.rules));
    explanation.policy_updated_at = Some(policy.updated_at.unix_timestamp_nanos().to_string());
    let mut remaining = MAX_TRACE_NODES;
    for rule in policy.rules.rules() {
        let applicable = rule
            .subject_type
            .as_ref()
            .is_none_or(|kind| kind == request.subject.kind())
            && rule
                .resource_type
                .as_ref()
                .is_none_or(|kind| kind == request.resource.kind())
            && (rule.actions.is_empty() || rule.actions.contains(request.action.name()));
        let mut conditions = Vec::new();
        if applicable && let Some(condition) = &rule.when {
            trace(
                condition,
                request,
                "when",
                &mut conditions,
                &mut remaining,
                &mut explanation.truncated,
            );
        }
        explanation.rules.push(RuleExplanation {
            id: rule.id.as_str().to_owned(),
            effect: rule.effect.as_str(),
            applicable,
            matched: matches(rule, request),
            conditions,
        });
    }
    explanation
}

fn trace(
    condition: &Condition,
    request: &EvaluationRequest,
    path: &str,
    out: &mut Vec<ConditionExplanation>,
    remaining: &mut usize,
    truncated: &mut bool,
) {
    if *remaining == 0 {
        *truncated = true;
        return;
    }
    *remaining -= 1;
    let (kind, missing) = match condition {
        Condition::All(_) => ("all", false),
        Condition::Any(_) => ("any", false),
        Condition::Not(_) => ("not", false),
        Condition::Attribute { of, name, .. } => {
            let bag = match of {
                super::Source::Subject => request.subject.properties(),
                super::Source::Resource => request.resource.properties(),
                super::Source::Action => request.action.properties(),
                super::Source::Context => request.context.properties(),
            };
            ("attribute", bag.get(name).is_none())
        }
        Condition::Trusted(predicate) => ("trusted_fact", request.context.trusted().is_none_or(|trusted| trusted.availability(predicate.fact()) != super::conditional::Availability::Known)),
        Condition::Group(_) => ("group", false),
        Condition::Role { .. } => ("role", false),
        Condition::Grant(_) => ("grant", false),
        Condition::AcrAtLeast(required) => (
            "acr_at_least",
            request
                .context
                .acr()
                .is_none_or(|held| !request.context.ladder().iter().any(|value| value == held))
                || !request.context.ladder().contains(required),
        ),
    };
    out.push(ConditionExplanation {
        path: path.to_owned(),
        kind,
        matched: holds(condition, request),
        missing,
    });
    match condition {
        Condition::All(children) | Condition::Any(children) => {
            for (index, child) in children.iter().enumerate() {
                trace(
                    child,
                    request,
                    &format!("{path}.{index}"),
                    out,
                    remaining,
                    truncated,
                );
            }
        }
        Condition::Not(child) => trace(
            child,
            request,
            &format!("{path}.0"),
            out,
            remaining,
            truncated,
        ),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Action, Context, Properties, Resource, RuleSet, Subject};
    use super::*;
    use serde_json::json;
    use time::OffsetDateTime;

    fn request(properties: Properties) -> EvaluationRequest {
        EvaluationRequest::new(
            Subject::new("user", "private-user", properties).expect("valid subject"),
            Action::new("read", Properties::empty()).expect("valid action"),
            Resource::new("document", "private-resource", Properties::empty())
                .expect("valid resource"),
            Context::default(),
        )
    }

    fn policy(rules: &serde_json::Value) -> StoredPolicy {
        StoredPolicy {
            rules: RuleSet::from_json(&json!({"version":1,"rules":rules})).expect("valid policy"),
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn distinguishes_missing_from_false_without_disclosing_values() {
        let policy = policy(
            &json!([{"id":"rule", "effect":"permit", "when":{"attribute":{"of":"subject","name":"private-name","equals":"private-literal"}}}]),
        );
        let absent = explain(
            Some(&policy),
            &request(Properties::empty()),
            "admin_policy_trial",
        );
        let present = explain(
            Some(&policy),
            &request(
                Properties::new([("private-name", json!("private-input"))]).expect("properties"),
            ),
            "admin_policy_trial",
        );
        assert!(absent.rules[0].conditions[0].missing);
        assert!(!present.rules[0].conditions[0].missing);
        assert!(!present.rules[0].matched);
        let rendered = serde_json::to_string(&present).expect("serializable");
        assert!(!rendered.contains("private-"));
        assert_eq!(absent.policy_revision, present.policy_revision);
    }

    #[test]
    fn revision_changes_with_content_even_when_timestamp_is_equal() {
        let first = policy(&json!([{"id":"rule", "effect":"permit"}]));
        let second = policy(&json!([{"id":"rule", "effect":"deny"}]));
        let request = request(Properties::empty());
        assert_ne!(
            explain(Some(&first), &request, "admin").policy_revision,
            explain(Some(&second), &request, "admin").policy_revision
        );
        assert!(explain(None, &request, "admin").policy_revision.is_none());
    }

    #[test]
    fn preserves_not_missing_semantics_and_shows_later_deny() {
        let policy = policy(&json!([
            {"id":"permit", "effect":"permit", "when":{"not":{"attribute":{"of":"context","name":"absent","equals":true}}}},
            {"id":"deny", "effect":"deny"}
        ]));
        let request = request(Properties::empty());
        let trace = explain(Some(&policy), &request, "admin");
        assert!(trace.rules[0].matched);
        assert!(trace.rules[0].conditions[1].missing);
        assert!(trace.rules[1].matched);
        assert!(!policy.rules.evaluate(&request).permit());
    }

    #[test]
    fn total_trace_budget_is_shared_across_rules() {
        let rules: Vec<_> = (0..128).map(|i| json!({"id":format!("r{i}"),"effect":"permit","when":{"all":[{"group":"private-group"},{"group":"private-group"}]}})).collect();
        let policy = policy(&json!(rules));
        let trace = explain(Some(&policy), &request(Properties::empty()), "admin");
        assert!(trace.truncated);
        assert_eq!(
            trace
                .rules
                .iter()
                .map(|r| r.conditions.len())
                .sum::<usize>(),
            MAX_TRACE_NODES
        );
        assert_eq!(trace.rules.len(), 128);
    }
}
