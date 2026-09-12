//! What a search can enumerate (Authorization API 1.0 §8, `ast-pj0.6`).
//!
//! §8's Search APIs turn the evaluation question round: instead of "may this
//! subject do this to that", a PEP asks "which subjects may", "which
//! resources" or "which actions", by omitting the id of the entity it is
//! searching for. §8 says the entities returned "SHOULD" evaluate to permit,
//! and this build makes that an "are": the endpoint evaluates every candidate
//! it is about to return, through the same [`crate::ports::PolicyEngine`] a
//! PEP would have called itself, and drops the ones that do not permit.
//!
//! Which leaves the question this module answers, and it is the whole of the
//! difficulty: **what are the candidates?** A PDP can only search a finite set
//! it can name. This one has three sources, and each of them is a deliberate
//! limit rather than an implementation detail:
//!
//! * **Subjects** are this tenant's own accounts, walked by the endpoint with
//!   a cursor over the directory. They are the one set this server holds in
//!   full, which is why §8.4's search is the useful one.
//! * **Resources** ([`candidate_resources`]) are the identifiers the *rules*
//!   name literally, plus the ones the subject's live authorizations name — an
//!   RFC 8707 resource indicator or an RFC 9396 `locations` entry. This server
//!   has no catalogue of a tenant's documents, invoices or repositories, and a
//!   PDP that invented one would be answering about entities it has never
//!   seen.
//! * **Actions** ([`candidate_actions`]) are the action names the applicable
//!   rules mention. A rule that names no action applies to *every* action, and
//!   an action vocabulary is the PEP's, not this server's — so such a rule
//!   contributes nothing enumerable, and its permits are invisible to §8.6.
//!
//! # What is therefore *not* enumerable, stated plainly
//!
//! A resource search answers with resource ids this deployment can name. If a
//! tenant's policy says "any editor may read any `todo`", the set of `todo`s
//! that permits is the PEP's own table and is not in this database: the search
//! returns the ids the rules and the grants name and nothing else. §8.3 makes
//! `results` REQUIRED and says nothing about completeness, so an incomplete
//! answer is a legal one — but a PEP that treated a resource search as a
//! catalogue would be wrong, and `docs/threat-model.md` and the endpoint's
//! module documentation say so where an integrator will read it.
//!
//! # Only `permit` rules propose candidates
//!
//! A `deny` rule cannot make anything evaluate to permit — deny wins in
//! [`RuleSet::evaluate`] — so a name that appears only in a deny is not a
//! candidate. It is still *applied*: the candidate list is a proposal, and
//! every proposal goes through the evaluator before it reaches a PEP.

use std::collections::BTreeSet;

use crate::policy::document::{Condition, Effect, GrantResource, Rule, RuleSet};
use crate::policy::request::ActiveGrant;

/// The most candidates one search will consider, whatever the document and the
/// grants hold.
///
/// The sources are already bounded — [`crate::policy::document::MAX_RULES`]
/// rules of [`crate::policy::document::MAX_ACTIONS`] actions, and a subject's
/// live grants — but they are bounded by numbers chosen for *parsing*, and
/// their product is the work one search request buys. A thousand is more
/// candidates than any catalogue this rule language can express usefully and
/// few enough that the endpoint's worst case stays a page of evaluations at a
/// time.
///
/// Collection stops at the cap rather than failing: the set is ordered, so
/// what is dropped is a deterministic tail rather than an arbitrary sample,
/// and a search that could be refused by the size of a tenant's own policy
/// would be a search a PEP cannot rely on.
pub const MAX_CANDIDATES: usize = 1_024;

/// The action names §8.6 can propose for this subject type and resource type.
///
/// The union of the `actions` of every `permit` rule that could apply, where
/// "could apply" is the rule's own heads: a rule with no `subject_type` is
/// about every subject type, and one with no `resource_type` about every
/// resource type.
///
/// A rule with an empty `actions` set applies to every action and names none,
/// so it adds nothing: there is no set of "all actions" for this server to
/// enumerate, because the vocabulary belongs to the PEP.
#[must_use]
pub fn candidate_actions(
    rules: &RuleSet,
    subject_type: &str,
    resource_type: &str,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for rule in applicable(rules, Some(subject_type), Some(resource_type)) {
        for action in &rule.actions {
            if candidates.len() >= MAX_CANDIDATES {
                return candidates;
            }
            candidates.insert(action.clone());
        }
    }
    candidates
}

/// The resource ids §8.5 can propose for this subject and resource type.
///
/// Two sources, both finite and both already in this database:
///
/// * every literal resource indicator a `grant` condition of an applicable
///   `permit` rule names — `{"grant": {"resource": "https://api.example/x"}}`
///   is a rule that names an entity;
/// * every RFC 8707 resource indicator and RFC 9396 `locations` entry of the
///   subject's *live* authorizations, which is what the `"$resource.id"`
///   substitution matches against.
///
/// `grants` is what [`ActiveGrant::of`] already filtered, so a revoked or
/// expired authorization proposes nothing.
#[must_use]
pub fn candidate_resources(
    rules: &RuleSet,
    grants: &[ActiveGrant],
    resource_type: &str,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    let add = |value: &str, candidates: &mut BTreeSet<String>| {
        if candidates.len() < MAX_CANDIDATES {
            candidates.insert(value.to_owned());
        }
    };
    for rule in applicable(rules, None, Some(resource_type)) {
        if let Some(condition) = rule.when.as_ref() {
            for literal in literals(condition) {
                add(&literal, &mut candidates);
            }
        }
    }
    for grant in grants {
        for resource in &grant.resources {
            add(resource, &mut candidates);
        }
        for detail in &grant.details {
            for location in &detail.locations {
                add(location, &mut candidates);
            }
        }
    }
    candidates
}

/// The `permit` rules whose heads admit this subject type and resource type.
///
/// `None` means "do not filter on this head", which is what a resource search
/// wants: it is looking for the resources of one type across every subject
/// type, because the subject is fixed by the request rather than by the rule.
fn applicable<'a>(
    rules: &'a RuleSet,
    subject_type: Option<&'a str>,
    resource_type: Option<&'a str>,
) -> impl Iterator<Item = &'a Rule> {
    rules.rules().iter().filter(move |rule| {
        rule.effect == Effect::Permit
            && head_admits(rule.subject_type.as_deref(), subject_type)
            && head_admits(rule.resource_type.as_deref(), resource_type)
    })
}

/// Whether a rule head admits an asked-for type.
///
/// A head of `None` is "any type" and admits everything; an asked-for type of
/// `None` is "I am not asking about this head" and is admitted by everything.
fn head_admits(head: Option<&str>, asked: Option<&str>) -> bool {
    match (head, asked) {
        (None, _) | (_, None) => true,
        (Some(head), Some(asked)) => head == asked,
    }
}

/// Every literal resource indicator a condition names, however deeply nested.
///
/// Walked with an explicit stack rather than by recursion. The parser bounds a
/// document at [`crate::policy::document::MAX_DEPTH`], so a recursive walk
/// would be safe today — and would stop being safe the moment that bound moved,
/// which is not a property to make depend on a constant in another module.
fn literals(condition: &Condition) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![condition];
    while let Some(condition) = pending.pop() {
        match condition {
            Condition::All(children) | Condition::Any(children) => pending.extend(children.iter()),
            Condition::Not(child) => pending.push(child),
            Condition::Grant(matched) => {
                if let Some(GrantResource::Literal(resource)) = matched.resource.as_ref() {
                    found.push(resource.clone());
                }
            }
            Condition::Attribute { .. }
            | Condition::Group(_)
            | Condition::Role { .. }
            | Condition::AcrAtLeast(_) => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientId;
    use crate::policy::request::DetailFact;

    fn rules(json: &str) -> RuleSet {
        RuleSet::parse(&format!(r#"{{"version": 1, "rules": {json}}}"#)).expect("a valid catalogue")
    }

    /// §8.6: an action search answers with the actions a policy names for the
    /// pair the request fixes.
    #[test]
    fn an_action_search_proposes_the_actions_its_rules_name() {
        // Arrange
        let policy = rules(
            r#"[
                {"id": "read", "effect": "permit", "subject_type": "user",
                 "resource_type": "todo", "actions": ["can_read", "can_list"]},
                {"id": "other", "effect": "permit", "subject_type": "user",
                 "resource_type": "invoice", "actions": ["can_pay"]}
            ]"#,
        );

        // Act
        let candidates = candidate_actions(&policy, "user", "todo");

        // Assert
        assert_eq!(
            candidates,
            BTreeSet::from(["can_list".to_owned(), "can_read".to_owned()])
        );
    }

    /// A `deny` names an action so that it can refuse it; proposing it as a
    /// candidate would be proposing an entity that cannot evaluate to permit.
    #[test]
    fn a_deny_proposes_no_action() {
        // Arrange
        let policy = rules(
            r#"[{"id": "no", "effect": "deny", "resource_type": "todo",
                 "actions": ["can_delete"]}]"#,
        );

        // Act
        let candidates = candidate_actions(&policy, "user", "todo");

        // Assert
        assert!(candidates.is_empty());
    }

    /// A rule with no `actions` applies to every action and names none: there
    /// is no vocabulary here to enumerate, and inventing one would be worse
    /// than answering with the names the document does give.
    #[test]
    fn a_rule_naming_no_action_proposes_none() {
        // Arrange
        let policy = rules(r#"[{"id": "any", "effect": "permit", "resource_type": "todo"}]"#);

        // Act, assert
        assert!(candidate_actions(&policy, "user", "todo").is_empty());
    }

    /// A rule with no `subject_type` is about every subject type, so it is
    /// applicable whatever the request fixed.
    #[test]
    fn a_rule_without_heads_applies_to_every_type() {
        // Arrange
        let policy = rules(r#"[{"id": "any", "effect": "permit", "actions": ["can_read"]}]"#);

        // Act, assert
        assert_eq!(
            candidate_actions(&policy, "machine", "anything"),
            BTreeSet::from(["can_read".to_owned()])
        );
    }

    /// §8.5: a resource search answers with the identifiers this deployment
    /// can name — the literals in the rules, and the subject's own live
    /// authorizations.
    #[test]
    fn a_resource_search_proposes_rule_literals_and_granted_resources() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit", "resource_type": "account",
                 "actions": ["can_read"],
                 "when": {"grant": {"resource": "https://api.example/accounts/1"}}}]"#,
        );
        let grants = vec![ActiveGrant {
            client: ClientId::new("app".to_owned()),
            scopes: BTreeSet::new(),
            resources: BTreeSet::from(["https://api.example/accounts/2".to_owned()]),
            details: vec![DetailFact {
                detail_type: "payment_initiation".to_owned(),
                actions: BTreeSet::new(),
                locations: BTreeSet::from(["https://api.example/accounts/3".to_owned()]),
            }],
        }];

        // Act
        let candidates = candidate_resources(&policy, &grants, "account");

        // Assert
        assert_eq!(
            candidates,
            BTreeSet::from([
                "https://api.example/accounts/1".to_owned(),
                "https://api.example/accounts/2".to_owned(),
                "https://api.example/accounts/3".to_owned(),
            ])
        );
    }

    /// The `"$resource.id"` substitution names no entity: it is the resource
    /// *of the request*, which in a search is the thing being searched for.
    #[test]
    fn the_resource_substitution_proposes_nothing_of_its_own() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit", "resource_type": "account",
                 "when": {"grant": {"resource": "$resource.id"}}}]"#,
        );

        // Act, assert
        assert!(candidate_resources(&policy, &[], "account").is_empty());
    }

    /// A literal nested under `all`/`any`/`not` is a literal the document
    /// names, and the walk has to find it wherever the administrator wrote it.
    #[test]
    fn a_nested_literal_is_found() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit", "resource_type": "account",
                 "when": {"all": [{"any": [
                     {"grant": {"resource": "https://api.example/deep"}}
                 ]}]}}]"#,
        );

        // Act, assert
        assert_eq!(
            candidate_resources(&policy, &[], "account"),
            BTreeSet::from(["https://api.example/deep".to_owned()])
        );
    }

    /// A rule about another resource type proposes nothing for this one.
    #[test]
    fn another_resource_type_proposes_nothing() {
        // Arrange
        let policy = rules(
            r#"[{"id": "r", "effect": "permit", "resource_type": "invoice",
                 "when": {"grant": {"resource": "https://api.example/invoices/1"}}}]"#,
        );

        // Act, assert
        assert!(candidate_resources(&policy, &[], "account").is_empty());
    }
}
