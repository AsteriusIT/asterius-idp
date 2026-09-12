//! The AuthZEN Search request and its page token — Authorization API 1.0 §8,
//! §8.2, §8.3, §8.4–§8.6, §10.1.1, §11.5, §11.7 (`ast-pj0.6`).
//!
//! A search is an evaluation with a hole in it, and this target is about what
//! may come out of that hole. Six properties:
//!
//! * **The hole is a hole.** Whatever the bytes say, an accepted search of one
//!   kind carries no entity of that kind: a subject search has no `subject`, a
//!   resource search no `resource`, an action search no `action`. A parser
//!   that let one through would answer a search with the entity the caller
//!   already named.
//! * **Everything else is complete.** The entities a search does *not* fill in
//!   are §5's, with a non-empty type, id or name — the same completeness §6.1
//!   demands, because that is what the candidate evaluation will be.
//! * **A candidate is a real request.** For an arbitrary identifier, the
//!   evaluation request the search mints is complete and is decided by the
//!   evaluator without panicking — which is what the endpoint does for every
//!   entity it is about to return.
//! * **A PEP asserts nothing.** No group, role, grant or `acr` reaches the
//!   subject of a candidate through the wire format; those are the endpoint's
//!   to resolve.
//! * **The page token binds to the query.** A token minted for one request is
//!   refused against any request that differs outside `page` — §8.2's
//!   "identical parameters" — and is accepted against the one it was minted
//!   for. A token from the bytes themselves is either refused or carries a
//!   cursor within the documented bound.
//! * **Parsing is total, deterministic and bounded** (§11.7): the same bytes
//!   give the same answer, `MAX_REQUEST_BYTES` and `MAX_PAGE` hold, and no
//!   input panics.
#![no_main]

use asterius_domain::policy::RuleSet;
use asterius_oidc::authzen::{AuthzenError, MAX_REQUEST_BYTES};
use asterius_oidc::authzen_search::{
    MAX_CURSOR, MAX_PAGE, SearchKind, SearchRequest, parse_search, search_response,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

/// A catalogue that walks rather than dismisses whatever survives the parser.
fn catalogue() -> RuleSet {
    RuleSet::parse(
        r#"{"version": 1, "rules": [
            {"id": "deny-locked", "effect": "deny",
             "when": {"attribute": {"of": "resource", "name": "locked", "equals": true}}},
            {"id": "read-public", "effect": "permit",
             "subject_type": "user", "resource_type": "document",
             "actions": ["read", "can_read"],
             "when": {"any": [{"group": "finance"},
                              {"attribute": {"of": "resource", "name": "public",
                                             "equals": true}}]}}
        ]}"#,
    )
    .expect("a fixed catalogue")
}

/// The three searches, so that one input exercises all of §8.4–§8.6.
const KINDS: [SearchKind; 3] = [
    SearchKind::Subject,
    SearchKind::Resource,
    SearchKind::Action,
];

/// What an accepted request must and must not carry, by kind.
fn check_shape(kind: SearchKind, request: &SearchRequest) {
    assert_eq!(request.kind, kind);
    match kind {
        SearchKind::Subject => {
            assert!(
                request.subject.is_none(),
                "a subject search named a subject"
            );
            assert!(
                request.searched_type.is_some(),
                "a subject search with no type to search"
            );
        }
        SearchKind::Resource => {
            assert!(
                request.resource.is_none(),
                "a resource search named a resource"
            );
            assert!(
                request.searched_type.is_some(),
                "no resource type to search"
            );
        }
        SearchKind::Action => {
            assert!(request.action.is_none(), "an action search named an action");
            assert!(
                request.searched_type.is_none(),
                "an action has no type in §5.3"
            );
        }
    }
    if let Some(subject) = request.subject.as_ref() {
        assert!(!subject.kind().is_empty() && !subject.id().is_empty());
        // Nothing a PEP wrote became a fact about authority.
        assert!(subject.groups().is_empty(), "a PEP claimed a group");
        assert!(
            subject.grants().is_empty(),
            "a PEP claimed an authorization"
        );
        assert!(
            subject.roles().tenant.is_empty() && subject.roles().clients.is_empty(),
            "a PEP claimed a role"
        );
    }
    if let Some(action) = request.action.as_ref() {
        assert!(!action.name().is_empty());
    }
    if let Some(resource) = request.resource.as_ref() {
        assert!(!resource.kind().is_empty() && !resource.id().is_empty());
    }
    assert!(request.context.acr().is_none(), "a PEP claimed an acr");
    assert!(
        request.page.limit > 0 && request.page.limit <= MAX_PAGE,
        "a page of {} entities",
        request.page.limit
    );
    if let Some(cursor) = request.page.after.as_deref() {
        assert!(
            !cursor.is_empty() && cursor.len() <= MAX_CURSOR,
            "a cursor of {} bytes",
            cursor.len()
        );
    }
}

/// §8.2: a token is accepted against the query it was minted for and refused
/// against any other.
fn check_binding(kind: SearchKind, request: &SearchRequest, document: &Value) {
    let Some(members) = document.as_object() else {
        return;
    };
    let token = request.next_token("cursor");

    let mut same = members.clone();
    same.insert("page".to_owned(), json!({ "token": token }));
    let resumed = parse_search(kind, &Value::Object(same).to_string().into_bytes())
        .expect("a token this PDP minted resumes the query it was minted for");
    assert_eq!(
        resumed.page.after.as_deref(),
        Some("cursor"),
        "a resumed search lost its place"
    );

    let mut changed = members.clone();
    changed.insert("this-was-not-here".to_owned(), json!("something else"));
    changed.insert("page".to_owned(), json!({ "token": token }));
    match parse_search(kind, &Value::Object(changed).to_string().into_bytes()) {
        Err(AuthzenError::PageChanged) => {}
        Err(other) => panic!("a changed query was refused for the wrong reason: {other}"),
        Ok(_) => panic!("§8.2: a page token was honoured against a changed query"),
    }
}

fuzz_target!(|data: &[u8]| {
    for kind in KINDS {
        let parsed = parse_search(kind, data);

        // Deterministic: the same bytes give the same answer, every time.
        match (&parsed, &parse_search(kind, data)) {
            (Ok(first), Ok(second)) => assert_eq!(first, second, "two parses disagreed"),
            (Err(first), Err(second)) => assert_eq!(first, second, "two refusals disagreed"),
            _ => panic!("the same bytes were both accepted and refused"),
        }

        let request = match parsed {
            Ok(request) => request,
            Err(error) => {
                // §10.1.2's body is an error message string.
                assert!(
                    !error.to_string().is_empty(),
                    "a refusal with no message to put in the 400"
                );
                if data.len() > MAX_REQUEST_BYTES {
                    assert_eq!(error, AuthzenError::TooLong);
                }
                continue;
            }
        };

        // §11.7: the bounds were applied, whatever else happened.
        assert!(
            data.len() <= MAX_REQUEST_BYTES,
            "accepted {} bytes",
            data.len()
        );
        check_shape(kind, &request);

        // A candidate is an ordinary evaluation request, and the evaluator is
        // total over it.
        let policy = catalogue();
        for candidate in ["alice", "https://api.example/x", "can_read"] {
            let Ok(evaluation) = request.candidate(candidate) else {
                continue;
            };
            assert!(!evaluation.subject.kind().is_empty());
            assert!(!evaluation.subject.id().is_empty());
            assert!(!evaluation.action.name().is_empty());
            assert!(!evaluation.resource.kind().is_empty());
            assert!(!evaluation.resource.id().is_empty());
            assert!(
                evaluation.subject.groups().is_empty() && evaluation.subject.grants().is_empty(),
                "a candidate carried facts a PEP wrote"
            );
            let decision = policy.evaluate(&evaluation);
            assert_eq!(
                decision,
                policy.evaluate(&evaluation),
                "two evaluations of one candidate disagreed"
            );
        }

        // §8.3: `results` is REQUIRED and `next_token` is present, empty on
        // the last page.
        let answer = search_response(vec![json!({"name": "can_read"})], None);
        assert!(answer["results"].is_array());
        assert_eq!(answer["page"]["next_token"], json!(""));

        if let Ok(document) = serde_json::from_slice::<Value>(data) {
            check_binding(kind, &request, &document);
        }
    }
});
