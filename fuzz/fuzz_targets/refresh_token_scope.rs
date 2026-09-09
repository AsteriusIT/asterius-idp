//! `refresh::requested_scopes` — RFC 6749 §6's one sentence about scope, and
//! the only place a client can influence what a refreshed token permits.
//!
//! "The scope of the access request … MUST NOT include any scope not
//! originally granted by the resource owner, and if omitted is treated as
//! equal to the scope originally granted." The whole of the risk is in the
//! first half: a `scope` parameter that widened the result would be privilege
//! escalation reachable from a form field, with no user anywhere near it.
//!
//! So the invariant this asserts is not "the function agrees with an example"
//! but the containment itself, for any granted set and any string: **whatever
//! comes back is a subset of what went in.** A failure of that is the bug;
//! everything else here is a corollary.
#![no_main]

use arbitrary::Arbitrary;
use asterius_oidc::refresh::requested_scopes;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

#[derive(Arbitrary, Debug)]
struct Input {
    /// What the token was issued for. Arbitrary strings, including ones that
    /// are not `scope-token`s: a stored set is a row, and rows get edited.
    granted: Vec<String>,
    /// The `scope` parameter, or its absence.
    requested: Option<String>,
}

fuzz_target!(|input: Input| {
    let granted: BTreeSet<String> = input.granted.into_iter().collect();

    let Ok(effective) = requested_scopes(input.requested.as_deref(), &granted) else {
        // A refusal says nothing beyond `invalid_scope`, and there is nothing
        // to assert about a set that was never built.
        return;
    };

    // The property. Nothing else in this file matters if this fails.
    assert!(
        effective.is_subset(&granted),
        "a refresh widened its scope: {effective:?} ⊄ {granted:?}"
    );

    // RFC 6749 §6: an omitted `scope` is the granted set, exactly.
    if input.requested.is_none() {
        assert_eq!(effective, granted, "an omitted scope changed the set");
    }

    // Every accepted member is a `scope-token` (§3.3). A scope carrying a
    // space would become two scopes in an access token's space-delimited
    // `scope` claim (RFC 9068 §2.2.3), which is the escalation the grammar
    // check exists to prevent — and a granted set holding one must not be able
    // to launder it through here.
    for scope in &effective {
        assert!(
            asterius_domain::entities::grant::is_scope_token(scope),
            "a scope outside RFC 6749 §3.3's grammar survived: {scope:?}"
        );
    }

    // Deterministic: the same request twice is the same authorization twice.
    assert_eq!(
        effective,
        requested_scopes(input.requested.as_deref(), &granted).expect("accepted once"),
        "the same request produced two different scope sets"
    );
});
