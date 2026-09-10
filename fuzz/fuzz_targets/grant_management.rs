//! `grant_management::parse` — the two Grant Management request parameters.
//!
//! Grant Management for OAuth 2.0 ID1 §5.4 is a list of combinations that must
//! be refused, and §7.1 adds one more. A validator of a *pair* of parameters is
//! where an implementation slips: each parameter looks harmless alone, and the
//! rules are all about the combination.
//!
//! The properties asserted here are the ones a wrong answer would break in a
//! way no error page would show:
//!
//! * **The flag is absolute.** With `grant_management` off, `parse` returns
//!   `None` for every input there is. Anything else would mean a deployment
//!   that never advertised the feature acting on a `grant_id` a client sent —
//!   which is the whole of what "isolated behind a flag" has to mean.
//! * **An accepted answer is well formed.** `create` never carries a
//!   `grant_id`, and `merge`/`replace` always do. The handler that persists the
//!   grant reads exactly that shape, and an answer that broke it would reach a
//!   database lookup with nothing to look up, or a create with an id to honour.
//! * **An accepted `grant_id` is one the caller may safely put in a query.** It
//!   is bounded and drawn from the alphabet a v4 UUID uses, so an id cannot
//!   carry a byte the store did not expect and cannot be arbitrarily long.
//! * **Only `Create` survives with no id.** Which is the same statement as the
//!   second, from the other side: there is no input for which a `merge` or a
//!   `replace` comes back with nothing to act on.
//! * **`parse` is total.** It returns for every pair of strings, without
//!   panicking, whatever bytes are in them.
#![no_main]

use asterius_oidc::grant_management::{
    Action, GrantManagementError, MAX_GRANT_ID_LEN, Policy, parse,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (String, String, bool, bool, bool, bool)| {
    let (action, grant_id, action_present, id_present, supported, action_required) = input;
    let action = action_present.then_some(action.as_str());
    let grant_id = id_present.then_some(grant_id.as_str());

    // The flag off: no input produces anything at all.
    let ignored = parse(action, grant_id, Policy::new(false, action_required));
    assert_eq!(
        ignored,
        Ok(None),
        "the feature is off and a request was still acted on"
    );

    let policy = Policy::new(supported, action_required);
    assert_eq!(
        policy.supported, supported,
        "the flag is what the caller asked for"
    );
    assert!(
        !policy.action_required || policy.supported,
        "§7.1 cannot outlive the feature it is about"
    );

    let Ok(outcome) = parse(action, grant_id, policy) else {
        // Every refusal has a code, and only one of them is the draft's own.
        let refusal = parse(action, grant_id, policy).expect_err("refused a moment ago");
        let code = refusal.code();
        assert!(
            code == "invalid_request" || code == "invalid_grant_id",
            "§5.4 registers no other code: {code}"
        );
        assert_eq!(
            code == "invalid_grant_id",
            refusal == GrantManagementError::UnknownGrant,
            "only an unusable grant_id gets the draft's own code"
        );
        return;
    };

    let Some(asked) = outcome else {
        // Nothing was asked for. That is only honest when the request named no
        // action, or the feature is off.
        assert!(
            !supported || action.is_none_or(str::is_empty),
            "an action was named and silently dropped"
        );
        return;
    };

    assert!(supported, "a request was acted on with the feature off");
    assert!(
        Action::ALL.contains(&asked.action),
        "an action nothing advertises came back accepted"
    );
    assert_eq!(
        asked.action.needs_an_existing_grant(),
        asked.grant_id().is_some(),
        "the two halves of the answer must agree about what it acts on"
    );
    assert_eq!(
        asked.action == Action::Create,
        asked.grant_id().is_none(),
        "§5.4: create cannot come back carrying a grant_id, and nothing else may come back without one"
    );
    if let Some(id) = asked.grant_id() {
        assert!(!id.is_empty());
        assert!(
            id.len() <= MAX_GRANT_ID_LEN,
            "an unbounded id reached a query"
        );
        assert!(
            id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "an id outside the alphabet Grant::new mints reached a query: {id:?}"
        );
    }
});
