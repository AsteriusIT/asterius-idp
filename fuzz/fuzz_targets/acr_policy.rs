//! The ACR policy parser, and the choice of `acr` it feeds (`ast-2vk.7`).
//!
//! Two entry points, both untrusted in the ways that matter. `AcrPolicy::from_json`
//! reads a document out of configuration or a database column, and
//! `AcrPolicy::assign` picks the class name that ends up in an ID token — where
//! a relying party compares it against what it asked for and decides whether to
//! let somebody move money.
//!
//! The properties are the ones a wrong answer breaks:
//!
//! * **A parsed policy round-trips.** `from_json(to_json(p)) == p`, so what a
//!   column holds and what the server enforces cannot drift.
//! * **Every accepted level is requestable.** `acr_values` is space-delimited
//!   (OIDC Core §3.1.2.1), so a value carrying whitespace would be a rung no
//!   client could ever ask for and one this server might nonetheless assert.
//! * **`assign` never invents.** Whatever comes back is a value on the ladder,
//!   and its methods are a subset of what the authentication actually used.
//!   This is the one-sided property: over-reporting a class is an authentication
//!   strength nobody proved.
//! * **An essential request is answered exactly or not at all** (OIDC Core
//!   §5.5.1.1: the returned `acr` "MUST" match one of the requested values). If
//!   any requested essential value was reachable with these methods, the answer
//!   is one of them — never a stronger value the client did not name.
//! * **A voluntary request cannot fail** (§3.1.2.1): with no essential values
//!   and a non-empty ladder that these methods reach, there is always an answer.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::{AcrLevel, AcrPolicy, AuthenticationMethod};
use libfuzzer_sys::fuzz_target;

/// The methods this build can record. Structured rather than raw bytes: the
/// interesting inputs are combinations of a five-value enum, and undirected
/// noise would spend its budget on strings that are not method names.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Method {
    Password,
    Passkey,
    OneTimeCode,
    UserVerified,
    ExistingSession,
}

impl From<Method> for AuthenticationMethod {
    fn from(method: Method) -> Self {
        match method {
            Method::Password => Self::Password,
            Method::Passkey => Self::Passkey,
            Method::OneTimeCode => Self::OneTimeCode,
            Method::UserVerified => Self::UserVerified,
            Method::ExistingSession => Self::ExistingSession,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Case {
    /// A document, as a column might hold it.
    document: String,
    /// A ladder built directly, for the paths a document cannot reach.
    levels: Vec<(String, Vec<Method>)>,
    /// What an authentication used.
    used: Vec<Method>,
    /// `claims`-borne essential values (§5.5.1.1).
    essential: Vec<String>,
    /// `acr_values` (§3.1.2.1).
    voluntary: Vec<String>,
}

fuzz_target!(|case: Case| {
    // The parser: anything at all, and the document form of a policy that was
    // built by hand.
    if let Ok(document) = serde_json::from_str::<serde_json::Value>(&case.document)
        && let Ok(parsed) = AcrPolicy::from_json(&document)
    {
        check(&parsed);
        let again = AcrPolicy::from_json(&parsed.to_json()).expect("a policy this build wrote");
        assert_eq!(
            again, parsed,
            "a policy did not survive its own stored form"
        );
    }

    let levels: Vec<AcrLevel> = case
        .levels
        .iter()
        .filter_map(|(value, methods)| {
            AcrLevel::new(
                value.clone(),
                methods.iter().copied().map(AuthenticationMethod::from),
            )
            .ok()
        })
        .collect();
    let Ok(policy) = AcrPolicy::new(levels) else {
        return;
    };
    check(&policy);
    assert_eq!(
        AcrPolicy::from_json(&policy.to_json()).expect("a policy this build built"),
        policy,
        "a policy did not survive its own stored form"
    );

    let used: Vec<AuthenticationMethod> = case
        .used
        .iter()
        .copied()
        .map(AuthenticationMethod::from)
        .collect();
    let assigned = policy.assign(&used, &case.essential, &case.voluntary);

    if let Some(assigned) = &assigned {
        let level = policy
            .level(assigned)
            .expect("assign returned a value that is not on the ladder");
        assert!(
            level.is_met_by(&used),
            "assign returned a class the authentication did not reach"
        );
    }

    // §5.5.1.1: essential wins, exactly.
    let reachable_essential = case.essential.iter().any(|value| {
        policy
            .level(value)
            .is_some_and(|level| level.is_met_by(&used))
    });
    if reachable_essential {
        let assigned = assigned
            .as_deref()
            .expect("an essential value was reachable and none was returned");
        assert!(
            case.essential.iter().any(|value| value == assigned),
            "an essential request was answered with a value it did not name"
        );
    }

    // §3.1.2.1: a voluntary request is never a failure. If any rung at all was
    // reached, something is reported.
    if policy.levels().iter().any(|level| level.is_met_by(&used)) {
        assert!(
            assigned.is_some(),
            "an authentication that reached a rung reported no class"
        );
    }
});

/// What is true of every policy this build accepts, however it was built.
fn check(policy: &AcrPolicy) {
    let mut seen = std::collections::BTreeSet::new();
    for level in policy.levels() {
        assert!(
            !level.value().is_empty(),
            "an empty acr value would be a class nobody could request"
        );
        assert!(
            !level.value().chars().any(char::is_whitespace),
            "acr_values is space-delimited: {:?} could never be requested",
            level.value()
        );
        assert!(
            !level.methods().is_empty(),
            "a level nothing satisfies would be a class asserted for free"
        );
        assert!(
            seen.insert(level.value()),
            "one acr value means two method sets"
        );
    }
    assert_eq!(
        policy.supported_values().len(),
        policy.levels().len(),
        "the published list and the ladder disagree"
    );
}
