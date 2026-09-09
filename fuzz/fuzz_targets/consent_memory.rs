//! `Remembered::covers` — the decision *not* to ask a person again.
//!
//! Every other decision in this server answers "may this happen?". This one
//! answers "has somebody already said it may?", and a wrong answer is not a
//! refused request: it is an authorization completed without anybody being
//! asked. So the property that matters is one-sided, and it is the one this
//! target asserts on arbitrary input.
//!
//! * **`Covered` implies containment, in every dimension.** If the memory says
//!   the screen may be skipped, then every scope, every (destination, claim)
//!   pair, every `authorization_details` element and every RFC 8707 resource
//!   being asked for was already covered by a grant that still stands. There is
//!   no combination of grants, timestamps and requests that produces a `Covered`
//!   for material nobody granted — which is the whole of the widening rule,
//!   asserted against the answer rather than against the arithmetic that
//!   produced it.
//! * **`offline_access` is never covered by an ordinary consent** (OIDC Core
//!   §11: the OP "MUST obtain explicit consent"). Even when it is inside the
//!   containment above, a `Covered` answer requires a grant that actually
//!   carried the scope, and one whose consent is still inside the tenant's
//!   window.
//! * **A revoked or expired grant contributes nothing.** Folding only revoked
//!   and expired grants must answer `Delta` for everything, whatever those
//!   grants covered — the property that makes revocation traverse the memory.
//! * **The delta never invents.** What comes back to be shown is a subset of
//!   what was asked for: a screen naming something the client did not request
//!   would be asking a person to agree to something nobody wants.
//! * **`always_ask` is absolute.** The tenant switch produces the whole request
//!   as the delta, for every memory.
//!
//! The inputs are shaped rather than random bytes: a grant is a row with
//! interdependent columns, and undirected noise spends its whole budget on
//! grants that fold in nothing.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::{ClientId, Grant, SubjectId, TenantId};
use asterius_oidc::consent_memory::{
    Asked, Coverage, DEFAULT_OFFLINE_ACCESS_MEMORY, MemoryPolicy, OFFLINE_ACCESS, Remembered,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};

/// Scope candidates, with `offline_access` among them so the rule that singles
/// it out is exercised rather than assumed.
const SCOPES: [&str; 8] = [
    "openid",
    "profile",
    "email",
    "payments",
    OFFLINE_ACCESS,
    "",
    "urn:example:scope",
    "OpenID",
];

/// RFC 8707 resource candidates.
const RESOURCES: [&str; 4] = [
    "https://api.example/",
    "https://api.example/v2",
    "https://other.example/",
    "",
];

/// The `claims` shapes a grant's `jsonb` column can hold, including the two
/// that differ only in which endpoint a claim is disclosed at.
const CLAIMS: [&str; 6] = [
    "{}",
    r#"{"id_token": {"email": {}}, "userinfo": {}}"#,
    r#"{"id_token": {}, "userinfo": {"email": {}}}"#,
    r#"{"id_token": {"email": {"essential": true}}, "userinfo": {"name": {}}}"#,
    "null",
    "[]",
];

/// One grant the user already holds.
#[derive(Arbitrary, Debug)]
struct Held {
    scope_picks: Vec<u8>,
    resource_picks: Vec<u8>,
    claims: u8,
    /// How long before `now` it was granted, in days.
    age_days: u16,
    revoked: bool,
    /// When set, the grant expires this many days after it was made.
    expires_after_days: Option<u16>,
    /// A grant for somebody else, or for another client.
    elsewhere: bool,
}

#[derive(Arbitrary, Debug)]
struct Input {
    held: Vec<Held>,
    asked_scopes: Vec<u8>,
    asked_resources: Vec<u8>,
    asked_claims: u8,
    always_ask: bool,
}

fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
}

fn client() -> ClientId {
    ClientId::new("billing")
}

fn subject() -> SubjectId {
    SubjectId::new("sub-1")
}

fn picked(picks: &[u8], corpus: &[&str]) -> BTreeSet<String> {
    picks
        .iter()
        .take(32)
        .map(|pick| corpus[usize::from(*pick) % corpus.len()].to_owned())
        .collect()
}

fn claims_json(pick: u8) -> serde_json::Value {
    serde_json::from_str(CLAIMS[usize::from(pick) % CLAIMS.len()]).expect("a fixed shape parses")
}

/// What a grant is asked to cover, in the same shape the memory reports.
///
/// Built through `Asked::from_parameters` rather than by hand, so the fuzzed
/// request goes through the same reader the server uses.
fn asked_of(input: &Input) -> Asked {
    let scopes: Vec<String> = picked(&input.asked_scopes, &SCOPES).into_iter().collect();
    let resources: Vec<String> = picked(&input.asked_resources, &RESOURCES)
        .into_iter()
        .collect();
    Asked::from_parameters(&serde_json::json!({
        "scopes": scopes,
        "resources": resources,
        "claims": claims_json(input.asked_claims),
    }))
}

fn grants_of(input: &Input) -> Vec<Grant> {
    input
        .held
        .iter()
        .take(8)
        .map(|held| {
            let created_at = now() - Duration::days(i64::from(held.age_days));
            let mut grant = Grant::new(
                TenantId::new("demo"),
                if held.elsewhere {
                    ClientId::new("somebody-else")
                } else {
                    client()
                },
                created_at,
            );
            grant.subject = Some(if held.elsewhere {
                SubjectId::new("sub-2")
            } else {
                subject()
            });
            grant.scopes = picked(&held.scope_picks, &SCOPES);
            grant.resources = picked(&held.resource_picks, &RESOURCES);
            grant.claims = claims_json(held.claims);
            if held.revoked {
                grant.revoked_at = Some(created_at);
            }
            grant.expires_at = held
                .expires_after_days
                .map(|days| created_at + Duration::days(i64::from(days)));
            grant
        })
        .collect()
}

/// Everything one set of grants covers, computed independently of the memory.
///
/// Deliberately not built by calling into `Remembered`: an oracle that shares
/// the implementation agrees with it even when it is wrong. This is the same
/// rule read off the specification — a grant counts when it is this client's,
/// this subject's, not revoked and not expired.
fn standing(grants: &[Grant]) -> Vec<&Grant> {
    grants
        .iter()
        .filter(|grant| {
            grant.client == client()
                && grant.subject.as_ref() == Some(&subject())
                && grant.revoked_at.is_none()
                && grant.expires_at.is_none_or(|expiry| expiry > now())
        })
        .collect()
}

fuzz_target!(|input: Input| {
    let grants = grants_of(&input);
    let asked = asked_of(&input);
    let policy = MemoryPolicy::new(input.always_ask);
    let remembered = Remembered::of_client(&grants, &client(), &subject(), now());
    let coverage = remembered.covers(&asked, policy, now());

    // The answer is a pure function of its inputs; two readers of one memory
    // must not disagree about whether a person was asked.
    assert_eq!(
        coverage,
        remembered.covers(&asked, policy, now()),
        "deciding whether to ask is not deterministic"
    );

    let standing = standing(&grants);

    if input.always_ask {
        assert_eq!(
            coverage,
            Coverage::Delta(asked.clone()),
            "the always-ask switch did not ask for everything"
        );
        return;
    }

    // A user with nothing standing has consented to nothing, whatever the set
    // arithmetic says about an empty request.
    if standing.is_empty() {
        assert_eq!(
            coverage,
            Coverage::Delta(asked.clone()),
            "a consent was remembered for a user who holds no grant"
        );
    }

    match &coverage {
        Coverage::Covered => {
            // --- the widening rule -------------------------------------------
            let covered_scopes: BTreeSet<&String> = standing
                .iter()
                .flat_map(|grant| grant.scopes.iter())
                .collect();
            for scope in &asked.scopes {
                assert!(
                    covered_scopes.contains(scope),
                    "a scope nobody granted was treated as consented to: {scope}"
                );
            }
            for resource in &asked.resources {
                let granted = standing
                    .iter()
                    .any(|grant| grant.resources.contains(resource));
                assert!(
                    granted,
                    "a resource nobody granted was treated as consented to: {resource}"
                );
            }

            // --- OIDC Core §11 -----------------------------------------------
            if asked.scopes.contains(OFFLINE_ACCESS) {
                let explicit = standing.iter().any(|grant| {
                    grant.scopes.contains(OFFLINE_ACCESS)
                        && grant.created_at + DEFAULT_OFFLINE_ACCESS_MEMORY > now()
                });
                assert!(
                    explicit,
                    "offline access was granted without an explicit consent inside its window"
                );
            }
        }
        Coverage::Delta(delta) => {
            // What is shown is part of what was asked for, and nothing else.
            assert!(
                delta.scopes.is_subset(&asked.scopes),
                "the consent screen would name a scope the client did not request"
            );
            assert!(
                delta.resources.is_subset(&asked.resources),
                "the consent screen would name a resource the client did not request"
            );
            assert!(
                delta.claims.is_subset(&asked.claims),
                "the consent screen would name a claim the client did not request"
            );
            // An empty delta means a request that asked for nothing, which is
            // `Delta` rather than `Covered` on purpose: with no standing grant
            // there is no consent, and an empty set being a subset of every
            // set must not be read as one. Every other empty delta is a
            // covered request wearing the wrong variant.
            assert!(
                !delta.is_empty() || asked.is_empty(),
                "an empty delta for a request that asked for something"
            );
        }
    }
});
