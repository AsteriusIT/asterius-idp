//! `AgentProfile` and `AgentLimits` — the stored agent policy (`ast-lh3.1`).
//!
//! The document is a `jsonb` column: written by a registration, by an
//! administrator through the tenant's registration policy, by a migration, or
//! by whoever last had a `psql` session open during an incident. It is read on
//! every issuance to an agent, and what it decides — the token's lifetime, the
//! scopes a person has to approve, the audiences an agent may name — is
//! security policy for a credential that runs unattended.
//!
//! The properties asserted are the ones nothing downstream re-checks:
//!
//! * **Parsing is total.** No input panics. A panic here is a 500 on a token
//!   request, or a client repository that cannot load a row.
//! * **What is accepted round-trips.** A profile written out and read back is
//!   the same profile, so storing what was loaded cannot drift an agent's
//!   limits — silently lengthening a token or losing a human-approval scope.
//! * **A profile always names an owner.** [`AgentProfile::from_json`] is the
//!   one door to an agent that acts for somebody, and an ownerless one must not
//!   come through it, whatever the bytes say.
//! * **Capping never lengthens.** Whatever the document asked for, the
//!   lifetime that comes out is no longer than the tenant's.
#![no_main]

use asterius_domain::{AgentLimits, AgentProfile, TokenLifetimes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(document) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };

    // The tenant's half: limits with no owner.
    if let Ok(limits) = AgentLimits::from_json(&document) {
        let round_tripped =
            AgentLimits::from_json(&limits.to_json()).expect("what was written parses");
        assert_eq!(round_tripped, limits, "agent limits did not round-trip");
    }

    // One agent's half: the same document with an owner.
    let Ok(profile) = AgentProfile::from_json(&document) else {
        return;
    };
    let round_tripped =
        AgentProfile::from_json(&profile.to_json()).expect("what was written parses");
    assert_eq!(
        round_tripped, profile,
        "an agent profile did not round-trip"
    );

    // Whatever the document said, the ceiling is a ceiling.
    let tenant = TokenLifetimes::default();
    let capped = profile.cap(tenant);
    assert!(
        capped.access_token() <= tenant.access_token(),
        "an agent profile lengthened an access token"
    );
    assert_eq!(
        capped.authorization_code(),
        tenant.authorization_code(),
        "an agent profile touched the authorization code lifetime"
    );

    // Total on any request, including the ones no client would send.
    let _ = profile.scope_needing_human_approval(["", "openid"]);
    let _ = profile.detail_type_needing_human_approval(["", "payment_initiation"]);
});
