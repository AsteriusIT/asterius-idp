//! `RegistrationPolicy` — the per-tenant registration policy, parsed and then
//! evaluated against arbitrary client metadata (`ast-m9c.6`).
//!
//! Two parsers in one target, because they are two halves of one decision: a
//! stored policy document and the registration document it judges. Both are
//! attacker-adjacent in different ways — the policy is a `jsonb` column an
//! administrator, a migration or somebody in a `psql` session writes, and the
//! metadata is whatever a registrant sent to an endpoint that may be
//! unauthenticated.
//!
//! The properties asserted are the ones nothing downstream re-checks:
//!
//! * **Evaluation is total.** No input panics. A panic here is a 500 at
//!   `POST /register`, reachable by anybody the deployment lets register.
//! * **Evaluation is deterministic.** The same policy and the same metadata
//!   give the same rule, every time. An operator chasing a refusal must not get
//!   a different answer on a retry, and a rule id that varied would make the
//!   audit trail unreadable.
//! * **What is accepted round-trips.** A policy written out and read back is
//!   the same policy, so saving what was loaded cannot drift a tenant's rules.
//! * **A refusal is always `invalid_client_metadata`.** Whatever rule failed,
//!   the wire code is one from RFC 7591 §3.2.2's closed list.
#![no_main]

use asterius_domain::{Capabilities, ClientRegistration, RegistrationPolicy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first line is the policy document, the rest is the registration.
    // Splitting on a newline keeps both halves human-readable in a crash
    // artefact, which matters more here than packing the input.
    let mut halves = data.splitn(2, |byte| *byte == b'\n');
    let (Some(policy_bytes), Some(metadata)) = (halves.next(), halves.next()) else {
        return;
    };
    let Ok(text) = std::str::from_utf8(policy_bytes) else {
        return;
    };
    let Ok(document) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let Ok(policy) = RegistrationPolicy::from_json(Some(&document)) else {
        return;
    };

    // What this server wrote, this server reads.
    let round_tripped =
        RegistrationPolicy::from_json(Some(&policy.to_json())).expect("what was written parses");
    assert_eq!(round_tripped, policy, "a policy did not round-trip");

    // The quota and the statement rule are total on every count, including the
    // ones no database will ever hold.
    let _ = policy.check_client_quota(u64::MAX);
    let _ = policy.check_client_quota(0);
    let _ = policy.check_software_statement_present(false);

    // Only a document the profile accepts reaches evaluation, which is exactly
    // what the endpoint does: the policy judges a validated registration.
    let Ok(registration) = ClientRegistration::from_json(metadata, Capabilities::default()) else {
        return;
    };

    let first = policy.evaluate(&registration);
    let second = policy.evaluate(&registration);
    assert_eq!(first, second, "policy evaluation is not deterministic");

    if let Err(violation) = first {
        assert_eq!(
            violation.to_metadata_error().code(),
            "invalid_client_metadata",
            "a policy refusal left RFC 7591 §3.2.2's list of codes"
        );
    }
});
