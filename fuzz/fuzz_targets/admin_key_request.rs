//! The three bodies the console's key screen posts, and the JWK rendering that
//! answers them.
//!
//! These are the validators standing between a request body and a *signing
//! key*: one decides which algorithm a rotation mints, one decides how long a
//! tenant's keys live, and one carries the only account anybody will ever have
//! of why a key was destroyed. None is reached without a session and a
//! synchroniser token, but "authenticated" is not "trusted" — an administrator
//! whose browser is running somebody else's script is exactly the caller these
//! parsers exist for.
//!
//! Properties:
//!
//! * **Total.** Arbitrary bytes are a request body. Parsing one must not
//!   panic.
//! * **The algorithm allow-list is closed.** RFC 8725 §3.1–3.2 says to fix the
//!   permitted algorithms in advance; FAPI 2.0 SP §5.4.1 fixes them to three.
//!   Whatever an `alg` member says, only `EdDSA`, `ES256` and `PS256` may come
//!   out — never `none`, never `HS256`.
//! * **A destruction is never unexplained.** The reason a purge carries is
//!   required, trimmed, single-line and bounded, because it is written to an
//!   audit record that a console and a SIEM read back.
//! * **A schedule that cannot work is refused.** Every accepted policy has
//!   positive periods and a propagation period shorter than its rotation
//!   period, because a key still waiting to sign when its successor is staged
//!   never signs at all, and the tenant's active key would then never change.
//! * **No private key material is ever rendered.** The members RFC 7518 §6.2.2,
//!   §6.3.2 and §6.4 define as private — `d`, `p`, `q`, `dp`, `dq`, `qi`,
//!   `oth`, `k` — must not survive being put through the API's JWK rendering,
//!   whatever the stored JWK holds. This is the acceptance criterion of
//!   `ast-f7m.7` stated over arbitrary input rather than over one fixture.
#![no_main]

use asterius_admin_api::keys::{PurgeRequest, RotationRequest, ScheduleRequest, public_members};
use asterius_domain::keys::{PurgeReason, SigningAlgorithm};
use libfuzzer_sys::fuzz_target;

/// Every JWK member that names private key material (RFC 7518 §6).
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    // 1. The rotation body. Both the raw bytes and the bytes dressed as an
    //    `alg`, so the budget goes on the allow-list rather than on failing to
    //    be JSON at all.
    for candidate in [
        raw.to_owned(),
        format!(r#"{{"alg":{}}}"#, serde_json::json!(raw)),
        format!(
            r#"{{"alg":{},"activate_immediately":true}}"#,
            serde_json::json!(raw)
        ),
    ] {
        if let Ok(request) = serde_json::from_str::<RotationRequest>(&candidate) {
            match request.algorithm() {
                Ok(algorithm) => assert!(
                    SigningAlgorithm::ALL.contains(&algorithm),
                    "{candidate:?} produced an algorithm outside the allow-list"
                ),
                Err(_) => assert!(
                    SigningAlgorithm::parse(&request.alg).is_none(),
                    "{candidate:?} refused an algorithm this server signs with"
                ),
            }
        }
    }

    // 2. The purge body. The reason ends up in an audit record read back by a
    //    console and a SIEM, so whatever survives validation must be a single
    //    line with no control characters in it — and a body that says nothing
    //    must never be accepted, because a destruction with no recorded reason
    //    is the one an incident review cannot use.
    for candidate in [
        raw.to_owned(),
        format!(r#"{{"reason":{}}}"#, serde_json::json!(raw)),
    ] {
        if let Ok(request) = serde_json::from_str::<PurgeRequest>(&candidate)
            && let Ok(reason) = request.reason()
        {
            let accepted = reason.as_str();
            assert!(
                !accepted.is_empty(),
                "{candidate:?} was accepted as a reason for destroying a key"
            );
            assert!(
                !accepted.chars().any(char::is_control),
                "a control character survived into an audit record: {accepted:?}"
            );
            assert!(
                accepted.chars().count() <= PurgeReason::MAX_LENGTH,
                "an over-long reason was accepted: {} characters",
                accepted.chars().count()
            );
            assert_eq!(accepted, accepted.trim(), "an untrimmed reason survived");
        }
    }

    // 3. The schedule body. Arbitrary numbers, through the validator.
    if let Ok(request) = serde_json::from_str::<ScheduleRequest>(raw)
        && let Ok(schedule) = request.schedule()
    {
        assert!(
            schedule.rotation_period.is_positive(),
            "accepted a rotation period that is not positive"
        );
        assert!(
            schedule.propagation_period.is_positive(),
            "accepted a propagation period that is not positive"
        );
        assert!(
            schedule.grace_period.is_positive(),
            "accepted a grace period that is not positive"
        );
        assert!(
            schedule.propagation_period < schedule.rotation_period,
            "accepted a policy under which a staged key never begins signing"
        );
        assert!(
            schedule.last_rotated_at.is_none(),
            "a form rewrote when the tenant last rotated"
        );
    }

    // 4. The rendering. Whatever a stored `public_jwk` holds — the column is
    //    `jsonb`, and an incident can put anything in one — no private member
    //    leaves through it.
    if let Ok(stored) = serde_json::from_str::<serde_json::Value>(raw) {
        let rendered = public_members(&stored);
        let object = rendered.as_object().expect("an object");
        for member in PRIVATE_MEMBERS {
            assert!(
                !object.contains_key(member),
                "the {member} member survived rendering: {rendered}"
            );
        }
    }

    // And with the private members forced in beside a public half, so the
    // budget is not spent waiting for a fuzzer to invent the letter `d`.
    let mut tampered = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": raw});
    for member in PRIVATE_MEMBERS {
        tampered[member] = serde_json::json!(raw);
    }
    let rendered = public_members(&tampered);
    let object = rendered.as_object().expect("an object");
    for member in PRIVATE_MEMBERS {
        assert!(
            !object.contains_key(member),
            "the {member} member survived rendering a tampered row"
        );
    }
});
