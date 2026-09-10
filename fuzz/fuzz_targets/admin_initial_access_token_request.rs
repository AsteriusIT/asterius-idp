//! The body the console posts to mint an initial access token (`ast-cu3`).
//!
//! The route this parses for is an *issuer of credentials*: what comes out of
//! it creates clients at a tenant. So the properties fuzzed here are not only
//! "does not panic" but the two that bound the credential.
//!
//! Properties:
//!
//! * **Total.** Arbitrary bytes are a request body, and a body that is not a
//!   JSON object, not UTF-8, or a number where a string belongs must be
//!   refused rather than crash the process every administrator shares.
//! * **The quota is never the caller's.** No accepted body can carry a quota,
//!   however it is spelt: `max_uses`, `max_clients`, anything. The ceiling
//!   comes from the tenant's registration policy at issuance, and a request
//!   that could name its own would defeat the whole setting. Asserted over the
//!   parsed value's *shape* — [`Requested`] has no quota field — and over the
//!   parse accepting bodies that try.
//! * **The lifetime is bounded.** Anything accepted is a positive number of
//!   seconds no larger than [`MAX_LIFETIME_SECONDS`], so no body can mint a
//!   credential that outlives the ceiling, and none can produce a zero or
//!   negative lifetime that would either issue a dead token or, worse, be read
//!   as "no expiry".
//! * **The label is bounded and non-empty.** It reaches a `text` column with a
//!   `check` on it and the audit trail; an unbounded one would be a row that
//!   breaks the screen that renders it.
#![no_main]

use asterius_admin_api::initial_access_tokens::{MAX_LIFETIME_SECONDS, requested};
use asterius_domain::MAX_INITIAL_ACCESS_TOKEN_LABEL_LEN;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(accepted) = requested(data) else {
        // A refusal is a correct outcome for arbitrary bytes. What must not
        // happen is a panic, which is what reaching this line proves did not.
        return;
    };

    assert!(
        !accepted.label.trim().is_empty(),
        "an empty label was accepted"
    );
    assert!(
        accepted.label.chars().count() <= MAX_INITIAL_ACCESS_TOKEN_LABEL_LEN,
        "a label past the column's check was accepted"
    );

    if let Some(seconds) = accepted.lifetime_seconds {
        assert!(seconds > 0, "a zero lifetime was accepted");
        assert!(
            seconds <= MAX_LIFETIME_SECONDS,
            "a lifetime past the ceiling was accepted"
        );
    }
});
