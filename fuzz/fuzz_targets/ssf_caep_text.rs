//! `caep::text` — CAEP 1.0 §2 free-text members.
//!
//! Every free-text member of a CAEP or RISC event — `friendly_name`, the two
//! `reason_*` messages, the x509 identifiers, the assurance namespace and
//! levels — goes through this one validator, and its output reaches a
//! receiver's log verbatim. Invariants beyond "does not panic":
//!
//! * **Bounded.** An accepted value is within [`caep::MAX_TEXT_LEN`]
//!   characters, so a SET cannot grow without limit through one of these.
//! * **No control characters.** An accepted value carries none, so it cannot
//!   inject a line into the log it is written to.
//! * **Non-empty.** An accepted value identifies something.
//! * **Idempotent.** What is accepted re-validates unchanged.
#![no_main]

use asterius_ssf::caep::{self, MAX_TEXT_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(accepted) = caep::text("member", text) else {
        return;
    };

    assert_eq!(accepted, text, "an accepted value was rewritten");
    assert!(!accepted.is_empty(), "accepted an empty value");
    assert!(
        accepted.chars().count() <= MAX_TEXT_LEN,
        "over the guard: {} characters",
        accepted.chars().count()
    );
    assert!(
        !accepted.chars().any(char::is_control),
        "accepted a control character"
    );

    let reparsed = caep::text("member", &accepted).expect("an accepted value must re-validate");
    assert_eq!(reparsed, accepted, "validation is not idempotent");
});
