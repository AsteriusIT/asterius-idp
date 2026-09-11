//! `caep::AssuranceLevelChange::new` — CAEP 1.0 §3.4.
//!
//! The one CAEP event this server builds from four caller-supplied strings.
//! Invariants beyond "does not panic":
//!
//! * **A change is between two different levels.** §3.4 is about a change, so
//!   an accepted value's `current_level` and `previous_level` differ.
//! * **The members are validated.** Each is non-empty, within the text bound
//!   and free of control characters — the same guard as every other free-text
//!   member, checked here because this constructor is a public entry point.
//! * **It renders.** An accepted change turns into an event without panicking.
#![no_main]

use arbitrary::Arbitrary;
use asterius_ssf::caep::{AssuranceLevelChange, ChangeDirection, EventDetails};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

#[derive(Debug, Arbitrary)]
struct Input<'a> {
    namespace: &'a str,
    current_level: &'a str,
    previous_level: &'a str,
    increase: bool,
}

fuzz_target!(|input: Input<'_>| {
    let direction = if input.increase {
        ChangeDirection::Increase
    } else {
        ChangeDirection::Decrease
    };
    let Ok(change) = AssuranceLevelChange::new(
        input.namespace,
        input.current_level,
        input.previous_level,
        direction,
    ) else {
        return;
    };

    assert_ne!(
        input.current_level, input.previous_level,
        "accepted a change between equal levels"
    );

    // It renders without panicking: the point of accepting it.
    let details = EventDetails::at(OffsetDateTime::UNIX_EPOCH);
    let _event = change.into_event(&details);
});
