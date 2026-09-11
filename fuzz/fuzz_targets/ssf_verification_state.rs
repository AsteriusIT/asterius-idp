//! The `state` of an SSF verification event (SSF 1.0 §8.1.4, `ast-f7m.8`).
//!
//! A `state` is placed verbatim into a signed SET and compared by the
//! receiver against what it sent; it is typed by an operator today and will
//! be sent by a receiver when `ast-0ju.4` lands the request endpoint. This
//! target is about the parse that stands between that text and the token.
//!
//! Properties:
//!
//! * **Total.** Any string is an input and parsing it must not panic.
//! * **Bounded.** An accepted value is non-empty, at most `MAX_STATE_LEN`
//!   characters, and carries no control character.
//! * **Verbatim.** An accepted value reads back exactly as it was given —
//!   no trimming, no normalisation — because the receiver compares bytes.
//! * **Silent about the value.** A refusal is one of a closed set of
//!   sentences that never echoes the input.
#![no_main]

use asterius_ssf::verification::{MAX_STATE_LEN, StateError, VerificationState};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    match VerificationState::parse(raw) {
        Ok(state) => {
            assert!(!state.as_str().is_empty());
            assert!(state.as_str().chars().count() <= MAX_STATE_LEN);
            assert!(!state.as_str().chars().any(char::is_control));
            assert_eq!(state.as_str(), raw, "an accepted state was altered");
        }
        Err(error) => {
            let expected = match error {
                StateError::Empty => raw.is_empty(),
                StateError::TooLong { max } => {
                    max == MAX_STATE_LEN && raw.chars().count() > MAX_STATE_LEN
                }
                StateError::Control => raw.chars().any(char::is_control),
            };
            assert!(
                expected,
                "a refusal that the input does not warrant: {error}"
            );
            if raw.len() >= 4 {
                assert!(
                    !error.to_string().contains(raw),
                    "a refusal echoed the state"
                );
            }
        }
    }
});
