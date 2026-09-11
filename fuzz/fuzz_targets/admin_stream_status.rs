//! The admin API's stream status document: the body of
//! `PUT /ssf/streams/{stream_id}/status` (`ast-f7m.8`).
//!
//! An operator's request to pause or re-enable a stream (SSF 1.0 §8.1.2),
//! with a reason that is written to the stream row, shown on the console and
//! — the day `ast-0ju.4` lands — read back by the receiver. This target is
//! about the parse between that body and the row.
//!
//! Properties:
//!
//! * **Total.** Arbitrary bytes are a body and parsing one must not panic.
//! * **Closed.** An accepted status is `enabled` or `paused`, never
//!   `disabled` — the third state of §8.1.2 is the receiver's to write.
//! * **Bounded.** An accepted reason is non-empty, trimmed, at most
//!   `MAX_REASON_LEN` characters and carries no control character; an
//!   accepted `enabled` carries no reason at all.
//! * **Silent about the body.** A refusal never echoes what was sent.
#![no_main]

use asterius_admin_api::ssf::{MAX_REASON_LEN, parse_status_request};
use asterius_ssf::stream::StreamStatus;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match parse_status_request(data) {
        Ok(request) => {
            assert!(matches!(
                request.status,
                StreamStatus::Enabled | StreamStatus::Paused
            ));
            match (&request.status, &request.reason) {
                (StreamStatus::Enabled, reason) => assert!(reason.is_none()),
                (_, Some(reason)) => {
                    assert!(!reason.is_empty());
                    assert_eq!(reason.trim(), reason);
                    assert!(reason.chars().count() <= MAX_REASON_LEN);
                    assert!(!reason.chars().any(char::is_control));
                }
                (_, None) => {}
            }
        }
        Err(error) => {
            let message = error.to_string();
            if let Ok(text) = std::str::from_utf8(data)
                && text.len() >= 8
            {
                assert!(!message.contains(text), "a refusal echoed the body");
            }
        }
    }
});
