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
//! * **Silent about the body.** A refusal is one of a closed set of
//!   sentences, so nothing that was sent can come back out.
//!
//! That last one used to be spelled "the message does not contain the body",
//! which is not the same statement: every sentence below is a fragment of
//! English, and a body that happens to *be* such a fragment — libFuzzer found
//! `the request body is not a status document: the body is not JSON` — made
//! the check fail without anything having leaked (`ast-eqe`). Membership in a
//! body-independent set says what was meant, and cannot coincide.
#![no_main]

use asterius_admin_api::ssf::{MAX_REASON_LEN, parse_status_request};
use asterius_ssf::stream::StreamStatus;
use libfuzzer_sys::fuzz_target;

/// Every sentence `parse_status_request` can refuse with, in full.
///
/// The parser builds each one from `&'static str` pieces and the
/// `MAX_REASON_LEN` constant, never from the body. Adding a refusal to the
/// parser without adding it here fails this target on the first input that
/// reaches it, which is the intended tripwire: a new message is exactly where
/// an echo would be introduced.
fn refusals() -> Vec<String> {
    let mut sentences: Vec<String> = [
        "the body ended early",
        "the body is not JSON",
        "the body carries a member the document does not have, or one of the wrong type",
    ]
    .iter()
    .map(|classification| format!("the request body is not a status document: {classification}"))
    .collect();
    sentences.push("status must be enabled or paused".to_owned());
    sentences.push("reason must not be empty when given".to_owned());
    sentences.push(format!("reason is longer than {MAX_REASON_LEN} characters"));
    sentences.push("reason must not carry a control character".to_owned());
    sentences
}

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
            assert!(
                refusals().contains(&message),
                "a refusal outside the closed set: {message}"
            );
        }
    }
});
