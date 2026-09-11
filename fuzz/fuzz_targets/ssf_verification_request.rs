//! The body of an SSF verification request (SSF 1.0 §8.1.4.2, `ast-0ju.5`).
//!
//! A receiver posts `{stream_id, state}` to the verification endpoint and the
//! transmitter answers 204 having queued a signed SET that echoes `state`
//! verbatim. This target is about the parse that stands between a receiver's
//! bytes and that token.
//!
//! Properties:
//!
//! * **Total.** Any byte string is an input and parsing it must not panic.
//! * **Signed-safe.** An accepted `state` is non-empty, within the bound and
//!   free of control characters — it becomes a claim in a token handed to a
//!   third party, and nothing downstream checks it again.
//! * **Verbatim.** An accepted `state` reads back exactly as the receiver
//!   wrote it, because the receiver compares it with what it sent.
//! * **Addressed.** An accepted request either names a stream identifier this
//!   server could have issued, or reports that it names none.
//! * **Silent about the value.** A refusal never echoes the body.
#![no_main]

use asterius_ssf::management::{ManagementError, VerificationRequest};
use asterius_ssf::stream::StreamId;
use asterius_ssf::verification::MAX_STATE_LEN;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    match VerificationRequest::parse(&body) {
        Ok(request) => {
            if let Some(state) = request.state.as_ref() {
                let raw = state.as_str();
                assert!(!raw.is_empty());
                assert!(raw.chars().count() <= MAX_STATE_LEN);
                assert!(!raw.chars().any(char::is_control));
                assert_eq!(
                    Some(raw),
                    body.get("state").and_then(serde_json::Value::as_str),
                    "an accepted state was altered"
                );
            }
            match request.addressed_stream() {
                Ok(stream) => assert!(StreamId::parse(stream.as_str()).is_some()),
                Err(error) => assert!(matches!(error, ManagementError::MissingStreamId)),
            }
        }
        Err(error) => {
            let message = error.to_string();
            if let Some(state) = body.get("state").and_then(serde_json::Value::as_str)
                && state.len() >= 4
            {
                assert!(!message.contains(state), "a refusal echoed the state");
            }
            if let Some(stream) = body.get("stream_id").and_then(serde_json::Value::as_str)
                && stream.len() >= 4
            {
                assert!(!message.contains(stream), "a refusal echoed the stream_id");
            }
        }
    }
});
