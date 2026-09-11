//! `PollRequest::parse` — RFC 8936 §2.1.
//!
//! The body a receiver `POST`s at the polling endpoint. It arrives as JSON
//! from a client holding nothing but an access token, and two of its members
//! are destructive: `ack` deletes queued SETs and `setErrs` retires them, both
//! by identifiers this object supplies.
//!
//! Three invariants beyond "does not panic":
//!
//! * **The bounds hold.** Every accepted request is inside the guards the
//!   module publishes, so no unbounded list of identifiers reaches a `WHERE`
//!   clause and no unbounded receiver string reaches the audit trail.
//! * **`maxEvents` cannot ask for more than the cap.** Whatever the receiver
//!   sent, `batch_size` is within `MAX_EVENTS` — a poll can never be made to
//!   read a tenant's whole backlog into memory.
//! * **Round-trip.** Anything accepted parses again to the same request, so
//!   two reads of one body cannot disagree about what is being acknowledged.
#![no_main]

use asterius_ssf::poll::{
    MAX_ACK, MAX_ERR_CODE_LEN, MAX_ERR_DESCRIPTION_LEN, MAX_EVENTS, MAX_JTI_LEN, MAX_SET_ERRS,
    PollRequest,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(body) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let Ok(request) = PollRequest::parse(&body) else {
        return;
    };

    assert!(
        request.batch_size() <= MAX_EVENTS,
        "accepted a batch of {}",
        request.batch_size()
    );
    assert!(
        !(request.batch_size() == 0 && request.waits()),
        "a poll that asks for no events must not wait for one"
    );

    assert!(
        request.ack.len() <= MAX_ACK,
        "accepted {} acks",
        request.ack.len()
    );
    for jti in &request.ack {
        assert!(
            jti.chars().count() <= MAX_JTI_LEN,
            "an acknowledged identifier is over the guard"
        );
    }

    assert!(
        request.set_errs.len() <= MAX_SET_ERRS,
        "accepted {} error reports",
        request.set_errs.len()
    );
    for rejected in &request.set_errs {
        assert!(
            rejected.jti.chars().count() <= MAX_JTI_LEN,
            "a rejected identifier is over the guard"
        );
        assert!(
            rejected.err.chars().count() <= MAX_ERR_CODE_LEN,
            "an error code is over the guard"
        );
        if let Some(description) = &rejected.description {
            assert!(
                description.chars().count() <= MAX_ERR_DESCRIPTION_LEN,
                "an error description is over the guard"
            );
        }
    }

    let again = PollRequest::parse(&body).expect("an accepted body must parse again");
    assert_eq!(again, request, "parsing is not idempotent");
});
