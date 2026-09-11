//! `StatusRequest::parse` and `SubjectRequest::parse` — SSF 1.0 §8.1.2.2,
//! §8.1.3.2 and §8.1.3.3.
//!
//! The two bodies a receiver sends to the management endpoints that are not
//! the stream configuration: one stops or starts the delivery of a tenant's
//! security signals, the other decides whose signals those are. Both arrive as
//! JSON from a client holding nothing but an access token.
//!
//! One target for both parsers, because they read the same envelope — a
//! `stream_id` that must be an identifier this server could have issued — and
//! the bug worth catching is in that shared part.
//!
//! Three invariants beyond "does not panic":
//!
//! * **A parsed `stream_id` is one this server could have issued.** It reaches
//!   a `WHERE` clause, and [`StreamId::parse`] is the only thing between the
//!   request and it.
//! * **A parsed status is one §8.1.2 defines.** There are three, and a fourth
//!   would be a stream in a state nothing downstream can read.
//! * **Parsing is idempotent.** Two reads of one body cannot disagree about
//!   which stream is addressed or what is being asked for.
#![no_main]

use asterius_ssf::management::{MAX_REASON_LEN, StatusRequest, SubjectRequest};
use asterius_ssf::stream::{StreamId, StreamStatus};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(body) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };

    if let Ok(request) = StatusRequest::parse(&body) {
        assert!(
            matches!(
                request.status,
                StreamStatus::Enabled | StreamStatus::Paused | StreamStatus::Disabled
            ),
            "accepted a status outside §8.1.2's three"
        );
        assert_eq!(
            StreamStatus::parse(request.status.as_str()),
            Some(request.status),
            "a parsed status does not round-trip through its wire spelling"
        );
        if let Some(reason) = &request.reason {
            assert!(
                reason.chars().count() <= MAX_REASON_LEN,
                "accepted an oversized reason"
            );
        }
        if let Some(stream) = &request.stream_id {
            assert_eq!(
                StreamId::parse(stream.as_str()).as_ref(),
                Some(stream),
                "accepted a stream_id this server could not have issued"
            );
        }
        let again = StatusRequest::parse(&body).expect("an accepted body must parse again");
        assert_eq!(again, request, "parsing a status request is not idempotent");
    }

    if let Ok(request) = SubjectRequest::parse(&body) {
        if let Some(stream) = &request.stream_id {
            assert_eq!(
                StreamId::parse(stream.as_str()).as_ref(),
                Some(stream),
                "accepted a stream_id this server could not have issued"
            );
        }
        assert!(
            request.subject.matches(&request.subject),
            "an accepted subject does not match itself"
        );
        let again = SubjectRequest::parse(&body).expect("an accepted body must parse again");
        assert_eq!(
            again, request,
            "parsing a subject request is not idempotent"
        );
    }
});
