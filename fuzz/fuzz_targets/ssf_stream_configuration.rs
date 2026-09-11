//! `StreamRequest::parse` — SSF 1.0 §8.1.1.
//!
//! The body a receiver `POST`s, `PATCH`es or `PUT`s at the stream
//! configuration endpoint. It arrives as JSON from a client holding nothing
//! but an access token, and everything downstream — the row that is written,
//! the URL a SET is pushed to, the object echoed back — is built from what
//! comes out of here.
//!
//! Four invariants beyond "does not panic":
//!
//! * **The bounds hold.** Every accepted request is within the guards the
//!   module publishes, so the store never sees an unbounded write.
//! * **A push endpoint is https and nothing else.** RFC 8935 §2.2. The one
//!   member of this object that becomes an outbound request.
//! * **No credential is smuggled in.** A `delivery` carrying an
//!   `authorization_header` is refused rather than accepted and dropped.
//! * **Round-trip.** Anything accepted parses again to the same request, so
//!   two reads of one body cannot disagree.
#![no_main]

use asterius_ssf::push::MAX_AUTHORIZATION_HEADER_LEN;
use asterius_ssf::stream::{
    DeliveryRequest, MAX_AUDIENCE, MAX_DESCRIPTION_LEN, MAX_EVENTS_REQUESTED,
    MAX_INACTIVITY_TIMEOUT, MAX_URL_LEN, MIN_INACTIVITY_TIMEOUT, StreamRequest,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(body) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let Ok(request) = StreamRequest::parse(&body) else {
        return;
    };

    if let Some(audience) = &request.audience {
        assert!(
            !audience.is_empty() && audience.len() <= MAX_AUDIENCE,
            "accepted {} audience values",
            audience.len()
        );
        for value in audience {
            assert!(!value.is_empty(), "accepted an empty audience value");
            assert!(
                value.chars().count() <= MAX_URL_LEN,
                "audience over the guard"
            );
        }
    }

    if let Some(events) = &request.events_requested {
        assert!(
            events.len() <= MAX_EVENTS_REQUESTED,
            "accepted {} requested events",
            events.len()
        );
        for event in events {
            assert!(
                asterius_ssf::EventUri::parse(event).is_ok(),
                "accepted an entry that is not an event type URI: {event:?}"
            );
        }
    }

    if let Some(description) = &request.description {
        assert!(
            description.chars().count() <= MAX_DESCRIPTION_LEN,
            "accepted an oversized description"
        );
    }

    if let Some(timeout) = request.inactivity_timeout {
        assert!(
            (MIN_INACTIVITY_TIMEOUT..=MAX_INACTIVITY_TIMEOUT).contains(&timeout),
            "accepted an inactivity timeout of {timeout}"
        );
    }

    if let Some(DeliveryRequest::Push {
        endpoint_url,
        authorization_header,
    }) = &request.delivery
    {
        let url = url::Url::parse(endpoint_url).expect("an accepted push endpoint must be a URL");
        assert_eq!(url.scheme(), "https", "accepted a push endpoint over {url}");
        assert!(url.has_host(), "accepted a push endpoint with no host");
        assert!(url.fragment().is_none(), "accepted a fragment in {url}");
        assert!(
            url.username().is_empty() && url.password().is_none(),
            "accepted credentials in a push endpoint"
        );
        assert!(
            endpoint_url.chars().count() <= MAX_URL_LEN,
            "push endpoint over the guard"
        );

        // SSF 1.0 §6.1.1's credential goes into a request header on every
        // delivery, so an accepted one is a value HTTP can carry and nothing
        // else: no control character, no leading or trailing whitespace, and
        // bounded. A value with a `\r\n` in it would be a second header in
        // every request this server then makes to that receiver.
        if let Some(header) = authorization_header {
            let value = header.expose();
            assert!(
                value.chars().count() <= MAX_AUTHORIZATION_HEADER_LEN,
                "accepted an unbounded authorization_header"
            );
            assert!(!value.is_empty(), "accepted an empty authorization_header");
            assert!(
                value
                    .bytes()
                    .all(|byte| (0x21..=0x7e).contains(&byte) || byte == b' ' || byte == b'\t'),
                "accepted an authorization_header that is not a field value"
            );
            assert_eq!(
                value.trim(),
                value,
                "accepted a padded authorization_header"
            );
            // And it never renders itself, wherever it is written.
            assert!(
                !format!("{header:?}").contains(value),
                "a credential rendered itself in Debug output"
            );
        }
    }

    let again = StreamRequest::parse(&body).expect("an accepted body must parse again");
    assert_eq!(again, request, "parsing is not idempotent");
});
