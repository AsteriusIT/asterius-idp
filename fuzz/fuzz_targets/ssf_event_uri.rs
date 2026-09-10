//! `EventUri::parse` — RFC 8417 §2, SSF 1.0 §4.2.
//!
//! The key an event appears under in `events`, and the string a receiver
//! dispatches on. Two invariants beyond "does not panic":
//!
//! * **Byte-exact.** What comes out is what went in. A receiver matches the
//!   key against the event type it registered for, so a parser that
//!   normalised — added a trailing slash, dropped a default port, lowercased
//!   a path — would emit an event type nobody subscribed to.
//! * **No escape.** An accepted URI is absolute, carries no fragment and is
//!   within the length guard, which is what the rest of the crate assumes
//!   without re-checking.
#![no_main]

use asterius_ssf::{EventUri, MAX_EVENT_URI_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(uri) = EventUri::parse(text) else {
        return;
    };

    let kept = uri.as_str();
    assert_eq!(kept, text, "the event type was rewritten");
    assert!(!kept.is_empty(), "accepted an empty event type");
    assert!(
        kept.chars().count() <= MAX_EVENT_URI_LEN,
        "over the guard: {} characters",
        kept.chars().count()
    );
    assert!(!kept.contains('#'), "accepted a fragment: {kept:?}");
    assert!(
        url::Url::parse(kept).is_ok(),
        "accepted a relative reference: {kept:?}"
    );

    let reparsed = EventUri::parse(kept).expect("an accepted event type must re-parse");
    assert_eq!(reparsed, uri, "parsing is not idempotent");
});
