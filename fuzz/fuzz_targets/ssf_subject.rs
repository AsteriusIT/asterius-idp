//! `Subject::from_json` — RFC 9493 §3.2, SSF 1.0 §3.3 and §8.1.3.1.
//!
//! The subject identifier a receiver sends to the add-subject and
//! remove-subject endpoints. It arrives as JSON from a client holding nothing
//! but an access token, and what comes out of here decides two things that
//! matter: which row is written, and — through [`Subject::matches`] — which
//! people's security events that receiver is sent.
//!
//! Four invariants beyond "does not panic":
//!
//! * **The bounds hold.** Every accepted identifier's canonical form is within
//!   the guard the module publishes, so the store never sees an unbounded key.
//! * **Round-trip.** An accepted identifier renders to JSON that parses back to
//!   the same identifier, so the row that is written and the row that is read
//!   are the same subject. This is what makes the canonical key a key.
//! * **Matching is reflexive.** A subject always matches itself, or a receiver
//!   would stop hearing about somebody it explicitly subscribed to.
//! * **Matching is symmetric.** §8.1.3.1 defines matching member by member,
//!   with no side that is privileged; an asymmetry would mean delivery
//!   depended on which of the two was the stream's.
#![no_main]

use asterius_ssf::{MAX_SUBJECT_BYTES, Subject};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Two documents separated by a newline, so the matching invariants are
    // fuzzed over *pairs* rather than over one identifier against itself.
    let mut documents = text.splitn(2, '\n');
    let Some(Ok(first)) = documents
        .next()
        .map(serde_json::from_str::<serde_json::Value>)
    else {
        return;
    };
    let Ok(subject) = Subject::from_json(&first) else {
        return;
    };

    let key = subject.key();
    assert!(
        key.len() <= MAX_SUBJECT_BYTES,
        "accepted a subject whose canonical form is {} bytes",
        key.len()
    );

    let again = Subject::from_json(&subject.to_json())
        .expect("an accepted subject must parse back from its own rendering");
    assert_eq!(again, subject, "the wire form does not round-trip");
    assert_eq!(again.key(), key, "the canonical key is not stable");

    assert!(subject.matches(&subject), "a subject does not match itself");

    if let Some(Ok(second)) = documents
        .next()
        .map(serde_json::from_str::<serde_json::Value>)
        && let Ok(other) = Subject::from_json(&second)
    {
        assert_eq!(
            subject.matches(&other),
            other.matches(&subject),
            "matching is not symmetric: {first} against {second}"
        );
        // Two identifiers with one canonical key are one subject, so they
        // match; a stream keyed by one of them must deliver to the other.
        if other.key() == key {
            assert!(
                subject.matches(&other),
                "two spellings of one key do not match"
            );
        }
    }
});
