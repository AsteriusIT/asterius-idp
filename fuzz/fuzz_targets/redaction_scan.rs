//! The credential scanner shared by the logs and the audit trail.
//!
//! A scanner that panics turns a log line into an outage, and one that is not
//! idempotent corrupts the audit hash chain — a record is redacted once on the
//! way in and must render identically when read back.
#![no_main]

use asterius_domain::audit::redaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let once = redaction::redact(text);
    assert_eq!(
        redaction::redact(&once),
        once,
        "redaction is not idempotent"
    );

    // A value the scanner itself calls a credential must never survive whole.
    if redaction::classify(text).is_some() && !text.trim().is_empty() {
        assert!(
            !once.contains(text.trim()),
            "a classified credential survived redaction"
        );
    }

    // Fingerprints are total and fixed width.
    assert_eq!(redaction::fingerprint(text).len(), 64);
});
