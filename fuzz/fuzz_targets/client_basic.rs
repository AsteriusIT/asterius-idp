//! RFC 6749 §2.3.1 HTTP Basic client credentials.
//!
//! The parser accepts attacker-controlled header bytes after HTTP parsing. It
//! must never panic, allocate without the stated bound, accept empty decoded
//! components, or leak a secret through `Debug`.
#![no_main]

use asterius_oidc::client_auth::parse_basic_credentials;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|header: &str| {
    if let Some((client_id, secret)) = parse_basic_credentials(header) {
        assert!(!client_id.is_empty());
        assert!(!secret.expose().is_empty());
        assert!(header.len() <= 2048);
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }
});
