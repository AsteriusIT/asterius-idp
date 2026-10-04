//! Canonical context pins cannot change spelling across parsing and rendering.
#![no_main]
use asterius_domain::outbound_scim::{canonical_issuer, canonical_uuid};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        if let Ok(issuer) = canonical_issuer(input) {
            assert!(
                issuer.as_str() == input
                    || (issuer.path() == "/" && issuer.as_str().strip_suffix('/') == Some(input))
            );
            assert_eq!(issuer.scheme(), "https");
            assert!(issuer.username().is_empty());
            assert!(issuer.query().is_none());
            assert!(issuer.fragment().is_none());
        }
        if let Ok(id) = canonical_uuid(input) {
            assert_eq!(id.to_string(), input);
        }
    }
});
