//! Closed ordinary-account forms cannot supply actor or assurance provenance.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|body: &[u8]| {
    for action in ["request", "decide", "cancel", "revoke"] {
        if let Some((csrf, _)) = asterius_server::http::entitlements::parse_command(action, body) {
            assert!(body.len() <= 4096);
            assert!(!csrf.is_empty());
            assert!(csrf.len() <= 256);
            let pairs: Vec<_> = url::form_urlencoded::parse(body).collect();
            let names: std::collections::BTreeSet<_> =
                pairs.iter().map(|(name, _)| name.as_ref()).collect();
            assert_eq!(names.len(), pairs.len());
            assert!(!names.contains("actor"));
            assert!(!names.contains("acr"));
            assert!(!names.contains("amr"));
        }
    }
});
