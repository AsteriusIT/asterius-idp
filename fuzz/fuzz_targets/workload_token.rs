//! External assertions remain bounded and cannot panic before issuer trust.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    use asterius_domain::workload::Algorithm;
    let algorithms = [
        Algorithm::RS256,
        Algorithm::PS256,
        Algorithm::ES256,
        Algorithm::EdDSA,
    ]
    .into_iter()
    .collect();
    if let Ok(keys) = asterius_jose::workload::KeySet::parse(bytes, &algorithms) {
        assert!(bytes.len() <= 65536);
        assert!(!keys.fingerprints().is_empty() && keys.fingerprints().len() <= 16);
    }
    if let Ok(token) = std::str::from_utf8(bytes)
        && let Ok(parsed) = asterius_jose::workload::Parsed::parse(token)
    {
        assert!(token.len() <= 8192);
        assert!(!parsed.issuer().is_empty());
        assert!(!parsed.kid().is_empty() && parsed.kid().len() <= 128);
        assert!(!format!("{parsed:?}").contains(token));
    }
});
