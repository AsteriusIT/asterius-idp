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
    if bytes.len() <= 65536 {
        let spiffe_algorithms = [Algorithm::RS256, Algorithm::PS256, Algorithm::ES256]
            .into_iter()
            .collect();
        let _ = asterius_jose::workload::SpiffeBundle::parse(bytes, &spiffe_algorithms);
        if let Ok(config) = serde_json::from_slice::<asterius_domain::workload::Config>(bytes) {
            let _ = config.validate(&asterius_domain::TenantId::new("fuzz"), "source");
        }
        if let Ok(details) = serde_json::from_slice::<Vec<serde_json::Value>>(bytes) {
            let _ = asterius_domain::workload::validate_actions(
                &details,
                &["read".to_owned()].into_iter().collect(),
                &["https://api.example/".to_owned()].into_iter().collect(),
            );
        }
    }
    if let Ok(keys) = asterius_jose::workload::KeySet::parse(bytes, &algorithms) {
        assert!(bytes.len() <= 65536);
        assert!(!keys.fingerprints().is_empty() && keys.fingerprints().len() <= 16);
    }
    if let Ok(token) = std::str::from_utf8(bytes) {
        let _ = asterius_jose::workload::issuer_hint(token);
        let _ = asterius_jose::workload::Parsed::parse_spiffe(token);
        let _ = asterius_domain::workload::spiffe_domain(token);
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
