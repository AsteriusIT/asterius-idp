//! Configuration bounds and independent server identities.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|body: &[u8]| {
    if body.len() > 65536 {
        return;
    }
    if let Ok(config) = serde_json::from_slice::<
        asterius_domain::temporary_entitlements::EntitlementConfiguration,
    >(body)
        && config.validate().is_ok()
    {
        assert!((1..=3600).contains(&config.max_duration_seconds));
        assert!((1..=2592000).contains(&config.max_eligibility_seconds));
        assert!((1..=16).contains(&config.approver_user_ids.len()));
        assert_eq!(
            config
                .approver_user_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            config.approver_user_ids.len()
        );
        assert!((1..=64).contains(&config.permissions.len()));
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
        let _ = asterius_domain::temporary_kubernetes::KubernetesBindingChange::parse(value.clone());
        let _ = asterius_domain::temporary_kubernetes::KubernetesJitIdentity::parse(value);
    }
});
