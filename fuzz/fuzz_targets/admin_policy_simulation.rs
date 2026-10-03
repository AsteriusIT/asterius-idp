//! Bounded simulation inputs cannot supply directory authority or production sources.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = asterius_admin_api::policies::parse_simulation(bytes);
    if bytes.len() > 65_536 {
        return;
    }
    if let Ok(fragment) = serde_json::from_slice::<serde_json::Value>(bytes) {
        let body = serde_json::json!({
            "user_id": "00000000-0000-0000-0000-000000000001",
            "client_id": "app", "resource_id": "https://api.example", "resource_type": "api",
            "action": "read", "expected_policy_revision": null,
            "hypothetical_context": fragment.clone()
        });
        let examples = serde_json::json!({
            "user_id": "00000000-0000-0000-0000-000000000001", "client_id": "app",
            "resource_id": "https://api.example", "resource_type": "api", "action": "read",
            "expected_policy_revision": null, "enforcement_action": "refresh_token",
            "hypothetical_trusted_context": fragment
        });
        let example_bytes = serde_json::to_vec(&examples).expect("JSON fixture serializes");
        if let Ok(parsed) = asterius_admin_api::policies::parse_simulation(&example_bytes) {
            assert!(parsed.trusted_examples.is_some());
            assert_eq!(parsed.enforcement_action, "refresh_token");
            assert!(parsed.policy.is_none());
        }
        let encoded = serde_json::to_vec(&body).expect("JSON fixture serializes");
        if let Ok(parsed) = asterius_admin_api::policies::parse_simulation(&encoded) {
            assert!(parsed.policy.is_none());
            assert!(parsed.expected_revision.is_none());
            assert!(parsed.context_supplied);
        }
    }
});
