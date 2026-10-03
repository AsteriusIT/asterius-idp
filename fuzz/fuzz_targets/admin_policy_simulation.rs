//! Bounded simulation requests cannot supply trusted subject facts.
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
            "hypothetical_context": fragment
        });
        let encoded = serde_json::to_vec(&body).expect("JSON fixture serializes");
        if let Ok(parsed) = asterius_admin_api::policies::parse_simulation(&encoded) {
            assert!(parsed.policy.is_none());
            assert!(parsed.expected_revision.is_none());
            assert!(parsed.context_supplied);
        }
    }
});
