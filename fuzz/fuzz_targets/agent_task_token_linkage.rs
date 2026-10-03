#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > 32768 {
        return;
    }
    if let Ok(claims) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = asterius_domain::agent_tasks::TokenQuery::from_claims(&claims);
    }
});
