//! Administrative classification never accepts a stale or caller-defined fact.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = asterius_admin_api::conditional::RequestedSettings::parse(&value);
    }
});
