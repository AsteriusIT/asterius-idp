#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(data) {
        // Invalid bounded query/identity refusals are expected fuzz outcomes.
        let _ = asterius_domain::agent_task_views::Query::parse(Some(raw));
        let _ = asterius_domain::agent_task_views::identity(raw);
    }
});
