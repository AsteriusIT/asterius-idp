#![no_main]
use asterius_domain::governance_reports::{MAX_PAGE, Query};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data)
        && let Ok(query) = Query::parse(input)
    {
        assert!((1..=MAX_PAGE).contains(&query.limit));
    }
});
