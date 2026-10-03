#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = asterius_server::http::account_grants::task_withdrawal(data);
});
