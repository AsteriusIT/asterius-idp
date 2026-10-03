#![no_main]
use asterius_domain::outbound_scim::{parse_peer_capabilities, parse_peer_token};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    let _ = parse_peer_capabilities(bytes);
    let _ = parse_peer_token(bytes);
});
