#![no_main]
//! `asterius_webauthn::client_data::verify`.
//!
//! JSON the browser writes and an attacker may rewrite. The three checks it
//! performs — ceremony, challenge, origin — are the ones that bind a
//! credential to this server rather than to whoever relayed the request, so
//! what is asserted is that nothing gets past them.

use asterius_webauthn::client_data::{self, Ceremony};
use libfuzzer_sys::fuzz_target;

const CHALLENGE: &[u8] = b"0123456789abcdef0123456789abcdef";
const ORIGIN: &str = "https://as.example";

fuzz_target!(|data: &[u8]| {
    let origins = vec![ORIGIN.to_owned()];

    for ceremony in [Ceremony::Create, Ceremony::Get] {
        let Ok(client) = client_data::verify(data, ceremony, CHALLENGE, &origins) else {
            continue;
        };
        // The only origin that can come back is one that was allowed. A parse
        // that returned anything else would mean the comparison had been
        // bypassed rather than passed.
        assert_eq!(
            client.origin(),
            ORIGIN,
            "an origin outside the allow-list was accepted"
        );
    }
});
