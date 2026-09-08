//! The client JWK Set parser, over arbitrary bytes.
//!
//! This is what a client's `jwks_uri` serves us, so the input is chosen by
//! whoever the client points at. Three invariants, and none of them is "it
//! parses":
//!
//! * It never panics — not on truncated base64url, not on a coordinate of the
//!   wrong length, not on nesting.
//! * A set that parses never holds more keys than the cap, because the number
//!   of keys is the number of signature checks one unauthenticated request can
//!   ask for.
//! * The two entry points agree. An inline `jwks` goes through
//!   `keys_from_jwk_set` and a fetched one through `parse_jwk_set`; if they
//!   ever diverged, a client could publish a key one path accepts and the other
//!   rejects, and the choice would be the client's.
#![no_main]

use asterius_domain::Kid;
use asterius_jose::client_keys::{MAX_KEYS, keys_from_jwk_set, parse_jwk_set};
use asterius_jose::verify::KeyResolver;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = parse_jwk_set(data);

    if let Ok(set) = &parsed {
        assert!(set.keys().len() <= MAX_KEYS, "the key cap was exceeded");

        // A `kid` narrows; it never widens. Whatever it names, the candidates
        // are a subset of the set, and an absent `kid` offers everything.
        assert!(set.candidates(Some(&Kid::new("unknown"))).len() <= set.keys().len());
        assert_eq!(set.candidates(None).len(), set.keys().len());
    }

    // Whatever `serde_json` makes of these bytes, the by-value path must make
    // the same of it as the by-reference one.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let inline = keys_from_jwk_set(&value);
        assert_eq!(
            parsed.is_ok(),
            inline.is_ok(),
            "an inline JWK Set and a fetched one disagreed"
        );
        if let (Ok(fetched), Ok(inline)) = (parsed, inline) {
            assert_eq!(
                fetched.verifying_keys(),
                inline.verifying_keys(),
                "an inline JWK Set and a fetched one produced different keys"
            );
        }
    }
});
