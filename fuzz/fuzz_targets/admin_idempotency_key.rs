//! The admin API's `Idempotency-Key` validator.
//!
//! The key is chosen by the caller, ends up as part of a database key, and is
//! written into log lines. Both destinations are why the validator exists: a
//! key carrying a newline is a log injection, and an unbounded one is a
//! request for the server to store whatever the caller sends.
//!
//! Properties:
//!
//! * **Total.** An `Idempotency-Key` header is arbitrary bytes.
//! * **Nothing accepted carries a control character.** That is the log
//!   injection, and it is the property with a security consequence.
//! * **Bounded on both sides.** Below the floor keys collide, so one
//!   administrator's creation is refused because another used `1`; above the
//!   ceiling the server stores whatever it was sent.
//! * **Preserving.** An accepted key is stored exactly as presented — a
//!   validator that trimmed or lowercased would make two distinct keys the
//!   same one, which is a creation silently refused.
#![no_main]

use asterius_admin_api::idempotency::{IdempotencyKey, MAX_LEN, MIN_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(accepted) = IdempotencyKey::parse(raw) else {
        // A refusal is always fine. What must never happen is the other
        // direction, checked below.
        return;
    };

    // Preserved byte for byte: a validator that normalised would collapse two
    // distinct keys into one, and the second creation would be refused as a
    // replay of the first.
    assert_eq!(accepted.as_str(), raw, "an accepted key was altered");

    // Bounded on both sides.
    assert!(
        (MIN_LEN..=MAX_LEN).contains(&raw.len()),
        "accepted a key of {} bytes",
        raw.len()
    );

    // The property with a security consequence: nothing accepted can break a
    // log line or carry a NUL into a query.
    for byte in raw.bytes() {
        assert!(
            byte.is_ascii_graphic() || byte == b' ',
            "accepted a key carrying byte {byte:#04x}"
        );
    }

    // Deterministic, and idempotent under re-parsing — the key is a value the
    // server will compare against a stored copy of itself.
    let again = IdempotencyKey::parse(accepted.as_str()).expect("an accepted key parses again");
    assert_eq!(accepted, again, "parsing a key is not deterministic");

    // The rendering is the key, so a log line and a database key say the same
    // thing.
    assert_eq!(accepted.to_string(), raw);
});
