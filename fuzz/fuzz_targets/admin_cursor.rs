//! The admin API's pagination cursor.
//!
//! A cursor arrives from the network on every page after the first, and it is
//! the one input to a listing that decides which rows a caller is shown. A
//! parser that is too generous turns "resume after this row" into a value an
//! attacker chose, and the value is about to be compared against a column.
//!
//! Properties:
//!
//! * **Total.** A `cursor` query parameter is arbitrary bytes and parsing one
//!   must not panic.
//! * **Round trip.** Anything this server mints, it reads back — as the same
//!   key, byte for byte. A cursor that does not survive its own encoding is a
//!   paging loop that silently repeats or skips a page.
//! * **Only this version.** A cursor minted under another scheme version is
//!   refused rather than reinterpreted as a key of this one, which is the
//!   whole reason the version is in the wire form.
//! * **Never empty.** An empty key would mean "resume after nothing", which is
//!   the first page — so accepting one would make a malformed cursor look like
//!   a successful reset rather than an error.
//! * **Bounded.** A megabyte of base64 is refused before it is decoded.
#![no_main]

use asterius_admin_api::pagination::{Cursor, PageRequest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    // The raw string, and the same bytes dressed as a well-formed cursor, so
    // the budget goes on the decoder rather than on failing to find a version
    // prefix at all.
    let minted = Cursor::after(raw).encode();
    for candidate in [raw.to_owned(), minted.clone(), format!("v1.{raw}")] {
        if let Ok(parsed) = Cursor::decode(&candidate) {
            assert!(!parsed.key().is_empty(), "decoded an empty key");

            // Deterministic, and its own wire form decodes to the same key.
            let again = Cursor::decode(&parsed.encode()).expect("a cursor this server minted");
            assert_eq!(parsed.key(), again.key(), "a cursor did not round trip");
        }

        // The parameter parser must be at least as strict as the decoder: a
        // cursor the decoder refuses may never reach a listing through it.
        let through_parameters = PageRequest::parse(Some(&candidate), None);
        assert_eq!(
            through_parameters.is_ok(),
            Cursor::decode(&candidate).is_ok(),
            "the parameter parser and the decoder disagree about {candidate:?}"
        );
    }

    // Anything this server mints, it reads back as exactly what went in.
    if !raw.is_empty() {
        let read_back = Cursor::decode(&minted).expect("a cursor this server minted");
        assert_eq!(read_back.key(), raw, "a minted cursor lost its key");
    }

    // A cursor carrying another scheme's version is never read as one of ours,
    // whatever its body says.
    for version in ["v0", "v2", "V1", ""] {
        let foreign = format!("{version}.{}", minted.trim_start_matches("v1."));
        assert!(
            Cursor::decode(&foreign).is_err(),
            "accepted a cursor from scheme {version:?}: {foreign:?}"
        );
    }

    // A limit is only ever a positive integer, and never exceeds the cap
    // whatever the caller asks for.
    if let Ok(request) = PageRequest::parse(None, Some(raw)) {
        assert!(request.limit > 0, "admitted a page of no rows");
        assert!(
            request.limit <= asterius_admin_api::pagination::MAX_LIMIT,
            "admitted a page above the cap: {}",
            request.limit
        );
    }
});
