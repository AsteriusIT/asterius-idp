//! `ReceiverError::parse` — RFC 8935 §2.3.
//!
//! The body a push receiver returns with a 400. It is the only document in the
//! push direction this transmitter reads, it is written by a third party at a
//! URL another party configured, and what comes out of it is stored in
//! `outbox.last_error`, audited, and rendered to an operator.
//!
//! The input is raw bytes, not JSON: a receiver's error page is whatever its
//! web server felt like sending, including invalid UTF-8, and the parser has
//! to answer for that rather than be handed a value some earlier stage already
//! accepted.
//!
//! Four invariants beyond "does not panic":
//!
//! * **Total.** Every byte string produces an answer. The status code has
//!   already said the delivery failed, so there is no second failure for a
//!   parse to express.
//! * **The code is one of this build's own constants.** A receiver cannot get
//!   a string of its choosing into a metric label, an audit member or a branch
//!   — including the `invalid_key` branch, which is the one that is acted on.
//! * **The description is bounded and printable.** No control characters, so
//!   nothing here forges a log line or repaints a terminal, and never more
//!   characters than the module's cap.
//! * **`detail()` says only those two things.** It is the string that reaches
//!   the operator's screen, so it may not grow without bound either.
#![no_main]

use asterius_ssf::push::{MAX_DESCRIPTION_CHARS, ReceiverError, ReceiverErrorCode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let error = ReceiverError::parse(data);

    // The closed set of §2.3, plus "not one of them". Compared by string
    // because that is the form the value is used in downstream.
    let known: Vec<&str> = ReceiverErrorCode::DEFINED
        .iter()
        .map(|code| code.as_str())
        .chain(std::iter::once("unrecognised"))
        .collect();
    assert!(
        known.contains(&error.code.as_str()),
        "a receiver chose the code: {:?}",
        error.code
    );

    // Only `invalid_key` may ask for a key refresh, whatever the body said.
    assert_eq!(
        error.code.suggests_key_refresh(),
        error.code == ReceiverErrorCode::InvalidKey
    );

    if let Some(description) = &error.description {
        assert!(
            description.chars().count() <= MAX_DESCRIPTION_CHARS,
            "an unbounded description was kept: {} characters",
            description.chars().count()
        );
        assert!(
            !description.chars().any(char::is_control),
            "a control character reached the operator's screen: {description:?}"
        );
        assert!(
            !description.is_empty() && !description.ends_with(' '),
            "an empty or padded description was kept: {description:?}"
        );
    }

    // The rendered line is the code, the description and a fixed frame around
    // them, so it is bounded by the two bounds above.
    let detail = error.detail();
    assert!(
        detail.chars().count() <= MAX_DESCRIPTION_CHARS + 64,
        "an unbounded detail line: {} characters",
        detail.chars().count()
    );
    assert!(detail.contains(error.code.as_str()));

    // The same bytes twice are the same answer: a parser whose result depended
    // on anything but its argument could not be reasoned about at all.
    assert_eq!(ReceiverError::parse(data), error);
});
