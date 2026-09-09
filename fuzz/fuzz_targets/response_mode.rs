//! `ResponseMode::parse` — the parameter that decides what an authorization
//! response *is* (`ast-gxh.5`).
//!
//! A tiny parser, and that is the point: the interesting property is not that
//! it survives arbitrary input but that it accepts *only* the two spellings
//! this server advertises. Everything downstream branches on the result — a
//! 303 with a code in a URL, or a page that posts one to the client — and a
//! third accepted spelling would be a delivery nobody implemented.
//!
//! So the assertions are about the boundary rather than about panics: what is
//! accepted round-trips to itself, is exactly `query` or `form_post`, and
//! nothing that merely resembles them (case, whitespace, a suffix, an
//! embedded NUL) gets in.
#![no_main]

use asterius_oidc::authorize::ResponseMode;
use libfuzzer_sys::fuzz_target;

/// The whole accepted language, written out. A parser that grew a third value
/// would fail here rather than in a browser.
const ACCEPTED: [&str; 2] = ["query", "form_post"];

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    match ResponseMode::parse(text) {
        Ok(mode) => {
            // Accepted means "one of the two", by value and by spelling.
            assert!(ACCEPTED.contains(&text), "accepted {text:?}");
            assert_eq!(mode.as_str(), text, "the spelling was rewritten");
            assert_eq!(ResponseMode::parse(mode.as_str()), Ok(mode));
        }
        Err(_) => {
            assert!(!ACCEPTED.contains(&text), "refused {text:?}");
        }
    }

    // Nothing built out of an accepted value is accepted itself: a mode is a
    // whole parameter, never a prefix, a suffix or a case fold of one. This is
    // what stops `form_post ` — a trailing space a proxy might trim later —
    // and `form_post.jwt` from being read as `form_post` by this server and as
    // something else by anything in front of it.
    for accepted in ACCEPTED {
        for decorated in [
            format!("{accepted}{text}"),
            format!("{text}{accepted}"),
            format!("{accepted} {text}"),
        ] {
            if decorated != accepted {
                assert!(
                    ResponseMode::parse(&decorated).is_err(),
                    "accepted a decorated mode: {decorated:?}"
                );
            }
        }
    }
});
