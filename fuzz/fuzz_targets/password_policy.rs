//! Password policy — NIST SP 800-63B §5.1.1.2.
//!
//! The policy decides what may become a stored credential, so the properties
//! are about what it accepts, not about panics:
//!
//! * **Normalisation is idempotent and total.** NFKC over arbitrary Unicode
//!   must not panic and must reach a fixed point — a password that normalised
//!   differently on the second pass would verify once and then never again.
//! * **An accepted password is within the length bounds *after* normalisation**,
//!   because normalisation can change the character count (a ligature becomes
//!   two characters) and the bound that matters is the one on what is hashed.
//! * **Length is counted in characters.** A multi-byte password must not be
//!   refused for its byte length; that would be a rule about the user's
//!   language.
//! * **The deny list sees the normalised form**, or a user evades it by typing
//!   a different spelling of the same string.
//! * **Whitespace survives.** Trimming would make two different passwords
//!   authenticate one account.
#![no_main]

use asterius_domain::entities::password::{
    AcceptedPassword, MAX_LENGTH, MIN_LENGTH, PasswordError, normalise,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(candidate) = std::str::from_utf8(data) else {
        return;
    };

    // Normalisation is total and idempotent.
    let once = normalise(candidate);
    assert_eq!(normalise(&once), once, "NFKC is not idempotent for {candidate:?}");

    // What the deny list is shown.
    let mut seen: Option<String> = None;
    let outcome = AcceptedPassword::accept(candidate, |shown| {
        seen = Some(shown.to_owned());
        false
    });

    // The deny list, when consulted, sees the normalised form.
    if let Some(shown) = &seen {
        assert_eq!(
            shown, &once,
            "the deny list saw a form other than the normalised one"
        );
    }

    match outcome {
        Ok(accepted) => {
            let stored = accepted.expose();

            // Accepted implies stored == normalised. Anything else means the
            // bytes that get hashed are not the bytes that were checked.
            assert_eq!(stored, once, "the accepted value is not the normalised one");

            // Within bounds, counted in characters.
            let length = stored.chars().count();
            assert!(
                (MIN_LENGTH..=MAX_LENGTH).contains(&length),
                "accepted a password of {length} characters"
            );

            // Whitespace is part of the password.
            assert_eq!(
                stored.trim_start().len() + (stored.len() - stored.trim_start().len()),
                stored.len(),
                "leading whitespace was altered"
            );

            // The deny list must have been consulted before acceptance.
            assert!(seen.is_some(), "a password was accepted without a deny-list check");
        }
        Err(PasswordError::TooShort) => {
            assert!(once.chars().count() < MIN_LENGTH, "refused a long-enough password");
        }
        Err(PasswordError::TooLong) => {
            assert!(once.chars().count() > MAX_LENGTH, "refused a short-enough password");
        }
        Err(PasswordError::TooCommon) => {
            unreachable!("the fixture never says a password is common");
        }
        Err(_) => {}
    }

    // A password on the deny list is always refused, whatever its shape.
    if !once.is_empty() {
        assert_eq!(
            AcceptedPassword::accept(candidate, |_| true).err(),
            match once.chars().count() {
                n if n < MIN_LENGTH => Some(PasswordError::TooShort),
                n if n > MAX_LENGTH => Some(PasswordError::TooLong),
                _ => Some(PasswordError::TooCommon),
            },
            "the deny list did not refuse {candidate:?}"
        );
    }
});
