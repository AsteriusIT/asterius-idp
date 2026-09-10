//! The self-service sign-up form — OpenID Connect Prompt Create 1.0 §3.
//!
//! This is the only parser in the server that turns text from somebody who has
//! proved nothing into a row in `users`, so what it accepts is what a stranger
//! can put in front of every relying party that renders a
//! `preferred_username`, in every unique index the accounts table has, and in
//! the destination header of mail this server sends. The properties asserted
//! here are the ones nothing downstream re-checks:
//!
//! * **Parsing is total.** No input panics, however long, however strange.
//! * **Nothing is invented.** Every accepted value is a *substring* of what was
//!   submitted — trimming is the only transformation, so the name written to
//!   the database is a name somebody typed.
//! * **No accepted name can reorder what a person reads.** Control characters
//!   and the Unicode bidirectional set are refused in both names. Escaping does
//!   not help against a right-to-left override: it is legal text that survives
//!   every encoder, and a consent screen is where it would be aimed. Restated
//!   here rather than imported, because an oracle that shares the subject's
//!   list agrees with it even when the list is wrong.
//! * **Neither name is ever an empty string.** A blank display name is `None`
//!   and not `Some("")`, so the claim bag can never carry an empty
//!   `preferred_username` — which OIDC Core §5.3.2 says is a claim that exists
//!   and asserts nothing.
//! * **The limits hold in characters.** A limit counted in bytes would be a
//!   limit on the user's alphabet; an accepted name is within the character
//!   count whatever it is written in.
//! * **An accepted address could be delivered to.** Not RFC 5322 — see the
//!   module documentation for why that is not validated here — but non-empty,
//!   within RFC 5321 §4.5.3.1.3's 320 octets, free of whitespace, and carrying
//!   an `@` that is neither the first nor the last character.
//! * **An accepted password is normalised.** NIST SP 800-63B §5.1.1.2's NFKC is
//!   applied, so what is hashed is stable across keyboards.
#![no_main]

use asterius_domain::entities::self_registration::{
    AcceptedRegistration, MAX_DISPLAY_NAME_LENGTH, MAX_REGISTRATION_EMAIL_LENGTH,
    MAX_REGISTRATION_USERNAME_LENGTH,
};
use libfuzzer_sys::fuzz_target;

/// The Unicode bidirectional formatting characters, restated from UAX #9.
///
/// U+061C ARABIC LETTER MARK, U+200E/U+200F the left- and right-to-left marks,
/// U+202A–U+202E the embedding and override set, U+2066–U+2069 the isolates.
const BIDIRECTIONAL: &[char] = &[
    '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

/// Whether a name may be shown to a person without reordering the page.
fn is_readable(value: &str) -> bool {
    !value.chars().any(char::is_control) && !value.chars().any(|c| BIDIRECTIONAL.contains(&c))
}

fuzz_target!(|input: (String, Option<String>, String, String)| {
    let (username, display_name, email, password) = input;

    let Ok(accepted) =
        AcceptedRegistration::accept(&username, display_name.as_deref(), &email, &password)
    else {
        // A refusal is an ordinary outcome and asserts nothing: this parser is
        // allowed to say no to anything. What it is not allowed to do is
        // accept something it should not, which is what the arms below check.
        return;
    };

    // Nothing invented. Trimming is the only transformation the two names and
    // the address go through, so each accepted value is still inside the
    // submission it came from.
    assert!(
        username.contains(accepted.username()),
        "the username was rewritten: {:?} -> {:?}",
        username,
        accepted.username()
    );
    assert!(
        email.contains(accepted.email()),
        "the address was rewritten: {:?} -> {:?}",
        email,
        accepted.email()
    );

    assert!(!accepted.username().is_empty());
    assert!(is_readable(accepted.username()));
    assert!(accepted.username().chars().count() <= MAX_REGISTRATION_USERNAME_LENGTH);
    assert_eq!(accepted.username(), accepted.username().trim());

    if let Some(chosen) = accepted.display_name() {
        let submitted = display_name.as_deref().unwrap_or_default();
        assert!(
            submitted.contains(chosen),
            "the display name was rewritten: {submitted:?} -> {chosen:?}"
        );
        // Never `Some("")`: a blank field is no display name at all, so the
        // claim bag cannot hold a `preferred_username` that asserts nothing.
        assert!(!chosen.is_empty());
        assert!(is_readable(chosen));
        assert!(chosen.chars().count() <= MAX_DISPLAY_NAME_LENGTH);
        assert_eq!(chosen, chosen.trim());
    }

    let address = accepted.email();
    assert!(!address.is_empty());
    assert!(address.len() <= MAX_REGISTRATION_EMAIL_LENGTH);
    assert!(!address.chars().any(char::is_whitespace));
    assert!(is_readable(address));
    let at = address.find('@').expect("an accepted address carries an @");
    assert!(at > 0, "an address may not begin with @: {address:?}");
    assert!(
        at < address.len() - 1,
        "an address may not end with @: {address:?}"
    );

    // NIST SP 800-63B §5.1.1.2: what is hashed is the normalised form, so the
    // same password typed on two keyboards verifies on both.
    let hashed = accepted.password().expose();
    assert_eq!(
        hashed,
        asterius_domain::entities::password::normalise(&password)
    );
    assert!(!hashed.is_empty());
});
