//! What a stranger may write into `users`: the sign-up form, and the policy it
//! has to pass (OpenID Connect Prompt Create 1.0 §3).
//!
//! # Why this is a type and not four checks in a handler
//!
//! Everything on this form arrives from somebody who has proved nothing. The
//! username becomes a unique index key and a value people read off a screen;
//! the display name becomes the `preferred_username` claim, which every relying
//! party renders; the address becomes the destination of mail this server
//! sends. A handler that validated three of them and forgot the fourth would be
//! a handler nobody could tell was wrong by reading it, so the whole form is one
//! parser with one output — [`AcceptedRegistration`] — and there is no way to
//! build that output without going through [`AcceptedRegistration::accept`].
//!
//! # What is checked, and what is deliberately not
//!
//! * The **username** is the rule `asterius_admin_api::users::accept_username`
//!   applies to an administrator's input, restated here in the domain so that
//!   the two doors into `users` cannot disagree about what a username is:
//!   non-empty after trimming, at most [`MAX_REGISTRATION_USERNAME_LENGTH`] characters, no
//!   control characters.
//! * The **display name** is the same shape, shorter, and *optional*: a person
//!   who does not care what they are called should not have to invent
//!   something, and an account with no display name simply releases no
//!   `preferred_username`. It is explicitly **not** unique and must never be
//!   made so — OIDC Core §5.1 says `preferred_username` is not stable and RPs
//!   "MUST NOT rely upon this value being unique".
//! * The **address** is checked shallowly, for the reason the admin API gives:
//!   the only proof an address belongs to somebody is a message they answered,
//!   which is `email_verified` and not a regular expression. What is refused is
//!   what a wrong answer would cost — an empty value, one past RFC 5321
//!   §4.5.3.1.3's 320 octets, whitespace or control characters, no `@`.
//! * The **password** is [`AcceptedPassword::accept_locally`], which is NIST SP
//!   800-63B §5.1.1.2's normalisation, the length floor and the deny list. No
//!   composition rules; see [`crate::entities::password`].
//!
//! Bidirectional formatting characters are refused in both names. They are not
//! control characters, they survive HTML escaping, and they reorder what a
//! human reads — which on a consent screen is the difference between "Sign in
//! as ada" and a name that renders as somebody else's.

use crate::entities::password::{AcceptedPassword, PasswordError};

/// The longest username this form accepts.
///
/// The same number `asterius_admin_api::users::MAX_USERNAME_LEN` uses, because
/// it is the same column and the same login form; it is about what a person can
/// type, not about storage.
pub const MAX_REGISTRATION_USERNAME_LENGTH: usize = 320;

/// The longest display name this form accepts.
///
/// Shorter than a username on purpose: it is rendered inside a sentence on the
/// consent screen ("Signed in as …"), and a 320-character name there is a
/// layout attack rather than a preference.
pub const MAX_DISPLAY_NAME_LENGTH: usize = 64;

/// The longest address, which RFC 5321 §4.5.3.1.3 fixes at 320 octets.
pub const MAX_REGISTRATION_EMAIL_LENGTH: usize = 320;

/// Why a sign-up was refused.
///
/// One variant per field and per rule, because the page names the field that
/// has to change: WCAG 2.2 SC 3.3.1 asks for the item in error to be
/// identified, and "something was wrong" is not that. None of these leaks
/// whether an account exists — that answer is not made here at all, it is the
/// store's unique index, and the caller renders it as its own message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrationError {
    /// Empty after trimming.
    #[error("enter a username")]
    UsernameMissing,
    /// Longer than [`MAX_REGISTRATION_USERNAME_LENGTH`].
    #[error("a username must be at most {MAX_REGISTRATION_USERNAME_LENGTH} characters")]
    UsernameTooLong,
    /// Carries a control or bidirectional formatting character.
    #[error("a username must not carry control or bidirectional formatting characters")]
    UsernameUnreadable,
    /// Longer than [`MAX_DISPLAY_NAME_LENGTH`].
    #[error("a display name must be at most {MAX_DISPLAY_NAME_LENGTH} characters")]
    DisplayNameTooLong,
    /// Carries a control or bidirectional formatting character.
    #[error("a display name must not carry control or bidirectional formatting characters")]
    DisplayNameUnreadable,
    /// Empty after trimming.
    #[error("enter an email address")]
    EmailMissing,
    /// Longer than [`MAX_REGISTRATION_EMAIL_LENGTH`], or shaped like nothing that could be
    /// delivered to.
    #[error("enter an email address this server could send to")]
    EmailUnusable,
    /// Whatever [`AcceptedPassword::accept_locally`] refused.
    #[error(transparent)]
    Password(#[from] PasswordError),
}

/// A sign-up that has passed policy, ready to become a row.
///
/// The fields are the *normalised* forms — trimmed names, an NFKC password —
/// because those are what gets stored and hashed, and a caller holding the raw
/// input beside this could write one and check the other.
#[derive(Debug)]
pub struct AcceptedRegistration {
    username: String,
    display_name: Option<String>,
    email: String,
    password: AcceptedPassword,
}

impl AcceptedRegistration {
    /// Applies the whole form's policy.
    ///
    /// The single entry point, and the reason there is no public constructor:
    /// an [`AcceptedRegistration`] in a handler's hands has been through every
    /// rule above, so the handler has none left to remember.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`] naming the first field that failed, in the order
    /// the form presents them — which is the order the page has to point at.
    // fuzz-target: registration_form
    pub fn accept(
        username: &str,
        display_name: Option<&str>,
        email: &str,
        password: &str,
    ) -> Result<Self, RegistrationError> {
        let username = accept_name(
            username,
            MAX_REGISTRATION_USERNAME_LENGTH,
            RegistrationError::UsernameMissing,
            RegistrationError::UsernameTooLong,
            RegistrationError::UsernameUnreadable,
        )?;

        // An absent field and a field somebody left blank are the same fact:
        // no display name. A form posted without the input at all — an older
        // page, a client that composed the body itself — must not be a
        // different outcome from a form posted with it empty.
        let display_name = match display_name.map(str::trim).filter(|v| !v.is_empty()) {
            None => None,
            Some(raw) => Some(accept_name(
                raw,
                MAX_DISPLAY_NAME_LENGTH,
                RegistrationError::DisplayNameTooLong,
                RegistrationError::DisplayNameTooLong,
                RegistrationError::DisplayNameUnreadable,
            )?),
        };

        let email = accept_email(email)?;
        let password = AcceptedPassword::accept_locally(password)?;

        Ok(Self {
            username,
            display_name,
            email,
            password,
        })
    }

    /// The login identifier, trimmed.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The `preferred_username` to store, when the person gave one.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// The address to confirm.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// The password, normalised and ready to hash.
    #[must_use]
    pub const fn password(&self) -> &AcceptedPassword {
        &self.password
    }

    /// Takes the password out, leaving the rest.
    #[must_use]
    pub fn into_password(self) -> AcceptedPassword {
        self.password
    }
}

/// Whether a character would reorder or hide what a person reads.
///
/// Control characters and the Unicode bidirectional formatting set (U+061C,
/// U+200E–U+200F, U+202A–U+202E, U+2066–U+2069). Escaping does not help against
/// these: they are legal text, they survive every encoder, and they are how a
/// name renders as a different name.
fn is_unreadable(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// The shared rule for the two names on the form.
fn accept_name(
    raw: &str,
    limit: usize,
    missing: RegistrationError,
    too_long: RegistrationError,
    unreadable: RegistrationError,
) -> Result<String, RegistrationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(missing);
    }
    // Counted in characters rather than bytes, like the password rule: a limit
    // in bytes is a limit on the user's alphabet.
    if trimmed.chars().count() > limit {
        return Err(too_long);
    }
    if trimmed.chars().any(is_unreadable) {
        return Err(unreadable);
    }
    Ok(trimmed.to_owned())
}

/// The shallow address check. See the module documentation for why it is
/// shallow.
fn accept_email(raw: &str) -> Result<String, RegistrationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(RegistrationError::EmailMissing);
    }
    if trimmed.len() > MAX_REGISTRATION_EMAIL_LENGTH
        || trimmed
            .chars()
            .any(|c| is_unreadable(c) || c.is_whitespace())
        || !trimmed.contains('@')
        || trimmed.starts_with('@')
        || trimmed.ends_with('@')
    {
        return Err(RegistrationError::EmailUnusable);
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A password long enough for policy and not on the deny list.
    const GOOD_PASSWORD: &str = "correct horse battery staple";

    fn accept(
        username: &str,
        display_name: Option<&str>,
        email: &str,
    ) -> Result<AcceptedRegistration, RegistrationError> {
        AcceptedRegistration::accept(username, display_name, email, GOOD_PASSWORD)
    }

    #[test]
    fn a_complete_form_is_accepted_and_trimmed() {
        let accepted = accept("  ada ", Some(" Ada L. "), " ada@example.test ")
            .expect("a well-formed sign-up");

        assert_eq!(accepted.username(), "ada");
        assert_eq!(accepted.display_name(), Some("Ada L."));
        assert_eq!(accepted.email(), "ada@example.test");
    }

    #[test]
    fn a_blank_display_name_is_the_same_as_none() {
        let blank = accept("ada", Some("   "), "ada@example.test").expect("a sign-up");

        assert_eq!(blank.display_name(), None);
    }

    /// OIDC Core §5.1: `preferred_username` is a display preference, so two
    /// people may choose the same one. Uniqueness belongs to the username.
    #[test]
    fn two_registrations_may_choose_the_same_display_name() {
        let first = accept("ada", Some("Ada"), "ada@example.test").expect("a sign-up");
        let second = accept("grace", Some("Ada"), "grace@example.test").expect("a sign-up");

        assert_eq!(first.display_name(), second.display_name());
        assert_ne!(first.username(), second.username());
    }

    #[test]
    fn a_username_that_is_only_whitespace_is_refused() {
        assert_eq!(
            accept("  ", None, "ada@example.test").expect_err("a refusal"),
            RegistrationError::UsernameMissing
        );
    }

    #[test]
    fn a_username_past_the_limit_is_refused() {
        let long = "a".repeat(MAX_REGISTRATION_USERNAME_LENGTH + 1);

        assert_eq!(
            accept(&long, None, "ada@example.test").expect_err("a refusal"),
            RegistrationError::UsernameTooLong
        );
    }

    /// A right-to-left override in a name renders as a different name on the
    /// consent screen, and escaping does not touch it.
    #[test]
    fn a_name_carrying_a_bidirectional_override_is_refused() {
        assert_eq!(
            accept("ada\u{202E}bob", None, "ada@example.test").expect_err("a refusal"),
            RegistrationError::UsernameUnreadable
        );
        assert_eq!(
            accept("ada", Some("Ada\u{202E}bob"), "ada@example.test").expect_err("a refusal"),
            RegistrationError::DisplayNameUnreadable
        );
    }

    #[test]
    fn a_display_name_past_the_limit_is_refused() {
        let long = "n".repeat(MAX_DISPLAY_NAME_LENGTH + 1);

        assert_eq!(
            accept("ada", Some(&long), "ada@example.test").expect_err("a refusal"),
            RegistrationError::DisplayNameTooLong
        );
    }

    #[test]
    fn an_address_without_an_at_sign_is_refused() {
        assert_eq!(
            accept("ada", None, "ada.example.test").expect_err("a refusal"),
            RegistrationError::EmailUnusable
        );
    }

    #[test]
    fn a_missing_address_is_refused_before_the_password_is_looked_at() {
        assert_eq!(
            AcceptedRegistration::accept("ada", None, "", "short").expect_err("a refusal"),
            RegistrationError::EmailMissing
        );
    }

    /// The deny list is the domain's, not a second copy: a sign-up form is
    /// exactly where `changeme` gets typed.
    #[test]
    fn a_common_password_is_refused() {
        assert_eq!(
            AcceptedRegistration::accept("ada", None, "ada@example.test", "administrator")
                .expect_err("a refusal"),
            RegistrationError::Password(PasswordError::TooCommon)
        );
    }

    #[test]
    fn a_short_password_is_refused() {
        assert_eq!(
            AcceptedRegistration::accept("ada", None, "ada@example.test", "short")
                .expect_err("a refusal"),
            RegistrationError::Password(PasswordError::TooShort)
        );
    }
}
