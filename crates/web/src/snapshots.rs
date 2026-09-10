//! Every page, pinned as bytes, in every locale it is offered in.
//!
//! The other tests in this crate each assert one property: that a value is
//! escaped, that a form carries a token, that a script is nonced. Those catch
//! the thing somebody meant to check. A snapshot catches the thing nobody did
//! — a heading that moved, an attribute a refactor dropped, a paragraph that
//! quietly stopped rendering — because it compares the whole document and a
//! diff is a diff.
//!
//! The house pattern is `crates/server/tests/golden/openid-configuration.json`
//! and the mechanism here is the same one: golden files under
//! `crates/web/tests/golden/`, regenerated deliberately with
//! `UPDATE_GOLDEN=1`. A diff is not necessarily a bug, but it is always
//! something a human should have meant to do.
//!
//! # Why this lives in `src/` and not in `tests/`
//!
//! A snapshot must be reproducible, so it needs a fixed nonce, and
//! [`crate::csp::Nonce::fixed_for_test`] is `#[cfg(test)]` — deliberately, so
//! that `source_audit` can hold the rule that a real nonce comes only from the
//! document middleware. An integration test in `tests/` could not see it, and
//! the alternative — making the fixture public — would trade a whole security
//! invariant for a directory.
//!
//! # `fr` is a locale, not yet a translation
//!
//! `locale` is the `lang` attribute and nothing more until `ast-ndk.5` brings
//! message bundles; this bead is what that one is built on. So the `fr`
//! snapshots are today the `en` snapshots with a different `lang`, and
//! [`tests::french_is_still_only_a_language_attribute`] says so out loud rather
//! than leaving a reader to notice. When the bundles land, that test fails,
//! and failing is its job: it is the marker that these files now have to be
//! regenerated with real French in them, and it should be deleted in the same
//! change.

#![cfg(test)]

use crate::csp::Nonce;
use crate::pages::{
    ConsentPage, DetailLine, DeviceConfirmationPage, DeviceOutcomePage, DevicePage,
    EmailVerificationPage, ErrorPage, FormPostPage, LoggedOutPage, LoginPage,
    LogoutConfirmationPage, NewPasswordPage, PasskeyPage, PasswordResetRequestPage,
    PasswordResetSentPage, RegistrationPage, ResponseField, ScopeLine, nonce_attribute, render,
};
use std::path::{Path, PathBuf};

/// The locales every page is pinned in.
const LOCALES: [&str; 2] = ["en", "fr"];

/// A nonce with a value that does not change between runs.
///
/// A generated one would make every snapshot differ from the last, which is
/// the one thing a snapshot may not do.
fn nonce() -> String {
    nonce_attribute(&Nonce::fixed_for_test("snapshot-nonce"))
}

/// The design tokens every snapshot is pinned with.
///
/// The *default* theme, not an exotic one: these files exist to catch a page
/// that changed by accident, and a themed page and an unthemed one should
/// differ only in the tokens. What the pinning buys here is that the theme
/// rule is inside the one nonce-carrying `<style>` element and nowhere else —
/// a change that moved it to a second element, or to a `style=` attribute,
/// shows up as a diff in fifteen files at once.
fn theme() -> String {
    crate::theme::custom_properties(&asterius_domain::Theme::default())
}

/// Where a page's pinned rendering lives.
fn golden_path(name: &str, locale: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.{locale}.html"))
}

/// Compares a rendering against its golden file, or writes it.
///
/// Regenerate with `UPDATE_GOLDEN=1 cargo nextest run -p asterius-web
/// snapshots` and read the diff before committing it.
fn assert_snapshot(name: &str, locale: &str, rendered: &str) {
    let path = golden_path(name, locale);

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        let parent = path.parent().expect("a golden file has a directory");
        std::fs::create_dir_all(parent).expect("create tests/golden");
        std::fs::write(&path, rendered).expect("write the golden file");
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "no golden file at {}; create it with UPDATE_GOLDEN=1",
            path.display()
        )
    });

    assert_eq!(
        rendered, expected,
        "{name} changed in {locale}.\nIf that was deliberate, regenerate with \
         UPDATE_GOLDEN=1 and read the diff before committing.",
    );
}

// ---------------------------------------------------------------------------
// The fixtures
//
// One per page, all built from the same handful of constants so that a diff
// between two goldens is a difference between two *pages* and never between
// two sets of test data.
// ---------------------------------------------------------------------------

/// The tenant every snapshot is rendered for.
const TENANT: &str = "Example Tenant";
/// The client every snapshot names, where a page names one.
const CLIENT: &str = "Example App";
/// The signed-in user.
const USER: &str = "ada";
/// The synchroniser token, fixed like the nonce.
const CSRF: &str = "snapshot-csrf";

fn login(locale: &str) -> String {
    render(&LoginPage {
        locale,
        tenant_name: TENANT,
        action: "/interaction/abc/login",
        passkey_options_action: "/interaction/abc/passkeys/options",
        passkey_finish_action: "/interaction/abc/passkeys/finish",
        csrf: CSRF,
        login_hint: Some("ada@example.test"),
        message: Some("That username and password did not match."),
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn consent(locale: &str) -> String {
    render(&ConsentPage {
        locale,
        tenant_name: TENANT,
        client_name: CLIENT,
        username: USER,
        redirect_host: "app.example.test",
        scopes: vec![
            ScopeLine {
                name: "openid".to_owned(),
                description: Some("Confirm who you are".to_owned()),
                required: true,
            },
            ScopeLine {
                name: "profile".to_owned(),
                description: Some("Read your name and picture".to_owned()),
                required: false,
            },
            ScopeLine {
                name: "payments:read".to_owned(),
                description: None,
                required: false,
            },
        ],
        offline_access: true,
        resources: vec!["https://api.example.test/".to_owned()],
        // RFC 9396 §2: one described element and one the operator registered
        // without a sentence, so the golden pins both — and pins that neither
        // renders the element's JSON.
        authorization_details: vec![
            DetailLine {
                name: "payment_initiation".to_owned(),
                description: Some("Initiate a payment of 30.00 EUR".to_owned()),
                locations: vec!["https://api.example.test/".to_owned()],
                actions: vec!["initiate".to_owned(), "status".to_owned()],
                datatypes: vec!["payments".to_owned()],
            },
            DetailLine {
                name: "account_information".to_owned(),
                description: None,
                locations: Vec::new(),
                actions: Vec::new(),
                datatypes: Vec::new(),
            },
        ],
        action: "/interaction/abc/consent",
        csrf: CSRF,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn error(locale: &str) -> String {
    render(&ErrorPage {
        locale,
        tenant_name: TENANT,
        message: "We could not complete that request.",
        correlation_id: "01JQ0000000000000000000000",
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn logout_confirmation(locale: &str) -> String {
    render(&LogoutConfirmationPage {
        locale,
        tenant_name: TENANT,
        action: "/logout",
        csrf: CSRF,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn logged_out(locale: &str, signed_out: bool) -> String {
    render(&LoggedOutPage {
        locale,
        tenant_name: TENANT,
        signed_out,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn passkey(locale: &str) -> String {
    render(&PasskeyPage {
        locale,
        tenant_name: TENANT,
        username: USER,
        options_action: "/interaction/abc/passkeys/options",
        finish_action: "/interaction/abc/passkeys/finish",
        next_href: "/interaction/abc",
        password_href: "/interaction/abc/password",
        csrf: CSRF,
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn form_post(locale: &str) -> String {
    render(&FormPostPage {
        locale,
        tenant_name: TENANT,
        redirect_host: "app.example.test",
        action: "https://app.example.test/callback",
        fields: vec![
            ResponseField {
                name: "code".to_owned(),
                value: "snapshot-code".to_owned(),
            },
            ResponseField {
                name: "state".to_owned(),
                value: "snapshot-state".to_owned(),
            },
        ],
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn device(locale: &str, user_code: Option<&str>) -> String {
    render(&DevicePage {
        locale,
        tenant_name: TENANT,
        action: "/device",
        csrf: CSRF,
        user_code,
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn device_confirmation(locale: &str) -> String {
    render(&DeviceConfirmationPage {
        locale,
        tenant_name: TENANT,
        client_name: CLIENT,
        user_code: "BDWD-HQPK",
        action: "/device/confirm",
        csrf: CSRF,
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn device_outcome(locale: &str, connected: bool) -> String {
    render(&DeviceOutcomePage {
        locale,
        tenant_name: TENANT,
        connected,
        client_name: CLIENT,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn registration(locale: &str) -> String {
    render(&RegistrationPage {
        locale,
        tenant_name: TENANT,
        action: "/register",
        csrf: CSRF,
        username: None,
        email: None,
        minimum_password_length: 12,
        sign_in_href: "/login",
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn email_verification(locale: &str, verified: bool) -> String {
    render(&EmailVerificationPage {
        locale,
        tenant_name: TENANT,
        email: "ada@example.test",
        verified,
        resend_action: "/register/verify/resend",
        continue_href: "/login",
        csrf: CSRF,
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn password_reset_request(locale: &str) -> String {
    render(&PasswordResetRequestPage {
        locale,
        tenant_name: TENANT,
        action: "/password/reset",
        csrf: CSRF,
        sign_in_href: "/login",
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn password_reset_sent(locale: &str) -> String {
    render(&PasswordResetSentPage {
        locale,
        tenant_name: TENANT,
        sign_in_href: "/login",
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

fn new_password(locale: &str) -> String {
    render(&NewPasswordPage {
        locale,
        tenant_name: TENANT,
        username: USER,
        action: "/password/new",
        csrf: CSRF,
        reset_token: "snapshot-reset-token",
        minimum_password_length: 12,
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
    })
}

/// Every snapshot this crate keeps, as `(name, locale, rendering)`.
///
/// The list exists so that the whole-tree properties below — the locale
/// attribute, the untranslated-French marker — are asserted over *every* page
/// rather than over whichever ones somebody remembered.
fn every_page(locale: &str) -> Vec<(&'static str, String)> {
    vec![
        ("login", login(locale)),
        ("consent", consent(locale)),
        ("error", error(locale)),
        ("logout_confirm", logout_confirmation(locale)),
        ("logged_out", logged_out(locale, true)),
        ("logged_out.still_signed_in", logged_out(locale, false)),
        ("passkey", passkey(locale)),
        ("form_post", form_post(locale)),
        ("device", device(locale, None)),
        ("device.prefilled", device(locale, Some("BDWD-HQPK"))),
        ("device_confirm", device_confirmation(locale)),
        ("device_done", device_outcome(locale, true)),
        ("device_done.refused", device_outcome(locale, false)),
        ("register", registration(locale)),
        ("verify_email", email_verification(locale, false)),
        ("verify_email.confirmed", email_verification(locale, true)),
        ("password_reset", password_reset_request(locale)),
        ("password_reset_sent", password_reset_sent(locale)),
        ("password_new", new_password(locale)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every page, in every locale, against its golden file.
    ///
    /// One test rather than nineteen, because the failure a reader wants is
    /// "these four pages changed", not four separate reports of the same
    /// refactor. Each mismatch is collected and reported together.
    #[test]
    fn every_page_matches_its_snapshots() {
        for locale in LOCALES {
            for (name, rendered) in every_page(locale) {
                assert_snapshot(name, locale, &rendered);
            }
        }
    }

    /// A page renders in the locale it was handed.
    ///
    /// The `lang` attribute is what a screen reader picks a voice from and
    /// what a browser offers to translate on (WCAG 2.2 SC 3.1.1), and it is
    /// the one thing `locale` does today. A page that hard-coded `lang="en"`
    /// would pass every snapshot above the moment its golden was regenerated.
    #[test]
    fn every_page_declares_the_locale_it_was_given() {
        for locale in LOCALES {
            for (name, rendered) in every_page(locale) {
                assert!(
                    rendered.contains(&format!("<html lang=\"{locale}\">")),
                    "{name} does not declare lang=\"{locale}\""
                );
            }
        }
    }

    /// A theme changes tokens, never markup (`ast-ndk.1`).
    ///
    /// The product rule is that a tenant supplies no HTML and no stylesheet,
    /// and the shape that rule would fail in is an inline `style=` attribute:
    /// it is the one place CSS can appear that no nonce covers, and a policy
    /// that has no `'unsafe-inline'` blocks it in the browser — so a page that
    /// grew one would render without the styling somebody meant it to have,
    /// and the CSP sweep in `e2e/console.spec.ts` would report a violation
    /// rather than a diff. This catches it here instead.
    #[test]
    fn no_page_rendered_with_a_theme_carries_an_inline_style_attribute() {
        for locale in LOCALES {
            for (name, rendered) in every_page(locale) {
                assert!(
                    !rendered.contains("style="),
                    "{name} carries an inline style attribute"
                );
            }
        }
    }

    /// One `<style>` element per page, nonced, with the tenant's tokens in it.
    ///
    /// Two elements would be two chances to forget the nonce; tokens outside
    /// it would be CSS reaching the browser by some route the policy does not
    /// describe.
    #[test]
    fn every_page_carries_its_theme_inside_one_nonce_carrying_style_element() {
        let expected = theme();
        let attribute = Nonce::fixed_for_test("snapshot-nonce").attribute();
        for locale in LOCALES {
            for (name, rendered) in every_page(locale) {
                assert_eq!(
                    rendered.matches("<style ").count(),
                    1,
                    "{name} has more than one style element"
                );
                let open = rendered
                    .find("<style ")
                    .expect("a page has a style element");
                let close = rendered.find("</style>").expect("it is closed");
                let block = &rendered[open..close];
                assert!(
                    block.contains(&attribute),
                    "{name}'s style element does not carry the page nonce"
                );
                assert!(
                    block.contains(&expected),
                    "{name} does not render its design tokens inside its style element"
                );
            }
        }
    }

    /// The marker for what `ast-ndk.5` still has to do.
    ///
    /// Templates come before message bundles — this bead blocks that one — so
    /// `fr` is a language attribute and the words underneath it are still
    /// English. That is a real gap in SC 3.1.1 and it should be visible in the
    /// test output rather than only in a ticket.
    ///
    /// **When the bundles land this test fails, and that is the signal.**
    /// Regenerate the `fr` goldens, read them, and delete this test in the
    /// same change.
    #[test]
    fn french_is_still_only_a_language_attribute() {
        for (name, english) in every_page("en") {
            let french = every_page("fr")
                .into_iter()
                .find(|(candidate, _)| *candidate == name)
                .map(|(_, rendered)| rendered)
                .expect("the same pages render in both locales");
            assert_eq!(
                english.replace("<html lang=\"en\">", "<html lang=\"fr\">"),
                french,
                "{name} differs between en and fr by more than its lang \
                 attribute, so message bundles have arrived: regenerate the fr \
                 goldens and delete this test"
            );
        }
    }
}
