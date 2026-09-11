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
//! # `fr` is a translation now, and only on some pages
//!
//! `ast-ndk.5` brought the message catalogue, so the `fr` goldens of the
//! authorization journey — login and step-up, consent, the error page, the two
//! logout pages — are French rather than English under a French `lang`
//! attribute. The rest of the tree (the device pages, registration, email
//! verification, the password-reset pair, the passkey enrolment page and the
//! form-post page) still holds its strings as English literals in the
//! templates.
//!
//! That gap is asserted rather than described: [`TRANSLATED`] lists the pages
//! whose two goldens must differ by more than a `lang` attribute, and
//! [`tests::the_untranslated_pages_are_the_ones_still_listed_as_untranslated`]
//! fails the day a page moves in either direction. Moving a page is therefore
//! adding its strings to `crate::i18n` and deleting a line from that list.

#![cfg(test)]

use crate::csp::Nonce;
use crate::i18n::Catalog;
use crate::pages::{
    ApprovalLine, ApprovalsPage, ConsentPage, DetailLine, DeviceConfirmationPage,
    DeviceOutcomePage, DevicePage, EmailVerificationPage, ErrorPage, FormPostPage, LoggedOutPage,
    LoginPage, LogoutConfirmationPage, NewPasswordPage, PasskeyPage, PasswordResetRequestPage,
    PasswordResetSentPage, RegistrationPage, ResponseField, ScopeLine, nonce_attribute, render,
};
use asterius_domain::Locale;
use std::path::{Path, PathBuf};

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

/// The chrome every snapshot is pinned with.
///
/// A fixed font URL rather than [`crate::brand::font_path`], for the same
/// reason the nonce is fixed: the real path carries a hash of the embedded
/// face, so updating the font would rewrite all thirty of these files in a way
/// that says nothing about the pages. The real path is pinned where it is
/// computed, by `brand::tests::the_font_path_names_the_bytes_it_serves`, and
/// the prefix it is served under by the tenancy tests.
///
/// The default mark, for the reason [`theme`] uses the default theme: these
/// files exist to catch a page that changed by accident.
fn brand() -> crate::brand::Brand<'static> {
    crate::brand::Brand::new("/assets/font/geist-snapshot.woff2")
}

/// Where a page's pinned rendering lives.
fn golden_path(name: &str, locale: Locale) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.{}.html", locale.as_tag()))
}

/// Compares a rendering against its golden file, or writes it.
///
/// Regenerate with `UPDATE_GOLDEN=1 cargo nextest run -p asterius-web
/// snapshots` and read the diff before committing it.
fn assert_snapshot(name: &str, locale: Locale, rendered: &str) {
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

fn login(text: &Catalog) -> String {
    render(&LoginPage {
        text,
        tenant_name: TENANT,
        action: "/interaction/abc/login",
        passkey_options_action: "/interaction/abc/passkeys/options",
        passkey_finish_action: "/interaction/abc/passkeys/finish",
        csrf: CSRF,
        login_hint: Some("ada@example.test"),
        message: Some("That username and password did not match."),
        recovery_href: Some("/recovery"),
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn consent(text: &Catalog) -> String {
    render(&ConsentPage {
        text,
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
        brand: brand(),
    })
}

fn error(text: &Catalog) -> String {
    render(&ErrorPage {
        text,
        tenant_name: TENANT,
        message: "We could not complete that request.",
        correlation_id: "01JQ0000000000000000000000",
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn logout_confirmation(text: &Catalog) -> String {
    render(&LogoutConfirmationPage {
        text,
        tenant_name: TENANT,
        action: "/logout",
        csrf: CSRF,
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn logged_out(text: &Catalog, signed_out: bool) -> String {
    render(&LoggedOutPage {
        text,
        tenant_name: TENANT,
        signed_out,
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn passkey(text: &Catalog) -> String {
    render(&PasskeyPage {
        text,
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
        brand: brand(),
    })
}

fn form_post(text: &Catalog) -> String {
    render(&FormPostPage {
        text,
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
        brand: brand(),
    })
}

fn device(text: &Catalog, user_code: Option<&str>) -> String {
    render(&DevicePage {
        text,
        tenant_name: TENANT,
        action: "/device",
        csrf: CSRF,
        user_code,
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn device_confirmation(text: &Catalog) -> String {
    render(&DeviceConfirmationPage {
        text,
        tenant_name: TENANT,
        client_name: CLIENT,
        user_code: "BDWD-HQPK",
        scopes: vec![ScopeLine {
            name: "payments".to_owned(),
            description: Some("read your payment history".to_owned()),
            required: true,
        }],
        authorization_details: vec![DetailLine {
            name: "payment_initiation".to_owned(),
            description: Some("move money on your behalf".to_owned()),
            locations: vec!["https://api.example/payments".to_owned()],
            actions: vec!["initiate".to_owned()],
            datatypes: vec!["account".to_owned()],
        }],
        action: "/device/confirm",
        csrf: CSRF,
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn device_outcome(text: &Catalog, connected: bool) -> String {
    render(&DeviceOutcomePage {
        text,
        tenant_name: TENANT,
        connected,
        client_name: CLIENT,
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn approvals(text: &Catalog, waiting: bool) -> String {
    let approvals = if waiting {
        vec![ApprovalLine {
            reference: "0f9d".repeat(16),
            client_name: CLIENT.to_owned(),
            binding_message: Some("W4SCT".to_owned()),
            scopes: vec![ScopeLine {
                name: "payments".to_owned(),
                description: Some("read your payment history".to_owned()),
                required: true,
            }],
            authorization_details: vec![DetailLine {
                name: "payment_initiation".to_owned(),
                description: Some("move money on your behalf".to_owned()),
                locations: vec!["https://api.example/payments".to_owned()],
                actions: vec!["initiate".to_owned()],
                datatypes: vec!["account".to_owned()],
            }],
            expires_in: "4 min 12 s".to_owned(),
            expires_at: "2026-01-01T00:04:12Z".to_owned(),
        }]
    } else {
        Vec::new()
    };
    render(&ApprovalsPage {
        text,
        tenant_name: TENANT,
        approvals,
        action: "/account/approvals/decide",
        device_action: "/device",
        sign_in_href: "/account/approvals?sign_in=1",
        csrf: CSRF,
        device_csrf: "snapshot-device-csrf",
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn registration(text: &Catalog) -> String {
    render(&RegistrationPage {
        text,
        tenant_name: TENANT,
        action: "/register",
        csrf: CSRF,
        username: None,
        email: None,
        display_name: None,
        minimum_password_length: 12,
        maximum_display_name_length: 64,
        sign_in_href: "/login",
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn email_verification(text: &Catalog, verified: bool) -> String {
    render(&EmailVerificationPage {
        text,
        tenant_name: TENANT,
        email: "ada@example.test",
        verified,
        resend_action: "/register/verify/resend",
        continue_href: "/login",
        csrf: CSRF,
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn password_reset_request(text: &Catalog) -> String {
    render(&PasswordResetRequestPage {
        text,
        tenant_name: TENANT,
        action: "/password/reset",
        csrf: CSRF,
        sign_in_href: "/login",
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn password_reset_sent(text: &Catalog) -> String {
    render(&PasswordResetSentPage {
        text,
        tenant_name: TENANT,
        sign_in_href: "/login",
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

fn new_password(text: &Catalog) -> String {
    render(&NewPasswordPage {
        text,
        tenant_name: TENANT,
        username: USER,
        action: "/password/new",
        csrf: CSRF,
        reset_token: "snapshot-reset-token",
        minimum_password_length: 12,
        message: None,
        nonce_attribute: nonce(),
        theme_css: &theme(),
        brand: brand(),
    })
}

/// The pages whose words come from `crate::i18n` rather than from the template.
///
/// `ast-ndk.5` moved the authorization journey. Everything else in
/// [`every_page`] is still English under whatever `lang` it is handed; see this
/// module's documentation.
const TRANSLATED: [&str; 8] = [
    "login",
    "consent",
    "error",
    "logout_confirm",
    "logged_out",
    "logged_out.still_signed_in",
    // `ast-lh3.6`'s inbox is in the catalogue from its first day: it is the
    // page most likely to be read in a hurry on somebody's own phone.
    "approvals",
    "approvals.empty",
];

/// Every snapshot this crate keeps, as `(name, locale, rendering)`.
///
/// The list exists so that the whole-tree properties below — the locale
/// attribute, the untranslated-French marker — are asserted over *every* page
/// rather than over whichever ones somebody remembered.
fn every_page(locale: Locale) -> Vec<(&'static str, String)> {
    let text = &Catalog::new(locale);
    vec![
        ("login", login(text)),
        ("consent", consent(text)),
        ("error", error(text)),
        ("logout_confirm", logout_confirmation(text)),
        ("logged_out", logged_out(text, true)),
        ("logged_out.still_signed_in", logged_out(text, false)),
        ("passkey", passkey(text)),
        ("form_post", form_post(text)),
        ("device", device(text, None)),
        ("device.prefilled", device(text, Some("BDWD-HQPK"))),
        ("device_confirm", device_confirmation(text)),
        ("device_done", device_outcome(text, true)),
        ("device_done.refused", device_outcome(text, false)),
        ("approvals", approvals(text, true)),
        ("approvals.empty", approvals(text, false)),
        ("register", registration(text)),
        ("verify_email", email_verification(text, false)),
        ("verify_email.confirmed", email_verification(text, true)),
        ("password_reset", password_reset_request(text)),
        ("password_reset_sent", password_reset_sent(text)),
        ("password_new", new_password(text)),
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
        for locale in Locale::SUPPORTED {
            for (name, rendered) in every_page(locale) {
                assert_snapshot(name, locale, &rendered);
            }
        }
    }

    /// A page renders in the locale it was handed.
    ///
    /// The `lang` attribute is what a screen reader picks a voice from and
    /// what a browser offers to translate on (WCAG 2.2 SC 3.1.1), and it is
    /// the first thing a catalogue has to get right. A page that hard-coded
    /// `lang="en"` would pass every snapshot above the moment its golden was
    /// regenerated.
    #[test]
    fn every_page_declares_the_locale_it_was_given() {
        for locale in Locale::SUPPORTED {
            for (name, rendered) in every_page(locale) {
                assert!(
                    rendered.contains(&format!("<html lang=\"{}\">", locale.as_tag())),
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
        for locale in Locale::SUPPORTED {
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
        for locale in Locale::SUPPORTED {
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

    /// Which pages have been through the catalogue, and which have not.
    ///
    /// The pages of the authorization journey are the ones `ast-ndk.5` moved.
    /// A page not named here renders English under `lang="fr"`, which is a real
    /// SC 3.1.1 defect and is why the list is an assertion rather than a
    /// comment.
    #[test]
    fn the_untranslated_pages_are_the_ones_still_listed_as_untranslated() {
        // Arrange
        let english = every_page(Locale::English);
        let french = every_page(Locale::French);

        // Act & assert
        for ((name, english), (_, french)) in english.into_iter().zip(french) {
            let only_the_lang_attribute =
                english.replace("<html lang=\"en\">", "<html lang=\"fr\">") == french;
            let translated = TRANSLATED.contains(&name);
            assert_eq!(
                translated,
                !only_the_lang_attribute,
                "{name} is {} in the TRANSLATED list, and its two goldens say otherwise: either \
                 its strings moved into `crate::i18n` and the list needs updating, or a message \
                 key was dropped from its template",
                if translated { "" } else { "not" }
            );
        }
    }
}
