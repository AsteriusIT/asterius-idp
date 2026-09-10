//! `Theme::parse` — a tenant's design tokens, as they arrive from an
//! administrator's console or a `jsonb` column (`ast-ndk.1`).
//!
//! This is the parser between "JSON an authenticated tenant administrator
//! wrote" and "typed tokens the sign-in page renders as CSS". The
//! administrator is not the adversary the OIDC parsers face, but the document
//! travels: it is stored, read back on every page render, and printed into a
//! `<style>` element that also carries the page's CSP nonce. A value that got
//! through here and reached that element unescaped would be cross-site
//! scripting on the password page, which is why the properties below are about
//! what the *output* can contain as much as about not panicking.
//!
//! * **Parsing is total.** No document panics. A panic is a 500 on the tenant
//!   settings screen, and — because the same parser reads the stored column —
//!   a stored document that panics is a tenant whose sign-in page never
//!   renders again.
//! * **Parsing is deterministic.** Two runs over the same bytes agree.
//! * **What is accepted round-trips.** A theme written out and read back is the
//!   same theme, so saving what was loaded cannot drift a tenant's palette.
//! * **Every accepted theme clears WCAG AA.** The contrast check is the one
//!   rule with no second enforcement anywhere downstream: if a document gets
//!   past it, unreadable text ships.
//! * **Every accepted theme renders to CSS that cannot leave its element.**
//!   The rendering is the one in `asterius_web::theme`, and the assertion is
//!   the real one: no `<`, `>`, `&`, quote, `@import` or `url(` in the output,
//!   whatever the document said.
//! * **Every refusal names a member of this server's own schema.** The path is
//!   shown to whoever submitted the document, so it must never be a reflection
//!   of what they typed.
#![no_main]

use asterius_domain::entities::theme::{Colour, MIN_CONTRAST_RATIO, Theme};
use asterius_web::theme::custom_properties;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let first = Theme::parse(text);
    let second = Theme::parse(text);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "parsing a theme is not deterministic"
    );

    let theme = match first {
        Ok(theme) => theme,
        Err(error) => {
            // The path is a JSON pointer into *our* schema. Anything else
            // would mean the refusal echoed the document back.
            let path = error.path();
            assert!(path.starts_with('/'), "a refusal path is a JSON pointer");
            assert!(
                path.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte == b'/'
                    || byte == b'_'
                    || byte.is_ascii_digit()),
                "a refusal path carried something that was not a schema member: {path}"
            );
            return;
        }
    };

    // What this server wrote, this server reads, unchanged.
    let round_tripped = Theme::from_json(&theme.to_json()).expect("what was written parses");
    assert_eq!(round_tripped, theme, "a theme did not round-trip");

    // WCAG 2.2 SC 1.4.3 on every pair the model checks. Re-derived here from
    // the public accessors rather than by calling the private check, so the
    // oracle and the code under test do not share a mistake.
    let palette = theme.palette();
    for (foreground, background) in [
        (palette.text(), palette.background()),
        (palette.muted_text(), palette.background()),
        (palette.accent_text(), palette.accent()),
        (palette.danger(), palette.background()),
    ] {
        let ratio = Colour::contrast_ratio(foreground, background);
        assert!(
            ratio >= MIN_CONTRAST_RATIO,
            "an accepted theme has a pair at {ratio}:1"
        );
    }

    // The rendering that ends up inside `<style nonce=…>`.
    let css = custom_properties(&theme);
    for forbidden in ['<', '>', '&', '"', '\'', '(', '@', '\\'] {
        assert!(
            !css.contains(forbidden),
            "a rendered theme carried {forbidden:?}: {css}"
        );
    }
    assert!(css.starts_with(":root{"), "{css}");
    assert!(css.ends_with('}'), "{css}");
});
