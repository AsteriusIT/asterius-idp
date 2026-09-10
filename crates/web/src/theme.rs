//! A tenant's design tokens, as the CSS custom properties a page carries.
//!
//! [`asterius_domain::Theme`] is the model — six colours, a font stack, two
//! scale values, all of them validated and bounded. This module is the only
//! place that turns one into CSS, and it produces exactly one thing: a
//! `:root { … }` rule of custom property declarations, appended to the single
//! nonce-carrying `<style>` element `base.html` already had.
//!
//! # Why there is no escaping here, and why that is the safe answer
//!
//! The obvious way to interpolate generated CSS into a template is `|safe`,
//! and `crate::source_audit` fails the build if a second `|safe` appears —
//! deliberately, because `|safe` is what an XSS looks like in an askama tree.
//!
//! So the template renders `{{ theme_css }}` *escaped*, like a user's name,
//! and this module guarantees the escaping is a no-op: every byte it can emit
//! is in [`SAFE_CHARACTERS`], which excludes `<`, `>`, `&`, `"` and `'` — the
//! five characters askama's HTML escaper rewrites. That holds because nothing
//! a tenant *typed* reaches this function: a colour is printed from three
//! bytes, a font stack is one of three literals in this repository, a scale
//! value is an integer.
//!
//! The property this buys is stronger than `|safe` with a careful serialiser.
//! If a future token ever did carry tenant text and this module forgot to
//! reject it, the output would be escaped rather than injected: a broken
//! declaration instead of `</style><script>`. `a_theme_renders_the_same_bytes_
//! escaped_or_not` and `no_rendered_theme_can_leave_the_style_element` pin
//! both halves.
//!
//! # Order matters: the tenant's rule comes last
//!
//! `style.css` declares the defaults in `:root` and a dark variant in a
//! `prefers-color-scheme` media query. CSS resolves same-specificity
//! declarations by document order, so the tenant's rule is appended *after*
//! both and wins in either scheme. See the note in
//! [`asterius_domain::entities::theme`] on what that costs.

use asterius_domain::Theme;

/// Every character a rendered theme may contain.
///
/// Notably absent: `<`, `>`, `&`, `"` and `'`. Those are what
/// `askama::filters::escape` rewrites, and their absence is what makes the
/// escaped and unescaped renderings the same bytes.
pub const SAFE_CHARACTERS: &str = "abcdefghijklmnopqrstuvwxyz\
                                   ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                   0123456789#-,;:{}. ";

/// The custom properties of one theme, as a single CSS rule.
///
/// Appended to the `<style>` block of every page; see the module docs for why
/// it is last and why it is not marked safe.
#[must_use]
pub fn custom_properties(theme: &Theme) -> String {
    let mut css = String::from(":root{");
    for (property, value) in declarations(theme) {
        css.push_str(&property);
        css.push(':');
        css.push_str(&value);
        css.push(';');
    }
    css.push('}');
    css
}

/// The declarations, in the order they are printed.
///
/// Split out so that a test can assert a property of each one rather than of a
/// string it would have to re-parse.
#[must_use]
pub fn declarations(theme: &Theme) -> Vec<(String, String)> {
    let palette = theme.palette();
    vec![
        // The four `style.css` has always had, kept under their old names so
        // that a tenant that sets no theme and a tenant that sets the default
        // one render the same page.
        ("--bg".to_owned(), palette.background().to_css()),
        ("--fg".to_owned(), palette.text().to_css()),
        ("--muted".to_owned(), palette.muted_text().to_css()),
        // The border colour is derived rather than chosen: it is the muted
        // text colour, which is already contrast-checked against the
        // background, and one fewer token is one fewer thing an administrator
        // can set to the background colour and make the form disappear.
        ("--line".to_owned(), palette.muted_text().to_css()),
        ("--accent".to_owned(), palette.accent().to_css()),
        ("--accent-fg".to_owned(), palette.accent_text().to_css()),
        ("--danger".to_owned(), palette.danger().to_css()),
        ("--radius".to_owned(), format!("{}px", theme.radius_px())),
        ("--space".to_owned(), format!("{}px", theme.spacing_px())),
        ("--font".to_owned(), theme.font().css().to_owned()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A theme whose every free-text member is an attempt to leave the
    /// `<style>` element.
    fn hostile_theme() -> Theme {
        // Every member the schema accepts is typed, so the hostile input has
        // to be refused at the door: this documents that there is no way to
        // *build* a theme carrying markup, which is the property the renderer
        // depends on.
        let document = json!({
            "palette": {
                "background": "#ffffff",
                "text": "#111111",
                "muted_text": "#555555",
                "accent": "#2f6fdb",
                "accent_text": "#ffffff",
                "danger": "#c0392b"
            },
            "font": "system-mono",
            "radius_px": 0,
            "spacing_px": 16,
            "product_name": "</style><script>alert(1)</script>"
        });
        Theme::from_json(&document).expect("the product name is text, not CSS")
    }

    #[test]
    fn a_theme_renders_one_rule_of_custom_properties() {
        let css = custom_properties(&Theme::default());

        assert!(css.starts_with(":root{"), "{css}");
        assert!(css.ends_with('}'), "{css}");
        assert_eq!(css.matches(":root").count(), 1, "one rule, not several");
    }

    /// A declaration that is not a custom property would be a tenant changing
    /// the *layout*, not the tokens — `display:none` on `form`, for one.
    #[test]
    fn every_declaration_is_a_custom_property() {
        for (property, _) in declarations(&hostile_theme()) {
            assert!(
                property.starts_with("--"),
                "{property} is not a custom property"
            );
        }
    }

    #[test]
    fn a_rendered_theme_uses_only_characters_html_escaping_leaves_alone() {
        let css = custom_properties(&hostile_theme());

        for character in css.chars() {
            assert!(
                SAFE_CHARACTERS.contains(character),
                "{character:?} is not one of the characters a theme may render"
            );
        }
    }

    /// The escaped and unescaped renderings must be the same bytes, or the
    /// template's `{{ theme_css }}` would produce broken CSS.
    #[test]
    fn a_theme_renders_the_same_bytes_escaped_or_not() {
        for theme in [Theme::default(), hostile_theme()] {
            let css = custom_properties(&theme);

            let escaped = askama::filters::escape(&css, askama::filters::Html)
                .expect("escaping a string cannot fail")
                .to_string();

            assert_eq!(escaped, css, "escaping changed the rendered theme");
        }
    }

    /// The one thing a `<style>` block must never contain.
    #[test]
    fn no_rendered_theme_can_leave_the_style_element() {
        let css = custom_properties(&hostile_theme()).to_ascii_lowercase();

        assert!(!css.contains("</style"), "{css}");
        assert!(!css.contains('<'), "{css}");
        // `@import` and `url(` are the two ways a stylesheet reaches an origin
        // nobody reviewed. Neither is expressible, because `@` and `(` are not
        // in the character set, but the absence is worth stating where a
        // reader looks for it.
        assert!(!css.contains("@import"), "{css}");
        assert!(!css.contains("url("), "{css}");
    }

    /// A tenant that saved the default theme sees the page a tenant with no
    /// theme sees.
    ///
    /// Both are reachable — a theme row is optional — and they must not be two
    /// designs. So this compares the values rather than spot-checking three of
    /// them: `style.css`'s own `:root` against the rule this module appends.
    ///
    /// `--line` is the one exception, and it is `ast-ndk.1`'s derivation
    /// rather than a drift: a theme has no border token, so the border becomes
    /// the muted text colour, while the stylesheet's default is the hairline
    /// this design is drawn with. A tenant theme therefore paints heavier
    /// borders than the shipped default until a border token exists.
    #[test]
    fn the_default_theme_renders_the_stylesheets_own_colours() {
        const STYLESHEET: &str = include_str!("../templates/style.css");

        let root = STYLESHEET
            .split_once(":root {")
            .expect("style.css opens with its defaults")
            .1;
        let root = &root[..root.find('}').expect("the :root block is closed")];
        let defaults: std::collections::BTreeMap<&str, &str> = root
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("--"))
            .filter_map(|line| line.trim_end_matches(';').split_once(':'))
            .map(|(property, value)| (property.trim(), value.trim()))
            .collect();

        for (property, value) in declarations(&Theme::default()) {
            if property == "--line" {
                continue;
            }
            assert_eq!(
                defaults.get(property.as_str()),
                Some(&value.as_str()),
                "{property} differs between style.css and the default theme"
            );
        }
    }

    /// The stylesheet, as the pair of sets that matter: what it reads and
    /// what it declares.
    fn stylesheet_properties() -> (
        std::collections::BTreeSet<String>,
        std::collections::BTreeSet<String>,
    ) {
        const STYLESHEET: &str = include_str!("../templates/style.css");

        let mut read = std::collections::BTreeSet::new();
        let mut rest = STYLESHEET;
        while let Some(start) = rest.find("var(") {
            rest = &rest[start + "var(".len()..];
            let end = rest.find([')', ',']).expect("a var() is closed");
            read.insert(rest[..end].trim().to_owned());
        }

        let declared = STYLESHEET
            .lines()
            .filter_map(|line| line.trim().strip_prefix("--"))
            .filter_map(|line| line.split_once(':'))
            .map(|(property, _)| format!("--{}", property.trim()))
            .collect();

        (read, declared)
    }

    /// Every custom property the stylesheet reads is one the stylesheet also
    /// declares, or a `var()` falls back to nothing and the page loses a
    /// colour.
    ///
    /// `style.css` reads more than a theme declares, deliberately: `--card`
    /// and `--backdrop` are *derived* from the tenant's `--bg` at use time, so
    /// a tenant that sets only a palette still gets a coherent page. The
    /// invariant is therefore about the stylesheet's own defaults, and the
    /// test below holds the other half.
    #[test]
    fn every_property_the_stylesheet_reads_is_declared() {
        let (read, declared) = stylesheet_properties();

        for property in read {
            assert!(
                declared.contains(&property),
                "{property} is read by style.css and declared nowhere in it"
            );
        }
    }

    /// Every property a theme declares is one the stylesheet has a default
    /// for.
    ///
    /// A tenant token nothing reads would be an administrator setting a
    /// colour and seeing no change, and the appended rule wins on document
    /// order only for a property the defaults also declare — so this is the
    /// half that keeps `theme` and `style.css` naming the same things.
    #[test]
    fn every_theme_property_has_a_default_in_the_stylesheet() {
        let (_, declared) = stylesheet_properties();

        for (property, _) in declarations(&Theme::default()) {
            assert!(
                declared.contains(&property),
                "{property} is a theme token that style.css declares no default for"
            );
        }
    }
}
