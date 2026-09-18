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
//! `style.css` declares the defaults in one `:root` rule. CSS resolves
//! same-specificity declarations by document order, so the tenant's rule is
//! appended after it and wins.
//!
//! There is no second rule to lose to any more: `ast-vn7` removed the
//! `prefers-color-scheme` block, and `style.css` is `color-scheme: light`. See
//! the note in [`asterius_domain::entities::theme`] for why a dark page is a
//! tenant's palette rather than a visitor's browser setting.

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

    /// The declarations of the first `:root` rule of a stylesheet.
    ///
    /// Last wins, as the cascade has it: `--backdrop` is declared twice on
    /// purpose — a literal for a browser with no `color-mix`, then the mix —
    /// and the value that counts is the second.
    fn first_root_block(css: &str) -> std::collections::BTreeMap<&str, &str> {
        let root = css
            .split_once(":root {")
            .expect("a stylesheet opens with its defaults")
            .1;
        let root = &root[..root.find('}').expect("the :root block is closed")];
        root.lines()
            .map(str::trim)
            .filter(|line| line.starts_with("--"))
            .filter_map(|line| line.trim_end_matches(';').split_once(':'))
            .map(|(property, value)| (property.trim(), value.trim()))
            .collect()
    }

    /// The console is drawn in these colours too (`ast-fe39`).
    ///
    /// `console/src/tokens.css` is a *copy* of the block above, and it has to
    /// be one: this file is `include!`d into the one nonce-carrying `<style>`
    /// element of every server-rendered page, while the console's CSS is
    /// bundled by Vite into a content-hashed file the entry document links.
    /// Neither consumer can read the other's bytes — one is an `include_str!`
    /// at `cargo build` time, the other an import resolved by a bundler that
    /// is not running then — so the values are duplicated and this test is
    /// what keeps the duplicate a cache rather than a fork.
    ///
    /// Both surfaces serve Geist from their own origin and share its stack.
    /// The console imports the vendored font through Vite; the pages use the
    /// hashed URL in `base.html`.
    ///
    /// [`DIVERGENT_COLOUR_TOKENS`] are the others, since `ast-k7az.1`: the
    /// console is greyscale and the pages are not. The reason is not taste.
    /// `--accent` and `--backdrop` are *tenant* tokens here — `--accent` is
    /// one of the six `asterius_domain::Theme` contrast-checks and a tenant's
    /// own rule overwrites it on every server-rendered page — while the
    /// console is this deployment's own tool, themed by nobody, so an accent
    /// it spends on links, primary buttons and the rail's current item is free
    /// to be ink rather than a hue. Sharing them would also mean repainting
    /// every tenant's sign-in page to restyle an admin screen. The divergence
    /// is asserted rather than tolerated: these two tokens *must* differ, so a
    /// future edit that quietly re-copies the indigo fails here instead of
    /// shipping.
    #[test]
    fn the_console_declares_the_same_design_tokens() {
        const STYLESHEET: &str = include_str!("../templates/style.css");
        const CONSOLE: &str = include_str!("../../../console/src/tokens.css");

        let pages = first_root_block(STYLESHEET);
        let console = first_root_block(CONSOLE);

        for (property, value) in &pages {
            let theirs = console.get(property).copied().unwrap_or_else(|| {
                panic!("{property} is a page token the console declares nowhere")
            });
            if DIVERGENT_COLOUR_TOKENS.contains(property) {
                assert_ne!(
                    &theirs, value,
                    "{property} is admitted as a console/pages divergence but no longer \
                     differs; drop it from DIVERGENT_COLOUR_TOKENS or restore the \
                     greyscale value"
                );
                continue;
            }
            assert_eq!(
                &theirs, value,
                "{property} differs between style.css and console/src/tokens.css"
            );
        }

        for property in DIVERGENT_COLOUR_TOKENS {
            assert!(
                pages.contains_key(property) && console.contains_key(property),
                "{property} is admitted as a divergence but one side declares it nowhere"
            );
        }
    }

    /// The tokens the console draws in its own greyscale (`ast-k7az.1`).
    ///
    /// Both are colour, and both are colour the console has no tenant to
    /// answer to about; every other token in the shared `:root` — the ink, the
    /// background, `--danger`, the radii, the shadow — is still copied value
    /// for value and still checked by
    /// [`the_console_declares_the_same_design_tokens`].
    const DIVERGENT_COLOUR_TOKENS: [&str; 2] = ["--accent", "--backdrop"];

    /// A stylesheet with its `/* … */` spans removed.
    ///
    /// Whole spans rather than the lines that open one: `tokens.css` writes
    /// down the indigo it used to be, in prose, and an explanation must not be
    /// what makes a check fire.
    fn without_comments(css: &str) -> String {
        let mut declarations = String::with_capacity(css.len());
        let mut rest = css;
        while let Some(start) = rest.find("/*") {
            declarations.push_str(&rest[..start]);
            match rest[start..].find("*/") {
                Some(end) => rest = &rest[start + end + 2..],
                None => break,
            }
        }
        declarations.push_str(rest);
        declarations
    }

    /// Every value a property is given in a stylesheet, in document order.
    fn values_of<'a>(css: &'a str, property: &str) -> Vec<&'a str> {
        let needle = format!("{property}:");
        let mut values = Vec::new();
        let mut rest = css;
        while let Some(start) = rest.find(&needle) {
            rest = &rest[start + needle.len()..];
            let end = rest.find(';').expect("a declaration ends in a semicolon");
            values.push(rest[..end].trim());
            rest = &rest[end..];
        }
        values
    }

    /// `ast-k7az.1`: in the console, colour means state and nothing else.
    ///
    /// The accent is ink, so the hue budget is spent on `--success`,
    /// `--danger`, `--warning` and `--info` — and `--info` has to be a blue of
    /// its own rather than the alias of `--accent` it used to be, or an
    /// informational message would be drawn in the same near-black as the body
    /// text it sits beside. Asserted per scheme, because the light and the
    /// dark palettes are two independent pairs.
    #[test]
    fn the_consoles_colour_is_reserved_for_state() {
        const CONSOLE: &str = include_str!("../../../console/src/tokens.css");
        let tokens = without_comments(CONSOLE);

        for indigo in ["#3f3fbf", "#a9b4ff"] {
            assert!(
                !tokens.contains(indigo),
                "{indigo} is still a live value in the console's tokens"
            );
        }

        let accents = values_of(&tokens, "--accent");
        let infos = values_of(&tokens, "--info");
        assert_eq!(accents.len(), 2, "one accent per scheme, light and dark");
        assert_eq!(infos.len(), 2, "one informational blue per scheme");
        for (scheme, (accent, info)) in ["light", "dark"].iter().zip(accents.iter().zip(&infos)) {
            assert_ne!(
                accent, info,
                "the {scheme} `--info` is the accent again, so information has no colour \
                 of its own"
            );
            assert!(
                info.starts_with('#'),
                "the {scheme} `--info` is `{info}`, not a colour of its own"
            );
        }
    }

    /// `ast-vn7`: one scheme, and the browser does not choose it.
    ///
    /// An absence, so it is asserted mechanically. A `prefers-color-scheme`
    /// block would substitute colours the tenant's own contrast check never
    /// saw — the tenant's rule is appended *after* it and wins on document
    /// order, so a themed tenant would get its own `--bg` under this file's
    /// `--fg`, a pair nobody measured. `color-scheme` is checked in the same
    /// test because the two have to agree: `light dark` without the media
    /// query would still let a browser repaint the form controls.
    #[test]
    fn the_stylesheet_offers_one_colour_scheme_and_it_is_light() {
        const STYLESHEET: &str = include_str!("../templates/style.css");

        // Comments removed first, and the whole `/* … */` span rather than the
        // lines that open one: this file explains *why* it no longer has a
        // `prefers-color-scheme` block, and the explanation must not be what
        // makes the check fire.
        let mut declarations = String::with_capacity(STYLESHEET.len());
        let mut rest = STYLESHEET;
        while let Some(start) = rest.find("/*") {
            declarations.push_str(&rest[..start]);
            match rest[start..].find("*/") {
                Some(end) => rest = &rest[start + end + 2..],
                None => break,
            }
        }
        declarations.push_str(rest);

        assert!(
            !declarations.contains("prefers-color-scheme"),
            "the stylesheet still lets the browser choose a palette"
        );
        assert!(
            declarations.contains("color-scheme: light;"),
            "the stylesheet does not declare the one scheme it supports"
        );
        assert!(
            !declarations.contains("color-scheme: light dark"),
            "`light dark` invites a browser to repaint controls in a scheme \
             no palette was validated for"
        );
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
