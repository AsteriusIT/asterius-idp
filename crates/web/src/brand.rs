//! The two pieces of a page that are *files* rather than tokens: the typeface
//! this server hosts, and the mark drawn beside a tenant's name.
//!
//! Both come from third parties and both are compiled into the binary. Neither
//! is fetched from anywhere: `asterius_web::csp::Policy` is `default-src
//! 'none'` with `font-src 'self'`, so a page that named an outside origin
//! would be a page whose font simply never loaded — and, per RFC 9700 §4.2.4,
//! a third-party fetch from an authorization page is how a `state` or a
//! `request_uri` leaks through a `Referer`. See `crates/web/assets/README.md`
//! for the provenance and the licences.
//!
//! # The font is a route, not a data URI
//!
//! The obvious way to embed a face with no extra request is `src:
//! url(data:font/woff2;base64,…)` in the `<style>` block every page already
//! carries. That is 93 KB of base64 on *every* page, uncacheable, inside a
//! document served `Cache-Control: no-store` — the interaction pages must be,
//! because they carry a `state` and an interaction id (RFC 9700 §4.3).
//!
//! So the face is one route whose path carries a hash of its own bytes
//! ([`font_path`]), answered with `Cache-Control: public, max-age=31536000,
//! immutable`. A year is safe precisely because the name is the digest: new
//! bytes are a new URL, so there is nothing to revalidate and nothing to
//! purge. The document that names it is not cached, which is what keeps the
//! two policies consistent.
//!
//! # The mark is inline SVG, from a closed set and nowhere else
//!
//! An icon has to be a document fragment: it is drawn in the tenant's colours
//! (`currentColor` against `--fg`), and a sprite or an `<img>` would be a
//! second request for 300 bytes. So [`Brand::icon_svg`] returns markup that
//! `base.html` renders **unescaped** — the second and last `|safe` in this
//! tree, and the one `crate::source_audit` exempts by its exact spelling.
//!
//! That is only safe because of what it can return: the markup is built here
//! from a [`TenantIcon`], which is an enumeration in
//! [`asterius_domain::entities::theme`], and the geometry is twenty-four files
//! in `crates/web/assets/icons` read at compile time. There is no code path
//! from a string to a rendered mark — not from the theme document, whose
//! `icon` member the schema holds to those same twenty-four tokens, and not
//! from anything a request carries. `tests::no_free_string_can_reach_the_
//! rendered_mark` is the statement of that, and it is the security point of
//! this module.
//!
//! A tenant that uploaded a logo gets the logo instead ([`Brand::with_logo`]),
//! and a logo is a raster: `asterius_domain::ImageFormat` answers an SVG
//! upload with a 415, so nothing a tenant supplies is ever XML this server
//! inlines.

use asterius_domain::TenantIcon;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// The typeface
// ---------------------------------------------------------------------------

/// Geist Variable, as bytes in the binary.
///
/// One variable file, not three static faces: the design asks for 400, 500 and
/// 600, and a variable file carries the whole axis in fewer bytes than two
/// static ones.
pub const FONT_BYTES: &[u8] = include_bytes!("../assets/fonts/Geist-Variable.woff2");

/// What the font route answers with.
///
/// RFC 8081 §4.4.5 registers `font/woff2`; the older `application/font-woff2`
/// is not sent, because `X-Content-Type-Options: nosniff` is on every response
/// and a browser that did not recognise the type would refuse the face.
pub const FONT_CONTENT_TYPE: &str = "font/woff2";

/// A year, and `immutable`, because [`font_path`] names the bytes.
pub const FONT_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// How much of the digest goes in the path.
///
/// The name is a cache key, not a signature: it has to change when the bytes
/// change, and 64 bits of SHA-256 is far past accidental collision for a table
/// with one row in it. The whole digest would be a 64-character path segment
/// in every page's `<style>` block.
const FONT_DIGEST_CHARACTERS: usize = 16;

/// The path the face is served at, hash and all.
///
/// Root-absolute as the *router* sees it: a page under a path-based tenant has
/// to prefix it with `MountPrefix::absolute`, exactly like a form action
/// (`ast-295`). [`Brand::new`] takes the already-prefixed URL for that reason.
///
/// Computed once, from the bytes themselves, so that the route and the
/// stylesheet cannot name two different paths — there is one function and both
/// call it.
#[must_use]
pub fn font_path() -> &'static str {
    static PATH: LazyLock<String> = LazyLock::new(|| {
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(FONT_BYTES));
        format!(
            "/assets/font/geist-{}.woff2",
            &digest[..FONT_DIGEST_CHARACTERS]
        )
    });
    &PATH
}

// ---------------------------------------------------------------------------
// The mark
// ---------------------------------------------------------------------------

/// The geometry of every mark, by the token that names it.
///
/// `include_str!` rather than a directory walk: a file that failed to read at
/// runtime would be a page with a hole in it, and this way a missing icon does
/// not compile. Each file holds *only* the child elements — the `<svg>`
/// wrapper below is this module's, so upstream cannot change the size, the
/// stroke or the colour of a mark by changing a file.
const GEOMETRY: &[(&str, &str)] = &[
    ("shield", include_str!("../assets/icons/shield.svg")),
    (
        "shield-check",
        include_str!("../assets/icons/shield-check.svg"),
    ),
    ("lock", include_str!("../assets/icons/lock.svg")),
    ("key-round", include_str!("../assets/icons/key-round.svg")),
    ("id-card", include_str!("../assets/icons/id-card.svg")),
    ("user", include_str!("../assets/icons/user.svg")),
    ("users", include_str!("../assets/icons/users.svg")),
    ("building-2", include_str!("../assets/icons/building-2.svg")),
    ("briefcase", include_str!("../assets/icons/briefcase.svg")),
    ("landmark", include_str!("../assets/icons/landmark.svg")),
    (
        "graduation-cap",
        include_str!("../assets/icons/graduation-cap.svg"),
    ),
    (
        "stethoscope",
        include_str!("../assets/icons/stethoscope.svg"),
    ),
    ("store", include_str!("../assets/icons/store.svg")),
    ("wallet", include_str!("../assets/icons/wallet.svg")),
    ("globe", include_str!("../assets/icons/globe.svg")),
    ("cloud", include_str!("../assets/icons/cloud.svg")),
    ("server", include_str!("../assets/icons/server.svg")),
    ("database", include_str!("../assets/icons/database.svg")),
    ("cpu", include_str!("../assets/icons/cpu.svg")),
    ("terminal", include_str!("../assets/icons/terminal.svg")),
    ("rocket", include_str!("../assets/icons/rocket.svg")),
    ("zap", include_str!("../assets/icons/zap.svg")),
    ("sparkles", include_str!("../assets/icons/sparkles.svg")),
    ("leaf", include_str!("../assets/icons/leaf.svg")),
];

/// The wrapper every mark is drawn in.
///
/// `currentColor` and not a literal: the square behind it is `--fg` and the
/// glyph is `--bg`, which is the one colour pair
/// `asterius_domain::Theme::from_json` checks for contrast — so a tenant that
/// sets a palette gets a mark that is still legible, and this module invents no
/// colour of its own. `aria-hidden` because the tenant's name is right beside
/// it: a screen reader that announced both would say the same thing twice.
const WRAPPER_OPEN: &str = "<svg class=\"brand-glyph\" width=\"16\" height=\"16\" \
     viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" \
     stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\" focusable=\"false\">";

/// The geometry of one mark.
///
/// # Panics
///
/// Never: [`GEOMETRY`] and [`TenantIcon::ALL`] are checked to name the same
/// tokens by `every_icon_the_domain_names_has_geometry_here`, which fails the
/// build rather than letting a page render an empty square.
fn geometry(icon: TenantIcon) -> &'static str {
    GEOMETRY
        .iter()
        .find(|(name, _)| *name == icon.name())
        .map(|(_, body)| body.trim())
        .expect("every TenantIcon has a file, asserted by this module's tests")
}

/// What a page draws beside the tenant's name, and where it fetches its face.
///
/// One value carried by every page rather than three fields on fourteen page
/// structs: the next thing the chrome grows should not be another fourteen-file
/// diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Brand<'a> {
    /// The face's URL, already carrying this request's mount prefix.
    font_url: &'a str,
    /// The tenant's own logo, when it has uploaded one.
    logo_url: &'a str,
    /// The mark drawn when it has not.
    icon: TenantIcon,
}

impl<'a> Brand<'a> {
    /// The chrome of a tenant that has chosen nothing: the default mark.
    ///
    /// `font_url` is [`font_path`] put through
    /// `asterius_server::tenancy::MountPrefix::absolute`; a page under
    /// `/t/{tenant}` that named the unprefixed path would ask for a face that
    /// 404s (`ast-295`).
    #[must_use]
    pub const fn new(font_url: &'a str) -> Self {
        Self {
            font_url,
            logo_url: "",
            icon: TenantIcon::Shield,
        }
    }

    /// The same chrome with the tenant's chosen mark.
    #[must_use]
    pub const fn with_icon(mut self, icon: TenantIcon) -> Self {
        self.icon = icon;
        self
    }

    /// The same chrome drawing the tenant's logo instead of a mark.
    ///
    /// A logo wins over an icon, which is the whole point of uploading one:
    /// `asterius_domain::AssetRef` names raster bytes this server decoded and
    /// re-encoded, so the `<img>` is not a document and carries no script.
    #[must_use]
    pub const fn with_logo(mut self, logo_url: &'a str) -> Self {
        self.logo_url = logo_url;
        self
    }

    /// The face's URL, for the template's `@font-face`.
    #[must_use]
    pub const fn font_url(&self) -> &'a str {
        self.font_url
    }

    /// The tenant's logo URL, or `""` when it has none.
    ///
    /// Empty rather than `Option` because the template branches on it, and
    /// `{% if brand.logo_url().is_empty() %}` is one expression a reader can
    /// check against the rendered page.
    #[must_use]
    pub const fn logo_url(&self) -> &'a str {
        self.logo_url
    }

    /// The mark, as the markup `base.html` renders unescaped.
    ///
    /// Every byte of the result comes from this file or from
    /// `crates/web/assets/icons`; [`Self::icon`] is an enumeration, so there is
    /// no input to this function that a request could influence beyond
    /// *choosing among twenty-four reviewed drawings*.
    #[must_use]
    pub fn icon_svg(&self) -> String {
        format!("{WRAPPER_OPEN}{}</svg>", geometry(self.icon))
    }

    /// Which mark this chrome draws.
    #[must_use]
    pub const fn icon(&self) -> TenantIcon {
        self.icon
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_font_path_names_the_bytes_it_serves() {
        use sha2::{Digest, Sha256};

        let path = font_path();

        let digest = hex::encode(Sha256::digest(FONT_BYTES));
        assert_eq!(
            path,
            format!("/assets/font/geist-{}.woff2", &digest[..16]),
            "the cached-for-a-year path is not the digest of what is served"
        );
        assert!(path.starts_with('/'), "a handler path is absolute: {path}");
        assert!(
            font_path() == path,
            "the path must not change between calls, or the route and the page disagree"
        );
    }

    /// The bytes really are the face they claim to be.
    ///
    /// `wOF2` is the WOFF2 signature (W3C WOFF2 §4). A file that had been
    /// replaced by a stray HTML error page — the classic outcome of a scripted
    /// download — would be served as `font/woff2` and silently never render.
    #[test]
    fn the_embedded_face_is_a_woff2_file() {
        assert_eq!(&FONT_BYTES[..4], b"wOF2", "not a WOFF2 file");
        assert!(
            FONT_BYTES.len() > 20_000,
            "a face this small is not a text font"
        );
    }

    /// A page that could not name a mark would render an empty square.
    #[test]
    fn every_icon_the_domain_names_has_geometry_here() {
        for icon in TenantIcon::ALL {
            let body = geometry(*icon);
            assert!(!body.is_empty(), "{} has no geometry", icon.name());
        }
        assert_eq!(
            GEOMETRY.len(),
            TenantIcon::ALL.len(),
            "the embedded set and the enumeration have drifted"
        );
    }

    /// The whole security claim of this module, as a property of every mark.
    ///
    /// The markup is rendered unescaped into a document that also carries a
    /// password field, so what matters is not that today's twenty-four files
    /// are harmless but that nothing in a rendered mark can *do* anything: no
    /// element that executes, no attribute that fetches, no way out of the
    /// `<svg>` element.
    #[test]
    fn no_rendered_mark_can_run_or_fetch_anything() {
        for icon in TenantIcon::ALL {
            let svg = Brand::new("/f.woff2").with_icon(*icon).icon_svg();
            let lowered = svg.to_ascii_lowercase();

            assert!(svg.starts_with("<svg "), "{svg}");
            assert!(svg.ends_with("</svg>"), "{svg}");
            assert_eq!(lowered.matches("<svg").count(), 1, "{svg}");
            assert_eq!(lowered.matches("</svg>").count(), 1, "{svg}");
            for forbidden in [
                "<script",
                "<foreignobject",
                "<use",
                "<image",
                "<animate",
                "<set",
                "<style",
                "href",
                "url(",
                "javascript:",
                "data:",
                // Every intrinsic event handler starts this way, and one of
                // them inside an inline SVG runs under the page's own origin.
                " on",
            ] {
                assert!(
                    !lowered.contains(forbidden),
                    "{} may render {forbidden}: {svg}",
                    icon.name()
                );
            }
        }
    }

    /// A mark is chosen, never supplied.
    ///
    /// The mutation this guards against is somebody widening `icon_svg` to
    /// take a name — "just for the console preview" — because at that moment
    /// the unescaped interpolation in `base.html` becomes a cross-site
    /// scripting bug. The proof is by exhaustion over the type: every value
    /// [`Brand`] can hold renders one of the reviewed drawings, so the set of
    /// markup this function can emit is finite and is this list.
    #[test]
    fn no_free_string_can_reach_the_rendered_mark() {
        let reviewed: std::collections::BTreeSet<String> = TenantIcon::ALL
            .iter()
            .map(|icon| Brand::new("/f.woff2").with_icon(*icon).icon_svg())
            .collect();

        assert_eq!(
            reviewed.len(),
            TenantIcon::ALL.len(),
            "two marks render the same markup"
        );
        for hostile in [
            "shield\"><script>alert(1)</script>",
            "../../../etc/passwd",
            "<svg onload=alert(1)/>",
        ] {
            assert!(
                TenantIcon::parse(hostile).is_none(),
                "{hostile} names an icon, so a string reached the renderer"
            );
        }
        // And the only way into the type is that parse: `Brand::with_icon`
        // takes a `TenantIcon`, which has no constructor from a string beyond
        // it. If this line ever fails to compile because `icon_svg` grew a
        // string parameter, that is the bug this test is here for.
        let brand = Brand::new("/f.woff2").with_icon(TenantIcon::Shield);
        assert!(reviewed.contains(&brand.icon_svg()));
    }

    #[test]
    fn a_tenant_with_a_logo_draws_the_logo_and_not_a_mark() {
        let brand = Brand::new("/f.woff2").with_logo("/t/acme/assets/logo/abc.png");

        assert_eq!(brand.logo_url(), "/t/acme/assets/logo/abc.png");
        assert!(
            Brand::new("/f.woff2").logo_url().is_empty(),
            "a tenant with no logo must report none, so the template draws the mark"
        );
    }

    #[test]
    fn the_default_mark_is_the_shield_of_the_shipped_design() {
        assert_eq!(Brand::new("/f.woff2").icon(), TenantIcon::Shield);
    }
}
