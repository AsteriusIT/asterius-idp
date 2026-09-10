//! A tenant's design tokens: the whole of what a tenant may change about how
//! its sign-in pages look.
//!
//! # The product rule this type exists to hold
//!
//! A tenant supplies **no markup, no stylesheet and no script** — it supplies
//! *values*. Everything in this module is a bounded scalar: a colour is six hex
//! digits, a font is one of a fixed set this deployment hosts itself, a radius
//! is a small integer, a link is an `https` URL, a logo is a digest naming
//! bytes this server decoded and re-encoded. There is no string in a
//! [`Theme`] that reaches a stylesheet, which is what makes the rendering in
//! `asterius_web::theme` safe: it does not escape tenant text, it prints
//! numbers and hex triples that cannot express `</style>`.
//!
//! The alternative — a `custom_css` member, which every hosted identity product
//! eventually grows — is a JavaScript foothold in a document that also carries
//! the user's password field. CSS alone can exfiltrate an input's value with
//! attribute selectors and a background image, and a `<style>` block a tenant
//! wrote is one `@import` away from an origin nobody reviewed. So the schema
//! has `additionalProperties: false` and a test that says so.
//!
//! # Why the validator is the one in [`crate::entities::authorization_details`]
//!
//! The shape check reuses [`Schema`], the JSON Schema subset written for
//! RFC 9396 type registration: same subset, same bounds, same fuzz target
//! shape. A second schema dialect in one product is a second set of bugs, and
//! this document is exactly what that subset was written for — a small object
//! with named members, an enumeration and a length bound.
//!
//! [`Schema`] answers "does this fit", and the *values* — a colour that is
//! really six hex digits, a URL that is really `https`, a contrast ratio that
//! really clears WCAG AA — are checked here, because a JSON Schema subset with
//! no `pattern` keyword cannot express any of them and adding one would be a
//! regular-expression engine on operator input.
//!
//! # Contrast is refused, not overridden
//!
//! WCAG 2.2 SC 1.4.3 (Contrast (Minimum)) asks for 4.5:1 between text and its
//! background. A tenant whose palette falls below it is refused, and there is
//! deliberately **no override flag**:
//!
//! * The people harmed by a 2:1 palette are not the administrator who chose it,
//!   and an override is a control that lets one party accept a risk on behalf
//!   of another who never sees the dialog.
//! * This is the *sign-in* page. A user who cannot read it cannot reach the
//!   application to complain about it, and cannot switch tenants either.
//! * An override with an audit record answers "who did this" after the fact.
//!   Refusal answers "this does not happen", and for a fixed set of six
//!   colours the cost of refusal is that an administrator picks a darker
//!   shade.
//!
//! If a deployment ever needs the override, it belongs behind an operator
//! (not tenant) setting, and it should arrive with the audit event and the
//! screen that shows the measured ratio. Nothing here anticipates it.
//!
//! # What a stored theme does to `prefers-color-scheme`
//!
//! The base stylesheet ships a light and a dark palette. A tenant theme
//! declares the same custom properties *after* both, so a themed tenant looks
//! the same in either scheme. That is a real loss and it is the honest one:
//! validating one palette for AA and then letting a media query substitute six
//! other colours would be a check that does not hold in the case it was
//! written for. A dark palette per tenant is a second token set and a second
//! contrast check, and it is not this bead.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use url::Url;

use crate::entities::authorization_details::{Schema, SchemaViolation};

/// The largest theme document this server will parse.
///
/// Applied to the raw bytes, before `serde_json` sees them, for the reason
/// [`crate::entities::authorization_details::MAX_BYTES`] gives: a validator is
/// a tree walk, and bounding the walk after building the tree is the wrong
/// order. Two kibibytes is roughly four times the largest document this schema
/// can describe.
pub const MAX_DOCUMENT_BYTES: usize = 2 * 1024;

/// The longest a product name may be, in characters.
///
/// It renders in a heading on a page sized for a phone.
pub const MAX_PRODUCT_NAME_CHARS: usize = 64;

/// The longest a support link may be, in characters.
pub const MAX_URL_CHARS: usize = 256;

/// WCAG 2.2 SC 1.4.3's minimum contrast ratio for body text.
pub const MIN_CONTRAST_RATIO: f64 = 4.5;

/// The corner radius scale, in CSS pixels.
///
/// Zero is square corners, which is a legitimate house style; the ceiling is
/// where a button stops being a rectangle.
pub const RADIUS_RANGE: std::ops::RangeInclusive<u32> = 0..=24;

/// The spacing base unit, in CSS pixels.
///
/// Everything else in the stylesheet is a multiple of it, so this is the one
/// number that makes a layout airier or tighter.
pub const SPACING_RANGE: std::ops::RangeInclusive<u32> = 4..=16;

/// How many hex digits a `sha-256` digest is written in.
const DIGEST_HEX_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a theme document was refused.
///
/// Every variant carries the JSON pointer of the member at fault, because the
/// consumer is a form with named fields: "invalid theme" makes an
/// administrator guess which of six colours it was.
///
/// The paths are safe to show. They name *our* schema's members, never the
/// tenant's values, so an error message cannot become a reflection of whatever
/// the administrator typed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ThemeError {
    /// The bytes were longer than [`MAX_DOCUMENT_BYTES`].
    #[error("a theme document is at most {MAX_DOCUMENT_BYTES} bytes")]
    TooLarge,
    /// The bytes were not JSON at all.
    #[error("a theme document is JSON")]
    NotJson,
    /// The document does not fit the schema.
    #[error("`{path}` does not fit the theme schema")]
    Schema {
        /// JSON pointer of the member at fault.
        path: String,
    },
    /// A colour member that is not `#rrggbb`.
    #[error("`{path}` is not a `#rrggbb` colour")]
    Colour {
        /// JSON pointer of the member at fault.
        path: String,
    },
    /// A font this deployment does not host.
    #[error("`{path}` is not one of the font stacks this server hosts")]
    Font {
        /// JSON pointer of the member at fault.
        path: String,
    },
    /// A scale value outside its range.
    #[error("`{path}` is outside {min}..={max}")]
    OutOfRange {
        /// JSON pointer of the member at fault.
        path: String,
        /// The smallest accepted value.
        min: u32,
        /// The largest accepted value.
        max: u32,
    },
    /// Free text with something other than printable characters in it.
    #[error("`{path}` is empty or contains a character that is not printable text")]
    NotPrintable {
        /// JSON pointer of the member at fault.
        path: String,
    },
    /// A link that is not an absolute `https` URL with a host and no
    /// credentials in it.
    #[error("`{path}` is not an absolute https URL with a host and no credentials")]
    NotHttps {
        /// JSON pointer of the member at fault.
        path: String,
    },
    /// An asset reference naming a format this server will not serve.
    #[error("`{path}` is not one of the raster image types this server accepts")]
    UnsupportedImageType {
        /// JSON pointer of the member at fault.
        path: String,
    },
    /// An asset reference whose digest is not 64 hex digits.
    #[error("`{path}` is not a sha-256 digest")]
    Digest {
        /// JSON pointer of the member at fault.
        path: String,
    },
    /// A foreground/background pair below [`MIN_CONTRAST_RATIO`].
    #[error(
        "`{foreground}` on `{background}` has a contrast ratio of {ratio:.2}:1, \
         below WCAG 2.2 AA's {MIN_CONTRAST_RATIO}:1"
    )]
    Contrast {
        /// JSON pointer of the foreground colour.
        foreground: String,
        /// JSON pointer of the background colour.
        background: String,
        /// What the pair actually measured.
        ratio: f64,
    },
}

impl ThemeError {
    /// The JSON pointer of the member the refusal is about.
    ///
    /// A contrast failure is about a pair, and names the foreground: it is the
    /// one an administrator changes.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::TooLarge | Self::NotJson => "/",
            Self::Schema { path }
            | Self::Colour { path }
            | Self::Font { path }
            | Self::OutOfRange { path, .. }
            | Self::NotPrintable { path }
            | Self::NotHttps { path }
            | Self::UnsupportedImageType { path }
            | Self::Digest { path } => path,
            Self::Contrast { foreground, .. } => foreground,
        }
    }
}

// ---------------------------------------------------------------------------
// Colours
// ---------------------------------------------------------------------------

/// One `#rrggbb` colour.
///
/// Deliberately the narrowest colour syntax CSS has. `rgb()`, `hsl()`,
/// `color-mix()`, `var()` and the named colours are all *expressions*, and an
/// expression in a token is a parser this server would have to write and get
/// right; three bytes are three bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Colour {
    red: u8,
    green: u8,
    blue: u8,
}

impl Colour {
    /// Reads `#rrggbb`, in either case.
    ///
    /// The three-digit shorthand is refused rather than expanded: one syntax
    /// means one thing for the round trip through the store to compare.
    ///
    /// # Errors
    ///
    /// [`None`] for anything that is not `#` followed by six hex digits.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.strip_prefix('#')?;
        if digits.len() != 6 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let channel = |from: usize| u8::from_str_radix(&digits[from..from + 2], 16).ok();
        Some(Self {
            red: channel(0)?,
            green: channel(2)?,
            blue: channel(4)?,
        })
    }

    /// The colour as CSS, normalised to lowercase `#rrggbb`.
    #[must_use]
    pub fn to_css(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.red, self.green, self.blue)
    }

    /// WCAG 2.2's relative luminance.
    ///
    /// The formula is from the definition of *relative luminance* in WCAG 2.2,
    /// applied to the sRGB channels.
    fn relative_luminance(self) -> f64 {
        fn linear(channel: u8) -> f64 {
            let value = f64::from(channel) / 255.0;
            if value <= 0.040_45 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        }
        0.2126 * linear(self.red) + 0.7152 * linear(self.green) + 0.0722 * linear(self.blue)
    }

    /// WCAG 2.2's contrast ratio between two colours, from 1:1 to 21:1.
    ///
    /// Symmetric, as the definition is: `(L1 + 0.05) / (L2 + 0.05)` with `L1`
    /// the lighter of the two.
    #[must_use]
    pub fn contrast_ratio(one: Self, other: Self) -> f64 {
        let first = one.relative_luminance();
        let second = other.relative_luminance();
        let (lighter, darker) = if first >= second {
            (first, second)
        } else {
            (second, first)
        };
        (lighter + 0.05) / (darker + 0.05)
    }
}

// ---------------------------------------------------------------------------
// The palette
// ---------------------------------------------------------------------------

/// The six colours a tenant sets.
///
/// Six, and not "a map of names to colours": a fixed set is what makes the
/// contrast check possible at all. A tenant that could invent
/// `--brand-tertiary` would have a token nothing measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    background: Colour,
    text: Colour,
    muted_text: Colour,
    accent: Colour,
    accent_text: Colour,
    danger: Colour,
}

/// The foreground/background pairs WCAG AA is checked on.
///
/// Named as a table rather than written out in the validator so that the test
/// and the check read the same list. Every pair here is text on the surface it
/// sits on: body text, secondary text, the label inside the primary button,
/// and the error text.
const CONTRAST_PAIRS: &[(&str, &str)] = &[
    ("text", "background"),
    ("muted_text", "background"),
    ("accent_text", "accent"),
    ("danger", "background"),
];

impl Default for Palette {
    /// The palette `crates/web/templates/style.css` has always shipped.
    ///
    /// It clears AA on every pair in [`CONTRAST_PAIRS`], which
    /// `the_default_palette_clears_the_bar_it_imposes` asserts rather than
    /// assumes.
    fn default() -> Self {
        Self {
            background: Colour {
                red: 0xff,
                green: 0xff,
                blue: 0xff,
            },
            text: Colour {
                red: 0x11,
                green: 0x11,
                blue: 0x11,
            },
            muted_text: Colour {
                red: 0x55,
                green: 0x55,
                blue: 0x55,
            },
            accent: Colour {
                red: 0x2f,
                green: 0x6f,
                blue: 0xdb,
            },
            accent_text: Colour {
                red: 0xff,
                green: 0xff,
                blue: 0xff,
            },
            danger: Colour {
                red: 0xc0,
                green: 0x39,
                blue: 0x2b,
            },
        }
    }
}

impl Palette {
    /// The page background.
    #[must_use]
    pub const fn background(&self) -> Colour {
        self.background
    }

    /// Body text.
    #[must_use]
    pub const fn text(&self) -> Colour {
        self.text
    }

    /// Secondary text: hints, descriptions, the small print.
    #[must_use]
    pub const fn muted_text(&self) -> Colour {
        self.muted_text
    }

    /// The primary button and the focus ring.
    #[must_use]
    pub const fn accent(&self) -> Colour {
        self.accent
    }

    /// The label inside the primary button.
    #[must_use]
    pub const fn accent_text(&self) -> Colour {
        self.accent_text
    }

    /// Error text and the error summary's rule.
    #[must_use]
    pub const fn danger(&self) -> Colour {
        self.danger
    }

    /// One colour by the name the schema uses.
    fn by_name(&self, name: &str) -> Option<Colour> {
        match name {
            "background" => Some(self.background),
            "text" => Some(self.text),
            "muted_text" => Some(self.muted_text),
            "accent" => Some(self.accent),
            "accent_text" => Some(self.accent_text),
            "danger" => Some(self.danger),
            _ => None,
        }
    }

    /// Checks every pair in [`CONTRAST_PAIRS`].
    fn check_contrast(&self) -> Result<(), ThemeError> {
        for (foreground, background) in CONTRAST_PAIRS {
            let (Some(front), Some(back)) = (self.by_name(foreground), self.by_name(background))
            else {
                // Unreachable while CONTRAST_PAIRS names members of this
                // struct, which `every_contrast_pair_names_a_colour` pins.
                continue;
            };
            let ratio = Colour::contrast_ratio(front, back);
            if ratio < MIN_CONTRAST_RATIO {
                return Err(ThemeError::Contrast {
                    foreground: format!("/palette/{foreground}"),
                    background: format!("/palette/{background}"),
                    ratio,
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fonts
// ---------------------------------------------------------------------------

/// The font stacks this deployment offers.
///
/// A closed set, and the reason is ADR-0009's: a page may not reach an origin
/// nobody reviewed, and "self-hosted" for a typeface means either a font file
/// this server serves or the fonts the operating system already has. This
/// deployment ships no font file, so the set is three system stacks — no
/// request leaves the page, and there is no `@font-face` for a tenant to point
/// at a URL of its choosing.
///
/// Every stack below is quote-free and ASCII by construction, which is what
/// lets `asterius_web::theme` print it into a `<style>` block: see
/// [`FontStack::css`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FontStack {
    /// The platform's UI sans-serif. The stylesheet's historical default.
    #[default]
    SystemSans,
    /// The platform's serif.
    SystemSerif,
    /// The platform's monospace, as used for one-time codes.
    SystemMono,
}

impl FontStack {
    /// Every stack, for a console that renders a picker.
    pub const ALL: &'static [Self] = &[Self::SystemSans, Self::SystemSerif, Self::SystemMono];

    /// The token as it appears in the theme document.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SystemSans => "system-sans",
            Self::SystemSerif => "system-serif",
            Self::SystemMono => "system-mono",
        }
    }

    /// Reads the token.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|stack| stack.name() == name)
    }

    /// The CSS `font-family` list.
    ///
    /// No quotes, no non-ASCII and no `<`, `>`, `&` — a family name that needed
    /// quoting would be a family this server does not host. Pinned by
    /// `a_font_stack_is_printable_inside_a_style_element`.
    #[must_use]
    pub const fn css(self) -> &'static str {
        match self {
            Self::SystemSans => "system-ui, -apple-system, Segoe UI, sans-serif",
            Self::SystemSerif => "Iowan Old Style, Palatino, Georgia, serif",
            Self::SystemMono => "ui-monospace, SFMono-Regular, Menlo, monospace",
        }
    }
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

/// The raster formats a tenant may upload.
///
/// SVG is absent on purpose and is the whole reason this is an enumeration:
/// an SVG is an XML document that may carry `<script>`, `<foreignObject>` and
/// external references, and served from the tenant's own origin it would run
/// in the same origin as the sign-in page. There is no sanitiser here that
/// could make that safe, so the answer to an SVG upload is 415.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// `image/png`.
    Png,
    /// `image/jpeg`.
    Jpeg,
    /// `image/webp`.
    Webp,
}

impl ImageFormat {
    /// Every accepted format.
    pub const ALL: &'static [Self] = &[Self::Png, Self::Jpeg, Self::Webp];

    /// The media type this format is stored and served as.
    #[must_use]
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }

    /// Reads a media type, without parameters.
    ///
    /// Exact match, lowercase: `image/PNG` and `image/png; charset=utf-8` are
    /// refused rather than normalised, because the only producer of this
    /// string is this server's own upload endpoint after it decoded the bytes.
    #[must_use]
    pub fn from_content_type(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|format| format.content_type() == value)
    }
}

/// A reference to an image this server has already decoded and re-encoded.
///
/// The theme document names a digest, never bytes: the blob lives in its own
/// table, the document is small enough to bound, and a digest is content
/// addressing — the same logo uploaded twice is one row, and a document that
/// names a digest nobody stored renders no logo rather than a broken one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetRef {
    digest: String,
    format: ImageFormat,
}

impl AssetRef {
    /// Names a stored asset.
    ///
    /// # Errors
    ///
    /// [`ThemeError::Digest`] if the digest is not 64 lowercase hex digits.
    pub fn new(digest: &str, format: ImageFormat, path: &str) -> Result<Self, ThemeError> {
        if digest.len() != DIGEST_HEX_LEN
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ThemeError::Digest {
                path: format!("{path}/digest"),
            });
        }
        Ok(Self {
            digest: digest.to_owned(),
            format,
        })
    }

    /// The `sha-256` of the re-encoded bytes, in lowercase hex.
    ///
    /// Safe in a URL path segment by construction: 64 characters of `[0-9a-f]`
    /// cannot traverse a directory or leave a path.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// What this server will serve the bytes as.
    #[must_use]
    pub const fn format(&self) -> ImageFormat {
        self.format
    }
}

// ---------------------------------------------------------------------------
// Support links
// ---------------------------------------------------------------------------

/// The links a tenant may put on its sign-in pages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SupportLinks {
    help: Option<Url>,
    privacy: Option<Url>,
    terms: Option<Url>,
}

impl SupportLinks {
    /// Where a user who cannot sign in is sent.
    #[must_use]
    pub const fn help_url(&self) -> Option<&Url> {
        self.help.as_ref()
    }

    /// The privacy notice.
    #[must_use]
    pub const fn privacy_url(&self) -> Option<&Url> {
        self.privacy.as_ref()
    }

    /// The terms of service.
    #[must_use]
    pub const fn terms_url(&self) -> Option<&Url> {
        self.terms.as_ref()
    }
}

/// Reads one support link.
///
/// `https` only, with a host, without credentials and without a fragment.
///
/// * `http` would put a link to a cleartext page on a page whose whole subject
///   is a password, and a tenant that has no TLS certificate for its help
///   centre has a problem this server should not paper over.
/// * A scheme like `javascript:` or `data:` is the same foothold the product
///   rule exists to deny, and refusing everything but `https` refuses those
///   without enumerating them.
/// * Credentials in a URL (`https://user:pass@host/`) are a phishing shape and
///   RFC 3986 §3.2.1 deprecates them.
fn parse_link(value: Option<&Value>, path: &str) -> Result<Option<Url>, ThemeError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let refuse = || ThemeError::NotHttps {
        path: path.to_owned(),
    };
    let text = value.as_str().ok_or_else(refuse)?;
    if text.chars().count() > MAX_URL_CHARS {
        return Err(refuse());
    }
    let url = Url::parse(text).map_err(|_| refuse())?;
    if url.scheme() != "https"
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(refuse());
    }
    Ok(Some(url))
}

// ---------------------------------------------------------------------------
// The theme
// ---------------------------------------------------------------------------

/// Everything a tenant may set about how its pages look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Theme {
    palette: Palette,
    font: FontStack,
    radius_px: u32,
    spacing_px: u32,
    product_name: Option<String>,
    support: SupportLinks,
    logo: Option<AssetRef>,
    favicon: Option<AssetRef>,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            palette: Palette::default(),
            font: FontStack::default(),
            radius_px: 4,
            spacing_px: 8,
            product_name: None,
            support: SupportLinks::default(),
            logo: None,
            favicon: None,
        }
    }
}

/// The theme document's schema, written in the subset of
/// [`crate::entities::authorization_details`].
///
/// Kept as a JSON literal rather than built with constructors so that it can be
/// read as the document it describes, and copied into an `OpenAPI` description
/// without a second source of truth. `additionalProperties: false` at every
/// level is the product rule in one keyword: a member this server does not know
/// about is refused, not carried.
const SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "required": ["palette", "font", "radius_px", "spacing_px"],
  "properties": {
    "palette": {
      "type": "object",
      "additionalProperties": false,
      "required": ["background", "text", "muted_text", "accent", "accent_text", "danger"],
      "properties": {
        "background": {"type": "string", "maxLength": 7},
        "text": {"type": "string", "maxLength": 7},
        "muted_text": {"type": "string", "maxLength": 7},
        "accent": {"type": "string", "maxLength": 7},
        "accent_text": {"type": "string", "maxLength": 7},
        "danger": {"type": "string", "maxLength": 7}
      }
    },
    "font": {"type": "string", "enum": ["system-sans", "system-serif", "system-mono"]},
    "radius_px": {"type": "integer"},
    "spacing_px": {"type": "integer"},
    "product_name": {"type": ["string", "null"], "maxLength": 64},
    "support": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "help_url": {"type": ["string", "null"], "maxLength": 256},
        "privacy_url": {"type": ["string", "null"], "maxLength": 256},
        "terms_url": {"type": ["string", "null"], "maxLength": 256}
      }
    },
    "logo": {
      "type": ["object", "null"],
      "additionalProperties": false,
      "required": ["digest", "content_type"],
      "properties": {
        "digest": {"type": "string", "maxLength": 64},
        "content_type": {"type": "string", "maxLength": 32}
      }
    },
    "favicon": {
      "type": ["object", "null"],
      "additionalProperties": false,
      "required": ["digest", "content_type"],
      "properties": {
        "digest": {"type": "string", "maxLength": 64},
        "content_type": {"type": "string", "maxLength": 32}
      }
    }
  }
}"#;

impl Theme {
    /// The schema document, as JSON.
    ///
    /// Public so that the admin API can publish it and the console can render
    /// a form from it rather than repeating the bounds in TypeScript.
    ///
    /// # Panics
    ///
    /// Never: [`SCHEMA`] is a literal in this file and
    /// `the_schema_literal_is_in_the_supported_subset` fails the build if it
    /// stops parsing.
    #[must_use]
    pub fn schema_document() -> Value {
        serde_json::from_str(SCHEMA).expect("the schema literal is valid JSON")
    }

    /// Reads a theme from bytes, bounding them first.
    ///
    /// # Errors
    ///
    /// [`ThemeError::TooLarge`] above [`MAX_DOCUMENT_BYTES`],
    /// [`ThemeError::NotJson`] for bytes that are not JSON, and whatever
    /// [`Theme::from_json`] refuses.
    // fuzz-target: theme_document
    pub fn parse(raw: &str) -> Result<Self, ThemeError> {
        if raw.len() > MAX_DOCUMENT_BYTES {
            return Err(ThemeError::TooLarge);
        }
        let document: Value = serde_json::from_str(raw).map_err(|_| ThemeError::NotJson)?;
        Self::from_json(&document)
    }

    /// Reads a theme from a parsed document: schema first, then values.
    ///
    /// # Errors
    ///
    /// [`ThemeError`], carrying the JSON pointer of the member at fault.
    pub fn from_json(document: &Value) -> Result<Self, ThemeError> {
        let schema = Schema::parse(&Self::schema_document())
            .expect("the theme schema is in the supported subset");
        if let Err(SchemaViolation { path, .. }) = schema.validate(document) {
            return Err(ThemeError::Schema { path });
        }

        // Unwrapping the object is safe only because the schema above asserted
        // it, and that is the order every read below relies on.
        let members = document
            .as_object()
            .ok_or_else(|| ThemeError::Schema { path: "/".into() })?;

        let palette = read_palette(members)?;
        palette.check_contrast()?;

        let font = members
            .get("font")
            .and_then(Value::as_str)
            .and_then(FontStack::parse)
            .ok_or_else(|| ThemeError::Font {
                path: "/font".into(),
            })?;

        Ok(Self {
            palette,
            font,
            radius_px: read_scale(members, "radius_px", &RADIUS_RANGE)?,
            spacing_px: read_scale(members, "spacing_px", &SPACING_RANGE)?,
            product_name: read_product_name(members)?,
            support: read_support(members)?,
            logo: read_asset(members, "logo")?,
            favicon: read_asset(members, "favicon")?,
        })
    }

    /// The document this theme was read from, rebuilt.
    ///
    /// A round trip through [`Theme::from_json`] is the identity, which
    /// `a_round_trip_through_json_keeps_every_token` pins: the store writes
    /// what this returns, and a read that lost a member would be a theme an
    /// administrator saved and did not get.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut document = Map::new();
        let mut palette = Map::new();
        for (name, colour) in self.palette_members() {
            palette.insert(name.to_owned(), Value::String(colour.to_css()));
        }
        document.insert("palette".into(), Value::Object(palette));
        document.insert("font".into(), Value::String(self.font.name().to_owned()));
        document.insert("radius_px".into(), Value::from(self.radius_px));
        document.insert("spacing_px".into(), Value::from(self.spacing_px));
        if let Some(name) = &self.product_name {
            document.insert("product_name".into(), Value::String(name.clone()));
        }

        let mut support = Map::new();
        for (name, url) in [
            ("help_url", self.support.help.as_ref()),
            ("privacy_url", self.support.privacy.as_ref()),
            ("terms_url", self.support.terms.as_ref()),
        ] {
            if let Some(url) = url {
                support.insert(name.to_owned(), Value::String(url.to_string()));
            }
        }
        if !support.is_empty() {
            document.insert("support".into(), Value::Object(support));
        }

        for (name, asset) in [
            ("logo", self.logo.as_ref()),
            ("favicon", self.favicon.as_ref()),
        ] {
            if let Some(asset) = asset {
                let mut reference = Map::new();
                reference.insert("digest".into(), Value::String(asset.digest.clone()));
                reference.insert(
                    "content_type".into(),
                    Value::String(asset.format.content_type().to_owned()),
                );
                document.insert(name.to_owned(), Value::Object(reference));
            }
        }

        Value::Object(document)
    }

    /// The palette, by the names the document uses.
    fn palette_members(&self) -> [(&'static str, Colour); 6] {
        [
            ("background", self.palette.background),
            ("text", self.palette.text),
            ("muted_text", self.palette.muted_text),
            ("accent", self.palette.accent),
            ("accent_text", self.palette.accent_text),
            ("danger", self.palette.danger),
        ]
    }

    /// The colours.
    #[must_use]
    pub const fn palette(&self) -> &Palette {
        &self.palette
    }

    /// The font stack.
    #[must_use]
    pub const fn font(&self) -> FontStack {
        self.font
    }

    /// The corner radius, in CSS pixels.
    #[must_use]
    pub const fn radius_px(&self) -> u32 {
        self.radius_px
    }

    /// The spacing base unit, in CSS pixels.
    #[must_use]
    pub const fn spacing_px(&self) -> u32 {
        self.spacing_px
    }

    /// The product name, if the tenant set one.
    ///
    /// Free text, and the only member of a theme that is: it renders in HTML,
    /// where askama escapes it, and it never reaches CSS.
    #[must_use]
    pub fn product_name(&self) -> Option<&str> {
        self.product_name.as_deref()
    }

    /// The support links.
    #[must_use]
    pub const fn support(&self) -> &SupportLinks {
        &self.support
    }

    /// The logo, if one is stored.
    #[must_use]
    pub const fn logo(&self) -> Option<&AssetRef> {
        self.logo.as_ref()
    }

    /// The favicon, if one is stored.
    #[must_use]
    pub const fn favicon(&self) -> Option<&AssetRef> {
        self.favicon.as_ref()
    }

    /// The same theme with a different logo (or none).
    #[must_use]
    pub fn with_logo(mut self, logo: Option<AssetRef>) -> Self {
        self.logo = logo;
        self
    }

    /// The same theme with a different favicon (or none).
    #[must_use]
    pub fn with_favicon(mut self, favicon: Option<AssetRef>) -> Self {
        self.favicon = favicon;
        self
    }
}

fn read_palette(members: &Map<String, Value>) -> Result<Palette, ThemeError> {
    let object = members
        .get("palette")
        .and_then(Value::as_object)
        .ok_or_else(|| ThemeError::Schema {
            path: "/palette".into(),
        })?;
    let mut colours = BTreeMap::new();
    for name in [
        "background",
        "text",
        "muted_text",
        "accent",
        "accent_text",
        "danger",
    ] {
        let colour = object
            .get(name)
            .and_then(Value::as_str)
            .and_then(Colour::parse)
            .ok_or_else(|| ThemeError::Colour {
                path: format!("/palette/{name}"),
            })?;
        colours.insert(name, colour);
    }
    let get = |name: &str| colours[name];
    Ok(Palette {
        background: get("background"),
        text: get("text"),
        muted_text: get("muted_text"),
        accent: get("accent"),
        accent_text: get("accent_text"),
        danger: get("danger"),
    })
}

fn read_scale(
    members: &Map<String, Value>,
    name: &str,
    range: &std::ops::RangeInclusive<u32>,
) -> Result<u32, ThemeError> {
    let out_of_range = || ThemeError::OutOfRange {
        path: format!("/{name}"),
        min: *range.start(),
        max: *range.end(),
    };
    let value = members
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(out_of_range)?;
    if !range.contains(&value) {
        return Err(out_of_range());
    }
    Ok(value)
}

fn read_product_name(members: &Map<String, Value>) -> Result<Option<String>, ThemeError> {
    let Some(value) = members.get("product_name") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let refuse = || ThemeError::NotPrintable {
        path: "/product_name".into(),
    };
    let text = value.as_str().ok_or_else(refuse)?.trim();
    if text.is_empty() || text.chars().count() > MAX_PRODUCT_NAME_CHARS {
        return Err(refuse());
    }
    // A control character in a name reaches a log line, a `<title>` and an
    // email subject; none of those want a line break or a bidirectional
    // override in the middle of a brand.
    if text.chars().any(char::is_control) {
        return Err(refuse());
    }
    Ok(Some(text.to_owned()))
}

fn read_support(members: &Map<String, Value>) -> Result<SupportLinks, ThemeError> {
    let Some(value) = members.get("support") else {
        return Ok(SupportLinks::default());
    };
    if value.is_null() {
        return Ok(SupportLinks::default());
    }
    let object = value.as_object().ok_or_else(|| ThemeError::Schema {
        path: "/support".into(),
    })?;
    Ok(SupportLinks {
        help: parse_link(object.get("help_url"), "/support/help_url")?,
        privacy: parse_link(object.get("privacy_url"), "/support/privacy_url")?,
        terms: parse_link(object.get("terms_url"), "/support/terms_url")?,
    })
}

fn read_asset(members: &Map<String, Value>, name: &str) -> Result<Option<AssetRef>, ThemeError> {
    let Some(value) = members.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let path = format!("/{name}");
    let object = value
        .as_object()
        .ok_or_else(|| ThemeError::Schema { path: path.clone() })?;
    let format = object
        .get("content_type")
        .and_then(Value::as_str)
        .and_then(ImageFormat::from_content_type)
        .ok_or_else(|| ThemeError::UnsupportedImageType {
            path: format!("{path}/content_type"),
        })?;
    let digest = object
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| ThemeError::Digest {
            path: format!("{path}/digest"),
        })?;
    AssetRef::new(digest, format, &path).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A complete document, as an administrator would send it.
    fn document() -> Value {
        json!({
            "palette": {
                "background": "#ffffff",
                "text": "#111111",
                "muted_text": "#555555",
                "accent": "#2f6fdb",
                "accent_text": "#ffffff",
                "danger": "#c0392b"
            },
            "font": "system-sans",
            "radius_px": 4,
            "spacing_px": 8,
            "product_name": "Acme Identity",
            "support": {
                "help_url": "https://help.example.com/sign-in",
                "privacy_url": "https://example.com/privacy"
            }
        })
    }

    #[test]
    fn a_complete_document_becomes_typed_tokens() {
        let theme = Theme::from_json(&document()).expect("the document is valid");

        assert_eq!(theme.palette().accent().to_css(), "#2f6fdb");
        assert_eq!(theme.font(), FontStack::SystemSans);
        assert_eq!(theme.radius_px(), 4);
        assert_eq!(theme.product_name(), Some("Acme Identity"));
        assert_eq!(
            theme.support().help_url().map(Url::as_str),
            Some("https://help.example.com/sign-in")
        );
    }

    #[test]
    fn the_schema_literal_is_in_the_supported_subset() {
        Schema::parse(&Theme::schema_document())
            .expect("the theme schema uses only the keywords the subset validator understands");
    }

    #[test]
    fn the_default_theme_is_the_palette_the_stylesheet_ships() {
        let theme = Theme::default();

        assert_eq!(theme.palette().background().to_css(), "#ffffff");
        assert_eq!(theme.palette().text().to_css(), "#111111");
        assert_eq!(theme.palette().accent().to_css(), "#2f6fdb");
    }

    /// The bar this module imposes has to be one the shipped default clears,
    /// or the first tenant to save the form it is prefilled with is refused.
    #[test]
    fn the_default_palette_clears_the_bar_it_imposes() {
        Palette::default()
            .check_contrast()
            .expect("the shipped palette meets the minimum it enforces");
    }

    #[test]
    fn every_contrast_pair_names_a_colour_the_palette_has() {
        let palette = Palette::default();
        for (foreground, background) in CONTRAST_PAIRS {
            assert!(
                palette.by_name(foreground).is_some(),
                "{foreground} is not a palette member"
            );
            assert!(
                palette.by_name(background).is_some(),
                "{background} is not a palette member"
            );
        }
    }

    #[test]
    fn a_round_trip_through_json_keeps_every_token() {
        let theme = Theme::from_json(&document()).expect("valid");

        let again = Theme::from_json(&theme.to_json()).expect("what we wrote, we read");

        assert_eq!(theme, again);
    }

    #[test]
    fn a_member_the_schema_does_not_name_is_refused() {
        let mut document = document();
        document["custom_css"] = json!("body{background:url(https://evil.example)}");

        let error = Theme::from_json(&document).expect_err("a theme carries no stylesheet");

        assert!(matches!(error, ThemeError::Schema { .. }), "{error}");
    }

    #[test]
    fn a_colour_that_is_not_six_hex_digits_is_refused_with_its_path() {
        let mut document = document();
        document["palette"]["accent"] = json!("red");

        let error = Theme::from_json(&document).expect_err("named colours are not tokens");

        assert_eq!(error.path(), "/palette/accent");
    }

    #[test]
    fn a_colour_that_is_a_css_expression_is_refused() {
        for hostile in [
            "var(--x)",
            "rgb(0,0,0)",
            "#fff",
            "#ffffff;}body{display:none",
            "url(https://evil.example)",
        ] {
            assert!(
                Colour::parse(hostile).is_none(),
                "{hostile} is not a colour token"
            );
        }
    }

    #[test]
    fn a_font_outside_the_hosted_set_is_refused_with_its_path() {
        let mut document = document();
        document["font"] = json!("Comic Sans MS");

        let error = Theme::from_json(&document).expect_err("a tenant picks from what we host");

        assert_eq!(error.path(), "/font");
    }

    /// The stacks are printed into a `<style>` block, so a family name that
    /// needed a quote — or worse, a `<` — would be a way out of it.
    #[test]
    fn a_font_stack_is_printable_inside_a_style_element() {
        for stack in FontStack::ALL {
            let css = stack.css();
            assert!(css.is_ascii(), "{css} is not ASCII");
            assert!(
                !css.contains(['<', '>', '&', '"', '\'', ';', '{', '}']),
                "{css} carries a character that could leave a declaration"
            );
        }
    }

    #[test]
    fn a_support_link_that_is_not_https_is_refused_with_its_path() {
        let mut document = document();
        document["support"]["help_url"] = json!("http://help.example.com/");

        let error = Theme::from_json(&document).expect_err("cleartext is not a support link");

        assert_eq!(error.path(), "/support/help_url");
        assert!(matches!(error, ThemeError::NotHttps { .. }));
    }

    #[test]
    fn a_scheme_that_runs_is_refused_like_any_other_non_https_scheme() {
        for hostile in [
            "javascript:alert(1)",
            "data:image/svg+xml,<svg onload=alert(1)>",
            "file:///etc/passwd",
            "https://user:pass@example.com/",
            "not a url at all",
        ] {
            let mut document = document();
            document["support"]["privacy_url"] = json!(hostile);

            let error = Theme::from_json(&document).expect_err("{hostile} is not a support link");

            assert_eq!(error.path(), "/support/privacy_url", "{hostile}");
        }
    }

    #[test]
    fn text_below_wcag_aa_on_its_background_is_refused() {
        let mut document = document();
        // #999999 on white measures about 2.85:1.
        document["palette"]["text"] = json!("#999999");

        let error = Theme::from_json(&document).expect_err("AA is not negotiable here");

        let ThemeError::Contrast { ratio, .. } = error else {
            panic!("the refusal names the ratio it measured: {error}")
        };
        assert!(ratio < MIN_CONTRAST_RATIO, "measured {ratio}");
    }

    #[test]
    fn a_button_label_below_wcag_aa_on_its_own_accent_is_refused() {
        let mut document = document();
        // White on yellow: the classic unreadable primary button.
        document["palette"]["accent"] = json!("#ffff00");

        let error = Theme::from_json(&document).expect_err("white on yellow is unreadable");

        assert_eq!(error.path(), "/palette/accent_text");
    }

    #[test]
    fn contrast_is_the_wcag_ratio_and_not_something_that_resembles_it() {
        let black = Colour::parse("#000000").expect("valid");
        let white = Colour::parse("#ffffff").expect("valid");

        assert!(
            (Colour::contrast_ratio(black, white) - 21.0).abs() < 0.01,
            "black on white is 21:1"
        );
        assert!(
            (Colour::contrast_ratio(white, white) - 1.0).abs() < 0.01,
            "a colour on itself is 1:1"
        );
        assert!(
            (Colour::contrast_ratio(white, black) - Colour::contrast_ratio(black, white)).abs()
                < 1e-9,
            "the ratio is symmetric"
        );
    }

    #[test]
    fn a_document_larger_than_the_bound_is_refused_before_it_is_parsed() {
        let padding = "a".repeat(MAX_DOCUMENT_BYTES + 1);

        let error = Theme::parse(&padding).expect_err("bounded first");

        assert_eq!(error, ThemeError::TooLarge);
    }

    #[test]
    fn a_scale_value_outside_its_range_is_refused_with_its_path() {
        for (member, value) in [("radius_px", 9001), ("spacing_px", 0)] {
            let mut document = document();
            document[member] = json!(value);

            let error = Theme::from_json(&document).expect_err("the scale is bounded");

            assert_eq!(error.path(), format!("/{member}"));
        }
    }

    #[test]
    fn a_product_name_with_a_control_character_is_refused() {
        let mut document = document();
        document["product_name"] = json!("Acme\u{0}Identity");

        let error = Theme::from_json(&document).expect_err("a name is printable text");

        assert_eq!(error.path(), "/product_name");
    }

    #[test]
    fn svg_is_not_a_content_type_this_model_can_hold() {
        assert_eq!(ImageFormat::from_content_type("image/svg+xml"), None);
        assert_eq!(
            ImageFormat::from_content_type("image/png"),
            Some(ImageFormat::Png)
        );
    }

    #[test]
    fn a_logo_reference_names_a_digest_and_a_raster_format() {
        let mut document = document();
        document["logo"] = json!({
            "digest": "a".repeat(DIGEST_HEX_LEN),
            "content_type": "image/webp",
        });

        let theme = Theme::from_json(&document).expect("a logo is a reference, not bytes");

        assert_eq!(
            theme.logo().map(AssetRef::format),
            Some(ImageFormat::Webp),
            "the reference keeps the format the bytes were re-encoded to"
        );
    }

    #[test]
    fn a_logo_reference_carrying_svg_is_refused_with_its_path() {
        let mut document = document();
        document["logo"] = json!({
            "digest": "a".repeat(DIGEST_HEX_LEN),
            "content_type": "image/svg+xml",
        });

        let error = Theme::from_json(&document).expect_err("SVG is a script container");

        assert_eq!(error.path(), "/logo/content_type");
    }

    #[test]
    fn a_digest_that_is_not_hex_is_refused_with_its_path() {
        for hostile in ["../../etc/passwd", "A".repeat(64).as_str(), "abc"] {
            let mut document = document();
            document["favicon"] = json!({
                "digest": hostile,
                "content_type": "image/png",
            });

            let error = Theme::from_json(&document).expect_err("a digest is 64 lowercase hex");

            assert_eq!(error.path(), "/favicon/digest", "{hostile}");
        }
    }

    /// The document is the store's format, so a member the reader ignores is a
    /// setting an administrator saved and did not get.
    #[test]
    fn every_schema_member_is_read_back_by_the_reader() {
        let schema = Theme::schema_document();
        let members: Vec<&String> = schema["properties"]
            .as_object()
            .expect("properties is an object")
            .keys()
            .collect();

        let mut document = document();
        document["logo"] = json!({"digest": "b".repeat(64), "content_type": "image/png"});
        document["favicon"] = json!({"digest": "c".repeat(64), "content_type": "image/jpeg"});
        let theme = Theme::from_json(&document).expect("valid");
        let written = theme.to_json();

        for member in members {
            assert!(
                written.get(member).is_some(),
                "{member} is in the schema and not in what the reader writes back"
            );
        }
    }
}
