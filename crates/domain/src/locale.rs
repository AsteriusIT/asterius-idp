//! Which language a page is written in, and how a request chooses one.
//!
//! Three parties have an opinion about the language an end-user sees, and this
//! module is the one place that ranks them:
//!
//! 1. the client, through OIDC Core §3.1.2.1's `ui_locales` — "End-User's
//!    preferred languages … ordered by preference";
//! 2. the browser, through RFC 9110 §12.5.4's `Accept-Language`;
//! 3. the tenant, through its configured default.
//!
//! The order is not arbitrary. `ui_locales` is the only one of the three that
//! carries a *deliberate* statement about this sign-in — a relying party that
//! runs its own French page and sends the user here has said which language the
//! journey is in — while `Accept-Language` describes the person's device and
//! the tenant default describes the deployment. Each layer is consulted only
//! when the one above it names nothing this server can render.
//!
//! # Nothing here refuses a request
//!
//! OIDC Core §3.1.2.1 is explicit that `ui_locales` is a hint: "If the OP does
//! not support one of the requested languages, it MUST NOT return an error."
//! So [`UiLocales::parse`] drops what it cannot use and [`negotiate`] falls
//! through to the next layer. There is no error type on the negotiation path
//! at all, which is the strongest way to state the rule: a language preference
//! cannot fail a sign-in, so it cannot be made to fail one by an attacker
//! either.
//!
//! # Why a tag is matched on its primary subtag
//!
//! RFC 4647 §3.4's lookup scheme truncates a tag from the right until it
//! matches something available: `fr-CA` finds `fr`. This server offers whole
//! languages rather than regional variants, so the whole of that algorithm here
//! is "compare the primary subtag", and `fr-CA fr en` therefore renders French
//! at the first preference rather than the second.

use std::fmt;

/// A language this server has words in.
///
/// A closed enum rather than a tag string, because everything downstream — the
/// message catalogue, the `lang` attribute, the discovery document's
/// `ui_locales_supported` — has to agree about what "supported" means, and a
/// string lets two of them disagree. Adding a language is adding a variant, and
/// the compiler then names every table that has to grow.
///
/// Deliberately *not* `#[non_exhaustive]`: the catalogue in `asterius_web::i18n`
/// matches on this enum, so adding a language has to break every table that has
/// to grow rather than fall through a wildcard arm and serve English under a
/// `lang` attribute that says otherwise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Locale {
    /// English.
    #[default]
    English,
    /// French.
    French,
}

impl Locale {
    /// Every language this build renders.
    pub const SUPPORTED: [Self; 2] = [Self::English, Self::French];

    /// The BCP 47 tags of [`Self::SUPPORTED`], for `ui_locales_supported`.
    ///
    /// Asserted equal to the enum in this module's tests rather than trusted:
    /// OIDC Discovery §3 makes that member a promise, and a deployment that
    /// advertised a language it has no catalogue for would be inviting clients
    /// to ask for one.
    pub const SUPPORTED_TAGS: [&'static str; 2] = ["en", "fr"];

    /// The BCP 47 tag, which is also the `lang` attribute.
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::French => "fr",
        }
    }

    /// The language a requested tag selects, if this build has one.
    ///
    /// RFC 4647 §3.4 lookup, collapsed: `fr-CA`, `FR` and `fr` all select
    /// French, `de` selects nothing. Matching is ASCII-case-insensitive
    /// because BCP 47 §2.1.1 says case carries no meaning.
    #[must_use]
    pub fn matching(tag: &str) -> Option<Self> {
        let primary = tag.split('-').next().unwrap_or(tag);
        Self::SUPPORTED
            .into_iter()
            .find(|locale| primary.eq_ignore_ascii_case(locale.as_tag()))
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_tag())
    }
}

/// BCP 47's basic shape: `[A-Za-z]{1,8}` followed by alphanumeric subtags
/// joined with `-` (RFC 5646 §2.1).
///
/// A shape check and not a registry lookup. What has to be true is that a value
/// carried through this server is not arbitrary text — it is stored on a pushed
/// request and read back at consent — not that somebody speaks it.
#[must_use]
pub fn is_language_tag(tag: &str) -> bool {
    let mut subtags = tag.split('-');
    let Some(primary) = subtags.next() else {
        return false;
    };
    if !(1..=8).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    subtags.all(|subtag| {
        (1..=8).contains(&subtag.len()) && subtag.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// The languages a client asked the pages to be in (OIDC Core §3.1.2.1).
///
/// A wrapper rather than a bare `Vec<String>` because the order *is* the
/// meaning, exactly as for `claims_locales` (§5.2): "ordered by preference" is
/// the whole of the parameter, and a set would lose it silently.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UiLocales(Vec<String>);

impl UiLocales {
    /// The most languages one request may name.
    ///
    /// Extra entries are dropped rather than refused, because §3.1.2.1 forbids
    /// an error: truncating a list degrades a preference where refusing would
    /// deny a sign-in. Eight is past the point where a further preference can
    /// change the answer for a server that offers two languages, and it bounds
    /// what a row carries from the push to the consent screen.
    pub const MAX: usize = 8;

    /// The longest single tag kept.
    ///
    /// A well-formed tag is far shorter; this only stops a megabyte of `a-a-a…`
    /// from being stored because it happened to be shaped like one.
    pub const MAX_TAG_BYTES: usize = 64;

    /// Parses the space-delimited parameter.
    ///
    /// Anything not shaped like a BCP 47 tag is dropped, never refused
    /// (§3.1.2.1). Tags this build has no words for are *kept* here and
    /// resolved by [`negotiate`]: what a client asked for is a fact about the
    /// request, and a stored `ja` that this server ignores today is the record
    /// that lets tomorrow's catalogue serve it.
    // fuzz-target: ui_locales_parse
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        Self(
            raw.unwrap_or_default()
                .split_whitespace()
                .filter(|tag| tag.len() <= Self::MAX_TAG_BYTES && is_language_tag(tag))
                .take(Self::MAX)
                .map(ToOwned::to_owned)
                .collect(),
        )
    }

    /// Rebuilds the list from stored tags.
    ///
    /// The same filter and the same bound as [`UiLocales::parse`], because a
    /// row is not more trustworthy than a form field: these tags were written
    /// by an earlier build, or by an operator with `psql`, and they are read
    /// back to choose what a person is shown.
    #[must_use]
    pub fn from_tags<I, S>(tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self(
            tags.into_iter()
                .filter(|tag| {
                    tag.as_ref().len() <= Self::MAX_TAG_BYTES && is_language_tag(tag.as_ref())
                })
                .take(Self::MAX)
                .map(|tag| tag.as_ref().to_owned())
                .collect(),
        )
    }

    /// The tags, most preferred first.
    #[must_use]
    pub fn preferences(&self) -> &[String] {
        &self.0
    }

    /// Whether the client expressed no usable preference.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The parameter as it would be sent again, or `None` when there is none.
    ///
    /// Rebuilt from the parsed tags rather than kept as the client's string, so
    /// that what this server passes on is what it understood.
    #[must_use]
    pub fn as_parameter(&self) -> Option<String> {
        if self.0.is_empty() {
            None
        } else {
            Some(self.0.join(" "))
        }
    }
}

/// The most elements read from one `Accept-Language` field.
///
/// RFC 9110 §12.5.4 puts no bound on the list, and the header arrives on pages
/// reachable before authentication. Anything past this cannot change the answer
/// for a two-language server, and a field that reaches this many entries
/// without naming one of them is not going to.
const MAX_ACCEPT_LANGUAGE_ELEMENTS: usize = 32;

/// Chooses the language a page is rendered in.
///
/// The three layers of the module documentation, in order: `ui_locales` first,
/// then `Accept-Language`, then the tenant's default. Nothing here fails; a
/// request that names only languages this build has no words for gets the
/// tenant's default, which is what OIDC Core §3.1.2.1 requires instead of an
/// error.
#[must_use]
pub fn negotiate(
    ui_locales: &UiLocales,
    accept_language: Option<&str>,
    tenant_default: Locale,
) -> Locale {
    for tag in ui_locales.preferences() {
        if let Some(locale) = Locale::matching(tag) {
            return locale;
        }
    }
    accept_language
        .and_then(from_accept_language)
        .unwrap_or(tenant_default)
}

/// The best supported language named by an `Accept-Language` field.
///
/// RFC 9110 §12.5.4: a comma-separated list of ranges, each optionally weighted
/// with `;q=`, default weight 1, and `q=0` meaning "not acceptable". A
/// malformed weight makes the *element* unusable rather than the field: this is
/// a header, it is often written by something other than a browser, and the
/// caller has a default to fall back to.
///
/// `*` is ignored. It means "anything else is acceptable", which is exactly the
/// case the tenant default already answers.
fn from_accept_language(raw: &str) -> Option<Locale> {
    let mut best: Option<(u16, Locale)> = None;
    for element in raw.split(',').take(MAX_ACCEPT_LANGUAGE_ELEMENTS) {
        let mut parts = element.split(';');
        let Some(range) = parts.next().map(str::trim) else {
            continue;
        };
        let Some(locale) = Locale::matching(range) else {
            continue;
        };
        let Some(weight) = quality(parts) else {
            continue;
        };
        // Zero is a refusal (§12.5.4), not a weak preference.
        if weight == 0 {
            continue;
        }
        // Strictly greater, so that equal weights keep the field's own order —
        // which is the order the client wrote them in.
        if best.is_none_or(|(best_weight, _)| weight > best_weight) {
            best = Some((weight, locale));
        }
    }
    best.map(|(_, locale)| locale)
}

/// The `q=` weight of one element, in thousandths.
///
/// Integer thousandths rather than a float: RFC 9110 §12.4.2 allows at most
/// three decimal places, so thousandths are exact and comparing two weights is
/// an integer comparison rather than a float one.
///
/// `None` means the element carried a `q` this function will not read, and the
/// caller drops the element.
fn quality<'a>(parameters: impl Iterator<Item = &'a str>) -> Option<u16> {
    let mut weight = 1000_u16;
    for parameter in parameters {
        let Some((name, value)) = parameter.split_once('=') else {
            // §12.5.4 allows extension parameters after `q`; one without a
            // value says nothing about quality.
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("q") {
            continue;
        }
        weight = thousandths(value.trim())?;
    }
    Some(weight)
}

/// `1`, `1.0`, `0`, `0.8`, `0.812` — as thousandths, or `None` if it is not one
/// of those.
fn thousandths(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let whole: u16 = match whole {
        "0" => 0,
        "1" => 1000,
        _ => return None,
    };
    if fraction.is_empty() {
        return Some(whole);
    }
    if fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut digits = 0_u16;
    for byte in fraction.bytes() {
        digits = digits * 10 + u16::from(byte - b'0');
    }
    // Left-pad to thousandths: "8" is 800, "81" is 810, "812" is 812.
    for _ in fraction.len()..3 {
        digits *= 10;
    }
    let total = whole.checked_add(digits)?;
    // `1.001` and anything else above 1 is not a quality value.
    (total <= 1000).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_advertised_tags_are_the_supported_locales() {
        let from_enum: Vec<&str> = Locale::SUPPORTED.iter().map(|l| l.as_tag()).collect();

        assert_eq!(from_enum, Locale::SUPPORTED_TAGS.to_vec());
    }

    /// OIDC Core §3.1.2.1: preferences are ordered, and a regional variant is
    /// looked up by RFC 4647 §3.4 truncation.
    #[test]
    fn the_first_understood_preference_wins_including_a_regional_variant() {
        let asked = UiLocales::parse(Some("fr-CA fr en"));

        assert_eq!(negotiate(&asked, None, Locale::English), Locale::French);
    }

    /// §3.1.2.1: "If the OP does not support one of the requested languages, it
    /// MUST NOT return an error."
    #[test]
    fn unsupported_languages_fall_through_instead_of_failing() {
        let asked = UiLocales::parse(Some("ja-Kana-JP de-CH"));

        assert_eq!(negotiate(&asked, None, Locale::English), Locale::English);
    }

    #[test]
    fn a_malformed_tag_is_dropped_and_the_rest_of_the_list_is_kept() {
        let asked = UiLocales::parse(Some("fr_CA <script> fr"));

        assert_eq!(asked.preferences(), ["fr"]);
    }

    #[test]
    fn no_more_than_eight_preferences_are_kept() {
        let asked = UiLocales::parse(Some("aa bb cc dd ee ff gg hh ii jj"));

        assert_eq!(asked.preferences().len(), UiLocales::MAX);
    }

    #[test]
    fn stored_tags_are_filtered_like_a_parameter() {
        let restored = UiLocales::from_tags(["fr", "not a tag", "en"]);

        assert_eq!(restored.preferences(), ["fr", "en"]);
    }

    #[test]
    fn the_browser_is_asked_only_when_the_client_named_nothing_usable() {
        let asked = UiLocales::parse(Some("de"));

        assert_eq!(
            negotiate(&asked, Some("fr-CA,fr;q=0.9,en;q=0.8"), Locale::English),
            Locale::French
        );
    }

    #[test]
    fn the_client_outranks_the_browser() {
        let asked = UiLocales::parse(Some("en"));

        assert_eq!(
            negotiate(&asked, Some("fr"), Locale::English),
            Locale::English
        );
    }

    #[test]
    fn the_tenant_default_is_the_last_word() {
        assert_eq!(
            negotiate(&UiLocales::default(), Some("de,ja"), Locale::French),
            Locale::French
        );
    }

    /// RFC 9110 §12.5.4: the highest weight wins, whatever the order.
    #[test]
    fn accept_language_is_read_by_weight_and_not_by_position() {
        assert_eq!(
            negotiate(
                &UiLocales::default(),
                Some("en;q=0.2, fr;q=0.9"),
                Locale::English
            ),
            Locale::French
        );
    }

    /// §12.5.4: `q=0` means "not acceptable".
    #[test]
    fn a_refused_language_is_not_chosen() {
        assert_eq!(
            negotiate(&UiLocales::default(), Some("fr;q=0"), Locale::English),
            Locale::English
        );
    }

    #[test]
    fn a_wildcard_leaves_the_choice_to_the_tenant() {
        assert_eq!(
            negotiate(&UiLocales::default(), Some("*"), Locale::French),
            Locale::French
        );
    }

    #[test]
    fn a_header_that_is_not_a_list_of_ranges_changes_nothing() {
        assert_eq!(
            negotiate(
                &UiLocales::default(),
                Some("\u{1}\u{0}garbage;;;q=q"),
                Locale::English
            ),
            Locale::English
        );
    }

    #[test]
    fn equal_weights_keep_the_order_the_client_wrote() {
        assert_eq!(
            negotiate(&UiLocales::default(), Some("fr, en"), Locale::English),
            Locale::French
        );
    }

    #[test]
    fn the_parameter_is_rebuilt_from_what_was_understood() {
        let asked = UiLocales::parse(Some("fr-CA nonsense_tag en"));

        assert_eq!(asked.as_parameter().as_deref(), Some("fr-CA en"));
        assert_eq!(UiLocales::default().as_parameter(), None);
    }

    #[test]
    fn quality_values_are_exact_thousandths() {
        assert_eq!(thousandths("1"), Some(1000));
        assert_eq!(thousandths("1.0"), Some(1000));
        assert_eq!(thousandths("0.8"), Some(800));
        assert_eq!(thousandths("0.81"), Some(810));
        assert_eq!(thousandths("0.812"), Some(812));
        assert_eq!(thousandths("0"), Some(0));
        assert_eq!(thousandths("1.001"), None);
        assert_eq!(thousandths("2"), None);
        assert_eq!(thousandths("0.1234"), None);
        assert_eq!(thousandths(""), None);
    }
}
