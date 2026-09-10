//! What a handler needs in order to render a page in the right language.
//!
//! The negotiation itself is [`asterius_domain::locale::negotiate`] and the
//! words are `asterius_web::i18n`. This module is the seam between them and an
//! HTTP request: it holds the two things a handler cannot compute — the
//! tenant's configured default and its overridden wording, both out of
//! `TenantSettings` — beside the one thing only the transport knows, the
//! `Accept-Language` field.
//!
//! # Nothing here fails
//!
//! A tenant whose settings cannot be read still gets pages: the default
//! language and the built-in wording. That is the opposite of the rule
//! `capabilities_for` follows, where a failed read must not fall back to the
//! deployment's flags, and the difference is what the value decides. A
//! capability that silently reverted would re-enable something a tenant
//! switched off; a language that silently reverts shows somebody English.
//! OIDC Core §3.1.2.1 says the same thing from the client's side — an
//! unsupported `ui_locales` "MUST NOT return an error" — and a page that
//! refused to render because a settings row was unreadable would be a sign-in
//! outage caused by a translation.

use asterius_domain::locale::{Locale, UiLocales, negotiate};
use asterius_domain::{MessageOverrides, TenantSettings};
use asterius_web::i18n::Catalog;
use axum::http::{HeaderMap, header};

/// The language a tenant's pages fall back to, and the words it has changed.
///
/// Built once per request, beside the other per-tenant values
/// `crate::http::protocol` resolves.
#[derive(Debug, Clone, Default)]
pub struct PageLanguage {
    /// The tenant's configured default: the last layer of the negotiation.
    default: Locale,
    /// The tenant's own wording, already validated as text by the domain.
    overrides: MessageOverrides,
    /// RFC 9110 §12.5.4, as the browser sent it.
    accept_language: Option<String>,
}

impl PageLanguage {
    /// Reads what this request and this tenant have to say about language.
    ///
    /// `None` settings is a deployment with no per-tenant settings wired, which
    /// is the built-in default and no overrides.
    #[must_use]
    pub fn new(settings: Option<&TenantSettings>, headers: &HeaderMap) -> Self {
        Self {
            default: settings.map_or_else(Locale::default, TenantSettings::default_locale),
            overrides: settings
                .map(|settings| settings.messages().clone())
                .unwrap_or_default(),
            accept_language: headers
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
        }
    }

    /// The language this request gets, given what the client asked for.
    #[must_use]
    pub fn negotiate(&self, asked: &UiLocales) -> Locale {
        negotiate(asked, self.accept_language.as_deref(), self.default)
    }

    /// The words of a language, with this tenant's substitutions applied.
    #[must_use]
    pub fn catalog(&self, locale: Locale) -> Catalog {
        Catalog::with_overrides(locale, &self.overrides)
    }

    /// Negotiation and catalogue in one step, for a handler that has no reason
    /// to name the language in between.
    #[must_use]
    pub fn for_request(&self, asked: &UiLocales) -> Catalog {
        self.catalog(self.negotiate(asked))
    }
}

/// The catalogue of a page whose words are still English literals.
///
/// `ast-ndk.5` moved the authorization journey — login and step-up, consent,
/// the error page, the two logout pages — into `asterius_web::i18n`. The
/// passkey enrolment page, the form-post page, the device pages and the
/// account-recovery pages still hold their strings in their templates, so they
/// are rendered with this rather than with a negotiated language: a page whose
/// `lang` says `fr` over English words is worse for a screen reader than one
/// that admits it is English (WCAG 2.2 SC 3.1.1).
///
/// Every use of this is a page left to translate. It goes away with the last
/// one.
pub static UNTRANSLATED: Catalog = Catalog::new(Locale::English);

/// The `ui_locales` of a pushed request, as `crates/server/src/http/par.rs`
/// stored them.
///
/// Read back through [`UiLocales::from_tags`] rather than trusted: the row was
/// written by an earlier build or edited by an operator, and these tags choose
/// what a person is shown.
#[must_use]
pub fn stored_ui_locales(parameters: &serde_json::Value) -> UiLocales {
    let Some(tags) = parameters.get("ui_locales").and_then(|v| v.as_array()) else {
        return UiLocales::default();
    };
    UiLocales::from_tags(tags.iter().filter_map(|tag| tag.as_str()))
}

/// The `ui_locales` of a form or query, before anything has been validated.
///
/// The end-session endpoint reads it here rather than from the parsed request,
/// because the pages it renders include the ones it draws when the request did
/// *not* parse (RP-Initiated Logout §4) — and a person who cannot be told what
/// went wrong should at least be told it in their language. Nothing is trusted:
/// [`UiLocales::parse`] keeps only what is shaped like a language tag, and a
/// duplicate parameter takes the first spelling, as everywhere else in this
/// server.
#[must_use]
pub fn form_ui_locales(pairs: &[(String, String)]) -> UiLocales {
    UiLocales::parse(
        pairs
            .iter()
            .find(|(name, _)| name == "ui_locales")
            .map(|(_, value)| value.as_str()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_web::MessageKey;
    use serde_json::json;

    fn headers(accept_language: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = accept_language {
            headers.insert(
                header::ACCEPT_LANGUAGE,
                value.parse().expect("a header value"),
            );
        }
        headers
    }

    /// The middle layer of OIDC Core §3.1.2.1's fallback, over HTTP.
    #[test]
    fn the_browsers_field_is_read_when_the_client_asked_for_nothing() {
        // Arrange
        let language = PageLanguage::new(None, &headers(Some("fr-CA,fr;q=0.9,en;q=0.8")));

        // Act
        let locale = language.negotiate(&UiLocales::default());

        // Assert
        assert_eq!(locale, Locale::French);
    }

    #[test]
    fn the_clients_parameter_outranks_the_browsers_field() {
        // Arrange
        let language = PageLanguage::new(None, &headers(Some("fr")));

        // Act
        let locale = language.negotiate(&UiLocales::parse(Some("en")));

        // Assert
        assert_eq!(locale, Locale::English);
    }

    #[test]
    fn the_tenants_default_is_reached_when_neither_names_a_language() {
        // Arrange
        let settings = TenantSettings::default().with_default_locale(Locale::French);
        let language = PageLanguage::new(Some(&settings), &headers(Some("de")));

        // Act
        let locale = language.negotiate(&UiLocales::parse(Some("ja")));

        // Assert
        assert_eq!(locale, Locale::French);
    }

    #[test]
    fn a_header_that_is_not_utf8_is_no_preference_rather_than_an_error() {
        // Arrange
        let mut raw = HeaderMap::new();
        raw.insert(
            header::ACCEPT_LANGUAGE,
            axum::http::HeaderValue::from_bytes(&[0xff, 0xfe]).expect("a header value"),
        );
        let language = PageLanguage::new(None, &raw);

        // Act
        let locale = language.negotiate(&UiLocales::default());

        // Assert
        assert_eq!(locale, Locale::English);
    }

    #[test]
    fn a_tenants_wording_reaches_the_catalogue() {
        // Arrange
        let overrides =
            MessageOverrides::from_pairs([("consent.allow", "Continuer")]).expect("plain text");
        let settings = TenantSettings::default().with_messages(overrides);
        let language = PageLanguage::new(Some(&settings), &headers(None));

        // Act
        let catalog = language.catalog(Locale::French);

        // Assert
        assert_eq!(catalog.get(MessageKey::ConsentAllow), "Continuer");
    }

    #[test]
    fn the_form_parameter_is_read_before_the_request_is_validated() {
        // Arrange
        let pairs = vec![
            ("ui_locales".to_owned(), "fr-CA fr".to_owned()),
            ("ui_locales".to_owned(), "en".to_owned()),
        ];

        // Act
        let asked = form_ui_locales(&pairs);

        // Assert
        assert_eq!(asked.preferences(), ["fr-CA", "fr"]);
        assert!(form_ui_locales(&[]).is_empty());
    }

    #[test]
    fn the_stored_parameter_is_read_back_and_filtered() {
        // Arrange
        let parameters = json!({ "ui_locales": ["fr-CA", "nonsense_tag", "en"] });

        // Act
        let asked = stored_ui_locales(&parameters);

        // Assert
        assert_eq!(asked.preferences(), ["fr-CA", "en"]);
        assert!(stored_ui_locales(&json!({})).is_empty());
    }
}
