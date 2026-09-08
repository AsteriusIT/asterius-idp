//! The pages a user sees, and the rule that they escape everything.
//!
//! Every page is an askama template with autoescaping on, rendered through
//! [`crate::Document`] so that the CSP nonce reaches the markup and the header
//! from the same value.
//!
//! # What is untrusted here
//!
//! Nearly all of it. A `client_name` comes from a registration document, a
//! `login_hint` and a `state` come from an authorization request, a scope
//! description may come from tenant configuration. None of it is this server's
//! text, and all of it lands in HTML.
//!
//! askama escapes by default for `.html` templates, so the defence is the
//! absence of `|safe` rather than the presence of a call. There is exactly one
//! `|safe` in the tree — the CSP nonce attribute, which this crate generates
//! and which is base64url by construction — and `crate::source_audit` fails the
//! build if a second appears.
//!
//! # No JavaScript
//!
//! Not a preference. Every page must work with scripting disabled
//! (`ast-2vk.1`), and a tree with no `<script>` in it is the only version of
//! `script-src 'nonce-…' 'strict-dynamic'` that cannot be got wrong. The
//! source audit asserts the absence.

use crate::csp::Nonce;
use askama::Template;

/// A scope, as shown on the consent screen.
///
/// The description is separate from the name because a user consents to a
/// meaning, not to an identifier: "read your payment history" is a decision,
/// `payments:read` is a token. Both are rendered — the name so that a
/// technical user can check what was actually asked for.
#[derive(Debug, Clone)]
pub struct ScopeLine {
    /// The scope token, as it appeared in the request.
    pub name: String,
    /// What it means, in the user's language.
    pub description: String,
}

/// The sign-in page.
#[derive(Debug, Template)]
#[template(path = "login.html")]
pub struct LoginPage<'a> {
    /// BCP 47 tag for the `lang` attribute.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// `login_hint` from the request, prefilled into the username field.
    ///
    /// Attacker-influenced: a client chooses it. It is escaped like everything
    /// else, and it is only ever a *prefill* — it does not identify the user
    /// and does not survive into the session.
    pub login_hint: Option<&'a str>,
    /// A previous failure, if this is a retry.
    ///
    /// Fixed strings chosen by this server, never a reason echoed from input.
    pub message: Option<&'a str>,
    /// The CSP nonce attribute, rendered raw. See the module docs.
    pub nonce_attribute: String,
}

/// The consent screen.
#[derive(Debug, Template)]
#[template(path = "consent.html")]
pub struct ConsentPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// The client's registered name. Attacker-chosen at registration time.
    pub client_name: &'a str,
    /// Who is signed in, so a user on a shared machine can see it is them.
    pub username: &'a str,
    /// What is being asked for.
    pub scopes: Vec<ScopeLine>,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
}

/// The error page.
///
/// One page for every failure a browser can reach. The message is one of a
/// fixed set and the correlation id points at a log line — see
/// [`crate::interaction::correlation_id`].
#[derive(Debug, Template)]
#[template(path = "error.html")]
pub struct ErrorPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// A generic description of what went wrong.
    pub message: &'a str,
    /// What to quote to support.
    pub correlation_id: &'a str,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
}

/// Renders a page, or an empty document if it somehow cannot.
///
/// A template that fails to render is a bug, not a runtime condition: every
/// value in these types is already a `String`, so there is nothing left to
/// fail on. Returning an empty body beats panicking on a request path, and the
/// caller's status still reaches the browser.
///
/// It lives here rather than in the server so that askama stays an
/// implementation detail of this crate — a handler should not have to name the
/// templating engine to render a page.
pub fn render<T: Template>(page: &T) -> String {
    page.render().unwrap_or_else(|error| {
        tracing::error!(%error, "a template failed to render");
        String::new()
    })
}

/// Builds the `nonce="…"` attribute for a template.
///
/// A free function rather than a method so that the one `|safe` in the
/// templates has an obvious, greppable source.
#[must_use]
pub fn nonce_attribute(nonce: &Nonce) -> String {
    nonce.attribute()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csp::Nonce;

    /// Values a client or a request can choose, each of which breaks out of
    /// HTML if it is not escaped.
    const HOSTILE: &[&str] = &[
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "' onerror='alert(1)",
        "\" onmouseover=\"alert(1)",
        "</title><script>alert(1)</script>",
        "</style><script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "&lt;script&gt;",
        "</textarea><svg onload=alert(1)>",
        "\u{0}<script>",
    ];

    /// A fixed nonce for template tests.
    ///
    /// Not `Nonce::generate()`: `source_audit` requires that a nonce is drawn
    /// only by the document middleware, and that rule is worth more than the
    /// convenience of calling it here. The fixture lives in `csp`, which the
    /// audit exempts as the module that defines the type.
    fn nonce() -> Nonce {
        Nonce::fixed_for_test("test-nonce-value")
    }

    /// Nothing hostile survives into the markup as markup.
    ///
    /// The assertion is deliberately blunt: after rendering, the page must not
    /// contain `<script`, an `onerror=` or an `onmouseover=` that the fixture
    /// put there. askama escapes by default, so this is really a test that no
    /// template gained a `|safe` on a request value.
    #[test]
    fn every_untrusted_value_on_the_login_page_is_escaped() {
        for hostile in HOSTILE {
            let nonce = nonce();
            let page = LoginPage {
                locale: "en",
                tenant_name: hostile,
                action: "/interaction/x/login",
                csrf: hostile,
                login_hint: Some(hostile),
                message: Some(hostile),
                nonce_attribute: nonce_attribute(&nonce),
            };
            let html = page.render().expect("render");
            assert_no_injection(&html, hostile);
        }
    }

    #[test]
    fn every_untrusted_value_on_the_consent_page_is_escaped() {
        for hostile in HOSTILE {
            let nonce = nonce();
            let page = ConsentPage {
                locale: "en",
                tenant_name: hostile,
                client_name: hostile,
                username: hostile,
                scopes: vec![ScopeLine {
                    name: (*hostile).to_owned(),
                    description: (*hostile).to_owned(),
                }],
                action: "/interaction/x/consent",
                csrf: hostile,
                nonce_attribute: nonce_attribute(&nonce),
            };
            let html = page.render().expect("render");
            assert_no_injection(&html, hostile);
        }
    }

    #[test]
    fn every_untrusted_value_on_the_error_page_is_escaped() {
        for hostile in HOSTILE {
            let nonce = nonce();
            let page = ErrorPage {
                locale: "en",
                tenant_name: hostile,
                message: hostile,
                correlation_id: hostile,
                nonce_attribute: nonce_attribute(&nonce),
            };
            let html = page.render().expect("render");
            assert_no_injection(&html, hostile);
        }
    }

    /// Escaping means the raw value never reaches the markup verbatim.
    ///
    /// The first version of this banned the substrings `onerror=` and
    /// `<script` outright, and was wrong: askama renders `' onerror='alert(1)`
    /// as `&#39; onerror=&#39;alert(1)`, which is inert text in a text node —
    /// the quotes that would have closed the attribute are gone. Banning the
    /// substring tests the wrong thing and fails on correct output.
    ///
    /// What escaping actually guarantees is this: every character that could
    /// change the parse — `< > " ' &` — is replaced, so an input containing
    /// one cannot appear verbatim. That is the property, and it is exact.
    fn assert_no_injection(html: &str, hostile: &str) {
        const DANGEROUS: [char; 5] = ['<', '>', '"', '\'', '&'];

        if hostile.contains(DANGEROUS) {
            assert!(
                !html.contains(hostile),
                "the raw value reached the markup unescaped: {hostile:?}"
            );
        }

        // No tag was opened by the input. Checked separately because it is the
        // outcome everything else exists to prevent, and because a future
        // template that interpolated into a `<script>` block would still fail
        // the verbatim check above only by luck.
        assert!(
            !html.to_lowercase().contains("<script"),
            "a script element appeared for input {hostile:?}"
        );

        // Escaped rather than dropped: a template that silently discarded the
        // value would satisfy every check above while losing the user's data.
        if hostile.contains('<') {
            assert!(
                html.contains("&#60;") || html.contains("&lt;"),
                "the value vanished rather than being escaped: {hostile:?}"
            );
        }
    }

    /// The nonce reaches the markup, and it is the one that was passed.
    #[test]
    fn the_page_carries_the_nonce_it_was_given() {
        let nonce = nonce();
        let page = ErrorPage {
            locale: "en",
            tenant_name: "Demo",
            message: "Something went wrong.",
            correlation_id: "abc123",
            nonce_attribute: nonce_attribute(&nonce),
        };
        let html = page.render().expect("render");
        assert!(
            html.contains(nonce.as_str()),
            "the nonce did not reach the markup"
        );
        assert!(html.contains("<style"), "the style block is gone");
    }

    /// Not one `<script>` in the tree. Every page works without JavaScript,
    /// and a tree with no script is the only `strict-dynamic` that cannot be
    /// got wrong.
    #[test]
    fn no_page_contains_a_script_element() {
        let nonce = nonce();
        let pages = [
            LoginPage {
                locale: "en",
                tenant_name: "Demo",
                action: "/x",
                csrf: "t",
                login_hint: None,
                message: None,
                nonce_attribute: nonce_attribute(&nonce),
            }
            .render()
            .expect("render"),
            ConsentPage {
                locale: "en",
                tenant_name: "Demo",
                client_name: "Billing",
                username: "ada",
                scopes: vec![ScopeLine {
                    name: "openid".into(),
                    description: "Confirm who you are".into(),
                }],
                action: "/x",
                csrf: "t",
                nonce_attribute: nonce_attribute(&nonce),
            }
            .render()
            .expect("render"),
            ErrorPage {
                locale: "en",
                tenant_name: "Demo",
                message: "Something went wrong.",
                correlation_id: "abc",
                nonce_attribute: nonce_attribute(&nonce),
            }
            .render()
            .expect("render"),
        ];
        for page in &pages {
            let lowered = page.to_lowercase();
            assert!(!lowered.contains("<script"), "{page}");
            assert!(!lowered.contains("javascript:"), "{page}");
        }
    }

    /// Every form that changes something carries a token.
    #[test]
    fn every_post_form_carries_a_csrf_field() {
        let nonce = nonce();
        for html in [
            LoginPage {
                locale: "en",
                tenant_name: "Demo",
                action: "/x",
                csrf: "the-token",
                login_hint: None,
                message: None,
                nonce_attribute: nonce_attribute(&nonce),
            }
            .render()
            .expect("render"),
            ConsentPage {
                locale: "en",
                tenant_name: "Demo",
                client_name: "Billing",
                username: "ada",
                scopes: Vec::new(),
                action: "/x",
                csrf: "the-token",
                nonce_attribute: nonce_attribute(&nonce),
            }
            .render()
            .expect("render"),
        ] {
            assert!(html.contains("method=\"post\""), "{html}");
            assert!(
                html.contains(r#"<input type="hidden" name="csrf" value="the-token">"#),
                "a POST form without a synchroniser token: {html}"
            );
        }
    }

    /// A denial is a decision, and needs the same protection as an approval.
    #[test]
    fn the_consent_form_offers_both_decisions_under_one_token() {
        let nonce = nonce();
        let html = ConsentPage {
            locale: "en",
            tenant_name: "Demo",
            client_name: "Billing",
            username: "ada",
            scopes: Vec::new(),
            action: "/x",
            csrf: "t",
            nonce_attribute: nonce_attribute(&nonce),
        }
        .render()
        .expect("render");
        assert!(html.contains(r#"value="allow""#), "{html}");
        assert!(html.contains(r#"value="deny""#), "{html}");
        assert_eq!(
            html.matches("name=\"csrf\"").count(),
            1,
            "both decisions must post under one token"
        );
    }

    /// A page saved to disk loses its headers but keeps its meta.
    #[test]
    fn every_page_declares_no_referrer_in_the_markup_too() {
        let nonce = nonce();
        let html = ErrorPage {
            locale: "en",
            tenant_name: "Demo",
            message: "x",
            correlation_id: "y",
            nonce_attribute: nonce_attribute(&nonce),
        }
        .render()
        .expect("render");
        assert!(
            html.contains(r#"<meta name="referrer" content="no-referrer">"#),
            "{html}"
        );
    }
}
