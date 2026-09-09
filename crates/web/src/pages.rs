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
//! (`ast-2vk.1`), and a tree with almost no `<script>` in it is the version of
//! `script-src 'nonce-…' 'strict-dynamic'` that is hardest to get wrong. The
//! source audit asserts the absence.
//!
//! There is exactly one exception, and it is named rather than pattern-matched:
//! [`PasskeyPage`] (`ast-ndk.7`). `navigator.credentials.create()` is a
//! JavaScript API, so a WebAuthn registration ceremony cannot be run from
//! markup at all. Its script is inline, carries the per-response nonce, and
//! interpolates nothing — every value reaches it through escaped `data-`
//! attributes. With scripting off the page offers the password path and says
//! why, rather than a button that cannot work.

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
    ///
    /// `None` renders the bare token. That is deliberately ugly: an
    /// unexplained scope should look unexplained rather than familiar.
    pub description: Option<String>,
    /// Whether the user may untick it and still proceed.
    pub required: bool,
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
    /// The host the user will be returned to. See the template.
    pub redirect_host: &'a str,
    /// What is being asked for.
    pub scopes: Vec<ScopeLine>,
    /// Whether a refresh token was asked for.
    pub offline_access: bool,
    /// RFC 8707 resource indicators named by the request.
    pub resources: Vec<String>,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
}

/// The logout confirmation question.
///
/// OIDC RP-Initiated Logout 1.0 §2: the OP asks the End-User whether to log
/// out when it cannot verify the request. The page therefore carries **no**
/// relying-party name, logo or URL — see the template for why that is a
/// security property rather than a missing feature — and it is rendered
/// before anything about the session has changed.
#[derive(Debug, Template)]
#[template(path = "logout_confirm.html")]
pub struct LogoutConfirmationPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name. The only name on the page.
    pub tenant_name: &'a str,
    /// Where the form posts to.
    pub action: &'a str,
    /// The synchroniser token for this rendering.
    pub csrf: &'a str,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
}

/// The neutral end of a logout.
///
/// Shown when there is no post-logout redirect to perform (§3), and when the
/// user chose to stay signed in. It names the provider and nothing else.
#[derive(Debug, Template)]
#[template(path = "logged_out.html")]
pub struct LoggedOutPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Whether the session was actually ended.
    pub signed_out: bool,
    /// The CSP nonce attribute.
    pub nonce_attribute: String,
}

/// The passkey enrolment page: the one page in this tree that runs script.
///
/// A WebAuthn registration ceremony is a call to
/// `navigator.credentials.create()`, which no amount of markup can make. So
/// this page carries one inline bootstrap under the per-response nonce, and
/// `source_audit` names it as an exemption rather than relaxing the rule for
/// everyone.
///
/// Nothing here is interpolated *into* the script. The endpoints, the token and
/// the destination arrive on `data-` attributes, which askama escapes like any
/// other attribute value, so the script's source text is a constant that a
/// reviewer can read once.
///
/// # Without JavaScript
///
/// The button is `hidden` in the markup and revealed by the script, so a
/// browser with scripting off — or one where the script was blocked, which
/// `<noscript>` does not cover — shows no button at all. The link to
/// [`Self::password_href`] is unconditional, and the `<noscript>` block says
/// why the button is missing.
#[derive(Debug, Template)]
#[template(path = "passkey.html")]
pub struct PasskeyPage<'a> {
    /// BCP 47 tag.
    pub locale: &'a str,
    /// The tenant's display name.
    pub tenant_name: &'a str,
    /// Who is enrolling, so a user on a shared machine can see it is them.
    pub username: &'a str,
    /// Where the script asks for creation options.
    pub options_action: &'a str,
    /// Where the script posts the attestation it got back.
    pub finish_action: &'a str,
    /// Where the browser goes once a passkey has been stored.
    pub next_href: &'a str,
    /// The path that works with no script at all: carry on with a password.
    pub password_href: &'a str,
    /// The synchroniser token, sent in the body of both fetches.
    pub csrf: &'a str,
    /// A previous failure, if this is a retry. A fixed string, never echoed.
    pub message: Option<&'a str>,
    /// The CSP nonce attribute — here it is the script's, not only the style's.
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
                redirect_host: hostile,
                scopes: vec![ScopeLine {
                    name: (*hostile).to_owned(),
                    description: Some((*hostile).to_owned()),
                    required: false,
                }],
                offline_access: true,
                resources: vec![(*hostile).to_owned()],
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

    /// A passkey page with the values a caller would pass.
    fn passkey<'a>(username: &'a str, message: Option<&'a str>) -> PasskeyPage<'a> {
        PasskeyPage {
            locale: "en",
            tenant_name: "Demo",
            username,
            options_action: "/passkeys/options",
            finish_action: "/passkeys/finish",
            next_href: "/account",
            password_href: "/interaction/x/login",
            csrf: "the-token",
            message,
            nonce_attribute: nonce_attribute(&nonce()),
        }
    }

    /// The scripted page escapes like every other one.
    ///
    /// It matters more here than anywhere: this is the page whose exemption
    /// lets `strict-dynamic` trust an inline block, so an injected second
    /// script would inherit that trust.
    #[test]
    fn every_untrusted_value_on_the_passkey_page_is_escaped() {
        for hostile in HOSTILE {
            let html = passkey(hostile, Some(hostile)).render().expect("render");
            assert_no_injection_beyond(&html, hostile, 1);
        }
    }

    /// One inline block, carrying the nonce the header names.
    ///
    /// A script without the nonce is a page that silently does nothing, and a
    /// second script is one nobody reviewed.
    #[test]
    fn the_passkey_page_carries_exactly_one_nonce_carrying_script() {
        let nonce = nonce();
        let html = PasskeyPage {
            nonce_attribute: nonce_attribute(&nonce),
            ..passkey("ada", None)
        }
        .render()
        .expect("render");

        assert_eq!(html.matches("<script").count(), 1, "{html}");
        assert!(
            html.contains(&format!("<script nonce=\"{}\">", nonce.as_str())),
            "the script did not get the nonce the header will name: {html}"
        );
        assert!(
            !html.contains("<script src"),
            "the bootstrap must be inline, not fetched: {html}"
        );
    }

    /// The ceremony's inputs travel as escaped attributes, never as source.
    ///
    /// This is what makes one `<script>` reviewable: its text is a constant.
    /// A value interpolated into it would be a cross-site scripting bug that
    /// no amount of HTML escaping fixes, because inside a script element the
    /// dangerous characters are different ones.
    #[test]
    fn the_passkey_script_interpolates_nothing() {
        let html = passkey("ada", None).render().expect("render");
        let start = html.find("<script").expect("a script");
        let body = &html[start..];

        for value in [
            "/passkeys/options",
            "/passkeys/finish",
            "/account",
            "the-token",
            "ada",
        ] {
            assert!(
                !body.contains(value),
                "{value:?} was interpolated into the script: {body}"
            );
        }
        // ...and they did reach the page, on the attributes the script reads.
        assert!(
            html.contains(r#"data-options-url="/passkeys/options""#),
            "{html}"
        );
        assert!(html.contains(r#"data-csrf="the-token""#), "{html}");
    }

    /// The acceptance criterion of `ast-ndk.7`: no dead button, and a reason.
    ///
    /// The button is `hidden` in the markup and revealed by the script, so a
    /// browser that never runs the script never shows a control that cannot
    /// work — including one where scripting is on but the script was blocked,
    /// which `<noscript>` does not cover. That is why the password link is
    /// outside the `<noscript>` and the explanation is inside it.
    #[test]
    fn without_javascript_the_passkey_page_explains_and_offers_the_password_path() {
        let html = passkey("ada", None).render().expect("render");

        assert!(
            html.contains(r#"<button type="button" id="passkey-register" hidden>"#),
            "the button must start hidden, or a no-script browser sees a dead control: {html}"
        );

        let noscript = html
            .split_once("<noscript>")
            .and_then(|(_, rest)| rest.split_once("</noscript>"))
            .map(|(inside, _)| inside.to_owned())
            .expect("a noscript block");
        assert!(
            noscript.contains("JavaScript"),
            "the fallback must say why the button is missing: {noscript}"
        );

        // The way out is in the markup unconditionally, not only inside the
        // `<noscript>`: a blocked script leaves the page with neither.
        let outside = html.replace(&noscript, "");
        assert!(
            outside.contains(r#"<a href="/interaction/x/login">"#),
            "the password path must survive outside the noscript block: {outside}"
        );
    }

    /// The logout pages carry the tenant's name, and nothing else escapes it.
    #[test]
    fn every_untrusted_value_on_the_logout_pages_is_escaped() {
        for hostile in HOSTILE {
            let nonce = nonce();
            let confirmation = LogoutConfirmationPage {
                locale: "en",
                tenant_name: hostile,
                action: "/logout",
                csrf: hostile,
                nonce_attribute: nonce_attribute(&nonce),
            }
            .render()
            .expect("render");
            assert_no_injection(&confirmation, hostile);

            for signed_out in [true, false] {
                let html = LoggedOutPage {
                    locale: "en",
                    tenant_name: hostile,
                    signed_out,
                    nonce_attribute: nonce_attribute(&nonce),
                }
                .render()
                .expect("render");
                assert_no_injection(&html, hostile);
            }
        }
    }

    /// The anti-phishing rule of RP-Initiated Logout 1.0 §2, asserted rather
    /// than trusted: the confirmation page is reached by a request nobody
    /// verified, so the template must have no field a client could fill.
    #[test]
    fn the_confirmation_page_can_render_no_relying_party_text() {
        let nonce = nonce();
        let html = LogoutConfirmationPage {
            locale: "en",
            tenant_name: "Demo",
            action: "/logout",
            csrf: "the-token",
            nonce_attribute: nonce_attribute(&nonce),
        }
        .render()
        .expect("render");

        assert!(html.contains("Log out of Demo?"));
        assert!(
            html.contains(r#"<input type="hidden" name="csrf" value="the-token">"#),
            "a forged logout is a denial of service: {html}"
        );
        assert!(html.contains(r#"value="logout""#) && html.contains(r#"value="stay""#));
        // A source-level check, because the field that would carry a client's
        // name is one somebody could add later without noticing what it is.
        let source = include_str!("../templates/logout_confirm.html");
        for forbidden in ["client_name", "logo", "redirect", "post_logout"] {
            assert!(
                !source.contains(&format!("{{{{ {forbidden}")),
                "the confirmation page renders {forbidden}, which the relying party chooses"
            );
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
        assert_no_injection_beyond(html, hostile, 0);
    }

    /// The same property for a page that legitimately carries `scripts` script
    /// elements of its own: none of them may have come from the input.
    fn assert_no_injection_beyond(html: &str, hostile: &str, scripts: usize) {
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
        assert_eq!(
            html.to_lowercase().matches("<script").count(),
            scripts,
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
                redirect_host: "rp.example",
                scopes: vec![ScopeLine {
                    name: "openid".into(),
                    description: Some("Confirm who you are".into()),
                    required: true,
                }],
                offline_access: false,
                resources: Vec::new(),
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
                redirect_host: "rp.example",
                scopes: Vec::new(),
                offline_access: false,
                resources: Vec::new(),
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
            redirect_host: "rp.example",
            scopes: Vec::new(),
            offline_access: false,
            resources: Vec::new(),
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

    fn consent(scopes: Vec<ScopeLine>, offline: bool, resources: Vec<String>) -> String {
        let nonce = nonce();
        ConsentPage {
            locale: "en",
            tenant_name: "Demo",
            client_name: "Billing",
            username: "ada",
            redirect_host: "rp.example",
            scopes,
            offline_access: offline,
            resources,
            action: "/interaction/x",
            csrf: "t",
            nonce_attribute: nonce_attribute(&nonce),
        }
        .render()
        .expect("render")
    }

    /// A required scope travels as a hidden field, not a disabled checkbox.
    ///
    /// A disabled input submits nothing, so the value would never reach the
    /// server and `openid` would silently vanish from the grant. The hidden
    /// field says the same thing to a person and cannot be unticked.
    #[test]
    fn a_required_scope_cannot_be_unticked_and_still_submits() {
        let html = consent(
            vec![ScopeLine {
                name: "openid".into(),
                description: Some("Confirm who you are".into()),
                required: true,
            }],
            false,
            Vec::new(),
        );
        assert!(
            html.contains(r#"<input type="hidden" name="scope" value="openid">"#),
            "{html}"
        );
        assert!(
            !html.contains(r#"type="checkbox" name="scope" value="openid""#),
            "a required scope was rendered as a checkbox: {html}"
        );
        assert!(
            !html.contains("disabled"),
            "a disabled input submits nothing: {html}"
        );
        assert!(html.contains("(required)"), "{html}");
    }

    /// An optional scope is a ticked checkbox: the user may decline it and
    /// still proceed, which is what "inadequate choice" in FAPI 2.0 SP §7
    /// means in practice.
    #[test]
    fn an_optional_scope_is_a_checkbox_the_user_can_untick() {
        let html = consent(
            vec![ScopeLine {
                name: "payments".into(),
                description: Some("See your payment history".into()),
                required: false,
            }],
            false,
            Vec::new(),
        );
        assert!(
            html.contains(r#"<input type="checkbox" name="scope" value="payments" checked>"#),
            "{html}"
        );
    }

    /// An unexplained scope shows its bare token rather than an invented
    /// description.
    #[test]
    fn a_scope_with_no_description_shows_its_name() {
        let html = consent(
            vec![ScopeLine {
                name: "obscure:thing".into(),
                description: None,
                required: false,
            }],
            false,
            Vec::new(),
        );
        assert!(html.contains("obscure:thing"), "{html}");
    }

    /// Acting later, without the user present, is a different thing from
    /// acting now, and is said so.
    #[test]
    fn offline_access_is_spelled_out_when_asked_for() {
        let with = consent(Vec::new(), true, Vec::new());
        assert!(with.contains("without you present"), "{with}");

        let without = consent(Vec::new(), false, Vec::new());
        assert!(!without.contains("without you present"), "{without}");
    }

    #[test]
    fn resources_are_listed_only_when_there_are_some() {
        let with = consent(Vec::new(), false, vec!["https://api.example/".into()]);
        assert!(with.contains("https://api.example/"), "{with}");
        assert!(with.contains("Access applies to"), "{with}");

        let without = consent(Vec::new(), false, Vec::new());
        assert!(!without.contains("Access applies to"), "{without}");
    }

    /// The name is chosen by whoever registered; the host is not.
    #[test]
    fn the_consent_page_names_the_host_the_user_returns_to() {
        let html = consent(Vec::new(), false, Vec::new());
        assert!(html.contains("rp.example"), "{html}");
        assert!(html.contains("returned to"), "{html}");
    }

    /// No remote assets: the acceptance criterion, and the reason
    /// `img-src 'self' data:` is in the policy. A client logo fetched from the
    /// client's own server would tell it exactly when a consent screen was
    /// shown, and to whom by IP.
    #[test]
    fn the_consent_page_loads_nothing_from_anywhere_else() {
        let html = consent(
            vec![ScopeLine {
                name: "openid".into(),
                description: Some("Confirm who you are".into()),
                required: true,
            }],
            true,
            vec!["https://api.example/".into()],
        );
        for remote in ["<img", "<iframe", "<link", "src=\"http", "url(http"] {
            assert!(
                !html.to_lowercase().contains(&remote.to_lowercase()),
                "the page pulls a remote asset ({remote}): {html}"
            );
        }
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
