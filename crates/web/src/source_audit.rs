//! Whole-tree checks for the three absence properties this crate's security
//! rests on.
//!
//! The pattern is `crates/server/src/http/source_audit.rs` and
//! `crates/domain/src/secret_audit.rs`: the correct implementation is that
//! something is *not there*, absence is what a reviewer stops noticing, so it
//! is asserted mechanically over the source of every crate. No database, no
//! network, a millisecond in the default suite.
//!
//! What each one buys:
//!
//! * A policy is only as good as its weakest directive, and the weakest
//!   directive anybody ever adds is `'unsafe-inline'` — usually to make one
//!   stubborn widget work. [`crate::csp`] is exempted because it is the file
//!   that names the keywords in order to look for them; the policy it actually
//!   produces is checked by `unsafe_keywords_appear_in_no_policy` there.
//! * A nonce that reaches the header but not the page (or the reverse) is a
//!   broken page; a document served without going through [`crate::document`]
//!   is a page with no policy at all. Both are prevented by there being one
//!   producer of `text/html` and one caller of the nonce generator.
//! * askama escapes by default, so a cross-site scripting bug in a template
//!   takes the form of somebody *adding* `|safe` — usually to make a piece of
//!   markup render, in a value that turns out to be attacker-supplied. The
//!   templates are scanned for it, with one exemption that is named rather
//!   than pattern-matched.
//! * A `<script>` in a template is the thing `strict-dynamic` trusts, so the
//!   templates that may have one are listed by name with the reason they must
//!   (`SCRIPTED_TEMPLATES`), and each listing is itself checked: one inline
//!   nonce-carrying block, nothing loaded from elsewhere, and a path through
//!   the page for a browser that never runs it. Everything not on that list
//!   still fails the build.

#![cfg(test)]

use std::path::Path;

/// Every `.rs` file in the workspace's own crates, with its repo-relative path.
fn workspace_sources() -> Vec<(String, String)> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/web has a parent")
        .to_path_buf();

    let mut files = Vec::new();
    let mut stack = vec![crates.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read a source directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let relative = path
                    .strip_prefix(&crates)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((
                    relative,
                    std::fs::read_to_string(&path).expect("read source"),
                ));
            }
        }
    }
    assert!(
        files.len() > 10,
        "the source walk found only {} files, so the audit is checking nothing",
        files.len()
    );
    files
}

/// Lines that are not pure comment. A comment explaining why a keyword is
/// forbidden must not be what makes the check fire.
fn code_lines(source: &str) -> impl Iterator<Item = (usize, &str)> {
    source
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with('*')
        })
}

/// Every code line of every crate outside `exempt`, with its address.
fn code_outside(exempt: &[&str]) -> Vec<(String, usize, String)> {
    workspace_sources()
        .into_iter()
        .filter(|(path, _)| !exempt.iter().any(|tail| path.ends_with(tail)))
        .flat_map(|(path, source)| {
            code_lines(&source)
                .map(|(number, line)| (path.clone(), number, line.to_owned()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The acceptance criterion from `ast-ndk.3`, as a grep.
    ///
    /// A nonce policy that also says `'unsafe-inline'` is a nonce policy in
    /// name only: CSP Level 3 §7.1 notes that a nonce "overrides the other
    /// restrictions present in the directive in which they're delivered", and
    /// the reverse is just as true — one permissive keyword makes every nonce
    /// on the page decorative.
    #[test]
    fn no_source_file_names_an_unsafe_csp_keyword() {
        // `wasm-unsafe-eval` and `unsafe-eval` share a needle, deliberately.
        const FORBIDDEN: &[&str] = &[
            "unsafe-inline",
            "unsafe-eval",
            "unsafe-hashes",
            "unsafe-allow-redirects",
        ];

        let mut offenders = Vec::new();
        for (path, number, line) in code_outside(&["web/src/csp.rs", "web/src/source_audit.rs"]) {
            for needle in FORBIDDEN {
                if line.contains(needle) {
                    offenders.push(format!("{path}:{number}: {needle}"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "no CSP keyword that permits inline script or eval may appear; found:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// One producer of HTML, so one place where the nonce can be forgotten —
    /// and it is a place where forgetting it does not compile.
    ///
    /// A future page that needs to serve HTML some other way (the console shell
    /// of `ast-f7m.3`, say) has two honest options: render it through
    /// [`crate::document::Document`], which is what it wants anyway because its
    /// bootstrap `<script>` needs the nonce; or add itself here, deliberately,
    /// in a diff a reviewer will see.
    #[test]
    fn every_html_response_is_produced_by_the_document_type() {
        const EXEMPT: &[&str] = &[
            // Produces it.
            "web/src/document.rs",
            // Names it in order to look for it.
            "web/src/source_audit.rs",
            // Names it in order to *refuse* it: a `jwks_uri` that answers with
            // a login page is a captive portal, not a key set.
            "server/src/outbound/jwks.rs",
        ];

        let mut offenders = Vec::new();
        for (path, number, line) in code_outside(EXEMPT) {
            // A test asserting what a response says is not a handler saying it.
            if path.contains("/tests/") {
                continue;
            }
            if line.contains("text/html") || line.contains("application/xhtml") {
                offenders.push(format!("{path}:{number}"));
            }
        }
        assert!(
            offenders.is_empty(),
            "HTML must be served through web::document::Document, so that it \
             carries a nonce and a policy; open-coded at:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// One caller, so one nonce per request.
    ///
    /// CSP Level 3 §7.1 requires a unique value per policy transmitted, which
    /// the middleware gives by drawing one per request. A second caller would
    /// be a handler rendering a page whose nonce is not the one in its own
    /// header — every script on it silently blocked.
    #[test]
    fn the_nonce_generator_is_called_in_one_place() {
        const EXEMPT: &[&str] = &[
            // Defines it, and draws from it in its own tests.
            "web/src/csp.rs",
            // The one caller: the middleware.
            "web/src/document.rs",
            "web/src/source_audit.rs",
        ];

        let mut offenders = Vec::new();
        for (path, number, line) in code_outside(EXEMPT) {
            // The rule is about the shipped binary: a *handler* that drew its
            // own nonce would put one in the header and a different one in the
            // page. An integration test constructing a context is not a code
            // path a browser reaches, and it has no middleware to draw from —
            // `Nonce::fixed_for_test` is `#[cfg(test)]` inside `web`, so it is
            // not visible from another crate's `tests/`.
            if path.contains("/tests/") {
                continue;
            }
            if line.contains("Nonce::generate") {
                offenders.push(format!("{path}:{number}"));
            }
        }
        assert!(
            offenders.is_empty(),
            "a nonce comes from the document middleware, through the request \
             extensions; drawn directly at:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// A template with its `{# … #}` comments removed.
    ///
    /// The same reasoning as `code_lines` for Rust: a comment *about* the rule
    /// must not trip it. `base.html` explains why there is no `<script>` in
    /// the tree, and saying so should not read as one.
    fn without_comments(source: &str) -> String {
        let mut out = String::with_capacity(source.len());
        let mut rest = source;
        while let Some(start) = rest.find("{#") {
            out.push_str(&rest[..start]);
            match rest[start..].find("#}") {
                // Keep the newlines so line numbers still mean something.
                Some(end) => {
                    let comment = &rest[start..start + end + 2];
                    out.extend(comment.chars().filter(|c| *c == '\n'));
                    rest = &rest[start + end + 2..];
                }
                None => return out,
            }
        }
        out.push_str(rest);
        out
    }

    /// Every `.html` template, with its file name and comments stripped.
    fn templates() -> Vec<(String, String)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("read templates/") {
            let path = entry.expect("directory entry").path();
            if path.extension().is_some_and(|e| e == "html") {
                files.push((
                    path.file_name()
                        .expect("file name")
                        .to_string_lossy()
                        .into_owned(),
                    without_comments(&std::fs::read_to_string(&path).expect("read a template")),
                ));
            }
        }
        assert!(!files.is_empty(), "found no templates to audit");
        files
    }

    /// The interpolations this crate is allowed to leave unescaped, in the
    /// spelling `marks_a_value_safe` normalises to.
    ///
    /// Two, and each is exempted **by its exact expression** rather than by
    /// file, so that a third `|safe` anywhere — including on the next line of
    /// `base.html` — still fails the build.
    ///
    /// * the CSP nonce attribute, which `crate::csp` generates and which is
    ///   `base64url` by construction;
    /// * the tenant's mark, which `crate::brand::Brand::icon_svg` builds from
    ///   an `asterius_domain::TenantIcon` — an enumeration — and twenty-four
    ///   reviewed files. It has to be unescaped because it is SVG, and it is
    ///   safe to be because it has no string input:
    ///   `brand::tests::no_free_string_can_reach_the_rendered_mark` is that
    ///   claim, and `no_rendered_mark_can_run_or_fetch_anything` is what the
    ///   markup may contain.
    const PERMITTED_SAFE: &[&str] = &["{{ nonce_attribute|safe }}", "{{ brand.icon_svg()|safe }}"];

    /// Whether a template line leaves an interpolation unescaped.
    ///
    /// A function rather than a loop body so that the rule can be shown to
    /// *fire*: see `the_safe_filter_audit_would_catch_a_new_use`. An absence
    /// check nobody has ever watched fail is an absence check that might be
    /// matching nothing at all — and this one was. askama accepts whitespace
    /// around a filter pipe, so `{{ client_name | safe }}` is the same
    /// template as `{{ client_name|safe }}` and only the second was being
    /// looked for. The pipes are normalised before the needle is applied.
    fn marks_a_value_safe(line: &str) -> bool {
        let mut normalised = line.to_owned();
        while normalised.contains(" |") || normalised.contains("| ") {
            normalised = normalised.replace(" |", "|").replace("| ", "|");
        }
        normalised.contains("|safe")
            && !PERMITTED_SAFE
                .iter()
                .any(|permitted| normalised.contains(permitted))
    }

    /// The only unescaped interpolation in the tree is the CSP nonce.
    ///
    /// askama escapes automatically, so a template injection here is always
    /// somebody adding `|safe`. The one legitimate use is the nonce attribute,
    /// which this crate generates and which is base64url by construction — it
    /// is exempted **by the exact expression**, not by file, so that adding a
    /// second `|safe` to `base.html` still fails.
    #[test]
    fn no_template_marks_a_request_value_safe() {
        let mut offenders = Vec::new();
        for (name, source) in templates() {
            for (number, line) in source.lines().enumerate() {
                if marks_a_value_safe(line) {
                    offenders.push(format!("{name}:{}: {}", number + 1, line.trim()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "askama escapes by default; `|safe` on a value from a request or a \
             registration is a cross-site scripting bug:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// Both exemptions are real: each permitted expression is still in a
    /// template.
    ///
    /// Without this, deleting the nonce from `base.html` would make the test
    /// above pass for the wrong reason — and every page would lose its inline
    /// style block, or its mark. An exemption for an expression nobody writes
    /// any more is an exemption that should be deleted, not carried.
    #[test]
    fn every_permitted_interpolation_is_still_rendered_somewhere() {
        let templates = templates();
        for permitted in PERMITTED_SAFE {
            assert!(
                templates
                    .iter()
                    .any(|(_, source)| source.contains(permitted)),
                "no template renders {permitted} any more; delete the exemption"
            );
        }
    }

    /// The `|safe` rule fires on the lines it is there for (`ast-ndk.2`).
    ///
    /// The tree passes `no_template_marks_a_request_value_safe` today, which
    /// is exactly the state in which a matcher that had stopped matching would
    /// look healthy. So the predicate is run against the lines somebody would
    /// actually write: a client name rendered as markup, a filter chain ending
    /// in `safe`, the tenant's own text. Each must be caught, and the nonce
    /// must not be.
    #[test]
    fn the_safe_filter_audit_would_catch_a_new_use() {
        for hostile in [
            "<p>{{ client_name|safe }}</p>",
            "<p>{{ message|safe }}</p>",
            "{{ login_hint|trim|safe }}",
            // The spelling that was slipping through: askama does not care
            // about whitespace around a pipe, and neither may this.
            "  {{ tenant_name | safe }}",
            "{{ tenant_name  |  safe }}",
            "{{ scope.description |safe }}",
            // The mutation `ast-vn7` opens the door to: the mark is exempted,
            // so the way to smuggle markup past this audit is to render
            // something *else* off the same value. `brand.logo_url()` is a
            // URL a tenant's upload named, and unescaped it is an attribute
            // break.
            "<img src={{ brand.logo_url()|safe }}>",
            "{{ brand.font_url()|safe }}",
            "{{ brand|safe }}",
        ] {
            assert!(
                marks_a_value_safe(hostile),
                "the audit would not catch {hostile}"
            );
        }
        for permitted in [
            "<style {{ nonce_attribute|safe }}>",
            "<span class=\"brand-mark\">{{ brand.icon_svg()|safe }}</span>",
        ] {
            assert!(
                !marks_a_value_safe(permitted),
                "a permitted interpolation is being reported: {permitted}"
            );
        }
    }

    /// Every control a user types into is named to a screen reader.
    ///
    /// WCAG 2.2 SC 1.3.1 and 3.3.2, as a grep over the markup rather than as
    /// something an axe run has to find at the far end of a browser. The house
    /// pattern is a `<label>` wrapping its control, so the check is
    /// positional: every non-hidden `<input` has to fall between a `<label`
    /// and the `</label>` that closes it.
    ///
    /// Hidden inputs are exempt because they are not controls — a CSRF token
    /// and a reset token have nothing to announce.
    #[test]
    fn every_visible_input_in_a_template_sits_inside_a_label() {
        let mut offenders = Vec::new();
        for (name, source) in templates() {
            let mut depth = 0usize;
            let mut rest = source.as_str();
            let mut consumed = 0usize;
            while let Some(offset) = rest.find('<') {
                let at = consumed + offset;
                let tail = &rest[offset..];
                if tail.starts_with("<label") {
                    depth += 1;
                } else if tail.starts_with("</label") {
                    depth = depth.saturating_sub(1);
                } else if tail.starts_with("<input") {
                    let element = &tail[..tail.find('>').map_or(tail.len(), |end| end + 1)];
                    let hidden = element.contains("type=\"hidden\"");
                    if !hidden && depth == 0 {
                        offenders.push(format!("{name}: byte {at}: {}", element.trim()));
                    }
                }
                consumed = at + 1;
                rest = &source[consumed..];
            }
        }
        assert!(
            offenders.is_empty(),
            "a control with no label is a control a screen reader announces as \
             \"edit text\"; found:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// There is one error summary, and it still manages the focus.
    ///
    /// `error_summary.html` is included by every page that can fail, so the
    /// three attributes that make a failure announce itself and take the caret
    /// (`role`, `tabindex`, `autofocus`) live in exactly one file — and a page
    /// that quietly hand-rolled its own would get none of them checked. Both
    /// halves are asserted: the partial keeps its attributes, and nobody else
    /// declares an alert.
    #[test]
    fn the_error_summary_is_the_only_alert_and_keeps_its_focus_handling() {
        let templates = templates();
        let (_, summary) = templates
            .iter()
            .find(|(name, _)| name == "error_summary.html")
            .expect("the shared error summary exists");

        for required in ["role=\"alert\"", "tabindex=\"-1\"", "autofocus"] {
            assert!(
                summary.contains(required),
                "the error summary lost {required}, so a failed submission no \
                 longer announces itself or takes the focus"
            );
        }

        let hand_rolled: Vec<&String> = templates
            .iter()
            .filter(|(name, source)| {
                name != "error_summary.html" && source.contains("role=\"alert\"")
            })
            .map(|(name, _)| name)
            .collect();
        assert!(
            hand_rolled.is_empty(),
            "these pages declare their own alert instead of including \
             error_summary.html: {hand_rolled:?}"
        );
    }

    /// The templates that may run script, each with the reason it must.
    ///
    /// The rule is not "no script" — it is "no script that nobody decided on".
    /// A page that genuinely needs one adds itself here, deliberately, in a
    /// diff a reviewer will see; the alternative, relaxing the predicate, buys
    /// the same page and loses every other page's guarantee.
    ///
    /// An entry is only half the exemption; the tests below hold the other
    /// half. The script has to be inline and nonce-carrying, the page has to
    /// keep working without it, and `javascript:` URLs and inline event
    /// handlers stay forbidden here as everywhere — no nonce can allow one.
    const SCRIPTED_TEMPLATES: &[ScriptedTemplate] = &[
        ScriptedTemplate {
            name: "passkey.html",
            reason: "ast-ndk.7: `navigator.credentials.create()` is a JavaScript API, so a \
                     WebAuthn registration ceremony cannot be run from markup. The script \
                     is inline under the per-response nonce and interpolates nothing — its \
                     inputs arrive on escaped `data-` attributes — and with scripting off \
                     the page shows no button, explains why, and offers the password path.",
            // The button here cannot work without script, so the page must
            // lead somewhere that can: the password path.
            without_script: "<a href=",
            explanation: Explanation::InTheTemplate,
        },
        ScriptedTemplate {
            name: "login.html",
            reason: "ast-2vk.4: `navigator.credentials.get()` is a JavaScript API, so a                      passkey sign-in cannot be run from markup, and conditional mediation                      — the browser offering a passkey inside its own username dropdown —                      exists only as a call. The script is inline under the per-response                      nonce and interpolates nothing. What still works without it is the                      mechanism this page always had: the username and password form, whose                      submit button is real, visible and never disabled. The passkey button                      starts hidden and the script reveals it, because unlike the form-post                      page's button it could do nothing on its own.",
            // The password form is the page; the passkey button is the extra.
            without_script: "<button type=\"submit\">",
            explanation: Explanation::InTheCatalogue(crate::i18n::MessageKey::LoginNoScript),
        },
        ScriptedTemplate {
            name: "form_post.html",
            reason: "ast-gxh.5: a form cannot submit itself. No HTML attribute does it and \
                     `<noscript>` renders rather than acts, so the auto-submission clients \
                     expect of `response_mode=form_post` is one inline line under the \
                     per-response nonce, interpolating nothing and naming one element by \
                     id. The page under it works pressed by hand: the submit button is \
                     real, visible and never disabled, which is the mirror image of \
                     passkey.html and the reason both halves of the criterion hold.",
            // The inverse of the passkey page: the control the script drives is
            // the same control a user without script presses.
            without_script: "<button type=\"submit\">",
            explanation: Explanation::InTheTemplate,
        },
    ];

    /// A template that may carry a `<script>`, and the claims made for it.
    ///
    /// The reason is for a reviewer; `without_script` is for the machine. A
    /// scripted page has to keep working without its script, but *what* that
    /// means differs per page — a link out of the passkey page, a submit
    /// button on the form-post page — and a test that accepted either for both
    /// would pass for a passkey page that had quietly lost its password link.
    /// So each entry names its own, and the test looks for that one.
    struct ScriptedTemplate {
        /// The file, in `crates/web/templates/`.
        name: &'static str,
        /// Why this page cannot be written without script.
        reason: &'static str,
        /// The markup that still works when the script does not run.
        without_script: &'static str,
        /// Where the sentence explaining the missing scripted path lives.
        ///
        /// It used to be "in the template", always. `ast-ndk.5` moved the
        /// login page's words into the message catalogue, and an audit that
        /// went on grepping the template for "JavaScript" would have failed
        /// that move — or, worse, passed a page that had quietly lost the
        /// explanation because the grep matched a comment.
        explanation: Explanation,
    }

    /// Where a scripted page's `<noscript>` sentence comes from.
    enum Explanation {
        /// Written in the template. The audit reads it there.
        InTheTemplate,
        /// Written in `crate::i18n`, under this key. The audit reads it there,
        /// in every language — a fallback that explains itself in English only
        /// is not a fallback for the person reading the French page.
        InTheCatalogue(crate::i18n::MessageKey),
    }

    /// No page runs script it was not deliberately given, so `strict-dynamic`
    /// has almost nothing to get wrong.
    #[test]
    fn no_template_contains_a_script_element() {
        for (name, source) in templates() {
            let lowered = source.to_lowercase();
            let permitted = SCRIPTED_TEMPLATES
                .iter()
                .any(|scripted| scripted.name == name);
            assert!(
                permitted || !lowered.contains("<script"),
                "{name} contains a script element. If it genuinely cannot work \
                 without one, add it to SCRIPTED_TEMPLATES with the reason \
                 rather than weakening this test"
            );
            assert!(
                !lowered.contains("javascript:"),
                "{name} contains a javascript: URL"
            );
            // Inline event handlers are script by another name, and no nonce
            // can allow them.
            for handler in [" onclick=", " onload=", " onerror=", " onsubmit="] {
                assert!(
                    !lowered.contains(handler),
                    "{name} contains an inline {handler} handler"
                );
            }
        }
    }

    /// An exemption is a claim about a file, and the claim is checked.
    ///
    /// Three ways an exemption could rot into a hole, all of them silent:
    /// the named template stops having a script (so the entry is now a blanket
    /// permission for whatever is added next), it gains a *second* script that
    /// nobody looked at, or its script loses the nonce and somebody reaches for
    /// a policy keyword to make the page work again. Each is a failure here.
    #[test]
    fn every_scripted_template_is_a_single_nonce_carrying_block() {
        const NONCED: &str = "<script {{ nonce_attribute|safe }}>";

        let templates = templates();
        for ScriptedTemplate { name, reason, .. } in SCRIPTED_TEMPLATES {
            let (_, source) = templates
                .iter()
                .find(|(candidate, _)| candidate == name)
                .unwrap_or_else(|| panic!("{name} is exempted but no such template exists"));

            assert!(
                reason.len() > 80,
                "{name}'s exemption needs a reason a reviewer can weigh, not a label"
            );

            let scripts = source.matches("<script").count();
            assert_eq!(
                scripts, 1,
                "{name} has {scripts} script elements; the exemption is for one \
                 reviewed bootstrap, so a second needs its own decision"
            );
            assert_eq!(
                source.matches(NONCED).count(),
                1,
                "{name}'s script must open with the per-response nonce, or \
                 `script-src 'nonce-…'` will block the page it exists for"
            );
            // No `src=`: `strict-dynamic` lets the bootstrap load what it
            // needs, and a remote script on an authorization page is exactly
            // what RFC 9700 §4.2.4 tells us not to fetch.
            assert!(
                !source.contains("<script src") && !source.contains("src=\"http"),
                "{name} pulls a script from somewhere else"
            );
        }
    }

    /// A scripted page still has to be usable with scripting off.
    ///
    /// The acceptance criterion of `ast-ndk.7`, and then of `ast-gxh.5`, as a
    /// grep: the page says why it is behaving differently and offers something
    /// that works. A `<noscript>` that only apologises would pass the first
    /// half and fail a user, so the control is required too — and it is the
    /// control that entry *declared*, not any control at all. The passkey page
    /// leads out to the password path because its own button cannot work
    /// unscripted; the form-post page keeps a submit button because its button
    /// is the whole mechanism and the script only presses it. Accepting either
    /// marker for both pages would let the passkey page lose its password link
    /// and still pass.
    #[test]
    fn every_scripted_template_offers_a_path_without_script() {
        for ScriptedTemplate {
            name,
            without_script,
            explanation,
            ..
        } in SCRIPTED_TEMPLATES
        {
            let (_, source) = templates()
                .into_iter()
                .find(|(candidate, _)| candidate == name)
                .unwrap_or_else(|| panic!("{name} is exempted but no such template exists"));
            assert!(
                source.contains("<noscript>"),
                "{name} runs script and never tells a browser without it what happened"
            );
            match explanation {
                Explanation::InTheTemplate => assert!(
                    source.contains("JavaScript"),
                    "{name}'s fallback must say why the scripted path is missing"
                ),
                Explanation::InTheCatalogue(key) => {
                    for locale in asterius_domain::Locale::SUPPORTED {
                        assert!(
                            key.built_in(locale).contains("JavaScript"),
                            "{name}'s fallback is {} in the catalogue, and in {locale} it does \
                             not say why the scripted path is missing",
                            key.as_str()
                        );
                    }
                }
            }
            assert!(
                source.contains(without_script),
                "{name} declares {without_script} as what still works without \
                 script, and the template does not contain it"
            );
        }
    }

    /// The one form in this tree that posts somewhere other than back here.
    ///
    /// A synchroniser token defends *this* server's state-changing endpoints,
    /// and `form_post.html` posts to the client's `redirect_uri` (`ast-gxh.5`).
    /// A token on it would be a value of ours handed to a third party, and it
    /// would protect nothing: the thing that makes the submission trustworthy
    /// to the client is the authorization code in the body, which is single-use
    /// and bound to the PKCE challenge that client pushed.
    ///
    /// Named here rather than pattern-matched, so that a second cross-origin
    /// form is a decision somebody writes down.
    const CROSS_ORIGIN_FORM_TEMPLATES: &[(&str, &str)] = &[(
        "form_post.html",
        "ast-gxh.5: the action is the client's registered redirect_uri, so a \
         CSRF token would be one of our values posted to somebody else. What \
         authenticates this submission to the client is the single-use, \
         PKCE-bound code it carries.",
    )];

    /// Every form that posts back here carries a synchroniser token.
    ///
    /// The check is on the template rather than on a rendered page, so a new
    /// form added without one fails immediately rather than when somebody
    /// remembers to write a test for that page.
    #[test]
    fn every_post_form_in_a_template_carries_a_csrf_field() {
        for (name, source) in templates() {
            if CROSS_ORIGIN_FORM_TEMPLATES
                .iter()
                .any(|(exempt, _)| *exempt == name)
            {
                continue;
            }
            let forms = source.matches("method=\"post\"").count();
            let tokens = source.matches("name=\"csrf\"").count();
            assert_eq!(
                forms, tokens,
                "{name} has {forms} POST form(s) and {tokens} CSRF field(s)"
            );
        }
    }

    /// The exemption above is a claim, and the claim is checked.
    ///
    /// Two ways it could rot. The named template stops being cross-origin —
    /// its form posts back here after all — and the exemption is now a hole in
    /// the CSRF rule for whatever is added to that page next; or it keeps
    /// posting to the client and somebody adds a token anyway, which sends a
    /// value of ours to a third party. Both fail here.
    #[test]
    fn a_cross_origin_form_posts_to_the_client_and_carries_no_token() {
        let templates = templates();
        for (name, reason) in CROSS_ORIGIN_FORM_TEMPLATES {
            let (_, source) = templates
                .iter()
                .find(|(candidate, _)| candidate == name)
                .unwrap_or_else(|| panic!("{name} is exempted but no such template exists"));

            assert!(
                reason.len() > 80,
                "{name}'s exemption needs a reason a reviewer can weigh, not a label"
            );
            assert_eq!(
                source.matches("method=\"post\"").count(),
                1,
                "{name} is exempted for one cross-origin form, so a second \
                 needs its own decision"
            );
            assert_eq!(
                source.matches("name=\"csrf\"").count(),
                0,
                "{name} posts to the client, so a synchroniser token on it \
                 would be handed to a third party"
            );
            // The action is a whole URI this server was given, not a path it
            // routes: a template posting to `/interaction/…` is same-origin and
            // has no business on this list.
            assert!(
                source.contains("action=\"{{ action }}\""),
                "{name}'s form does not post to an interpolated action"
            );
            assert!(
                !source.contains("action=\"/"),
                "{name} posts to a path on this server, so it is not \
                 cross-origin and needs the token like every other form"
            );
        }
    }

    /// No page reaches an origin nobody reviewed (`ast-vn7`).
    ///
    /// RFC 9700 §4.2.4: the pages around an authorization response "SHOULD NOT
    /// include third-party resources", because a third-party fetch is how a
    /// `state` or a `request_uri` leaks through a `Referer`. `default-src
    /// 'none'` is the browser-side half and `csp-sweep.spec.ts` watches it in
    /// a real browser; this is the half that fails the build instead of a
    /// pipeline, over the markup that is actually written.
    ///
    /// The face `ast-vn7` added is what makes this worth stating now: it is
    /// the first `url(…)` in the tree, and a face is exactly the resource a
    /// developer reaches for a CDN for.
    #[test]
    fn no_template_names_an_origin_off_this_server() {
        let mut offenders = Vec::new();
        for (name, source) in templates() {
            for (number, line) in source.lines().enumerate() {
                for needle in ["https://", "http://", "//fonts.", "url(//"] {
                    if line.contains(needle) {
                        offenders.push(format!("{name}:{}: {}", number + 1, line.trim()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "a page may fetch nothing from another origin:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The face is declared, served from here, and never blocks the page.
    ///
    /// Three properties in one place because they are one decision. The `src`
    /// is the interpolated path — a literal would be a path that 404s under a
    /// path-based tenant (`ast-295`) — and `font-display: swap` is what keeps
    /// a slow or failed font fetch from leaving a sign-in form invisible,
    /// which is the accessibility cost of self-hosting a face.
    #[test]
    fn the_face_is_declared_once_from_this_origin_and_swaps() {
        let base = templates()
            .into_iter()
            .find(|(name, _)| name == "base.html")
            .map(|(_, source)| source)
            .expect("base.html is the one layout");

        assert_eq!(
            base.matches("@font-face").count(),
            1,
            "the layout declares the face once, or a page fetches it twice"
        );
        assert!(
            base.contains("src:url(\"{{ brand.font_url() }}\")"),
            "the face is not fetched from the path this server serves it at"
        );
        assert!(
            base.contains("font-display:swap"),
            "a face without `swap` hides the sign-in form until it loads"
        );
    }

    /// The stripper removes comments and nothing else.
    #[test]
    fn a_comment_about_a_script_is_not_a_script() {
        let source = "{# there is no <script> here #}\n<p>text</p>\n";
        let stripped = without_comments(source);
        assert!(!stripped.contains("<script"), "{stripped:?}");
        assert!(stripped.contains("<p>text</p>"), "{stripped:?}");

        // Real markup outside a comment still survives, or the audits above
        // would pass by deleting everything.
        let hostile = "<script>alert(1)</script>\n";
        assert!(without_comments(hostile).contains("<script"));

        // An unterminated comment does not panic and does not leak its tail.
        assert!(!without_comments("{# unterminated <script>").contains("<script"));
    }

    /// The `tests/` exemption is narrow: production sources are still scanned.
    ///
    /// Without this, widening the path filter by accident — to `/test`, say,
    /// which matches nothing today but would match a future `src/testing.rs` —
    /// would turn the rule off without any test noticing.
    #[test]
    fn the_nonce_rule_still_covers_production_sources() {
        let scanned: Vec<String> = code_outside(&["web/src/csp.rs"])
            .into_iter()
            .map(|(path, _, _)| path)
            .filter(|path| !path.contains("/tests/"))
            .collect();
        assert!(
            scanned
                .iter()
                .any(|p| p.ends_with("server/src/http/interaction.rs")),
            "the handler that renders pages is not being scanned"
        );
        assert!(
            scanned.iter().any(|p| p.ends_with("web/src/pages.rs")),
            "the page types are not being scanned"
        );
    }

    /// An absence check that cannot fail passes for the wrong reason, so prove
    /// the matcher fires — and that a comment about the rule does not.
    #[test]
    fn the_audit_would_catch_a_violation() {
        let hostile = "    let policy = \"script-src 'unsafe-inline'\";\n";
        assert!(code_lines(hostile).any(|(_, line)| line.contains("unsafe-inline")));

        let served = "        (header::CONTENT_TYPE, \"text/html\"),\n";
        assert!(code_lines(served).any(|(_, line)| line.contains("text/html")));

        let drawn = "    let nonce = Nonce::generate();\n";
        assert!(code_lines(drawn).any(|(_, line)| line.contains("Nonce::generate")));

        // ...and not on the comments that explain why each is forbidden.
        for explanation in [
            "// never 'unsafe-inline'; see CSP Level 3 §7.1\n",
            "//! serves text/html through Document\n",
            "    // Nonce::generate is the middleware's job\n",
        ] {
            assert_eq!(code_lines(explanation).count(), 0, "{explanation}");
        }
    }
}
