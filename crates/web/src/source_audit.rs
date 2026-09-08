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

    /// The only unescaped interpolation in the tree is the CSP nonce.
    ///
    /// askama escapes automatically, so a template injection here is always
    /// somebody adding `|safe`. The one legitimate use is the nonce attribute,
    /// which this crate generates and which is base64url by construction — it
    /// is exempted **by the exact expression**, not by file, so that adding a
    /// second `|safe` to `base.html` still fails.
    #[test]
    fn no_template_marks_a_request_value_safe() {
        const PERMITTED: &str = "{{ nonce_attribute|safe }}";

        let mut offenders = Vec::new();
        for (name, source) in templates() {
            for (number, line) in source.lines().enumerate() {
                if !line.contains("|safe") {
                    continue;
                }
                if line.contains(PERMITTED) {
                    continue;
                }
                offenders.push(format!("{name}:{}: {}", number + 1, line.trim()));
            }
        }
        assert!(
            offenders.is_empty(),
            "askama escapes by default; `|safe` on a value from a request or a \
             registration is a cross-site scripting bug:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The exemption is real: the nonce attribute is still marked safe.
    ///
    /// Without this, deleting the nonce from `base.html` would make the test
    /// above pass for the wrong reason — and every page would lose its inline
    /// style block.
    #[test]
    fn the_nonce_attribute_is_still_the_one_permitted_interpolation() {
        let found = templates()
            .iter()
            .any(|(_, source)| source.contains("{{ nonce_attribute|safe }}"));
        assert!(found, "no template renders the CSP nonce any more");
    }

    /// No page runs script, so `strict-dynamic` has nothing to get wrong.
    #[test]
    fn no_template_contains_a_script_element() {
        for (name, source) in templates() {
            let lowered = source.to_lowercase();
            assert!(
                !lowered.contains("<script"),
                "{name} contains a script element"
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

    /// Every form that posts carries a synchroniser token.
    ///
    /// The check is on the template rather than on a rendered page, so a new
    /// form added without one fails immediately rather than when somebody
    /// remembers to write a test for that page.
    #[test]
    fn every_post_form_in_a_template_carries_a_csrf_field() {
        for (name, source) in templates() {
            let forms = source.matches("method=\"post\"").count();
            let tokens = source.matches("name=\"csrf\"").count();
            assert_eq!(
                forms, tokens,
                "{name} has {forms} POST form(s) and {tokens} CSRF field(s)"
            );
        }
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
