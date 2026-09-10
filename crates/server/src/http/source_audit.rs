//! Whole-tree checks for two rules that a code review would otherwise have to
//! remember every time.
//!
//! Both are absence properties: the correct implementation is that a thing is
//! *not there*, and absence is exactly what a reviewer stops noticing. So they
//! are asserted mechanically, over the source of every crate, with no database
//! and no network — a millisecond in the default suite.

#![cfg(test)]

use std::path::Path;

/// Every `.rs` file in the workspace's own crates, with its repo-relative path.
fn workspace_sources() -> Vec<(String, String)> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/server has a parent")
        .to_path_buf();

    let mut files = Vec::new();
    let mut stack = vec![crates.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read a source directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let relative = path
                    .strip_prefix(&crates)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                files.push((
                    relative,
                    std::fs::read_to_string(&path).expect("read source"),
                ));
            }
        }
    }
    assert!(
        files.len() > 10,
        "the source walk found only {} files",
        files.len()
    );
    files
}

/// Lines that are pure comment, which carry rationale rather than behaviour.
fn code_lines(source: &str) -> impl Iterator<Item = (usize, &str)> {
    source
        .lines()
        .enumerate()
        .map(|(n, line)| (n + 1, line))
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with('*')
        })
}

fn is_at(path: &str, tail: &str) -> bool {
    path.replace('\\', "/").ends_with(tail)
}

/// Macros that compare a value rather than build one.
const ASSERTION_MACROS: &[&str] = &["assert_eq!(", "assert_ne!(", "assert!(", "matches!("];

/// True for a path under an integration-test directory (`crates/*/tests/`).
fn is_integration_test(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.starts_with("tests/") || normalized.contains("/tests/")
}

/// True when the `SEE_OTHER` on `lines[index]` is an argument being compared
/// by an assertion macro, rather than a value being constructed.
///
/// Two conditions, both required: the constant sits in argument position (it
/// is alone on its line, or directly after a `,` or after the macro's own
/// paren — never after a call such as `.status(`), and the statement it
/// belongs to opens with an assertion macro.
fn is_assertion_argument(lines: &[&str], index: usize) -> bool {
    let head = lines[index]
        .split("StatusCode::SEE_OTHER")
        .next()
        .unwrap_or("")
        .trim_end();
    let argument_position = head.is_empty()
        || head.ends_with(',')
        || ASSERTION_MACROS
            .iter()
            .any(|macro_name| head.ends_with(macro_name));
    if !argument_position {
        return false;
    }

    let mut current = index;
    loop {
        let line = lines[current].trim();
        if ASSERTION_MACROS
            .iter()
            .any(|macro_name| line.contains(macro_name))
        {
            return true;
        }
        if current == 0 {
            return false;
        }
        // A previous statement ended, so this one did not open with an assertion.
        let previous = lines[current - 1].trim_end();
        if previous.ends_with(';') || previous.ends_with('{') || previous.ends_with('}') {
            return false;
        }
        current -= 1;
    }
}

/// Lines of `source` that open-code a `SEE_OTHER` redirect.
///
/// The rule this serves is that a *handler* must never build a redirect by
/// hand; `http::redirect::SeeOther` is the one reviewed place that guarantees
/// 303 (FAPI 2.0 SP §5.3.2.2 items 10–11). An integration test that asserts a
/// response *is* a 303 compares a status, it does not construct one, so it is
/// exempt — and the exemption is kept as narrow as that sentence: this audit
/// only, `tests/` directories only, assertion arguments only. A constructed
/// `SEE_OTHER` under `tests/`, and any use at all under `src/`, still fail.
fn open_coded_see_other(path: &str, source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let exempt_assertions = is_integration_test(path);

    let mut offenders = Vec::new();
    for (number, line) in code_lines(source) {
        if !line.contains("StatusCode::SEE_OTHER") {
            continue;
        }
        if exempt_assertions && is_assertion_argument(&lines, number - 1) {
            continue;
        }
        offenders.push(format!("{path}:{number}"));
    }
    offenders
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FAPI 2.0 SP §5.3.2.2 items 10–11: never 307. The rule is widened to
    /// every redirect status except 303, because 302 and 308 carry the same
    /// method-and-body replay hazard in some browsers, and there is no
    /// situation in this server that wants one.
    ///
    /// `SEE_OTHER` is confined to the redirect helper so that redirects keep
    /// going through one reviewed place rather than being open-coded.
    #[test]
    fn no_redirect_status_other_than_303_appears_in_the_tree() {
        const FORBIDDEN: &[&str] = &[
            "TEMPORARY_REDIRECT",
            "PERMANENT_REDIRECT",
            "MOVED_PERMANENTLY",
            "StatusCode::FOUND",
            "MULTIPLE_CHOICES",
            "NOT_MODIFIED",
        ];

        let mut offenders = Vec::new();
        for (path, source) in workspace_sources() {
            // This file names every forbidden constant in order to look for it.
            if is_at(&path, "http/source_audit.rs") {
                continue;
            }
            for (number, line) in code_lines(&source) {
                for needle in FORBIDDEN {
                    if line.contains(needle) {
                        offenders.push(format!("{path}:{number}: {needle}"));
                    }
                }
                // A status built from a literal sidesteps the named constants.
                for literal in [
                    "from_u16(301",
                    "from_u16(302",
                    "from_u16(307",
                    "from_u16(308",
                ] {
                    if line.contains(literal) {
                        offenders.push(format!("{path}:{number}: {literal}"));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "only 303 See Other may be used; found:\n  {}\nUse http::redirect::SeeOther.",
            offenders.join("\n  ")
        );
    }

    #[test]
    fn see_other_is_only_constructed_by_the_redirect_helper() {
        let mut offenders = Vec::new();
        for (path, source) in workspace_sources() {
            if is_at(&path, "http/redirect.rs") || is_at(&path, "http/source_audit.rs") {
                continue;
            }
            offenders.extend(open_coded_see_other(&path, &source));
        }
        assert!(
            offenders.is_empty(),
            "redirects must go through http::redirect::SeeOther; open-coded at:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// RFC 9113 §8.2.3: a user agent MAY split the cookie list across several
    /// `cookie` fields, and a server MUST join them before parsing.
    /// `HeaderMap::get` returns the first field only, so it silently drops
    /// every cookie that did not happen to be sent first — a bug with no
    /// symptom until two `__Host-` cookies exist at once, which is every page
    /// served to a signed-in user mid-flow (`ast-bze`).
    ///
    /// The correct read is `http::cookies`, which is `get_all` and a join.
    /// This is an absence property with an intermittent, client-dependent
    /// symptom, which is the worst kind to catch in review: the code looks
    /// right and passes every test written against a single-field request.
    #[test]
    fn the_cookie_header_is_never_read_as_a_single_field() {
        const FORBIDDEN: &[&str] = &[
            ".get(header::COOKIE)",
            ".get(&header::COOKIE)",
            ".get(COOKIE)",
            ".get(\"cookie\")",
            ".get(\"Cookie\")",
        ];

        let mut offenders = Vec::new();
        for (path, source) in workspace_sources() {
            // This file names every forbidden spelling in order to look for it.
            if is_at(&path, "http/source_audit.rs") {
                continue;
            }
            for (number, line) in code_lines(&source) {
                let condensed: String = line.chars().filter(|c| !c.is_whitespace()).collect();
                for needle in FORBIDDEN {
                    if condensed.contains(needle) {
                        offenders.push(format!("{path}:{number}: {needle}"));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "the cookie list may be split across fields; found:\n  {}\nUse crate::http::cookies.",
            offenders.join("\n  ")
        );
    }

    /// FAPI 2.0 SP §5.2.3: the authorization endpoint must not be reachable
    /// from a cross-origin script. The implementation is that no CORS layer
    /// exists; this is what keeps it that way when someone hits a browser
    /// error in the admin console and reaches for the obvious fix.
    ///
    /// The admin console is first-party and same-origin (`ast-f7m.2`), so it
    /// does not need CORS either.
    #[test]
    fn no_cors_layer_is_used_anywhere() {
        const FORBIDDEN: &[&str] = &[
            "CorsLayer",
            "tower_http::cors",
            "AllowOrigin",
            "allow_credentials(",
        ];

        let mut offenders = Vec::new();
        for (path, source) in workspace_sources() {
            if is_at(&path, "http/source_audit.rs") {
                continue;
            }
            for (number, line) in code_lines(&source) {
                for needle in FORBIDDEN {
                    if line.contains(needle) {
                        offenders.push(format!("{path}:{number}: {needle}"));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "no CORS layer may exist (FAPI 2.0 SP §5.2.3); found:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The `cors` feature of tower-http must not be enabled either — an
    /// unavailable API is a stronger guarantee than a grep.
    #[test]
    fn the_tower_http_cors_feature_is_not_enabled() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest).expect("read workspace manifest");
        let tower_http = text
            .lines()
            .find(|line| line.starts_with("tower-http"))
            .expect("tower-http is a workspace dependency");
        assert!(
            !tower_http.contains("\"cors\""),
            "tower-http must not enable the cors feature: {tower_http}"
        );
    }

    #[test]
    fn a_handler_under_src_that_open_codes_see_other_still_fails_the_audit() {
        let hostile = "        Response::builder().status(StatusCode::SEE_OTHER)\n";

        let offenders = open_coded_see_other("server/src/http/authorize.rs", hostile);

        assert_eq!(
            offenders,
            vec!["server/src/http/authorize.rs:1".to_string()]
        );
    }

    /// The exemption is for comparing a status, not for the word: a source
    /// file under `src/` gets none of it, even inside an assertion.
    #[test]
    fn an_assertion_under_src_is_not_exempt() {
        let unit_test = "        assert_eq!(response.status(), StatusCode::SEE_OTHER);\n";

        let offenders = open_coded_see_other("server/src/http/redirect_test.rs", unit_test);

        assert_eq!(offenders.len(), 1, "found: {offenders:?}");
    }

    #[test]
    fn an_integration_test_asserting_on_see_other_is_exempt() {
        let assertion = concat!(
            "        let started = self.get(&path).await;\n",
            "        assert_eq!(\n",
            "            started.status,\n",
            "            StatusCode::SEE_OTHER,\n",
            "            \"the request did not start an interaction\"\n",
            "        );\n",
        );

        let offenders = open_coded_see_other("server/tests/end_to_end.rs", assertion);

        assert!(offenders.is_empty(), "found: {offenders:?}");
    }

    #[test]
    fn an_integration_test_that_constructs_see_other_is_not_exempt() {
        let construction =
            "        let stub = Response::builder().status(StatusCode::SEE_OTHER);\n";

        let offenders = open_coded_see_other("server/tests/end_to_end.rs", construction);

        assert_eq!(offenders, vec!["server/tests/end_to_end.rs:1".to_string()]);
    }

    /// The audit is only worth having if it can fail, so prove the matcher
    /// works rather than trusting an empty result.
    #[test]
    fn the_audit_would_catch_a_violation() {
        let hostile = "    let r = StatusCode::TEMPORARY_REDIRECT;\n";
        assert!(code_lines(hostile).any(|(_, l)| l.contains("TEMPORARY_REDIRECT")));

        // ...and does not fire on a comment explaining why it is forbidden.
        let explanation = "    // never TEMPORARY_REDIRECT, see FAPI 2.0 SP §5.3.2.2\n";
        assert!(!code_lines(explanation).any(|(_, l)| l.contains("TEMPORARY_REDIRECT")));
    }
}
