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
            for (number, line) in code_lines(&source) {
                if line.contains("StatusCode::SEE_OTHER") {
                    offenders.push(format!("{path}:{number}"));
                }
            }
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
