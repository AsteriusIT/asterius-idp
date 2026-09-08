//! Two checks that keep `==` away from secret material.
//!
//! The first is the one that carries the weight. [`Secret`] and [`OpaqueToken`]
//! do not implement `PartialEq`, so `==` on them is a compile error rather than
//! a review finding. That is a stronger guarantee than any grep, for three
//! reasons: it holds for code nobody has written yet, it holds in crates this
//! file never reads, and it holds where the comparison is reached through a
//! generic bound and the characters `==` appear nowhere. What a test can add is
//! the other half — the compiler will not tell us that a trait we never wanted
//! is *still* absent, so we ask it, and a future `#[derive(PartialEq)]` fails
//! the build instead of quietly reopening the oracle.
//!
//! The second check exists because the type-level guarantee has exactly one
//! exit. `secret.expose() == candidate` compiles: it compares two `&str` with
//! the ordinary short-circuiting operator, and it is precisely the timing
//! oracle the first check removed. That one can only be caught textually, so it
//! is caught textually, over every crate in the workspace, in the manner of
//! `crates/server/src/http/source_audit.rs`.
//!
//! [`Secret`]: crate::Secret
//! [`OpaqueToken`]: crate::OpaqueToken

#![cfg(test)]

use std::marker::PhantomData;
use std::path::Path;

/// Answers "does `T` implement `PartialEq`?" without needing `T` to implement
/// it, and without a nightly feature.
///
/// An inherent associated constant wins over a trait one during path
/// resolution — but only when its `where` clause is satisfied. So a `T` that is
/// `PartialEq` resolves to the inherent `true`, and everything else falls back
/// to the blanket `false`. The type is never constructed; only its associated
/// constant is ever named.
struct Probe<T: ?Sized>(PhantomData<T>);

trait ProbeFallback {
    const IMPLEMENTS_PARTIAL_EQ: bool = false;
}

impl<T: ?Sized> ProbeFallback for Probe<T> {}

impl<T: PartialEq + ?Sized> Probe<T> {
    const IMPLEMENTS_PARTIAL_EQ: bool = true;
}

/// Every `.rs` file in the workspace's own crates, with its repo-relative path.
fn workspace_sources() -> Vec<(String, String)> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/domain has a parent")
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

/// The code of a file, one entry per line, with pure-comment lines dropped and
/// obvious continuations folded into the line that starts them.
///
/// The fold is what makes the check survive `rustfmt`: a comparison long enough
/// to be wrapped puts the operator on its own line, and a per-line scan would
/// see two innocent halves. A line that ends in `;`, `{` or `}` has finished,
/// so folding stops there and an unrelated neighbour is not dragged in.
fn logical_lines(source: &str) -> Vec<(usize, String)> {
    let code: Vec<(usize, &str)> = source
        .lines()
        .enumerate()
        .map(|(n, line)| (n + 1, line.trim()))
        .filter(|(_, line)| !line.starts_with("//") && !line.starts_with('*'))
        .collect();

    code.iter()
        .enumerate()
        .map(|(index, (number, line))| {
            let folded = if line.ends_with(';') || line.ends_with('{') || line.ends_with('}') {
                (*line).to_owned()
            } else {
                match code.get(index + 1) {
                    Some((_, next)) => format!("{line} {next}"),
                    None => (*line).to_owned(),
                }
            };
            (*number, folded)
        })
        .collect()
}

/// Whether a logical line compares an exposed secret with an operator instead
/// of a constant-time comparison.
fn compares_an_exposed_secret(line: &str) -> bool {
    line.contains(".expose()")
        && (line.contains("==")
            || line.contains("!=")
            || line.contains(".eq(")
            || line.contains(".ne("))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpaqueToken, Secret, TenantId};

    /// The absence asserted here is what makes `token == presented` — the most
    /// natural thing to write at a token endpoint — refuse to compile.
    ///
    /// These are `const` blocks, so they are checked when the crate is built
    /// rather than when the test runs: adding a `PartialEq` impl fails the
    /// build, and the error points here. The `#[test]` wrapper exists so the
    /// property has a name in the suite and so the failure has an address.
    #[test]
    fn no_type_that_carries_a_secret_implements_partial_eq() {
        const {
            assert!(
                !Probe::<Secret<String>>::IMPLEMENTS_PARTIAL_EQ,
                "Secret<String> implements PartialEq: `==` on a secret compiles again"
            );
        }
        const {
            assert!(
                !Probe::<Secret<Vec<u8>>>::IMPLEMENTS_PARTIAL_EQ,
                "Secret<Vec<u8>> implements PartialEq: `==` on a secret compiles again"
            );
        }
        const {
            assert!(
                !Probe::<OpaqueToken>::IMPLEMENTS_PARTIAL_EQ,
                "OpaqueToken implements PartialEq: `==` on a token compiles again"
            );
        }
    }

    /// A probe that answered `false` for everything would make the check above
    /// pass by accident, which is the failure mode of every absence check.
    #[test]
    fn the_probe_still_recognises_a_type_that_does_implement_partial_eq() {
        const { assert!(Probe::<String>::IMPLEMENTS_PARTIAL_EQ) };
        const { assert!(Probe::<TenantId>::IMPLEMENTS_PARTIAL_EQ) };
        const { assert!(Probe::<[u8]>::IMPLEMENTS_PARTIAL_EQ) };
    }

    /// The acceptance criterion in full: codes, tokens, PKCE verifiers and CSRF
    /// tokens are compared with [`crate::secret::ct_eq`] and with nothing else.
    #[test]
    fn no_exposed_secret_is_compared_with_an_equality_operator() {
        let mut offenders = Vec::new();
        for (path, source) in workspace_sources() {
            // This file names the pattern in order to look for it.
            if path.ends_with("domain/src/secret_audit.rs") {
                continue;
            }
            for (number, line) in logical_lines(&source) {
                if compares_an_exposed_secret(&line) {
                    offenders.push(format!("{path}:{number}: {line}"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "a secret must be compared with ct_eq, never with an operator; found:\n  {}",
            offenders.join("\n  ")
        );
    }

    #[test]
    fn the_source_audit_would_catch_a_violation() {
        let hostile = "if code.expose() == presented {\n";
        assert!(
            logical_lines(hostile)
                .iter()
                .any(|(_, l)| compares_an_exposed_secret(l))
        );

        let reversed = "let ok = presented != stored.expose();\n";
        assert!(
            logical_lines(reversed)
                .iter()
                .any(|(_, l)| compares_an_exposed_secret(l))
        );

        // Wrapped by rustfmt across two lines, which a per-line scan would miss.
        let wrapped = "let ok = verifier.expose()\n== challenge;\n";
        assert!(
            logical_lines(wrapped)
                .iter()
                .any(|(_, l)| compares_an_exposed_secret(l))
        );

        // ...and does not fire on the comment that explains why it is banned.
        let explanation = "// never write secret.expose() == other; use ct_eq\n";
        assert!(logical_lines(explanation).is_empty());

        // ...nor on a legitimate exposure next to an unrelated comparison.
        let innocent = "let url = config.url.expose();\nif retries == 0 {\n";
        assert!(
            !logical_lines(innocent)
                .iter()
                .any(|(_, l)| compares_an_exposed_secret(l))
        );
    }
}
