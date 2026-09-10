//! A source-level check that no query forgets its tenant.
//!
//! The schema puts `tenant_id` first in every primary key, and [`TenantScope`]
//! makes the tenant a precondition rather than an argument — but neither stops
//! someone writing `select … from clients` with no predicate. This test reads
//! the crate's own source and requires that any statement naming a
//! tenant-scoped table also names `tenant_id`.
//!
//! It runs with no database and finishes in about a millisecond, so it is part
//! of the default `cargo test` rather than something CI alone catches.
//!
//! [`TenantScope`]: crate::TenantScope

#![cfg(test)]

/// Tables whose rows belong to exactly one tenant.
///
/// `tenants` is absent on purpose: it is the table that *resolves* a tenant, so
/// a lookup by issuer or host legitimately has no tenant predicate yet.
const TENANT_SCOPED_TABLES: &[&str] = &[
    "clients",
    "client_keys",
    "client_key_fetches",
    "users",
    "subject_identifiers",
    "retired_subject_identifiers",
    "credentials",
    "sessions",
    "session_clients",
    "auth_requests",
    "grants",
    "authorization_codes",
    "refresh_tokens",
    "access_token_denylist",
    "access_token_cutoffs",
    "jti_replay",
    "signing_keys",
    "key_rotation_schedules",
    "audit_events",
    "outbox",
    "rate_limits",
    "resource_servers",
    "authorization_details_types",
    "initial_access_tokens",
    "recovery_tokens",
];

/// Extracts the SQL string literals passed to `sqlx` macros in one file.
///
/// Crude on purpose: it looks for `sqlx::query` and takes the double-quoted
/// strings that follow, up to the closing parenthesis of the macro. A parser
/// that understood Rust would be more precise and would also be a thing to
/// maintain; over-collecting here only makes the check stricter.
fn sql_literals(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let bytes = source.as_bytes();
    let mut cursor = 0;
    while let Some(start) = source[cursor..].find("sqlx::query") {
        let mut i = cursor + start;
        let mut depth = 0_i32;
        let mut current: Option<String> = None;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth <= 0 {
                        i += 1;
                        break;
                    }
                }
                b'"' => {
                    let mut j = i + 1;
                    let mut literal = String::new();
                    while j < bytes.len() && bytes[j] != b'"' {
                        if bytes[j] == b'\\' {
                            j += 1;
                        }
                        if j < bytes.len() {
                            literal.push(bytes[j] as char);
                        }
                        j += 1;
                    }
                    current.get_or_insert_with(String::new).push_str(&literal);
                    current.as_mut().expect("just inserted").push(' ');
                    i = j;
                }
                _ => {}
            }
            i += 1;
        }
        if let Some(sql) = current {
            found.push(sql);
        }
        cursor = i;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crate_sources() -> Vec<(String, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&root).expect("read src/") {
            let path = entry.expect("dir entry").path();
            // This file's own fixtures are deliberately non-compliant.
            if path.file_name().is_some_and(|n| n == "sql_audit.rs") {
                continue;
            }
            if path.extension().is_some_and(|e| e == "rs") {
                let name = path
                    .file_name()
                    .expect("file name")
                    .to_string_lossy()
                    .into_owned();
                files.push((name, std::fs::read_to_string(&path).expect("read source")));
            }
        }
        assert!(!files.is_empty(), "found no sources to audit");
        files
    }

    #[test]
    fn every_query_over_a_tenant_scoped_table_names_tenant_id() {
        let mut offenders = Vec::new();
        for (file, source) in crate_sources() {
            for sql in sql_literals(&source) {
                let lowered = sql.to_lowercase();
                let touches: Vec<&str> = TENANT_SCOPED_TABLES
                    .iter()
                    .copied()
                    .filter(|table| {
                        // Word-ish match, so `clients` does not fire on
                        // `session_clients` and vice versa.
                        lowered
                            .split(|c: char| !c.is_alphanumeric() && c != '_')
                            .any(|word| word == *table)
                    })
                    .collect();
                if !touches.is_empty() && !lowered.contains("tenant_id") {
                    offenders.push(format!("{file}: {touches:?} in `{}`", sql.trim()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "these statements touch tenant-scoped tables without a tenant_id predicate:\n  {}",
            offenders.join("\n  ")
        );
    }

    #[test]
    fn the_audit_actually_finds_the_queries_it_is_auditing() {
        // A silent check that never matches anything is worse than no check, so
        // assert the extractor works on both a good and a bad statement.
        let good = r#"sqlx::query!("select 1 from clients where tenant_id = $1", x)"#;
        let bad = r#"sqlx::query_as!(Row, "select 1 from grants")"#;
        assert_eq!(sql_literals(good).len(), 1, "extractor missed a query");
        assert!(sql_literals(good)[0].contains("tenant_id"));
        assert_eq!(sql_literals(bad).len(), 1);
        assert!(!sql_literals(bad)[0].contains("tenant_id"));
    }

    #[test]
    fn the_audit_reads_the_real_tenant_repository() {
        let sources = crate_sources();
        let (_, tenants) = sources
            .iter()
            .find(|(name, _)| name == "tenants.rs")
            .expect("tenants.rs is audited");
        assert!(
            sql_literals(tenants).len() >= 6,
            "expected every tenant repository statement to be extracted"
        );
    }
}
