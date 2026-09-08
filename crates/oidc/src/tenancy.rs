//! Turning a request's host and path into a tenant.
//!
//! Asterius is multi-tenant and a tenant *is* an issuer, so the first thing any
//! request needs is the answer to "whose authorization server is this?". Two
//! things make that more than a prefix match.
//!
//! **There are two well-known forms, and clients use both.** For an issuer with
//! a path component, OIDC Discovery §4 appends: `{issuer}/.well-known/{doc}`.
//! RFC 8414 §3.1 inserts instead: `https://{host}/.well-known/{doc}{path}`. MCP
//! Authorization tells clients to try both. So
//! `/t/demo/.well-known/openid-configuration` and
//! `/.well-known/openid-configuration/t/demo` are the same request, and both
//! must resolve to the same tenant.
//!
//! **The tenant id arrives from the network.** It is a path segment under
//! attacker control, and it is about to select which tenant's keys sign a
//! token. [`TenantId::parse`] is what stands between those two facts.
//!
//! This module is pure: it does not know whether a tenant exists, only what the
//! request is asking for. Deciding whether the answer is a real, active tenant
//! is the adapter's job.

use asterius_domain::{TenantId, TenantIdError};

/// The path segment that introduces a tenant in a path-based issuer.
pub const TENANT_PREFIX: &str = "/t/";

/// The prefix every well-known document lives under (RFC 8615).
pub const WELL_KNOWN_PREFIX: &str = "/.well-known/";

/// How a request named its tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// `/t/{tenant}/…` — the ordinary shape, and OIDC Discovery §4's
    /// path-appending form for metadata.
    PathAppended,
    /// `/.well-known/{document}/t/{tenant}` — RFC 8414 §3.1's path-insertion
    /// form. Only ever seen on metadata requests.
    PathInserted,
    /// No tenant in the path. The host must identify the tenant instead.
    HostOnly,
}

/// What a request's path is asking for, once tenancy is removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The tenant named in the path, if any.
    pub tenant: Option<TenantId>,
    /// The path a protocol handler should see: tenancy stripped, so handlers
    /// are mounted at `/authorize` and `/token` and never learn that tenants
    /// exist.
    pub path: String,
    /// Which form the client used.
    pub form: Form,
}

/// Why a path could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteError {
    /// The path named a tenant, but not a usable one.
    #[error("invalid tenant identifier: {0}")]
    Tenant(#[from] TenantIdError),
    /// The path-insertion form was used with a trailing path that is not a
    /// tenant, so there is nothing to resolve.
    #[error("well-known path suffix {0:?} is not a tenant path")]
    NotATenantPath(String),
    /// The input was not an absolute path.
    ///
    /// Found by fuzzing: `route("")` used to return a `Route` whose `path` was
    /// empty, which is not a path and which every caller assumes cannot happen.
    /// An HTTP request always carries at least `/`, so this is unreachable
    /// through the server — but a postcondition that only holds for the inputs
    /// someone remembered is not a postcondition.
    #[error("not an absolute path: {0:?}")]
    NotAPath(String),
    /// The path contains a `.` or `..` segment.
    ///
    /// Also found by fuzzing. No endpoint this server publishes has a
    /// relative segment in its path, so one can only be an attempt to reach a
    /// handler by a spelling that review and routing tables did not consider.
    /// Rejecting is cheaper than reasoning about which normalisation every
    /// proxy in front of us performs.
    #[error("path contains a relative segment: {0:?}")]
    RelativeSegment(String),
}

/// Splits a request path into a tenant and the path a handler should see.
///
/// # Errors
///
/// Returns [`RouteError`] when the path names a tenant that is not a valid
/// identifier, or uses the path-insertion form with a suffix that is not a
/// tenant path. Both are client errors, not "tenant not found": the request is
/// malformed regardless of which tenants exist.
// fuzz-target: tenant_route
pub fn route(path: &str) -> Result<Route, RouteError> {
    if !path.starts_with('/') {
        return Err(RouteError::NotAPath(path.to_owned()));
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(RouteError::RelativeSegment(path.to_owned()));
    }

    // RFC 8414 §3.1 path-insertion: /.well-known/{document}{issuer-path}
    if let Some(rest) = path.strip_prefix(WELL_KNOWN_PREFIX) {
        let (document, suffix) = match rest.find('/') {
            Some(slash) => (&rest[..slash], &rest[slash..]),
            None => (rest, ""),
        };

        if suffix.is_empty() {
            // `/.well-known/{document}` with nothing after it: the host has to
            // name the tenant.
            return Ok(Route {
                tenant: None,
                path: path.to_owned(),
                form: Form::HostOnly,
            });
        }

        let tenant = tenant_from_prefix(suffix)
            .ok_or_else(|| RouteError::NotATenantPath(suffix.to_owned()))?;
        let (tenant, remainder) = tenant?;
        if !remainder.is_empty() {
            // `/.well-known/x/t/demo/extra` is not a form any specification
            // defines, and guessing at it would be a way to reach a handler
            // through an unexpected path.
            return Err(RouteError::NotATenantPath(suffix.to_owned()));
        }
        return Ok(Route {
            tenant: Some(tenant),
            path: format!("{WELL_KNOWN_PREFIX}{document}"),
            form: Form::PathInserted,
        });
    }

    // Ordinary path-based tenancy: /t/{tenant}/…
    if let Some(parsed) = tenant_from_prefix(path) {
        let (tenant, remainder) = parsed?;
        return Ok(Route {
            tenant: Some(tenant),
            path: if remainder.is_empty() {
                "/".to_owned()
            } else {
                remainder.to_owned()
            },
            form: Form::PathAppended,
        });
    }

    Ok(Route {
        tenant: None,
        path: path.to_owned(),
        form: Form::HostOnly,
    })
}

/// Reads a `/t/{tenant}` prefix, returning the tenant and what follows it.
///
/// `None` means the path does not start with the tenant prefix at all;
/// `Some(Err(_))` means it does but the identifier is unusable.
fn tenant_from_prefix(path: &str) -> Option<Result<(TenantId, &str), RouteError>> {
    let rest = path.strip_prefix(TENANT_PREFIX)?;
    let (raw, remainder) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, ""),
    };
    Some(
        TenantId::parse(raw)
            .map(|tenant| (tenant, remainder))
            .map_err(RouteError::Tenant),
    )
}

/// Builds the path-appending well-known URL for an issuer path (OIDC Discovery §4).
#[must_use]
pub fn path_appended(issuer_path: &str, document: &str) -> String {
    format!("{issuer_path}{WELL_KNOWN_PREFIX}{document}")
}

/// Builds the path-insertion well-known URL for an issuer path (RFC 8414 §3.1).
#[must_use]
pub fn path_inserted(issuer_path: &str, document: &str) -> String {
    format!("{WELL_KNOWN_PREFIX}{document}{issuer_path}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(path: &str) -> Route {
        route(path).unwrap_or_else(|e| panic!("{path:?} should resolve: {e}"))
    }

    #[test]
    fn a_tenant_path_is_stripped_before_handlers_see_it() {
        let resolved = ok("/t/demo/authorize");
        assert_eq!(resolved.tenant.as_ref().map(TenantId::as_str), Some("demo"));
        assert_eq!(resolved.path, "/authorize");
        assert_eq!(resolved.form, Form::PathAppended);
    }

    #[test]
    fn a_bare_tenant_path_resolves_to_the_root() {
        assert_eq!(ok("/t/demo").path, "/");
        assert_eq!(ok("/t/demo/").path, "/");
    }

    /// The acceptance criterion for `ast-83p.10`, and the reason this module
    /// exists: MCP clients try both forms, and both must land on one tenant and
    /// one handler path.
    #[test]
    fn both_well_known_forms_resolve_to_the_same_tenant_and_document() {
        let appended = ok("/t/demo/.well-known/openid-configuration");
        let inserted = ok("/.well-known/openid-configuration/t/demo");

        assert_eq!(appended.tenant, inserted.tenant);
        assert_eq!(appended.path, "/.well-known/openid-configuration");
        assert_eq!(inserted.path, "/.well-known/openid-configuration");
        assert_eq!(appended.form, Form::PathAppended);
        assert_eq!(inserted.form, Form::PathInserted);
    }

    #[test]
    fn both_forms_work_for_every_well_known_document_we_serve() {
        for document in [
            "openid-configuration",
            "oauth-authorization-server",
            "ssf-configuration",
            "authzen-configuration",
        ] {
            let appended = ok(&path_appended("/t/demo", document));
            let inserted = ok(&path_inserted("/t/demo", document));
            assert_eq!(appended.path, format!("/.well-known/{document}"));
            assert_eq!(inserted.path, format!("/.well-known/{document}"));
            assert_eq!(appended.tenant, inserted.tenant);
        }
    }

    #[test]
    fn a_well_known_document_with_no_tenant_path_is_left_to_the_host() {
        let resolved = ok("/.well-known/openid-configuration");
        assert_eq!(resolved.tenant, None);
        assert_eq!(resolved.path, "/.well-known/openid-configuration");
        assert_eq!(resolved.form, Form::HostOnly);
    }

    #[test]
    fn a_path_without_tenancy_is_left_alone() {
        for path in ["/", "/authorize", "/token", "/admin/api/v1/tenants"] {
            let resolved = ok(path);
            assert_eq!(resolved.tenant, None);
            assert_eq!(resolved.path, path);
            assert_eq!(resolved.form, Form::HostOnly);
        }
    }

    /// `/t/` is the tenant prefix, but `/tokens` merely starts with `/t`.
    #[test]
    fn the_tenant_prefix_matches_a_whole_segment() {
        assert_eq!(ok("/token").tenant, None);
        assert_eq!(ok("/tokens/x").tenant, None);
        assert_eq!(ok("/t").tenant, None);
    }

    /// A tenant id is attacker-controlled and is about to choose signing keys.
    #[test]
    fn a_malformed_tenant_is_an_error_not_a_lookup() {
        // Literal `..` is caught earlier, by the relative-segment rule; these
        // are the ones that reach the identifier check.
        for path in ["/t/%2e%2e/authorize", "/t/Demo/authorize", "/t//authorize"] {
            assert!(
                matches!(route(path), Err(RouteError::Tenant(_))),
                "{path:?} was not rejected: {:?}",
                route(path)
            );
        }
    }

    /// The path-insertion form is defined as issuer-path-after-document and
    /// nothing else. Anything trailing is not a form any specification defines,
    /// and guessing would be a way to reach a handler by an unexpected route.
    #[test]
    fn the_insertion_form_rejects_a_suffix_that_is_not_exactly_a_tenant() {
        for path in [
            "/.well-known/openid-configuration/t/demo/extra",
            "/.well-known/openid-configuration/not-a-tenant",
            "/.well-known/openid-configuration/authorize",
        ] {
            assert!(
                matches!(route(path), Err(RouteError::NotATenantPath(_))),
                "{path:?} was not rejected: {:?}",
                route(path)
            );
        }
    }

    /// Found by fuzzing: every accepted route must hand downstream something
    /// that is actually a path, and an input that is not one must be refused
    /// rather than passed through.
    #[test]
    fn an_input_that_is_not_a_path_is_refused() {
        for not_a_path in [
            "",
            "authorize",
            "t/demo/authorize",
            "https://as.example/authorize",
        ] {
            assert!(
                matches!(route(not_a_path), Err(RouteError::NotAPath(_))),
                "accepted {not_a_path:?}: {:?}",
                route(not_a_path)
            );
        }
    }

    #[test]
    fn every_accepted_route_yields_an_absolute_path() {
        for path in [
            "/",
            "/t/demo",
            "/t/demo/authorize",
            "/.well-known/openid-configuration",
        ] {
            assert!(ok(path).path.starts_with('/'), "{path} produced a non-path");
        }
    }

    #[test]
    fn the_two_builders_agree_with_the_resolver() {
        let appended = path_appended("/t/demo", "openid-configuration");
        let inserted = path_inserted("/t/demo", "openid-configuration");
        assert_eq!(appended, "/t/demo/.well-known/openid-configuration");
        assert_eq!(inserted, "/.well-known/openid-configuration/t/demo");
        assert_eq!(ok(&appended).tenant, ok(&inserted).tenant);
    }
}
