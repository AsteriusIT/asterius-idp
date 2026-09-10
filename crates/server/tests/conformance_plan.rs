//! The OIDF plan's browser `match` patterns, against the routes this server
//! mounts.
//!
//! # Why this file exists
//!
//! `ast-7fj` found 55 of 56 modules of the FAPI 2.0 suite in `INTERRUPTED`
//! after `ast-295` moved the interaction pages under `/t/{tenant}/`. Nothing
//! failed: the plan (`conformance/plans/*.json`) still told the suite's browser
//! to wait for `https://asterius:9443/interaction/*`, the server answered 404
//! there, and the harness sat on a page that would never arrive. A plan and a
//! router drifting apart is silent by construction — the plan is data the suite
//! reads and the router is code the plan never sees.
//!
//! So the two are tied here. Every `match` in every plan, including the
//! per-module `override` map, is resolved the way a real request is resolved —
//! `asterius_oidc::tenancy::route`, the same function the tenancy middleware
//! calls — and the handler path that comes out must be a path the router
//! mounts. Reverting a pattern to `/interaction/*` fails this test instead of
//! the harness.
//!
//! The second half of the file guards `conformance/waivers.json`, the list of
//! modules whose failure does not stop a release (`ast-p2l.1`): every waiver
//! has to name a beads ticket that is still open.
//!
//! No database, no browser: JSON, the endpoint registry, and the page path
//! constants. It runs in the default suite like `source_audit`.

use asterius_oidc::metadata::Endpoint;
use asterius_oidc::tenancy;
use asterius_server::config::Config;
use asterius_server::http::{client_configuration, passkeys};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The interaction pages, which are deliberately absent from the [`Endpoint`]
/// registry: they are this server's own user interface, not a protocol surface
/// a client discovers. Kept in step with `protocol::routes` by
/// [`every_literal_route_in_protocol_is_known_here`].
const INTERACTION_PATH: &str = "/interaction/{id}";

/// The two discovery documents, mounted at literal paths in `protocol::routes`
/// because the tenancy layer normalises both spellings of the URL onto them.
const DISCOVERY_PATHS: [&str; 2] = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/server sits two levels under the repository root")
        .to_path_buf()
}

/// Every plan the repository ships, as (file name, parsed JSON).
fn plans() -> Vec<(String, Value)> {
    let dir = repo_root().join("conformance/plans");
    let mut plans = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("conformance/plans is readable") {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_some_and(|e| e == "json") {
            let name = path
                .file_name()
                .expect("a file has a name")
                .to_string_lossy()
                .into_owned();
            let text = std::fs::read_to_string(&path).expect("read the plan");
            let json: Value =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name} is not JSON: {e}"));
            plans.push((name, json));
        }
    }
    assert!(
        !plans.is_empty(),
        "conformance/plans holds no plan to check"
    );
    plans
}

/// What the conformance deployment offers, read from the configuration that
/// deployment actually boots with — so an endpoint switched off there is not
/// counted as mounted here.
fn conformance_capabilities() -> asterius_domain::Capabilities {
    let path = repo_root().join("conformance/asterius.toml");
    let text = std::fs::read_to_string(&path).expect("read conformance/asterius.toml");
    Config::parse(&text, &path, &BTreeMap::new())
        .expect("the conformance configuration parses")
        .features
}

/// Every path pattern the router mounts *under* a tenant, in axum's spelling.
fn mounted_paths() -> Vec<String> {
    let capabilities = conformance_capabilities();
    let mut paths: Vec<String> = Endpoint::enabled(&capabilities)
        .map(|endpoint| endpoint.path().to_owned())
        .collect();
    paths.extend(DISCOVERY_PATHS.iter().map(|path| (*path).to_owned()));
    paths.push(client_configuration::path());
    paths.push(INTERACTION_PATH.to_owned());
    paths.push(passkeys::PAGE_PATH.to_owned());
    paths.push(passkeys::OPTIONS_PATH.to_owned());
    paths.push(passkeys::FINISH_PATH.to_owned());
    paths.push(passkeys::LOGIN_OPTIONS_PATH.to_owned());
    paths.push(passkeys::LOGIN_FINISH_PATH.to_owned());
    paths
}

/// Whether `path` is what `pattern` mounts: segment by segment, with `{name}`
/// standing for exactly one segment, as axum's router matches.
fn mounts(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();
    pattern.len() == path.len()
        && pattern
            .iter()
            .zip(&path)
            .all(|(mounted, segment)| mounted.starts_with('{') || mounted == segment)
}

/// One `match` from a plan, with enough context to name it in a failure.
#[derive(Debug)]
struct Pattern {
    /// The plan file it came from.
    plan: String,
    /// The module it applies to, or `<default>` for the plan's own `browser`.
    module: String,
    /// The URL glob the suite matches the browser's location against.
    url: String,
}

/// Every browser `match` in a plan: the default `browser` block and each
/// module's `override`, block matches and task matches alike.
fn patterns(plan: &str, json: &Value) -> Vec<Pattern> {
    let mut found = Vec::new();
    let mut collect = |module: &str, browser: &Value| {
        for block in browser.as_array().into_iter().flatten() {
            let tasks = block
                .get("tasks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten();
            for value in std::iter::once(block).chain(tasks) {
                if let Some(url) = value.get("match").and_then(Value::as_str) {
                    found.push(Pattern {
                        plan: plan.to_owned(),
                        module: module.to_owned(),
                        url: url.to_owned(),
                    });
                }
            }
        }
    };

    if let Some(browser) = json.get("browser") {
        collect("<default>", browser);
    }
    for (module, value) in json
        .get("override")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        if let Some(browser) = value.get("browser") {
            collect(module, browser);
        }
    }
    assert!(!found.is_empty(), "{plan} declares no browser match");
    found
}

/// The authority and path of an absolute URL, without pulling in a parser: a
/// plan holds literal URLs, not user input.
fn split(url: &str) -> (String, String) {
    let rest = url
        .split_once("://")
        .map_or(url, |(_scheme, rest)| rest)
        .to_owned();
    match rest.find('/') {
        Some(slash) => (rest[..slash].to_owned(), rest[slash..].to_owned()),
        None => (rest, "/".to_owned()),
    }
}

/// A concrete path to resolve, from a glob the suite matches on: the trailing
/// `*` stands for a query string or for the identifier in the path.
fn probe(pattern_path: &str) -> String {
    let stem = pattern_path.trim_end_matches('*');
    if stem.is_empty() {
        return "/".to_owned();
    }
    if stem.ends_with('/') {
        return format!("{stem}an-identifier");
    }
    stem.to_owned()
}

/// Every `match` aimed at this server names a route the router mounts, under
/// the tenant the plan's own discovery URL names.
#[test]
fn every_plan_match_names_a_mounted_route() {
    // Arrange.
    let mounted = mounted_paths();

    for (plan, json) in plans() {
        let discovery = json
            .get("server")
            .and_then(|server| server.get("discoveryUrl"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{plan} declares no server.discoveryUrl"))
            .to_owned();
        let (authority, discovery_path) = split(&discovery);
        let expected_tenant = tenancy::route(&discovery_path)
            .unwrap_or_else(|e| panic!("{plan}: discoveryUrl is not a route: {e}"))
            .tenant;

        for pattern in patterns(&plan, &json) {
            let (host, path) = split(&pattern.url);
            // The suite's own callback page is not served by this server.
            if host != authority {
                continue;
            }

            // Act.
            let route = tenancy::route(&probe(&path)).unwrap_or_else(|e| {
                panic!(
                    "{}: module {}: match {} is not a routable path: {e}",
                    pattern.plan, pattern.module, pattern.url
                )
            });

            // Assert.
            assert_eq!(
                route.tenant, expected_tenant,
                "{}: module {}: match {} does not name the tenant its discoveryUrl does — \
                 a page mounted under /t/<tenant>/ is a 404 at the root (ast-295)",
                pattern.plan, pattern.module, pattern.url
            );
            assert!(
                mounted
                    .iter()
                    .any(|route_path| mounts(route_path, &route.path)),
                "{}: module {}: match {} resolves to {}, which no route mounts; \
                 the router mounts {:?}",
                pattern.plan,
                pattern.module,
                pattern.url,
                route.path,
                mounted
            );
        }
    }
}

/// The page paths this file lists are the page paths `protocol::routes` mounts.
///
/// The endpoint paths come from the registry and cannot drift. The pages do
/// not: they are string literals at the `.route` call. So the literals in that
/// file are read back and each one must be known here, which is what stops a
/// new page from being mounted and silently left out of the check above.
#[test]
fn every_literal_route_in_protocol_is_known_here() {
    // Arrange.
    let source = std::fs::read_to_string(repo_root().join("crates/server/src/http/protocol.rs"))
        .expect("read protocol.rs");
    let mounted = mounted_paths();

    // Act.
    let literals: Vec<String> = source
        .split(".route(")
        .skip(1)
        .filter_map(|tail| {
            let quote = tail.find('"')?;
            // Only a literal that opens the argument is a route path; a string
            // further along belongs to some other expression.
            if tail[..quote].chars().any(|c| !c.is_whitespace()) {
                return None;
            }
            let rest = &tail[quote + 1..];
            let end = rest.find('"')?;
            Some(rest[..end].to_owned())
        })
        .collect();

    // Assert.
    assert!(
        !literals.is_empty(),
        "no literal route found in protocol.rs — has the parsing gone stale?"
    );
    for literal in literals {
        assert!(
            mounted.contains(&literal),
            "protocol.rs mounts {literal}, which this test's route table does not know; \
             add it so the conformance plan check can see it"
        );
    }
}

// ---------------------------------------------------------------------------
// The waiver list.
//
// `ast-p2l.1`: the FAPI 2.0 plan does not end at "100 % pass", so
// `scripts/conformance-verdict.py` treats PASSED, REVIEW, WARNING and SKIPPED
// as green and FAILED as red — unless `conformance/waivers.json` names the
// module. A waiver is a decision to ship a known non-conformance, and what makes
// it a decision rather than a shrug is the ticket attached to it.
//
// So the ticket is checked here, on every pull request, and not in the gate that
// runs at 3am: a waiver whose ticket has been closed is a failure nobody is
// dealing with any more, and the moment to find that out is the moment the
// ticket is closed. `.beads/issues.jsonl` is a passive export of the tracker —
// if it is stale, this test is stale with it, which is the same bargain every
// other check that reads a committed file makes.
// ---------------------------------------------------------------------------

/// The waiver entries, as the JSON objects they are written as.
fn waivers() -> Vec<Value> {
    let path = repo_root().join("conformance/waivers.json");
    let text = std::fs::read_to_string(&path).expect("conformance/waivers.json is readable");
    let json: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("conformance/waivers.json is not JSON: {e}"));
    json.get("waivers")
        .and_then(Value::as_array)
        .expect("conformance/waivers.json has a 'waivers' array")
        .clone()
}

/// The status beads holds for an issue, or `None` if the export has never heard
/// of it.
fn beads_status(id: &str) -> Option<String> {
    let path = repo_root().join(".beads/issues.jsonl");
    let text = std::fs::read_to_string(&path).expect(".beads/issues.jsonl is readable");
    for line in text.lines() {
        let Ok(issue) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if issue.get("id").and_then(Value::as_str) == Some(id) {
            return issue
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
    }
    None
}

/// Every waiver says which module, why, when, and under which ticket.
#[test]
fn every_waiver_is_a_decision_somebody_wrote_down() {
    // Arrange.
    let entries = waivers();
    let mut seen: Vec<String> = Vec::new();

    for waiver in entries {
        // Act.
        let module = waiver
            .get("module")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let ticket = waiver.get("ticket").and_then(Value::as_str).unwrap_or("");
        let reason = waiver.get("reason").and_then(Value::as_str).unwrap_or("");
        let recorded = waiver.get("recorded").and_then(Value::as_str).unwrap_or("");

        // Assert.
        assert!(
            !module.is_empty(),
            "a waiver in conformance/waivers.json names no module"
        );
        assert!(
            ticket.starts_with("ast-"),
            "the waiver for {module} names {ticket:?}, which is not a beads id"
        );
        assert!(
            reason.len() >= 40,
            "the waiver for {module} explains itself in {} characters. A waiver is read \
             by somebody deciding whether to ship without this module passing",
            reason.len()
        );
        assert!(
            recorded.len() == 10 && recorded.split('-').count() == 3,
            "the waiver for {module} was recorded {recorded:?}, which is not a YYYY-MM-DD date"
        );
        assert!(
            !seen.contains(&module),
            "{module} is waived twice; the second entry is dead text"
        );
        seen.push(module);
    }
}

/// A waived module names a ticket, and that ticket is still open.
#[test]
fn every_waiver_names_a_ticket_beads_still_has_open() {
    for waiver in waivers() {
        // Arrange.
        let module = waiver
            .get("module")
            .and_then(Value::as_str)
            .expect("a waiver names a module");
        let ticket = waiver
            .get("ticket")
            .and_then(Value::as_str)
            .expect("a waiver names a ticket");

        // Act.
        let status = beads_status(ticket);

        // Assert.
        let status = status.unwrap_or_else(|| {
            panic!(
                "the waiver for {module} names {ticket}, which beads does not know. A \
                 conformance failure waived under a ticket that does not exist is a \
                 failure nobody is dealing with"
            )
        });
        assert_ne!(
            status, "closed",
            "the waiver for {module} names {ticket}, which is closed. Either the module \
             passes now and the waiver goes, or the work is not done and the ticket \
             reopens — but the conformance suite must not be waived on a finished ticket"
        );
    }
}
