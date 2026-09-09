//! `Config::parse` — the TOML file and the environment overrides.
//!
//! Configuration is not attacker-controlled in a healthy deployment, but it is
//! the first thing that runs, it merges two sources with different trust, and
//! it is edited under pressure during an incident. It must fail rather than
//! panic, whatever it is handed.
#![no_main]

use asterius_server::Config;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Half the input becomes an environment override, so the merge path is
    // exercised as well as the parser. The split has to land on a character
    // boundary: `text.len() / 2` does not, and slicing there panics — which is
    // how this target crashed on its first run, in the harness rather than in
    // the parser.
    let midpoint = text.chars().count() / 2;
    let split = text
        .char_indices()
        .nth(midpoint)
        .map_or(text.len(), |(index, _)| index);
    let mut env = BTreeMap::new();
    if split < text.len() {
        env.insert(
            "ASTERIUS__DATABASE__URL".to_owned(),
            text[split..].to_owned(),
        );
    }

    let Ok(config) = Config::parse(text, Path::new("fuzz.toml"), &env) else {
        return;
    };

    // Anything accepted must satisfy what the rest of the server assumes.
    for tenant in &config.tenants {
        assert!(tenant.issuer.as_str().starts_with("https://"));
        assert!(!tenant.id.as_str().is_empty());
    }
    assert!(config.server.request_timeout.as_secs() < u64::from(u32::MAX));
});
