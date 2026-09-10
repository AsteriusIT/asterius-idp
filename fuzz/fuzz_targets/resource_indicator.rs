//! Resource indicators — RFC 8707 §2, §3.
//!
//! A `resource` is attacker-controlled text that becomes the `aud` of an access
//! token: whatever this parser accepts, some resource server will one day
//! compare against its own identifier. Four properties matter, and each of them
//! is a way a token could end up accepted by something it was not meant for:
//!
//! * **What is accepted is an absolute, fragment-free URI.** RFC 8707 §2. A
//!   fragment never reaches a server, so two indicators differing only there
//!   name one resource while looking like two.
//! * **The value is preserved byte for byte.** §2's comparison is a simple
//!   string comparison against what was registered; a parser that normalised
//!   would match a spelling the resource server does not.
//! * **Parsing is total and deterministic.** No input panics, and the same
//!   input always gives the same answer — a registry lookup that varied per
//!   call would be an audience that intermittently exists.
//! * **The registry is the authority.** A value the registry does not hold is
//!   `invalid_target` however well formed, and a token is never audienced at
//!   something nobody registered (RFC 9068 §2.2 makes `aud` REQUIRED, and an
//!   empty audience is refused rather than issued).
#![no_main]

use asterius_domain::{Grant, InvalidTarget, ResourceIdentifier, ResourceRegistry, ResourceServer};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

/// The one identifier the fuzzed registry holds.
const REGISTERED: &str = "https://api.example/v1";

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let registry = ResourceRegistry::new([ResourceServer {
        identifier: ResourceIdentifier::parse(REGISTERED).expect("a fixed identifier"),
        scopes: Some(["read".to_owned()].into_iter().collect()),
        default_token_lifetime: None,
    }]);

    match ResourceIdentifier::parse(text) {
        Err(InvalidTarget) => {
            // Refusing is total: the registry refuses it too, whatever it holds.
            assert!(!registry.registers(text), "an unparsable value resolved");
        }
        Ok(parsed) => {
            // Byte for byte, or the comparison at the resource server is not
            // the comparison this server made.
            assert_eq!(parsed.as_str(), text);
            // Deterministic.
            assert_eq!(
                ResourceIdentifier::parse(text)
                    .as_ref()
                    .map(ResourceIdentifier::as_str),
                Ok(text)
            );
            // RFC 8707 §2's two rules, restated as properties of the output.
            assert!(!text.contains('#'), "accepted a fragment: {text:?}");
            let url = url::Url::parse(text).expect("an accepted value parses as a URL");
            assert!(
                url.has_host(),
                "accepted a value with no authority: {text:?}"
            );

            // §3: well formed is not the same as registered.
            assert_eq!(
                registry.registers(text),
                text == REGISTERED,
                "the registry accepted something it does not hold: {text:?}"
            );
        }
    }

    // Whatever the input, the audience decision is total and never empty.
    let requested: BTreeSet<String> = [text.to_owned()].into_iter().collect();
    let registered: BTreeSet<String> = [REGISTERED.to_owned()].into_iter().collect();
    for (request, authorised, defaults) in [
        (&requested, &BTreeSet::new(), &registered),
        (&requested, &registered, &BTreeSet::new()),
        (&BTreeSet::new(), &requested, &requested),
    ] {
        match registry.targets(request, authorised, defaults) {
            Err(InvalidTarget) => {}
            Ok(targets) => {
                assert!(!targets.is_empty(), "an empty audience was allowed");
                assert!(targets.len() <= Grant::MAX_RESOURCES);
                for target in &targets {
                    assert!(
                        registry.registers(target),
                        "audienced at something unregistered: {target:?}"
                    );
                }
                // Narrowing only: a scope the grant does not carry cannot
                // appear, and a scope the resource server refuses cannot either.
                let granted: BTreeSet<String> = ["read".to_owned(), "write".to_owned()]
                    .into_iter()
                    .collect();
                let permitted = registry.permitted_scopes(&targets, &granted);
                assert!(permitted.iter().all(|scope| granted.contains(scope)));
                assert!(!permitted.contains("write"));
            }
        }
    }
});
