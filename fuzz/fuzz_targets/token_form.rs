//! Token endpoint dispatch — RFC 6749 §3.2, §5.2.
//!
//! Dispatch decides which grant handler sees a request, so an acceptance here
//! is a grant this server will attempt. The properties:
//!
//! * **Nothing dispatches to a grant the client did not register.** That is
//!   RFC 6749 §5.2's `unauthorized_client`, and it is the check that keeps a
//!   client registered only for `authorization_code` from using
//!   `refresh_token`.
//! * **Nothing dispatches to a grant this deployment disabled.** A feature
//!   flag that can be bypassed by a form parameter is not a feature flag.
//! * **A disabled grant and an unimplemented one give the same code**, so the
//!   endpoint does not map an operator's configuration for anyone who asks.
//! * **Every rejection is one of RFC 6749 §5.2's codes**, and none of them
//!   quotes the request back.
//! * **Parsing is total.** The acceptance criterion for `ast-a05.1` says so.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::entities::client::GrantType;
use asterius_domain::{Capabilities, ClientRegistration};
use asterius_oidc::form::Parameters;
use asterius_oidc::token::{TokenError, dispatch};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

/// RFC 6749 §5.2's codes, plus the two this endpoint can return.
const PERMITTED_CODES: &[&str] = &[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
];

#[derive(Arbitrary, Debug)]
struct Input {
    /// Which grants the client registered, by index into `GrantType::ALL`.
    registered: Vec<u8>,
    /// Which features the deployment offers.
    flags: u8,
    /// The `grant_type` values sent, in order. More than one is the
    /// duplicate-parameter case.
    grant_types: Vec<GrantChoice>,
    /// Other parameters, which must be ignored.
    extra: Vec<(String, String)>,
}

#[derive(Arbitrary, Debug)]
enum GrantChoice {
    /// A real grant, by index.
    Known(u8),
    /// Arbitrary text.
    Text(String),
}

impl GrantChoice {
    fn render(&self) -> String {
        match self {
            Self::Known(i) => GrantType::ALL[usize::from(*i) % GrantType::ALL.len()]
                .as_str()
                .to_owned(),
            Self::Text(text) => text.clone(),
        }
    }
}

fn capabilities(flags: u8) -> Capabilities {
    Capabilities {
        mtls: flags & 0b0000_0001 != 0,
        grant_management: flags & 0b0000_0010 != 0,
        ciba: flags & 0b0000_0100 != 0,
        device_flow: flags & 0b0000_1000 != 0,
        token_exchange: flags & 0b0001_0000 != 0,
        ssf: flags & 0b0010_0000 != 0,
        authzen: flags & 0b0100_0000 != 0,
        dpop_nonce: flags & 0b1000_0000 != 0,
    }
}

/// A registration for `grants`, or `None` if that set is not a valid document.
///
/// RFC 7591 §2.1 ties `response_types: ["code"]` to `authorization_code`, so
/// not every subset is expressible — building it through the real validator
/// rather than around it keeps this target honest about what can exist.
fn registration(grants: &[GrantType]) -> Option<ClientRegistration> {
    let names: Vec<&str> = grants.iter().map(|g| g.as_str()).collect();
    ClientRegistration::from_json(
        &serde_json::to_vec(&json!({
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "grant_types": names,
            "scope": "openid",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        }))
        .ok()?,
        Capabilities {
            mtls: true,
            grant_management: true,
            ciba: true,
            device_flow: true,
            token_exchange: true,
            ssf: true,
            authzen: true,
            dpop_nonce: true,
        },
    )
    .ok()
}

fuzz_target!(|input: Input| {
    let registered: Vec<GrantType> = input
        .registered
        .iter()
        .map(|i| GrantType::ALL[usize::from(*i) % GrantType::ALL.len()])
        .collect();
    let Some(registration) = registration(&registered) else {
        return;
    };
    let capabilities = capabilities(input.flags);

    let mut pairs: Vec<(String, String)> = Vec::new();
    for choice in &input.grant_types {
        pairs.push(("grant_type".to_owned(), choice.render()));
    }
    for (name, value) in &input.extra {
        // Never let a generated parameter become a second `grant_type`.
        if name != "grant_type" {
            pairs.push((name.clone(), value.clone()));
        }
    }

    let params = Parameters::from_pairs(pairs.clone());
    match dispatch(&params, &registration, &capabilities) {
        Ok(accepted) => {
            let grant = accepted.grant();

            // Exactly one `grant_type` was sent, and it named this grant.
            let sent: Vec<&String> = pairs
                .iter()
                .filter(|(k, _)| k == "grant_type")
                .map(|(_, v)| v)
                .collect();
            assert_eq!(
                sent.len(),
                1,
                "RFC 6749 §3.2: dispatched with {} grant_type parameters",
                sent.len()
            );
            assert_eq!(sent[0].as_str(), grant.as_str());

            // The client registered it.
            assert!(
                registration.allows(grant),
                "dispatched to {}, which the client did not register",
                grant.as_str()
            );

            // The deployment offers it.
            if let Some(feature) = grant.required_feature() {
                assert!(
                    capabilities.is_enabled(feature),
                    "dispatched to {}, whose feature is disabled",
                    grant.as_str()
                );
            }
        }
        Err(error) => {
            // Always one of the specification's codes.
            assert!(
                PERMITTED_CODES.contains(&error.code()),
                "invented an error code: {}",
                error.code()
            );
            assert!(
                (400..=401).contains(&error.status()),
                "unexpected status {}",
                error.status()
            );

            // `Display` is for the log, and deliberately names the offending
            // parameter — an operator needs that. What the *client* sees is a
            // constant chosen by the HTTP layer, which is where the no-echo
            // rule is tested (`crates/server/tests/token.rs`).
            //
            // An earlier version of this target substring-checked `Display`
            // against every request value and failed on "unsupported
            // grant_type", because a request had sent the literal value
            // `grant_type`. A fixed message that happens to share a word with
            // the input is not a reflection, and asserting otherwise was
            // testing the wrong layer.
            assert!(
                !matches!(error, TokenError::MalformedRequest),
                "dispatch produced MalformedRequest, which it has no path to"
            );
        }
    }
});
