//! Token exchange request parsing — RFC 8693 §2.1.
//!
//! An acceptance here is an exchange this server will attempt, so the
//! properties are the ones that decide what the *rest* of the grant is allowed
//! to assume:
//!
//! * **Parsing is total.** No form body panics this.
//! * **Every rejection is one of §2.2.2's codes**, which are `invalid_request`
//!   and `invalid_target`; anything needing the token itself is the handler's
//!   `invalid_grant` and cannot be decided here.
//! * **§2.1's two REQUIRED parameters are present on every acceptance**, and
//!   the subject token is non-empty and within the bound the endpoint reads.
//! * **An accepted request named no `actor_token`** — this server derives the
//!   actor from client authentication, and a request that slipped one past
//!   would get a token naming somebody the client did not ask for.
//! * **An accepted `requested_token_type` is an access token.** v1 mints one
//!   kind; a request for another that parsed would be answered with something
//!   it did not ask for.
//! * **Every target is a resource identifier**, so the audience resolution
//!   downstream never sees a value it would have to interpret.
#![no_main]

use asterius_oidc::form::Parameters;
use asterius_oidc::token_exchange::{
    ACCESS_TOKEN, ExchangeError, MAX_SUBJECT_TOKEN_BYTES, SubjectTokenType, parse,
};
use libfuzzer_sys::fuzz_target;

/// RFC 8693 §2.2.2's codes.
const PERMITTED_CODES: &[&str] = &["invalid_request", "invalid_target"];

/// The parameter names §2.1 defines, so the generator spends its budget on
/// them rather than on arbitrary keys the parser never reads.
const NAMES: &[&str] = &[
    "subject_token",
    "subject_token_type",
    "actor_token",
    "actor_token_type",
    "requested_token_type",
    "scope",
    "audience",
    "resource",
];

/// Values worth reaching: the specification's own identifiers, alongside
/// whatever the fuzzer invents.
const VALUES: &[&str] = &[
    "urn:ietf:params:oauth:token-type:access_token",
    "urn:ietf:params:oauth:token-type:id_token",
    "urn:ietf:params:oauth:token-type:jwt",
    "urn:ietf:params:oauth:token-type:refresh_token",
    "urn:ietf:params:oauth:token-type:saml2",
    "https://api.example/",
    "header.payload.signature",
];

fuzz_target!(|input: Vec<(u8, String)>| {
    let pairs: Vec<(String, String)> = input
        .iter()
        .map(|(choice, text)| {
            let name = NAMES[usize::from(*choice) % NAMES.len()];
            // Half the time a value from the specification, half the time the
            // fuzzer's own: neither alone reaches both the accepting and the
            // refusing branches often enough to be interesting.
            let value = if choice % 2 == 0 {
                VALUES[usize::from(*choice) % VALUES.len()].to_owned()
            } else {
                text.clone()
            };
            (name.to_owned(), value)
        })
        .collect();

    let params = Parameters::from_pairs(pairs.clone());
    let sent = |name: &str| -> Vec<&String> {
        pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value)
            .collect()
    };

    match parse(&params) {
        Ok(request) => {
            // §2.1: both REQUIRED parameters, exactly once each.
            let subject = sent("subject_token");
            assert_eq!(
                subject.len(),
                1,
                "accepted {} subject tokens",
                subject.len()
            );
            assert_eq!(subject[0].as_str(), request.subject_token);
            assert!(!request.subject_token.is_empty(), "accepted an empty token");
            assert!(
                request.subject_token.len() <= MAX_SUBJECT_TOKEN_BYTES,
                "accepted a subject token of {} bytes",
                request.subject_token.len()
            );

            let kind = sent("subject_token_type");
            assert_eq!(kind.len(), 1, "accepted {} subject token types", kind.len());
            assert_eq!(
                SubjectTokenType::parse(kind[0]),
                Some(request.subject_token_type)
            );

            // The actor is the authenticated client, never a parameter.
            assert!(
                sent("actor_token").is_empty() && sent("actor_token_type").is_empty(),
                "accepted a request naming an actor token"
            );

            // v1 mints access tokens and says so.
            for requested in sent("requested_token_type") {
                assert_eq!(
                    requested.as_str(),
                    ACCESS_TOKEN,
                    "accepted a request for another token type"
                );
            }

            // Every target came from the request and is a resource identifier.
            for target in &request.targets {
                assert!(
                    asterius_domain::ResourceIdentifier::parse(target).is_ok(),
                    "accepted a target that is not a resource identifier: {target}"
                );
                let named = sent("audience")
                    .into_iter()
                    .chain(sent("resource"))
                    .any(|value| {
                        asterius_domain::ResourceIdentifier::parse(value)
                            .is_ok_and(|parsed| parsed.as_str() == target)
                    });
                assert!(named, "invented a target: {target}");
            }
        }
        Err(error) => {
            assert!(
                PERMITTED_CODES.contains(&error.code()),
                "invented an error code: {}",
                error.code()
            );
            // `Display` names the offending parameter for the log; what the
            // client sees is a constant chosen by the HTTP layer, which is
            // where the no-echo rule is tested. What must hold here is that a
            // duplicate is reported as one — the only variant that carries a
            // value at all.
            if let ExchangeError::Duplicated(name) = &error {
                assert!(
                    NAMES.contains(&name.as_str()),
                    "reported a duplicate of a parameter that was never read: {name}"
                );
            }
        }
    }
});
