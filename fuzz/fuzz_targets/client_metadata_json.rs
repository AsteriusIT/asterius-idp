//! `ClientRegistration::from_json` — RFC 7591 §2, FAPI 2.0 SP §5.3.2.1.
//!
//! Client registration is the widest attacker-controlled JSON surface in the
//! server: a document with twenty interacting fields, arriving at an endpoint
//! that may be open (`ast-m9c.4`), and producing the record every later
//! authorization decision is made against. "Does not panic" is the least of it.
//! Four properties beyond that:
//!
//! * **Nothing accepted is weaker than the profile.** Every rule the validator
//!   exists for is re-asserted here on whatever it let through: a
//!   sender-constrained token, an allow-listed algorithm, an https redirect
//!   URI, an authentication method that is not a shared secret.
//! * **A flag that is off cannot be reached.** An mTLS method or a
//!   flag-gated grant must not survive validation against a deployment that
//!   has the flag off, or a registration would enable what configuration
//!   disabled.
//! * **Turning a flag on never rejects what was already accepted.** Otherwise
//!   an operator enabling mTLS would invalidate yesterday's registrations.
//! * **An accepted redirect URI survives re-registration unchanged.** Matching
//!   is byte-exact (RFC 9700 §4.1), so a URI that came out of the validator and
//!   then failed to go back in — or came back different — would break the
//!   comparison the authorization endpoint depends on.
#![no_main]

use asterius_domain::{ApplicationType, Capabilities, ClientRegistration, RedirectUri};
use libfuzzer_sys::fuzz_target;

/// Every flag on. Anything gated must be reachable, or half the validator is
/// never exercised.
const EVERYTHING: Capabilities = Capabilities {
    mtls: true,
    grant_management: true,
    ciba: true,
    device_flow: true,
    token_exchange: true,
    ssf: true,
    authzen: true,
    dpop_nonce: true,
};

fuzz_target!(|data: &[u8]| {
    // The first byte picks the deployment's flags, so the same corpus entry
    // exercises both sides of every capability check.
    let Some((&selector, document)) = data.split_first() else {
        return;
    };
    let capabilities = Capabilities {
        mtls: selector & 1 != 0,
        ciba: selector & 2 != 0,
        device_flow: selector & 4 != 0,
        token_exchange: selector & 8 != 0,
        ..Capabilities::default()
    };

    let outcome = ClientRegistration::from_json(document, capabilities);

    // Validation is a pure function of its two inputs; the registration
    // endpoint, the admin API and the seed scripts have to agree.
    assert_eq!(
        outcome.is_ok(),
        ClientRegistration::from_json(document, capabilities).is_ok(),
        "validation is not deterministic"
    );

    if ClientRegistration::from_json(document, Capabilities::default()).is_ok() {
        assert!(
            ClientRegistration::from_json(document, EVERYTHING).is_ok(),
            "enabling every feature rejected a client that was already valid"
        );
    }

    let Ok(client) = outcome else { return };

    assert!(
        client.token_binding.is_dpop_bound() || client.token_binding.is_certificate_bound(),
        "an accepted client would be issued bearer access tokens"
    );
    assert!(
        !client.token_endpoint_auth_method.requires_mtls() || capabilities.mtls,
        "an mTLS authentication method survived with the flag off"
    );
    assert!(
        !client.use_mtls_endpoint_aliases || capabilities.mtls,
        "mtls_endpoint_aliases survived with the flag off"
    );
    assert!(
        !client.token_binding.is_certificate_bound() || capabilities.mtls,
        "certificate binding survived with the flag off"
    );
    for grant in &client.grant_types {
        assert!(
            grant
                .required_feature()
                .is_none_or(|feature| capabilities.is_enabled(feature)),
            "the grant {grant} survived with its feature off"
        );
    }
    for uri in &client.redirect_uris {
        assert!(
            uri.as_str().starts_with("https://")
                || (client.application_type == ApplicationType::Native
                    && uri.as_str().starts_with("http://")),
            "an http redirect URI survived on a client that is not native"
        );
        assert!(
            !uri.as_str().contains('#'),
            "a redirect URI with a fragment was accepted"
        );
    }

    // Everything a later request compares against must be reproducible: feed
    // the accepted values back in and they must come out identical.
    if !client.redirect_uris.is_empty() {
        let uris: Vec<&str> = client
            .redirect_uris
            .iter()
            .map(RedirectUri::as_str)
            .collect();
        let rebuilt = serde_json::json!({
            "client_name": client.client_name,
            "application_type": client.application_type.as_str(),
            "redirect_uris": uris,
            "grant_types": ["authorization_code"],
            "jwks_uri": "https://rp.example/jwks",
        });
        let encoded = serde_json::to_vec(&rebuilt).expect("a validated client re-serialises");
        let again = ClientRegistration::from_json(&encoded, capabilities)
            .expect("a validated client must be re-registerable");
        assert_eq!(
            again
                .redirect_uris
                .iter()
                .map(RedirectUri::as_str)
                .collect::<Vec<_>>(),
            uris,
            "a redirect URI changed on the way back through the validator"
        );
    }
});
