//! The transmitter configuration document (SSF 1.0 §7).
//!
//! A receiver bootstraps from this document: it learns who the transmitter
//! claims to be, which keys sign the tokens it will get, and — once the
//! management API exists — where to configure a stream. SSF 1.0 §7.2 puts it
//! at `/.well-known/ssf-configuration`, and §7.2.4 makes the check a receiver
//! runs on it exactly one comparison: the `issuer` in the document must be
//! identical to the URL it fetched the document from, and to the `iss` of
//! every SET that arrives afterwards.
//!
//! ## The transmitter's keys are the tenant's keys
//!
//! `jwks_uri` names the OP's JWK Set, not a set of its own. [`crate::Set`]
//! signs through [`asterius_domain::Signer`] with the tenant's active key —
//! the same key, the same `kid` and the same rotation schedule as an ID token
//! (`ast-0ju.2`) — so a second set would publish the same material at a second
//! URL and give a receiver two places to be told about a rotation. What a
//! dedicated SET key would buy is separation of purpose: a receiver handed a
//! transmitter key cannot use it to accept an ID token, because it is a
//! different key. That is worth having the day a tenant wants to hand a
//! receiver a key without handing it the OP's; it is not worth having while
//! the signer is one port with one key, because the two sets would be the same
//! bytes and the separation would be a URL. See `docs/threat-model.md`.
//!
//! ## This document is deliberately incomplete
//!
//! SSF 1.0 §7.1 makes `configuration_endpoint`, `status_endpoint`,
//! `add_subject_endpoint`, `remove_subject_endpoint`, `verification_endpoint`
//! and `delivery_methods_supported` REQUIRED for a transmitter that supports
//! stream configuration. None of those routes exist yet (`ast-0ju.3` through
//! `ast-0ju.7`), and this document names none of them. A strict reading of
//! §7.1 calls that incomplete, and it is the honest incompleteness: the
//! alternative is advertising five URLs that answer 404, which is what RFC
//! 8414 §2's rule against documents that do not describe actual behaviour
//! exists to stop, and which would let a receiver believe it had configured a
//! stream it had not. Each of those stories adds its own member with its own
//! route, and the parity test in `crates/server/tests/ssf_configuration.rs`
//! holds in both states.

use asterius_domain::Issuer;
use serde_json::{Value, json};

/// The well-known document name, under RFC 8615's prefix (SSF 1.0 §7.2).
pub const WELL_KNOWN_DOCUMENT: &str = "ssf-configuration";

/// SSF 1.0 §7.1 `spec_version`: the version of the specification this
/// transmitter implements, spelled with an underscore because §7.1 spells it
/// that way.
pub const SPEC_VERSION: &str = "1_0";

/// Builds one tenant's transmitter configuration document.
///
/// `jwks_uri` is passed in rather than derived here: the URL belongs to the
/// endpoint registry the OP's own metadata is rendered from
/// (`asterius_oidc::metadata::Endpoint::Jwks`), and computing it a second time
/// in this crate would be a second opinion about where the keys live.
///
/// The `issuer` is the tenant's, which is what [`crate::ReadySet::issue`] puts in
/// `iss`. SSF 1.0 §7.2.4 is that identity, and [`Issuer`] is what enforces the
/// rest of §7.1's shape: https, no query, no fragment, canonical form.
#[must_use]
pub fn transmitter_metadata(issuer: &Issuer, jwks_uri: &str) -> Value {
    json!({
        "spec_version": SPEC_VERSION,

        // SSF 1.0 §7.1 and §7.2.4: identical to the `iss` of every SET, and to
        // the URL this document was fetched from.
        "issuer": issuer.as_str(),

        // §7.1 makes this REQUIRED when the transmitter signs, and it always
        // signs: a `SignedSet` is the only thing this server emits.
        "jwks_uri": jwks_uri,

        // §7.1: how a receiver authenticates at the management endpoints. An
        // OAuth 2.0 access token is the only scheme this server could honour —
        // it is the only credential it issues — so the list has one entry and
        // will still have one entry when `ast-0ju.3` builds the endpoints that
        // check it.
        "authorization_schemes": [{ "spec_urn": "urn:ietf:rfc:6749" }],

        // §7.1: whether a new stream starts subscribed to every subject or to
        // none. NONE, and not merely because there is no stream API yet: a
        // stream that began by emitting an event about every user in the
        // tenant would send a receiver identifiers for people it has never
        // seen, which is precisely the correlation handle this crate's threat
        // model refuses to hand out.
        "default_subjects": "NONE",

        // §7.1: the subject members a receiver must understand to interpret
        // this transmitter's events. Empty is a claim, not a placeholder — it
        // says no member beyond the base format is required — and it is true
        // because every subject this crate builds is a plain RFC 9493 format
        // with no member a receiver may skip.
        "critical_subject_members": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> Issuer {
        Issuer::parse("https://as.example/t/demo").expect("an issuer")
    }

    fn document() -> Value {
        transmitter_metadata(&issuer(), "https://as.example/t/demo/jwks")
    }

    /// SSF 1.0 §7.1.
    #[test]
    fn the_document_names_the_specification_version() {
        assert_eq!(document()["spec_version"], json!("1_0"));
    }

    /// SSF 1.0 §7.2.4: a receiver compares this against the URL it fetched,
    /// and against the `iss` of every SET.
    #[test]
    fn the_issuer_is_the_tenants_issuer_verbatim() {
        assert_eq!(document()["issuer"], json!("https://as.example/t/demo"));
    }

    /// The decision this module documents: the SETs are signed by the key the
    /// ID tokens are signed by, so the set to verify them against is the OP's.
    #[test]
    fn the_jwks_uri_is_the_one_the_caller_passed() {
        assert_eq!(
            document()["jwks_uri"],
            json!("https://as.example/t/demo/jwks")
        );
    }

    /// SSF 1.0 §7.1: `[{spec_urn}]`, and RFC 6749 is the only scheme this
    /// server has a credential for.
    #[test]
    fn the_only_authorization_scheme_is_oauth() {
        assert_eq!(
            document()["authorization_schemes"],
            json!([{ "spec_urn": "urn:ietf:rfc:6749" }])
        );
    }

    /// SSF 1.0 §7.1: `ALL` or `NONE`, and a new stream subscribes to nobody.
    #[test]
    fn a_new_stream_subscribes_to_no_subject_by_default() {
        assert_eq!(document()["default_subjects"], json!("NONE"));
    }

    #[test]
    fn no_subject_member_is_critical() {
        assert_eq!(document()["critical_subject_members"], json!([]));
    }

    /// SSF 1.0 §7.1 requires every URL in this document to be https. The
    /// issuer type enforces it for `issuer`; this pins the rest.
    #[test]
    fn every_url_member_is_https() {
        let document = document();
        let object = document.as_object().expect("an object");
        for (key, value) in object {
            let Some(text) = value.as_str() else { continue };
            if text.starts_with("http") {
                assert!(text.starts_with("https://"), "{key} is not https: {text}");
            }
        }
    }

    /// The parity rule, asserted where the document is built as well as where
    /// it is served: no endpoint is named while no endpoint is routed
    /// (`ast-0ju.3` through `ast-0ju.7`). A story that adds a member here adds
    /// a route with it, and updates this test as it does.
    #[test]
    fn no_management_endpoint_is_advertised_before_one_exists() {
        let document = document();
        let object = document.as_object().expect("an object");
        let endpoints: Vec<&String> = object
            .keys()
            .filter(|key| key.ends_with("_endpoint"))
            .collect();
        assert!(
            endpoints.is_empty(),
            "advertised without a route: {endpoints:?}"
        );
        assert!(
            object.get("delivery_methods_supported").is_none(),
            "a delivery method is advertised before `ast-0ju.6` delivers one"
        );
    }
}
