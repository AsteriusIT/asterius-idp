//! The PDP metadata document (Authorization API 1.0 §9).
//!
//! A PEP bootstraps from this document the way an OAuth client bootstraps from
//! RFC 8414's: it learns which PDP it is talking to and where to send an
//! evaluation. §9.2 puts it at `/.well-known/authzen-configuration`, inserted
//! between the host and the path of the PDP identifier — the multi-tenant
//! example in §9.2 is exactly this deployment's shape — and §9.2.3 gives a PEP
//! one check to run on what comes back: `policy_decision_point` must be
//! identical to the identifier the URL was derived from.
//!
//! ## The PDP identifier is the tenant issuer
//!
//! `ast-pj0.3` left the choice open between the tenant issuer and the issuer
//! plus a `/authzen` segment. It is the issuer, for three reasons that all say
//! the same thing.
//!
//! §9.2.3's check is a string comparison against the URL the document was
//! fetched from, so the identifier has to be the one this server *serves* the
//! document under. That is the tenant issuer: `crate::tenancy` resolves both
//! well-known spellings — OIDC Discovery §4's appended
//! `{issuer}/.well-known/authzen-configuration` and RFC 8414 §3.1's inserted
//! `/.well-known/authzen-configuration{issuer-path}` — against the tenant
//! path and nothing longer. An identifier with a `/authzen` segment would need
//! a third routing form for no property in return.
//!
//! A tenant already has exactly one identity in this server, and it is the
//! issuer: it is the `iss` of every token, the `issuer` of the SSF
//! transmitter document (`asterius_ssf::metadata`) and the base of every URL
//! either document names. A second identifier for the same tenant would be a
//! second thing a deployment has to keep in step, and a PEP comparing one
//! against the other would be comparing two spellings of one tenant.
//!
//! ## What a PEP's token is audienced to is *not* the identifier
//!
//! Worth stating, because it is the one place this looks inconsistent.
//! `ast-pj0.1` requires the access token at the evaluation endpoint to carry
//! `aud` equal to [`crate::metadata::Endpoint::AccessEvaluation`]'s URL — the
//! concrete resource, RFC 9068 §3 and RFC 8707 style — not the PDP
//! identifier. Authorization API 1.0 §11.2 asks the PDP to authenticate the
//! PEP and says nothing about which audience it should insist on, and the
//! narrower one is the safer one: a token minted for this tenant's PDP cannot
//! be replayed at another endpoint of the same tenant, which a token audienced
//! to the issuer could be.
//!
//! So the two values are related but not equal, and this document publishes
//! both: `policy_decision_point` is the identifier §9.2.3 validates, and
//! `access_evaluation_endpoint` is byte-for-byte the `aud` a PEP must ask its
//! authorization server for. Both are rendered from the one registry
//! (`ast-o0t.3`), so neither can drift from the route that answers.
//!
//! ## What is deliberately absent
//!
//! §9.2.2 says a parameter with no value is omitted rather than emptied, and
//! three things are therefore missing.
//!
//! `search_subject_endpoint`, `search_resource_endpoint` and
//! `search_action_endpoint` (§9.1.1, OPTIONAL) wait for `ast-pj0.6`: there is
//! no search in this build, no variant for one in the registry, and a URL here
//! would be a URL that answers 404 — the parity rule `ast-o0t.3` exists for.
//!
//! `capabilities` (§9.1.2) is absent for a stricter reason: this build
//! implements no capability beyond the evaluation API, so the member would be
//! empty, and an empty member is exactly what §9.2.2 tells a PDP not to send.
//! The URNs themselves are not guessed here — a capability URN this PDP does
//! not honour is a promise a PEP would act on.
//!
//! `signed_metadata` (§9.1.3, OPTIONAL) is present only where an operator
//! asked for it, because signing it is only meaningful where a PEP can fetch
//! the keys: the server inserts it, from [`signed_metadata_claims`] and the
//! tenant's signer, and `crates/server/src/http/protocol.rs` holds that half.

use crate::metadata::Endpoint;
use asterius_domain::{Capabilities, Issuer};
use serde_json::{Map, Value, json};

/// The well-known document name, under RFC 8615's prefix (§9.2).
pub const WELL_KNOWN_DOCUMENT: &str = "authzen-configuration";

/// The explicit type of a signed PDP metadata document (§9.1.3).
///
/// RFC 8414 §2.1, which §9.1.3 follows, defines the member as "a JWT
/// containing metadata parameters as claims" and does not name a `typ`. This
/// server types everything it signs (RFC 8725 §3.11): the same key signs
/// access tokens, ID tokens and SETs, and a claims set that carries an `iss`
/// and an `iat` and nothing else would otherwise be one a verifier with a
/// loose policy could mistake for one of those.
pub const SIGNED_METADATA_TYP: &str = "authzen-metadata+jwt";

/// Builds one tenant's PDP metadata document (§9.1.1).
///
/// The identifier is the issuer, for the reasons in the [module
/// documentation](self); the endpoints are whatever this deployment actually
/// mounts, taken from the registry through
/// [`Endpoint::in_pdp_metadata`] so that the document and the router cannot
/// disagree.
///
/// A deployment with [`asterius_domain::Feature::Authzen`] off has no
/// evaluation endpoint to name, and this returns the identifier alone. The
/// server does not serve that document — the feature gate answers 404, as it
/// does for the SSF transmitter — but the function stays total, because
/// "which endpoints are there" is the registry's answer to give and not this
/// function's to assume.
#[must_use]
pub fn pdp_metadata(issuer: &Issuer, capabilities: &Capabilities) -> Value {
    let mut document = Map::new();

    // §9.1.1: REQUIRED, https, no query and no fragment — which `Issuer`
    // enforces on the way in, so this is a copy rather than a construction.
    document.insert("policy_decision_point".to_owned(), json!(issuer.as_str()));

    // §9.1.1: `access_evaluation_endpoint` is REQUIRED and the boxcar sibling
    // (`ast-pj0.2`) is OPTIONAL. Both are rendered from the registry when they
    // are mounted and from nowhere when they are not.
    for endpoint in Endpoint::enabled(capabilities).filter(|e| e.in_pdp_metadata()) {
        document.insert(
            endpoint.metadata_key().to_owned(),
            json!(endpoint.url(issuer)),
        );
    }

    Value::Object(document)
}

/// The claims of a signed metadata document (§9.1.3, RFC 8414 §2.1).
///
/// Every member of `document` repeated as a claim, plus the `iss` RFC 8414
/// §2.1 makes REQUIRED and an `iat` saying when this copy was made. A
/// `signed_metadata` member is never copied in: §9.1.3's document signs the
/// parameters, not itself.
///
/// There is no `exp`. This is a description of a server rather than a
/// credential, its freshness is the `Cache-Control` the response carries, and
/// an expiry would mean a PEP that cached the document per RFC 8414's rules
/// holding a signature it must now reject while the document it describes is
/// unchanged.
#[must_use]
pub fn signed_metadata_claims(document: &Value, issuer: &Issuer, issued_at: i64) -> Value {
    let mut claims = Map::new();
    claims.insert("iss".to_owned(), json!(issuer.as_str()));
    claims.insert("iat".to_owned(), json!(issued_at));
    if let Some(members) = document.as_object() {
        for (key, value) in members {
            if key == "signed_metadata" {
                continue;
            }
            claims.insert(key.clone(), value.clone());
        }
    }
    Value::Object(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{Capabilities, Issuer};

    fn issuer() -> Issuer {
        Issuer::parse("https://as.example/t/demo").expect("an issuer")
    }

    fn authzen_on() -> Capabilities {
        Capabilities {
            authzen: true,
            ..Capabilities::default()
        }
    }

    /// §9.1.1: `policy_decision_point` is REQUIRED, https, and carries no
    /// query or fragment. It is the tenant's issuer, which is the identifier
    /// the well-known URL of this document is derived from (§9.2.3).
    #[test]
    fn the_policy_decision_point_is_the_tenant_issuer() {
        // Arrange, act
        let document = pdp_metadata(&issuer(), &authzen_on());

        // Assert
        let pdp = document["policy_decision_point"]
            .as_str()
            .expect("a policy decision point");
        assert_eq!(pdp, "https://as.example/t/demo");
        assert!(pdp.starts_with("https://"));
        assert!(!pdp.contains('?') && !pdp.contains('#'));
    }

    /// §9.1.1: `access_evaluation_endpoint` is REQUIRED, and it is the URL the
    /// registry mounts and the OP metadata advertises — which is also the
    /// `aud` a PEP's access token must carry (`ast-pj0.1`).
    #[test]
    fn the_evaluation_endpoint_comes_from_the_registry() {
        // Arrange, act
        let document = pdp_metadata(&issuer(), &authzen_on());

        // Assert
        assert_eq!(
            document["access_evaluation_endpoint"],
            serde_json::json!(crate::metadata::Endpoint::AccessEvaluation.url(&issuer()))
        );
    }

    /// §9.1.1's OPTIONAL sibling: the boxcar (§7) is advertised beside the
    /// evaluation endpoint, at the URL the router mounts — which is also the
    /// `aud` a PEP's token must carry there, and not the one for §6.1's
    /// endpoint (`ast-pj0.2`).
    #[test]
    fn the_boxcar_endpoint_is_advertised_at_the_url_that_answers() {
        // Arrange, act
        let document = pdp_metadata(&issuer(), &authzen_on());

        // Assert
        assert_eq!(
            document["access_evaluations_endpoint"],
            serde_json::json!("https://as.example/t/demo/access/v1/evaluations")
        );
        assert_eq!(
            document["access_evaluations_endpoint"],
            serde_json::json!(crate::metadata::Endpoint::AccessEvaluations.url(&issuer())),
            "the advertised boxcar is not the one the registry mounts"
        );
        assert_ne!(
            document["access_evaluations_endpoint"], document["access_evaluation_endpoint"],
            "two endpoints, two audiences"
        );
    }

    /// §9.2.2: a parameter with nothing to say is omitted rather than empty.
    /// Nothing here searches (`ast-pj0.6`), so no `search_*` member exists.
    #[test]
    fn nothing_unimplemented_is_advertised() {
        // Arrange, act
        let document = pdp_metadata(&issuer(), &authzen_on());
        let members = document.as_object().expect("an object");

        // Assert
        for absent in [
            "search_subject_endpoint",
            "search_resource_endpoint",
            "search_action_endpoint",
            "capabilities",
            "signed_metadata",
        ] {
            assert!(
                !members.contains_key(absent),
                "{absent} is advertised by a PDP that does not implement it"
            );
        }
    }

    /// The document describes the endpoints this deployment mounts, so a
    /// deployment with the feature off names none of them.
    #[test]
    fn a_deployment_without_the_feature_advertises_no_endpoint() {
        // Arrange, act
        let document = pdp_metadata(&issuer(), &Capabilities::default());
        let members = document.as_object().expect("an object");

        // Assert
        assert!(
            !members.keys().any(|key| key.ends_with("_endpoint")),
            "a PDP with no evaluation endpoint advertises one: {members:?}"
        );
    }

    /// §9.1.3: the signed document carries the same members, plus the `iss`
    /// RFC 8414 §2.1 requires of a signed metadata JWT, and never a
    /// `signed_metadata` member of its own.
    #[test]
    fn the_signed_claims_repeat_the_document_under_an_issuer() {
        // Arrange
        let document = pdp_metadata(&issuer(), &authzen_on());

        // Act
        let claims = signed_metadata_claims(&document, &issuer(), 1_700_000_000);

        // Assert
        assert_eq!(
            claims["iss"],
            serde_json::json!("https://as.example/t/demo")
        );
        assert_eq!(claims["iat"], serde_json::json!(1_700_000_000));
        assert_eq!(
            claims["access_evaluation_endpoint"],
            document["access_evaluation_endpoint"]
        );
        assert_eq!(
            claims["policy_decision_point"],
            document["policy_decision_point"]
        );
        assert!(claims.get("signed_metadata").is_none());
    }
}
