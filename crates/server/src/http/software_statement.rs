//! Software statements — RFC 7591 §2.3, §3.1.1, §5.
//!
//! A software statement is "a JWT that asserts metadata values about the client
//! software", signed by somebody other than the party registering. RFC 7591
//! §2.3 gives it precedence: "Values of client metadata that are conveyed in
//! the software statement ... MUST take precedence over those conveyed using
//! plain JSON values". So a statement is not a hint attached to a registration;
//! it is an *override* of it, and the issuer that signed it decides what the
//! new client is.
//!
//! # That makes an issuer a root of trust
//!
//! Everything else this endpoint accepts is a claim the registrant makes about
//! itself, refused or admitted by the profile and by the tenant's policy. A
//! software statement is a claim a *third party* makes, and this server acts on
//! it. An operator who adds an issuer to
//! [`asterius_domain::SoftwareStatementRule`] has said: whoever holds that
//! signing key may create clients in this tenant with metadata of their
//! choosing, subject to the same policy.
//!
//! Three things follow, and all three are in the code below.
//!
//! * **The issuer list is per tenant and closed.** There is no discovery, no
//!   "any issuer with a valid signature", and no way for a statement to
//!   nominate its own key set. An `iss` that is not on the list is
//!   `unapproved_software_statement` and nothing is fetched.
//! * **The `iss` in an unverified payload selects a key set and asserts
//!   nothing.** It is read before any signature is checked, which is safe only
//!   because it is used for one thing — picking which configured JWKS to fetch
//!   — and because the verification that follows requires the same `iss`
//!   again, this time under the signature.
//! * **The keys come through the one outbound path.** ADR-0006:
//!   `asterius_server::outbound` is the only thing in this process that opens a
//!   socket to an address configuration or a client chose, and it carries the
//!   SSRF guard, the body cap and the timeouts. This module holds no HTTP
//!   client.
//!
//! # What it does not do yet
//!
//! The issuer's JWKS is fetched per registration with the statement. There is
//! no cache: `ast-mxc.8` owns the fetch cache and its negative entries, and a
//! second cache here would be a second policy about how long a rotated key
//! stays believed. Registrations carrying a statement are rare — an agent is
//! onboarded once — so the cost is one fetch per new client.

use asterius_domain::ports::ClientUrlFetcher;
use asterius_domain::{ClientMetadataError, SoftwareStatementRule, keys::SigningAlgorithm};
use asterius_jose::client_keys::parse_jwk_set;
use asterius_jose::verify::{Policy, TypRule};
use serde_json::{Map, Value};
use time::OffsetDateTime;

/// The `typ` values a software statement may carry.
///
/// RFC 7591 registers no media type for it, so a statement that carries none is
/// accepted — that is the interoperable case, and refusing it would refuse
/// every statement in the wild. What is refused is a token announcing itself as
/// something else: an access token or a DPoP proof presented here is not a
/// statement whatever it says inside, and RFC 8725 §3.11 is why the check is
/// made before any key is fetched.
const TYP: TypRule = TypRule::OptionalOneOf(&["software-statement+jwt", "jwt"]);

/// The claims a JWT carries about itself, which are not client metadata.
///
/// RFC 7519 §4.1's registered names. They are dropped when the statement is
/// merged into the registration document: `iss` is the issuer of the assertion
/// and not a metadata field, and letting one through would put an attacker's
/// choice of value into a field a future version of this server may read.
const JWT_CLAIMS: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// The largest software statement this server will read.
///
/// Smaller than the registration document that carries it: a statement is a
/// handful of metadata claims and a signature.
pub const MAX_BYTES: usize = 8 * 1024;

/// The statement a registration document carries, if it carries one.
///
/// Reads the member and nothing else — the document is parsed properly by
/// [`asterius_domain::ClientRegistration::from_json`] afterwards, and a
/// registration whose JSON is broken is refused there, with the position, by
/// the one parser that owns that decision. A document that is not an object at
/// all therefore returns `None` here rather than an error.
///
/// # Errors
///
/// [`ClientMetadataError::InvalidSoftwareStatement`] when the member is present
/// and is not a string, or is longer than [`MAX_BYTES`].
pub fn extract(body: &[u8]) -> Result<Option<String>, ClientMetadataError> {
    let Ok(document) = serde_json::from_slice::<Value>(body) else {
        return Ok(None);
    };
    let Some(member) = document.get("software_statement") else {
        return Ok(None);
    };
    let Some(statement) = member.as_str() else {
        return Err(ClientMetadataError::InvalidSoftwareStatement {
            reason: "must be a string carrying a JWT (RFC 7591 §2.3)",
        });
    };
    if statement.len() > MAX_BYTES {
        return Err(ClientMetadataError::InvalidSoftwareStatement {
            reason: "is larger than this server will read",
        });
    }
    Ok(Some(statement.to_owned()))
}

/// The `iss` a statement claims, read without verifying anything.
///
/// Used for one purpose: choosing which configured JWKS to fetch. Nothing else
/// in this module reads the unverified payload, and the verification that
/// follows requires this same value under the signature — so a statement that
/// lies here fails there rather than being believed.
fn claimed_issuer(statement: &str) -> Option<String> {
    let unverified = asterius_jose::jws::parse(statement).ok()?;
    let claims: Value = serde_json::from_slice(unverified.unverified_payload()).ok()?;
    claims.get("iss")?.as_str().map(ToOwned::to_owned)
}

/// Verifies a statement and merges its claims over the registration document.
///
/// The result is the document [`asterius_domain::ClientRegistration::from_json`]
/// then validates, so a statement cannot register anything the profile would
/// have refused from a plain document: precedence (RFC 7591 §2.3) decides
/// *which* values are used, never *whether* they are checked.
///
/// # Errors
///
/// * [`ClientMetadataError::UnapprovedSoftwareStatement`] when the `iss` is not
///   one this tenant trusts, or the tenant trusts none.
/// * [`ClientMetadataError::InvalidSoftwareStatement`] for everything else: not
///   a JWS, wrong `typ`, an algorithm outside the profile, a signature no
///   published key verifies, an expired statement, or claims that are not a
///   JSON object.
pub async fn merge(
    outbound: &dyn ClientUrlFetcher,
    rule: &SoftwareStatementRule,
    statement: &str,
    document: &[u8],
    now: OffsetDateTime,
) -> Result<Vec<u8>, ClientMetadataError> {
    // Before anything is fetched: a tenant that trusts nobody cannot be made to
    // fetch anything by presenting a statement.
    let Some(issuer) = claimed_issuer(statement) else {
        return Err(ClientMetadataError::InvalidSoftwareStatement {
            reason: "is not a JWT with an issuer",
        });
    };
    let Some(trusted) = rule.issuer(&issuer) else {
        return Err(ClientMetadataError::UnapprovedSoftwareStatement);
    };

    let raw = outbound.fetch(&trusted.jwks_uri).await.map_err(|error| {
        // The reason is logged, not returned: it names an address and a status
        // for a host the registrant may have no relationship with.
        tracing::warn!(%error, issuer = %trusted.issuer, "cannot fetch a software statement issuer's keys");
        ClientMetadataError::InvalidSoftwareStatement {
            reason: "could not be verified against its issuer's published keys",
        }
    })?;
    let keys = parse_jwk_set(&raw).map_err(|error| {
        tracing::warn!(%error, issuer = %trusted.issuer, "a software statement issuer publishes an unusable JWKS");
        ClientMetadataError::InvalidSoftwareStatement {
            reason: "could not be verified against its issuer's published keys",
        }
    })?;

    // `iss` again, under the signature this time. `without_expiry` because RFC
    // 7591 §2.3 does not require `exp` of a software statement — an assertion
    // about a piece of software is not a session — but an `exp` that *is*
    // present is honoured by the verifier, so an issuer that dates its
    // statements gets what it asked for.
    let policy = Policy::new(TYP, SigningAlgorithm::ALL.to_vec())
        .issued_by(trusted.issuer.clone())
        .without_expiry();
    let verified =
        asterius_jose::verify::verify(statement, &policy, &keys, now).map_err(|error| {
            tracing::debug!(%error, issuer = %trusted.issuer, "a software statement was refused");
            ClientMetadataError::InvalidSoftwareStatement {
                reason: "was not signed by a key its issuer publishes, or is no longer valid",
            }
        })?;

    let Some(claims) = verified.claims.as_object() else {
        return Err(ClientMetadataError::InvalidSoftwareStatement {
            reason: "does not carry a JSON object of claims",
        });
    };

    // The document the registrant sent. A body that is not an object is not
    // this module's error to report — the registration parser owns that
    // message, with a position — so it is replaced by an empty object here and
    // fails there.
    let mut merged: Map<String, Value> = serde_json::from_slice(document).unwrap_or_default();

    // RFC 7591 §2.3: the statement's values take precedence. Insertion order
    // is the claim order of the statement, which `serde_json`'s map preserves
    // or sorts deterministically depending on its features — either way the
    // *result* does not depend on it, because each key is written once.
    for (name, value) in claims {
        if JWT_CLAIMS.contains(&name.as_str()) {
            continue;
        }
        merged.insert(name.clone(), value.clone());
    }

    serde_json::to_vec(&Value::Object(merged)).map_err(|_| {
        // Unreachable: every value came out of `serde_json` a moment ago.
        ClientMetadataError::InvalidSoftwareStatement {
            reason: "could not be applied to the registration document",
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_with_no_statement_carries_none() {
        // Arrange
        let body = br#"{"client_name":"x"}"#;

        // Act
        let outcome = extract(body);

        // Assert
        assert_eq!(outcome, Ok(None));
    }

    /// RFC 7591 §2.3 makes the member a string carrying a JWT. An object there
    /// is a registrant trying a different shape on the parser.
    #[test]
    fn a_statement_that_is_not_a_string_is_invalid() {
        // Arrange
        let body = br#"{"software_statement":{"iss":"x"}}"#;

        // Act
        let outcome = extract(body);

        // Assert
        assert_eq!(
            outcome.map_err(|error| error.code()),
            Err("invalid_software_statement")
        );
    }

    #[test]
    fn a_broken_document_carries_no_statement() {
        // The registration parser reports the syntax error, with a position.
        assert_eq!(extract(b"{not json"), Ok(None));
    }

    #[test]
    fn an_oversized_statement_is_invalid() {
        // Arrange
        let statement = "a".repeat(MAX_BYTES + 1);
        let body = serde_json::to_vec(&serde_json::json!({ "software_statement": statement }))
            .expect("serialise");

        // Act
        let outcome = extract(&body);

        // Assert
        assert!(outcome.is_err());
    }

    #[test]
    fn a_statement_that_is_not_a_jwt_has_no_issuer() {
        assert_eq!(claimed_issuer("not.a.jwt"), None);
    }
}
