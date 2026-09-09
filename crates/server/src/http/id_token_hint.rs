//! Verifying an `id_token_hint` — once, for both endpoints that take one.
//!
//! Two specifications ask for the same token in two places. OIDC RP-Initiated
//! Logout 1.0 §2 takes one to say *whose session* is being ended, and OIDC Core
//! §3.1.2.1 takes one to say *who the authorization request is about*. The
//! cryptographic half of the question is identical in both — is this a token
//! this tenant signed, and is it still readable — and `ast-o4u.1` had already
//! written it for logout. This module is that code, moved rather than copied:
//! a second verifier would be a second set of rules, and the rule that drifts
//! is always the one about which keys are trusted.
//!
//! # What is the same at both endpoints
//!
//! * **The signature, over this tenant's keys, retired ones included.** A hint
//!   is by nature an old token, so a key that has been rotated out but not yet
//!   destroyed must still verify it — [`KeyStore::public_key`] resolves a `kid`
//!   whatever state the key is in. The `kid` narrows an already-trusted set; it
//!   is never followed anywhere.
//! * **`iss` is this tenant's issuer.** A token another issuer signed is not a
//!   hint about anything here.
//! * **`exp` is ignored.** Both specifications say so in as many words —
//!   RP-Initiated Logout §4 for logout, and OIDC Core §3.1.2.1 for
//!   authorization, which requires an OP to accept an ID Token "when the ID
//!   Token... has expired". The hint's job is to name a party and a subject,
//!   not to authorise anything, and a client holding a two-hour-old ID token is
//!   the ordinary case rather than the suspicious one.
//!
//! # What is not the same
//!
//! **`aud`.** At logout the audience is what is being *read out* of the token —
//! the relying party is unknown until the hint names it — so it cannot also be
//! the thing checked against. At the authorization endpoint the client is
//! already authenticated by the time the hint is read, so `aud` is pinned to
//! it: a hint whose audience is some other client is one this client was never
//! given, and honouring it would let a client drive a decision using a token
//! issued to somebody else. [`names_client`] is that check, and it exists only
//! on the authorization side.
//!
//! **What a failure means.** At logout a hint that does not verify leaves the
//! relying party unidentified and the request one that has to be confirmed by
//! the user — §2 already has an answer for it, and it is a question. At the
//! authorization endpoint there is no such fallback: OIDC Core §3.1.2.1 says
//! the ID Token "MUST be validated", so a hint that does not verify makes the
//! whole request invalid, and it is refused at the push while the client is
//! still on the connection.

use asterius_domain::{KeyStore, SigningAlgorithm, Tenant};
use asterius_jose::verify::{self, Policy, TypRule};
use asterius_oidc::tokens::id_token::ID_TOKEN_TYP;
use serde_json::{Value, json};
use time::OffsetDateTime;

/// The claims of a hint this tenant signed.
///
/// `None` for anything that does not verify: a token signed by somebody else,
/// one naming another issuer, one whose `kid` this tenant has destroyed, or a
/// string that is not a JWS at all. The caller decides what that means, and the
/// two callers decide differently — see the module documentation.
pub async fn verified_claims(
    keys: &dyn KeyStore,
    tenant: &Tenant,
    hint: &str,
    now: OffsetDateTime,
) -> Option<Value> {
    let unverified = asterius_jose::jws::parse(hint).ok()?;
    let kid = unverified.kid();

    // The candidate keys are fetched before verification, because the resolver
    // is synchronous and because a `kid` must narrow an already-trusted set
    // rather than be followed.
    let mut jwks: Vec<Value> = Vec::new();
    if let Some(kid) = &kid {
        match keys.public_key(&tenant.id, kid).await {
            Ok(Some(record)) => jwks.push(record.public_jwk),
            Ok(None) => {}
            Err(error) => {
                tracing::error!(%error, tenant = %tenant.id, "cannot read a key for an id_token_hint");
                return None;
            }
        }
    }
    if jwks.is_empty() {
        match keys.published_keys(&tenant.id).await {
            Ok(records) => jwks.extend(records.into_iter().map(|record| record.public_jwk)),
            Err(error) => {
                tracing::error!(%error, tenant = %tenant.id, "cannot read the key set for an id_token_hint");
                return None;
            }
        }
    }
    let resolver = asterius_jose::keys_from_jwk_set(&json!({"keys": jwks})).ok()?;

    let policy = Policy::new(
        TypRule::Exactly(ID_TOKEN_TYP),
        SigningAlgorithm::ALL.to_vec(),
    )
    .issued_by(tenant.issuer.as_str().to_owned())
    .accepting_expired();

    match verify::verify(hint, &policy, &resolver, now) {
        Ok(verified) => Some(verified.claims),
        Err(error) => {
            // Debug, not warn: a stale hint signed by a key that has since been
            // rotated is ordinary, and both callers have an answer for it.
            tracing::debug!(%error, tenant = %tenant.id, "an id_token_hint did not verify");
            None
        }
    }
}

/// Whether a verified hint was issued to `client_id` (OIDC Core §2).
///
/// "The `aud` value... MUST contain the OAuth 2.0 `client_id` of the Relying
/// Party", and `azp` names the party the token was issued to when there is more
/// than one audience. So the client must be *in* `aud`, and when `azp` is
/// present it must *be* the client: a token audienced at two parties and
/// authorised for one of them is not a hint the other may use.
///
/// The claims must already have had their signature checked. This function
/// reads a verified token; it does not verify one.
#[must_use]
pub fn names_client(claims: &Value, client_id: &str) -> bool {
    if let Some(azp) = claims.get("azp").and_then(Value::as_str)
        && azp != client_id
    {
        return false;
    }
    match claims.get("aud") {
        Some(Value::String(one)) => one == client_id,
        Some(Value::Array(many)) => many.iter().any(|entry| entry.as_str() == Some(client_id)),
        _ => false,
    }
}

/// The `sub` a verified hint names, when it names one.
///
/// OIDC Core §2 makes `sub` required in an ID token, so a hint without one is
/// not an ID token this server issued — it verified, which means it was signed
/// by this tenant, and it is still not something to draw a subject from.
#[must_use]
pub fn subject(claims: &Value) -> Option<&str> {
    claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|subject| !subject.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// OIDC Core §2: `aud` must contain the client. The single-string form is
    /// how a token issued to one party is written.
    #[test]
    fn a_hint_audienced_at_the_client_names_it() {
        let claims = json!({"sub": "u-1", "aud": "billing"});

        assert!(names_client(&claims, "billing"));
    }

    /// The case this check exists for: a token issued to another client.
    #[test]
    fn a_hint_audienced_elsewhere_does_not_name_the_client() {
        let claims = json!({"sub": "u-1", "aud": "shipping"});

        assert!(!names_client(&claims, "billing"));
    }

    /// A multi-valued audience containing the client is a match, because §2
    /// asks for containment rather than equality.
    #[test]
    fn a_multi_valued_audience_containing_the_client_names_it() {
        let claims = json!({"sub": "u-1", "aud": ["shipping", "billing"], "azp": "billing"});

        assert!(names_client(&claims, "billing"));
    }

    /// `azp` names the party the token was authorised for, and it wins: being
    /// listed in `aud` is not the same as being the client it was issued to.
    #[test]
    fn an_azp_naming_another_party_refuses_the_hint() {
        let claims = json!({"sub": "u-1", "aud": ["billing", "shipping"], "azp": "shipping"});

        assert!(!names_client(&claims, "billing"));
    }

    /// A hint with no `sub` is not an ID token this server issued.
    #[test]
    fn a_hint_without_a_subject_yields_none() {
        assert_eq!(subject(&json!({"aud": "billing"})), None);
        assert_eq!(subject(&json!({"sub": ""})), None);
        assert_eq!(subject(&json!({"sub": "u-1"})), Some("u-1"));
    }
}
