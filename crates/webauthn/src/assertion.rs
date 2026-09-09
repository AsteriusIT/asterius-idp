//! The authentication ceremony (WebAuthn L3 §7.2).
//!
//! Registration proves a credential into existence; an assertion proves that
//! the same authenticator is still holding it, *now*, for this server. The
//! difference is one signature — over the authenticator's own bytes and a hash
//! of the browser's — and the counter that comes with it.
//!
//! # The signature counter, which is the whole reason this file is longer than
//! §7.2 looks
//!
//! §6.1.1 defines `signCount` as a value an authenticator increments on every
//! assertion, and §7.2 step 21 is the only anti-cloning signal WebAuthn has:
//! two copies of one credential drift apart, and the copy that is behind is
//! visible the moment it signs. A counter that is stored and never read is not
//! a weaker version of that protection — it is none of it, with a column that
//! makes it look present.
//!
//! The specification is equally clear about the other side. An authenticator
//! is *permitted* to report zero always (§6.1.1: "authenticators that do not
//! implement a signature counter set signCount to zero"), and most platform
//! passkeys do, because a synchronised credential lives on several devices at
//! once and a monotonic counter across them is not a thing that exists. So the
//! rule is the specification's rule and not a stricter one:
//!
//! * both the stored and the presented counter zero — the authenticator does
//!   not count, and nothing is inferred. [`SignCount::NotSupported`];
//! * presented greater than stored — ordinary progress. [`SignCount::Advanced`],
//!   and the caller stores the new value;
//! * either one non-zero and presented not greater than stored — the signal
//!   §7.2 step 21 calls "a cloned authenticator, or a malfunction".
//!   [`SignCount::Regressed`].
//!
//! What to do with the third case is the relying party's, and this server's
//! answer is [`SignCountPolicy::Block`]: the assertion fails and the caller is
//! told exactly why, so it can write the audit record the bead asks for. It is
//! a safe answer to take because the check happens **after** the signature: a
//! regression is only ever reported for an assertion that really was produced
//! by the credential's private key over a challenge this server issued this
//! minute. Nobody without that key can provoke it.
//!
//! # What the caller still owns
//!
//! * Spending the challenge (§7.2 step 11 compares; it does not consume).
//! * Finding the credential by its id and, when `allowCredentials` was empty,
//!   checking that `userHandle` names the user that credential belongs to
//!   (steps 6 and 7). Both are queries, and this crate answers none.
//! * Storing [`SignCount::Advanced`]'s value, and acting on
//!   [`AssertionError::SignCountRegressed`].

use crate::authenticator_data;
use crate::client_data::{self, Ceremony};
use crate::cose::CredentialPublicKey;
use crate::{Challenge, RelyingParty, signature};
use asterius_domain::sha256;

/// Why an assertion was refused.
///
/// As with registration, the variants exist for the log: the browser is told
/// one thing however this failed. §7.2 defines no error vocabulary, and the
/// distinctions here — "that origin is not ours", "that signature is not this
/// key's" — are exactly the ones an attacker probing for a usable credential
/// would like drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssertionError {
    /// The browser's half was refused.
    #[error("client data: {0}")]
    ClientData(#[from] client_data::ClientDataError),
    /// The authenticator's half was refused.
    #[error("authenticator data: {0}")]
    AuthenticatorData(#[from] authenticator_data::AuthenticatorDataError),
    /// The signature is not this credential's over these bytes.
    #[error("signature: {0}")]
    Signature(#[from] signature::SignatureError),
    /// The counter went backwards, and policy is to block (§7.2 step 21).
    ///
    /// Carries both values because the audit record is the point: an operator
    /// looking at a cloned-authenticator alert needs to see how far behind the
    /// presented counter was.
    #[error("the signature counter went backwards: {presented} is not above {stored}")]
    SignCountRegressed {
        /// What this assertion reported.
        presented: u32,
        /// What the credential record held.
        stored: u32,
    },
}

/// What this relying party does about a counter that did not advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignCountPolicy {
    /// Refuse the assertion. This server's default, and the bead's.
    #[default]
    Block,
    /// Accept it and report [`SignCount::Regressed`] to the caller.
    ///
    /// Exists because §7.2 step 21 leaves the decision to the relying party
    /// and because a deployment that has met a genuinely broken authenticator
    /// model needs somewhere to say so. Nothing selects it today; the
    /// per-tenant policy that would is `ast-2vk.7`.
    Allow,
}

/// What the counter said about this credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignCount {
    /// Neither side counts. Nothing to store and nothing to infer.
    NotSupported,
    /// The counter moved forward. The caller stores this value.
    Advanced(u32),
    /// The counter did not move forward, and both values are not zero.
    Regressed {
        /// What this assertion reported.
        presented: u32,
        /// What the credential record held.
        stored: u32,
    },
}

/// The three fields an `AuthenticatorAssertionResponse` contributes (§5.2.2).
///
/// A struct rather than three arguments because they are three byte strings of
/// no distinguishable type, and getting two of them the wrong way round is a
/// mistake a signature check would report as "does not verify".
#[derive(Debug, Clone, Copy)]
pub struct AssertionResponse<'a> {
    /// `clientDataJSON`, as the octets received.
    pub client_data_json: &'a [u8],
    /// `authenticatorData`, which the authenticator signed verbatim.
    pub authenticator_data: &'a [u8],
    /// `signature`.
    pub signature: &'a [u8],
}

/// What a verified assertion proved.
#[derive(Debug, Clone)]
pub struct Assertion {
    /// The origin the ceremony actually happened at, for the audit record.
    pub origin: String,
    /// Whether the user was verified, not merely present.
    ///
    /// The `amr` value `user` (RFC 8176) is this bit and nothing else.
    pub user_verified: bool,
    /// Whether the credential may be backed up (§6.1.3).
    pub backup_eligible: bool,
    /// Whether it currently is. Worth storing again: a credential that has
    /// since been synchronised to a second device says so here first.
    pub backup_state: bool,
    /// What the counter said.
    pub sign_count: SignCount,
}

/// Verifies an authentication response.
///
/// §7.2 in the order the specification writes it, with the steps that belong
/// to a store left to the caller — see the module documentation for the list.
///
/// `stored_sign_count` is the counter on the credential record, which for a
/// credential that has never asserted is the one registration wrote.
///
/// # Errors
///
/// [`AssertionError`] if any step fails, including
/// [`AssertionError::SignCountRegressed`] under [`SignCountPolicy::Block`].
pub fn verify(
    relying_party: &RelyingParty,
    challenge: &Challenge,
    response: &AssertionResponse<'_>,
    key: &CredentialPublicKey,
    stored_sign_count: u32,
    policy: SignCountPolicy,
) -> Result<Assertion, AssertionError> {
    // Steps 10-13.
    let client = client_data::verify(
        response.client_data_json,
        Ceremony::Get,
        challenge.as_bytes(),
        relying_party.origins(),
    )?;

    // Steps 15-18.
    let asserted = authenticator_data::verify_assertion(
        response.authenticator_data,
        relying_party.id_hash(),
        relying_party.user_verification(),
    )?;

    // Steps 19-20. The signed bytes are the authenticator data exactly as it
    // arrived, followed by the hash of the client data exactly as it arrived:
    // re-encoding either would verify a document nobody signed.
    let mut signed = Vec::with_capacity(response.authenticator_data.len() + 32);
    signed.extend_from_slice(response.authenticator_data);
    signed.extend_from_slice(&sha256(response.client_data_json));
    signature::verify(key, &signed, response.signature)?;

    // Step 21, and only now: a counter is a claim, and an unsigned claim is
    // not one worth acting on. Reaching this line means the credential's own
    // private key signed a challenge this server issued.
    let sign_count = classify(asserted.sign_count, stored_sign_count);
    if let SignCount::Regressed { presented, stored } = sign_count
        && policy == SignCountPolicy::Block
    {
        return Err(AssertionError::SignCountRegressed { presented, stored });
    }

    Ok(Assertion {
        origin: client.origin().to_owned(),
        user_verified: asserted.user_verified,
        backup_eligible: asserted.backup_eligible,
        backup_state: asserted.backup_state,
        sign_count,
    })
}

/// §7.2 step 21's three cases, and nothing else.
#[must_use]
pub const fn classify(presented: u32, stored: u32) -> SignCount {
    if presented == 0 && stored == 0 {
        // §6.1.1 permits an authenticator not to count, and a synchronised
        // passkey generally does not. Refusing this would refuse most of the
        // credentials this server exists to accept.
        SignCount::NotSupported
    } else if presented > stored {
        SignCount::Advanced(presented)
    } else {
        SignCount::Regressed { presented, stored }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator_data::UserVerification;
    use crate::cose;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair};
    use ciborium::value::Value;

    /// The flag bits, spelled out here so a test says what it sets.
    const UP: u8 = 1 << 0;
    const UV: u8 = 1 << 2;

    fn relying_party() -> RelyingParty {
        RelyingParty::new(
            "id.example.com",
            vec!["https://id.example.com".to_owned()],
            UserVerification::Required,
        )
        .expect("a relying party")
    }

    fn challenge() -> Challenge {
        Challenge::new(vec![7_u8; 32]).expect("32 bytes")
    }

    fn client_data(origin: &str, challenge: &Challenge) -> Vec<u8> {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes());
        format!(r#"{{"type":"webauthn.get","challenge":"{encoded}","origin":"{origin}"}}"#)
            .into_bytes()
    }

    fn authenticator_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
        let mut data = asterius_domain::sha256(rp_id.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&sign_count.to_be_bytes());
        data
    }

    /// An ES256 pair and the COSE key that names its public half.
    fn credential() -> (EcdsaKeyPair, CredentialPublicKey) {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &random,
        )
        .expect("a generated key");
        let pair = EcdsaKeyPair::from_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            document.as_ref(),
        )
        .expect("the generated key parses");
        let point = pair.public_key().as_ref().to_vec();
        let map = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(point[1..33].to_vec()),
            ),
            (
                Value::Integer((-3).into()),
                Value::Bytes(point[33..].to_vec()),
            ),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&map, &mut encoded).expect("a CBOR map encodes");
        (
            pair,
            cose::parse(&encoded).expect("a key this server accepts"),
        )
    }

    /// Signs one, the way an authenticator would.
    fn sign(pair: &EcdsaKeyPair, authenticator_data: &[u8], client_data: &[u8]) -> Vec<u8> {
        let mut signed = authenticator_data.to_vec();
        signed.extend_from_slice(&asterius_domain::sha256(client_data));
        pair.sign(&SystemRandom::new(), &signed)
            .expect("a signature")
            .as_ref()
            .to_vec()
    }

    #[test]
    fn an_assertion_from_the_credentials_own_key_verifies() {
        // Arrange
        let (pair, key) = credential();
        let challenge = challenge();
        let client = client_data("https://id.example.com", &challenge);
        let data = authenticator_data("id.example.com", UP | UV, 9);
        let signature = sign(&pair, &data, &client);

        // Act
        let assertion = verify(
            &relying_party(),
            &challenge,
            &AssertionResponse {
                client_data_json: &client,
                authenticator_data: &data,
                signature: &signature,
            },
            &key,
            8,
            SignCountPolicy::Block,
        );

        // Assert
        let assertion = assertion.expect("the ceremony verifies");
        assert_eq!(assertion.sign_count, SignCount::Advanced(9));
    }

    #[test]
    fn a_signature_over_other_bytes_is_refused() {
        // Arrange
        let (pair, key) = credential();
        let challenge = challenge();
        let client = client_data("https://id.example.com", &challenge);
        let data = authenticator_data("id.example.com", UP | UV, 9);
        let elsewhere = authenticator_data("id.example.com", UP | UV, 10);
        let signature = sign(&pair, &elsewhere, &client);

        // Act
        let outcome = verify(
            &relying_party(),
            &challenge,
            &AssertionResponse {
                client_data_json: &client,
                authenticator_data: &data,
                signature: &signature,
            },
            &key,
            8,
            SignCountPolicy::Block,
        );

        // Assert
        assert_eq!(
            outcome.unwrap_err(),
            AssertionError::Signature(signature::SignatureError::BadSignature)
        );
    }

    #[test]
    fn an_assertion_from_another_origin_is_refused() {
        // Arrange
        let (pair, key) = credential();
        let challenge = challenge();
        let client = client_data("https://id.example.com.evil.test", &challenge);
        let data = authenticator_data("id.example.com", UP | UV, 9);
        let signature = sign(&pair, &data, &client);

        // Act
        let outcome = verify(
            &relying_party(),
            &challenge,
            &AssertionResponse {
                client_data_json: &client,
                authenticator_data: &data,
                signature: &signature,
            },
            &key,
            8,
            SignCountPolicy::Block,
        );

        // Assert
        assert_eq!(
            outcome.unwrap_err(),
            AssertionError::ClientData(client_data::ClientDataError::UntrustedOrigin)
        );
    }

    /// §7.1 step 15's rule, on the other ceremony: a passkey this server
    /// treats as sufficient on its own has to have verified a user.
    #[test]
    fn an_assertion_without_user_verification_is_refused() {
        // Arrange
        let (pair, key) = credential();
        let challenge = challenge();
        let client = client_data("https://id.example.com", &challenge);
        let data = authenticator_data("id.example.com", UP, 9);
        let signature = sign(&pair, &data, &client);

        // Act
        let outcome = verify(
            &relying_party(),
            &challenge,
            &AssertionResponse {
                client_data_json: &client,
                authenticator_data: &data,
                signature: &signature,
            },
            &key,
            8,
            SignCountPolicy::Block,
        );

        // Assert
        assert_eq!(
            outcome.unwrap_err(),
            AssertionError::AuthenticatorData(
                authenticator_data::AuthenticatorDataError::NoUserVerification
            )
        );
    }

    /// The clone signal, and the reason the counter is stored at all.
    #[test]
    fn a_counter_that_did_not_advance_blocks_a_signed_assertion() {
        // Arrange
        let (pair, key) = credential();
        let challenge = challenge();
        let client = client_data("https://id.example.com", &challenge);
        let data = authenticator_data("id.example.com", UP | UV, 4);
        let signature = sign(&pair, &data, &client);

        // Act
        let outcome = verify(
            &relying_party(),
            &challenge,
            &AssertionResponse {
                client_data_json: &client,
                authenticator_data: &data,
                signature: &signature,
            },
            &key,
            9,
            SignCountPolicy::Block,
        );

        // Assert
        assert_eq!(
            outcome.unwrap_err(),
            AssertionError::SignCountRegressed {
                presented: 4,
                stored: 9,
            }
        );
    }

    /// §6.1.1: an authenticator that does not count reports zero, always. That
    /// is the common case for a synchronised passkey and it must sign in.
    #[test]
    fn an_authenticator_that_never_counts_is_not_treated_as_cloned() {
        // Arrange
        let (pair, key) = credential();
        let challenge = challenge();
        let client = client_data("https://id.example.com", &challenge);
        let data = authenticator_data("id.example.com", UP | UV, 0);
        let signature = sign(&pair, &data, &client);

        // Act
        let assertion = verify(
            &relying_party(),
            &challenge,
            &AssertionResponse {
                client_data_json: &client,
                authenticator_data: &data,
                signature: &signature,
            },
            &key,
            0,
            SignCountPolicy::Block,
        );

        // Assert
        assert_eq!(
            assertion
                .expect("a zero counter is not a regression")
                .sign_count,
            SignCount::NotSupported
        );
    }

    /// A counter that *was* counting and now reports zero is the interesting
    /// half of the zero rule: §7.2 step 21 only exempts the case where both
    /// are zero, so this one is still a clone signal.
    #[test]
    fn a_counter_that_falls_back_to_zero_is_a_regression() {
        // Arrange, Act
        let outcome = classify(0, 12);

        // Assert
        assert_eq!(
            outcome,
            SignCount::Regressed {
                presented: 0,
                stored: 12,
            }
        );
    }

    /// The escape hatch is a policy, not a second code path: the same
    /// assertion is accepted and the caller is told what happened.
    #[test]
    fn a_relaxed_policy_reports_the_regression_instead_of_refusing() {
        // Arrange
        let (pair, key) = credential();
        let challenge = challenge();
        let client = client_data("https://id.example.com", &challenge);
        let data = authenticator_data("id.example.com", UP | UV, 4);
        let signature = sign(&pair, &data, &client);

        // Act
        let assertion = verify(
            &relying_party(),
            &challenge,
            &AssertionResponse {
                client_data_json: &client,
                authenticator_data: &data,
                signature: &signature,
            },
            &key,
            9,
            SignCountPolicy::Allow,
        );

        // Assert
        assert_eq!(
            assertion
                .expect("an allowed regression verifies")
                .sign_count,
            SignCount::Regressed {
                presented: 4,
                stored: 9,
            }
        );
    }

    /// §7.2 step 11, from the other side: a challenge this server did not
    /// issue for this ceremony is not one an assertion may be built on.
    #[test]
    fn an_assertion_for_another_challenge_is_refused() {
        // Arrange
        let (pair, key) = credential();
        let signed_for = Challenge::new(vec![1_u8; 32]).expect("32 bytes");
        let client = client_data("https://id.example.com", &signed_for);
        let data = authenticator_data("id.example.com", UP | UV, 9);
        let signature = sign(&pair, &data, &client);

        // Act
        let outcome = verify(
            &relying_party(),
            &challenge(),
            &AssertionResponse {
                client_data_json: &client,
                authenticator_data: &data,
                signature: &signature,
            },
            &key,
            8,
            SignCountPolicy::Block,
        );

        // Assert
        assert_eq!(
            outcome.unwrap_err(),
            AssertionError::ClientData(client_data::ClientDataError::ChallengeMismatch)
        );
    }

    /// §7.2 step 15: a credential scoped to another relying party cannot be
    /// spent here, whatever the browser says the origin was.
    #[test]
    fn an_assertion_for_another_relying_party_is_refused() {
        // Arrange
        let (pair, key) = credential();
        let challenge = challenge();
        let client = client_data("https://id.example.com", &challenge);
        let data = authenticator_data("other.example.com", UP | UV, 9);
        let signature = sign(&pair, &data, &client);

        // Act
        let outcome = verify(
            &relying_party(),
            &challenge,
            &AssertionResponse {
                client_data_json: &client,
                authenticator_data: &data,
                signature: &signature,
            },
            &key,
            8,
            SignCountPolicy::Block,
        );

        // Assert
        assert_eq!(
            outcome.unwrap_err(),
            AssertionError::AuthenticatorData(
                authenticator_data::AuthenticatorDataError::WrongRelyingParty
            )
        );
    }
}
