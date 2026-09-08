//! The registration ceremony against W3C WebAuthn Level 3 §7.1.
//!
//! Every case is one numbered step of §7.1, or one sentence of §6.1 or §8.7.
//! The fixtures are assembled here rather than recorded from a browser: a
//! recorded blob proves one authenticator worked once, and what needs proving
//! is that each check *refuses* when its own bit is wrong — which needs a
//! generator that can produce one wrong thing at a time.

use asterius_webauthn::authenticator_data::AuthenticatorDataError;
use asterius_webauthn::client_data::ClientDataError;
use asterius_webauthn::cose::CoseError;
use asterius_webauthn::{
    Challenge, CoseAlgorithm, RegistrationError, RelyingParty, RelyingPartyError, UserVerification,
    attestation::AttestationError, registration,
};
use base64::Engine as _;
use ciborium::value::Value;

const RP_ID: &str = "as.example";
const ORIGIN: &str = "https://as.example";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn challenge() -> Challenge {
    Challenge::new(vec![7_u8; 32]).expect("32 bytes is enough")
}

fn relying_party(uv: UserVerification) -> RelyingParty {
    RelyingParty::new(RP_ID, vec![ORIGIN.to_owned()], uv).expect("a valid relying party")
}

/// A `clientDataJSON` the browser would have produced.
fn client_data(ceremony: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{ceremony}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        b64(challenge)
    )
    .into_bytes()
}

/// A `COSE_Key` an authenticator would have produced.
fn cose_key(kty: i64, alg: i64, crv: Option<i64>, x_len: usize, y_len: Option<usize>) -> Vec<u8> {
    let mut entries = vec![
        (Value::Integer(1.into()), Value::Integer(kty.into())),
        (Value::Integer(3.into()), Value::Integer(alg.into())),
    ];
    if let Some(crv) = crv {
        entries.push((Value::Integer((-1).into()), Value::Integer(crv.into())));
    }
    entries.push((Value::Integer((-2).into()), Value::Bytes(vec![1; x_len])));
    if let Some(y) = y_len {
        entries.push((Value::Integer((-3).into()), Value::Bytes(vec![2; y])));
    }
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).expect("encode");
    out
}

/// An RSA COSE key. RFC 8230 §4 puts the modulus at label -1 and the exponent
/// at -2, which is *not* where the EC and OKP coordinates live — the generic
/// builder above cannot express it.
fn rsa_key(modulus_len: usize) -> Vec<u8> {
    let entries = vec![
        (Value::Integer(1.into()), Value::Integer(3.into())),
        (Value::Integer(3.into()), Value::Integer((-257).into())),
        (
            Value::Integer((-1).into()),
            Value::Bytes(vec![1; modulus_len]),
        ),
        (Value::Integer((-2).into()), Value::Bytes(vec![1, 0, 1])),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).expect("encode");
    out
}

/// A P-256 key, which is what almost every passkey actually is.
fn es256_key() -> Vec<u8> {
    cose_key(2, -7, Some(1), 32, Some(32))
}

/// How the fixture should be bent, one thing at a time.
#[derive(Clone)]
struct Authenticator {
    rp_id: String,
    flags: u8,
    sign_count: u32,
    credential_id: Vec<u8>,
    key: Vec<u8>,
}

/// UP | UV | BE | AT — a healthy platform authenticator making a passkey.
const HEALTHY: u8 = 0b0100_1101;

impl Default for Authenticator {
    fn default() -> Self {
        Self {
            rp_id: RP_ID.to_owned(),
            flags: HEALTHY,
            sign_count: 0,
            credential_id: vec![9; 32],
            key: es256_key(),
        }
    }
}

impl Authenticator {
    /// §6.1 packed authenticator data with §6.5.2 attested credential data.
    fn authenticator_data(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&asterius_domain::sha256(self.rp_id.as_bytes()));
        out.push(self.flags);
        out.extend_from_slice(&self.sign_count.to_be_bytes());
        // aaguid
        out.extend_from_slice(&[0xAB; 16]);
        out.extend_from_slice(
            &u16::try_from(self.credential_id.len())
                .expect("a test credential id fits")
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.credential_id);
        out.extend_from_slice(&self.key);
        out
    }

    /// §6.5's attestation object, format `none`.
    fn attestation_object(&self) -> Vec<u8> {
        self.attestation_object_with("none", Value::Map(Vec::new()))
    }

    fn attestation_object_with(&self, fmt: &str, statement: Value) -> Vec<u8> {
        let object = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text(fmt.into())),
            (Value::Text("attStmt".into()), statement),
            (
                Value::Text("authData".into()),
                Value::Bytes(self.authenticator_data()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&object, &mut out).expect("encode");
        out
    }
}

/// Runs the ceremony with the default expectations.
fn verify(
    authenticator: &Authenticator,
    client: &[u8],
    uv: UserVerification,
) -> Result<registration::Registration, RegistrationError> {
    registration::verify(
        &relying_party(uv),
        &challenge(),
        client,
        &authenticator.attestation_object(),
        &CoseAlgorithm::ALL,
    )
}

// ---- the happy path ------------------------------------------------------

#[test]
fn a_well_formed_registration_is_accepted_and_reports_what_it_proved() {
    let authenticator = Authenticator::default();
    let registration = verify(
        &authenticator,
        &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
        UserVerification::Required,
    )
    .expect("a healthy registration");

    assert_eq!(registration.credential.credential_id, vec![9; 32]);
    assert_eq!(registration.credential.aaguid, [0xAB; 16]);
    assert_eq!(
        registration.credential.public_key.algorithm(),
        CoseAlgorithm::Es256
    );
    assert!(registration.credential.user_verified);
    assert!(registration.credential.backup_eligible);
    // BE without BS: eligible for backup, not yet backed up.
    assert!(!registration.credential.backup_state);
    assert_eq!(registration.origin, ORIGIN);
}

// ---- §7.1 step 7: the ceremony -------------------------------------------

/// A `webauthn.get` response replayed into a registration would otherwise
/// register a credential the user only meant to authenticate with.
#[test]
fn an_assertion_replayed_into_a_registration_is_refused() {
    let error = verify(
        &Authenticator::default(),
        &client_data("webauthn.get", challenge().as_bytes(), ORIGIN),
        UserVerification::Required,
    )
    .expect_err("a get response must not register");
    assert!(matches!(
        error,
        RegistrationError::ClientData(ClientDataError::WrongCeremony)
    ));
}

// ---- §7.1 step 8: the challenge ------------------------------------------

#[test]
fn a_challenge_that_is_not_the_one_issued_is_refused() {
    for wrong in [vec![8_u8; 32], vec![7_u8; 31], vec![7_u8; 33], Vec::new()] {
        let error = verify(
            &Authenticator::default(),
            &client_data("webauthn.create", &wrong, ORIGIN),
            UserVerification::Required,
        )
        .expect_err("a wrong challenge must be refused");
        assert!(
            matches!(
                error,
                RegistrationError::ClientData(ClientDataError::ChallengeMismatch)
            ),
            "{error} for {wrong:?}"
        );
    }
}

/// §13.4.3: at least 16 bytes. A shorter one is refused where it is made
/// rather than where it is compared.
#[test]
fn a_challenge_shorter_than_the_specification_permits_cannot_be_built() {
    assert!(Challenge::new(vec![0; 15]).is_err());
    assert!(Challenge::new(vec![0; 16]).is_ok());
}

// ---- §7.1 steps 9 and 10: the origin -------------------------------------

/// Byte-exact. Every one of these is a spelling that resolves somewhere else,
/// or somewhere the same but under a name this server did not write down.
#[test]
fn an_origin_that_is_not_exactly_the_registered_one_is_refused() {
    for wrong in [
        "https://as.example.evil.com",
        "https://evil.com",
        "http://as.example",
        "https://as.example:8443",
        "https://AS.example",
        "https://as.example/",
        "https://sub.as.example",
    ] {
        let error = verify(
            &Authenticator::default(),
            &client_data("webauthn.create", challenge().as_bytes(), wrong),
            UserVerification::Required,
        )
        .expect_err("a foreign origin must be refused");
        assert!(
            matches!(
                error,
                RegistrationError::ClientData(ClientDataError::UntrustedOrigin)
            ),
            "accepted {wrong}"
        );
    }
}

/// A subdomain is a *legal* place to use a credential scoped to `as.example`
/// as far as the browser is concerned — the RP ID is a registrable suffix. It
/// is this server's own origin list that says no, which is why the list exists
/// separately from the RP ID.
#[test]
fn a_subdomain_is_accepted_only_when_it_was_written_down() {
    let party = RelyingParty::new(
        RP_ID,
        vec![ORIGIN.to_owned(), "https://sub.as.example".to_owned()],
        UserVerification::Required,
    )
    .expect("a valid relying party");

    let authenticator = Authenticator::default();
    assert!(
        registration::verify(
            &party,
            &challenge(),
            &client_data(
                "webauthn.create",
                challenge().as_bytes(),
                "https://sub.as.example"
            ),
            &authenticator.attestation_object(),
            &CoseAlgorithm::ALL,
        )
        .is_ok()
    );
}

// ---- §7.1 step 13: the relying party -------------------------------------

#[test]
fn a_credential_made_for_another_relying_party_is_refused() {
    let authenticator = Authenticator {
        rp_id: "evil.example".to_owned(),
        ..Authenticator::default()
    };
    let error = verify(
        &authenticator,
        &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
        UserVerification::Required,
    )
    .expect_err("another RP's credential must be refused");
    assert!(matches!(
        error,
        RegistrationError::AuthenticatorData(AuthenticatorDataError::WrongRelyingParty)
    ));
}

// ---- §7.1 steps 14-16: the flags -----------------------------------------

#[test]
fn a_credential_made_without_a_human_present_is_refused() {
    let authenticator = Authenticator {
        flags: HEALTHY & !0b0000_0001,
        ..Authenticator::default()
    };
    let error = verify(
        &authenticator,
        &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
        UserVerification::Required,
    )
    .expect_err("UP is not optional");
    assert!(matches!(
        error,
        RegistrationError::AuthenticatorData(AuthenticatorDataError::NoUserPresence)
    ));
}

#[test]
fn user_verification_is_required_by_default_and_waivable_by_policy() {
    let authenticator = Authenticator {
        flags: HEALTHY & !0b0000_0100,
        ..Authenticator::default()
    };
    let client = client_data("webauthn.create", challenge().as_bytes(), ORIGIN);

    let error = verify(&authenticator, &client, UserVerification::Required)
        .expect_err("UV is required by default");
    assert!(matches!(
        error,
        RegistrationError::AuthenticatorData(AuthenticatorDataError::NoUserVerification)
    ));

    let allowed = verify(&authenticator, &client, UserVerification::Discouraged)
        .expect("a policy that does not require UV accepts it");
    assert!(
        !allowed.credential.user_verified,
        "the flag must still be recorded truthfully"
    );
}

/// §6.1: "If the BE flag is not set, the BS flag MUST NOT be set." A
/// credential reporting that it is backed up *and* that it cannot be is
/// describing something that does not exist.
#[test]
fn backup_flags_that_contradict_each_other_are_refused() {
    let authenticator = Authenticator {
        // BS set, BE clear.
        flags: (HEALTHY & !0b0000_1000) | 0b0001_0000,
        ..Authenticator::default()
    };
    let error = verify(
        &authenticator,
        &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
        UserVerification::Required,
    )
    .expect_err("BS without BE is not a state");
    assert!(matches!(
        error,
        RegistrationError::AuthenticatorData(AuthenticatorDataError::InconsistentBackupFlags)
    ));
}

#[test]
fn a_registration_without_attested_credential_data_is_refused() {
    let authenticator = Authenticator {
        flags: HEALTHY & !0b0100_0000,
        ..Authenticator::default()
    };
    let error = verify(
        &authenticator,
        &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
        UserVerification::Required,
    )
    .expect_err("registration needs a credential");
    assert!(matches!(
        error,
        RegistrationError::AuthenticatorData(AuthenticatorDataError::NoAttestedCredentialData)
    ));
}

// ---- §8.7: attestation ---------------------------------------------------

/// Only `none`. Accepting a format whose statement nobody verifies would be
/// worse than refusing it: it would look like attestation and prove nothing.
#[test]
fn an_attestation_format_this_server_does_not_verify_is_refused() {
    let authenticator = Authenticator::default();
    for fmt in ["packed", "tpm", "android-key", "apple", "fido-u2f"] {
        let object = authenticator.attestation_object_with(fmt, Value::Map(Vec::new()));
        let error = registration::verify(
            &relying_party(UserVerification::Required),
            &challenge(),
            &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
            &object,
            &CoseAlgorithm::ALL,
        )
        .expect_err("only none is accepted");
        assert!(
            matches!(
                error,
                RegistrationError::Attestation(AttestationError::UnsupportedFormat)
            ),
            "accepted {fmt}"
        );
    }
}

/// §8.7 defines the `none` statement as an *empty* map. Something inside it is
/// a field this server would be ignoring.
#[test]
fn a_none_attestation_carrying_a_statement_is_refused() {
    let authenticator = Authenticator::default();
    let object = authenticator.attestation_object_with(
        "none",
        Value::Map(vec![(
            Value::Text("sig".into()),
            Value::Bytes(vec![1, 2, 3]),
        )]),
    );
    let error = registration::verify(
        &relying_party(UserVerification::Required),
        &challenge(),
        &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
        &object,
        &CoseAlgorithm::ALL,
    )
    .expect_err("none means none");
    assert!(matches!(
        error,
        RegistrationError::Attestation(AttestationError::NonEmptyStatement)
    ));
}

// ---- COSE keys -----------------------------------------------------------

#[test]
fn every_algorithm_this_server_accepts_round_trips() {
    for (algorithm, key) in [
        (CoseAlgorithm::Es256, es256_key()),
        (CoseAlgorithm::EdDsa, cose_key(1, -8, Some(6), 32, None)),
        (CoseAlgorithm::Rs256, rsa_key(256)),
    ] {
        let authenticator = Authenticator {
            key,
            ..Authenticator::default()
        };
        let registration = verify(
            &authenticator,
            &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
            UserVerification::Required,
        )
        .unwrap_or_else(|e| panic!("{algorithm:?} was refused: {e}"));
        assert_eq!(registration.credential.public_key.algorithm(), algorithm);
    }
}

/// A key whose type and algorithm disagree is not a capability mismatch — it
/// is somebody assembling a structure by hand.
#[test]
fn a_key_whose_type_and_algorithm_disagree_is_refused() {
    for (kty, alg, crv) in [
        (2, -8, Some(1)), // EC2 claiming EdDSA
        (1, -7, Some(6)), // OKP claiming ES256
        (2, -7, Some(6)), // P-256 algorithm on an Ed25519 curve
    ] {
        let authenticator = Authenticator {
            key: cose_key(kty, alg, crv, 32, Some(32)),
            ..Authenticator::default()
        };
        let error = verify(
            &authenticator,
            &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
            UserVerification::Required,
        )
        .expect_err("a self-contradicting key must be refused");
        assert!(
            matches!(
                error,
                RegistrationError::AuthenticatorData(AuthenticatorDataError::PublicKey(
                    CoseError::TypeMismatch
                ))
            ),
            "accepted kty={kty} alg={alg}: {error}"
        );
    }
}

/// A short coordinate is a different point once it is left-padded, so one key
/// would have several spellings — and a credential-id-to-key mapping that is
/// not a function.
#[test]
fn a_coordinate_of_the_wrong_length_is_refused() {
    for (x, y) in [(31, 32), (32, 31), (33, 32), (0, 32)] {
        let authenticator = Authenticator {
            key: cose_key(2, -7, Some(1), x, Some(y)),
            ..Authenticator::default()
        };
        let error = verify(
            &authenticator,
            &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
            UserVerification::Required,
        )
        .expect_err("a mis-sized coordinate must be refused");
        assert!(
            matches!(
                error,
                RegistrationError::AuthenticatorData(AuthenticatorDataError::PublicKey(
                    CoseError::BadLength
                ))
            ),
            "accepted x={x} y={y}: {error}"
        );
    }
}

/// §7.1 step 17: the algorithm has to be one that was offered.
#[test]
fn a_key_of_an_algorithm_that_was_not_offered_is_refused() {
    let authenticator = Authenticator::default();
    let error = registration::verify(
        &relying_party(UserVerification::Required),
        &challenge(),
        &client_data("webauthn.create", challenge().as_bytes(), ORIGIN),
        &authenticator.attestation_object(),
        // ES256 is what the authenticator returned; it was not on the menu.
        &[CoseAlgorithm::EdDsa],
    )
    .expect_err("an unoffered algorithm must be refused");
    assert!(matches!(error, RegistrationError::AlgorithmNotOffered));
}

// ---- truncation ----------------------------------------------------------

/// Every prefix of a valid structure. None may panic, and none may be
/// accepted: this is a parser over bytes anyone who can reach the endpoint
/// chooses, so a slice index would be a denial of service.
#[test]
fn no_truncation_of_a_valid_registration_panics_or_is_accepted() {
    let authenticator = Authenticator::default();
    let object = authenticator.attestation_object();
    let client = client_data("webauthn.create", challenge().as_bytes(), ORIGIN);

    for len in 0..object.len() {
        let result = registration::verify(
            &relying_party(UserVerification::Required),
            &challenge(),
            &client,
            &object[..len],
            &CoseAlgorithm::ALL,
        );
        assert!(
            result.is_err(),
            "a {len}-byte attestation object was accepted"
        );
    }
}

#[test]
fn no_truncation_of_client_data_panics_or_is_accepted() {
    let authenticator = Authenticator::default();
    let object = authenticator.attestation_object();
    let client = client_data("webauthn.create", challenge().as_bytes(), ORIGIN);

    for len in 0..client.len() {
        let result = registration::verify(
            &relying_party(UserVerification::Required),
            &challenge(),
            &client[..len],
            &object,
            &CoseAlgorithm::ALL,
        );
        assert!(result.is_err(), "{len} bytes of client data was accepted");
    }
}

// ---- the relying party itself --------------------------------------------

/// `https://example.com` as an RP ID is the classic mistake. It fails at the
/// authenticator with an error nobody can read, so it is refused here.
#[test]
fn an_rp_id_that_is_not_a_bare_domain_is_refused() {
    for bad in [
        "https://as.example",
        "as.example/",
        "as.example:443",
        "user@as.example",
        "",
    ] {
        assert_eq!(
            RelyingParty::new(bad, vec![ORIGIN.to_owned()], UserVerification::Required)
                .map(|_| ())
                .expect_err("not a domain"),
            RelyingPartyError::NotADomain,
            "accepted {bad:?}"
        );
    }
}

#[test]
fn an_origin_list_that_could_never_match_is_refused_at_construction() {
    assert_eq!(
        RelyingParty::new(RP_ID, Vec::new(), UserVerification::Required)
            .map(|_| ())
            .expect_err("no origins"),
        RelyingPartyError::NoOrigins
    );
    for bad in ["http://as.example", "as.example", "https://as.example/cb"] {
        assert_eq!(
            RelyingParty::new(RP_ID, vec![bad.to_owned()], UserVerification::Required)
                .map(|_| ())
                .expect_err("not an origin"),
            RelyingPartyError::NotAnOrigin,
            "accepted {bad}"
        );
    }
}
