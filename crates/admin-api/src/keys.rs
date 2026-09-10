//! The signing-key screen's resources: inventory, JWKS preview, and the two
//! bodies the console posts.
//!
//! # A private key cannot reach this module
//!
//! The strongest statement this crate can make about "private key material
//! never leaves the server" is that it never arrives. The port the handlers
//! hold — [`asterius_domain::keys::KeyAdministration`] — returns
//! [`PublicKeyRecord`], which carries a public JWK and no other key bytes, and
//! has no method that yields a signing key at all. So there is nothing here to
//! redact, and no future handler can accidentally serialise a secret it was
//! never given.
//!
//! That is the structural half. [`public_members`] is the belt to that
//! braces, and it is not redundant: `signing_keys.public_jwk` is a `jsonb`
//! column, and a column is something an operator can `UPDATE` during an
//! incident and something a bug in a future key provider can write the wrong
//! value into. So the rendering is an **allow-list** of the public JWK members
//! RFC 7517 §4 and RFC 7518 §6 define, not a deny-list of the private ones: a
//! member nobody has thought about yet is dropped rather than published, which
//! is the direction that fails safe. `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`
//! and `k` are the members that name private material today, and the test
//! below feeds every one of them through a record to prove none survives.
//!
//! # The preview is the document, not a description of it
//!
//! [`jwks_document`] renders the JWK Set from the same records
//! `GET /jwks` publishes and in the same way, so the "preview" an operator
//! reads before rotating is the bytes a relying party will fetch afterwards.
//! A preview assembled differently would be a second implementation of the
//! most security-relevant document this server serves, and the two would
//! diverge exactly when it mattered.

use asterius_domain::keys::{
    Activation, KeyRotation, Kid, PublicKeyRecord, RotationSchedule, SigningAlgorithm,
};
use serde_json::{Map, Value, json};
use time::Duration;

use crate::error::AdminError;

/// The JWK members that are public, and the only ones this API will render.
///
/// RFC 7517 §4 (`kty`, `use`, `key_ops`, `alg`, `kid`, and the X.509 members)
/// and RFC 7518 §6.2–6.3 (`crv`, `x`, `y` for EC and OKP; `n`, `e` for RSA).
/// Every *private* member RFC 7518 defines — `d`, `p`, `q`, `dp`, `dq`, `qi`,
/// `oth` for RSA and EC, `k` for the symmetric keys this server does not use —
/// is absent from this list, and absent is how they are refused.
const PUBLIC_JWK_MEMBERS: [&str; 13] = [
    "kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256", "crv", "x", "y", "n",
];

/// The public members of a JWK, and nothing else.
///
/// An allow-list, for the reason the module documentation gives: a stored JWK
/// is a `jsonb` column, and the failure mode of a deny-list is that a member
/// invented after this code was written is published by default.
///
/// `e` is handled beside the list because `n` and `e` are the RSA pair and
/// keeping thirteen entries plus one readable beats a fourteen-entry array
/// nobody scans. See [`PUBLIC_JWK_MEMBERS`].
// fuzz-target: admin_key_request
#[must_use]
pub fn public_members(jwk: &Value) -> Value {
    let Some(object) = jwk.as_object() else {
        // Not an object, so not a JWK. An empty one rather than the value:
        // whatever this is, it is not something to hand to a browser.
        return json!({});
    };

    let mut rendered = Map::new();
    for member in PUBLIC_JWK_MEMBERS.iter().copied().chain(["e"]) {
        if let Some(value) = object.get(member) {
            rendered.insert(member.to_owned(), value.clone());
        }
    }
    Value::Object(rendered)
}

/// One key, as the console's inventory renders it.
///
/// The `kid` is in plain text here and that is deliberate: it is published in
/// the JWKS to the whole internet, and an inventory whose rows an operator
/// cannot match against a token header would be useless. (The *audit* trail
/// records it as a fingerprint instead — see `PgKeyRepository::record` — for a
/// different reason: the trail redacts high-entropy strings by shape.)
#[must_use]
pub fn summarise(record: &PublicKeyRecord) -> Value {
    json!({
        "kid": record.kid.as_str(),
        "alg": record.algorithm.as_str(),
        "use": record.purpose.as_str(),
        "state": record.state.as_str(),
        "published": record.state.is_published(),
        "created_at": record.created_at.unix_timestamp(),
        "public_jwk": public_members(&record.public_jwk),
    })
}

/// The inventory: every key, grouped by algorithm, with that algorithm's
/// rotation policy beside it.
///
/// Grouped rather than a flat list because "which key signs my `ES256` tokens,
/// and when does it change?" is one question, and an operator answering it from
/// a flat list has to do the grouping in their head.
#[must_use]
pub fn inventory_document(
    records: &[PublicKeyRecord],
    schedules: &[(SigningAlgorithm, RotationSchedule)],
) -> Value {
    let algorithms: Vec<Value> = SigningAlgorithm::ALL
        .iter()
        .map(|algorithm| {
            let keys: Vec<Value> = records
                .iter()
                .filter(|record| record.algorithm == *algorithm)
                .map(summarise)
                .collect();
            let schedule = schedules
                .iter()
                .find(|(named, _)| named == algorithm)
                .map(|(_, schedule)| schedule_document(*schedule));

            json!({
                "alg": algorithm.as_str(),
                "keys": keys,
                "schedule": schedule,
            })
        })
        .collect();

    json!({ "algorithms": algorithms })
}

/// A rotation policy, in whole seconds.
///
/// Seconds rather than an ISO 8601 duration because that is the unit the
/// console's form takes and the unit the schema stores; a third spelling in
/// between is a third place to get a conversion wrong.
#[must_use]
pub fn schedule_document(schedule: RotationSchedule) -> Value {
    json!({
        "rotation_period_seconds": schedule.rotation_period.whole_seconds(),
        "propagation_period_seconds": schedule.propagation_period.whole_seconds(),
        "grace_period_seconds": schedule.grace_period.whole_seconds(),
        "last_rotated_at": schedule.last_rotated_at.map(time::OffsetDateTime::unix_timestamp),
    })
}

/// The JWK Set exactly as `GET /jwks` would serve it right now.
///
/// Only the published states, because that is what a JWK Set is: OIDC Core
/// §10.1.1 keeps "recently decommissioned signing keys" in it and drops them
/// afterwards. A preview that showed retired keys would show a document no
/// relying party will ever receive.
#[must_use]
pub fn jwks_document(records: &[PublicKeyRecord]) -> Value {
    json!({
        "keys": records
            .iter()
            .filter(|record| record.state.is_published())
            .map(|record| public_members(&record.public_jwk))
            .collect::<Vec<Value>>(),
    })
}

/// What one rotation did, as the console reports it.
#[must_use]
pub fn rotation_document(rotation: &KeyRotation) -> Value {
    json!({
        "created_kid": rotation.created.as_ref().map(Kid::as_str),
        "activated_kid": rotation.activated.as_ref().map(Kid::as_str),
        "superseded_kid": rotation.superseded.as_ref().map(Kid::as_str),
        "retired_kids": rotation.retired.iter().map(Kid::as_str).collect::<Vec<&str>>(),
        "changed": !rotation.is_empty(),
    })
}

/// What `POST /keys/rotate` takes.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationRequest {
    /// The algorithm to rotate. Required: rotating "the keys" is three
    /// rotations, and an operator who meant one of them should not discover
    /// that by reading the result.
    pub alg: String,
    /// Whether the staged key starts signing at once. Absent means the safe
    /// answer — see [`Activation`].
    #[serde(default)]
    pub activate_immediately: bool,
}

impl RotationRequest {
    /// The algorithm this asks for.
    ///
    /// # Errors
    ///
    /// [`AdminError::Invalid`] for anything outside [`SigningAlgorithm::ALL`].
    /// The parser is the allow-list that keeps `none` and `HS256` from being
    /// values at all (RFC 8725 §3.1), and a console is not an exception to it.
    // fuzz-target: admin_key_request
    pub fn algorithm(&self) -> Result<SigningAlgorithm, AdminError> {
        SigningAlgorithm::parse(&self.alg).ok_or_else(|| {
            AdminError::Invalid(format!(
                "alg: {} is not one of the algorithms this server signs with",
                self.alg
            ))
        })
    }

    /// When the staged key may start signing.
    #[must_use]
    pub const fn activation(&self) -> Activation {
        if self.activate_immediately {
            Activation::Immediate
        } else {
            Activation::OnSchedule
        }
    }
}

/// What `PUT /keys/schedule` takes.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleRequest {
    /// The algorithm whose policy this replaces.
    pub alg: String,
    /// How often a new key is staged.
    pub rotation_period_seconds: i64,
    /// How long a new key is published before it may sign.
    pub propagation_period_seconds: i64,
    /// How long a key stays published after it stops signing.
    pub grace_period_seconds: i64,
}

impl ScheduleRequest {
    /// The algorithm this policy is for.
    ///
    /// # Errors
    ///
    /// [`AdminError::Invalid`] for an algorithm this server does not sign with.
    pub fn algorithm(&self) -> Result<SigningAlgorithm, AdminError> {
        SigningAlgorithm::parse(&self.alg).ok_or_else(|| {
            AdminError::Invalid(format!(
                "alg: {} is not one of the algorithms this server signs with",
                self.alg
            ))
        })
    }

    /// The policy, with `last_rotated_at` left where it is.
    ///
    /// Setting a policy must not rewrite when the tenant last rotated: that
    /// field is a fact about what happened, and a form that could edit it would
    /// let an operator postpone a rotation by claiming one had occurred.
    ///
    /// # Errors
    ///
    /// [`AdminError::Invalid`] if a period is negative, or if the propagation
    /// period is not shorter than the rotation period — a key that is still
    /// waiting to sign when its successor is staged never signs at all, and the
    /// tenant's active key would then never change while the screen showed a
    /// schedule that said it did.
    // fuzz-target: admin_key_request
    pub fn schedule(&self) -> Result<RotationSchedule, AdminError> {
        for (field, seconds) in [
            ("rotation_period_seconds", self.rotation_period_seconds),
            (
                "propagation_period_seconds",
                self.propagation_period_seconds,
            ),
            ("grace_period_seconds", self.grace_period_seconds),
        ] {
            if seconds <= 0 {
                return Err(AdminError::Invalid(format!(
                    "{field}: must be a positive whole number of seconds"
                )));
            }
        }

        if self.propagation_period_seconds >= self.rotation_period_seconds {
            return Err(AdminError::Invalid(
                "propagation_period_seconds: must be shorter than \
                 rotation_period_seconds, or a staged key is replaced before it \
                 ever begins signing"
                    .to_owned(),
            ));
        }

        Ok(RotationSchedule {
            rotation_period: Duration::seconds(self.rotation_period_seconds),
            propagation_period: Duration::seconds(self.propagation_period_seconds),
            grace_period: Duration::seconds(self.grace_period_seconds),
            last_rotated_at: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::TenantId;
    use asterius_domain::keys::{KeyPurpose, KeyState, Kid};
    use time::OffsetDateTime;

    fn record(state: KeyState, jwk: Value) -> PublicKeyRecord {
        PublicKeyRecord {
            tenant: TenantId::new("demo"),
            kid: Kid::new("k-1"),
            algorithm: SigningAlgorithm::EdDsa,
            purpose: KeyPurpose::Signing,
            state,
            public_jwk: jwk,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// The acceptance criterion of `ast-f7m.7`, at the one place this crate can
    /// state it: whatever a row holds, no private JWK member is rendered.
    ///
    /// The members are the ones RFC 7518 §6.2.2, §6.3.2 and §6.4 define as
    /// private — `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k` — and the record
    /// here is a row that has been tampered with to carry all of them at once.
    #[test]
    fn no_private_jwk_member_survives_being_rendered() {
        // Arrange
        let tampered = record(
            KeyState::Active,
            json!({
                "kty": "OKP", "crv": "Ed25519", "use": "sig", "kid": "k-1",
                "x": "public-part",
                "d": "PRIVATE", "p": "PRIVATE", "q": "PRIVATE", "dp": "PRIVATE",
                "dq": "PRIVATE", "qi": "PRIVATE", "oth": ["PRIVATE"], "k": "PRIVATE",
            }),
        );

        // Act
        let rendered = serde_json::to_string(&json!({
            "summary": summarise(&tampered),
            "jwks": jwks_document(std::slice::from_ref(&tampered)),
        }))
        .expect("serialise");

        // Assert
        assert!(
            !rendered.contains("PRIVATE"),
            "private key material was rendered: {rendered}"
        );
        for member in [
            "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"", "\"oth\"", "\"k\"",
        ] {
            assert!(
                !rendered.contains(member),
                "the {member} member was rendered: {rendered}"
            );
        }
        assert!(
            rendered.contains("public-part"),
            "the public half was dropped"
        );
    }

    /// A member nobody has thought about is dropped rather than published: the
    /// allow-list is what makes that the default.
    #[test]
    fn a_member_the_allow_list_does_not_name_is_not_rendered() {
        // Arrange
        let jwk = json!({"kty": "OKP", "x": "public", "asterius_private_hint": "leak"});

        // Act
        let rendered = public_members(&jwk);

        // Assert
        assert_eq!(rendered, json!({"kty": "OKP", "x": "public"}));
    }

    /// OIDC Core §10.1.1: a JWK Set holds the keys in use and the recently
    /// decommissioned ones. A retired key has left it, so the preview must not
    /// show one — the preview is a promise about what a relying party will
    /// fetch.
    #[test]
    fn the_preview_holds_exactly_the_published_keys() {
        // Arrange
        let published = [KeyState::Pending, KeyState::Active, KeyState::Retiring]
            .map(|state| record(state, json!({"kty": "OKP", "x": state.as_str()})));
        let retired = record(KeyState::Retired, json!({"kty": "OKP", "x": "retired"}));
        let mut records = published.to_vec();
        records.push(retired);

        // Act
        let document = jwks_document(&records);

        // Assert
        let keys = document["keys"].as_array().expect("keys").clone();
        assert_eq!(keys.len(), 3, "{document}");
        assert!(
            !keys.iter().any(|key| key["x"] == json!("retired")),
            "a retired key is in the JWK Set preview: {document}"
        );
    }

    /// Every algorithm the discovery document advertises gets a group, even one
    /// holding no key: an empty group is the console telling an operator that a
    /// `PS256` client would have nothing to verify against, and a missing group
    /// says nothing at all.
    #[test]
    fn the_inventory_names_every_algorithm_this_server_advertises() {
        // Arrange / Act
        let document = inventory_document(&[], &[]);

        // Assert
        let names: Vec<&str> = document["algorithms"]
            .as_array()
            .expect("algorithms")
            .iter()
            .filter_map(|group| group["alg"].as_str())
            .collect();
        assert_eq!(names, ["EdDSA", "ES256", "PS256"]);
    }

    /// RFC 8725 §3.1: the permitted algorithms are fixed in advance. The
    /// console posts an `alg` and is not an exception.
    #[test]
    fn a_rotation_of_an_algorithm_this_server_refuses_is_not_a_rotation() {
        for rejected in ["none", "HS256", "RS256", "ES384", "", "eddsa"] {
            // Arrange
            let request = RotationRequest {
                alg: rejected.to_owned(),
                activate_immediately: false,
            };

            // Act / Assert
            assert!(
                request.algorithm().is_err(),
                "the console was allowed to rotate {rejected}"
            );
        }
    }

    /// The safe default is the absent one: a body that says nothing about
    /// activation gets the propagation period (OIDC Core §10.1.1).
    #[test]
    fn a_rotation_that_does_not_ask_for_immediate_activation_waits() {
        // Arrange
        let body = json!({"alg": "EdDSA"});

        // Act
        let request: RotationRequest = serde_json::from_value(body).expect("parse");

        // Assert
        assert_eq!(request.activation(), Activation::OnSchedule);
        assert_eq!(request.algorithm().expect("alg"), SigningAlgorithm::EdDsa);
    }

    #[test]
    fn a_rotation_may_ask_for_immediate_activation() {
        // Arrange
        let body = json!({"alg": "ES256", "activate_immediately": true});

        // Act
        let request: RotationRequest = serde_json::from_value(body).expect("parse");

        // Assert
        assert_eq!(request.activation(), Activation::Immediate);
    }

    /// A propagation period that outlasts the rotation period stages a
    /// successor before its predecessor has begun signing, so the active key
    /// never changes. Refused at the form rather than discovered months later
    /// by an operator wondering why the `kid` is the one from January.
    #[test]
    fn a_schedule_whose_propagation_outlasts_its_rotation_is_refused() {
        // Arrange
        let request = ScheduleRequest {
            alg: "EdDSA".to_owned(),
            rotation_period_seconds: 900,
            propagation_period_seconds: 900,
            grace_period_seconds: 60,
        };

        // Act / Assert
        assert!(request.schedule().is_err());
    }

    #[test]
    fn a_schedule_period_that_is_not_positive_is_refused() {
        for (rotation, propagation, grace) in [(0, 1, 1), (900, 0, 1), (900, 60, 0), (900, -1, 1)] {
            // Arrange
            let request = ScheduleRequest {
                alg: "EdDSA".to_owned(),
                rotation_period_seconds: rotation,
                propagation_period_seconds: propagation,
                grace_period_seconds: grace,
            };

            // Act / Assert
            assert!(
                request.schedule().is_err(),
                "accepted {rotation}/{propagation}/{grace}"
            );
        }
    }

    /// Setting a policy states what should happen next, and never rewrites what
    /// already happened.
    #[test]
    fn setting_a_policy_does_not_claim_a_rotation_took_place() {
        // Arrange
        let request = ScheduleRequest {
            alg: "EdDSA".to_owned(),
            rotation_period_seconds: 7_776_000,
            propagation_period_seconds: 900,
            grace_period_seconds: 604_800,
        };

        // Act
        let schedule = request.schedule().expect("a valid policy");

        // Assert
        assert_eq!(schedule.last_rotated_at, None);
        assert_eq!(schedule.rotation_period, Duration::days(90));
    }
}
