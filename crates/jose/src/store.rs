//! An in-process key store and signer.
//!
//! This is the implementation everything else is written against. Persisting
//! keys, encrypting them at rest and rotating them belongs to `ast-mxc.3`; what
//! is here is the shape those will fill in — a store that can answer "which key
//! signs for this tenant" and "which key does this `kid` mean", and a signer
//! that always writes a `kid`, an allow-listed `alg` and an explicit `typ`.

use crate::{JoseError, SigningKey, VerifyingKey, jws};
use asterius_domain::keys::{
    KeyPurpose, KeyState, KeyStore, PublicKeyRecord, Signer, SigningAlgorithm,
};
use asterius_domain::{CompactJws, DomainError, Kid, TenantId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;

/// Derives a `kid` from a public JWK, per RFC 7638.
///
/// A thumbprint rather than a random string, for two reasons. It is stable —
/// the same key always has the same `kid`, so a key restored from a backup does
/// not orphan every token signed with it. And it is verifiable — anyone holding
/// the public key can recompute it, so a `kid` cannot quietly point at
/// different material than it did yesterday.
///
/// RFC 7638 §3.2 fixes the construction: the required members for the key type,
/// lexicographically ordered, in the smallest possible JSON, hashed with
/// SHA-256. No whitespace, no other members — which is why this builds the JSON
/// by hand rather than re-serialising the JWK.
///
/// # Errors
///
/// Returns [`JoseError::PublicKey`] if the JWK is missing a required member.
pub fn thumbprint(jwk: &Value) -> Result<Kid, JoseError> {
    let member = |name: &str| -> Result<String, JoseError> {
        jwk.get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(JoseError::PublicKey)
    };

    let kty = member("kty")?;
    // The required members, in lexicographic order, per RFC 7638 §3.2.
    let canonical = match kty.as_str() {
        "OKP" => format!(
            r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
            member("crv")?,
            member("x")?
        ),
        "EC" => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            member("crv")?,
            member("x")?,
            member("y")?
        ),
        "RSA" => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            member("e")?,
            member("n")?
        ),
        _ => return Err(JoseError::PublicKey),
    };

    Ok(Kid::new(B64.encode(Sha256::digest(canonical.as_bytes()))))
}

/// One key, with everything the store needs to know about it.
struct StoredKey {
    kid: Kid,
    key: SigningKey,
    state: KeyState,
    public_jwk: Value,
    created_at: OffsetDateTime,
}

/// Keys held in memory, keyed by tenant.
#[derive(Clone, Default)]
pub struct LocalKeyStore {
    keys: Arc<RwLock<HashMap<String, Vec<StoredKey>>>>,
}

impl std::fmt::Debug for LocalKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tenants = self.keys.read().map(|keys| keys.len()).unwrap_or_default();
        f.debug_struct("LocalKeyStore")
            .field("tenants", &tenants)
            .finish()
    }
}

impl LocalKeyStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates a key for a tenant and puts it straight into `Active`.
    ///
    /// The shortcut is for tests and for first boot. Real rotation moves a key
    /// through `Pending` first so that verifiers can fetch it before anything
    /// is signed with it (`ast-mxc.3`).
    ///
    /// # Errors
    ///
    /// Returns [`JoseError`] if generation fails.
    pub fn generate(
        &self,
        tenant: &TenantId,
        algorithm: SigningAlgorithm,
    ) -> Result<Kid, JoseError> {
        let key = SigningKey::generate(algorithm)?;
        let public_jwk = key.public_jwk()?;
        let kid = thumbprint(&public_jwk)?;

        let mut jwk = public_jwk;
        jwk["kid"] = Value::String(kid.as_str().to_owned());

        let mut keys = self.keys.write().map_err(|_| JoseError::Signing)?;
        let tenant_keys = keys.entry(tenant.as_str().to_owned()).or_default();

        // At most one active key per algorithm: the previous one starts
        // retiring rather than disappearing, so tokens it signed still verify.
        for existing in tenant_keys.iter_mut() {
            if existing.state == KeyState::Active && existing.key.algorithm() == algorithm {
                existing.state = KeyState::Retiring;
            }
        }

        tenant_keys.push(StoredKey {
            kid: kid.clone(),
            key,
            state: KeyState::Active,
            public_jwk: jwk,
            created_at: OffsetDateTime::now_utc(),
        });
        Ok(kid)
    }

    /// The verifying key a `kid` refers to, in whatever state it is.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::PublicKey`] if the key exists but its public half
    /// cannot be read.
    pub fn verifying_key(
        &self,
        tenant: &TenantId,
        kid: &Kid,
    ) -> Result<Option<VerifyingKey>, JoseError> {
        let keys = self.keys.read().map_err(|_| JoseError::PublicKey)?;
        let Some(stored) = keys
            .get(tenant.as_str())
            .and_then(|tenant_keys| tenant_keys.iter().find(|key| &key.kid == kid))
        else {
            return Ok(None);
        };
        stored.key.verifying_key().map(Some)
    }
}

#[async_trait::async_trait]
impl KeyStore for LocalKeyStore {
    async fn published_keys(&self, tenant: &TenantId) -> Result<Vec<PublicKeyRecord>, DomainError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| DomainError::invalid("keys", "key store lock is poisoned"))?;
        Ok(keys
            .get(tenant.as_str())
            .map(|tenant_keys| {
                tenant_keys
                    .iter()
                    .filter(|key| key.state.is_published())
                    .map(|key| PublicKeyRecord {
                        tenant: tenant.clone(),
                        kid: key.kid.clone(),
                        algorithm: key.key.algorithm(),
                        // Every key this store holds signs. It has no way to
                        // make an encryption key, which is the crudest
                        // possible enforcement of FAPI 2.0 SP §6.8 item 2 and
                        // also the most reliable one.
                        purpose: KeyPurpose::Signing,
                        state: key.state,
                        public_jwk: key.public_jwk.clone(),
                        created_at: key.created_at,
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn public_key(
        &self,
        tenant: &TenantId,
        kid: &Kid,
    ) -> Result<Option<PublicKeyRecord>, DomainError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| DomainError::invalid("keys", "key store lock is poisoned"))?;
        Ok(keys.get(tenant.as_str()).and_then(|tenant_keys| {
            tenant_keys
                .iter()
                .find(|key| &key.kid == kid)
                .map(|key| PublicKeyRecord {
                    tenant: tenant.clone(),
                    kid: key.kid.clone(),
                    algorithm: key.key.algorithm(),
                    purpose: KeyPurpose::Signing,
                    state: key.state,
                    public_jwk: key.public_jwk.clone(),
                    created_at: key.created_at,
                })
        }))
    }
}

#[async_trait::async_trait]
impl Signer for LocalKeyStore {
    async fn sign(
        &self,
        tenant: &TenantId,
        typ: &'static str,
        claims: &Value,
    ) -> Result<CompactJws, DomainError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| DomainError::invalid("keys", "key store lock is poisoned"))?;

        let stored = keys
            .get(tenant.as_str())
            .and_then(|tenant_keys| {
                // The active key, preferring the default algorithm — a tenant
                // may hold an active key per algorithm, and EdDSA is what we
                // sign with unless it is absent.
                tenant_keys
                    .iter()
                    .find(|key| {
                        key.state == KeyState::Active
                            && key.key.algorithm() == SigningAlgorithm::DEFAULT
                    })
                    .or_else(|| tenant_keys.iter().find(|key| key.state == KeyState::Active))
            })
            .ok_or_else(|| DomainError::invalid("keys", "no active signing key for this tenant"))?;

        jws::sign(&stored.key, &stored.kid, typ, claims)
            .map_err(|e| DomainError::invalid("jws", e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tenant() -> TenantId {
        TenantId::new("demo")
    }

    #[tokio::test]
    async fn a_generated_key_signs_and_appears_in_the_published_set() {
        let store = LocalKeyStore::new();
        let kid = store
            .generate(&tenant(), SigningAlgorithm::EdDsa)
            .expect("generate");

        let jws = store
            .sign(&tenant(), "at+jwt", &json!({"sub": "alice"}))
            .await
            .expect("sign");

        let verifying = store
            .verifying_key(&tenant(), &kid)
            .expect("lookup")
            .expect("present");
        let payload = jws::parse(jws.as_str())
            .expect("parse")
            .verify(&verifying, "at+jwt")
            .expect("verify");
        assert_eq!(
            serde_json::from_slice::<Value>(&payload).expect("json")["sub"],
            "alice"
        );

        let published = store.published_keys(&tenant()).await.expect("published");
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].kid, kid);
        assert_eq!(published[0].state, KeyState::Active);
    }

    #[tokio::test]
    async fn signing_without_a_key_is_an_error_not_a_panic() {
        let store = LocalKeyStore::new();
        assert!(store.sign(&tenant(), "at+jwt", &json!({})).await.is_err());
    }

    /// A verifier that fetched the JWKS before a rotation must still be able to
    /// check tokens signed before it, so the old key keeps verifying and stays
    /// published.
    #[tokio::test]
    async fn rotation_retires_the_old_key_without_orphaning_its_tokens() {
        let store = LocalKeyStore::new();
        let old_kid = store
            .generate(&tenant(), SigningAlgorithm::EdDsa)
            .expect("first");
        let old_token = store
            .sign(&tenant(), "at+jwt", &json!({"v": 1}))
            .await
            .expect("sign");

        let new_kid = store
            .generate(&tenant(), SigningAlgorithm::EdDsa)
            .expect("second");
        assert_ne!(old_kid, new_kid);

        // New tokens use the new key.
        let new_token = store
            .sign(&tenant(), "at+jwt", &json!({"v": 2}))
            .await
            .expect("sign");
        assert_eq!(
            jws::parse(new_token.as_str()).expect("parse").kid(),
            Some(new_kid.clone())
        );

        // The old token still verifies against the old key.
        let old_key = store
            .verifying_key(&tenant(), &old_kid)
            .expect("lookup")
            .expect("present");
        jws::parse(old_token.as_str())
            .expect("parse")
            .verify(&old_key, "at+jwt")
            .expect("a token signed before rotation must still verify");

        // Both keys are still published.
        let published = store.published_keys(&tenant()).await.expect("published");
        assert_eq!(published.len(), 2);
        let states: Vec<KeyState> = published.iter().map(|key| key.state).collect();
        assert!(states.contains(&KeyState::Active));
        assert!(states.contains(&KeyState::Retiring));
    }

    #[tokio::test]
    async fn one_tenants_key_never_answers_for_another() {
        let store = LocalKeyStore::new();
        let alpha = TenantId::new("alpha");
        let beta = TenantId::new("beta");
        let alpha_kid = store
            .generate(&alpha, SigningAlgorithm::EdDsa)
            .expect("alpha");
        store
            .generate(&beta, SigningAlgorithm::EdDsa)
            .expect("beta");

        assert!(
            store
                .verifying_key(&beta, &alpha_kid)
                .expect("lookup")
                .is_none()
        );
        assert!(
            store
                .public_key(&beta, &alpha_kid)
                .await
                .expect("lookup")
                .is_none()
        );
        assert_eq!(
            store.published_keys(&alpha).await.expect("published").len(),
            1
        );

        // A token from alpha must not verify under any of beta's keys.
        let token = store
            .sign(&alpha, "at+jwt", &json!({}))
            .await
            .expect("sign");
        for key in store.published_keys(&beta).await.expect("published") {
            let verifying = store
                .verifying_key(&beta, &key.kid)
                .expect("lookup")
                .expect("present");
            assert!(
                jws::parse(token.as_str())
                    .expect("parse")
                    .verify(&verifying, "at+jwt")
                    .is_err()
            );
        }
    }

    /// RFC 7638: the thumbprint is over the required members only, in
    /// lexicographic order, with no whitespace.
    #[test]
    fn a_thumbprint_is_stable_and_ignores_members_that_are_not_required() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let jwk = key.public_jwk().expect("jwk");

        let first = thumbprint(&jwk).expect("thumbprint");
        assert_eq!(first, thumbprint(&jwk).expect("thumbprint"));

        // `alg`, `use` and `kid` are not required members, so adding or
        // changing them must not move the thumbprint.
        let mut decorated = jwk;
        decorated["kid"] = json!("something-else");
        decorated["use"] = json!("sig");
        decorated["ext"] = json!(true);
        assert_eq!(thumbprint(&decorated).expect("thumbprint"), first);
    }

    /// RFC 7638 §3.1's worked example, which is the only way to know the
    /// construction matches the specification rather than merely being
    /// self-consistent.
    #[test]
    fn the_rfc_7638_example_produces_the_published_thumbprint() {
        let jwk = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        assert_eq!(
            thumbprint(&jwk).expect("thumbprint").as_str(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn a_jwk_missing_a_required_member_has_no_thumbprint() {
        assert!(thumbprint(&json!({"kty": "OKP", "crv": "Ed25519"})).is_err());
        assert!(thumbprint(&json!({"kty": "EC", "crv": "P-256", "x": "a"})).is_err());
        assert!(thumbprint(&json!({"kty": "RSA", "n": "a"})).is_err());
        assert!(thumbprint(&json!({"kty": "oct", "k": "a"})).is_err());
        assert!(thumbprint(&json!({})).is_err());
    }
}
