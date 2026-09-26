//! Operator-pinned RFC 9421 request keys for configured SSF peers.

use crate::config::TenantConfig;
use asterius_domain::SigningAlgorithm;
use asterius_jose::http_signatures::{SignedFields, sign_response};
use asterius_jose::{SigningKey, VerifyingKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::collections::HashMap;

/// One peer's public key, never selected from request-supplied URLs or JWKs.
#[derive(Debug, Clone)]
pub struct PeerKey {
    pub keyid: String,
    pub key: VerifyingKey,
    /// Present only when this peer requires signed receiver responses.
    pub response_signer: Option<ResponseSigner>,
}

/// Boot-loaded local Ed25519 key for one peer's response policy.
#[derive(Debug, Clone)]
pub struct ResponseSigner {
    pub keyid: String,
    key: std::sync::Arc<SigningKey>,
}

impl ResponseSigner {
    /// Signs the exact status and body bytes with a fresh nonce and two-minute expiry.
    ///
    /// # Errors
    ///
    /// Returns an error if the clock, random source, or signing primitive fails.
    pub fn sign(&self, status: u16, body: &[u8]) -> Result<SignedFields, String> {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "response nonce unavailable".to_owned())?;
        let now = time::OffsetDateTime::now_utc();
        let expires = now
            .checked_add(time::Duration::minutes(2))
            .ok_or_else(|| "response signing clock invalid".to_owned())?;
        sign_response(
            status,
            body,
            &self.keyid,
            &hex::encode(nonce),
            now,
            expires,
            &self.key,
        )
        .map_err(|_| "HTTP response signing failed".to_owned())
    }
}

/// Boot-checked peer directory, indexed by resolved tenant and SET issuer.
#[derive(Debug, Clone, Default)]
pub struct PeerKeys(HashMap<String, HashMap<String, PeerKey>>);

impl PeerKeys {
    /// Loads each pinned Ed25519 key once. A missing or malformed file stops startup.
    ///
    /// # Errors
    ///
    /// Returns a path-scoped error without exposing public key contents.
    pub fn load(tenants: &[TenantConfig]) -> Result<Self, String> {
        let mut by_tenant = HashMap::new();
        for tenant in tenants {
            let mut peers = HashMap::new();
            for config in &tenant.http_signature_peers {
                let path = &config.public_key_file;
                let metadata = std::fs::metadata(path).map_err(|error| {
                    format!("cannot read HTTP signature key {}: {error}", path.display())
                })?;
                if metadata.len() > 256 {
                    return Err(format!(
                        "HTTP signature key {} exceeds 256 bytes",
                        path.display()
                    ));
                }
                let raw = std::fs::read_to_string(path).map_err(|error| {
                    format!("cannot read HTTP signature key {}: {error}", path.display())
                })?;
                let bytes = STANDARD
                    .decode(raw.trim())
                    .map_err(|_| format!("HTTP signature key {} is not base64", path.display()))?;
                if bytes.len() != 32 {
                    return Err(format!(
                        "HTTP signature key {} is not Ed25519",
                        path.display()
                    ));
                }
                let response_signer = config
                    .response_signing
                    .as_ref()
                    .map(|response| {
                        let path = &response.private_key_file;
                        let metadata = std::fs::metadata(path).map_err(|error| {
                            format!("cannot read HTTP response key {}: {error}", path.display())
                        })?;
                        if metadata.len() > 4096 {
                            return Err(format!(
                                "HTTP response key {} exceeds 4096 bytes",
                                path.display()
                            ));
                        }
                        let pkcs8 = std::fs::read(path).map_err(|error| {
                            format!("cannot read HTTP response key {}: {error}", path.display())
                        })?;
                        let key = SigningKey::from_pkcs8(SigningAlgorithm::EdDsa, &pkcs8).map_err(
                            |_| {
                                format!(
                                    "HTTP response key {} is not Ed25519 PKCS#8",
                                    path.display()
                                )
                            },
                        )?;
                        Ok(ResponseSigner {
                            keyid: response.keyid.clone(),
                            key: std::sync::Arc::new(key),
                        })
                    })
                    .transpose()?;
                peers.insert(
                    config.client_id.clone(),
                    PeerKey {
                        keyid: config.keyid.clone(),
                        key: VerifyingKey::new(SigningAlgorithm::EdDsa, bytes),
                        response_signer,
                    },
                );
            }
            by_tenant.insert(tenant.id.as_str().to_owned(), peers);
        }
        Ok(Self(by_tenant))
    }

    /// Finds the pinned key for the claimed SET issuer under the resolved tenant.
    #[must_use]
    pub fn find(&self, tenant: &str, client_id: &str) -> Option<&PeerKey> {
        self.0.get(tenant)?.get(client_id)
    }
}
