//! Operator-pinned RFC 9421 request keys for configured SSF peers.

use crate::config::TenantConfig;
use asterius_domain::SigningAlgorithm;
use asterius_jose::VerifyingKey;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::collections::HashMap;

/// One peer's public key, never selected from request-supplied URLs or JWKs.
#[derive(Debug, Clone)]
pub struct PeerKey {
    pub keyid: String,
    pub key: VerifyingKey,
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
                peers.insert(
                    config.client_id.clone(),
                    PeerKey {
                        keyid: config.keyid.clone(),
                        key: VerifyingKey::new(SigningAlgorithm::EdDsa, bytes),
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
