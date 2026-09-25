//! Operator-pinned OpenID4VP verifier policies loaded at process startup.

use crate::config::{Oid4vpVerifierConfig, TenantConfig};
use asterius_jose::{ClientKeySet, keys_from_jwk_set, oid4vp::PresentationPolicy};
use asterius_oidc::oid4vp::VerifierQuery;
use std::collections::HashMap;
use std::path::Path;

/// A validated verifier profile with local, pinned public keys.
#[derive(Debug, Clone)]
pub struct ConfiguredVerifier {
    /// Stable identifier within one tenant.
    pub id: String,
    /// OAuth client allowed to initiate and retrieve this verifier's result.
    pub initiator_client_id: String,
    /// Request shape offered to wallets.
    pub query: VerifierQuery,
    holder: String,
    holder_keys: ClientKeySet,
    credential_issuer: String,
    credential_issuer_keys: ClientKeySet,
    accept_without_status: bool,
}

impl ConfiguredVerifier {
    /// Produces a transaction-bound verification policy.
    #[must_use]
    pub fn policy(&self, nonce: String) -> PresentationPolicy {
        PresentationPolicy {
            client_id: self.query.client_id.clone(),
            nonce,
            holder: self.holder.clone(),
            holder_keys: self.holder_keys.clone(),
            credential_issuer: self.credential_issuer.clone(),
            credential_issuer_keys: self.credential_issuer_keys.clone(),
            credential_type: self.query.credential_type.clone(),
            required_claim_paths: self.query.claim_paths.clone(),
            accept_without_status: self.accept_without_status,
        }
    }
}

/// The complete boot-checked verifier directory.
#[derive(Debug, Clone, Default)]
pub struct Oid4vpVerifiers(HashMap<String, Vec<ConfiguredVerifier>>);

impl Oid4vpVerifiers {
    /// Loads every named JWKS. A missing, malformed or keyless trust anchor
    /// stops startup rather than causing a runtime fallback.
    ///
    /// # Errors
    ///
    /// Returns a path-scoped configuration error without disclosing key bytes.
    pub fn load(tenants: &[TenantConfig]) -> Result<Self, String> {
        let mut entries = HashMap::new();
        for tenant in tenants {
            let mut verifiers = Vec::new();
            for config in &tenant.oid4vp_verifiers {
                verifiers.push(load_verifier(config)?);
            }
            entries.insert(tenant.id.as_str().to_owned(), verifiers);
        }
        Ok(Self(entries))
    }

    /// Finds a configured verifier under the resolved tenant.
    #[must_use]
    pub fn find(&self, tenant_id: &str, verifier_id: &str) -> Option<&ConfiguredVerifier> {
        self.0
            .get(tenant_id)?
            .iter()
            .find(|verifier| verifier.id == verifier_id)
    }

    /// Whether any verifier is enabled for this tenant.
    #[must_use]
    pub fn enabled(&self, tenant_id: &str) -> bool {
        self.0
            .get(tenant_id)
            .is_some_and(|entries| !entries.is_empty())
    }
}

fn load_verifier(config: &Oid4vpVerifierConfig) -> Result<ConfiguredVerifier, String> {
    let holder_keys = load_keys(&config.holder_jwks_file)?;
    let credential_issuer_keys = load_keys(&config.issuer_jwks_file)?;
    let query = VerifierQuery {
        client_id: config.wallet_client_id.clone(),
        response_uri: config.response_uri.clone(),
        credential_id: config.credential_id.clone(),
        credential_type: config.credential_type.clone(),
        claim_paths: config.claim_paths.clone(),
    };
    asterius_oidc::oid4vp::prepare(&query)
        .map_err(|error| format!("invalid OID4VP verifier {}: {error}", config.id))?;
    Ok(ConfiguredVerifier {
        id: config.id.clone(),
        initiator_client_id: config.initiator_client_id.clone(),
        query,
        holder: config.holder.clone(),
        holder_keys,
        credential_issuer: config.credential_issuer.as_str().to_owned(),
        credential_issuer_keys,
        accept_without_status: config.accept_without_status,
    })
}

fn load_keys(path: &Path) -> Result<ClientKeySet, String> {
    const MAX_JWKS_BYTES: u64 = 65_536;
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("cannot read OID4VP JWKS {}: {error}", path.display()))?;
    if metadata.len() > MAX_JWKS_BYTES {
        return Err(format!("OID4VP JWKS {} exceeds 64 KiB", path.display()));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read OID4VP JWKS {}: {error}", path.display()))?;
    if bytes.len() > MAX_JWKS_BYTES as usize {
        return Err(format!("OID4VP JWKS {} exceeds 64 KiB", path.display()));
    }
    let jwks = serde_json::from_slice(&bytes)
        .map_err(|_| format!("OID4VP JWKS {} is not JSON", path.display()))?;
    let keys = keys_from_jwk_set(&jwks)
        .map_err(|_| format!("OID4VP JWKS {} has invalid keys", path.display()))?;
    if keys.is_empty() {
        return Err(format!("OID4VP JWKS {} has no usable keys", path.display()));
    }
    Ok(keys)
}
