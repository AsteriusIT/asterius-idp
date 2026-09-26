//! Operator-pinned ID-JAG trust, loaded before serving token requests.
//!
//! A token's unverified `iss` may select a row here, but only that row's local
//! keys may verify it. Neither `jku`, `x5u`, nor a JWKS URL in the token can
//! expand the trust set. Loading a missing or malformed pin fails startup.
//! This store does not enable redemption: the replay, subject and consent
//! transaction must exist before a JWT-bearer grant handler is registered.

use crate::config::TenantConfig;
use asterius_jose::{ClientKeySet, id_jag::IdJagPolicy, parse_jwk_set};
use std::{collections::HashMap, fs};

#[derive(Debug, Clone)]
struct Trust {
    config: crate::config::IdJagTrustConfig,
    audience: String,
    keys: ClientKeySet,
}

/// Trusted upstream issuers, partitioned by tenant and downstream client.
#[derive(Debug, Clone, Default)]
pub struct IdJagTrusts(HashMap<String, HashMap<(String, String), Trust>>);

impl IdJagTrusts {
    /// Loads each operator-owned JWKS file with a strict size bound.
    ///
    /// # Errors
    /// An unreadable, malformed or keyless file prevents startup.
    pub fn load(tenants: &[TenantConfig]) -> Result<Self, String> {
        const MAX_JWKS_BYTES: u64 = 65_536;
        let mut by_tenant = HashMap::new();
        for tenant in tenants {
            let mut trusted = HashMap::new();
            for config in &tenant.id_jag_trusts {
                let file = &config.jwks_file;
                let metadata = fs::metadata(file)
                    .map_err(|_| format!("cannot read ID-JAG JWKS {}", file.display()))?;
                if metadata.len() > MAX_JWKS_BYTES {
                    return Err(format!("ID-JAG JWKS {} exceeds 64 KiB", file.display()));
                }
                let bytes = fs::read(file)
                    .map_err(|_| format!("cannot read ID-JAG JWKS {}", file.display()))?;
                let keys = parse_jwk_set(&bytes)
                    .map_err(|_| format!("ID-JAG JWKS {} has invalid keys", file.display()))?;
                if keys.is_empty() {
                    return Err(format!("ID-JAG JWKS {} has no usable keys", file.display()));
                }
                trusted.insert(
                    (config.issuer.as_str().to_owned(), config.client_id.clone()),
                    Trust {
                        config: config.clone(),
                        audience: tenant.issuer.as_str().to_owned(),
                        keys,
                    },
                );
            }
            by_tenant.insert(tenant.id.as_str().to_owned(), trusted);
        }
        Ok(Self(by_tenant))
    }

    /// Builds a preflight policy from a configured issuer/client pair and a
    /// DPoP key already proved at this request's token endpoint.
    #[must_use]
    pub fn policy(
        &self,
        tenant_id: &str,
        issuer: &str,
        client_id: &str,
        dpop_jkt: &str,
    ) -> Option<IdJagPolicy> {
        let trust = self
            .0
            .get(tenant_id)?
            .get(&(issuer.to_owned(), client_id.to_owned()))?;
        Some(IdJagPolicy {
            issuer: trust.config.issuer.as_str().to_owned(),
            audience: trust.audience.clone(),
            client_id: trust.config.client_id.clone(),
            actor_client_id: trust.config.actor_client_id.clone(),
            dpop_jkt: dpop_jkt.to_owned(),
            resources: trust.config.resources.clone(),
            scopes: trust.config.scopes.clone(),
            issuer_keys: trust.keys.clone(),
        })
    }
}
