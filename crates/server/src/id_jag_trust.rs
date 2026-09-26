//! Operator-pinned ID-JAG trust, loaded before serving token requests.
//!
//! A token's unverified `iss` may select a row here, but only that row's local
//! keys may verify it. Neither `jku`, `x5u`, nor a JWKS URL in the token can
//! expand the trust set. Loading a missing or malformed pin fails startup.
//! This store does not enable redemption: the replay, subject and consent
//! transaction must exist before a JWT-bearer grant handler is registered.

use crate::config::TenantConfig;
use asterius_jose::{
    ClientKeySet,
    id_jag::{self, IdJagPolicy, ValidatedIdJag},
    parse_jwk_set,
};
use serde_json::Value;
use std::{collections::HashMap, fs};
use time::OffsetDateTime;

/// One generic refusal for unknown issuers and invalid assertions alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("ID-JAG assertion cannot be redeemed")]
pub struct UntrustedIdJag;

#[derive(Debug, Clone)]
struct Trust {
    config: crate::config::IdJagTrustConfig,
    audience: String,
    keys: ClientKeySet,
}

/// Trusted upstream issuers, partitioned by tenant and downstream client.
#[derive(Debug, Clone, Default)]
pub struct IdJagTrusts(HashMap<String, HashMap<(String, String), Trust>>);

/// A configured authorization choice safe to show an account owner. Signing
/// keys and operator-owned JWKS paths never leave the trust store.
#[derive(Debug, Clone)]
pub struct IdJagConsentOption {
    pub issuer: String,
    pub actor_client_id: String,
    pub client_id: String,
    pub resources: Vec<String>,
    pub scopes: Vec<String>,
}

impl IdJagTrusts {
    /// Whether an operator configured this upstream issuer for at least one
    /// downstream client in the routed tenant.
    #[must_use]
    pub fn supports_issuer(&self, tenant_id: &str, issuer: &str) -> bool {
        self.0
            .get(tenant_id)
            .is_some_and(|trusted| trusted.keys().any(|(configured, _)| configured == issuer))
    }

    /// The tenant's exact operator-pinned choices for the owner consent page.
    #[must_use]
    pub fn consent_options(&self, tenant_id: &str) -> Vec<IdJagConsentOption> {
        let mut options: Vec<_> = self
            .0
            .get(tenant_id)
            .into_iter()
            .flat_map(|trusts| trusts.values())
            .map(|trust| IdJagConsentOption {
                issuer: trust.config.issuer.as_str().to_owned(),
                actor_client_id: trust.config.actor_client_id.clone(),
                client_id: trust.config.client_id.clone(),
                resources: trust.config.resources.iter().cloned().collect(),
                scopes: trust.config.scopes.iter().cloned().collect(),
            })
            .collect();
        options.sort_by(|a, b| (&a.issuer, &a.client_id).cmp(&(&b.issuer, &b.client_id)));
        options
    }

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
    fn policy(
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

    /// Verifies an ID-JAG using only the authenticated client's operator-pinned
    /// issuer keys and actor. An unverified `iss` selects a candidate pin; it
    /// cannot authorize the token or introduce a key source. The request's
    /// DPoP key must already have been proved by the token endpoint.
    ///
    /// # Errors
    /// Returns the same refusal for an unknown pin and every invalid token.
    pub fn verify(
        &self,
        tenant_id: &str,
        client_id: &str,
        dpop_jkt: &str,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<ValidatedIdJag, UntrustedIdJag> {
        if token.is_empty() || token.len() > 8192 || dpop_jkt.is_empty() {
            return Err(UntrustedIdJag);
        }
        let parsed = asterius_jose::jws::parse(token).map_err(|_| UntrustedIdJag)?;
        let header: Value =
            serde_json::from_slice(parsed.raw_header()).map_err(|_| UntrustedIdJag)?;
        if header.as_object().is_some_and(|fields| {
            ["jku", "x5u", "jwk", "x5c"]
                .iter()
                .any(|name| fields.contains_key(*name))
        }) {
            return Err(UntrustedIdJag);
        }
        let claims: Value =
            serde_json::from_slice(parsed.unverified_payload()).map_err(|_| UntrustedIdJag)?;
        let issuer = claims
            .get("iss")
            .and_then(Value::as_str)
            .ok_or(UntrustedIdJag)?;
        let policy = self
            .policy(tenant_id, issuer, client_id, dpop_jkt)
            .ok_or(UntrustedIdJag)?;
        id_jag::validate(token, &policy, now).map_err(|_| UntrustedIdJag)
    }
}
