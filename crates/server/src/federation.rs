//! Tenant-scoped OpenID Federation leaf Entity Configurations.
//!
//! A signed self-statement does not establish trust in a remote entity. The
//! tenant-pinned resolver in [`trust`] verifies remote RP paths separately.

pub mod trust;

use asterius_domain::{Issuer, KeyStore, TenantId};
use asterius_jose::jws;
use asterius_store_pg::PgFederationKeys;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::config::TenantConfig;
use crate::outbound::jwks::HttpsClientUrlFetcher;
use trust::FederationTrust;

/// Five minutes, matching the metadata cache boundary.
pub const LIFETIME_SECONDS: i64 = 300;
/// The path appended to each Federation Entity Identifier.
pub const CONFIGURATION_PATH: &str = "/.well-known/openid-federation";

#[derive(Debug)]
struct Entity {
    issuer: Issuer,
    tenant: TenantId,
    keys: PgFederationKeys,
    authority_hints: Vec<String>,
}

/// Configured OP leaves. Absence is a 404, never a partial statement.
#[derive(Debug, Clone, Default)]
pub struct FederationEntities {
    entities: Arc<HashMap<String, Entity>>,
    trust: Option<FederationTrust>,
}

impl FederationEntities {
    /// Loads or imports dedicated Federation signing keys. Key reuse fails boot.
    pub async fn load(
        tenants: &[TenantConfig],
        oidc_keys: &dyn KeyStore,
        fetcher: HttpsClientUrlFetcher,
        federation_keys: PgFederationKeys,
    ) -> Result<Self, String> {
        let mut entities = HashMap::new();
        let mut federation_kids = HashSet::new();
        for tenant in tenants {
            if !tenant.federation_enabled {
                continue;
            }
            let legacy = if federation_keys
                .has_key(&tenant.id)
                .await
                .map_err(|e| e.to_string())?
            {
                None
            } else {
                match tenant.federation_signing_key_file.as_ref() {
                    Some(path) => Some(Zeroizing::new(tokio::fs::read(path).await.map_err(|e| {
                        format!("tenant {} Federation key file cannot be read: {e}", tenant.id)
                    })?)),
                    None => None,
                }
            };
            federation_keys
                .initialize(
                    &tenant.id,
                    legacy.as_deref().map(Vec::as_slice),
                    OffsetDateTime::now_utc(),
                )
                .await
                .map_err(|e| e.to_string())?;
            let snapshot = federation_keys
                .snapshot(&tenant.id)
                .await
                .map_err(|e| e.to_string())?;
            if !federation_kids.insert(snapshot.kid.as_str().to_owned()) {
                return Err(format!(
                    "tenant {} Federation key is reused by another tenant",
                    tenant.id
                ));
            }
            if oidc_keys
                .public_key(&tenant.id, &snapshot.kid)
                .await
                .map_err(|e| e.to_string())?
                .is_some()
            {
                return Err(format!(
                    "tenant {} Federation key also signs OIDC tokens",
                    tenant.id
                ));
            }
            entities.insert(
                tenant.id.as_str().to_owned(),
                Entity {
                    issuer: tenant.issuer.clone(),
                    tenant: tenant.id.clone(),
                    keys: federation_keys.clone(),
                    authority_hints: tenant
                        .federation_authority_hints
                        .iter()
                        .map(|hint| hint.as_str().to_owned())
                        .collect(),
                },
            );
        }
        Ok(Self {
            entities: Arc::new(entities),
            trust: Some(FederationTrust::load(tenants, fetcher)?),
        })
    }

    /// Advance published key rotation states for each enabled tenant.
    pub async fn sweep_keys(&self, now: OffsetDateTime) -> Result<(), String> {
        for entity in self.entities.values() {
            entity
                .keys
                .sweep(&entity.tenant, now)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// The tenant-pinned remote RP resolver, initialized at boot.
    #[must_use]
    pub fn trust(&self) -> Option<&FederationTrust> {
        self.trust.as_ref()
    }

    /// Whether this tenant explicitly opted in at boot.
    #[must_use]
    pub fn contains(&self, tenant: &TenantId) -> bool {
        self.entities.contains_key(tenant.as_str())
    }

    /// Signs one short-lived Entity Configuration using the dedicated key.
    /// The OP metadata is supplied by the same producer as OIDC discovery.
    pub async fn sign(
        &self,
        tenant: &TenantId,
        op_metadata: &Value,
        now: OffsetDateTime,
    ) -> Result<Option<asterius_domain::CompactJws>, String> {
        let Some(entity) = self.entities.get(tenant.as_str()) else {
            return Ok(None);
        };
        if op_metadata.get("issuer").and_then(Value::as_str) != Some(entity.issuer.as_str()) {
            return Err("Federation OP metadata issuer disagrees with tenant issuer".to_owned());
        }
        let snapshot = entity
            .keys
            .snapshot(&entity.tenant)
            .await
            .map_err(|e| e.to_string())?;
        let claims = json!({
            "iss": entity.issuer.as_str(),
            "sub": entity.issuer.as_str(),
            "iat": now.unix_timestamp(),
            "exp": now.unix_timestamp() + LIFETIME_SECONDS,
            "jwks": {"keys": snapshot.jwks},
            "authority_hints": entity.authority_hints,
            "metadata": {"openid_provider": op_metadata},
        });
        jws::sign(
            &snapshot.active,
            &snapshot.kid,
            "entity-statement+jwt",
            &claims,
        )
        .map(Some)
        .map_err(|error| error.to_string())
    }
}
