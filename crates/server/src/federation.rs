//! Tenant-scoped OpenID Federation leaf Entity Configurations.
//!
//! This is the publishing boundary only. A signed self-statement does not
//! establish trust in a remote entity; chain resolution and metadata policy
//! are separate work under `ast-s36.14.1`.

use asterius_domain::{Issuer, KeyStore, TenantId};
use asterius_jose::{SigningKey, jws, store::thumbprint};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::config::TenantConfig;

/// Five minutes, matching the metadata cache boundary.
pub const LIFETIME_SECONDS: i64 = 300;
/// The path appended to each Federation Entity Identifier.
pub const CONFIGURATION_PATH: &str = "/.well-known/openid-federation";

#[derive(Debug)]
struct Entity {
    issuer: Issuer,
    key: SigningKey,
    kid: asterius_domain::Kid,
    jwk: Value,
    authority_hints: Vec<String>,
}

/// Configured OP leaves. Absence is a 404, never a partial statement.
#[derive(Debug, Clone, Default)]
pub struct FederationEntities {
    entities: Arc<HashMap<String, Entity>>,
}

impl FederationEntities {
    /// Loads each tenant's dedicated PKCS#8 DER key. Boot fails on a missing,
    /// malformed or reused OIDC token-signing key.
    pub async fn load(tenants: &[TenantConfig], oidc_keys: &dyn KeyStore) -> Result<Self, String> {
        let mut entities = HashMap::new();
        let mut federation_kids = HashSet::new();
        for tenant in tenants {
            let Some(path) = &tenant.federation_signing_key_file else {
                continue;
            };
            let bytes = Zeroizing::new(std::fs::read(path).map_err(|error| {
                format!(
                    "tenant {} Federation key file cannot be read: {error}",
                    tenant.id
                )
            })?);
            let key = SigningKey::from_pkcs8(asterius_domain::SigningAlgorithm::EdDsa, &bytes)
                .map_err(|error| {
                    format!("tenant {} Federation key is invalid: {error}", tenant.id)
                })?;
            let mut jwk = key.public_jwk().map_err(|error| error.to_string())?;
            let kid = thumbprint(&jwk).map_err(|error| error.to_string())?;
            if !federation_kids.insert(kid.as_str().to_owned()) {
                return Err(format!(
                    "tenant {} Federation key is reused by another tenant",
                    tenant.id
                ));
            }
            if oidc_keys
                .public_key(&tenant.id, &kid)
                .await
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err(format!(
                    "tenant {} Federation key also signs OIDC tokens",
                    tenant.id
                ));
            }
            jwk["kid"] = json!(kid.as_str());
            jwk["use"] = json!("sig");
            entities.insert(
                tenant.id.as_str().to_owned(),
                Entity {
                    issuer: tenant.issuer.clone(),
                    key,
                    kid,
                    jwk,
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
        })
    }

    /// Whether this tenant explicitly opted in at boot.
    #[must_use]
    pub fn contains(&self, tenant: &TenantId) -> bool {
        self.entities.contains_key(tenant.as_str())
    }

    /// Signs one short-lived Entity Configuration using the dedicated key.
    /// The OP metadata is supplied by the same producer as OIDC discovery.
    pub fn sign(
        &self,
        tenant: &TenantId,
        op_metadata: Value,
        now: OffsetDateTime,
    ) -> Result<Option<asterius_domain::CompactJws>, String> {
        let Some(entity) = self.entities.get(tenant.as_str()) else {
            return Ok(None);
        };
        if op_metadata.get("issuer").and_then(Value::as_str) != Some(entity.issuer.as_str()) {
            return Err("Federation OP metadata issuer disagrees with tenant issuer".to_owned());
        }
        let claims = json!({
            "iss": entity.issuer.as_str(),
            "sub": entity.issuer.as_str(),
            "iat": now.unix_timestamp(),
            "exp": now.unix_timestamp() + LIFETIME_SECONDS,
            "jwks": {"keys": [entity.jwk.clone()]},
            "authority_hints": entity.authority_hints,
            "metadata": {"openid_provider": op_metadata},
        });
        jws::sign(&entity.key, &entity.kid, "entity-statement+jwt", &claims)
            .map(Some)
            .map_err(|error| error.to_string())
    }
}
