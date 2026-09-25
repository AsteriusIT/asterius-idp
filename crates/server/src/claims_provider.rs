//! Operator-pinned Claims Provider trust and consent-bound aggregate delivery.
//!
//! A signed UserInfo JWT is indivisible: filtering its decoded JSON would
//! invalidate the signature, while shipping it intact would disclose every
//! attribute it contains. A source is therefore eligible only when all of its
//! attributes were requested in the same delivery location and none collides
//! with a direct claim or another source.

use crate::config::{ClaimsProviderConfig, TenantConfig};
use asterius_domain::{DomainError, Tenant};
use asterius_jose::{
    ClientKeySet,
    claims_aggregation::{ClaimsProviderPolicy, verify_signed_userinfo},
    keys_from_jwk_set,
};
use asterius_oidc::claims::ClaimsRequest;
use asterius_store_pg::StoredClaimSource;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};
use time::OffsetDateTime;

/// The destination the RP requested from this OP.
#[derive(Debug, Clone, Copy)]
pub enum Destination {
    IdToken,
    UserInfo,
}

#[derive(Debug, Clone)]
struct Provider {
    issuer: String,
    keys: ClientKeySet,
    allowed_claims: BTreeSet<String>,
}

/// Trusted CPs loaded once from each tenant's operator-owned files.
#[derive(Debug, Clone, Default)]
pub struct ClaimsProviders(HashMap<String, HashMap<String, Provider>>);

impl ClaimsProviders {
    /// Loads pinned JWKS; a missing, malformed or keyless file stops startup.
    ///
    /// # Errors
    /// Returns a path-scoped configuration error without disclosing keys.
    pub fn load(tenants: &[TenantConfig]) -> Result<Self, String> {
        let mut by_tenant = HashMap::new();
        for tenant in tenants {
            let mut providers = HashMap::new();
            for entry in &tenant.claims_providers {
                providers.insert(entry.issuer.as_str().to_owned(), load_provider(entry)?);
            }
            by_tenant.insert(tenant.id.as_str().to_owned(), providers);
        }
        Ok(Self(by_tenant))
    }

    /// Whether this tenant has any approved CPs.
    #[must_use]
    pub fn enabled(&self, tenant_id: &str) -> bool {
        self.0
            .get(tenant_id)
            .is_some_and(|providers| !providers.is_empty())
    }

    /// Compose OIDC Core §5.6.2's aggregated response members from live rows.
    /// Every selected JWT is verified again with operator-pinned keys, and
    /// *every* claim it contains must fit the consented request. A row for a
    /// provider no longer configured, or with excess claims, is omitted.
    ///
    /// # Errors
    /// Refuses corrupted eligible rows and conflicting source names.
    pub fn deliver(
        &self,
        tenant: &Tenant,
        request: &ClaimsRequest,
        destination: Destination,
        direct: &Map<String, Value>,
        rows: &[StoredClaimSource],
        now: OffsetDateTime,
    ) -> Result<Map<String, Value>, DomainError> {
        if rows.len() > 4 {
            return Err(DomainError::invalid(
                "claims_aggregation",
                "too many providers",
            ));
        }
        let requested: BTreeSet<String> = match destination {
            Destination::IdToken => request.id_token(),
            Destination::UserInfo => request.userinfo(),
        }
        .keys()
        .map(|claim| claim.as_str().to_owned())
        .collect();
        let mut names = Map::new();
        let mut sources = Map::new();
        for row in rows {
            let Some(provider) = self
                .0
                .get(tenant.id.as_str())
                .and_then(|providers| providers.get(&row.provider_issuer))
            else {
                continue;
            };
            let stored: BTreeSet<String> = row.claim_names.iter().cloned().collect();
            if stored.is_empty()
                || stored.len() != row.claim_names.len()
                || !stored.is_subset(&requested)
                || !stored.is_subset(&provider.allowed_claims)
            {
                continue;
            }
            // No name may have two asserted values in one response. A direct
            // claim takes precedence and never turns into a CP claim by mere
            // presence of a connected provider.
            if stored
                .iter()
                .any(|name| direct.contains_key(name) || names.contains_key(name))
            {
                continue;
            }
            let policy = ClaimsProviderPolicy {
                issuer: provider.issuer.clone(),
                keys: provider.keys.clone(),
                op_issuer: tenant.issuer.as_str().to_owned(),
                provider_subject: row.provider_subject.clone(),
                approved_claims: stored.clone(),
            };
            let verified = verify_signed_userinfo(&row.signed_userinfo, &policy, now)
                .map_err(|error| DomainError::invalid("claims_aggregation", error.to_string()))?;
            if verified.names() != &stored || verified.expires_at() != row.expires_at {
                return Err(DomainError::invalid(
                    "claims_aggregation",
                    "stored source differs from signed JWT",
                ));
            }
            let source_id = format!("src{}", sources.len() + 1);
            for name in &stored {
                names.insert(name.clone(), json!(source_id));
            }
            sources.insert(source_id, json!({"JWT": row.signed_userinfo}));
        }
        if names.is_empty() {
            return Ok(Map::new());
        }
        Ok(Map::from_iter([
            ("_claim_names".to_owned(), Value::Object(names)),
            ("_claim_sources".to_owned(), Value::Object(sources)),
        ]))
    }
}

fn load_provider(entry: &ClaimsProviderConfig) -> Result<Provider, String> {
    const MAX_JWKS_BYTES: u64 = 65_536;
    let path: &Path = &entry.jwks_file;
    let metadata = std::fs::metadata(path).map_err(|error| {
        format!(
            "cannot read Claims Provider JWKS {}: {error}",
            path.display()
        )
    })?;
    if metadata.len() > MAX_JWKS_BYTES {
        return Err(format!(
            "Claims Provider JWKS {} exceeds 64 KiB",
            path.display()
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "cannot read Claims Provider JWKS {}: {error}",
            path.display()
        )
    })?;
    let jwks = serde_json::from_slice(&bytes)
        .map_err(|_| format!("Claims Provider JWKS {} is not JSON", path.display()))?;
    let keys = keys_from_jwk_set(&jwks)
        .map_err(|_| format!("Claims Provider JWKS {} has invalid keys", path.display()))?;
    if keys.is_empty() {
        return Err(format!(
            "Claims Provider JWKS {} has no usable keys",
            path.display()
        ));
    }
    Ok(Provider {
        issuer: entry.issuer.as_str().to_owned(),
        keys,
        allowed_claims: entry.allowed_claims.clone(),
    })
}
