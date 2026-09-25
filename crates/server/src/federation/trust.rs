//! Guarded Federation discovery, pinned roots and expiry-bound chain caching.
//!
//! Unverified Entity Configurations are read only to discover candidate URLs.
//! Every URL crosses the shared SSRF guard, and no metadata is returned until
//! the complete path and intermediate configurations verify against a pinned
//! tenant root. This boundary is intentionally separate from client registration.

use crate::config::TenantConfig;
use crate::outbound::jwks::{FetchError, HttpsClientUrlFetcher};
use asterius_domain::{Issuer, TenantId};
use asterius_jose::federation::{
    ChainError, MAX_ANCHOR_JWKS_BYTES, MAX_CHAIN_STATEMENTS, MAX_STATEMENT_BYTES, TrustAnchor,
    VerifiedChain,
};
use asterius_jose::jws;
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use url::Url;

const MAX_DISCOVERY_FETCHES: usize = 32;
const MAX_HINTS: usize = 8;
const MAX_CACHE_ENTRIES: usize = 256;
const POSITIVE_CACHE_SECONDS: i64 = 300;
const NEGATIVE_CACHE_SECONDS: i64 = 30;
const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(15);

/// A chain cannot be safely resolved. Error text never contains JWT contents.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The tenant has no operator-pinned trust root.
    #[error("no Federation trust anchor is configured for this tenant")]
    NoAnchor,
    /// The offered Entity Identifier or Entity Statement is malformed.
    #[error("invalid Federation discovery data: {0}")]
    Invalid(&'static str),
    /// A guarded HTTPS retrieval failed.
    #[error("Federation statement fetch failed: {0}")]
    Fetch(#[from] FetchError),
    /// A candidate chain failed signature, policy or constraint validation.
    #[error("Federation trust chain failed validation: {0}")]
    Chain(#[from] ChainError),
    /// No path from this leaf reaches a configured root.
    #[error("no valid Federation path to a configured trust anchor")]
    NoTrustedPath,
    /// The bounded discovery budget was exhausted.
    #[error("Federation discovery budget exhausted")]
    Budget,
    /// The total resolution deadline was reached.
    #[error("Federation resolution timed out")]
    TimedOut,
}

#[derive(Debug, Clone)]
struct Configuration {
    raw: String,
    entity_id: String,
    authority_hints: Vec<String>,
    fetch_endpoint: Option<String>,
}

#[derive(Debug)]
struct Candidate {
    current: Configuration,
    statements: Vec<String>,
    intermediates: Vec<String>,
    seen: HashSet<String>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    until: i64,
    chain: Option<VerifiedChain>,
}

/// Resolves remote RP trust only through tenant-pinned roots.
#[derive(Debug, Clone)]
pub struct FederationTrust {
    roots: Arc<HashMap<String, Vec<TrustAnchor>>>,
    fetcher: HttpsClientUrlFetcher,
    cache: Arc<Mutex<HashMap<(String, String), CacheEntry>>>,
}

impl FederationTrust {
    /// Loads local JWK Set files at boot. Malformed or oversized roots fail boot.
    pub fn load(tenants: &[TenantConfig], fetcher: HttpsClientUrlFetcher) -> Result<Self, String> {
        let mut roots = HashMap::new();
        for tenant in tenants {
            let mut tenant_roots = Vec::new();
            for configured in &tenant.federation_trust_anchors {
                let file = std::fs::File::open(&configured.jwks_file).map_err(|error| {
                    format!(
                        "tenant {} Federation trust root cannot be opened: {error}",
                        tenant.id
                    )
                })?;
                let mut bytes = Vec::new();
                file.take((MAX_ANCHOR_JWKS_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|error| {
                        format!(
                            "tenant {} Federation trust root cannot be read: {error}",
                            tenant.id
                        )
                    })?;
                if bytes.len() > MAX_ANCHOR_JWKS_BYTES {
                    return Err(format!(
                        "tenant {} Federation trust root exceeds size limit",
                        tenant.id
                    ));
                }
                let jwks: Value = serde_json::from_slice(&bytes).map_err(|_| {
                    format!("tenant {} Federation trust root is not JSON", tenant.id)
                })?;
                tenant_roots.push(
                    TrustAnchor::new(tenant.id.clone(), configured.entity_id.clone(), &jwks)
                        .map_err(|error| {
                            format!(
                                "tenant {} Federation trust root is invalid: {error}",
                                tenant.id
                            )
                        })?,
                );
            }
            if !tenant_roots.is_empty() {
                roots.insert(tenant.id.as_str().to_owned(), tenant_roots);
            }
        }
        Ok(Self {
            roots: Arc::new(roots),
            fetcher,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Fetches and validates a leaf's path to one pinned root. The returned
    /// metadata can be inspected by a later registration flow, which must
    /// perform its own client-metadata and key checks.
    pub async fn resolve(
        &self,
        tenant: &TenantId,
        entity_id: &str,
        now: OffsetDateTime,
    ) -> Result<VerifiedChain, ResolveError> {
        let entity = Issuer::parse(entity_id).map_err(|_| {
            tracing::warn!(tenant = %tenant, reason = "invalid_entity_id", "Federation trust chain refused");
            ResolveError::Invalid("Entity Identifier")
        })?;
        if entity.as_str() != entity_id {
            tracing::warn!(tenant = %tenant, reason = "noncanonical_entity_id", "Federation trust chain refused");
            return Err(ResolveError::Invalid("noncanonical Entity Identifier"));
        }
        if !self.roots.contains_key(tenant.as_str()) {
            tracing::warn!(tenant = %tenant, reason = "no_anchor", "Federation trust chain refused");
            return Err(ResolveError::NoAnchor);
        }
        let key = (tenant.as_str().to_owned(), entity_id.to_owned());
        if let Ok(cache) = self.cache.lock()
            && let Some(entry) = cache.get(&key)
            && now.unix_timestamp() < entry.until
        {
            if let Some(chain) = &entry.chain {
                tracing::info!(tenant = %tenant, entity = entity_id, anchor = chain.anchor_entity_id(), cache = true, "Federation trust chain accepted");
                return Ok(chain.clone());
            }
            tracing::warn!(tenant = %tenant, entity = entity_id, reason = "cached_refusal", "Federation trust chain refused");
            return Err(ResolveError::NoTrustedPath);
        }

        let outcome = tokio::time::timeout(
            RESOLUTION_TIMEOUT,
            self.resolve_uncached(tenant, entity_id, now),
        )
        .await
        .unwrap_or(Err(ResolveError::TimedOut));
        let until = match &outcome {
            Ok(chain) => (now.unix_timestamp() + POSITIVE_CACHE_SECONDS).min(chain.expires_at()),
            Err(_) => now.unix_timestamp() + NEGATIVE_CACHE_SECONDS,
        };
        if let Ok(mut cache) = self.cache.lock() {
            cache.retain(|_, entry| entry.until > now.unix_timestamp());
            if cache.len() >= MAX_CACHE_ENTRIES
                && let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.until)
                    .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest);
            }
            cache.insert(
                key,
                CacheEntry {
                    until,
                    chain: outcome.as_ref().ok().cloned(),
                },
            );
        }
        match &outcome {
            Ok(chain) => {
                tracing::info!(tenant = %tenant, entity = entity_id, anchor = chain.anchor_entity_id(), "Federation trust chain accepted");
            }
            Err(error) => {
                tracing::warn!(tenant = %tenant, entity = entity_id, reason = %error, "Federation trust chain refused");
            }
        }
        outcome
    }

    async fn resolve_uncached(
        &self,
        tenant: &TenantId,
        entity_id: &str,
        now: OffsetDateTime,
    ) -> Result<VerifiedChain, ResolveError> {
        let roots = self
            .roots
            .get(tenant.as_str())
            .ok_or(ResolveError::NoAnchor)?;
        let leaf = self.fetch_configuration(entity_id).await?;
        let mut queue = VecDeque::from([Candidate {
            current: leaf.clone(),
            statements: vec![leaf.raw],
            intermediates: Vec::new(),
            seen: HashSet::from([entity_id.to_owned()]),
        }]);
        let mut fetches = 1;
        while let Some(path) = queue.pop_front() {
            if path.statements.len() + 2 > MAX_CHAIN_STATEMENTS {
                continue;
            }
            for superior in &path.current.authority_hints {
                if path.seen.contains(superior) {
                    continue;
                }
                if fetches + 2 > MAX_DISCOVERY_FETCHES {
                    return Err(ResolveError::Budget);
                }
                fetches += 2;
                let Ok(config) = self.fetch_configuration(superior).await else {
                    continue;
                };
                let Some(endpoint) = &config.fetch_endpoint else {
                    continue;
                };
                let Ok(statement) = self
                    .fetch_subordinate(endpoint, &path.current.entity_id, superior)
                    .await
                else {
                    continue;
                };
                let mut statements = path.statements.clone();
                statements.push(statement);
                if let Some(anchor) = roots.iter().find(|root| root.entity_id() == superior) {
                    statements.push(config.raw);
                    let refs = statements.iter().map(String::as_str).collect::<Vec<_>>();
                    let intermediates = path
                        .intermediates
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>();
                    if let Ok(chain) =
                        anchor.validate_with_intermediates(tenant, &refs, &intermediates, now)
                    {
                        return Ok(chain);
                    }
                    continue;
                }
                let mut seen = path.seen.clone();
                seen.insert(superior.clone());
                let mut intermediates = path.intermediates.clone();
                intermediates.push(config.raw.clone());
                queue.push_back(Candidate {
                    current: config,
                    statements,
                    intermediates,
                    seen,
                });
            }
        }
        Err(ResolveError::NoTrustedPath)
    }

    async fn fetch_configuration(&self, entity_id: &str) -> Result<Configuration, ResolveError> {
        let url = format!(
            "{}/.well-known/openid-federation",
            entity_id.trim_end_matches('/')
        );
        let raw = self.fetch_statement(&url).await?;
        let claims = unverified_claims(&raw)?;
        if claims.get("iss").and_then(Value::as_str) != Some(entity_id)
            || claims.get("sub").and_then(Value::as_str) != Some(entity_id)
        {
            return Err(ResolveError::Invalid("Entity Configuration identity"));
        }
        let hints = claims
            .get("authority_hints")
            .map(|value| {
                value
                    .as_array()
                    .ok_or(ResolveError::Invalid("authority hints"))
            })
            .transpose()?
            .map(|array| {
                array
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or(ResolveError::Invalid("authority hint"))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        if hints.len() > MAX_HINTS {
            return Err(ResolveError::Budget);
        }
        let mut canonical_hints = Vec::new();
        for hint in hints {
            let parsed =
                Issuer::parse(hint).map_err(|_| ResolveError::Invalid("authority hint"))?;
            if parsed.as_str() != hint {
                return Err(ResolveError::Invalid("noncanonical authority hint"));
            }
            canonical_hints.push(hint.to_owned());
        }
        let fetch_endpoint = claims
            .pointer("/metadata/federation_entity/federation_fetch_endpoint")
            .map(|value| {
                value
                    .as_str()
                    .ok_or(ResolveError::Invalid("federation_fetch_endpoint"))
            })
            .transpose()?
            .map(str::to_owned);
        Ok(Configuration {
            raw,
            entity_id: entity_id.to_owned(),
            authority_hints: canonical_hints,
            fetch_endpoint,
        })
    }

    async fn fetch_subordinate(
        &self,
        endpoint: &str,
        subject: &str,
        issuer: &str,
    ) -> Result<String, ResolveError> {
        let mut url =
            Url::parse(endpoint).map_err(|_| ResolveError::Invalid("federation_fetch_endpoint"))?;
        url.query_pairs_mut().append_pair("sub", subject);
        let raw = self.fetch_statement(url.as_str()).await?;
        let claims = unverified_claims(&raw)?;
        if claims.get("iss").and_then(Value::as_str) != Some(issuer)
            || claims.get("sub").and_then(Value::as_str) != Some(subject)
        {
            return Err(ResolveError::Invalid("Subordinate Statement identity"));
        }
        Ok(raw)
    }

    async fn fetch_statement(&self, url: &str) -> Result<String, ResolveError> {
        let bytes = self.fetcher.fetch_entity_statement(url).await?;
        if bytes.len() > MAX_STATEMENT_BYTES {
            return Err(ResolveError::Invalid("oversized Entity Statement"));
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| ResolveError::Invalid("Entity Statement encoding"))?;
        if text.trim() != text {
            return Err(ResolveError::Invalid("Entity Statement whitespace"));
        }
        Ok(text)
    }
}

/// Parse only enough unverified data to choose guarded discovery requests.
/// Trust is conferred only by `TrustAnchor::validate_with_intermediates`.
fn unverified_claims(raw: &str) -> Result<Value, ResolveError> {
    let token = jws::parse(raw).map_err(|_| ResolveError::Invalid("Entity Statement JWS"))?;
    if token.claimed_typ() != Some("entity-statement+jwt") {
        return Err(ResolveError::Invalid("Entity Statement typ"));
    }
    let claims: Value = serde_json::from_slice(token.unverified_payload())
        .map_err(|_| ResolveError::Invalid("Entity Statement JSON"))?;
    if !claims.is_object() {
        return Err(ResolveError::Invalid("Entity Statement claims"));
    }
    Ok(claims)
}
