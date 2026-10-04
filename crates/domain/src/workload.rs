//! Operator-pinned workload trust, distinct from browser identity providers.
use crate::{Actor, ClientId, DomainError, Issuer, ResourceIdentifier, TenantId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;

pub const MAX_TRUSTS: usize = 64;
pub const MAX_ASSERTION_BYTES: usize = 8192;
pub const MAX_CLAIMS_BYTES: usize = 4096;
pub const MAX_JWKS_BYTES: usize = 65536;
pub const MAX_KEYS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Algorithm {
    RS256,
    PS256,
    ES256,
    EdDSA,
}
impl Algorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::PS256 => "PS256",
            Self::ES256 => "ES256",
            Self::EdDSA => "EdDSA",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Kubernetes,
    Github,
    Spiffe,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Keys {
    Inline {
        jwks: Value,
    },
    Remote {
        uri: String,
    },
    SpiffeBundle {
        trust_domain: String,
        bundle: String,
    },
}
impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Inline { .. } => "Inline(public keys withheld)",
            Self::Remote { .. } => "Remote(pinned location withheld)",
            Self::SpiffeBundle { .. } => "SpiffeBundle(public authorities withheld)",
        })
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub provider: Provider,
    pub principal: String,
    pub clients: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
    pub resources: BTreeSet<String>,
    pub actions: BTreeSet<String>,
    pub required_claims: BTreeMap<String, String>,
    pub algorithms: BTreeSet<Algorithm>,
    pub keys: Keys,
    #[serde(default)]
    pub enabled: bool,
}
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadConfig")
            .field("provider", &self.provider)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct Trust {
    pub tenant: TenantId,
    pub id: String,
    pub version: i64,
    pub config: Config,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub id: String,
    pub version: i64,
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub provider: Provider,
    pub principal: String,
    pub clients: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
    pub resources: BTreeSet<String>,
    pub actions: BTreeSet<String>,
    pub required_claims: BTreeMap<String, String>,
    pub algorithms: BTreeSet<Algorithm>,
    pub enabled: bool,
    pub key_source: String,
    pub fingerprints: Vec<String>,
}

#[must_use]
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && id.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || (i > 0 && (b == b'-' || b == b'_'))
        })
}
fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn invalid() -> DomainError {
    DomainError::invalid("workload_trust", "invalid workload trust configuration")
}
impl Config {
    // fuzz-target: workload_token
    pub fn validate(&self, tenant: &TenantId, id: &str) -> Result<(), DomainError> {
        if !valid_id(id)
            || !text(&self.issuer, 1024)
            || Issuer::parse(&self.issuer).map_or(true, |issuer| issuer.as_str() != self.issuer)
            || self.audience != format!("urn:asterius:workload:{}:{id}", tenant.as_str())
            || !text(
                &self.subject,
                if self.provider == Provider::Spiffe {
                    2048
                } else {
                    1024
                },
            )
            || !self
                .principal
                .strip_prefix("workload:")
                .is_some_and(valid_id)
            || self.clients.is_empty()
            || self.clients.len() > 16
            || self.clients.iter().any(|v| !text(v, 512))
            || self.scopes.len() > 64
            || self.scopes.iter().any(|v| {
                !text(v, 128)
                    || v.bytes()
                        .any(|b| !(0x21..=0x7e).contains(&b) || b == b'"' || b == b'\\')
                    || v == "openid"
                    || v == "offline_access"
            })
            || self.resources.is_empty()
            || self.resources.len() > 16
            || self
                .resources
                .iter()
                .any(|v| ResourceIdentifier::parse(v).is_err())
            || self.actions.len() > 64
            || self.actions.iter().any(|v| !text(v, 128))
            || self.algorithms.is_empty()
            || self.required_claims.len() > 32
            || self
                .required_claims
                .iter()
                .any(|(k, v)| !k.starts_with('/') || !text(k, 128) || !text(v, 1024))
        {
            return Err(invalid());
        }
        self.validate_provider()?;
        match &self.keys {
            Keys::Inline { jwks } => {
                if serde_json::to_vec(jwks).map_or(true, |bytes| {
                    bytes.is_empty() || bytes.len() > MAX_JWKS_BYTES
                }) {
                    return Err(invalid());
                }
            }
            Keys::Remote { uri } => {
                let url = url::Url::parse(uri).map_err(|_| invalid())?;
                if uri.len() > 2048
                    || url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                {
                    return Err(invalid());
                }
            }
            Keys::SpiffeBundle {
                trust_domain,
                bundle,
            } => {
                if self.provider != Provider::Spiffe
                    || spiffe_domain(&self.subject) != Some(trust_domain.as_str())
                    || bundle.is_empty()
                    || bundle.len() > MAX_JWKS_BYTES
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
    fn validate_provider(&self) -> Result<(), DomainError> {
        let required: &[&str] = match self.provider {
            Provider::Kubernetes => &[
                "/kubernetes.io/namespace",
                "/kubernetes.io/serviceaccount/name",
                "/kubernetes.io/serviceaccount/uid",
            ],
            Provider::Github => &[
                "/repository_id",
                "/repository_owner_id",
                "/environment",
                "/ref",
                "/event_name",
                "/workflow_ref",
                "/workflow_sha",
            ],
            Provider::Spiffe => &[],
        };
        if required
            .iter()
            .any(|key| !self.required_claims.contains_key(*key))
        {
            return Err(invalid());
        }
        match self.provider {
            Provider::Kubernetes => {
                if self.subject
                    != format!(
                        "system:serviceaccount:{}:{}",
                        self.required_claims["/kubernetes.io/namespace"],
                        self.required_claims["/kubernetes.io/serviceaccount/name"]
                    )
                {
                    return Err(invalid());
                }
            }
            Provider::Github => {
                if ["/repository_id", "/repository_owner_id"]
                    .iter()
                    .any(|key| {
                        !self.required_claims[*key]
                            .bytes()
                            .all(|b| b.is_ascii_digit())
                    })
                    || matches!(
                        self.required_claims["/event_name"].as_str(),
                        "pull_request" | "pull_request_target"
                    )
                    || self.required_claims.contains_key("/job_workflow_ref")
                        != self.required_claims.contains_key("/job_workflow_sha")
                {
                    return Err(invalid());
                }
            }
            Provider::Spiffe => {
                if !matches!(self.keys, Keys::SpiffeBundle { .. })
                    || !self.issuer.starts_with("https://")
                    || self.algorithms.contains(&Algorithm::EdDSA)
                    || !self.required_claims.is_empty()
                    || spiffe_domain(&self.subject).is_none()
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
    #[must_use]
    pub fn summary(&self, id: &str, version: i64, fingerprints: Vec<String>) -> Summary {
        Summary {
            id: id.to_owned(),
            version,
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            subject: self.subject.clone(),
            provider: self.provider,
            principal: self.principal.clone(),
            clients: self.clients.clone(),
            scopes: self.scopes.clone(),
            resources: self.resources.clone(),
            actions: self.actions.clone(),
            required_claims: self.required_claims.clone(),
            algorithms: self.algorithms.clone(),
            enabled: self.enabled,
            key_source: match self.keys {
                Keys::Inline { .. } => "inline",
                Keys::Remote { .. } => "remote",
                Keys::SpiffeBundle { .. } => "spiffe_bundle",
            }
            .to_owned(),
            fingerprints,
        }
    }
}

/// The approved profile compares a canonical identity without URL normalization.
// fuzz-target: workload_token
#[must_use]
pub fn spiffe_domain(id: &str) -> Option<&str> {
    if id.len() > 2048 || !id.is_ascii() {
        return None;
    }
    let (domain, path) = id.strip_prefix("spiffe://")?.split_once('/')?;
    if domain.is_empty()
        || domain.len() > 255
        || !domain.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
        || path.split('/').any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || !segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
    {
        return None;
    }
    Some(domain)
}

#[derive(Debug, Clone)]
pub struct Verified {
    pub client: ClientId,
    pub provider: Provider,
    pub tenant: TenantId,
    pub trust_id: String,
    pub trust_version: i64,
    pub principal: String,
    pub source_subject: String,
    pub trust_domain: Option<String>,
    pub expires_at: OffsetDateTime,
    pub digest: [u8; 32],
    pub scopes: BTreeSet<String>,
    pub resources: BTreeSet<String>,
    pub actions: BTreeSet<String>,
}

#[async_trait::async_trait]
pub trait Registry: std::fmt::Debug + Send + Sync {
    async fn candidates(&self, tenant: &TenantId, issuer: &str) -> Result<Vec<Trust>, DomainError>;
    async fn list(&self, tenant: &TenantId) -> Result<Vec<Summary>, DomainError>;
    async fn find(&self, tenant: &TenantId, id: &str) -> Result<Option<Summary>, DomainError>;
    async fn put(
        &self,
        tenant: &TenantId,
        id: &str,
        config: &Config,
        expected: Option<i64>,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<Summary, DomainError>;
    async fn delete(
        &self,
        tenant: &TenantId,
        id: &str,
        expected: i64,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;
}

#[async_trait::async_trait]
pub trait Verifier: std::fmt::Debug + Send + Sync {
    async fn verify(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<Verified, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        serde_json::from_value(serde_json::json!({"issuer":"https://cluster.example","audience":"urn:asterius:workload:acme:inventory","subject":"system:serviceaccount:apps:inventory","provider":"kubernetes","principal":"workload:inventory","clients":["client-one"],"scopes":["inventory:read"],"resources":["https://api.example/"],"actions":["read"],"required_claims":{"/kubernetes.io/namespace":"apps","/kubernetes.io/serviceaccount/name":"inventory","/kubernetes.io/serviceaccount/uid":"sa-uid"},"algorithms":["EdDSA"],"keys":{"kind":"inline","jwks":{"keys":[]}},"enabled":true})).expect("config")
    }

    #[test]
    fn exact_tenant_trust_mapping_and_default_disabled_are_required() {
        let mut config = config();
        assert!(config.validate(&TenantId::new("acme"), "inventory").is_ok());
        assert!(
            config
                .validate(&TenantId::new("other"), "inventory")
                .is_err()
        );
        config.subject = "system:serviceaccount:other:inventory".to_owned();
        assert!(
            config
                .validate(&TenantId::new("acme"), "inventory")
                .is_err()
        );
        let mut value = serde_json::to_value(super::tests::config()).expect("config");
        value.as_object_mut().expect("object").remove("enabled");
        let config: Config = serde_json::from_value(value).expect("defaults");
        assert!(!config.enabled);
    }
    #[test]
    fn secret_material_is_absent_from_summary_and_debug() {
        let config = config();
        let summary =
            serde_json::to_value(config.summary("inventory", 1, vec![])).expect("summary");
        assert!(summary.get("keys").is_none());
        assert!(summary.get("jwks").is_none());
        assert!(!format!("{config:?}").contains("jwks"));
    }
    #[test]
    fn github_trust_requires_stable_ids_and_rejects_pull_requests() {
        let mut config = config();
        config.provider = Provider::Github;
        config.subject = "repo:org/repo:environment:prod".to_owned();
        config.required_claims = [
            ("/repository_id", "123"),
            ("/repository_owner_id", "456"),
            ("/environment", "prod"),
            ("/ref", "refs/heads/main"),
            ("/event_name", "push"),
            (
                "/workflow_ref",
                "org/repo/.github/workflows/deploy.yml@refs/heads/main",
            ),
            ("/workflow_sha", "sha"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        assert!(config.validate(&TenantId::new("acme"), "inventory").is_ok());
        config
            .required_claims
            .insert("/event_name".to_owned(), "pull_request_target".to_owned());
        assert!(
            config
                .validate(&TenantId::new("acme"), "inventory")
                .is_err()
        );
    }
}

/// Exact action/location ceilings for the registered RFC 9396 workload dialect.
// fuzz-target: workload_token
pub fn validate_actions(
    details: &[Value],
    allowed: &BTreeSet<String>,
    targets: &BTreeSet<String>,
) -> Result<(), DomainError> {
    if details.len() > 16 {
        return Err(invalid());
    }
    for element in details {
        let object = element.as_object().ok_or_else(invalid)?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "type" | "actions" | "locations"))
            || object.get("type").and_then(Value::as_str) != Some("urn:asterius:workload-actions")
        {
            return Err(invalid());
        }
        let actions = object
            .get("actions")
            .and_then(Value::as_array)
            .filter(|actions| !actions.is_empty() && actions.len() <= 64)
            .ok_or_else(invalid)?;
        if actions.iter().any(|action| {
            !action
                .as_str()
                .is_some_and(|action| allowed.contains(action))
        }) {
            return Err(invalid());
        }
        let locations = object
            .get("locations")
            .and_then(Value::as_array)
            .filter(|locations| locations.len() == 1)
            .ok_or_else(invalid)?;
        if locations.iter().any(|location| {
            !location
                .as_str()
                .is_some_and(|location| targets.contains(location))
        }) {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod action_tests {
    use super::*;
    #[test]
    fn workload_actions_never_widen_or_escape_the_resource() {
        let allowed = BTreeSet::from(["read".to_owned()]);
        let targets = BTreeSet::from(["https://api.example/".to_owned()]);
        let element = serde_json::json!({"type":"urn:asterius:workload-actions","actions":["read"],"locations":["https://api.example/"]});
        assert!(validate_actions(std::slice::from_ref(&element), &allowed, &targets).is_ok());
        for (field, value) in [
            ("actions", serde_json::json!(["write"])),
            ("locations", serde_json::json!(["https://other.example/"])),
            ("type", serde_json::json!("other")),
            ("extra", serde_json::json!(true)),
        ] {
            let mut bad = element.clone();
            bad[field] = value;
            assert!(validate_actions(&[bad], &allowed, &targets).is_err());
        }
        assert!(validate_actions(&[], &allowed, &targets).is_ok());
    }
}

#[cfg(test)]
mod spiffe_tests {
    use super::*;

    #[test]
    fn spiffe_identity_is_canonical_and_bounded() {
        assert_eq!(
            spiffe_domain("spiffe://example.test/ns/Workload_1"),
            Some("example.test")
        );
        for id in [
            "SPIFFE://example.test/a",
            "spiffe://EXAMPLE.test/a",
            "spiffe://example.test",
            "spiffe://example.test/",
            "spiffe://example.test/a/",
            "spiffe://example.test/a//b",
            "spiffe://example.test/../b",
            "spiffe://example.test/%61",
            "spiffe://example.test/a?b",
            "spiffe://user@example.test/a",
            "spiffe://example.test:443/a",
            "spiffe://example.test/é",
        ] {
            assert!(spiffe_domain(id).is_none(), "{id}");
        }
        let max = format!("spiffe://example.test/{}", "a".repeat(2026));
        assert_eq!(max.len(), 2048);
        assert!(spiffe_domain(&max).is_some());
        assert!(spiffe_domain(&(max + "a")).is_none());
    }

    #[test]
    fn spiffe_trust_requires_its_own_domain_bundle_and_algorithms() {
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "issuer":"https://spire.example.test", "audience":"urn:asterius:workload:acme:inventory",
            "subject":"spiffe://example.test/inventory", "provider":"spiffe", "principal":"workload:inventory",
            "clients":["client-one"], "scopes":["inventory:read"], "resources":["https://api.example/"],
            "actions":["read"], "required_claims":{}, "algorithms":["ES256"],
            "keys":{"kind":"spiffe_bundle","trust_domain":"example.test","bundle":"{\"keys\":[]}"}
        })).expect("config");
        let tenant = TenantId::new("acme");
        assert!(config.validate(&tenant, "inventory").is_ok());
        config.algorithms.insert(Algorithm::EdDSA);
        assert!(config.validate(&tenant, "inventory").is_err());
        config.algorithms.remove(&Algorithm::EdDSA);
        config.subject = "spiffe://other.test/inventory".to_owned();
        assert!(config.validate(&tenant, "inventory").is_err());
        config.subject = "spiffe://example.test/inventory".to_owned();
        config.keys = Keys::Inline {
            jwks: serde_json::json!({"keys":[]}),
        };
        assert!(config.validate(&tenant, "inventory").is_err());
    }
}
