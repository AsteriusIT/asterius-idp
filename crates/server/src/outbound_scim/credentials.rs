//! Operator-owned client keys, bound to the complete source and target context.

use asterius_domain::outbound_scim::{
    CredentialBinding, OutboundScimCredentials, canonical_issuer,
};
use asterius_domain::{DomainError, Kid, Secret, SigningAlgorithm};
use asterius_jose::{SigningKey, jws};
use std::{path::PathBuf, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Configuration owns the path; API callers can name only its scoped reference.
#[derive(Clone)]
pub struct OperatorCredential {
    pub binding: CredentialBinding,
    pub key_file: PathBuf,
    pub kid: Kid,
    pub algorithm: SigningAlgorithm,
}
impl std::fmt::Debug for OperatorCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperatorCredential")
            .field("generation", &self.binding.generation)
            .finish_non_exhaustive()
    }
}

struct LoadedCredential {
    binding: CredentialBinding,
    key: Arc<SigningKey>,
    kid: Kid,
}

pub struct ScopedCredentialRegistry {
    entries: Vec<LoadedCredential>,
}
impl std::fmt::Debug for ScopedCredentialRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScopedCredentialRegistry")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

fn refused() -> DomainError {
    DomainError::invalid(
        "outbound_scim_credentials",
        "invalid operator credential registry",
    )
}

impl ScopedCredentialRegistry {
    /// Load only fixed operator paths at composition time, never from a command
    /// body. DER PKCS#8 files remain private; no bytes or path enter SQL/logs.
    pub fn load(entries: Vec<OperatorCredential>) -> Result<Self, DomainError> {
        if entries.len() > 100 {
            return Err(refused());
        }
        let mut loaded = Vec::<LoadedCredential>::with_capacity(entries.len());
        for entry in entries {
            let issuer = canonical_issuer(&entry.binding.target_issuer)?;
            if entry.binding.target_admin_resource
                != format!("{}/admin/api/v1", entry.binding.target_issuer)
                || entry.binding.scim_origin != issuer.origin().ascii_serialization()
                || entry.binding.reference.is_empty()
                || !entry
                    .binding
                    .reference
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || entry.binding.target_client.as_str().is_empty()
                || entry.binding.reference.len() > 64
                || !entry
                    .binding
                    .reference
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                || !entry.key_file.is_absolute()
                || loaded
                    .iter()
                    .any(|existing| existing.binding == entry.binding)
            {
                return Err(refused());
            }
            let metadata = std::fs::metadata(&entry.key_file).map_err(|_| refused())?;
            if !metadata.is_file() || metadata.len() > 16 * 1024 {
                return Err(refused());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(refused());
                }
            }
            let bytes = Zeroizing::new(std::fs::read(&entry.key_file).map_err(|_| refused())?);
            if bytes.len() > 16 * 1024 {
                return Err(refused());
            }
            let key = SigningKey::from_pkcs8(entry.algorithm, &bytes).map_err(|_| refused())?;
            loaded.push(LoadedCredential {
                binding: entry.binding,
                key: Arc::new(key),
                kid: entry.kid,
            });
        }
        Ok(Self { entries: loaded })
    }

    /// Catalogue configuration can select a deployment reference only through
    /// every context pin. Knowing another tenant's identifier proves nothing.
    #[must_use]
    pub fn contains(&self, binding: &CredentialBinding) -> bool {
        self.entries.iter().any(|entry| entry.binding == *binding)
    }
}

#[async_trait::async_trait]
impl OutboundScimCredentials for ScopedCredentialRegistry {
    async fn assertion(&self, binding: &CredentialBinding) -> Result<Secret<String>, DomainError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.binding == *binding)
            .ok_or_else(|| DomainError::Conflict("credential_binding_mismatch".into()))?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = serde_json::json!({"iss":binding.target_client.as_str(),"sub":binding.target_client.as_str(),"aud":binding.target_issuer,"iat":now,"exp":now+60,"jti":Uuid::new_v4().to_string()});
        let assertion = jws::sign(&entry.key, &entry.kid, "JWT", &claims)
            .map_err(|_| DomainError::Conflict("credential_unavailable".into()))?;
        Ok(Secret::new(assertion.as_str().to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{ClientId, TenantId};

    fn binding() -> CredentialBinding {
        CredentialBinding {
            reference: "owned".into(),
            generation: Uuid::from_u128(1),
            source_tenant: TenantId::new("source"),
            target_admin_resource: "https://target.example/t/destination/admin/api/v1".into(),
            scim_origin: "https://target.example".into(),
            target_issuer: "https://target.example/t/destination".into(),
            target_client: ClientId::new("c.destination"),
        }
    }
    fn registry() -> ScopedCredentialRegistry {
        ScopedCredentialRegistry {
            entries: vec![LoadedCredential {
                binding: binding(),
                key: Arc::new(SigningKey::generate(SigningAlgorithm::Es256).expect("key")),
                kid: Kid::new("owned"),
            }],
        }
    }
    #[tokio::test]
    async fn reference_knowledge_never_crosses_source_or_target_context() {
        let registry = registry();
        let original = binding();
        let mut foreign = original.clone();
        foreign.source_tenant = TenantId::new("foreign");
        assert!(registry.assertion(&foreign).await.is_err());
        let mut foreign = original.clone();
        foreign.target_admin_resource.push_str("/foreign");
        assert!(registry.assertion(&foreign).await.is_err());
        let mut foreign = original.clone();
        foreign.target_client = ClientId::new("c.foreign");
        assert!(registry.assertion(&foreign).await.is_err());
        let mut foreign = original.clone();
        foreign.scim_origin = "https://foreign.example".into();
        assert!(registry.assertion(&foreign).await.is_err());
        let mut foreign = original.clone();
        foreign.generation = Uuid::from_u128(2);
        assert!(registry.assertion(&foreign).await.is_err());
        let mut foreign = original.clone();
        foreign.target_issuer = "https://target.example/t/foreign".into();
        assert!(registry.assertion(&foreign).await.is_err());
        assert!(registry.assertion(&original).await.is_ok());
    }
    #[tokio::test]
    async fn each_assertion_has_fresh_jti_and_a_fixed_short_issuer_audience() {
        let registry = registry();
        let binding = binding();
        let first = registry.assertion(&binding).await.expect("assertion");
        let second = registry.assertion(&binding).await.expect("assertion");
        assert_ne!(first.expose(), second.expose());
        let verified = jws::parse(first.expose())
            .expect("JWS")
            .verify(&registry.entries[0].key.verifying_key().expect("public key"))
            .expect("signature");
        let claims: serde_json::Value = serde_json::from_slice(&verified).expect("claims");
        assert_eq!(claims["aud"], binding.target_issuer);
        assert_eq!(
            claims["exp"].as_i64().expect("exp") - claims["iat"].as_i64().expect("iat"),
            60
        );
        assert_eq!(claims["iss"], binding.target_client.as_str());
        assert!(!format!("{registry:?}").contains("target.example"));
    }
}

impl asterius_domain::outbound_scim::OutboundScimCredentialCatalogue for ScopedCredentialRegistry {
    fn available(&self, binding: &CredentialBinding) -> bool {
        self.contains(binding)
    }
    fn descriptors(
        &self,
        tenant: &asterius_domain::TenantId,
    ) -> Vec<asterius_domain::outbound_scim::CredentialDescriptor> {
        self.entries
            .iter()
            .filter(|entry| entry.binding.source_tenant == *tenant)
            .map(
                |entry| asterius_domain::outbound_scim::CredentialDescriptor {
                    reference: entry.binding.reference.clone(),
                    generation: entry.binding.generation,
                    target_issuer: entry.binding.target_issuer.clone(),
                    target_client: entry.binding.target_client.as_str().to_owned(),
                },
            )
            .collect()
    }
}
