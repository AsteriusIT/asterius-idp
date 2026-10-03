//! Versioned, secret-free management identities and the atomic management port.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{DomainError, TenantId};

/// Resource kinds are deliberately bounded independently of ordinary administration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Tenant,
    Application,
    Resource,
    Group,
    Membership,
    Policy,
}

impl Kind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Application => "application",
            Self::Resource => "resource",
            Self::Group => "group",
            Self::Membership => "membership",
            Self::Policy => "policy",
        }
    }
    #[must_use]
    pub const fn read_scope(self) -> &'static str {
        match self {
            Self::Tenant => "admin.tenants:read",
            Self::Application => "admin.clients:read",
            Self::Resource => "admin.resource_servers:read",
            Self::Group => "admin.groups:read",
            Self::Membership => "admin.memberships:read",
            Self::Policy => "admin.policies:read",
        }
    }
    #[must_use]
    pub const fn write_scope(self) -> &'static str {
        match self {
            Self::Tenant => "admin.tenants:write",
            Self::Application => "admin.clients:write",
            Self::Resource => "admin.resource_servers:write",
            Self::Group => "admin.groups:write",
            Self::Membership => "admin.memberships:write",
            Self::Policy => "admin.policies:write",
        }
    }
}

/// Portable import identity. Display names are never lookup keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub tenant: TenantId,
    pub kind: Kind,
    pub keys: Vec<String>,
}

impl Identity {
    // fuzz-target: declarative_import_id
    pub fn parse(encoded: &str) -> Result<Self, Error> {
        if encoded.len() > 4096 {
            return Err(Error::Invalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::Invalid)?;
        let parts: Vec<String> = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        let [tenant, kind, keys @ ..] = parts.as_slice() else {
            return Err(Error::Invalid);
        };
        let tenant = TenantId::parse(tenant).map_err(|_| Error::Invalid)?;
        let kind: Kind =
            serde_json::from_value(Value::String(kind.clone())).map_err(|_| Error::Invalid)?;
        let identity = Self {
            tenant,
            kind,
            keys: keys.to_vec(),
        };
        identity.validate()?;
        Ok(identity)
    }
    pub fn validate(&self) -> Result<(), Error> {
        let count = if self.kind == Kind::Membership { 2 } else { 1 };
        if self.keys.len() != count
            || self
                .keys
                .iter()
                .any(|key| key.is_empty() || key.len() > 2048 || key.chars().any(char::is_control))
        {
            return Err(Error::Invalid);
        }
        match self.kind {
            Kind::Group | Kind::Membership => {
                for key in &self.keys {
                    let uuid = uuid::Uuid::parse_str(key).map_err(|_| Error::Invalid)?;
                    if uuid.to_string() != *key {
                        return Err(Error::Invalid);
                    }
                }
            }
            Kind::Resource => {
                crate::ResourceIdentifier::parse(&self.keys[0]).map_err(|_| Error::Invalid)?;
            }
            Kind::Policy if self.keys[0] != "policy" => return Err(Error::Invalid),
            Kind::Tenant if self.keys[0] != self.tenant.as_str() => return Err(Error::Invalid),
            _ => {}
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<String, Error> {
        self.validate()?;
        let mut parts = vec![
            self.tenant.as_str().to_owned(),
            self.kind.as_str().to_owned(),
        ];
        parts.extend(self.keys.clone());
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&parts).map_err(|_| Error::Invalid)?))
    }
    /// Unambiguous database key, independent of transport encoding.
    pub fn key(&self) -> Result<String, Error> {
        serde_json::to_string(&self.keys).map_err(|_| Error::Invalid)
    }
}

/// A canonical read, excluding all credential material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub contract_version: u8,
    pub id: String,
    pub kind: Kind,
    pub spec: Value,
    pub revision: String,
    pub owner: Option<String>,
    pub origin: Vec<Value>,
    pub deletion_protection: bool,
}

/// A mutation intent. Expected revisions are always required after creation.
#[derive(Debug, Clone)]
pub enum Mutation {
    Create {
        kind: Kind,
        external_key: String,
        spec: Value,
        deletion_protection: bool,
    },
    Replace {
        identity: Identity,
        expected: String,
        spec: Value,
        deletion_protection: bool,
    },
    Adopt {
        identity: Identity,
        expected: String,
    },
    Release {
        identity: Identity,
        expected: String,
    },
    Delete {
        identity: Identity,
        expected: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid declarative request")]
    Invalid,
    #[error("the resource does not exist")]
    NotFound,
    #[error("the resource revision changed")]
    Revision,
    #[error("the resource has another owner or managed origin")]
    Owner,
    #[error("resource deletion is protected")]
    Protected,
    #[error("resource dependencies prevent deletion")]
    Dependency,
    #[error("the logical creation key conflicts with another intent")]
    LogicalKey,
    #[error("this declarative resource adapter is not implemented")]
    Unsupported,
    #[error("the management store is unavailable")]
    Storage(#[source] DomainError),
}

/// Implementations commit live writes, ownership and logical IDs together.
#[async_trait::async_trait]
pub trait Management: std::fmt::Debug + Send + Sync {
    /// Validates against runtime policy and fills public server defaults without writing.
    async fn normalise(&self, tenant: &TenantId, kind: Kind, spec: &Value) -> Result<Value, Error>;

    async fn read(&self, identity: &Identity) -> Result<Document, Error>;
    async fn resolve(
        &self,
        tenant: &TenantId,
        owner: &str,
        kind: Kind,
        external_key: &str,
    ) -> Result<Document, Error>;
    async fn mutate(
        &self,
        tenant: &TenantId,
        owner: &str,
        mutation: Mutation,
    ) -> Result<Option<Document>, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audience_import_preserves_delimiters() {
        let id = Identity {
            tenant: TenantId::parse("acme").expect("tenant"),
            kind: Kind::Resource,
            keys: vec!["https://api.example/a?x=y".to_owned()],
        };
        assert_eq!(
            Identity::parse(&id.encode().expect("encoding")).expect("parse"),
            id
        );
    }
    #[test]
    fn malformed_and_cross_kind_identifiers_are_rejected() {
        assert!(Identity::parse("not-base64!").is_err());
        let raw = URL_SAFE_NO_PAD.encode(br#"["acme","membership","not-a-uuid"]"#);
        assert!(Identity::parse(&raw).is_err());
    }
}
