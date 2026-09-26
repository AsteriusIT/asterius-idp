//! Tenant policy for one `OpenID4VCI` credential configuration.

use serde_json::{Value, json};
use std::collections::BTreeSet;

/// The only claim schema currently backed by this server's user store.
pub const IDENTITY_CREDENTIAL_TYPE: &str = "AsteriusIdentityCredential";

/// An explicit, bounded configuration. Absence in tenant settings disables
/// issuance; an upgrade cannot quietly expose identity claims to wallets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialConfiguration {
    id: String,
    scope: String,
    credential_type: String,
    claims: BTreeSet<String>,
}

/// Why a tenant's credential configuration cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigurationError {
    /// A configuration identifier must be a short URL-safe name.
    #[error("credential configuration id must be a short URL-safe name")]
    InvalidId,
    /// The OAuth scope must be a single token that the AS can authorize.
    #[error("credential scope must be a single visible ASCII token")]
    InvalidScope,
    /// This issuer cannot substantiate an arbitrary scheme or attestation.
    #[error("only AsteriusIdentityCredential is supported")]
    InvalidCredentialType,
    /// A claim outside the identity profile has no approved release semantics.
    #[error("unsupported credential claim")]
    InvalidClaim,
    /// The stored policy has the wrong shape or is missing a required field.
    #[error("credential issuance policy is malformed")]
    Malformed,
}

impl CredentialConfiguration {
    /// Validates names before they can appear in metadata or offers.
    ///
    /// # Errors
    ///
    /// Invalid identifiers, OAuth scopes, or VC types are refused.
    pub fn new(
        id: impl Into<String>,
        scope: impl Into<String>,
        credential_type: impl Into<String>,
    ) -> Result<Self, ConfigurationError> {
        let id = id.into();
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(ConfigurationError::InvalidId);
        }
        let scope = scope.into();
        if scope.is_empty()
            || scope.len() > 128
            || scope
                .bytes()
                .any(|byte| !(0x21..=0x7e).contains(&byte) || matches!(byte, b'"' | b'\\'))
        {
            return Err(ConfigurationError::InvalidScope);
        }
        let credential_type = credential_type.into();
        if credential_type != IDENTITY_CREDENTIAL_TYPE {
            return Err(ConfigurationError::InvalidCredentialType);
        }
        Ok(Self {
            id,
            scope,
            credential_type,
            claims: BTreeSet::new(),
        })
    }

    /// Opts in to current, truthful profile fields. An empty set releases only
    /// the grant's subject; `email` is issued only when the address is verified.
    ///
    /// # Errors
    /// Unknown fields are refused rather than silently omitted.
    pub fn with_claims(mut self, claims: BTreeSet<String>) -> Result<Self, ConfigurationError> {
        if claims.iter().any(|claim| claim != "email") {
            return Err(ConfigurationError::InvalidClaim);
        }
        self.claims = claims;
        Ok(self)
    }

    /// Reads a stored policy, refusing extra fields so unsupported choices do
    /// not appear to be accepted when a newer server wrote the row.
    ///
    /// # Errors
    ///
    /// Malformed documents and invalid names are refused.
    pub fn from_json(value: &Value) -> Result<Self, ConfigurationError> {
        let object = value.as_object().ok_or(ConfigurationError::Malformed)?;
        if !matches!(object.len(), 3 | 4)
            || object
                .keys()
                .any(|key| !matches!(key.as_str(), "id" | "scope" | "credential_type" | "claims"))
        {
            return Err(ConfigurationError::Malformed);
        }
        let field = |name| {
            object
                .get(name)
                .and_then(Value::as_str)
                .ok_or(ConfigurationError::Malformed)
        };
        let claims = match object.get("claims") {
            None => BTreeSet::new(),
            Some(Value::Array(values)) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(ConfigurationError::Malformed)
                })
                .collect::<Result<BTreeSet<_>, _>>()?,
            Some(_) => return Err(ConfigurationError::Malformed),
        };
        Self::new(field("id")?, field("scope")?, field("credential_type")?)?.with_claims(claims)
    }

    /// The stable JSON representation in tenant settings.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({"id": self.id, "scope": self.scope, "credential_type": self.credential_type, "claims": self.claims})
    }

    /// The identifier used in Credential Offers and Requests.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The exact OAuth scope authorizing this configuration.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The VC `type` value in addition to `VerifiableCredential`.
    #[must_use]
    pub fn credential_type(&self) -> &str {
        &self.credential_type
    }

    /// Approved profile fields, never inferred from the configuration name.
    #[must_use]
    pub const fn claims(&self) -> &BTreeSet<String> {
        &self.claims
    }
}
