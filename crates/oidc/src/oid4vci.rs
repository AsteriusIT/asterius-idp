//! OpenID4VCI 1.0 issuer metadata and offer values.
//!
//! This module only builds protocol documents from an explicit configuration.
//! A caller must publish them only after the matching authorization, nonce,
//! proof, and credential endpoints are operational for the same tenant.

use asterius_domain::{CredentialConfiguration, Issuer};
use serde::Deserialize;
use serde_json::{Value, json};

/// The well-known suffix inserted before an issuer's tenant path.
pub const WELL_KNOWN: &str = "/.well-known/openid-credential-issuer";
/// The selected credential format from OpenID4VCI 1.0 Appendix A.1.1.
pub const FORMAT: &str = "jwt_vc_json";
/// A JWT proof with an embedded public JWK, per Appendix F.1.
pub const PROOF_ALGORITHM: &str = "ES256";
/// The supported credential issuer signature algorithm.
pub const CREDENTIAL_ALGORITHM: &str = "EdDSA";

/// The canonical metadata URL for a tenant issuer.
///
/// OpenID4VCI §12.2.2 inserts the well-known segment between the authority
/// and the issuer path, unlike the path-appended OIDC discovery alias.
#[must_use]
pub fn metadata_url(issuer: &Issuer) -> String {
    format!(
        "https://{}{}{}",
        issuer.authority(),
        WELL_KNOWN,
        issuer.path()
    )
}

/// Renders only the features that the credential service must implement.
///
/// `nonce_endpoint` is advertised because this policy requires one-time key
/// proof challenges. The service must not serve this document until the
/// corresponding endpoints and OAuth scope gate are live.
#[must_use]
pub fn issuer_metadata(issuer: &Issuer, configuration: &CredentialConfiguration) -> Value {
    json!({
        "credential_issuer": issuer.as_str(),
        "authorization_servers": [issuer.as_str()],
        "credential_endpoint": format!("{issuer}/credential"),
        "nonce_endpoint": format!("{issuer}/nonce"),
        "credential_configurations_supported": {
            configuration.id(): {
                "format": FORMAT,
                "scope": configuration.scope(),
                "credential_signing_alg_values_supported": [CREDENTIAL_ALGORITHM],
                "cryptographic_binding_methods_supported": ["jwk"],
                "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": [PROOF_ALGORITHM]}
                },
                "credential_definition": {
                    "type": ["VerifiableCredential", configuration.credential_type()]
                }
            }
        }
    })
}

/// A direct authorization-code offer for one configured credential.
///
/// This contains no grant code or subject data. The wallet must still obtain
/// authorization from the tenant AS and prove possession of its key.
#[must_use]
pub fn authorization_code_offer(issuer: &Issuer, configuration: &CredentialConfiguration) -> Value {
    json!({
        "credential_issuer": issuer.as_str(),
        "credential_configuration_ids": [configuration.id()],
        "grants": {"authorization_code": {}}
    })
}

/// One credential instance and one JWT wallet proof. Unknown request members
/// are ignored as OpenID4VCI §8.2 requires; the selected fields stay bounded.
#[derive(Debug, Deserialize)]
pub struct CredentialRequest {
    pub credential_configuration_id: String,
    pub proofs: JwtProofs,
}

/// The supported proof envelope from OpenID4VCI §8.2.
#[derive(Debug, Deserialize)]
pub struct JwtProofs {
    pub jwt: Vec<String>,
}

/// Why a credential request cannot be processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialRequestError {
    /// Invalid or unsupported request members.
    #[error("invalid credential request")]
    Invalid,
    /// The request names a different tenant configuration.
    #[error("unsupported credential configuration")]
    UnsupportedConfiguration,
}

impl CredentialRequest {
    /// Parses the one-instance request without accepting unimplemented options.
    ///
    /// # Errors
    ///
    /// Oversized, malformed, batch, or unsupported configurations are refused.
    pub fn parse(
        body: &[u8],
        configuration: &CredentialConfiguration,
    ) -> Result<Self, CredentialRequestError> {
        if body.len() > 16 * 1024 {
            return Err(CredentialRequestError::Invalid);
        }
        let request: Self =
            serde_json::from_slice(body).map_err(|_| CredentialRequestError::Invalid)?;
        if request.credential_configuration_id != configuration.id() {
            return Err(CredentialRequestError::UnsupportedConfiguration);
        }
        if request.proofs.jwt.len() != 1
            || request.proofs.jwt[0].is_empty()
            || request.proofs.jwt[0].len() > 8192
        {
            return Err(CredentialRequestError::Invalid);
        }
        Ok(request)
    }

    /// The single compact JWT proof to validate against a consumed nonce.
    #[must_use]
    pub fn proof(&self) -> &str {
        &self.proofs.jwt[0]
    }
}
