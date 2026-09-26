//! `OpenID4VCI` 1.0 issuer metadata and offer values.
//!
//! Documents and claim sets are built from an explicit tenant configuration.
//! The HTTP layer publishes them only where authorization, nonce, proof, and
//! credential endpoints are operational for the same tenant.

use asterius_domain::{CredentialConfiguration, Issuer, User};
use serde::Deserialize;
use serde_json::{Value, json};

/// The well-known suffix inserted before an issuer's tenant path.
pub const WELL_KNOWN: &str = "/.well-known/openid-credential-issuer";
/// The selected credential format from `OpenID4VCI` 1.0 Appendix A.1.1.
pub const FORMAT: &str = "jwt_vc_json";
/// A JWT proof with an embedded public JWK, per Appendix F.1.
pub const PROOF_ALGORITHM: &str = "ES256";
/// The supported credential issuer signature algorithm.
pub const CREDENTIAL_ALGORITHM: &str = "EdDSA";
/// VCDM 1.1 context used by the selected JWT VC JSON representation.
pub const VC_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";

/// Why the current account cannot substantiate its configured claim set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialClaimsError {
    /// The policy opted in to email but the address is absent or unverified.
    #[error("verified email is required by the credential policy")]
    UnverifiedEmail,
    /// The clock value could not be encoded as a VCDM timestamp.
    #[error("credential issuance time cannot be encoded")]
    InvalidTime,
}

/// Builds a short-lived JWT VC JSON payload from the grant's subject and only
/// tenant-approved, current account fields. The caller signs it as `JWT` with
/// an EdDSA issuer key after it has spent the wallet's one-time proof nonce.
///
/// # Errors
/// An approved email claim without a verified current address fails closed.
pub fn credential_claims(
    issuer: &Issuer,
    configuration: &CredentialConfiguration,
    subject: &str,
    user: &User,
    wallet_jwk: &Value,
    now: time::OffsetDateTime,
) -> Result<Value, CredentialClaimsError> {
    let mut credential_subject = serde_json::Map::new();
    if configuration.claims().contains("email") {
        let Some(email) = user.email.as_ref().filter(|_| user.email_verified) else {
            return Err(CredentialClaimsError::UnverifiedEmail);
        };
        credential_subject.insert("email".to_owned(), json!(email));
    }
    let id = format!("{issuer}/credential/{}", uuid::Uuid::new_v4());
    let subject_uri = format!("{issuer}/subjects/{subject}");
    credential_subject.insert("id".to_owned(), json!(subject_uri));
    let expiry = now + time::Duration::hours(1);
    let issued_at = now.unix_timestamp();
    let issuance_date = now
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| CredentialClaimsError::InvalidTime)?;
    let expiration_date = expiry
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| CredentialClaimsError::InvalidTime)?;
    Ok(json!({
        "iss": issuer.as_str(),
        "sub": subject,
        "jti": id,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expiry.unix_timestamp(),
        "cnf": {"jwk": wallet_jwk},
        "vc": {
            "@context": [VC_CONTEXT],
            "id": id,
            "type": ["VerifiableCredential", configuration.credential_type()],
            "issuer": issuer.as_str(),
            "issuanceDate": issuance_date,
            "expirationDate": expiration_date,
            "credentialSubject": credential_subject,
        }
    }))
}

/// The canonical metadata URL for a tenant issuer.
///
/// `OpenID4VCI` §12.2.2 inserts the well-known segment between the authority
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
/// proof challenges. The service serves this only when the corresponding
/// endpoints and OAuth scope gate are live.
#[must_use]
pub fn issuer_metadata(issuer: &Issuer, configuration: &CredentialConfiguration) -> Value {
    let mut claims = vec![json!({"path": ["credentialSubject", "id"], "mandatory": true})];
    if configuration.claims().contains("email") {
        claims.push(json!({"path": ["credentialSubject", "email"], "mandatory": true}));
    }
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
                },
                "credential_metadata": {"claims": claims}
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
/// are ignored as `OpenID4VCI` §8.2 requires; the selected fields stay bounded.
#[derive(Debug, Deserialize)]
pub struct CredentialRequest {
    pub credential_configuration_id: String,
    pub proofs: JwtProofs,
    #[serde(
        default,
        rename = "credential_identifier",
        deserialize_with = "reject_unsupported"
    )]
    _credential_identifier: (),
    #[serde(
        default,
        rename = "credential_response_encryption",
        deserialize_with = "reject_unsupported"
    )]
    _credential_response_encryption: (),
}

fn reject_unsupported<'de, D>(_deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    Err(serde::de::Error::custom(
        "unsupported credential request member",
    ))
}

/// The supported proof envelope from `OpenID4VCI` §8.2.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
