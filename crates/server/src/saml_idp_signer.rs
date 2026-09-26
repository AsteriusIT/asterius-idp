//! Internal tenant SAML IdP signing-key boundary.
//!
//! Provisioning validates that the X.509 certificate contains the public half
//! of the imported RSA key. Issuance opens the same KEK-wrapped row, checks
//! the pair again, and binds the signed assertion to a validated request.
//! This module does not route browsers or decide whether a user is logged in.

use asterius_domain::{DomainError, Tenant};
use asterius_jose::Kek;
use asterius_store_pg::Store;
use aws_lc_rs::signature::{
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaKeyPair, UnparsedPublicKey,
};
use std::sync::Arc;

use crate::saml::{Assertion, build_post_response};
use crate::saml_validation::ValidatedAuthnRequest;

/// Confirms an RSA-SHA256 signature made by the imported private key verifies
/// with exactly the certificate's RSA public key. No certificate chain is
/// trusted here: the operator is the provisioning authority.
pub(crate) fn validate_key_pair(
    certificate_der: &[u8],
    private_key_pkcs8: &[u8],
) -> Result<(), DomainError> {
    let invalid = || DomainError::invalid("saml.idp_key", "invalid SAML IdP certificate or key");
    let (remaining, certificate) =
        x509_parser::parse_x509_certificate(certificate_der).map_err(|_| invalid())?;
    if !remaining.is_empty()
        || !certificate.validity().is_valid()
        || certificate
            .key_usage()
            .map_err(|_| invalid())?
            .is_some_and(|usage| !usage.value.digital_signature())
        || !matches!(
            certificate.public_key().parsed(),
            Ok(x509_parser::public_key::PublicKey::RSA(_))
        )
    {
        return Err(invalid());
    }
    let key = RsaKeyPair::from_pkcs8(private_key_pkcs8).map_err(|_| invalid())?;
    if !(256..=1024).contains(&key.public_modulus_len()) {
        return Err(invalid());
    }
    const CHALLENGE: &[u8] = b"asterius SAML IdP certificate and key match v1";
    let mut signature = vec![0_u8; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &aws_lc_rs::rand::SystemRandom::new(),
        CHALLENGE,
        &mut signature,
    )
    .map_err(|_| invalid())?;
    UnparsedPublicKey::new(
        &RSA_PKCS1_2048_8192_SHA256,
        certificate.public_key().subject_public_key.data.as_ref(),
    )
    .verify(CHALLENGE, &signature)
    .map_err(|_| invalid())
}

/// Signs with this tenant's stable, provisioned SAML IdP key only.
#[derive(Debug, Clone)]
pub struct SamlIdpSigner {
    store: Store,
    kek: Arc<dyn Kek>,
}

impl SamlIdpSigner {
    #[must_use]
    pub const fn new(store: Store, kek: Arc<dyn Kek>) -> Self {
        Self { store, kek }
    }

    /// The authenticated account/session decision belongs to the caller. This
    /// method requires the assertion to match the exact tenant, SP and request
    /// previously accepted by `SamlRequestValidator` before it loads a key.
    pub async fn build_response(
        &self,
        tenant: &Tenant,
        request: &ValidatedAuthnRequest,
        response_id: &str,
        assertion: &Assertion<'_>,
    ) -> Result<String, DomainError> {
        if request.tenant_id() != tenant.id.as_str()
            || assertion.issuer != tenant.issuer.as_str()
            || assertion.audience != request.sp_entity_id()
            || assertion.recipient != request.acs_url()
            || assertion.in_response_to != request.request_id()
        {
            return Err(DomainError::invalid(
                "saml.response",
                "request and assertion differ",
            ));
        }
        let material = self
            .store
            .scope(tenant.id.clone())
            .saml_idp_keys(Arc::clone(&self.kek))
            .load_for_signing()
            .await?
            .ok_or_else(|| {
                DomainError::invalid("saml.idp_key", "no SAML IdP key is provisioned")
            })?;
        validate_key_pair(&material.certificate_der, &material.private_key_pkcs8)?;
        build_post_response(response_id, assertion, &material.private_key_pkcs8)
            .map_err(|_| DomainError::invalid("saml.response", "cannot sign SAML response"))
    }
}
