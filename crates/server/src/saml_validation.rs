//! Internal SAML AuthnRequest validation boundary.
//!
//! This service does not route a browser request or issue a response. The
//! bounded XML parser deliberately rejects XML Signature elements. HTTP-
//! Redirect query and POST XML signatures are verified using a tenant-scoped
//! pinned SP key before replay reservation. Raw unsigned XML passes only
//! when the SP explicitly opts in; the default persisted policy refuses it.

use asterius_domain::{DomainError, Tenant};
use asterius_store_pg::{PgSamlTrust, SamlSp, Store};
use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use time::{Duration, OffsetDateTime};

use crate::saml::{UntrustedAuthnRequest, parse_authn_request};
use crate::saml_post::parse_post_form;
use crate::saml_redirect::parse_redirect_query;
use crate::saml_xmlsig::parse_signed_post;

/// Refusal is uniform so XML, trust and replay distinctions cannot become a
/// browser-facing oracle when this service is eventually wired to a route.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("SAML request cannot be accepted")]
    Refused,
    #[error("SAML request store is unavailable")]
    Store(#[source] DomainError),
}

/// A request accepted under one routed tenant and one exact SP trust row.
/// Its construction is private to the validator. It is not a login or an
/// authorization to issue an assertion.
#[derive(Debug, Clone)]
pub struct ValidatedAuthnRequest {
    tenant_id: String,
    sp_entity_id: String,
    acs_url: String,
    request_id: String,
    issued_at: OffsetDateTime,
    relay_state: Option<Vec<u8>>,
}

impl ValidatedAuthnRequest {
    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    #[must_use]
    pub fn sp_entity_id(&self) -> &str {
        &self.sp_entity_id
    }
    #[must_use]
    pub fn acs_url(&self) -> &str {
        &self.acs_url
    }
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    #[must_use]
    pub const fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }
    #[must_use]
    pub fn relay_state(&self) -> Option<&[u8]> {
        self.relay_state.as_deref()
    }
}

/// A service over the same store the admin trust routes write.
#[derive(Debug, Clone)]
pub struct SamlRequestValidator {
    store: Store,
}

impl SamlRequestValidator {
    #[must_use]
    pub const fn new(store: Store) -> Self {
        Self { store }
    }

    /// Validates a bounded XML request in the tenant selected by routing,
    /// then reserves its ID atomically. All comparisons are byte-for-byte:
    /// URL parsing or normalization cannot turn a supplied destination or ACS
    /// into a different operator-approved endpoint.
    ///
    /// The destination is the canonical future SSO endpoint derived from the
    /// routed tenant's issuer. No browser route currently serves it.
    pub async fn validate_unsigned(
        &self,
        tenant: &Tenant,
        xml: &[u8],
        now: OffsetDateTime,
    ) -> Result<ValidatedAuthnRequest, ValidationError> {
        let request = parse_authn_request(xml).map_err(|_| ValidationError::Refused)?;
        let (trust, sp) = self.check_routed(tenant, &request, now).await?;
        if !sp.allow_unsigned_requests {
            return Err(ValidationError::Refused);
        }
        let reserved = trust
            .reserve_unsigned_request(&sp.entity_id, &sp.acs_url, &request.id)
            .await
            .map_err(ValidationError::Store)?;
        if !reserved {
            return Err(ValidationError::Refused);
        }
        Ok(Self::accepted(tenant, sp, request, None))
    }

    /// Decodes and verifies a signed HTTP-Redirect query against the exact
    /// RSA-SHA256 key pinned for the parsed issuer in the routed tenant.
    /// Signed query octets include the original encoded RelayState when
    /// present. A key in XML, a URL, or another tenant is never consulted.
    pub async fn validate_redirect(
        &self,
        tenant: &Tenant,
        raw_query: &str,
        now: OffsetDateTime,
    ) -> Result<ValidatedAuthnRequest, ValidationError> {
        let redirect = parse_redirect_query(raw_query).map_err(|_| ValidationError::Refused)?;
        let request = parse_authn_request(&redirect.xml).map_err(|_| ValidationError::Refused)?;
        let (trust, sp) = self.check_routed(tenant, &request, now).await?;
        let key = sp
            .redirect_signing_public_key_der
            .as_deref()
            .ok_or(ValidationError::Refused)?;
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key)
            .verify(&redirect.signing_input, &redirect.signature)
            .map_err(|_| ValidationError::Refused)?;
        let reserved = trust
            .reserve_signed_request(&sp.entity_id, &sp.acs_url, key, &request.id)
            .await
            .map_err(ValidationError::Store)?;
        if !reserved {
            return Err(ValidationError::Refused);
        }
        Ok(Self::accepted(tenant, sp, request, redirect.relay_state))
    }

    /// Validates the strict HTTP-POST binding profile with an enveloped
    /// XML Signature over the exact AuthnRequest root. The parsed issuer
    /// selects only a candidate SP within the routed tenant; the request is
    /// accepted only after its digest and RSA signature verify against that
    /// SP's operator-pinned key and its ID is atomically reserved.
    /// No browser route currently calls this method.
    pub async fn validate_post(
        &self,
        tenant: &Tenant,
        content_type: &str,
        body: &[u8],
        now: OffsetDateTime,
    ) -> Result<ValidatedAuthnRequest, ValidationError> {
        let form = parse_post_form(content_type, body).map_err(|_| ValidationError::Refused)?;
        let signed = parse_signed_post(&form.xml).map_err(|_| ValidationError::Refused)?;
        let (trust, sp) = self
            .check_routed(tenant, signed.unverified_request(), now)
            .await?;
        let key = sp
            .redirect_signing_public_key_der
            .as_deref()
            .ok_or(ValidationError::Refused)?;
        let request = signed.verify(key).map_err(|_| ValidationError::Refused)?;
        let reserved = trust
            .reserve_signed_request(&sp.entity_id, &sp.acs_url, key, &request.id)
            .await
            .map_err(ValidationError::Store)?;
        if !reserved {
            return Err(ValidationError::Refused);
        }
        Ok(Self::accepted(tenant, sp, request, form.relay_state))
    }

    async fn check_routed(
        &self,
        tenant: &Tenant,
        request: &UntrustedAuthnRequest,
        now: OffsetDateTime,
    ) -> Result<(PgSamlTrust, SamlSp), ValidationError> {
        let destination = format!("{}/saml/sso", tenant.issuer.as_str().trim_end_matches('/'));
        if request.destination.as_deref() != Some(destination.as_str())
            || request.issued_at > now + Duration::seconds(60)
            || now - request.issued_at > Duration::minutes(5)
        {
            return Err(ValidationError::Refused);
        }

        let trust = self.store.scope(tenant.id.clone()).saml_trust();
        let sp = trust
            .find(&request.issuer)
            .await
            .map_err(ValidationError::Store)?
            .ok_or(ValidationError::Refused)?;
        if request.acs.as_deref().is_some_and(|acs| acs != sp.acs_url)
            || request
                .binding
                .as_deref()
                .is_some_and(|binding| binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
        {
            return Err(ValidationError::Refused);
        }

        Ok((trust, sp))
    }

    fn accepted(
        tenant: &Tenant,
        sp: SamlSp,
        request: UntrustedAuthnRequest,
        relay_state: Option<Vec<u8>>,
    ) -> ValidatedAuthnRequest {
        ValidatedAuthnRequest {
            tenant_id: tenant.id.as_str().to_owned(),
            sp_entity_id: sp.entity_id,
            acs_url: sp.acs_url,
            request_id: request.id,
            issued_at: request.issued_at,
            relay_state,
        }
    }
}
