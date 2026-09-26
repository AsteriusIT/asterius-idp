//! Internal SAML AuthnRequest validation boundary.
//!
//! This service does not route a browser request or issue a response. The
//! bounded XML parser deliberately rejects XML Signature elements; there is
//! no Redirect-binding signature verifier either. Consequently only an SP
//! explicitly provisioned for unsigned requests can pass this boundary.
//! The default persisted policy refuses every request.

use asterius_domain::{DomainError, Tenant};
use asterius_store_pg::Store;
use time::{Duration, OffsetDateTime};

use crate::saml::parse_authn_request;

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
        if !sp.allow_unsigned_requests
            || request.acs.as_deref().is_some_and(|acs| acs != sp.acs_url)
            || request
                .binding
                .as_deref()
                .is_some_and(|binding| binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
        {
            return Err(ValidationError::Refused);
        }

        let reserved = trust
            .reserve_unsigned_request(&sp.entity_id, &sp.acs_url, &request.id)
            .await
            .map_err(ValidationError::Store)?;
        if !reserved {
            return Err(ValidationError::Refused);
        }
        Ok(ValidatedAuthnRequest {
            tenant_id: tenant.id.as_str().to_owned(),
            sp_entity_id: sp.entity_id,
            acs_url: sp.acs_url,
            request_id: request.id,
            issued_at: request.issued_at,
        })
    }
}
