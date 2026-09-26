//! One-use SAML login continuation, bound to the first-party interaction.
//!
//! The `AuthnRequest` was fully verified and replay-reserved before `begin`.
//! Resume is permitted only after that exact interaction is consumed into the
//! presented session, while the SP trust still names the same ACS and key.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId};
use sqlx::{PgPool, Row as _};
use time::OffsetDateTime;

/// Values accepted by the request validator, never browser input at resume.
#[derive(Debug)]
pub struct NewPendingSamlLogin<'a> {
    pub token_digest: &'a str,
    pub interaction_digest: &'a str,
    pub sp_entity_id: &'a str,
    pub acs_url: &'a str,
    pub request_id: &'a str,
    pub issued_at: OffsetDateTime,
    pub relay_state: Option<&'a [u8]>,
    pub signing_key_der: Option<&'a [u8]>,
    pub expires_at: OffsetDateTime,
}

/// Result of an atomic one-use consume after the interaction established the
/// exact browser session presented at resume.
#[derive(Debug)]
pub struct ConsumedPendingSamlLogin {
    pub sp_entity_id: String,
    pub acs_url: String,
    pub request_id: String,
    pub issued_at: OffsetDateTime,
    pub relay_state: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct PgSamlPending {
    pool: PgPool,
    tenant: TenantId,
}

impl PgSamlPending {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Stores only the already-validated request, bound to one login journey.
    pub async fn begin(&self, pending: &NewPendingSamlLogin<'_>) -> Result<(), DomainError> {
        let interaction = hex::decode(pending.interaction_digest)
            .map_err(|_| DomainError::invalid("saml.interaction", "invalid digest"))?;
        if interaction.len() != 32 || pending.token_digest.len() != 64 {
            return Err(DomainError::invalid("saml.interaction", "invalid digest"));
        }
        sqlx::query(
            "insert into saml_pending_logins
                 (tenant_id, token_digest, interaction_id_hash, sp_entity_id, acs_url,
                  request_id, issued_at, relay_state, signing_key_der, expires_at)
             values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(self.tenant.as_str())
        .bind(pending.token_digest)
        .bind(interaction)
        .bind(pending.sp_entity_id)
        .bind(pending.acs_url)
        .bind(pending.request_id)
        .bind(pending.issued_at)
        .bind(pending.relay_state)
        .bind(pending.signing_key_der)
        .bind(pending.expires_at)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    /// Consumes only when the completed login produced `session_digest` and
    /// SP trust still pins exactly the same recipient and signature policy.
    pub async fn consume(
        &self,
        token_digest: &str,
        session_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<ConsumedPendingSamlLogin>, DomainError> {
        let row = sqlx::query(
            "update saml_pending_logins p set consumed_at = $4
               from first_party_interactions i, saml_sp_trusts sp
              where p.tenant_id = $1 and p.token_digest = $2
                and p.consumed_at is null and p.expires_at > $4
                and i.tenant_id = p.tenant_id
                and i.interaction_id_hash = p.interaction_id_hash
                and i.destination = 'saml_sso'
                and i.consumed_at is not null and i.expires_at > $4
                and i.session_id = $3
                and sp.tenant_id = p.tenant_id
                and sp.entity_id = p.sp_entity_id
                and sp.acs_url = p.acs_url
                and ((p.signing_key_der is not null
                      and sp.redirect_signing_public_key_der = p.signing_key_der)
                     or (p.signing_key_der is null
                         and sp.allow_unsigned_requests = true))
            returning p.sp_entity_id, p.acs_url, p.request_id,
                      p.issued_at, p.relay_state",
        )
        .bind(self.tenant.as_str())
        .bind(token_digest)
        .bind(session_digest)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(|row| {
            Ok(ConsumedPendingSamlLogin {
                sp_entity_id: row.try_get("sp_entity_id").map_err(to_domain_error)?,
                acs_url: row.try_get("acs_url").map_err(to_domain_error)?,
                request_id: row.try_get("request_id").map_err(to_domain_error)?,
                issued_at: row.try_get("issued_at").map_err(to_domain_error)?,
                relay_state: row.try_get("relay_state").map_err(to_domain_error)?,
            })
        })
        .transpose()
    }
}
