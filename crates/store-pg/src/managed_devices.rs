//! Current device evidence read on an already-held policy publication fence.
//! No pool checkout or session lookup is permitted inside the signing fence.
use asterius_domain::managed_devices::{Compliance, DeviceBinding, LeafFingerprint, Posture};
use asterius_domain::policy::conditional::{Availability, Fact, FactValue};
use asterius_domain::{DomainError, Grant, TenantId};
use sqlx::PgConnection;
use time::OffsetDateTime;

use crate::error::to_domain_error;

#[derive(Debug)]
pub struct PgManagedDevices;

#[derive(sqlx::FromRow)]
struct DeviceRow {
    source_generation: i64,
    enrollment_generation: i64,
    user_id: Option<uuid::Uuid>,
    leaf_sha256: Option<Vec<u8>>,
    allowed_client_ids: Option<Vec<String>>,
    removed_at: Option<OffsetDateTime>,
    observed_at: Option<OffsetDateTime>,
    source_expires_at: Option<OffsetDateTime>,
    managed: Option<bool>,
    compliant: Option<bool>,
}

impl PgManagedDevices {
    /// Resolve exact private issuance evidence on the caller's existing fence.
    /// The caller must hold the tenant publication fence until the final signature
    /// and recheck `Fact::at` after awaited cryptographic/audit operations.
    ///
    /// # Errors
    /// Returns a storage error instead of inventing an available device fact.
    pub async fn resolve_for_grant_on(
        connection: &mut PgConnection,
        tenant: &TenantId,
        grant: &Grant,
        binding: Option<&DeviceBinding>,
        current_anchor: Option<&LeafFingerprint>,
    ) -> Result<Fact, DomainError> {
        let Some(binding) = binding else {
            return Ok(missing(Availability::Absent));
        };
        let Some(anchor) = current_anchor else {
            return Ok(missing(Availability::Unavailable));
        };
        if grant.tenant != *tenant || binding.tenant() != tenant
            || binding.client() != &grant.client || grant.user.as_ref() != Some(binding.user())
            || anchor.as_str() != binding.anchor_sha256()
        {
            return Ok(missing(Availability::Invalid));
        }
        if !source_current_on(connection, tenant, binding).await? {
            return Ok(missing(Availability::Invalid));
        }
        let account: Option<bool> = sqlx::query_scalar(
            "select status='active' from users where tenant_id=$1 and user_id=$2 for share"
        ).bind(tenant.as_str()).bind(binding.user().as_uuid()).fetch_optional(&mut *connection)
            .await.map_err(to_domain_error)?;
        let application: Option<bool> = sqlx::query_scalar(
            "select status='active' from clients where tenant_id=$1 and client_id=$2 for share"
        ).bind(tenant.as_str()).bind(binding.client().as_str()).fetch_optional(&mut *connection)
            .await.map_err(to_domain_error)?;
        if account != Some(true) || application != Some(true) {
            return Ok(missing(Availability::Invalid));
        }
        let row: Option<DeviceRow> = sqlx::query_as(
            "select source_generation, enrollment_generation, user_id, leaf_sha256, \
             allowed_client_ids, removed_at, observed_at, source_expires_at, managed, compliant \
             from managed_devices where tenant_id=$1 and source_id=$2 and device_id=$3 for share"
        ).bind(tenant.as_str()).bind(binding.source()).bind(binding.device())
            .fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
        // Lock waits cannot turn the caller's earlier clock into fresh authority.
        let now: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *connection).await.map_err(to_domain_error)?;
        Ok(resolve_row(row.as_ref(), binding, now))
    }
}

async fn source_current_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    binding: &DeviceBinding,
) -> Result<bool, DomainError> {
    let relay: Option<String> = sqlx::query_scalar(
        "select client_id from managed_device_sources where tenant_id=$1 and source_id=$2"
    ).bind(tenant.as_str()).bind(binding.source()).fetch_optional(&mut *connection)
        .await.map_err(to_domain_error)?;
    let Some(relay) = relay else { return Ok(false); };
    let active: Option<bool> = sqlx::query_scalar(
        "select status='active' and not is_agent and client_type='confidential' \
         and grant_types=ARRAY['client_credentials']::text[] and dpop_bound_access_tokens \
         and token_endpoint_auth_method in ('private_key_jwt','tls_client_auth','self_signed_tls_client_auth') \
         from clients where tenant_id=$1 and client_id=$2 for share"
    ).bind(tenant.as_str()).bind(&relay).fetch_optional(&mut *connection)
        .await.map_err(to_domain_error)?;
    if active != Some(true) { return Ok(false); }
    let current: Option<bool> = sqlx::query_scalar(
        "select enabled and generation=$3 and client_id=$4 from managed_device_sources \
         where tenant_id=$1 and source_id=$2 for share"
    ).bind(tenant.as_str()).bind(binding.source()).bind(binding.source_generation()).bind(&relay)
        .fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
    Ok(current == Some(true))
}

fn missing(availability: Availability) -> Fact {
    Fact::missing(availability, "managed-device-relay/v1")
}

fn resolve_row(row: Option<&DeviceRow>, binding: &DeviceBinding, now: OffsetDateTime) -> Fact {
    let Some(row) = row else { return missing(Availability::Invalid); };
    if row.removed_at.is_some() || row.source_generation != binding.source_generation()
        || row.enrollment_generation != binding.enrollment_generation()
        || row.user_id.as_ref() != Some(binding.user().as_uuid())
        || row.leaf_sha256.as_ref().is_none_or(|leaf| hex::encode(leaf) != binding.leaf_sha256())
        || row.allowed_client_ids.as_ref().is_none_or(|clients| !clients.iter().any(|client| client == binding.client().as_str()))
    {
        return missing(Availability::Invalid);
    }
    if binding.proof_expires_at() <= now || binding.certificate_expires_at() <= now {
        return missing(Availability::Stale);
    }
    if binding.validate(now).is_err() { return missing(Availability::Invalid); }
    let (Some(observed), Some(source_expiry)) = (row.observed_at, row.source_expires_at) else {
        return missing(Availability::Absent);
    };
    if observed > now { return missing(Availability::Invalid); }
    let Some(freshness) = observed.checked_add(asterius_domain::managed_devices::MAX_FACT_AGE) else {
        return missing(Availability::Invalid);
    };
    let expiry = freshness.min(source_expiry).min(binding.certificate_expires_at()).min(binding.proof_expires_at());
    if expiry <= now { return missing(Availability::Stale); }
    let posture = Posture { managed: row.managed, compliant: row.compliant, disk_encrypted: None, risk: None };
    let value = match posture.compliance() {
        Compliance::Compliant => "compliant",
        Compliance::NonCompliant => "non_compliant",
        Compliance::Unknown => return missing(Availability::Unavailable),
    };
    Fact::known(FactValue::Text(value.to_owned()), "managed-device-relay/v1", observed, expiry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::managed_devices::{MAX_FACT_AGE, VerifiedDeviceEvidence};
    use asterius_domain::{ClientId, UserId};
    use time::Duration;
    use uuid::Uuid;

    fn fixture(now: OffsetDateTime) -> (DeviceBinding, DeviceRow) {
        let user = UserId::generate();
        let proof = DeviceBinding::from_verified(VerifiedDeviceEvidence {
            tenant: TenantId::parse("device-tenant").expect("fixture tenant"),
            user,
            client: ClientId::new("device-app"),
            interaction_digest: "a".repeat(64),
            source: Uuid::new_v4(),
            source_generation: 7,
            device: Uuid::new_v4(),
            enrollment_generation: 9,
            leaf_sha256: "b".repeat(64),
            anchor_sha256: "c".repeat(64),
            certificate_expires_at: now + Duration::hours(1),
            proof_expires_at: now + MAX_FACT_AGE,
        }, now).expect("verified fixture");
        let row = DeviceRow {
            source_generation: 7,
            enrollment_generation: 9,
            user_id: Some(*user.as_uuid()),
            leaf_sha256: Some(hex::decode("b".repeat(64)).expect("fixture leaf")),
            allowed_client_ids: Some(vec!["device-app".to_owned()]),
            removed_at: None,
            observed_at: Some(now),
            source_expires_at: Some(now + Duration::hours(1)),
            managed: Some(true),
            compliant: Some(true),
        };
        (proof, row)
    }

    #[test]
    fn managed_device_resolution_keeps_original_proof_deadline_after_posture_refresh() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(20000);
        let (proof, mut row) = fixture(now);
        row.observed_at = Some(now + Duration::seconds(299));
        let fact = resolve_row(Some(&row), &proof, now + Duration::seconds(299));
        assert_eq!(fact.expires_at, Some(now + MAX_FACT_AGE));
        assert_eq!(fact.at(now + MAX_FACT_AGE), Availability::Stale);
        assert_eq!(resolve_row(Some(&row), &proof, now + MAX_FACT_AGE).availability, Availability::Stale);
    }

    #[test]
    fn managed_device_resolution_rejects_future_unknown_and_reenrollment_aba() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(20000);
        let (proof, mut row) = fixture(now);
        assert_eq!(resolve_row(Some(&row), &proof, now).at(now), Availability::Known);
        row.observed_at = Some(now + Duration::seconds(1));
        assert_eq!(resolve_row(Some(&row), &proof, now).availability, Availability::Invalid);
        row.observed_at = Some(now);
        row.managed = None;
        assert_eq!(resolve_row(Some(&row), &proof, now).availability, Availability::Unavailable);
        row.managed = Some(true);
        row.enrollment_generation += 1;
        assert_eq!(resolve_row(Some(&row), &proof, now).availability, Availability::Invalid);
    }
}
