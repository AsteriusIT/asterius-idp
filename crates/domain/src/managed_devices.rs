//! Candidate managed-device-relay/v1 types. Not wired into a deployment while
//! normative review of managed-device-posture-source.md remains pending.
//! A parsed payload is not source authentication or proof of device possession.

use crate::{ClientId, DomainError, TenantId, UserId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const PROFILE: &str = "managed-device-relay/v1";
pub const MAX_UPDATE_BYTES: usize = 8192;
pub const MAX_OBSERVATIONS: usize = 32;
pub const MAX_ALLOWED_CLIENTS: usize = 64;
pub const MAX_FACT_AGE: Duration = Duration::seconds(300);
pub const FORWARD_TOLERANCE: Duration = Duration::seconds(5);
pub const REMOVAL_RETENTION: Duration = Duration::days(30);

/// Private evidence transported between server adapters. This is never an OAuth
/// request parameter or public JWT claim, and deserialization is not verification.
/// A caller must first establish certificate possession at the trusted proxy and
/// pin the current enrollment, source, anchor and exact interaction generations.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBinding {
    tenant: TenantId,
    user: UserId,
    client: ClientId,
    interaction_digest: String,
    source: Uuid,
    source_generation: i64,
    device: Uuid,
    enrollment_generation: i64,
    leaf_sha256: String,
    anchor_sha256: String,
    certificate_expires_at: OffsetDateTime,
    proof_expires_at: OffsetDateTime,
}

impl std::fmt::Debug for DeviceBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceBinding([private evidence])")
    }
}

/// Input to the trusted possession adapter, after chain verification and exact
/// tenant/user/application/interaction lookup. It must never be decoded from HTTP.
pub struct VerifiedDeviceEvidence {
    pub tenant: TenantId,
    pub user: UserId,
    pub client: ClientId,
    pub interaction_digest: String,
    pub source: Uuid,
    pub source_generation: i64,
    pub device: Uuid,
    pub enrollment_generation: i64,
    pub leaf_sha256: String,
    pub anchor_sha256: String,
    pub certificate_expires_at: OffsetDateTime,
    pub proof_expires_at: OffsetDateTime,
}

impl DeviceBinding {
    /// Seal already-verified evidence with an original deadline of at most 300s.
    /// Current generation/posture checks remain mandatory at every policy fence.
    pub fn from_verified(evidence: VerifiedDeviceEvidence, now: OffsetDateTime) -> Result<Self, DomainError> {
        let binding = Self {
            tenant: evidence.tenant,
            user: evidence.user,
            client: evidence.client,
            interaction_digest: evidence.interaction_digest,
            source: evidence.source,
            source_generation: evidence.source_generation,
            device: evidence.device,
            enrollment_generation: evidence.enrollment_generation,
            leaf_sha256: evidence.leaf_sha256,
            anchor_sha256: evidence.anchor_sha256,
            certificate_expires_at: evidence.certificate_expires_at,
            proof_expires_at: evidence.proof_expires_at,
        };
        binding.validate(now)?;
        Ok(binding)
    }

    /// Storage is private but may be corrupt; loading never skips these bounds.
    pub fn validate(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        let latest = now.checked_add(MAX_FACT_AGE).ok_or_else(invalid)?;
        if self.source_generation <= 0 || self.enrollment_generation <= 0
            || self.source.is_nil() || self.device.is_nil()
            || self.client.as_str().is_empty() || self.client.as_str().len() > 256
            || self.client.as_str().chars().any(char::is_control)
            || self.proof_expires_at <= now || self.proof_expires_at > latest
            || self.certificate_expires_at <= now
            || self.proof_expires_at > self.certificate_expires_at
        { return Err(invalid()); }
        LeafFingerprint::parse(&self.interaction_digest)?;
        LeafFingerprint::parse(&self.leaf_sha256)?;
        LeafFingerprint::parse(&self.anchor_sha256)?;
        Ok(())
    }
    #[must_use]
    pub fn tenant(&self) -> &TenantId { &self.tenant }
    #[must_use]
    pub const fn user(&self) -> &UserId { &self.user }
    #[must_use]
    pub fn client(&self) -> &ClientId { &self.client }
    #[must_use]
    pub fn interaction_digest(&self) -> &str { &self.interaction_digest }
    #[must_use]
    pub const fn source(&self) -> Uuid { self.source }
    #[must_use]
    pub const fn source_generation(&self) -> i64 { self.source_generation }
    #[must_use]
    pub const fn device(&self) -> Uuid { self.device }
    #[must_use]
    pub const fn enrollment_generation(&self) -> i64 { self.enrollment_generation }
    #[must_use]
    pub fn leaf_sha256(&self) -> &str { &self.leaf_sha256 }
    #[must_use]
    pub fn anchor_sha256(&self) -> &str { &self.anchor_sha256 }
    #[must_use]
    pub const fn certificate_expires_at(&self) -> OffsetDateTime { self.certificate_expires_at }
    #[must_use]
    pub const fn proof_expires_at(&self) -> OffsetDateTime { self.proof_expires_at }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
    Unknown,
}

/// Only the latest bounded attributes are stored; no arbitrary inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Posture {
    pub managed: Option<bool>,
    pub compliant: Option<bool>,
    pub disk_encrypted: Option<bool>,
    pub risk: Option<Risk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compliance {
    Compliant,
    NonCompliant,
    Unknown,
}
impl Posture {
    /// Unknown management/compliance is unavailable authority. Diagnostic risk
    /// and encryption attributes never silently invent another policy clause.
    #[must_use]
    pub const fn compliance(&self) -> Compliance {
        match (self.managed, self.compliant) {
            (Some(true), Some(true)) => Compliance::Compliant,
            (Some(_), Some(_)) => Compliance::NonCompliant,
            _ => Compliance::Unknown,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub device_id: Uuid,
    pub enrollment_generation: i64,
    pub sequence: i64,
    pub observed_at: i64,
    pub expires_at: i64,
    pub posture: Posture,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    pub profile: String,
    pub source_generation: i64,
    pub observations: Vec<Observation>,
}
impl Update {
    /// Structural/timestamp validation only. The adapter must atomically check
    /// source authority, active enrollment generation and strictly newer sequence.
    pub fn parse(bytes: &[u8], now: OffsetDateTime) -> Result<Self, DomainError> {
        if bytes.len() > MAX_UPDATE_BYTES {
            return Err(invalid());
        }
        let update: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        update.validate(now)?;
        Ok(update)
    }
    pub fn validate(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.profile != PROFILE
            || self.source_generation <= 0
            || self.observations.is_empty()
            || self.observations.len() > MAX_OBSERVATIONS
        {
            return Err(invalid());
        }
        let earliest = now.checked_sub(MAX_FACT_AGE).ok_or_else(invalid)?;
        let latest = now.checked_add(FORWARD_TOLERANCE).ok_or_else(invalid)?;
        let mut devices = BTreeSet::new();
        for observation in &self.observations {
            let observed = OffsetDateTime::from_unix_timestamp(observation.observed_at)
                .map_err(|_| invalid())?;
            let expiry = OffsetDateTime::from_unix_timestamp(observation.expires_at)
                .map_err(|_| invalid())?;
            if !devices.insert(observation.device_id)
                || observation.enrollment_generation <= 0
                || observation.sequence < 0
                || observed < earliest
                || observed > latest
                || expiry <= observed
                || expiry <= now
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceChange {
    pub client_id: ClientId,
    pub expected_revision: Option<Uuid>,
    #[serde(default)]
    pub enabled: bool,
}

impl SourceChange {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.client_id.as_str().is_empty()
            || self.client_id.as_str().len() > 256
            || self.client_id.as_str().chars().any(char::is_control)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct LeafFingerprint(String);
impl std::fmt::Debug for LeafFingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LeafFingerprint([withheld])")
    }
}
impl LeafFingerprint {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid());
        }
        Ok(Self(value.to_owned()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub user_id: UserId,
    pub leaf_sha256: String,
    pub allowed_client_ids: Vec<ClientId>,
}
impl std::fmt::Debug for EnrollmentRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("EnrollmentRequest")
            .field("allowed_client_count", &self.allowed_client_ids.len())
            .finish_non_exhaustive()
    }
}
impl EnrollmentRequest {
    pub fn validate(&self) -> Result<LeafFingerprint, DomainError> {
        let unique: BTreeSet<_> = self.allowed_client_ids.iter().collect();
        if self.allowed_client_ids.len() > MAX_ALLOWED_CLIENTS
            || unique.len() != self.allowed_client_ids.len()
            || self.allowed_client_ids.iter().any(|client| {
                client.as_str().is_empty()
                    || client.as_str().len() > 256
                    || client.as_str().chars().any(char::is_control)
            })
        {
            return Err(invalid());
        }
        LeafFingerprint::parse(&self.leaf_sha256)
    }
}

/// A source client is checked against the authenticated request, never supplied
/// as the enrollment association in a browser hint or token-device claim.
#[async_trait::async_trait]
pub trait Relay: std::fmt::Debug + Send + Sync {
    async fn enroll(
        &self,
        tenant: &TenantId,
        source: Uuid,
        authenticated_client: &ClientId,
        request: &EnrollmentRequest,
        now: OffsetDateTime,
    ) -> Result<Uuid, DomainError>;
    async fn ingest(
        &self,
        tenant: &TenantId,
        source: Uuid,
        authenticated_client: &ClientId,
        update: &Update,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;
}

fn invalid() -> DomainError {
    DomainError::invalid("managed_device", "invalid bounded managed-device input")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn update(now: OffsetDateTime) -> serde_json::Value {
        json!({"profile":PROFILE,"source_generation":1,"observations":[{
            "device_id":Uuid::new_v4(),"enrollment_generation":1,"sequence":0,
            "observed_at":now.unix_timestamp(),"expires_at":now.unix_timestamp()+600,
            "posture":{"managed":true,"compliant":true,"disk_encrypted":true,"risk":"low"}
        }]})
    }
    #[test]
    fn managed_device_update_is_closed_bounded_and_rejects_duplicate_devices() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(20000);
        let mut value = update(now);
        assert!(Update::parse(&serde_json::to_vec(&value).expect("fixture JSON"), now).is_ok());
        let first = value["observations"][0].clone();
        value["observations"].as_array_mut().expect("fixture array").push(first);
        assert!(Update::parse(&serde_json::to_vec(&value).expect("fixture JSON"), now).is_err());
        assert!(Update::parse(&vec![b' '; MAX_UPDATE_BYTES + 1], now).is_err());
        let mut value = update(now);
        value["observations"][0]["posture"]["browser_hint"] = json!(true);
        assert!(Update::parse(&serde_json::to_vec(&value).expect("fixture JSON"), now).is_err());
    }
    #[test]
    fn managed_device_binding_preserves_original_deadline_and_redacts_evidence() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(20000);
        let proof = DeviceBinding::from_verified(VerifiedDeviceEvidence {
            tenant: TenantId::parse("tenant-a").expect("fixture tenant"),
            user: UserId::new(Uuid::new_v4()),
            client: ClientId::new("application-a"),
            interaction_digest: "a".repeat(64),
            source: Uuid::new_v4(),
            source_generation: 1,
            device: Uuid::new_v4(),
            enrollment_generation: 1,
            leaf_sha256: "b".repeat(64),
            anchor_sha256: "c".repeat(64),
            certificate_expires_at: now + Duration::hours(1),
            proof_expires_at: now + MAX_FACT_AGE,
        }, now).expect("verified fixture");
        let stored = serde_json::to_value(&proof).expect("private storage");
        let restored: DeviceBinding = serde_json::from_value(stored).expect("private storage");
        assert_eq!(restored.proof_expires_at(), now + MAX_FACT_AGE);
        assert!(restored.validate(now + MAX_FACT_AGE).is_err());
        assert_eq!(format!("{proof:?}"), "DeviceBinding([private evidence])");
    }

    #[test]
    fn managed_device_unknown_posture_is_not_compliance_authority() {
        let posture = Posture { managed: None, compliant: Some(true), disk_encrypted: None, risk: None };
        assert_eq!(posture.compliance(), Compliance::Unknown);
        let partial = Posture { managed: Some(false), compliant: None, disk_encrypted: None, risk: None };
        assert_eq!(partial.compliance(), Compliance::Unknown);
    }
}
