//! Draft managed-device-relay/v1 types. Not wired into a deployment while
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
    fn managed_device_unknown_posture_is_not_compliance_authority() {
        let posture = Posture { managed: None, compliant: Some(true), disk_encrypted: None, risk: None };
        assert_eq!(posture.compliance(), Compliance::Unknown);
        let partial = Posture { managed: Some(false), compliant: None, disk_encrypted: None, risk: None };
        assert_eq!(partial.compliance(), Compliance::Unknown);
    }
}
