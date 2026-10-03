//! Independently approved, expiring application roles; never standing assignments.
use crate::{ClientId, DomainError, Grant, RoleName, TenantId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementConfiguration {
    pub owner_user_id: Uuid,
    pub client_id: String,
    pub resource: String,
    pub role_name: String,
    pub permissions: Vec<String>,
    pub approver_user_ids: Vec<Uuid>,
    pub requester_acr: String,
    pub approver_acr: String,
    pub max_duration_seconds: i32,
    pub max_eligibility_seconds: i32,
    pub enabled: bool,
}
impl EntitlementConfiguration {
    // fuzz-target: temporary_entitlement_configuration
    pub fn validate(&self) -> Result<(), DomainError> {
        RoleName::parse(&self.role_name)
            .map_err(|e| DomainError::invalid("role_name", e.to_string()))?;
        crate::ResourceIdentifier::parse(&self.resource)
            .map_err(|e| DomainError::invalid("resource", e.to_string()))?;
        let unique: std::collections::BTreeSet<_> = self.approver_user_ids.iter().collect();
        if !(1..=16).contains(&self.approver_user_ids.len())
            || unique.len() != self.approver_user_ids.len()
            || !self
                .approver_user_ids
                .iter()
                .any(|id| *id != self.owner_user_id)
            || !(1..=3600).contains(&self.max_duration_seconds)
            || !(1..=2_592_000).contains(&self.max_eligibility_seconds)
            || self.client_id.is_empty()
            || self.client_id.len() > 2048
            || self.requester_acr.is_empty()
            || self.requester_acr.len() > 256
            || self.approver_acr.is_empty()
            || self.approver_acr.len() > 256
            || self.permissions.is_empty()
            || self.permissions.len() > 64
            || self
                .permissions
                .iter()
                .any(|s| !crate::entities::grant::is_scope_token(s))
            || self
                .permissions
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.permissions.len()
        {
            return Err(DomainError::invalid(
                "entitlement",
                "invalid bounds or duplicate values",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub entitlement_id: Uuid,
    pub revision: Uuid,
    pub editor_user_id: Uuid,
    pub created_at: i64,
    #[serde(flatten)]
    pub configuration: EntitlementConfiguration,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EligibilityChange {
    pub user_id: Uuid,
    pub not_before: i64,
    pub expires_at: i64,
    pub expected_revision: Option<Uuid>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eligibility {
    pub eligibility_id: Uuid,
    pub entitlement_id: Uuid,
    pub user_id: Uuid,
    pub editor_user_id: Uuid,
    pub revision: Uuid,
    pub not_before: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
    Cancelled,
    Expired,
    Invalidated,
}
impl RequestStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Invalidated => "invalidated",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementRequest {
    pub request_id: Uuid,
    pub entitlement_id: Uuid,
    pub eligibility_id: Uuid,
    pub eligibility_revision: Uuid,
    pub policy_revision: Uuid,
    pub requester_user_id: Uuid,
    pub client_id: String,
    pub resource: String,
    pub role_name: String,
    pub permissions: Vec<String>,
    pub requester_acr: String,
    pub approver_acr: String,
    pub duration_seconds: i32,
    pub reason: String,
    pub created_at: i64,
    pub deadline: i64,
    pub status: RequestStatus,
    pub decided_at: Option<i64>,
    pub decided_by: Option<Uuid>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStatus {
    Active,
    Expired,
    Revoked,
    Invalidated,
}
impl ActivationStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Invalidated => "invalidated",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activation {
    pub status: ActivationStatus,
    pub activation_id: Uuid,
    pub request_id: Uuid,
    pub entitlement_id: Uuid,
    pub user_id: Uuid,
    pub activated_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<String>,
    pub expiry_recorded_at: Option<i64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntitlements {
    pub observed_at: i64,
    pub entitlements: Vec<Entitlement>,
    pub eligibilities: Vec<Eligibility>,
    pub requests: Vec<EntitlementRequest>,
    pub activations: Vec<Activation>,
}
/// Comes only from the ordinary browser session adapter, never posted claims.
#[derive(Debug, Clone)]
pub struct SessionActor {
    pub user: UserId,
    pub session_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestActivation {
    pub entitlement_id: Uuid,
    pub duration_seconds: i32,
    pub reason: String,
    pub idempotency_key: Uuid,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Deny,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideRequest {
    pub request_id: Uuid,
    pub decision: Decision,
    pub idempotency_key: Uuid,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    pub request_id: Uuid,
    pub idempotency_key: Uuid,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeActivation {
    pub activation_id: Uuid,
    pub reason: String,
    pub idempotency_key: Uuid,
}
#[derive(Debug, Clone)]
pub struct ActiveTemporaryRole {
    pub activation_id: Uuid,
    pub entitlement_id: Uuid,
    pub client: ClientId,
    pub resource: String,
    pub permissions: Vec<String>,
    pub policy_revision: Uuid,
    pub eligibility_revision: Uuid,
    pub role: RoleName,
    pub expires_at: OffsetDateTime,
}
#[derive(Debug, Clone)]
pub struct TemporaryRoleSnapshot {
    pub observed_at: OffsetDateTime,
    pub roles: Vec<ActiveTemporaryRole>,
}

/// Read-only lifecycle evidence for governance. This is not role authority:
/// actual issuance still requires an exact, nondelegated grant and frozen proof.
#[derive(Debug, Clone, Serialize)]
pub struct TemporaryEntitlementProvenance {
    pub activation_id: Uuid,
    pub entitlement_id: Uuid,
    pub request_id: Uuid,
    pub client: String,
    pub resource: String,
    pub role_name: String,
    pub permissions: Vec<String>,
    pub policy_revision: Uuid,
    pub eligibility_revision: Uuid,
    pub expires_at: OffsetDateTime,
}
#[derive(Debug, Clone, Serialize)]
pub struct TemporaryEntitlementProvenanceSnapshot {
    pub observed_at: OffsetDateTime,
    pub entries: Vec<TemporaryEntitlementProvenance>,
}

/// Frozen methods and their policy incarnation are distinct from cumulative AMR.
#[derive(Debug)]
pub struct AssuranceProof<'a> {
    pub at: Option<OffsetDateTime>,
    pub revision: Option<&'a str>,
    pub methods: &'a [crate::AuthenticationMethod],
}
#[must_use]
pub fn assurance_current(
    policy: &crate::AcrPolicy,
    required: &str,
    proof: AssuranceProof<'_>,
    now: OffsetDateTime,
) -> bool {
    let Some(at) = proof.at else { return false };
    let age = now - at;
    !age.is_negative()
        && age <= time::Duration::seconds(120)
        && proof.revision
            == Some(crate::sha256_hex(policy.to_json().to_string().as_bytes()).as_str())
        && policy
            .level(required)
            .is_some_and(|level| level.is_met_by(proof.methods))
}

pub fn validate_reason(reason: &str) -> Result<(), DomainError> {
    if reason.trim().is_empty() || reason.len() > 1024 || reason.chars().any(char::is_control) {
        return Err(DomainError::invalid(
            "reason",
            "requires 1..1024 bytes without control characters",
        ));
    }
    Ok(())
}

#[async_trait::async_trait]
pub trait TemporaryEntitlements: Send + Sync {
    async fn list(
        &self,
        tenant: &TenantId,
        owner: &UserId,
    ) -> Result<Vec<Entitlement>, DomainError>;
    async fn get(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        entitlement: Uuid,
    ) -> Result<Entitlement, DomainError>;
    async fn configure(
        &self,
        tenant: &TenantId,
        actor: &UserId,
        id: Option<Uuid>,
        expected: Option<Uuid>,
        configuration: EntitlementConfiguration,
    ) -> Result<Entitlement, DomainError>;
    async fn eligibilities(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        entitlement: Uuid,
    ) -> Result<Vec<Eligibility>, DomainError>;
    async fn set_eligibility(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        entitlement: Uuid,
        change: EligibilityChange,
    ) -> Result<Eligibility, DomainError>;
    async fn remove_eligibility(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        entitlement: Uuid,
        eligibility: Uuid,
        expected: Uuid,
    ) -> Result<(), DomainError>;
    async fn owner_requests(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        entitlement: Uuid,
    ) -> Result<Vec<EntitlementRequest>, DomainError>;
    async fn owner_activations(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        entitlement: Uuid,
    ) -> Result<Vec<Activation>, DomainError>;
    async fn owner_revoke(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        entitlement: Uuid,
        command: RevokeActivation,
    ) -> Result<Activation, DomainError>;
    async fn account(
        &self,
        tenant: &TenantId,
        actor: &SessionActor,
    ) -> Result<AccountEntitlements, DomainError>;
    async fn request(
        &self,
        tenant: &TenantId,
        actor: &SessionActor,
        command: RequestActivation,
    ) -> Result<EntitlementRequest, DomainError>;
    async fn decide(
        &self,
        tenant: &TenantId,
        actor: &SessionActor,
        command: DecideRequest,
    ) -> Result<EntitlementRequest, DomainError>;
    async fn cancel(
        &self,
        tenant: &TenantId,
        actor: &SessionActor,
        command: CancelRequest,
    ) -> Result<EntitlementRequest, DomainError>;
    async fn revoke(
        &self,
        tenant: &TenantId,
        actor: &SessionActor,
        command: RevokeActivation,
    ) -> Result<Activation, DomainError>;
    async fn resolve_for_grant(
        &self,
        tenant: &TenantId,
        grant: &Grant,
    ) -> Result<TemporaryRoleSnapshot, DomainError>;
    async fn reconcile_expired(&self, tenant: &TenantId, limit: u16) -> Result<u64, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn configuration() -> EntitlementConfiguration {
        EntitlementConfiguration {
            owner_user_id: Uuid::new_v4(),
            client_id: "app".into(),
            resource: "https://api.example/".into(),
            role_name: "approve".into(),
            permissions: vec!["read".into()],
            approver_user_ids: vec![Uuid::new_v4()],
            requester_acr: crate::acr::PASSKEY.into(),
            approver_acr: crate::acr::PASSKEY.into(),
            max_duration_seconds: 900,
            max_eligibility_seconds: 86400,
            enabled: true,
        }
    }
    #[test]
    fn temporary_configuration_roundtrip_preserves_closed_bounds() {
        let config = configuration();
        assert!(config.validate().is_ok());
        let record = Entitlement {
            entitlement_id: Uuid::new_v4(),
            revision: Uuid::new_v4(),
            editor_user_id: config.owner_user_id,
            created_at: 1000,
            configuration: config,
        };
        let encoded = serde_json::to_value(&record).unwrap();
        let decoded: Entitlement = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.revision, record.revision);
        for (seconds, eligibility) in [(0, 86400), (3601, 86400), (900, 0), (900, 2592001)] {
            let mut c = configuration();
            c.max_duration_seconds = seconds;
            c.max_eligibility_seconds = eligibility;
            assert!(c.validate().is_err());
        }
        let mut duplicate = configuration();
        duplicate
            .approver_user_ids
            .push(duplicate.approver_user_ids[0]);
        assert!(duplicate.validate().is_err());
        let mut empty = configuration();
        empty.approver_user_ids.clear();
        assert!(empty.validate().is_err());
    }
    #[test]
    fn temporary_assurance_refuses_missing_stale_and_relabelled_evidence() {
        let policy = crate::AcrPolicy::default();
        let now = OffsetDateTime::from_unix_timestamp(1000).unwrap();
        let revision = crate::sha256_hex(policy.to_json().to_string().as_bytes());
        let methods = [crate::AuthenticationMethod::Passkey];
        for (at, revision, methods) in [
            (None, Some(revision.as_str()), methods.as_slice()),
            (
                Some(now - time::Duration::seconds(121)),
                Some(revision.as_str()),
                methods.as_slice(),
            ),
            (
                Some(now + time::Duration::seconds(1)),
                Some(revision.as_str()),
                methods.as_slice(),
            ),
            (Some(now), Some("other-policy"), methods.as_slice()),
            (
                Some(now),
                Some(revision.as_str()),
                [crate::AuthenticationMethod::Password].as_slice(),
            ),
        ] {
            assert!(!assurance_current(
                &policy,
                crate::acr::PASSKEY,
                AssuranceProof {
                    at,
                    revision,
                    methods
                },
                now
            ));
        }
        assert!(assurance_current(
            &policy,
            crate::acr::PASSKEY,
            AssuranceProof {
                at: Some(now - time::Duration::seconds(120)),
                revision: Some(&revision),
                methods: &methods
            },
            now
        ));
    }
    #[test]
    fn rejects_empty_oversized_and_control_reasons() {
        for value in [
            "".to_owned(),
            "  ".to_owned(),
            "a".repeat(1025),
            "a\nreason".to_owned(),
        ] {
            assert!(validate_reason(&value).is_err());
        }
        assert!(validate_reason(&"é".repeat(512)).is_ok());
        assert!(validate_reason(&"é".repeat(513)).is_err());
    }
}
