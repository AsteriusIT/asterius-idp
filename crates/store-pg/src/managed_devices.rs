//! Current device evidence read on an already-held policy publication fence.
//! No pool checkout or session lookup is permitted inside the signing fence.
use asterius_domain::managed_devices::{
    Compliance, DeviceBinding, DeviceSummary, EnrollmentRequest, LeafFingerprint,
    Posture, Registry, Relay, RelayCredential, RemovalAuthority, SourceChange, SourceSummary, Update,
};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::policy::conditional::{Availability, Fact, FactValue};
use asterius_domain::{ClientId, DomainError, Grant, TenantId, UserId};
use sqlx::{PgConnection, PgPool};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
use time::OffsetDateTime;

use crate::error::to_domain_error;

#[derive(Debug, Clone)]
pub struct PgManagedDevices {
    pool: PgPool,
    audit: Arc<dyn AuditSink>,
}

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
    #[must_use]
    pub fn new(pool: PgPool, audit: Arc<dyn AuditSink>) -> Self { Self { pool, audit } }

    /// Preflight only; final policy reads still use the publication fence.
    pub async fn bind_request_in(pool: &PgPool, tenant: &TenantId, grant: &Grant,
        certificate: &asterius_domain::managed_devices::DeviceCertificateEvidence,
        request_digest: &str, now: OffsetDateTime,
    ) -> Result<Option<DeviceBinding>, DomainError> {
        let mut transaction = pool.begin().await.map_err(to_domain_error)?;
        let active: Option<String> = sqlx::query_scalar("select tenant_id from tenants where tenant_id=$1 and status='active' for share")
            .bind(tenant.as_str()).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
        if active.is_none() { return Ok(None); }
        let binding = Self::bind_request_on(&mut transaction, tenant, grant, certificate, request_digest, now).await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(binding)
    }

    /// Build fresh possession for an exact authenticated request/grant on the
    /// caller's publication connection. Never read a previous code/session proof.
    pub async fn bind_request_on(connection: &mut PgConnection, tenant: &TenantId, grant: &Grant,
        certificate: &asterius_domain::managed_devices::DeviceCertificateEvidence,
        request_digest: &str, now: OffsetDateTime,
    ) -> Result<Option<DeviceBinding>, DomainError> {
        use asterius_domain::managed_devices::VerifiedDeviceEvidence;
        let Some(user) = grant.user.filter(|_| grant.tenant == *tenant) else { return Ok(None); };
        LeafFingerprint::parse(request_digest)?;
        let leaf = hex::decode(certificate.leaf.as_str()).map_err(|_| DomainError::NotFound)?;
        let device: Option<(Uuid, Uuid, i64, i64, String)> = sqlx::query_as(
            "select d.device_id,d.source_id,d.source_generation,d.enrollment_generation,s.client_id \
             from managed_devices d join managed_device_sources s using(tenant_id,source_id) \
             where d.tenant_id=$1 and d.leaf_sha256=$2 and d.user_id=$3 and $4=any(d.allowed_client_ids) \
             and d.removed_at is null and s.enabled and s.generation=d.source_generation for share of d,s"
        ).bind(tenant.as_str()).bind(leaf).bind(user.as_uuid()).bind(grant.client.as_str())
            .fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
        let Some((device, source, source_generation, enrollment_generation, source_client)) = device else { return Ok(None); };
        relay_client_on(connection, tenant, &ClientId::new(source_client)).await?;
        let current_user: Option<Uuid> = sqlx::query_scalar("select user_id from users where tenant_id=$1 and user_id=$2 and status='active' for share")
            .bind(tenant.as_str()).bind(user.as_uuid()).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
        let current_client: Option<String> = sqlx::query_scalar("select client_id from clients where tenant_id=$1 and client_id=$2 and status='active' for share")
            .bind(tenant.as_str()).bind(grant.client.as_str()).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
        if current_user.is_none() || current_client.is_none() { return Ok(None); }
        let current: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()").fetch_one(connection).await.map_err(to_domain_error)?;
        let expiry = (now + time::Duration::seconds(300)).min(certificate.expires_at);
        if expiry <= current { return Ok(None); }
        DeviceBinding::from_verified_request(VerifiedDeviceEvidence {
            tenant: tenant.clone(), user, client: grant.client.clone(), interaction_digest: request_digest.to_owned(),
            source, source_generation, device, enrollment_generation,
            leaf_sha256: certificate.leaf.as_str().to_owned(), anchor_sha256: certificate.anchor.as_str().to_owned(),
            certificate_expires_at: certificate.expires_at, proof_expires_at: expiry,
        }, grant, current).map(Some)
    }

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
        Self::resolve_on(connection,tenant,grant,binding,current_anchor,false).await
    }

    /// Early exchange evaluation only: exact verified parent authority plus a
    /// provisional child. This is never the final issued-authority resolver.
    pub async fn resolve_preflight_on(
        connection: &mut PgConnection, tenant: &TenantId, grant: &Grant,
        binding: Option<&DeviceBinding>, current_anchor: Option<&LeafFingerprint>,
    ) -> Result<Fact, DomainError> {
        Self::resolve_on(connection,tenant,grant,binding,current_anchor,true).await
    }

    async fn resolve_on(
        connection: &mut PgConnection, tenant: &TenantId, grant: &Grant,
        binding: Option<&DeviceBinding>, current_anchor: Option<&LeafFingerprint>, preflight: bool,
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
            || binding.bound_grant_id().is_some_and(|id| id != &grant.id)
            || (binding.bound_grant_id().is_some() && binding.request_parent()!=grant.parent.as_ref())
        {
            return Ok(missing(Availability::Invalid));
        }
        if preflight {
            let Some(parent) = binding.request_parent().filter(|id| grant.parent.as_ref()==Some(id)) else {
                return Ok(missing(Availability::Unavailable));
            };
            let parent = Uuid::parse_str(parent.as_str()).map_err(|_| DomainError::NotFound)?;
            let row: Option<(Option<Uuid>, Option<String>)> = sqlx::query_as(
                "select user_id,subject from grants where tenant_id=$1 and grant_id=$2 for share"
            ).bind(tenant.as_str()).bind(parent).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
            let Some((user,subject)) = row else { return Ok(missing(Availability::Invalid)); };
            let current: bool = sqlx::query_scalar("select claimed_at is not null and revoked_at is null and (expires_at is null or expires_at>clock_timestamp()) from grants where tenant_id=$1 and grant_id=$2")
                .bind(tenant.as_str()).bind(parent).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
            if !current || binding.bound_grant_id()!=Some(&grant.id) || user!=grant.user.map(|u|*u.as_uuid())
                || subject.as_deref()!=grant.subject.as_ref().map(asterius_domain::SubjectId::as_str)
            { return Ok(missing(Availability::Invalid)); }
        }
        if binding.bound_grant_id().is_some() && !preflight {
            let id = Uuid::parse_str(grant.id.as_str()).map_err(|_| DomainError::NotFound)?;
            let row: Option<(String, Option<Uuid>, Option<String>, bool)> = sqlx::query_as(
                "select client_id,user_id,subject,claimed_at is not null and revoked_at is null \
                 and (expires_at is null or expires_at>clock_timestamp()) from grants \
                 where tenant_id=$1 and grant_id=$2 for share"
            ).bind(tenant.as_str()).bind(id).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
            let Some((client,user,subject,live)) = row else { return Ok(missing(Availability::Invalid)); };
            let live_after_lock: bool = sqlx::query_scalar("select claimed_at is not null and revoked_at is null and (expires_at is null or expires_at>clock_timestamp()) from grants where tenant_id=$1 and grant_id=$2")
                .bind(tenant.as_str()).bind(id).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
            if !live || !live_after_lock || client!=grant.client.as_str() || user!=grant.user.map(|user| *user.as_uuid())
                || subject.as_deref()!=grant.subject.as_ref().map(asterius_domain::SubjectId::as_str)
            { return Ok(missing(Availability::Invalid)); }
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

#[derive(sqlx::FromRow)]
struct SourceRow {
    source_id: Uuid,
    client_id: String,
    generation: i64,
    revision: Uuid,
    enabled: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}
impl SourceRow {
    fn summary(self) -> SourceSummary {
        SourceSummary {
            id: self.source_id, client_id: ClientId::new(self.client_id),
            generation: self.generation, revision: self.revision, enabled: self.enabled,
            created_at: self.created_at, updated_at: self.updated_at,
        }
    }
}

async fn publication_write_on(connection: &mut PgConnection, tenant: &TenantId) -> Result<(), DomainError> {
    // Every device writer takes the publication fence FIRST. Inverting this
    // order can deadlock a signature holding tenant/source/enrollment SHARE.
    let exists: Option<String> = sqlx::query_scalar(
        "select tenant_id from tenants where tenant_id=$1 and status='active' for update"
    ).bind(tenant.as_str()).fetch_optional(connection).await.map_err(to_domain_error)?;
    if exists.is_none() { return Err(DomainError::NotFound); }
    Ok(())
}

async fn relay_client_on(connection: &mut PgConnection, tenant: &TenantId, client: &ClientId) -> Result<(), DomainError> {
    let active: Option<bool> = sqlx::query_scalar(
        "select status='active' and not is_agent and client_type='confidential' \
         and grant_types=ARRAY['client_credentials']::text[] and dpop_bound_access_tokens \
         and token_endpoint_auth_method in ('private_key_jwt','tls_client_auth','self_signed_tls_client_auth') \
         from clients where tenant_id=$1 and client_id=$2 for share"
    ).bind(tenant.as_str()).bind(client.as_str()).fetch_optional(connection).await.map_err(to_domain_error)?;
    if active != Some(true) { return Err(DomainError::invalid("device_source", "current independent FAPI relay client required")); }
    Ok(())
}

async fn relay_source_on(
    connection: &mut PgConnection, tenant: &TenantId, source: Uuid, client: &ClientId,
) -> Result<SourceRow, DomainError> {
    relay_client_on(connection, tenant, client).await?;
    let row: Option<SourceRow> = sqlx::query_as(
        "select source_id, client_id, generation, revision, enabled, created_at, updated_at \
         from managed_device_sources where tenant_id=$1 and source_id=$2 for share"
    ).bind(tenant.as_str()).bind(source).fetch_optional(connection).await.map_err(to_domain_error)?;
    let row = row.ok_or(DomainError::NotFound)?;
    if !row.enabled || row.client_id != client.as_str() { return Err(DomainError::NotFound); }
    Ok(row)
}

impl PgManagedDevices {
    async fn record_on(
        &self, connection: &mut PgConnection, tenant: &TenantId,
        event: EventType, actor: Actor, detail: Detail, now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let event = self.audit.prepare(AuditEvent::new(tenant.clone(), event, Outcome::Success, actor, now).detail(detail));
        crate::audit::append(connection, event).await
    }
}

#[async_trait::async_trait]
impl Registry for PgManagedDevices {
    async fn sources(&self, tenant: &TenantId) -> Result<Vec<SourceSummary>, DomainError> {
        let rows: Vec<SourceRow> = sqlx::query_as(
            "select source_id, client_id, generation, revision, enabled, created_at, updated_at \
             from managed_device_sources where tenant_id=$1 order by source_id limit 65"
        ).bind(tenant.as_str()).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        if rows.len() > 64 { return Err(DomainError::invalid("device_sources", "source bound exceeded")); }
        Ok(rows.into_iter().map(SourceRow::summary).collect())
    }

    async fn save_source(
        &self, tenant: &TenantId, id: Option<Uuid>, change: &SourceChange,
        actor: Actor, now: OffsetDateTime,
    ) -> Result<SourceSummary, DomainError> {
        change.validate()?;
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        publication_write_on(&mut transaction, tenant).await?;
        relay_client_on(&mut transaction, tenant, &change.client_id).await?;
        let requested_id = id;
        let id = id.unwrap_or_else(Uuid::new_v4);
        let current: Option<Uuid> = sqlx::query_scalar(
            "select revision from managed_device_sources where tenant_id=$1 and source_id=$2 for update"
        ).bind(tenant.as_str()).bind(id).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
        if requested_id.is_some() && current.is_none() { return Err(DomainError::NotFound); }
        if current != change.expected_revision { return Err(DomainError::Conflict("device source revision changed".into())); }
        if current.is_none() {
            let count: i64 = sqlx::query_scalar("select count(*) from managed_device_sources where tenant_id=$1")
                .bind(tenant.as_str()).fetch_one(&mut *transaction).await.map_err(to_domain_error)?;
            if count >= 64 { return Err(DomainError::invalid("device_sources", "source bound exceeded")); }
        }
        let row: SourceRow = sqlx::query_as(
            "insert into managed_device_sources (tenant_id,source_id,client_id,generation,revision,enabled,created_at,updated_at) \
             values($1,$2,$3,nextval('managed_device_generations'),$4,$5,$6,$6) \
             on conflict(tenant_id,source_id) do update set client_id=excluded.client_id, \
             generation=excluded.generation,revision=excluded.revision,enabled=excluded.enabled,updated_at=excluded.updated_at \
             returning source_id,client_id,generation,revision,enabled,created_at,updated_at"
        ).bind(tenant.as_str()).bind(id).bind(change.client_id.as_str()).bind(Uuid::new_v4()).bind(change.enabled).bind(now)
            .fetch_one(&mut *transaction).await.map_err(to_domain_error)?;
        self.record_on(&mut transaction, tenant, EventType::DEVICE_SOURCE_CHANGED, actor,
            Detail::new().text("source_id", id.to_string()).number("generation", row.generation), now).await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(row.summary())
    }

    async fn devices(
        &self, tenant: &TenantId, owner: Option<UserId>, after: Option<Uuid>, limit: u16,
    ) -> Result<Vec<DeviceSummary>, DomainError> {
        if limit == 0 || limit > 100 { return Err(DomainError::invalid("devices", "page limit must be between1 and100")); }
        let rows: Vec<SummaryRow> = sqlx::query_as(
            "select device_id, source_id, source_generation,enrollment_generation,revision,user_id, \
             allowed_client_ids, sequence,observed_at,source_expires_at,managed,compliant,disk_encrypted,risk,removed_at \
             from managed_devices where tenant_id=$1 and ($2::uuid is null or user_id=$2) \
             and ($3::uuid is null or device_id>$3) order by device_id limit $4"
        ).bind(tenant.as_str()).bind(owner.map(|owner| *owner.as_uuid())).bind(after).bind(i64::from(limit))
            .fetch_all(&self.pool).await.map_err(to_domain_error)?;
        rows.into_iter().map(SummaryRow::summary).collect()
    }

    async fn remove(
        &self, tenant: &TenantId, id: Uuid, expected: Uuid,
        authority: RemovalAuthority, now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        publication_write_on(&mut transaction, tenant).await?;
        let row: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "select revision,user_id from managed_devices where tenant_id=$1 and device_id=$2 for update"
        ).bind(tenant.as_str()).bind(id).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
        let (revision, owner) = row.ok_or(DomainError::NotFound)?;
        let actor = match authority {
            RemovalAuthority::Administrator(actor) => actor,
            RemovalAuthority::Owner(user) if owner == Some(*user.as_uuid()) => Actor::User(user.to_string()),
            RemovalAuthority::Owner(_) => return Err(DomainError::NotFound),
        };
        if revision != expected { return Err(DomainError::Conflict("device revision changed".into())); }
        sqlx::query("update managed_devices set enrollment_generation=nextval('managed_device_generations'), \
            revision=$3,user_id=null,leaf_sha256=null,allowed_client_ids=null,sequence=null,observed_at=null, \
            source_expires_at=null,managed=null,compliant=null,disk_encrypted=null,risk=null, \
            removed_at=coalesce(removed_at,$4),updated_at=$4 where tenant_id=$1 and device_id=$2")
            .bind(tenant.as_str()).bind(id).bind(Uuid::new_v4()).bind(now).execute(&mut *transaction).await.map_err(to_domain_error)?;
        sqlx::query("delete from managed_device_interaction_proofs where tenant_id=$1 and device_id=$2")
            .bind(tenant.as_str()).bind(id).execute(&mut *transaction).await.map_err(to_domain_error)?;
        sqlx::query("delete from managed_device_code_proofs where tenant_id=$1 and device_id=$2")
            .bind(tenant.as_str()).bind(id).execute(&mut *transaction).await.map_err(to_domain_error)?;
        self.record_on(&mut transaction, tenant, EventType::DEVICE_REMOVED, actor, Detail::new().text("device_id", id.to_string()), now).await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Relay for PgManagedDevices {
    async fn enroll(
        &self, tenant: &TenantId, source: Uuid, credential: &RelayCredential,
        request: &EnrollmentRequest, now: OffsetDateTime,
    ) -> Result<Uuid, DomainError> {
        let fingerprint = request.validate()?;
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        publication_write_on(&mut transaction, tenant).await?;
        let authenticated_client = credential.client();
        let source_row = relay_source_on(&mut transaction, tenant, source, authenticated_client).await?;
        require_relay_credential_on(&mut transaction, tenant, credential, true).await?;
        enrollment_principals_on(&mut transaction, tenant, request).await?;
        let count: i64 = sqlx::query_scalar("select count(*) from managed_devices where tenant_id=$1 and removed_at is null")
            .bind(tenant.as_str()).fetch_one(&mut *transaction).await.map_err(to_domain_error)?;
        if count >= 10000 { return Err(DomainError::invalid("devices", "active enrollment bound exceeded")); }
        let device = Uuid::new_v4();
        let clients: Vec<_> = request.allowed_client_ids.iter().map(ClientId::as_str).collect();
        let leaf = hex::decode(fingerprint.as_str()).map_err(|_| DomainError::invalid("device", "invalid certificate fingerprint"))?;
        sqlx::query("insert into managed_devices (tenant_id,device_id,source_id,source_generation,revision, \
            user_id,leaf_sha256,allowed_client_ids,created_at,updated_at) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)")
            .bind(tenant.as_str()).bind(device).bind(source).bind(source_row.generation).bind(Uuid::new_v4())
            .bind(request.user_id.as_uuid()).bind(leaf).bind(clients).bind(now)
            .execute(&mut *transaction).await.map_err(to_domain_error)?;
        self.record_on(&mut transaction, tenant, EventType::DEVICE_ENROLLED, Actor::Client(authenticated_client.clone()),
            Detail::new().text("device_id",device.to_string()).text("source_id",source.to_string()),now).await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(device)
    }

    async fn ingest(
        &self, tenant: &TenantId, source: Uuid, credential: &RelayCredential,
        update: &Update, supplied_now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        // Enforce payload work bounds before sorting/locking; the DB clock
        // below still decides timestamp validity after all lock waits.
        update.validate(supplied_now)?;
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        publication_write_on(&mut transaction, tenant).await?;
        let authenticated_client = credential.client();
        let source_row = relay_source_on(&mut transaction, tenant, source, authenticated_client).await?;
        require_relay_credential_on(&mut transaction, tenant, credential, false).await?;
        if source_row.generation != update.source_generation { return Err(DomainError::Conflict("device source generation changed".into())); }
        // Rows lock in UUID order, independent of caller payload ordering.
        let mut observations: Vec<_> = update.observations.iter().collect();
        observations.sort_unstable_by_key(|observation| observation.device_id);
        for observation in &observations {
            let row: Option<(i64, Option<i64>)> = sqlx::query_as(
                "select enrollment_generation,sequence from managed_devices where tenant_id=$1 and source_id=$2 \
                 and source_generation=$3 and device_id=$4 and removed_at is null for update"
            ).bind(tenant.as_str()).bind(source).bind(update.source_generation).bind(observation.device_id)
                .fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
            let (generation, sequence) = row.ok_or(DomainError::NotFound)?;
            if generation != observation.enrollment_generation || sequence.is_some_and(|sequence| sequence >= observation.sequence) {
                return Err(DomainError::Conflict("device enrollment or sequence changed".into()));
            }
        }
        let now: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *transaction).await.map_err(to_domain_error)?;
        update.validate(now)?;
        for observation in observations {
            let observed = OffsetDateTime::from_unix_timestamp(observation.observed_at)
                .map_err(|_| DomainError::invalid("device", "invalid observation time"))?;
            let expiry = OffsetDateTime::from_unix_timestamp(observation.expires_at)
                .map_err(|_| DomainError::invalid("device", "invalid source expiry"))?;
            let risk = observation.posture.risk.map(|risk| match risk {
                asterius_domain::managed_devices::Risk::Low => "low",
                asterius_domain::managed_devices::Risk::Medium => "medium",
                asterius_domain::managed_devices::Risk::High => "high",
                asterius_domain::managed_devices::Risk::Unknown => "unknown",
            });
            sqlx::query("update managed_devices set sequence=$3,observed_at=$4,source_expires_at=$5,managed=$6, \
                compliant=$7,disk_encrypted=$8,risk=$9,revision=$10,updated_at=$11 where tenant_id=$1 and device_id=$2")
                .bind(tenant.as_str()).bind(observation.device_id).bind(observation.sequence).bind(observed).bind(expiry)
                .bind(observation.posture.managed).bind(observation.posture.compliant).bind(observation.posture.disk_encrypted)
                .bind(risk).bind(Uuid::new_v4()).bind(now).execute(&mut *transaction).await.map_err(to_domain_error)?;
        }
        self.record_on(&mut transaction, tenant, EventType::DEVICE_POSTURE_UPDATED, Actor::Client(authenticated_client.clone()),
            Detail::new().text("source_id",source.to_string()).number("observation_count",i64::try_from(update.observations.len()).map_err(|_| DomainError::invalid("device", "observation bound exceeded"))?),now).await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(())
    }
}

async fn enrollment_principals_on(
    connection: &mut PgConnection, tenant: &TenantId, request: &EnrollmentRequest,
) -> Result<(), DomainError> {
    let active: Option<bool> = sqlx::query_scalar("select status='active' from users where tenant_id=$1 and user_id=$2 for share")
        .bind(tenant.as_str()).bind(request.user_id.as_uuid()).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
    if active != Some(true) { return Err(DomainError::NotFound); }
    let mut clients: Vec<_> = request.allowed_client_ids.iter().collect();
    clients.sort_unstable();
    for client in clients {
        let active: Option<bool> = sqlx::query_scalar("select status='active' from clients where tenant_id=$1 and client_id=$2 for share")
            .bind(tenant.as_str()).bind(client.as_str()).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
        if active != Some(true) { return Err(DomainError::NotFound); }
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct SummaryRow {
    device_id: Uuid, source_id: Uuid, source_generation: i64, enrollment_generation: i64,
    revision: Uuid, user_id: Option<Uuid>, allowed_client_ids: Option<Vec<String>>,
    sequence: Option<i64>, observed_at: Option<OffsetDateTime>, source_expires_at: Option<OffsetDateTime>,
    managed: Option<bool>, compliant: Option<bool>, disk_encrypted: Option<bool>, risk: Option<String>,
    removed_at: Option<OffsetDateTime>,
}
impl SummaryRow {
    fn summary(self) -> Result<DeviceSummary, DomainError> {
        let risk = self.risk.map(|risk| serde_json::from_value(serde_json::Value::String(risk))).transpose()
            .map_err(|_| DomainError::invalid("device", "invalid stored risk"))?;
        Ok(DeviceSummary {
            id:self.device_id, source_id:self.source_id,source_generation:self.source_generation,
            enrollment_generation:self.enrollment_generation, revision:self.revision,
            user_id:self.user_id.map(UserId::new),
            allowed_client_ids:self.allowed_client_ids.unwrap_or_default().into_iter().map(ClientId::new).collect(),
            sequence:self.sequence, observed_at:self.observed_at,source_expires_at:self.source_expires_at,
            posture:self.sequence.map(|_| Posture { managed:self.managed,compliant:self.compliant,disk_encrypted:self.disk_encrypted,risk }),
            removed_at:self.removed_at,
        })
    }
}

impl PgManagedDevices {
    /// Called only after successful root client-credentials signing, on the
    /// same held publication connection. This never records workload/task/
    /// delegated modes or derives authority from an optional public grant ID.
    ///
    /// # Errors
    /// Refuses expired/ambiguous receipts and current grant/client changes.
    pub async fn record_relay_token_on(
        connection: &mut PgConnection,
        tenant: &TenantId,
        issuance: asterius_domain::keys::AccessIssuance<'_>,
        claims: &serde_json::Value,
    ) -> Result<(), DomainError> {
        let Some(scope) = claims.get("scope").and_then(serde_json::Value::as_str) else { return Ok(()); };
        let enrollments = scope.split_ascii_whitespace().any(|scope| scope == asterius_domain::managed_devices::ENROLLMENT_SCOPE);
        let posture = scope.split_ascii_whitespace().any(|scope| scope == asterius_domain::managed_devices::POSTURE_SCOPE);
        if !enrollments && !posture { return Ok(()); }
        let grant = issuance.grant;
        if issuance.kind != asterius_domain::GrantType::ClientCredentials || grant.tenant != *tenant
            || grant.user.is_some() || grant.subject.is_some() || grant.session.is_some()
            || grant.parent.is_some() || !grant.actor_chain.is_empty() || grant.task.is_some()
        { return Ok(()); }
        relay_client_on(connection, tenant, &grant.client).await?;
        if claims.get("client_id").and_then(serde_json::Value::as_str) != Some(grant.client.as_str())
            || claims.get("sub").and_then(serde_json::Value::as_str) != Some(grant.client.as_str())
        { return Err(DomainError::invalid("device_relay", "signed client context mismatch")); }
        let jti = claims.get("jti").and_then(serde_json::Value::as_str)
            .ok_or_else(|| DomainError::invalid("device_relay", "signed identifier required"))?;
        let credential = RelayCredential::from_verified(grant.client.clone(), jti)?;
        let expiry = claims.get("exp").and_then(serde_json::Value::as_i64)
            .and_then(|expiry| OffsetDateTime::from_unix_timestamp(expiry).ok())
            .ok_or_else(|| DomainError::invalid("device_relay", "signed expiry required"))?;
        let now: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *connection).await.map_err(to_domain_error)?;
        if expiry <= now { return Err(DomainError::invalid("device_relay", "signed authority expired")); }
        let current: Option<bool> = sqlx::query_scalar(
            "select user_id is null and subject is null and session_id is null and parent_grant_id is null \
             and actor_chain='[]'::jsonb and revoked_at is null and claimed_at is not null \
             and (expires_at is null or expires_at>clock_timestamp()) \
             and not exists(select 1 from agent_task_grants t where t.tenant_id=g.tenant_id and t.grant_id=g.grant_id) \
             from grants g where tenant_id=$1 and grant_id=$2 and client_id=$3 for share"
        ).bind(tenant.as_str()).bind(crate::grants::uuid(&grant.id)?).bind(grant.client.as_str())
            .fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
        if current != Some(true) { return Err(DomainError::invalid("device_relay", "current root client grant required")); }
        sqlx::query("insert into managed_device_relay_tokens(tenant_id,jti,grant_id,client_id,enrollments,posture,expires_at) \
            values($1,$2,$3,$4,$5,$6,$7)")
            .bind(tenant.as_str()).bind(credential.jti()).bind(crate::grants::uuid(&grant.id)?)
            .bind(grant.client.as_str()).bind(enrollments).bind(posture).bind(expiry)
            .execute(connection).await.map_err(to_domain_error)?;
        Ok(())
    }

    /// Authentication adapter's cheap current mode check. Lifecycle writers
    /// repeat it with exact grant row locks after publication/source lock waits.
    ///
    /// # Errors
    /// Storage failure never acquires service authority.
    pub async fn relay_token_current(&self, tenant: &TenantId, client: &ClientId, jti: &str) -> Result<bool, DomainError> {
        Self::relay_token_current_in(&self.pool, tenant, client, jti).await
    }

    /// Verify a private successful-issuance receipt before accepting relay authority.
    pub async fn relay_token_current_in(pool: &PgPool, tenant: &TenantId, client: &ClientId, jti: &str) -> Result<bool, DomainError> {
        let mut connection = pool.acquire().await.map_err(to_domain_error)?;
        relay_token_current_on(&mut connection, tenant, client, jti).await
    }

}

async fn relay_token_current_on(
    connection: &mut PgConnection, tenant: &TenantId, client: &ClientId, jti: &str,
) -> Result<bool, DomainError> {
    let current: bool = sqlx::query_scalar(
        "select exists(select 1 from managed_device_relay_tokens r join grants g \
         on g.tenant_id=r.tenant_id and g.grant_id=r.grant_id \
         where r.tenant_id=$1 and r.client_id=$2 and r.jti=$3 and r.expires_at>clock_timestamp() \
         and g.client_id=r.client_id and g.revoked_at is null and g.user_id is null and g.subject is null \
         and g.parent_grant_id is null and g.session_id is null and g.actor_chain='[]'::jsonb \
         and (g.expires_at is null or g.expires_at>clock_timestamp()) \
         and not exists(select 1 from agent_task_grants t where t.tenant_id=g.tenant_id and t.grant_id=g.grant_id))"
    ).bind(tenant.as_str()).bind(client.as_str()).bind(jti).fetch_one(connection).await.map_err(to_domain_error)?;
    Ok(current)
}

async fn require_relay_credential_on(
    connection: &mut PgConnection, tenant: &TenantId, credential: &RelayCredential, enrollment: bool,
) -> Result<(), DomainError> {
    let grant: Option<Uuid> = sqlx::query_scalar(
        "select grant_id from managed_device_relay_tokens where tenant_id=$1 and client_id=$2 and jti=$3"
    ).bind(tenant.as_str()).bind(credential.client().as_str()).bind(credential.jti())
        .fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
    let grant = grant.ok_or(DomainError::NotFound)?;
    let locked: Option<Uuid> = sqlx::query_scalar("select grant_id from grants where tenant_id=$1 and grant_id=$2 for share")
        .bind(tenant.as_str()).bind(grant).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
    if locked.is_none() { return Err(DomainError::NotFound); }
    if !relay_token_current_on(connection, tenant, credential.client(), credential.jti()).await? {
        return Err(DomainError::NotFound);
    }
    let permitted: Option<bool> = sqlx::query_scalar(
        "select case when $4 then enrollments else posture end from managed_device_relay_tokens \
         where tenant_id=$1 and client_id=$2 and jti=$3 and expires_at>clock_timestamp() for share"
    ).bind(tenant.as_str()).bind(credential.client().as_str()).bind(credential.jti()).bind(enrollment)
        .fetch_optional(connection).await.map_err(to_domain_error)?;
    if permitted != Some(true) { return Err(DomainError::NotFound); }
    Ok(())
}

/// Capture only on the stable PAR row AND its current browser arrival. The
/// caller supplies a verifier-owned certificate, never a browser fingerprint.
pub(crate) async fn capture_interaction(
    pool: &PgPool,
    tenant: &TenantId,
    interaction_digest: &str,
    certificate: &asterius_domain::managed_devices::DeviceCertificateEvidence,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    use asterius_domain::managed_devices::{DeviceBinding, VerifiedDeviceEvidence};
    let interaction = hex::decode(interaction_digest).map_err(|_| DomainError::NotFound)?;
    if interaction.len() != 32 { return Err(DomainError::NotFound); }
    let mut transaction = pool.begin().await.map_err(to_domain_error)?;
    let active: Option<String> = sqlx::query_scalar("select tenant_id from tenants where tenant_id=$1 and status='active' for share")
        .bind(tenant.as_str()).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
    if active.is_none() { return Err(DomainError::NotFound); }
    let request: Option<(Vec<u8>, String, String, OffsetDateTime)> = sqlx::query_as(
        "select request_uri_hash,client_id,session_id,expires_at from auth_requests \
         where tenant_id=$1 and interaction_id_hash=$2 and consumed_at is null \
         and expires_at>clock_timestamp() and session_id is not null for update"
    ).bind(tenant.as_str()).bind(&interaction).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
    let Some((request, client, session, request_expiry)) = request else { return Err(DomainError::NotFound); };
    let user: Option<Uuid> = sqlx::query_scalar(
        "select user_id from sessions where tenant_id=$1 and session_id=$2 and revoked_at is null \
         and expires_at>clock_timestamp() and idle_expires_at>clock_timestamp() for share"
    ).bind(tenant.as_str()).bind(session).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
    let user = user.ok_or(DomainError::NotFound)?;
    let device: Option<(Uuid, Uuid, i64, i64, String)> = sqlx::query_as(
        "select d.device_id,d.source_id,d.source_generation,d.enrollment_generation,s.client_id \
         from managed_devices d join managed_device_sources s using(tenant_id,source_id) \
         where d.tenant_id=$1 and d.leaf_sha256=$2 and d.user_id=$3 and $4=any(d.allowed_client_ids) \
         and d.removed_at is null and s.enabled and s.generation=d.source_generation for share of d,s"
    ).bind(tenant.as_str()).bind(hex::decode(certificate.leaf.as_str()).map_err(|_| DomainError::NotFound)?)
        .bind(user).bind(&client).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
    let Some((device, source, source_generation, enrollment_generation, source_client)) = device else {
        transaction.commit().await.map_err(to_domain_error)?;
        return Ok(());
    };
    relay_client_on(&mut transaction, tenant, &ClientId::new(source_client)).await?;
    let active: Option<String> = sqlx::query_scalar("select client_id from clients where tenant_id=$1 and client_id=$2 and status='active' for share")
        .bind(tenant.as_str()).bind(&client).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
    let user_active: Option<Uuid> = sqlx::query_scalar("select user_id from users where tenant_id=$1 and user_id=$2 and status='active' for share")
        .bind(tenant.as_str()).bind(user).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
    if active.is_none() || user_active.is_none() { return Err(DomainError::NotFound); }
    let current: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
        .fetch_one(&mut *transaction).await.map_err(to_domain_error)?;
    if certificate.expires_at<=current || request_expiry<=current { return Err(DomainError::NotFound); }
    let existing: Option<Value> = sqlx::query_scalar(
        "select binding from managed_device_interaction_proofs where tenant_id=$1 and request_uri_hash=$2"
    ).bind(tenant.as_str()).bind(&request).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
    if let Some(existing) = existing {
        let existing: DeviceBinding = serde_json::from_value(existing).map_err(|_| DomainError::NotFound)?;
        existing.validate(current)?;
        if existing.interaction_digest()!=interaction_digest || existing.user()!=&UserId::new(user)
            || existing.client().as_str()!=client || existing.device()!=device
            || existing.anchor_sha256()!=certificate.anchor.as_str()
            || existing.enrollment_generation()!=enrollment_generation || existing.source_generation()!=source_generation
        { return Err(DomainError::NotFound); }
        // Repeated submissions never refresh the original five-minute proof.
    } else {
        let expiry = (now + time::Duration::seconds(300)).min(certificate.expires_at).min(request_expiry);
        let binding = DeviceBinding::from_verified(VerifiedDeviceEvidence {
            tenant: tenant.clone(), user: UserId::new(user), client: ClientId::new(client),
            interaction_digest: interaction_digest.to_owned(), source, source_generation,
            device, enrollment_generation, leaf_sha256: certificate.leaf.as_str().to_owned(),
            anchor_sha256: certificate.anchor.as_str().to_owned(), certificate_expires_at: certificate.expires_at,
            proof_expires_at: expiry,
        }, current)?;
        sqlx::query("insert into managed_device_interaction_proofs(tenant_id,request_uri_hash,interaction_id_hash,device_id,binding,expires_at) values($1,$2,$3,$4,$5,$6)")
            .bind(tenant.as_str()).bind(request).bind(interaction).bind(device)
            .bind(serde_json::to_value(binding).map_err(|_| DomainError::NotFound)?).bind(expiry)
            .execute(&mut *transaction).await.map_err(to_domain_error)?;
    }
    transaction.commit().await.map_err(to_domain_error)
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
