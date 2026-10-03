//! Candidate supplied-connection online authentication adapter, not yet exported.
//! Callers verify the ID signature before review and hold the publication fence
//! while recording a successfully signed identity assertion.

use asterius_domain::{ClientId, CompactJws, DomainError, Grant, TenantId, sha256};
use serde_json::Value;
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::to_domain_error;
use asterius_domain::kubernetes_online::{OnlineProfile, ProfileChange};

#[derive(Debug, Clone)]
pub struct PgKubernetesOnline {
    pool: sqlx::PgPool,
}

impl PgKubernetesOnline {
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self { Self { pool } }

    pub async fn profile(&self, tenant: &TenantId, client: &ClientId)
        -> Result<Option<OnlineProfile>, DomainError> {
        let row: Option<(String, Uuid, bool)> = sqlx::query_as(
            "select reviewer_client_id,revision,enabled from kubernetes_online_profiles where tenant_id=$1 and client_id=$2",
        ).bind(tenant.as_str()).bind(client.as_str()).fetch_optional(&self.pool)
            .await.map_err(to_domain_error)?;
        Ok(row.map(|(reviewer_client_id,revision,enabled)| OnlineProfile {reviewer_client_id,revision,enabled}))
    }

    pub async fn replace_profile(&self, tenant: &TenantId, client: &ClientId,
        actor: &asterius_domain::Actor, change: &ProfileChange)
        -> Result<OnlineProfile, DomainError> {
        change.validate()?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let anchor: Option<(String,)> = sqlx::query_as(
            "select tenant_id from tenants where tenant_id=$1 and status='active' for no key update",
        ).bind(tenant.as_str()).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if anchor.is_none() { return Err(DomainError::NotFound); }
        let valid: bool = sqlx::query_scalar(
            "select exists(select 1 from kubernetes_profiles p
              join clients c on c.tenant_id=p.tenant_id and c.client_id=p.client_id
              join clients r on r.tenant_id=p.tenant_id and r.client_id=$3
              where p.tenant_id=$1 and p.client_id=$2 and c.client_id<>r.client_id
                and c.status='active' and not c.is_agent and c.subject_type='public'
                and c.compliance_profile='oidc' and c.application_type='web'
                and c.token_endpoint_auth_method='private_key_jwt' and c.dpop_bound_access_tokens
                and c.id_token_signed_response_alg='ES256' and not c.encrypt_id_token
                and c.managed_groups_claim and cardinality(c.redirect_uris)=1
                and 'openid'=any(c.scopes) and 'authorization_code'=any(c.grant_types) and 'refresh_token'=any(c.grant_types)
                and r.status='active' and not r.is_agent and r.compliance_profile='fapi'
                and r.dpop_bound_access_tokens and r.token_endpoint_auth_method='private_key_jwt'
                and 'client_credentials'=any(r.grant_types) and 'admin.kubernetes_reviews:read'=any(r.scopes))",
        ).bind(tenant.as_str()).bind(client.as_str()).bind(&change.reviewer_client_id)
            .fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        if !valid { return Err(invalid()); }
        let row: Option<(String,Uuid,bool)> = if let Some(expected) = change.expected_revision {
            sqlx::query_as("update kubernetes_online_profiles set reviewer_client_id=$3,enabled=$4 where tenant_id=$1 and client_id=$2 and revision=$5 returning reviewer_client_id,revision,enabled")
                .bind(tenant.as_str()).bind(client.as_str()).bind(&change.reviewer_client_id)
                .bind(change.enabled).bind(expected).fetch_optional(&mut *tx).await.map_err(to_domain_error)?
        } else {
            sqlx::query_as("insert into kubernetes_online_profiles(tenant_id,client_id,reviewer_client_id,enabled) values($1,$2,$3,$4) on conflict(tenant_id,client_id) do nothing returning reviewer_client_id,revision,enabled")
                .bind(tenant.as_str()).bind(client.as_str()).bind(&change.reviewer_client_id)
                .bind(change.enabled).fetch_optional(&mut *tx).await.map_err(to_domain_error)?
        };
        let (reviewer_client_id,revision,enabled) = row.ok_or_else(|| DomainError::Conflict("online profile revision changed".into()))?;
        let (now,): (OffsetDateTime,) = sqlx::query_as("select clock_timestamp()")
            .fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        crate::audit::append(&mut tx,asterius_domain::AuditEvent::new(
            tenant.clone(),asterius_domain::EventType::ADMIN_CHANGED,
            asterius_domain::Outcome::Success,actor.clone(),now,
        ).detail(asterius_domain::Detail::new().text("operation","kubernetes_online.profile")
            .text("client_id",client.as_str()).text("revision",revision.to_string())
            .text("enabled",enabled.to_string()))).await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(OnlineProfile {reviewer_client_id,revision,enabled})
    }
}

/// Only a selected public ES256 key is read; no signing credential is exposed.
pub async fn public_key_on(connection: &mut PgConnection, tenant: &TenantId,
    kid: &str) -> Result<Option<Value>, DomainError> {
    if kid.is_empty() || kid.len()>1024 { return Ok(None); }
    let row: Option<(String,Value)> = sqlx::query_as(
        "select state,public_jwk from signing_keys where tenant_id=$1 and kid=$2 and purpose='sig' and alg='ES256'",
    ).bind(tenant.as_str()).bind(kid).fetch_optional(connection).await.map_err(to_domain_error)?;
    Ok(row.and_then(|(state,key)| asterius_domain::KeyState::parse(&state)
        .filter(|state|state.is_trusted()).map(|_|key)))
}

#[derive(Debug)]
pub struct OnlineIdentity {
    pub username: String,
    pub groups: Vec<String>,
}

fn invalid() -> DomainError {
    DomainError::invalid("kubernetes_online", "current exact online identity required")
}

pub async fn enabled_on(connection: &mut PgConnection, tenant: &TenantId,
    client: &ClientId) -> Result<bool, DomainError> {
    sqlx::query_scalar("select exists(select 1 from kubernetes_online_profiles where tenant_id=$1 and client_id=$2 and enabled)")
        .bind(tenant.as_str()).bind(client.as_str()).fetch_one(connection).await.map_err(to_domain_error)
}

/// Persist only the digest of the complete, successfully signed compact ID JWT.
/// An enabled profile never falls back to an unbound identity on storage failure.
/// The transaction is the signer's existing publication transaction.
pub async fn record_signed_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    grant: &Grant,
    signed: &CompactJws,
    claims: &Value,
) -> Result<(), DomainError> {
    let enabled = enabled_on(connection,tenant,&grant.client).await?;
    if !enabled {
        return Ok(());
    }
    let user = grant.user.as_ref().ok_or_else(invalid)?;
    let subject = grant.subject.as_ref().ok_or_else(invalid)?;
    let session = grant.session.as_ref().ok_or_else(invalid)?;
    if grant.tenant != *tenant
        || signed.as_str().len() > 16384
        || claims.get("asterius_jit").is_some()
        || claims.get("aud").and_then(Value::as_str) != Some(grant.client.as_str())
        || claims.get("sub").and_then(Value::as_str) != Some(subject.as_str())
        || claims.get("sid").and_then(Value::as_str) != Some(session.as_str())
    {
        return Err(invalid());
    }
    let issued_at = claims.get("iat").and_then(Value::as_i64).ok_or_else(invalid)?;
    let expires_at = claims.get("exp").and_then(Value::as_i64).ok_or_else(invalid)?;
    if expires_at <= issued_at || expires_at.saturating_sub(issued_at) > 300 {
        return Err(invalid());
    }
    let issued_at = OffsetDateTime::from_unix_timestamp(issued_at).map_err(|_| invalid())?;
    let expires_at = OffsetDateTime::from_unix_timestamp(expires_at).map_err(|_| invalid())?;
    let digest = sha256(signed.as_str().as_bytes());
    // All identifiers are joined to authoritative current rows. The stable sid
    // survives cookie rotation, while logout, expiry and account disable refuse.
    let inserted: Option<(Uuid,)> = sqlx::query_as(
        "insert into kubernetes_online_tokens(tenant_id,token_digest,client_id,grant_id,user_id,public_sid,subject,profile_revision,cluster_profile_revision,reviewer_client_id,issued_at,expires_at)
         select p.tenant_id,$2,p.client_id,g.grant_id,u.user_id,s.public_sid,g.subject,p.revision,k.revision,p.reviewer_client_id,$8,$9
         from kubernetes_online_profiles p
         join kubernetes_profiles k on k.tenant_id=p.tenant_id and k.client_id=p.client_id
         join tenants t on t.tenant_id=p.tenant_id and t.status='active'
         join clients c on c.tenant_id=p.tenant_id and c.client_id=p.client_id
         join clients r on r.tenant_id=p.tenant_id and r.client_id=p.reviewer_client_id
         join grants g on g.tenant_id=p.tenant_id and g.client_id=p.client_id and g.grant_id=$4
         join users u on u.tenant_id=g.tenant_id and u.user_id=g.user_id and u.user_id=$5
         join sessions s on s.tenant_id=g.tenant_id and s.public_sid=g.session_id and s.public_sid=$6 and s.user_id=u.user_id
         where p.tenant_id=$1 and p.client_id=$3 and p.enabled
           and g.subject=$7 and g.claimed_at is not null and g.revoked_at is null
           and (g.expires_at is null or g.expires_at>clock_timestamp())
           and u.status='active' and s.revoked_at is null
           and s.expires_at>clock_timestamp() and s.idle_expires_at>clock_timestamp()
           and c.status='active' and not c.is_agent and c.subject_type='public'
           and c.compliance_profile='oidc' and c.id_token_signed_response_alg='ES256'
           and not c.encrypt_id_token and c.managed_groups_claim
           and r.status='active' and not r.is_agent and r.compliance_profile='fapi' and r.dpop_bound_access_tokens
           and r.token_endpoint_auth_method='private_key_jwt' and 'client_credentials'=any(r.grant_types)
           and 'admin.kubernetes_reviews:read'=any(r.scopes)
           and $9>clock_timestamp() and $8<=clock_timestamp()+interval '30 seconds'
         on conflict(tenant_id,token_digest) do nothing returning grant_id",
    )
    .bind(tenant.as_str())
    .bind(digest.as_slice())
    .bind(grant.client.as_str())
    .bind(Uuid::parse_str(grant.id.as_str()).map_err(|_| invalid())?)
    .bind(user.as_uuid())
    .bind(session.as_str())
    .bind(subject.as_str())
    .bind(issued_at)
    .bind(expires_at)
    .fetch_optional(&mut *connection)
    .await
    .map_err(to_domain_error)?;
    if inserted.is_none() {
        return Err(invalid());
    }
    Ok(())
}

/// Read current authority after signature validation. No session heartbeat, new
/// binding, audit write or grant mutation occurs on this authentication path.
pub async fn review_verified_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    reviewer: &ClientId,
    client: &ClientId,
    compact: &str,
    claims: &Value,
) -> Result<Option<OnlineIdentity>, DomainError> {
    let Some(subject) = claims.get("sub").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some(expiry) = claims.get("exp").and_then(Value::as_i64) else {
        return Ok(None);
    };
    if claims.get("aud").and_then(Value::as_str) != Some(client.as_str())
        || claims.get("asterius_jit").is_some()
        || compact.len()>16384
    {
        return Ok(None);
    }
    let expiry = OffsetDateTime::from_unix_timestamp(expiry).map_err(|_| invalid())?;
    let digest = sha256(compact.as_bytes());
    // One primary-database statement supplies a consistent authority snapshot.
    // Removed directory memberships narrow issued groups; new ones cannot add.
    let row: Option<(String, String, Vec<Uuid>)> = sqlx::query_as(
        "select k.cluster_id,b.subject,
                array(select gm.group_id from group_memberships gm
                      where gm.tenant_id=b.tenant_id and gm.user_id=b.user_id
                        and gm.group_id=any(k.group_ids) order by gm.group_id)
         from kubernetes_online_tokens b
         join kubernetes_online_profiles p on p.tenant_id=b.tenant_id and p.client_id=b.client_id and p.revision=b.profile_revision
         join kubernetes_profiles k on k.tenant_id=b.tenant_id and k.client_id=b.client_id and k.revision=b.cluster_profile_revision
         join tenants t on t.tenant_id=b.tenant_id and t.status='active'
         join clients c on c.tenant_id=b.tenant_id and c.client_id=b.client_id
         join clients r on r.tenant_id=p.tenant_id and r.client_id=p.reviewer_client_id
         join grants g on g.tenant_id=b.tenant_id and g.grant_id=b.grant_id and g.client_id=b.client_id and g.user_id=b.user_id and g.subject=b.subject and g.session_id=b.public_sid
         join users u on u.tenant_id=b.tenant_id and u.user_id=b.user_id
         join sessions s on s.tenant_id=b.tenant_id and s.public_sid=b.public_sid and s.user_id=b.user_id
         where b.tenant_id=$1 and b.token_digest=$2 and b.client_id=$3 and b.subject=$4 and b.expires_at=$5
           and p.enabled and p.reviewer_client_id=$6 and b.reviewer_client_id=$6
           and b.expires_at>clock_timestamp() and g.claimed_at is not null and g.revoked_at is null
           and (g.expires_at is null or g.expires_at>clock_timestamp())
           and u.status='active' and s.revoked_at is null and s.expires_at>clock_timestamp() and s.idle_expires_at>clock_timestamp()
           and c.status='active' and not c.is_agent and c.subject_type='public' and c.compliance_profile='oidc'
           and c.id_token_signed_response_alg='ES256' and not c.encrypt_id_token and c.managed_groups_claim
           and r.status='active' and not r.is_agent and r.compliance_profile='fapi' and r.dpop_bound_access_tokens
           and r.token_endpoint_auth_method='private_key_jwt' and 'client_credentials'=any(r.grant_types)
           and 'admin.kubernetes_reviews:read'=any(r.scopes)",
    )
    .bind(tenant.as_str())
    .bind(digest.as_slice())
    .bind(client.as_str())
    .bind(subject)
    .bind(expiry)
    .bind(reviewer.as_str())
    .fetch_optional(&mut *connection)
    .await
    .map_err(to_domain_error)?;
    let Some((cluster, subject, current)) = row else {
        return Ok(None);
    };
    let Some(issued) = claims.get("group_ids").and_then(Value::as_array) else {
        return Ok(None);
    };
    if issued.len()>100 {
        return Ok(None);
    }
    let mut issued_groups = std::collections::BTreeSet::new();
    for value in issued {
        let Some(value) = value.as_str() else { return Ok(None); };
        let Some(raw) = value.strip_prefix("group:") else { return Ok(None); };
        let Ok(id) = Uuid::parse_str(raw) else { return Ok(None); };
        if id.to_string()!=raw || !issued_groups.insert(id) {
            return Ok(None);
        }
    }
    let prefix = format!("asterius:{}:{cluster}:",tenant.as_str());
    Ok(Some(OnlineIdentity {
        username: format!("{prefix}{subject}"),
        groups: current.into_iter().filter(|id| issued_groups.contains(id))
            .map(|id|format!("{prefix}group:group:{id}")).collect(),
    }))
}
