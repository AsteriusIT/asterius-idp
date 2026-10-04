//! Candidate supplied-connection online authentication adapter pending delivery review.
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
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    pub async fn reviewer_token_current(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        jti: &str,
    ) -> Result<bool, DomainError> {
        let mut connection = self.pool.acquire().await.map_err(to_domain_error)?;
        reviewer_token_current_on(&mut connection, tenant, client, jti).await
    }

    pub async fn begin_review(&self) -> Result<OnlineReview<'_>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query("set transaction read only")
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        sqlx::query("set local statement_timeout = '2800ms'")
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        Ok(OnlineReview { tx })
    }

    pub async fn profile(
        &self,
        tenant: &TenantId,
        client: &ClientId,
    ) -> Result<Option<OnlineProfile>, DomainError> {
        let row: Option<(String, Uuid, bool)> = sqlx::query_as(
            "select reviewer_client_id,revision,enabled from kubernetes_online_profiles where tenant_id=$1 and client_id=$2",
        ).bind(tenant.as_str()).bind(client.as_str()).fetch_optional(&self.pool)
            .await.map_err(to_domain_error)?;
        Ok(
            row.map(|(reviewer_client_id, revision, enabled)| OnlineProfile {
                reviewer_client_id,
                revision,
                enabled,
            }),
        )
    }

    pub async fn replace_profile(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        actor: &asterius_domain::Actor,
        change: &ProfileChange,
    ) -> Result<OnlineProfile, DomainError> {
        change.validate()?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let anchor: Option<(String,)> = sqlx::query_as(
            "select tenant_id from tenants where tenant_id=$1 and status='active' for no key update",
        ).bind(tenant.as_str()).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if anchor.is_none() {
            return Err(DomainError::NotFound);
        }
        let valid: bool = sqlx::query_scalar(
            "select exists(select 1 from kubernetes_profiles p
              join clients c on c.tenant_id=p.tenant_id and c.client_id=p.client_id
              join clients r on r.tenant_id=p.tenant_id and r.client_id=$3
              where p.tenant_id=$1 and p.client_id=$2 and c.client_id<>r.client_id
                and not exists(select 1 from agent_task_clients task where task.tenant_id=c.tenant_id and task.client_id=c.client_id)
           and not exists(select 1 from agent_task_clients task where task.tenant_id=r.tenant_id and task.client_id=r.client_id)
           and c.status='active' and not c.is_agent and c.subject_type='public'
                and c.compliance_profile='oidc' and c.application_type='web'
                and c.token_endpoint_auth_method='private_key_jwt' and c.dpop_bound_access_tokens
                and c.id_token_signed_response_alg='ES256' and not c.encrypt_id_token
                and c.managed_groups_claim and cardinality(c.redirect_uris)=1
                and 'openid'=any(c.scopes) and 'authorization_code'=any(c.grant_types) and 'refresh_token'=any(c.grant_types)
                and r.status='active' and not r.is_agent and r.compliance_profile='fapi'
                and r.dpop_bound_access_tokens and r.token_endpoint_auth_method='private_key_jwt'
                and r.grant_types=ARRAY['client_credentials']::text[] and 'admin.kubernetes_reviews:read'=any(r.scopes))",
        ).bind(tenant.as_str()).bind(client.as_str()).bind(&change.reviewer_client_id)
            .fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        if !valid {
            return Err(invalid());
        }
        if change.enabled {
            let jit: bool = sqlx::query_scalar("select exists(select 1 from temporary_kubernetes_bindings where tenant_id=$1 and cluster_client_id=$2 and enabled)")
                .bind(tenant.as_str()).bind(client.as_str()).fetch_one(&mut *tx).await.map_err(to_domain_error)?;
            if jit {
                return Err(DomainError::Conflict(
                    "online and temporary Kubernetes modes cannot be enabled together".into(),
                ));
            }
        }
        let row: Option<(String, Uuid, bool)> = if let Some(expected) = change.expected_revision {
            sqlx::query_as("update kubernetes_online_profiles set reviewer_client_id=$3,enabled=$4 where tenant_id=$1 and client_id=$2 and revision=$5 returning reviewer_client_id,revision,enabled")
                .bind(tenant.as_str()).bind(client.as_str()).bind(&change.reviewer_client_id)
                .bind(change.enabled).bind(expected).fetch_optional(&mut *tx).await.map_err(to_domain_error)?
        } else {
            sqlx::query_as("insert into kubernetes_online_profiles(tenant_id,client_id,reviewer_client_id,enabled) values($1,$2,$3,$4) on conflict(tenant_id,client_id) do nothing returning reviewer_client_id,revision,enabled")
                .bind(tenant.as_str()).bind(client.as_str()).bind(&change.reviewer_client_id)
                .bind(change.enabled).fetch_optional(&mut *tx).await.map_err(to_domain_error)?
        };
        let (reviewer_client_id, revision, enabled) =
            row.ok_or_else(|| DomainError::Conflict("online profile revision changed".into()))?;
        let (now,): (OffsetDateTime,) = sqlx::query_as("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        crate::audit::append(
            &mut tx,
            asterius_domain::AuditEvent::new(
                tenant.clone(),
                asterius_domain::EventType::ADMIN_CHANGED,
                asterius_domain::Outcome::Success,
                actor.clone(),
                now,
            )
            .detail(
                asterius_domain::Detail::new()
                    .text("operation", "kubernetes_online.profile")
                    .text("client_id", client.as_str())
                    .text("revision", revision.to_string())
                    .text("enabled", enabled.to_string()),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(OnlineProfile {
            reviewer_client_id,
            revision,
            enabled,
        })
    }
}

#[derive(Debug)]
pub struct OnlineReview<'a> {
    tx: sqlx::Transaction<'a, sqlx::Postgres>,
}
impl OnlineReview<'_> {
    pub async fn public_key(
        &mut self,
        tenant: &TenantId,
        kid: &str,
    ) -> Result<Option<Value>, DomainError> {
        public_key_on(&mut self.tx, tenant, kid).await
    }
    pub async fn review(
        &mut self,
        tenant: &TenantId,
        reviewer: &ClientId,
        client: &ClientId,
        compact: &str,
        claims: &Value,
    ) -> Result<Option<OnlineIdentity>, DomainError> {
        review_verified_on(&mut self.tx, tenant, reviewer, client, compact, claims).await
    }
    pub async fn commit(self) -> Result<(), DomainError> {
        self.tx.commit().await.map_err(to_domain_error)
    }
}

/// Only a selected public ES256 key is read; no signing credential is exposed.
pub async fn public_key_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    kid: &str,
) -> Result<Option<Value>, DomainError> {
    if kid.is_empty() || kid.len() > 1024 {
        return Ok(None);
    }
    let row: Option<(String,Value)> = sqlx::query_as(
        "select state,public_jwk from signing_keys where tenant_id=$1 and kid=$2 and purpose='sig' and alg='ES256'",
    ).bind(tenant.as_str()).bind(kid).fetch_optional(connection).await.map_err(to_domain_error)?;
    Ok(row.and_then(|(state, key)| {
        asterius_domain::KeyState::parse(&state)
            .filter(|state| state.is_trusted())
            .map(|_| key)
    }))
}

#[derive(Debug)]
pub struct OnlineIdentity {
    pub username: String,
    pub groups: Vec<String>,
}

fn invalid() -> DomainError {
    DomainError::invalid(
        "kubernetes_online",
        "current exact online identity required",
    )
}

pub async fn enabled_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    client: &ClientId,
) -> Result<bool, DomainError> {
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
    let enabled = enabled_on(connection, tenant, &grant.client).await?;
    if !enabled {
        return Ok(());
    }
    let user = grant.user.as_ref().ok_or_else(invalid)?;
    let subject = grant.subject.as_ref().ok_or_else(invalid)?;
    let session_lookup = grant.session.as_ref().ok_or_else(invalid)?;
    let public_sid = claims
        .get("sid")
        .and_then(Value::as_str)
        .filter(|sid| !sid.is_empty() && sid.len() <= 2048)
        .ok_or_else(invalid)?;
    if grant.task.is_some()
        || grant.parent.is_some()
        || !grant.actor_chain.is_empty()
        || grant.tenant != *tenant
        || signed.as_str().len() > 16384
        || claims.get("asterius_jit").is_some()
        || claims.get("aud").and_then(Value::as_str) != Some(grant.client.as_str())
        || claims.get("sub").and_then(Value::as_str) != Some(subject.as_str())
    {
        return Err(invalid());
    }
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(invalid)?;
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(invalid)?;
    if expires_at <= issued_at || expires_at.saturating_sub(issued_at) > 300 {
        return Err(invalid());
    }
    let issued_at = OffsetDateTime::from_unix_timestamp(issued_at).map_err(|_| invalid())?;
    let expires_at = OffsetDateTime::from_unix_timestamp(expires_at).map_err(|_| invalid())?;
    let digest = sha256(signed.as_str().as_bytes());
    // All identifiers are joined to authoritative current rows. The stable sid
    // survives cookie rotation, while logout, expiry and account disable refuse.
    // Grant.session is the private lookup digest, never the public signed sid.
    // Both must identify this exact authoritative session; neither substitutes
    // for the other, and no same-user session can repair a missing association.
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
         join sessions s on s.tenant_id=g.tenant_id and s.session_id=g.session_id and s.session_id=$10 and s.public_sid=$6 and s.user_id=u.user_id
         where p.tenant_id=$1 and p.client_id=$3 and p.enabled
           and g.subject=$7 and g.claimed_at is not null and g.revoked_at is null
           and (g.expires_at is null or g.expires_at>clock_timestamp())
           and g.parent_grant_id is null and g.actor_chain='[]'::jsonb
           and not exists(select 1 from agent_task_grants task where task.tenant_id=g.tenant_id and task.grant_id=g.grant_id)
           and u.status='active' and s.revoked_at is null
           and s.expires_at>clock_timestamp() and s.idle_expires_at>clock_timestamp()
           and not exists(select 1 from agent_task_clients task where task.tenant_id=c.tenant_id and task.client_id=c.client_id)
           and not exists(select 1 from agent_task_clients task where task.tenant_id=r.tenant_id and task.client_id=r.client_id)
           and c.status='active' and not c.is_agent and c.subject_type='public'
           and c.compliance_profile='oidc' and c.application_type='web'
           and c.token_endpoint_auth_method='private_key_jwt' and c.dpop_bound_access_tokens
           and cardinality(c.redirect_uris)=1 and 'openid'=any(c.scopes)
           and 'authorization_code'=any(c.grant_types) and 'refresh_token'=any(c.grant_types)
           and c.id_token_signed_response_alg='ES256'
           and not c.encrypt_id_token and c.managed_groups_claim
           and r.status='active' and not r.is_agent and r.compliance_profile='fapi' and r.dpop_bound_access_tokens
           and r.token_endpoint_auth_method='private_key_jwt' and r.grant_types=ARRAY['client_credentials']::text[]
           and 'admin.kubernetes_reviews:read'=any(r.scopes)
           and $9>clock_timestamp() and $8<=clock_timestamp()+interval '30 seconds'
         on conflict(tenant_id,token_digest) do nothing returning grant_id",
    )
    .bind(tenant.as_str())
    .bind(digest.as_slice())
    .bind(grant.client.as_str())
    .bind(Uuid::parse_str(grant.id.as_str()).map_err(|_| invalid())?)
    .bind(user.as_uuid())
    .bind(public_sid)
    .bind(subject.as_str())
    .bind(issued_at)
    .bind(expires_at)
    .bind(session_lookup.as_str())
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
        || compact.len() > 16384
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
         join grants g on g.tenant_id=b.tenant_id and g.grant_id=b.grant_id and g.client_id=b.client_id and g.user_id=b.user_id and g.subject=b.subject
         join users u on u.tenant_id=b.tenant_id and u.user_id=b.user_id
         join sessions s on s.tenant_id=b.tenant_id and s.session_id=g.session_id and s.public_sid=b.public_sid and s.user_id=b.user_id
         where b.tenant_id=$1 and b.token_digest=$2 and b.client_id=$3 and b.subject=$4 and b.expires_at=$5
           and p.enabled and p.reviewer_client_id=$6 and b.reviewer_client_id=$6
           and b.expires_at>clock_timestamp() and g.claimed_at is not null and g.revoked_at is null
           and (g.expires_at is null or g.expires_at>clock_timestamp())
           and g.parent_grant_id is null and g.actor_chain='[]'::jsonb
           and not exists(select 1 from agent_task_grants task where task.tenant_id=g.tenant_id and task.grant_id=g.grant_id)
           and u.status='active' and s.revoked_at is null and s.expires_at>clock_timestamp() and s.idle_expires_at>clock_timestamp()
           and not exists(select 1 from agent_task_clients task where task.tenant_id=c.tenant_id and task.client_id=c.client_id)
           and not exists(select 1 from agent_task_clients task where task.tenant_id=r.tenant_id and task.client_id=r.client_id)
           and c.status='active' and not c.is_agent and c.subject_type='public' and c.compliance_profile='oidc'
           and c.application_type='web' and c.token_endpoint_auth_method='private_key_jwt'
           and c.dpop_bound_access_tokens and cardinality(c.redirect_uris)=1
           and 'openid'=any(c.scopes) and 'authorization_code'=any(c.grant_types)
           and 'refresh_token'=any(c.grant_types)
           and c.id_token_signed_response_alg='ES256' and not c.encrypt_id_token and c.managed_groups_claim
           and r.status='active' and not r.is_agent and r.compliance_profile='fapi' and r.dpop_bound_access_tokens
           and r.token_endpoint_auth_method='private_key_jwt' and r.grant_types=ARRAY['client_credentials']::text[]
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
    if issued.len() > 100 {
        return Ok(None);
    }
    let mut issued_groups = std::collections::BTreeSet::new();
    for value in issued {
        let Some(value) = value.as_str() else {
            return Ok(None);
        };
        let Some(raw) = value.strip_prefix("group:") else {
            return Ok(None);
        };
        let Ok(id) = Uuid::parse_str(raw) else {
            return Ok(None);
        };
        if id.to_string() != raw || !issued_groups.insert(id) {
            return Ok(None);
        }
    }
    let prefix = format!("asterius:{}:{cluster}:", tenant.as_str());
    Ok(Some(OnlineIdentity {
        username: format!("{prefix}{subject}"),
        groups: current
            .into_iter()
            .filter(|id| issued_groups.contains(id))
            .map(|id| format!("{prefix}group:group:{id}"))
            .collect(),
    }))
}

/// Successful CC issuance is a private receipt; never inferred from public sub.
pub async fn record_reviewer_token_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    issuance: asterius_domain::keys::AccessIssuance<'_>,
    claims: &Value,
) -> Result<(), DomainError> {
    let scope = claims
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !scope
        .split_ascii_whitespace()
        .any(|scope| scope == asterius_domain::kubernetes_online::REVIEW_SCOPE)
    {
        return Ok(());
    }
    let grant = issuance.grant;
    if issuance.kind != asterius_domain::GrantType::ClientCredentials
        || grant.tenant != *tenant
        || grant.user.is_some()
        || grant.parent.is_some()
        || grant.task.is_some()
        || !grant.actor_chain.is_empty()
        || claims.get("act").is_some()
        || claims.get("client_id").and_then(Value::as_str) != Some(grant.client.as_str())
        || claims.get("sub").and_then(Value::as_str) != Some(grant.client.as_str())
    {
        return Err(invalid());
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|jti| !jti.is_empty() && jti.len() <= 1024)
        .ok_or_else(invalid)?;
    let expires = OffsetDateTime::from_unix_timestamp(
        claims
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
    let issuer: Option<(String,)> =
        sqlx::query_as("select issuer from tenants where tenant_id=$1 and status='active'")
            .bind(tenant.as_str())
            .fetch_optional(&mut *connection)
            .await
            .map_err(to_domain_error)?;
    let issuer = issuer.ok_or_else(invalid)?.0;
    let resource = format!("{issuer}/admin/api/v1");
    let audience = claims.get("aud").is_some_and(|aud| match aud {
        Value::String(aud) => aud == &resource,
        Value::Array(aud) => aud
            .iter()
            .any(|aud| aud.as_str() == Some(resource.as_str())),
        _ => false,
    });
    if !audience || claims.get("iss").and_then(Value::as_str) != Some(issuer.as_str()) {
        return Err(invalid());
    }
    let receipt:Option<(Uuid,)> = sqlx::query_as("insert into kubernetes_online_reviewer_tokens(tenant_id,jti_digest,grant_id,client_id,expires_at)
        select g.tenant_id,$2,g.grant_id,g.client_id,$5 from grants g
        join clients c on c.tenant_id=g.tenant_id and c.client_id=g.client_id
        where g.tenant_id=$1 and g.grant_id=$3 and g.client_id=$4 and g.user_id is null
          and g.parent_grant_id is null and g.actor_chain='[]'::jsonb and g.claimed_at is not null
          and g.revoked_at is null and (g.expires_at is null or g.expires_at>clock_timestamp())
          and not exists(select 1 from agent_task_grants task where task.tenant_id=g.tenant_id and task.grant_id=g.grant_id)
          and not exists(select 1 from agent_task_clients task where task.tenant_id=c.tenant_id and task.client_id=c.client_id)
          and c.status='active' and not c.is_agent and c.compliance_profile='fapi'
          and c.token_endpoint_auth_method='private_key_jwt' and c.dpop_bound_access_tokens
          and c.grant_types=ARRAY['client_credentials']::text[] and 'admin.kubernetes_reviews:read'=any(c.scopes)
          and $5>clock_timestamp() returning grant_id")
        .bind(tenant.as_str()).bind(sha256(jti.as_bytes()).as_slice())
        .bind(Uuid::parse_str(grant.id.as_str()).map_err(|_|invalid())?).bind(grant.client.as_str()).bind(expires)
        .fetch_optional(connection).await.map_err(to_domain_error)?;
    if receipt.is_none() {
        return Err(invalid());
    }
    Ok(())
}

pub async fn reviewer_token_current_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    client: &ClientId,
    jti: &str,
) -> Result<bool, DomainError> {
    if jti.is_empty() || jti.len() > 1024 {
        return Ok(false);
    }
    sqlx::query_scalar("select exists(select 1 from kubernetes_online_reviewer_tokens b
        join grants g on g.tenant_id=b.tenant_id and g.grant_id=b.grant_id and g.client_id=b.client_id
        join clients c on c.tenant_id=b.tenant_id and c.client_id=b.client_id
        join tenants t on t.tenant_id=b.tenant_id and t.status='active'
        where b.tenant_id=$1 and b.client_id=$2 and b.jti_digest=$3 and b.expires_at>clock_timestamp()
          and g.user_id is null and g.parent_grant_id is null and g.actor_chain='[]'::jsonb
          and g.claimed_at is not null and g.revoked_at is null and (g.expires_at is null or g.expires_at>clock_timestamp())
          and not exists(select 1 from agent_task_grants task where task.tenant_id=g.tenant_id and task.grant_id=g.grant_id)
          and not exists(select 1 from agent_task_clients task where task.tenant_id=c.tenant_id and task.client_id=c.client_id)
          and c.status='active' and not c.is_agent and c.compliance_profile='fapi'
          and c.token_endpoint_auth_method='private_key_jwt' and c.dpop_bound_access_tokens
          and c.grant_types=ARRAY['client_credentials']::text[] and 'admin.kubernetes_reviews:read'=any(c.scopes))")
        .bind(tenant.as_str()).bind(client.as_str()).bind(sha256(jti.as_bytes()).as_slice())
        .fetch_one(connection).await.map_err(to_domain_error)
}
