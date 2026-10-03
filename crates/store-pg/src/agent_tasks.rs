//! Durable immutable approvals and the task access-token signing fence.
use crate::error::to_domain_error;
use asterius_domain::agent_tasks::{
    Binding, MAX_TASK_LIFETIME, MAX_TASK_TOKEN_LIFETIME, Permissions, invalid,
};
use asterius_domain::{
    Actor, AuditEvent, AuditSink, ClientId, Detail, DomainError, EventType, Grant, Outcome, Signer,
    TenantId, UserId,
};
use sqlx::{PgConnection, PgPool, Row as _};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Authenticated owner approval; tenant and fresh session are supplied by the
/// account adapter, never by this payload.
#[derive(Debug)]
pub struct Approval<'a> {
    pub owner: UserId,
    pub root: &'a Grant,
    pub permissions: &'a Permissions,
    pub label: &'a str,
    pub expiry: OffsetDateTime,
    pub now: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct PgAgentTasks {
    pub(crate) pool: PgPool,
}

impl PgAgentTasks {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn required(
        &self,
        tenant: &TenantId,
        client: &ClientId,
    ) -> Result<bool, DomainError> {
        sqlx::query_scalar(
            "select exists(select 1 from agent_task_clients where tenant_id=$1 and client_id=$2)",
        )
        .bind(tenant.as_str())
        .bind(client.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)
    }

    /// Explicit owner approval of an existing human-authorized root. The
    /// caller proves fresh session authentication and CSRF before this port.
    #[expect(
        clippy::too_many_lines,
        reason = "Keep immutable approval, root narrowing and audit in one reviewable transaction"
    )]
    pub async fn approve(
        &self,
        tenant: &TenantId,
        approval: Approval<'_>,
        audit: &dyn AuditSink,
    ) -> Result<Binding, DomainError> {
        let Approval {
            owner,
            root,
            permissions,
            label,
            expiry,
            now,
        } = approval;
        permissions.validate()?;
        if root.tenant != *tenant
            || root.user != Some(owner)
            || root.parent.is_some()
            || label.is_empty()
            || label.len() > 256
            || label.chars().any(char::is_control)
            || expiry <= now
            || expiry > now + MAX_TASK_LIFETIME
            || root.expires_at.is_some_and(|value| expiry > value)
            || !permissions.scopes.is_subset(&root.scopes)
            || !permissions.resources.is_subset(&root.resources)
        {
            return Err(invalid());
        }
        // Exact root RAR evidence must cover each requested type-aware detail.
        let root_ceiling = Permissions {
            scopes: root.scopes.clone(),
            resources: root.resources.clone(),
            authorization_details: root.authorization_details.clone(),
            max_delegation_depth: 8,
        };
        let mut approved = root.clone();
        approved.scopes.clone_from(&permissions.scopes);
        approved.resources.clone_from(&permissions.resources);
        approved
            .authorization_details
            .clone_from(&permissions.authorization_details);
        root_ceiling.permits(&approved)?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        principal_locks(
            &mut tx,
            tenant,
            owner.as_uuid(),
            &root.client,
            &root.client,
            &[],
        )
        .await?;
        // Serializes activation of the task obligation against a legacy mint
        // already holding the same client SHARE fence.
        sqlx::query("select client_id from clients where tenant_id=$1 and client_id=$2 for update")
            .bind(tenant.as_str())
            .bind(root.client.as_str())
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let current_clock: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        if expiry <= current_clock || expiry > current_clock + MAX_TASK_LIFETIME {
            return Err(invalid());
        }
        let current=sqlx::query("select user_id,client_id,scopes,resources,authorization_details,revoked_at,expires_at from grants where tenant_id=$1 and grant_id=$2 for update")
            .bind(tenant.as_str()).bind(grant_uuid(root)?).fetch_optional(&mut *tx).await.map_err(to_domain_error)?.ok_or_else(invalid)?;
        if current
            .try_get::<Option<Uuid>, _>("user_id")
            .map_err(to_domain_error)?
            != Some(*owner.as_uuid())
            || current
                .try_get::<Option<OffsetDateTime>, _>("revoked_at")
                .map_err(to_domain_error)?
                .is_some()
            || current
                .try_get::<Option<OffsetDateTime>, _>("expires_at")
                .map_err(to_domain_error)?
                .is_some_and(|value| value < expiry)
            || current
                .try_get::<String, _>("client_id")
                .map_err(to_domain_error)?
                != root.client.as_str()
            || current
                .try_get::<Vec<String>, _>("scopes")
                .map_err(to_domain_error)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                != root.scopes
            || current
                .try_get::<Vec<String>, _>("resources")
                .map_err(to_domain_error)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                != root.resources
            || current
                .try_get::<serde_json::Value, _>("authorization_details")
                .map_err(to_domain_error)?
                != serde_json::Value::Array(root.authorization_details.clone())
        {
            return Err(invalid());
        }
        // Freeze the run's root to the newly approved narrowing. Older broader
        // refresh credentials cannot silently inherit the smaller approval.
        sqlx::query("update grants set scopes=$3,resources=$4,authorization_details=$5,expires_at=$6 where tenant_id=$1 and grant_id=$2")
            .bind(tenant.as_str()).bind(grant_uuid(root)?)
            .bind(permissions.scopes.iter().cloned().collect::<Vec<_>>())
            .bind(permissions.resources.iter().cloned().collect::<Vec<_>>())
            .bind(serde_json::Value::Array(permissions.authorization_details.clone())).bind(expiry)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        let task = Uuid::new_v4();
        let revision: i64=sqlx::query_scalar("insert into agent_tasks(tenant_id,task_id,root_grant_id,root_reference,owner_user_id,owner_reference,initiating_client_id,client_reference,permissions,label,approved_at,expires_at) values($1,$2,$3,$3,$4,$4,$5,$5,$6,$7,$8,$9) returning approval_revision")
            .bind(tenant.as_str()).bind(task).bind(grant_uuid(root)?).bind(owner.as_uuid()).bind(root.client.as_str())
            .bind(serde_json::to_value(permissions).map_err(|_|invalid())?).bind(label).bind(current_clock).bind(expiry)
            .fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        sqlx::query("insert into agent_task_grants(tenant_id,grant_id,task_id,root_grant_id,approval_revision) values($1,$2,$3,$2,$4)")
            .bind(tenant.as_str()).bind(grant_uuid(root)?).bind(task).bind(revision).execute(&mut *tx).await.map_err(to_domain_error)?;
        // Existing delegations cannot remain a legacy refresh/exchange route
        // when their human root enters an explicitly approved task.
        sqlx::query(r"with recursive descendants as (
                select grant_id,array[grant_id] as path from grants where tenant_id=$1 and grant_id=$2
                union all select g.grant_id,d.path||g.grant_id from descendants d
                join grants g on g.tenant_id=$1 and g.parent_grant_id=d.grant_id
                where cardinality(d.path)<10 and not g.grant_id=any(d.path)
            ) insert into agent_task_grants(tenant_id,grant_id,task_id,root_grant_id,approval_revision)
              select $1,grant_id,$3,$2,$4 from descendants on conflict(tenant_id,grant_id) do nothing")
            .bind(tenant.as_str()).bind(grant_uuid(root)?).bind(task).bind(revision)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        sqlx::query("insert into agent_task_clients(tenant_id,client_id) values($1,$2) on conflict do nothing")
            .bind(tenant.as_str()).bind(root.client.as_str()).execute(&mut *tx).await.map_err(to_domain_error)?;
        crate::audit::append(
            &mut tx,
            audit.prepare(
                AuditEvent::new(
                    tenant.clone(),
                    EventType::AGENT_TASK_APPROVED,
                    Outcome::Success,
                    Actor::User(owner.to_string()),
                    now,
                )
                .client(root.client.clone())
                .grant(root.id.clone())
                .detail(
                    Detail::new()
                        .text("task_id", task.to_string())
                        .number("approval_revision", revision)
                        .text("operation", "task_approved"),
                ),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(Binding {
            task_id: task,
            root_grant_id: grant_uuid(root)?,
            approval_revision: revision,
            expires_at: expiry,
        })
    }

    /// Resolve an authenticated task JWT through private durable lineage.
    /// Optional public grant claims cannot substitute for this mapping.
    pub async fn token_grant(
        &self,
        tenant: &TenantId,
        jti: &str,
        task: Uuid,
        revision: i64,
    ) -> Result<Option<asterius_domain::GrantId>, DomainError> {
        self.active_link(tenant, jti, None, task, revision, None)
            .await
    }

    async fn rejected(&self, grant: &Grant, audit: &dyn AuditSink) -> Result<(), DomainError> {
        let mut detail = Detail::new().text("reason", "task_authority_refused").text(
            "parent_grant_id",
            grant
                .parent
                .as_ref()
                .map_or("", asterius_domain::GrantId::as_str),
        );
        let actor = if let Some(binding) = &grant.task {
            detail = detail
                .text("task_id", binding.task_id.to_string())
                .text("task_root_grant_id", binding.root_grant_id.to_string())
                .number("approval_revision", binding.approval_revision);
            let owner:Option<Uuid>=sqlx::query_scalar("select owner_user_id from agent_tasks where tenant_id=$1 and task_id=$2 and approval_revision=$3")
                .bind(grant.tenant.as_str()).bind(binding.task_id).bind(binding.approval_revision).fetch_optional(&self.pool).await.map_err(to_domain_error)?;
            owner.map_or_else(
                || Actor::Client(grant.client.clone()),
                |owner| Actor::Agent {
                    client: grant.client.clone(),
                    on_behalf_of: owner.to_string(),
                },
            )
        } else {
            Actor::Client(grant.client.clone())
        };
        audit
            .record(
                AuditEvent::new(
                    grant.tenant.clone(),
                    EventType::AGENT_TASK_ISSUED,
                    Outcome::Failure,
                    actor,
                    OffsetDateTime::now_utc(),
                )
                .client(grant.client.clone())
                .grant(grant.id.clone())
                .detail(detail),
            )
            .await
    }

    /// Resolve stored lineage or attach a client-credentials child to its
    /// explicitly selected approved run. This never accepts a root from JWTs.
    pub async fn prepare(
        &self,
        grant: &mut Grant,
        selected: Option<&str>,
        requested_details: Option<&str>,
        now: OffsetDateTime,
        lifetime: Duration,
        audit: &dyn AuditSink,
    ) -> Result<Duration, DomainError> {
        let result = self
            .prepare_inner(grant, selected, requested_details, now, lifetime)
            .await;
        if result.is_err() {
            self.rejected(grant, audit).await?;
        }
        result
    }

    async fn prepare_inner(
        &self,
        grant: &mut Grant,
        selected: Option<&str>,
        requested_details: Option<&str>,
        now: OffsetDateTime,
        lifetime: Duration,
    ) -> Result<Duration, DomainError> {
        let required = self.required(&grant.tenant, &grant.client).await?;
        let selected = selected
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| invalid())?;
        if let Some(task) = selected {
            if !required || grant.user.is_some() || grant.parent.is_some() {
                return Err(invalid());
            }
            let root:Uuid=sqlx::query_scalar("select root_grant_id from agent_tasks where tenant_id=$1 and task_id=$2 and initiating_client_id=$3")
                .bind(grant.tenant.as_str()).bind(task).bind(grant.client.as_str()).fetch_optional(&self.pool).await.map_err(to_domain_error)?.ok_or_else(invalid)?;
            grant.parent = Some(asterius_domain::GrantId::new(root.to_string()));
        }
        let lookup = grant.parent.as_ref().unwrap_or(&grant.id);
        let row=sqlx::query("select t.task_id,t.root_grant_id,t.approval_revision,t.expires_at,t.revoked_at,t.permissions,g.authorization_details as source_details from agent_tasks t join agent_task_grants b using(tenant_id,task_id,root_grant_id,approval_revision) join grants g on g.tenant_id=b.tenant_id and g.grant_id=b.grant_id where b.tenant_id=$1 and b.grant_id=$2")
            .bind(grant.tenant.as_str()).bind(Uuid::parse_str(lookup.as_str()).map_err(|_|invalid())?).fetch_optional(&self.pool).await.map_err(to_domain_error)?;
        let Some(row) = row else {
            return if required || requested_details.is_some() {
                Err(invalid())
            } else {
                Ok(lifetime)
            };
        };
        let expiry: OffsetDateTime = row.try_get("expires_at").map_err(to_domain_error)?;
        grant.task = Some(Binding {
            task_id: row.try_get("task_id").map_err(to_domain_error)?,
            root_grant_id: row.try_get("root_grant_id").map_err(to_domain_error)?,
            approval_revision: row.try_get("approval_revision").map_err(to_domain_error)?,
            expires_at: expiry,
        });
        if expiry <= now
            || row
                .try_get::<Option<OffsetDateTime>, _>("revoked_at")
                .map_err(to_domain_error)?
                .is_some()
        {
            return Err(invalid());
        }
        let permissions: Permissions =
            serde_json::from_value(row.try_get("permissions").map_err(to_domain_error)?)
                .map_err(|_| invalid())?;
        permissions.validate()?;
        if let Some(raw) = requested_details {
            grant.authorization_details = asterius_domain::agent_tasks::parse_details(raw)?;
        } else if grant.authorization_details.is_empty() {
            grant.authorization_details =
                serde_json::from_value(row.try_get("source_details").map_err(to_domain_error)?)
                    .map_err(|_| invalid())?;
        }
        permissions.permits(grant)?;

        let ancestor_deadline:Option<OffsetDateTime>=sqlx::query_scalar("with recursive lineage as (select expires_at,parent_grant_id,1 as depth from grants where tenant_id=$1 and grant_id=$2 union all select g.expires_at,g.parent_grant_id,l.depth+1 from grants g join lineage l on g.grant_id=l.parent_grant_id where g.tenant_id=$1 and l.depth<10) select min(expires_at) from lineage")
            .bind(grant.tenant.as_str()).bind(Uuid::parse_str(lookup.as_str()).map_err(|_|invalid())?).fetch_one(&self.pool).await.map_err(to_domain_error)?;
        let expiry = ancestor_deadline.map_or(expiry, |deadline| expiry.min(deadline));
        let settings: serde_json::Value = sqlx::query_scalar(
            "select settings from tenants where tenant_id=$1 and status='active'",
        )
        .bind(grant.tenant.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        .ok_or_else(invalid)?;
        let settings = asterius_domain::TenantSettings::from_json(settings.get("options"))
            .map_err(|_| invalid())?;
        let mut capped = lifetime
            .min(settings.lifetimes().access_token())
            .min(MAX_TASK_TOKEN_LIFETIME)
            .min(expiry - now);
        let policies:Vec<serde_json::Value>=sqlx::query_scalar("with recursive lineage as (select client_id,parent_grant_id,1 as depth from grants where tenant_id=$1 and grant_id=$2 union all select g.client_id,g.parent_grant_id,l.depth+1 from grants g join lineage l on g.grant_id=l.parent_grant_id where g.tenant_id=$1 and l.depth<10) select c.agent_policy from clients c where c.tenant_id=$1 and c.is_agent and (c.client_id=$3 or c.client_id in (select client_id from lineage))")
            .bind(grant.tenant.as_str()).bind(Uuid::parse_str(lookup.as_str()).map_err(|_|invalid())?).bind(grant.client.as_str()).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        for policy in policies {
            let limits = asterius_domain::AgentLimits::from_json(&policy).map_err(|_| invalid())?;
            if let Some(cap) = limits.access_token_ttl_cap() {
                capped = capped.min(cap);
            }
        }
        if let Some(limits) = settings.registration().agent_limits()
            && let Some(cap) = limits.access_token_ttl_cap()
        {
            capped = capped.min(cap);
        }
        if capped <= Duration::ZERO {
            return Err(invalid());
        }
        grant.expires_at = Some(grant.expires_at.unwrap_or(expiry).min(expiry));
        Ok(capped)
    }
}

pub(crate) fn grant_uuid(grant: &Grant) -> Result<Uuid, DomainError> {
    Uuid::parse_str(grant.id.as_str()).map_err(|_| invalid())
}

async fn principal_locks(
    connection: &mut PgConnection,
    tenant: &TenantId,
    owner: &Uuid,
    initiating: &ClientId,
    recipient: &ClientId,
    related: &[String],
) -> Result<(), DomainError> {
    sqlx::query("select tenant_id from tenants where tenant_id=$1 and status='active' for share")
        .bind(tenant.as_str())
        .fetch_optional(&mut *connection)
        .await
        .map_err(to_domain_error)?
        .ok_or_else(invalid)?;
    let mut expected = related.to_vec();
    expected.push(initiating.to_string());
    expected.push(recipient.to_string());
    expected.sort();
    expected.dedup();
    let active:bool=sqlx::query_scalar("select exists(select 1 from (select user_id from users where tenant_id=$1 and user_id=$2 and status='active' for share) u)")
        .bind(tenant.as_str()).bind(owner).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
    if !active {
        return Err(invalid());
    }
    let clients=sqlx::query("select client_id,is_agent,agent_owner_user_id from clients where tenant_id=$1 and client_id=any($2) and status='active' order by client_id for share")
        .bind(tenant.as_str()).bind(&expected).fetch_all(connection).await.map_err(to_domain_error)?;
    if clients.len() != expected.len()
        || clients.iter().any(|row| {
            row.get::<bool, _>("is_agent")
                && row.get::<Option<Uuid>, _>("agent_owner_user_id") != Some(*owner)
        })
    {
        return Err(invalid());
    }
    let initiator = clients
        .iter()
        .find(|row| row.get::<String, _>("client_id") == initiating.as_str())
        .ok_or_else(invalid)?;
    if !initiator
        .try_get::<bool, _>("is_agent")
        .map_err(to_domain_error)?
        || initiator
            .try_get::<Option<Uuid>, _>("agent_owner_user_id")
            .map_err(to_domain_error)?
            != Some(*owner)
    {
        return Err(invalid());
    }
    Ok(())
}

/// Production signing decorator. Only an explicit access-token call with a
/// durable grant may mint task authority. Specialized raw-sign paths fail
/// closed for task-enabled clients; ID/logout/event signing is unchanged.
#[derive(Debug)]
pub struct TaskSigner<'a> {
    pub tasks: &'a PgAgentTasks,
    pub inner: &'a dyn Signer,
    pub audit: &'a dyn AuditSink,
}

impl TaskSigner<'_> {
    async fn sign_unbound(
        &self,
        tenant: &TenantId,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        self.sign_unbound_with(tenant, None, algorithm, typ, claims)
            .await
    }

    // Preserve the exact issuance through the non-task client fence so inner
    // policy decorators can evaluate it after every outer lock wait.
    async fn sign_unbound_with(
        &self,
        tenant: &TenantId,
        issuance: Option<asterius_domain::keys::AccessIssuance<'_>>,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        let client = if typ == "oauth-id-jag+jwt" {
            claims
                .get("act")
                .and_then(|value| value.get("client_id"))
                .and_then(serde_json::Value::as_str)
        } else {
            claims.get("client_id").and_then(serde_json::Value::as_str)
        }
        .ok_or_else(invalid)?;
        let mut tx = self.tasks.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query(
            "select tenant_id from tenants where tenant_id=$1 and status='active' for share",
        )
        .bind(tenant.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?
        .ok_or_else(invalid)?;

        sqlx::query("select client_id from clients where tenant_id=$1 and client_id=$2 and status='active' for share")
            .bind(tenant.as_str()).bind(client).fetch_optional(&mut *tx).await.map_err(to_domain_error)?.ok_or_else(invalid)?;
        let required: bool = sqlx::query_scalar(
            "select exists(select 1 from agent_task_clients where tenant_id=$1 and client_id=$2)",
        )
        .bind(tenant.as_str())
        .bind(client)
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if required {
            // This raw specialized path has no approved task context to name.
            // Record the authenticated client and constant refusal after
            // releasing its fence; never guess a task from a current run list.
            drop(tx);
            self.audit
                .record(
                    AuditEvent::new(
                        tenant.clone(),
                        EventType::AGENT_TASK_ISSUED,
                        Outcome::Failure,
                        Actor::Client(ClientId::new(client)),
                        OffsetDateTime::now_utc(),
                    )
                    .client(ClientId::new(client))
                    .detail(Detail::new().text("reason", "task_context_required")),
                )
                .await?;
            return Err(invalid());
        }
        if let Some(issuance) = issuance {
            if issuance.grant.task.is_some() {
                return Err(invalid());
            }
            let lookup = issuance.grant.parent.as_ref().unwrap_or(&issuance.grant.id);
            let lookup = Uuid::parse_str(lookup.as_str()).map_err(|_| invalid())?;
            // First approval backfills historical descendants under the root
            // UPDATE lock. KEY SHARE serializes even an ordinary recipient's
            // previously unbound issuance with that approval; client locks
            // precede the root consistently with the task path.
            let root: Option<Uuid> = sqlx::query_scalar("with recursive lineage as (select grant_id,parent_grant_id,1 as depth from grants where tenant_id=$1 and grant_id=$2 union all select g.grant_id,g.parent_grant_id,l.depth+1 from grants g join lineage l on g.grant_id=l.parent_grant_id where g.tenant_id=$1 and l.depth<10) select grant_id from lineage where parent_grant_id is null")
                .bind(tenant.as_str()).bind(lookup).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
            if let Some(root) = root {
                sqlx::query("select grant_id from grants where tenant_id=$1 and grant_id=$2 and revoked_at is null and (expires_at is null or expires_at>clock_timestamp()) for key share")
                    .bind(tenant.as_str()).bind(root).fetch_optional(&mut *tx).await.map_err(to_domain_error)?.ok_or_else(invalid)?;
                let bound: bool = sqlx::query_scalar("select exists(select 1 from agent_task_grants where tenant_id=$1 and grant_id=$2)")
                    .bind(tenant.as_str()).bind(lookup).fetch_one(&mut *tx).await.map_err(to_domain_error)?;
                if bound {
                    return Err(invalid());
                }
            } else if issuance.grant.parent.is_some() {
                // Missing/cyclic/deeper-than-supported ancestry cannot fall
                // back to a standalone client credential.
                return Err(invalid());
            }
        }
        let token = match issuance {
            Some(issuance) => {
                self.inner
                    .sign_access(tenant, issuance, algorithm, typ, claims)
                    .await?
            }
            None => self.inner.sign(tenant, algorithm, typ, claims).await?,
        };
        tx.commit().await.map_err(to_domain_error)?;
        Ok(token)
    }
}

#[async_trait::async_trait]
impl Signer for TaskSigner<'_> {
    async fn prepare(
        &self,
        tenant: &TenantId,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
    ) -> Result<Option<Box<dyn Signer + '_>>, DomainError> {
        let Some(inner) = self.inner.prepare(tenant, algorithm).await? else {
            return Ok(None);
        };
        Ok(Some(Box::new(PreparedTaskSigner {
            tasks: self.tasks.clone(),
            inner,
            audit: self.audit,
        })))
    }

    async fn sign(
        &self,
        tenant: &TenantId,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        if let Some(prepared) = self.prepare(tenant, algorithm).await? {
            return prepared.sign(tenant, algorithm, typ, claims).await;
        }
        self.sign_checked(tenant, algorithm, typ, claims).await
    }

    async fn sign_identity(
        &self,
        tenant: &TenantId,
        grant: &Grant,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        self.sign_identity_bound(tenant, grant, None, algorithm, typ, claims)
            .await
    }

    async fn sign_identity_bound(
        &self,
        tenant: &TenantId,
        grant: &Grant,
        binding: Option<&asterius_domain::managed_devices::DeviceBinding>,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        if !matches!(typ, "JWT" | "dpop+id_token") {
            return Err(DomainError::invalid(
                "id_token",
                "identity assertion type required",
            ));
        }
        if let Some(prepared) = self.prepare(tenant, algorithm).await? {
            return prepared
                .sign_identity_bound(tenant, grant, binding, algorithm, typ, claims)
                .await;
        }
        self.inner
            .sign_identity_bound(tenant, grant, binding, algorithm, typ, claims)
            .await
    }

    async fn sign_access(
        &self,
        tenant: &TenantId,
        issuance: asterius_domain::keys::AccessIssuance<'_>,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        if let Some(prepared) = self.prepare(tenant, algorithm).await? {
            return prepared
                .sign_access(tenant, issuance, algorithm, typ, claims)
                .await;
        }
        self.sign_access_checked(tenant, issuance, algorithm, typ, claims)
            .await
    }
}

impl TaskSigner<'_> {
    async fn sign_checked(
        &self,
        tenant: &TenantId,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        if matches!(typ, "at+jwt" | "oauth-id-jag+jwt") {
            return self.sign_unbound(tenant, algorithm, typ, claims).await;
        }
        self.inner.sign(tenant, algorithm, typ, claims).await
    }

    async fn sign_access_checked(
        &self,
        tenant: &TenantId,
        issuance: asterius_domain::keys::AccessIssuance<'_>,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        let grant = issuance.grant;
        let result = self
            .sign_access_fenced(tenant, issuance, algorithm, typ, claims)
            .await;
        if result.is_err() && grant.task.is_some() {
            self.tasks.rejected(grant, self.audit).await?;
        }
        result
    }
    #[expect(
        clippy::too_many_lines,
        reason = "The ordered principal/lineage locks, signature and commit form one security fence"
    )]
    async fn sign_access_fenced(
        &self,
        tenant: &TenantId,
        issuance: asterius_domain::keys::AccessIssuance<'_>,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        let grant = issuance.grant;
        if grant.tenant != *tenant || !matches!(typ, "at+jwt" | "oauth-id-jag+jwt") {
            return Err(invalid());
        }
        if typ == "oauth-id-jag+jwt" {
            // ID-JAG has no task lineage protocol. Its source client must remain
            // non-task, while the inner policy receives its exact grant context.
            return self
                .sign_unbound_with(tenant, Some(issuance), algorithm, typ, claims)
                .await;
        }
        let lookup = grant.parent.as_ref().unwrap_or(&grant.id);
        let hint=sqlx::query("select t.task_id,t.owner_user_id,t.initiating_client_id,t.root_grant_id from agent_tasks t join agent_task_grants b using(tenant_id,task_id,root_grant_id,approval_revision) where b.tenant_id=$1 and b.grant_id=$2")
            .bind(tenant.as_str()).bind(Uuid::parse_str(lookup.as_str()).map_err(|_|invalid())?).fetch_optional(&self.tasks.pool).await.map_err(to_domain_error)?;
        let Some(hint) = hint else {
            return self
                .sign_unbound_with(tenant, Some(issuance), algorithm, typ, claims)
                .await;
        };
        let task_id: Uuid = hint.try_get("task_id").map_err(to_domain_error)?;
        let root: Uuid = hint.try_get("root_grant_id").map_err(to_domain_error)?;
        let owner: Uuid = hint.try_get("owner_user_id").map_err(to_domain_error)?;
        if grant.user.is_some_and(|user| user.as_uuid() != &owner) {
            return Err(invalid());
        }
        let initiating = ClientId::new(
            hint.try_get::<String, _>("initiating_client_id")
                .map_err(to_domain_error)?,
        );
        let mut tx = self.tasks.pool.begin().await.map_err(to_domain_error)?;
        // All changes to these principal rows conflict with SHARE. Owner
        // changes run their terminal task fence in that same transaction.
        let related:Vec<String>=sqlx::query_scalar("with recursive lineage as (select client_id,parent_grant_id,1 as depth from grants where tenant_id=$1 and grant_id=$2 union all select g.client_id,g.parent_grant_id,l.depth+1 from grants g join lineage l on g.grant_id=l.parent_grant_id where g.tenant_id=$1 and l.depth<10) select distinct client_id from lineage")
            .bind(tenant.as_str()).bind(Uuid::parse_str(lookup.as_str()).map_err(|_|invalid())?).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
        principal_locks(
            &mut tx,
            tenant,
            &owner,
            &initiating,
            &grant.client,
            &related,
        )
        .await?;
        sqlx::query("select grant_id from grants where tenant_id=$1 and grant_id=$2 for update")
            .bind(tenant.as_str())
            .bind(root)
            .fetch_optional(&mut *tx)
            .await
            .map_err(to_domain_error)?
            .ok_or_else(invalid)?;
        let task=sqlx::query("select approval_revision,permissions,expires_at,revoked_at,owner_reference,client_reference from agent_tasks where tenant_id=$1 and task_id=$2 and root_grant_id=$3 for update")
            .bind(tenant.as_str()).bind(task_id).bind(root).fetch_optional(&mut *tx).await.map_err(to_domain_error)?.ok_or_else(invalid)?;
        let now: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let expiry: OffsetDateTime = task.try_get("expires_at").map_err(to_domain_error)?;
        if expiry <= now
            || task
                .try_get::<Option<OffsetDateTime>, _>("revoked_at")
                .map_err(to_domain_error)?
                .is_some()
            || task
                .try_get::<Option<Uuid>, _>("owner_reference")
                .map_err(to_domain_error)?
                .is_none()
            || task
                .try_get::<Option<String>, _>("client_reference")
                .map_err(to_domain_error)?
                .is_none()
        {
            return Err(invalid());
        }
        let revision: i64 = task.try_get("approval_revision").map_err(to_domain_error)?;
        let permissions: Permissions =
            serde_json::from_value(task.try_get("permissions").map_err(to_domain_error)?)
                .map_err(|_| invalid())?;
        permissions.validate()?;
        permissions.permits(grant)?;
        if grant.task.as_ref().is_none_or(|binding| {
            binding.task_id != task_id
                || binding.root_grant_id != root
                || binding.approval_revision != revision
        }) || claims
            .get("authorization_details")
            .map_or(!grant.authorization_details.is_empty(), |details| {
                details != &serde_json::Value::Array(grant.authorization_details.clone())
            })
        {
            return Err(invalid());
        }
        let existing: bool = sqlx::query_scalar(
            "select exists(select 1 from grants where tenant_id=$1 and grant_id=$2)",
        )
        .bind(tenant.as_str())
        .bind(grant_uuid(grant)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let lineage_start = if existing {
            grant_uuid(grant)?
        } else {
            Uuid::parse_str(lookup.as_str()).map_err(|_| invalid())?
        };
        // Bounded lineage traversal; no cycle may be treated as a valid root.
        let ancestors=sqlx::query("with recursive lineage as (select grant_id,parent_grant_id,revoked_at,expires_at,scopes,resources,authorization_details,array[grant_id] as path,false as cycle from grants where tenant_id=$1 and grant_id=$2 union all select g.grant_id,g.parent_grant_id,g.revoked_at,g.expires_at,g.scopes,g.resources,g.authorization_details,l.path||g.grant_id,g.grant_id=any(l.path) from grants g join lineage l on g.grant_id=l.parent_grant_id where g.tenant_id=$1 and not l.cycle and cardinality(l.path)<=9) select * from lineage")
            .bind(tenant.as_str()).bind(lineage_start).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
        if ancestors.is_empty()
            || ancestors.len() > 10
            || !ancestors
                .iter()
                .any(|row| row.get::<Uuid, _>("grant_id") == root)
        {
            return Err(invalid());
        }
        let mut ids = ancestors
            .iter()
            .map(|row| row.get::<Uuid, _>("grant_id"))
            .collect::<Vec<_>>();
        ids.sort();
        sqlx::query("select grant_id from grants where tenant_id=$1 and grant_id=any($2) order by grant_id for update")
            .bind(tenant.as_str()).bind(&ids).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
        // Re-read after acquiring all locks: a snapshot taken while waiting
        // for an intermediate revoke is never authority to sign.
        let current=sqlx::query("select g.grant_id,g.user_id,g.revoked_at,g.expires_at,g.scopes,g.resources,g.authorization_details,c.is_agent,c.agent_policy,c.status from grants g join clients c using(tenant_id,client_id) where g.tenant_id=$1 and g.grant_id=any($2)")
            .bind(tenant.as_str()).bind(&ids).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
        let mut deadline = expiry;
        let mut ancestor_cap = MAX_TASK_TOKEN_LIFETIME;
        for ancestor in current {
            if ancestor
                .try_get::<Option<Uuid>, _>("user_id")
                .map_err(to_domain_error)?
                .is_some_and(|user| user != owner)
            {
                return Err(invalid());
            }
            if ancestor
                .try_get::<Option<OffsetDateTime>, _>("revoked_at")
                .map_err(to_domain_error)?
                .is_some()
            {
                return Err(invalid());
            }
            if let Some(value) = ancestor
                .try_get::<Option<OffsetDateTime>, _>("expires_at")
                .map_err(to_domain_error)?
            {
                deadline = deadline.min(value);
            }
            let ceiling = Permissions {
                scopes: ancestor
                    .try_get::<Vec<String>, _>("scopes")
                    .map_err(to_domain_error)?
                    .into_iter()
                    .collect(),
                resources: ancestor
                    .try_get::<Vec<String>, _>("resources")
                    .map_err(to_domain_error)?
                    .into_iter()
                    .collect(),
                authorization_details: serde_json::from_value(
                    ancestor
                        .try_get("authorization_details")
                        .map_err(to_domain_error)?,
                )
                .map_err(|_| invalid())?,
                max_delegation_depth: permissions.max_delegation_depth,
            };
            ceiling.permits(grant)?;
            if ancestor
                .try_get::<String, _>("status")
                .map_err(to_domain_error)?
                != "active"
            {
                return Err(invalid());
            }
            if ancestor
                .try_get::<bool, _>("is_agent")
                .map_err(to_domain_error)?
            {
                let limits = asterius_domain::AgentLimits::from_json(
                    &ancestor
                        .try_get::<serde_json::Value, _>("agent_policy")
                        .map_err(to_domain_error)?,
                )
                .map_err(|_| invalid())?;
                if limits
                    .scopes()
                    .is_some_and(|allowed| !grant.scopes.is_subset(allowed))
                    || limits
                        .audiences()
                        .is_some_and(|allowed| !grant.resources.is_subset(allowed))
                    || grant.actor_chain.len().max(1) > usize::from(limits.max_delegation_depth())
                {
                    return Err(invalid());
                }
                if let Some(cap) = limits.access_token_ttl_cap() {
                    ancestor_cap = ancestor_cap.min(cap);
                }
            }
        }
        if ancestors.iter().any(|row| row.get::<bool, _>("cycle")) {
            return Err(invalid());
        }
        let issued = claims
            .get("iat")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(invalid)?;
        let expires = claims
            .get("exp")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(invalid)?;
        let expires = OffsetDateTime::from_unix_timestamp(expires).map_err(|_| invalid())?;
        let policy_cap = current_policy(
            &mut tx,
            tenant,
            grant,
            issuance.kind,
            claims,
            issuance.implicit_resources,
        )
        .await?
        .min(ancestor_cap);
        if expires <= now
            || expires > deadline
            || expires.unix_timestamp() - issued > 300
            || expires.unix_timestamp() - issued > policy_cap.whole_seconds()
            || claims.get("client_id").and_then(serde_json::Value::as_str)
                != Some(grant.client.as_str())
        {
            return Err(invalid());
        }
        let mut signed_claims = claims.clone();
        if let Some(object) = signed_claims.as_object_mut() {
            // The owner's roles are not inherited by an agent task merely
            // because the human approved its exact scope/action ceilings.
            object.remove("roles");
            object.remove("resource_access");
        }
        signed_claims["task_id"] = serde_json::json!(task_id);
        signed_claims["task_approval_revision"] = serde_json::json!(revision);
        if !existing {
            crate::grants::PgGrantRepository::insert_on(&mut tx, tenant, grant).await?;
        }
        let claimed=sqlx::query("update grants set claimed_at=coalesce(claimed_at,$3) where tenant_id=$1 and grant_id=$2 and revoked_at is null and (expires_at is null or expires_at>$3)")
            .bind(tenant.as_str()).bind(grant_uuid(grant)?).bind(now).execute(&mut *tx).await.map_err(to_domain_error)?.rows_affected();
        if claimed != 1 {
            return Err(invalid());
        }
        let jti = claims
            .get("jti")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        sqlx::query(
            "insert into agent_task_tokens(tenant_id,jti,grant_id,expires_at) values($1,$2,$3,$4)",
        )
        .bind(tenant.as_str())
        .bind(jti)
        .bind(grant_uuid(grant)?)
        .bind(expires)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let token = self
            .inner
            .sign(tenant, algorithm, typ, &signed_claims)
            .await?;
        // Fresh current time immediately before commit; signing latency never
        // turns an expired run into an issued credential.
        let commit_clock: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        if expires <= commit_clock || deadline <= commit_clock {
            return Err(invalid());
        }
        let event = AuditEvent::new(
            tenant.clone(),
            EventType::AGENT_TASK_ISSUED,
            Outcome::Success,
            Actor::Agent {
                client: grant.client.clone(),
                on_behalf_of: owner.to_string(),
            },
            now,
        )
        .client(grant.client.clone())
        .grant(grant.id.clone())
        .detail(
            Detail::new()
                .text("task_id", task_id.to_string())
                .text("task_root_grant_id", root.to_string())
                .number("approval_revision", revision)
                .text(
                    "parent_grant_id",
                    grant
                        .parent
                        .as_ref()
                        .map_or("", asterius_domain::GrantId::as_str),
                ),
        );
        crate::audit::append(&mut tx, self.audit.prepare(event)).await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(token)
    }
}

struct PreparedTaskSigner<'a> {
    tasks: PgAgentTasks,
    inner: Box<dyn Signer + 'a>,
    audit: &'a dyn AuditSink,
}
impl std::fmt::Debug for PreparedTaskSigner<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedTaskSigner")
            .finish_non_exhaustive()
    }
}
#[async_trait::async_trait]
impl Signer for PreparedTaskSigner<'_> {
    async fn sign(
        &self,
        tenant: &TenantId,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        TaskSigner {
            tasks: &self.tasks,
            inner: self.inner.as_ref(),
            audit: self.audit,
        }
        .sign_checked(tenant, algorithm, typ, claims)
        .await
    }
    async fn sign_identity(
        &self,
        tenant: &TenantId,
        grant: &Grant,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        self.sign_identity_bound(tenant, grant, None, algorithm, typ, claims)
            .await
    }

    async fn sign_identity_bound(
        &self,
        tenant: &TenantId,
        grant: &Grant,
        binding: Option<&asterius_domain::managed_devices::DeviceBinding>,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        if !matches!(typ, "JWT" | "dpop+id_token") {
            return Err(DomainError::invalid(
                "id_token",
                "identity assertion type required",
            ));
        }
        self.inner
            .sign_identity_bound(tenant, grant, binding, algorithm, typ, claims)
            .await
    }

    async fn sign_access(
        &self,
        tenant: &TenantId,
        issuance: asterius_domain::keys::AccessIssuance<'_>,
        algorithm: Option<asterius_domain::SigningAlgorithm>,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<asterius_domain::CompactJws, DomainError> {
        TaskSigner {
            tasks: &self.tasks,
            inner: self.inner.as_ref(),
            audit: self.audit,
        }
        .sign_access_checked(tenant, issuance, algorithm, typ, claims)
        .await
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Review all current registration and resource ceilings together before signing"
)]
async fn current_policy(
    connection: &mut PgConnection,
    tenant: &TenantId,
    grant: &Grant,
    kind: asterius_domain::GrantType,
    claims: &serde_json::Value,
    implicit_resources: &[asterius_domain::ResourceServer],
) -> Result<Duration, DomainError> {
    let document: serde_json::Value = sqlx::query_scalar(
        "select settings from tenants where tenant_id=$1 and status='active' for share",
    )
    .bind(tenant.as_str())
    .fetch_optional(&mut *connection)
    .await
    .map_err(to_domain_error)?
    .ok_or_else(invalid)?;
    let settings = asterius_domain::TenantSettings::from_json(document.get("options"))
        .map_err(|_| invalid())?;
    let row=sqlx::query("select scopes,resources,authorization_details_types,grant_types,is_agent,agent_policy from clients where tenant_id=$1 and client_id=$2 and status='active' for share")
        .bind(tenant.as_str()).bind(grant.client.as_str()).fetch_optional(&mut *connection).await.map_err(to_domain_error)?.ok_or_else(invalid)?;
    let scopes = claims
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?
        .split(' ')
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    let resources = match claims.get("aud") {
        Some(serde_json::Value::String(value)) => std::collections::BTreeSet::from([value.clone()]),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|value| value.as_str().map(str::to_owned).ok_or_else(invalid))
            .collect::<Result<_, _>>()?,
        _ => return Err(invalid()),
    };
    if !scopes.is_subset(&grant.scopes)
        || !resources.is_subset(&grant.resources)
        || !scopes.is_subset(
            &row.try_get::<Vec<String>, _>("scopes")
                .map_err(to_domain_error)?
                .into_iter()
                .collect(),
        )
        || !row
            .try_get::<Vec<String>, _>("grant_types")
            .map_err(to_domain_error)?
            .iter()
            .any(|value| value == kind.as_str())
    {
        return Err(invalid());
    }
    let types = row
        .try_get::<Vec<String>, _>("authorization_details_types")
        .map_err(to_domain_error)?;
    for detail in &grant.authorization_details {
        let name = detail
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        if !types.iter().any(|value| value == name) {
            return Err(invalid());
        }
        let schema:serde_json::Value=sqlx::query_scalar("select schema from authorization_details_types where tenant_id=$1 and type_name=$2 for share")
            .bind(tenant.as_str()).bind(name).fetch_optional(&mut *connection).await.map_err(to_domain_error)?.ok_or_else(invalid)?;
        asterius_domain::entities::authorization_details::Schema::parse(&schema)
            .map_err(|_| invalid())?
            .validate(detail)
            .map_err(|_| invalid())?;
    }
    let mut cap = settings
        .lifetimes()
        .access_token()
        .min(MAX_TASK_TOKEN_LIFETIME);
    for resource in &resources {
        // Stored policy overrides server-owned defaults, as ResourceRegistry does.
        let policy = sqlx::query("select scopes,token_lifetime_seconds from resource_servers where tenant_id=$1 and identifier=$2 for share")
            .bind(tenant.as_str()).bind(resource).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
        let (allowed, lifetime) = if let Some(policy) = policy {
            (
                policy
                    .try_get::<Option<Vec<String>>, _>("scopes")
                    .map_err(to_domain_error)?
                    .map(|values| {
                        values
                            .into_iter()
                            .collect::<std::collections::BTreeSet<_>>()
                    }),
                policy
                    .try_get::<Option<i32>, _>("token_lifetime_seconds")
                    .map_err(to_domain_error)?
                    .map(|seconds| Duration::seconds(i64::from(seconds))),
            )
        } else {
            let policy = implicit_resources
                .iter()
                .find(|policy| policy.identifier.as_str() == resource)
                .ok_or_else(invalid)?;
            (policy.scopes.clone(), policy.default_token_lifetime)
        };
        if allowed
            .as_ref()
            .is_some_and(|allowed| !scopes.is_subset(allowed))
        {
            return Err(invalid());
        }
        if let Some(lifetime) = lifetime {
            cap = cap.min(lifetime);
        }
    }
    let mut limits = Vec::new();
    if row
        .try_get::<bool, _>("is_agent")
        .map_err(to_domain_error)?
    {
        limits.push(
            asterius_domain::AgentLimits::from_json(
                &row.try_get::<serde_json::Value, _>("agent_policy")
                    .map_err(to_domain_error)?,
            )
            .map_err(|_| invalid())?,
        );
    }
    if row
        .try_get::<bool, _>("is_agent")
        .map_err(to_domain_error)?
        && let Some(tenant_limits) = settings.registration().agent_limits()
    {
        limits.push(tenant_limits.clone());
    }
    for limits in limits {
        if !limits.grant_types().contains(&kind)
            || limits
                .scopes()
                .is_some_and(|allowed| !scopes.is_subset(allowed))
            || limits
                .audiences()
                .is_some_and(|allowed| !resources.is_subset(allowed))
            || grant.actor_chain.len().max(1) > usize::from(limits.max_delegation_depth())
            || limits.authorization_details_types().is_some_and(|allowed| {
                grant.authorization_details.iter().any(|detail| {
                    !detail
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|name| allowed.contains(name))
                })
            })
        {
            return Err(invalid());
        }
        if let Some(value) = limits.access_token_ttl_cap() {
            cap = cap.min(value);
        }
    }
    Ok(cap)
}
