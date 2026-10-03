//! Uncached authoritative task-token lineage and descendant withdrawal.
use crate::{agent_tasks::PgAgentTasks, error::to_domain_error};
use asterius_domain::agent_tasks::TokenQuery;
use asterius_domain::{DomainError, GrantId, TenantId};
use sqlx::Row as _;
use uuid::Uuid;

impl PgAgentTasks {
    /// Called only with authenticated token facts. Legacy tokens cannot
    /// bypass a client identity whose explicit task obligation is active.
    pub async fn token_active(
        &self,
        tenant: &TenantId,
        query: &TokenQuery,
    ) -> Result<bool, DomainError> {
        let Some(approval) = query.approval else {
            return Ok(!self.required(tenant, &query.client).await?);
        };
        Ok(self
            .active_link(
                tenant,
                &query.jti,
                Some(query.client.as_str()),
                approval.task_id,
                approval.revision,
                None,
            )
            .await?
            .is_some())
    }

    /// Refresh and stored-grant status uses the same exact lineage, without
    /// pretending that an opaque refresh token carries signed task claims.
    pub async fn grant_active(
        &self,
        tenant: &TenantId,
        grant: &GrantId,
    ) -> Result<bool, DomainError> {
        let grant =
            Uuid::parse_str(grant.as_str()).map_err(|_| asterius_domain::agent_tasks::invalid())?;
        let row = sqlx::query("select g.client_id,b.task_id,b.approval_revision from grants g left join agent_task_grants b using(tenant_id,grant_id) where g.tenant_id=$1 and g.grant_id=$2")
            .bind(tenant.as_str()).bind(grant).fetch_optional(&self.pool).await.map_err(to_domain_error)?;
        let Some(row) = row else {
            return Ok(false);
        };
        let task: Option<Uuid> = row.try_get("task_id").map_err(to_domain_error)?;
        let Some(task) = task else {
            let client = asterius_domain::ClientId::new(
                row.try_get::<String, _>("client_id")
                    .map_err(to_domain_error)?,
            );
            return Ok(!self.required(tenant, &client).await?);
        };
        let revision = row.try_get("approval_revision").map_err(to_domain_error)?;
        Ok(self
            .active_link(tenant, "", None, task, revision, Some(grant))
            .await?
            .is_some())
    }

    /// Fresh account authorization is checked by the caller. Possessing the
    /// task UUID alone cannot read or withdraw another owner's run.
    pub async fn revoke_owned(
        &self,
        tenant: &TenantId,
        task: Uuid,
        owner: asterius_domain::UserId,
        now: time::OffsetDateTime,
        audit: &dyn asterius_domain::AuditSink,
    ) -> Result<bool, DomainError> {
        let root: Option<Uuid> = sqlx::query_scalar("select root_grant_id from agent_tasks where tenant_id=$1 and task_id=$2 and owner_user_id=$3")
            .bind(tenant.as_str()).bind(task).bind(owner.as_uuid()).fetch_optional(&self.pool).await.map_err(to_domain_error)?;
        let Some(root) = root else {
            return Ok(false);
        };
        let grants = crate::PgGrantRepository::new(self.pool.clone(), tenant.clone());
        match grants
            .revoke_with_audit(
                &GrantId::new(root.to_string()),
                asterius_domain::RevocationReason::UserRevoked,
                &[],
                now,
                audit,
            )
            .await
        {
            Ok(_) | Err(DomainError::NotFound) => Ok(true),
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn active_link(
        &self,
        tenant: &TenantId,
        jti: &str,
        client: Option<&str>,
        task: Uuid,
        revision: i64,
        grant: Option<Uuid>,
    ) -> Result<Option<GrantId>, DomainError> {
        if (grant.is_none() && jti.is_empty()) || jti.len() > 256 || revision <= 0 {
            return Ok(None);
        }
        // One statement observes one committed state. Root and intermediate
        // tombstones are authoritative even while bounded cleanup is pending.
        let row = sqlx::query(r"
            with recursive source as (
                select tenant_id,grant_id from agent_task_tokens
                where tenant_id=$1 and jti=$2 and expires_at>clock_timestamp() and $6::uuid is null
                union all
                select tenant_id,grant_id from agent_task_grants where tenant_id=$1 and grant_id=$6
            ), lineage as (
                select g.*,array[g.grant_id] as path,false as cycle
                from source x join grants g using(tenant_id,grant_id)
                where ($3::text is null or g.client_id=$3)
                union all
                select g.*,l.path||g.grant_id,g.grant_id=any(l.path)
                from grants g join lineage l on g.tenant_id=l.tenant_id and g.grant_id=l.parent_grant_id
                where not l.cycle and cardinality(l.path)<11
            )
            select b.grant_id from source x
            join agent_task_grants b using(tenant_id,grant_id)
            join agent_tasks t using(tenant_id,task_id,root_grant_id,approval_revision)
            join tenants tenant on tenant.tenant_id=t.tenant_id and tenant.status='active'
            join users owner on owner.tenant_id=t.tenant_id and owner.user_id=t.owner_reference
            join clients agent on agent.tenant_id=t.tenant_id and agent.client_id=t.client_reference
            where t.task_id=$4 and t.approval_revision=$5
              and t.expires_at>clock_timestamp() and t.revoked_at is null
              and t.root_reference=t.root_grant_id and owner.status='active'
              and agent.status='active' and agent.is_agent and agent.agent_owner_user_id=t.owner_user_id
              and exists(select 1 from lineage where grant_id=b.grant_id)
              and exists(select 1 from lineage where grant_id=t.root_grant_id)
              and not exists(
                select 1 from lineage l left join clients c using(tenant_id,client_id)
                where l.cycle or cardinality(l.path)>10 or l.revoked_at is not null
                  or (l.expires_at is not null and l.expires_at<=clock_timestamp())
                  or c.client_id is null or c.status<>'active'
                  or (c.is_agent and c.agent_owner_user_id is distinct from t.owner_user_id)
                  or (l.user_id is not null and l.user_id<>t.owner_user_id)
              )
            ").bind(tenant.as_str()).bind(jti).bind(client).bind(task).bind(revision).bind(grant)
            .fetch_optional(&self.pool).await.map_err(to_domain_error)?;
        row.map(|row| {
            row.try_get::<Uuid, _>("grant_id")
                .map(|id| GrantId::new(id.to_string()))
                .map_err(to_domain_error)
        })
        .transpose()
    }
}

/// Immutable trusted withdrawal identifiers; callers supply their audit sink.
pub(crate) struct Withdrawal {
    task: Uuid,
    root: Uuid,
    revision: i64,
    owner: Uuid,
    agent: String,
    ancestor: Uuid,
}

impl Withdrawal {
    pub(crate) fn event(
        &self,
        tenant: &TenantId,
        now: time::OffsetDateTime,
    ) -> asterius_domain::AuditEvent {
        use asterius_domain::{Actor, AuditEvent, Detail, EventType, Outcome};
        AuditEvent::new(
            tenant.clone(),
            EventType::AGENT_TASK_WITHDRAWN,
            Outcome::Success,
            Actor::System,
            now,
        )
        .client(asterius_domain::ClientId::new(self.agent.clone()))
        .grant(GrantId::new(self.ancestor.to_string()))
        .detail(
            Detail::new()
                .text("task_id", self.task.to_string())
                .text("root_grant_id", self.root.to_string())
                .text("ancestor_grant_id", self.ancestor.to_string())
                .text("owner_user_id", self.owner.to_string())
                .number("approval_revision", self.revision)
                .text(
                    "withdrawal_scope",
                    if self.ancestor == self.root {
                        "task"
                    } else {
                        "subtree"
                    },
                ),
        )
    }
}

/// Shares the signing fence before any descendant snapshot is taken. Legacy
/// grants have no task hint and retain their existing single-grant semantics.
pub(crate) async fn begin_withdrawal(
    connection: &mut sqlx::PgConnection,
    tenant: &TenantId,
    ancestor: Uuid,
    reason: &str,
    now: time::OffsetDateTime,
) -> Result<Option<Withdrawal>, DomainError> {
    // Approval backfills under the root writer lock. Resolve the immutable
    // ancestry first and take that same lock even for a legacy unbound grant;
    // only then inspect binding, so activation cannot escape withdrawal.
    let root: Option<Uuid> = sqlx::query_scalar(
        r"
        with recursive lineage as (
            select grant_id,parent_grant_id,array[grant_id] as path,false as cycle
            from grants where tenant_id=$1 and grant_id=$2
            union all
            select g.grant_id,g.parent_grant_id,l.path||g.grant_id,g.grant_id=any(l.path)
            from lineage l join grants g on g.tenant_id=$1 and g.grant_id=l.parent_grant_id
            where cardinality(l.path)<11 and not l.cycle
        ) select grant_id from lineage where parent_grant_id is null
            and cardinality(path)<=10 and not cycle
        ",
    )
    .bind(tenant.as_str())
    .bind(ancestor)
    .fetch_optional(&mut *connection)
    .await
    .map_err(to_domain_error)?;
    let root = root.ok_or(DomainError::NotFound)?;
    sqlx::query("select grant_id from grants where tenant_id=$1 and grant_id=$2 for update")
        .bind(tenant.as_str())
        .bind(root)
        .fetch_optional(&mut *connection)
        .await
        .map_err(to_domain_error)?
        .ok_or(DomainError::NotFound)?;
    let hint = sqlx::query("select task_id,root_grant_id,approval_revision from agent_task_grants where tenant_id=$1 and grant_id=$2")
        .bind(tenant.as_str()).bind(ancestor).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
    let Some(hint) = hint else {
        return Ok(None);
    };
    if hint
        .try_get::<Uuid, _>("root_grant_id")
        .map_err(to_domain_error)?
        != root
    {
        return Err(asterius_domain::agent_tasks::invalid());
    }
    let task: Uuid = hint.try_get("task_id").map_err(to_domain_error)?;
    let revision: i64 = hint.try_get("approval_revision").map_err(to_domain_error)?;
    let task_row = sqlx::query("select owner_user_id,initiating_client_id from agent_tasks where tenant_id=$1 and task_id=$2 and root_grant_id=$3 and approval_revision=$4 for update")
        .bind(tenant.as_str()).bind(task).bind(root).bind(revision).fetch_optional(&mut *connection).await.map_err(to_domain_error)?.ok_or(DomainError::NotFound)?;
    if root == ancestor {
        sqlx::query("update agent_tasks set revoked_at=$3,revocation_reason=$4 where tenant_id=$1 and task_id=$2 and revoked_at is null")
            .bind(tenant.as_str()).bind(task).bind(now).bind(reason).execute(&mut *connection).await.map_err(to_domain_error)?;
    }
    sqlx::query("insert into agent_task_withdrawals(tenant_id,ancestor_grant_id,task_id,root_grant_id,approval_revision,withdrawn_at,reason) values($1,$2,$3,$4,$5,$6,$7) on conflict(tenant_id,ancestor_grant_id) do nothing")
        .bind(tenant.as_str()).bind(ancestor).bind(task).bind(root).bind(revision).bind(now).bind(reason).execute(&mut *connection).await.map_err(to_domain_error)?;
    Ok(Some(Withdrawal {
        task,
        root,
        revision,
        ancestor,
        owner: task_row.try_get("owner_user_id").map_err(to_domain_error)?,
        agent: task_row
            .try_get("initiating_client_id")
            .map_err(to_domain_error)?,
    }))
}

/// One tenant pass touches at most 512 candidate grants and ten ancestors
/// each. UUID cursoring bounds both width and depth, including sibling runs;
/// no newly issued descendant can enter a withdrawn subtree behind the cursor.
pub(crate) async fn cleanup_withdrawals(
    connection: &mut sqlx::PgConnection,
    tenant: &TenantId,
) -> Result<bool, DomainError> {
    use sqlx::Connection as _;
    let queue = sqlx::query("select ancestor_grant_id,root_grant_id,task_id from agent_task_withdrawals where tenant_id=$1 and completed_at is null order by withdrawn_at,ancestor_grant_id limit 1")
        .bind(tenant.as_str()).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
    let Some(queue) = queue else {
        return Ok(false);
    };
    let ancestor: Uuid = queue
        .try_get("ancestor_grant_id")
        .map_err(to_domain_error)?;
    let root: Uuid = queue.try_get("root_grant_id").map_err(to_domain_error)?;
    let task: Uuid = queue.try_get("task_id").map_err(to_domain_error)?;
    let mut tx = connection.begin().await.map_err(to_domain_error)?;
    if sqlx::query(
        "select grant_id from grants where tenant_id=$1 and grant_id=$2 for update skip locked",
    )
    .bind(tenant.as_str())
    .bind(root)
    .fetch_optional(&mut *tx)
    .await
    .map_err(to_domain_error)?
    .is_none()
    {
        return Ok(true);
    }
    sqlx::query("select task_id from agent_tasks where tenant_id=$1 and task_id=$2 for update")
        .bind(tenant.as_str())
        .bind(task)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?
        .ok_or(DomainError::NotFound)?;
    let queue = sqlx::query("select cursor_grant_id,withdrawn_at,reason from agent_task_withdrawals where tenant_id=$1 and ancestor_grant_id=$2 and completed_at is null for update skip locked")
        .bind(tenant.as_str()).bind(ancestor).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
    let Some(queue) = queue else {
        return Ok(true);
    };
    let cursor: Option<Uuid> = queue.try_get("cursor_grant_id").map_err(to_domain_error)?;
    let withdrawn: time::OffsetDateTime = queue.try_get("withdrawn_at").map_err(to_domain_error)?;
    let reason: String = queue.try_get("reason").map_err(to_domain_error)?;
    let candidates: Vec<Uuid> = sqlx::query_scalar("select grant_id from agent_task_grants where tenant_id=$1 and task_id=$2 and ($3::uuid is null or grant_id>$3) order by grant_id limit 512")
        .bind(tenant.as_str()).bind(task).bind(cursor).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
    let affected: Vec<Uuid> = sqlx::query_scalar(r"
        with recursive paths as (
            select g.grant_id as candidate,g.grant_id,g.parent_grant_id,1 as depth
            from grants g where tenant_id=$1 and grant_id=any($2)
            union all select p.candidate,g.grant_id,g.parent_grant_id,p.depth+1
            from paths p join grants g on g.tenant_id=$1 and g.grant_id=p.parent_grant_id where p.depth<10
        ) select distinct candidate from paths where grant_id=$3 order by candidate
        ").bind(tenant.as_str()).bind(&candidates).bind(ancestor).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
    // Same root/task lock order as mint/revoke; all selected grant locks use
    // UUID order. Cleanup is not a fresh authority decision or external I/O.
    sqlx::query("select grant_id from grants where tenant_id=$1 and grant_id=any($2) order by grant_id for update")
        .bind(tenant.as_str()).bind(&affected).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
    sqlx::query("update grants set revoked_at=$3,revocation_reason=$4 where tenant_id=$1 and grant_id=any($2) and revoked_at is null")
        .bind(tenant.as_str()).bind(&affected).bind(withdrawn).bind(&reason).execute(&mut *tx).await.map_err(to_domain_error)?;
    sqlx::query("update refresh_tokens set revoked_at=$3 where tenant_id=$1 and grant_id=any($2) and revoked_at is null")
        .bind(tenant.as_str()).bind(&affected).bind(withdrawn).execute(&mut *tx).await.map_err(to_domain_error)?;
    sqlx::query("insert into access_token_denylist(tenant_id,jti,grant_id,revoked_at,expires_at) select tenant_id,jti,grant_id,$3,expires_at from agent_task_tokens where tenant_id=$1 and grant_id=any($2) and expires_at>clock_timestamp() on conflict(tenant_id,jti) do nothing")
        .bind(tenant.as_str()).bind(&affected).bind(withdrawn).execute(&mut *tx).await.map_err(to_domain_error)?;
    for grant in &affected {
        crate::cutoffs::withdraw(
            &mut *tx,
            tenant,
            crate::cutoffs::Principal::Grant(grant.to_string().as_str()),
            withdrawn,
        )
        .await?;
    }
    sqlx::query("update agent_task_withdrawals set cursor_grant_id=coalesce($3,cursor_grant_id),processed_grants=processed_grants+$4,completed_at=case when $5 then clock_timestamp() else null end where tenant_id=$1 and ancestor_grant_id=$2")
        .bind(tenant.as_str()).bind(ancestor).bind(candidates.last().copied()).bind(i64::try_from(affected.len()).map_err(|_| asterius_domain::agent_tasks::invalid())?).bind(candidates.len()<512).execute(&mut *tx).await.map_err(to_domain_error)?;
    tx.commit().await.map_err(to_domain_error)?;
    sqlx::query_scalar("select exists(select 1 from agent_task_withdrawals where tenant_id=$1 and completed_at is null)")
        .bind(tenant.as_str()).fetch_one(&mut *connection).await.map_err(to_domain_error)
}
