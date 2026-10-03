//! Bounded repeatable snapshots for the administrative task viewer.
use crate::error::to_domain_error;
use asterius_domain::agent_task_views::{
    Ceiling, GrantNode, MAX_LINEAGE_ROWS, MAX_TASK_PAGE, Page, Query, Snapshot, State, Task,
};
use asterius_domain::agent_tasks::Permissions;
use asterius_domain::{
    AgentLimits, ClientId, DomainError, ResourceServer, TenantId, TenantSettings,
};
use sqlx::{Row as _, postgres::PgRow};
use std::collections::BTreeSet;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PgAgentTaskViews {
    pool: sqlx::PgPool,
}
impl PgAgentTaskViews {
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
    pub async fn list(&self, tenant: &TenantId, query: &Query) -> Result<Page, DomainError> {
        bounded(query)?;
        let rows=sqlx::query(&format!("{TASK_SELECT} where t.tenant_id=$1 and ($2::uuid is null or t.task_id>$2) and ($3::uuid is null or t.owner_user_id=$3) and ($4::text is null or t.initiating_client_id=$4) order by t.task_id limit $5"))
            .bind(tenant.as_str()).bind(query.cursor).bind(query.owner).bind(query.agent.as_ref().map(ClientId::as_str)).bind(i64::try_from(query.limit+1).map_err(|_|invalid())?)
            .fetch_all(&self.pool).await.map_err(to_domain_error)?;
        let now = rows
            .first()
            .map(|row| {
                row.try_get::<OffsetDateTime, _>("observed_at")
                    .map_err(to_domain_error)
            })
            .transpose()?
            .unwrap_or_else(OffsetDateTime::now_utc);
        let more = rows.len() > query.limit;
        let items = rows
            .iter()
            .take(query.limit)
            .map(|row| task(row, now))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = more
            .then(|| items.last().map(|task| task.task_id))
            .flatten();
        Ok(Page {
            items,
            next_cursor,
            observed_at: instant(now)?,
        })
    }
    pub async fn snapshot(
        &self,
        tenant: &TenantId,
        id: Uuid,
        query: &Query,
        implicit: &[ResourceServer],
    ) -> Result<Snapshot, DomainError> {
        bounded(query)?;
        if query.owner.is_some() || query.agent.is_some() {
            return Err(invalid());
        }
        // Read-only repeatable state: all parent, principal and policy rows are
        // one observation, never a promise about a later authorization request.
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query("set transaction isolation level repeatable read read only")
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let now: OffsetDateTime = sqlx::query_scalar("select transaction_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let row = sqlx::query(&format!(
            "{TASK_SELECT} where t.tenant_id=$1 and t.task_id=$2"
        ))
        .bind(tenant.as_str())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?
        .ok_or(DomainError::NotFound)?;
        let mut task = task(&row, now)?;
        let permissions: Permissions =
            serde_json::from_value(row.try_get("permissions").map_err(to_domain_error)?)
                .map_err(|_| invalid())?;
        let approved = Ceiling::approved(&permissions)?;
        let mut current = approved.clone();
        let settings: serde_json::Value =
            row.try_get("tenant_settings").map_err(to_domain_error)?;
        let settings = TenantSettings::from_json(settings.get("options")).map_err(|_| invalid())?;
        let mut kinds: BTreeSet<String> = set(&row, "client_grant_types")?;
        let mut ttl = settings.lifetimes().access_token().whole_seconds().min(300);
        let deadline = deadline(&row, task.expires_at.as_str())?;
        ttl = ttl.min((deadline - now).whole_seconds().max(0));
        current.narrow(
            &set(&row, "client_scopes")?,
            &set(&row, "client_resources")?,
            permissions.max_delegation_depth,
        );
        apply_limits(&mut current, &mut kinds, &mut ttl, &row, &settings)?;
        apply_resource_policies(&mut tx, tenant, &mut current, implicit).await?;
        current.cap_lifetime(ttl);
        if task.state != State::Active {
            clear(&mut current);
            kinds.clear();
            ttl = 0;
        }
        // The initiating agent is not the only authority: the immutable root
        // and each ancestor client must still permit the displayed ceiling.
        let root = root_node(
            &mut tx,
            &NodeContext {
                tenant,
                task: &task,
                approved: &approved,
                task_current: &current,
                now,
                settings: &settings,
            },
        )
        .await?;
        apply_root_observation(root, &mut task, &mut current, &mut kinds, &mut ttl);
        let nodes=sqlx::query("select g.* from agent_task_grants b join grants g using(tenant_id,grant_id) where b.tenant_id=$1 and b.task_id=$2 and ($3::uuid is null or b.grant_id>$3) order by b.grant_id limit $4")
            .bind(tenant.as_str()).bind(id).bind(query.cursor).bind(i64::try_from(query.limit+1).map_err(|_|invalid())?).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
        let more = nodes.len() > query.limit;
        let mut lineage = Vec::new();
        for node in nodes.iter().take(query.limit) {
            lineage.push(
                grant_node(
                    &mut tx,
                    node,
                    &NodeContext {
                        tenant,
                        task: &task,
                        approved: &approved,
                        task_current: &current,
                        now,
                        settings: &settings,
                    },
                )
                .await?,
            );
        }
        let next_cursor = more
            .then(|| lineage.last().map(|node| node.grant_id))
            .flatten();
        tx.commit().await.map_err(to_domain_error)?;
        Ok(Snapshot {
            task,
            approved_ceiling: approved,
            current_issuance_ceiling: current,
            current_grant_types: kinds,
            maximum_new_token_ttl_seconds: ttl,
            observed_at: instant(now)?,
            lineage,
            next_cursor,
            conditional_decision: "not_evaluated",
        })
    }
}
async fn apply_resource_policies(
    connection: &mut sqlx::PgConnection,
    tenant: &TenantId,
    current: &mut Ceiling,
    implicit: &[ResourceServer],
) -> Result<(), DomainError> {
    let resources = current.resources.clone();
    for resource in resources {
        let policy=sqlx::query("select scopes,token_lifetime_seconds from resource_servers where tenant_id=$1 and identifier=$2")
                .bind(tenant.as_str()).bind(&resource).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
        if let Some(policy) = policy {
            let scopes: Option<Vec<String>> = policy.try_get("scopes").map_err(to_domain_error)?;
            let scopes = scopes.map(|values| values.into_iter().collect());
            let lifetime: Option<i32> = policy
                .try_get("token_lifetime_seconds")
                .map_err(to_domain_error)?;
            current.resource_policy(&resource, scopes.as_ref(), lifetime.map(i64::from));
        } else if let Some(policy) = implicit
            .iter()
            .find(|policy| policy.identifier.as_str() == resource)
        {
            current.resource_policy(
                &resource,
                policy.scopes.as_ref(),
                policy
                    .default_token_lifetime
                    .map(time::Duration::whole_seconds),
            );
        } else {
            let mut resources = current.resources.clone();
            resources.remove(&resource);
            current.narrow(
                &current.scopes.clone(),
                &resources,
                current.max_delegation_depth,
            );
        }
    }
    // A removed or incompatible RAR schema cannot be presented as an
    // available action comparator, even if its historical approval remains.
    let schema:Option<serde_json::Value>=sqlx::query_scalar("select schema from authorization_details_types where tenant_id=$1 and type_name='urn:asterius:workload-actions'")
            .bind(tenant.as_str()).fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
    if let Some(schema) = schema {
        let schema = asterius_domain::entities::authorization_details::Schema::parse(&schema)
            .map_err(|_| invalid())?;
        current.actions.retain(|action|schema.validate(&serde_json::json!({"type":"urn:asterius:workload-actions","locations":[action.resource],"actions":action.actions})).is_ok());
    } else {
        current.actions.clear();
    }
    Ok(())
}
async fn root_node(
    connection: &mut sqlx::PgConnection,
    context: &NodeContext<'_>,
) -> Result<Option<RootObservation>, DomainError> {
    let root = sqlx::query("select g.*,c.is_agent,c.agent_policy,c.authorization_details_types,c.grant_types as client_grant_types from grants g left join clients c using(tenant_id,client_id) where g.tenant_id=$1 and g.grant_id=$2")
        .bind(context.tenant.as_str()).bind(context.task.root_grant_id)
        .fetch_optional(&mut *connection).await.map_err(to_domain_error)?;
    match root {
        Some(root) => {
            let node = grant_node(connection, &root, context).await?;
            let mut kinds = set(&root, "client_grant_types")?;
            let mut ceiling = node.current_issuance_ceiling.clone();
            let mut ttl = 300;
            apply_limits(&mut ceiling, &mut kinds, &mut ttl, &root, context.settings)?;
            Ok(Some(RootObservation { node, kinds }))
        }
        None => Ok(None),
    }
}
struct RootObservation {
    node: GrantNode,
    kinds: BTreeSet<String>,
}
fn apply_root_observation(
    root: Option<RootObservation>,
    task: &mut Task,
    current: &mut Ceiling,
    kinds: &mut BTreeSet<String>,
    ttl: &mut i64,
) {
    if let Some(root) = root {
        kinds.retain(|kind| root.kinds.contains(kind));
        let root = root.node;
        *current = root.current_issuance_ceiling;
        if root.state == State::Active {
            *ttl = (*ttl).min(
                current
                    .resource_ceilings
                    .iter()
                    .map(|resource| resource.maximum_token_ttl_seconds)
                    .max()
                    .unwrap_or(0),
            );
        } else {
            task.state = root.state;
            kinds.clear();
            *ttl = 0;
        }
    } else {
        task.state = State::AncestorUnavailable;
        clear(current);
        kinds.clear();
        *ttl = 0;
    }
}
const TASK_SELECT: &str = "select t.*,statement_timestamp() as observed_at,tenant.status as tenant_status,tenant.settings as tenant_settings,owner.status as owner_status,c.status as client_status,c.is_agent,c.agent_owner_user_id,c.scopes as client_scopes,c.resources as client_resources,c.grant_types as client_grant_types,c.agent_policy,c.authorization_details_types,root.grant_id as current_root,root.revoked_at as root_revoked_at,root.expires_at as root_expires_at from agent_tasks t join tenants tenant using(tenant_id) left join users owner on owner.tenant_id=t.tenant_id and owner.user_id=t.owner_reference left join clients c on c.tenant_id=t.tenant_id and c.client_id=t.client_reference left join grants root on root.tenant_id=t.tenant_id and root.grant_id=t.root_reference";
fn invalid() -> DomainError {
    DomainError::invalid("task_view", "task evidence cannot be read")
}
fn bounded(query: &Query) -> Result<(), DomainError> {
    if !(1..=MAX_TASK_PAGE).contains(&query.limit)
        || query
            .agent
            .as_ref()
            .is_some_and(|agent| agent.as_str().is_empty() || agent.as_str().len() > 256)
    {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn instant(time: OffsetDateTime) -> Result<String, DomainError> {
    time.format(&Rfc3339).map_err(|_| invalid())
}
fn optional_instant(row: &PgRow, column: &str) -> Result<Option<String>, DomainError> {
    row.try_get::<Option<OffsetDateTime>, _>(column)
        .map_err(to_domain_error)?
        .map(instant)
        .transpose()
}
fn set(row: &PgRow, column: &str) -> Result<BTreeSet<String>, DomainError> {
    Ok(row
        .try_get::<Option<Vec<String>>, _>(column)
        .map_err(to_domain_error)?
        .unwrap_or_default()
        .into_iter()
        .collect())
}
fn task(row: &PgRow, now: OffsetDateTime) -> Result<Task, DomainError> {
    let expires: OffsetDateTime = row.try_get("expires_at").map_err(to_domain_error)?;
    let revoked: Option<OffsetDateTime> = row.try_get("revoked_at").map_err(to_domain_error)?;
    let root_revoked: Option<OffsetDateTime> =
        row.try_get("root_revoked_at").map_err(to_domain_error)?;
    let root_expires: Option<OffsetDateTime> =
        row.try_get("root_expires_at").map_err(to_domain_error)?;
    let owner: Uuid = row.try_get("owner_user_id").map_err(to_domain_error)?;
    let state = if revoked.is_some() || root_revoked.is_some() {
        State::Withdrawn
    } else if expires <= now || root_expires.is_some_and(|expiry| expiry <= now) {
        State::Expired
    } else if row
        .try_get::<String, _>("tenant_status")
        .map_err(to_domain_error)?
        != "active"
        || row
            .try_get::<Option<String>, _>("owner_status")
            .map_err(to_domain_error)?
            .as_deref()
            != Some("active")
        || row
            .try_get::<Option<String>, _>("client_status")
            .map_err(to_domain_error)?
            .as_deref()
            != Some("active")
        || row
            .try_get::<Option<bool>, _>("is_agent")
            .map_err(to_domain_error)?
            != Some(true)
        || row
            .try_get::<Option<Uuid>, _>("agent_owner_user_id")
            .map_err(to_domain_error)?
            != Some(owner)
    {
        State::PrincipalUnavailable
    } else if row
        .try_get::<Option<Uuid>, _>("current_root")
        .map_err(to_domain_error)?
        .is_none()
    {
        State::AncestorUnavailable
    } else {
        State::Active
    };
    Ok(Task {
        task_id: row.try_get("task_id").map_err(to_domain_error)?,
        root_grant_id: row.try_get("root_grant_id").map_err(to_domain_error)?,
        owner_user_id: owner,
        initiating_client_id: ClientId::new(
            row.try_get::<String, _>("initiating_client_id")
                .map_err(to_domain_error)?,
        ),
        approval_revision: row.try_get("approval_revision").map_err(to_domain_error)?,
        label: row.try_get("label").map_err(to_domain_error)?,
        approved_at: instant(row.try_get("approved_at").map_err(to_domain_error)?)?,
        expires_at: instant(expires)?,
        revoked_at: revoked.or(root_revoked).map(instant).transpose()?,
        state,
    })
}
fn deadline(row: &PgRow, expiry: &str) -> Result<OffsetDateTime, DomainError> {
    let expiry = OffsetDateTime::parse(expiry, &Rfc3339).map_err(|_| invalid())?;
    Ok(row
        .try_get::<Option<OffsetDateTime>, _>("root_expires_at")
        .map_err(to_domain_error)?
        .map_or(expiry, |root| root.min(expiry)))
}
fn clear(ceiling: &mut Ceiling) {
    ceiling.scopes.clear();
    ceiling.resources.clear();
    ceiling.actions.clear();
    ceiling.resource_ceilings.clear();
}
fn apply_limits(
    ceiling: &mut Ceiling,
    kinds: &mut BTreeSet<String>,
    ttl: &mut i64,
    row: &PgRow,
    settings: &TenantSettings,
) -> Result<(), DomainError> {
    let is_agent = row
        .try_get::<Option<bool>, _>("is_agent")
        .map_err(to_domain_error)?
        .unwrap_or(false);
    let mut limits = Vec::new();
    if is_agent {
        if let Some(document) = row
            .try_get::<Option<serde_json::Value>, _>("agent_policy")
            .map_err(to_domain_error)?
        {
            limits.push(AgentLimits::from_json(&document).map_err(|_| invalid())?);
        }
        if let Some(tenant) = settings.registration().agent_limits() {
            limits.push(tenant.clone());
        }
    }
    let types = set(row, "authorization_details_types")?;
    if !types.contains("urn:asterius:workload-actions") {
        ceiling.actions.clear();
    }
    for limits in limits {
        let scopes = limits
            .scopes()
            .cloned()
            .unwrap_or_else(|| ceiling.scopes.clone());
        let resources = limits
            .audiences()
            .cloned()
            .unwrap_or_else(|| ceiling.resources.clone());
        ceiling.narrow(&scopes, &resources, limits.max_delegation_depth());
        kinds.retain(|kind| {
            limits
                .grant_types()
                .iter()
                .any(|allowed| allowed.as_str() == kind)
        });
        if limits
            .authorization_details_types()
            .is_some_and(|types| !types.contains("urn:asterius:workload-actions"))
        {
            ceiling.actions.clear();
        }
        if let Some(cap) = limits.access_token_ttl_cap() {
            *ttl = (*ttl).min(cap.whole_seconds());
        }
    }
    ceiling.cap_lifetime(*ttl);
    Ok(())
}

struct NodeContext<'a> {
    tenant: &'a TenantId,
    task: &'a Task,
    approved: &'a Ceiling,
    task_current: &'a Ceiling,
    now: OffsetDateTime,
    settings: &'a TenantSettings,
}
async fn grant_node(
    connection: &mut sqlx::PgConnection,
    row: &PgRow,
    context: &NodeContext<'_>,
) -> Result<GrantNode, DomainError> {
    let tenant = context.tenant;
    let task = context.task;
    let approved = context.approved;
    let task_current = context.task_current;
    let now = context.now;
    let id: Uuid = row.try_get("grant_id").map_err(to_domain_error)?;
    let ancestors = sqlx::query(
        r"
        with recursive lineage as (
            select g.*,array[g.grant_id] as path,false as cycle
            from grants g where tenant_id=$1 and grant_id=$2
            union all
            select g.*,l.path||g.grant_id,g.grant_id=any(l.path)
            from grants g join lineage l on g.tenant_id=l.tenant_id and g.grant_id=l.parent_grant_id
            where cardinality(l.path)<10 and not l.cycle
        ) select l.*,c.status as client_status,c.is_agent,c.agent_owner_user_id,
            c.scopes as client_scopes,c.resources as client_resources,
            c.grant_types as client_grant_types,c.agent_policy,c.authorization_details_types
        from lineage l left join clients c using(tenant_id,client_id)
        order by cardinality(l.path)
        ",
    )
    .bind(tenant.as_str())
    .bind(id)
    .fetch_all(&mut *connection)
    .await
    .map_err(to_domain_error)?;
    let mut recorded = approved.clone();
    recorded.narrow(
        &set(row, "scopes")?,
        &set(row, "resources")?,
        approved.max_delegation_depth,
    );
    let details: serde_json::Value = row
        .try_get("authorization_details")
        .map_err(to_domain_error)?;
    let details = details.as_array().ok_or_else(invalid)?;
    recorded.narrow_actions(details);
    let mut observation = AncestorObservation {
        current: task_current.clone(),
        state: task.state,
        ids: Vec::new(),
        kinds: BTreeSet::new(),
        root_found: false,
        ttl: (OffsetDateTime::parse(&task.expires_at, &Rfc3339).map_err(|_| invalid())? - now)
            .whole_seconds()
            .clamp(0, 300),
    };
    for ancestor in &ancestors {
        apply_ancestor(ancestor, context, &mut observation)?;
    }
    let AncestorObservation {
        mut current,
        mut state,
        mut ids,
        ttl,
        root_found,
        ..
    } = observation;
    let complete_root = ancestors.last().is_some_and(|ancestor| {
        ancestor.try_get::<Uuid, _>("grant_id").ok() == Some(task.root_grant_id)
            && ancestor.try_get::<Option<Uuid>, _>("parent_grant_id").ok() == Some(None)
    });
    if !root_found || !complete_root || ids.len() > MAX_LINEAGE_ROWS {
        state = State::AncestorUnavailable;
    }
    ids.reverse();
    current.cap_lifetime(ttl);
    let chain: serde_json::Value = row.try_get("actor_chain").map_err(to_domain_error)?;
    if state != State::Active
        || chain
            .as_array()
            .is_none_or(|chain| chain.len() > usize::from(current.max_delegation_depth))
    {
        clear(&mut current);
    }
    Ok(GrantNode {
        grant_id: id,
        parent_grant_id: row.try_get("parent_grant_id").map_err(to_domain_error)?,
        client_id: ClientId::new(
            row.try_get::<String, _>("client_id")
                .map_err(to_domain_error)?,
        ),
        depth: ids.len().saturating_sub(1),
        ancestry: ids,
        expires_at: optional_instant(row, "expires_at")?,
        revoked_at: optional_instant(row, "revoked_at")?,
        state,
        recorded_ceiling: recorded,
        current_issuance_ceiling: current,
    })
}

struct AncestorObservation {
    current: Ceiling,
    state: State,
    ids: Vec<Uuid>,
    kinds: BTreeSet<String>,
    ttl: i64,
    root_found: bool,
}
fn apply_ancestor(
    ancestor: &PgRow,
    context: &NodeContext<'_>,
    observation: &mut AncestorObservation,
) -> Result<(), DomainError> {
    let task = context.task;
    let now = context.now;
    let settings = context.settings;
    let ancestor_id: Uuid = ancestor.try_get("grant_id").map_err(to_domain_error)?;
    observation.root_found |= ancestor_id == task.root_grant_id;
    observation.ids.push(ancestor_id);
    if ancestor
        .try_get::<bool, _>("cycle")
        .map_err(to_domain_error)?
    {
        observation.state = State::AncestorUnavailable;
    }
    if observation.state == State::Active
        && ancestor
            .try_get::<Option<OffsetDateTime>, _>("revoked_at")
            .map_err(to_domain_error)?
            .is_some()
    {
        observation.state = State::Withdrawn;
    }
    if let Some(expiry) = ancestor
        .try_get::<Option<OffsetDateTime>, _>("expires_at")
        .map_err(to_domain_error)?
    {
        observation.ttl = observation.ttl.min((expiry - now).whole_seconds().max(0));
        if observation.state == State::Active && expiry <= now {
            observation.state = State::Expired;
        }
    }
    if observation.state == State::Active
        && (ancestor
            .try_get::<Option<String>, _>("client_status")
            .map_err(to_domain_error)?
            .as_deref()
            != Some("active")
            || ancestor
                .try_get::<Option<Uuid>, _>("user_id")
                .map_err(to_domain_error)?
                .is_some_and(|user| user != task.owner_user_id)
            || (ancestor
                .try_get::<Option<bool>, _>("is_agent")
                .map_err(to_domain_error)?
                == Some(true)
                && ancestor
                    .try_get::<Option<Uuid>, _>("agent_owner_user_id")
                    .map_err(to_domain_error)?
                    != Some(task.owner_user_id)))
    {
        observation.state = State::PrincipalUnavailable;
    }
    observation.current.narrow(
        &set(ancestor, "scopes")?,
        &set(ancestor, "resources")?,
        observation.current.max_delegation_depth,
    );
    let detail: serde_json::Value = ancestor
        .try_get("authorization_details")
        .map_err(to_domain_error)?;
    observation
        .current
        .narrow_actions(detail.as_array().ok_or_else(invalid)?);
    observation.current.narrow(
        &set(ancestor, "client_scopes")?,
        &set(ancestor, "client_resources")?,
        observation.current.max_delegation_depth,
    );
    apply_limits(
        &mut observation.current,
        &mut observation.kinds,
        &mut observation.ttl,
        ancestor,
        settings,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_task_view_missing_root_clears_current_authority() {
        let mut task = Task {
            task_id: Uuid::new_v4(),
            root_grant_id: Uuid::new_v4(),
            owner_user_id: Uuid::new_v4(),
            initiating_client_id: ClientId::new("agent"),
            approval_revision: 1,
            label: "controlled task".into(),
            approved_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-01T00:10:00Z".into(),
            revoked_at: None,
            state: State::Active,
        };
        let permissions = Permissions {
            scopes: BTreeSet::from(["read".into()]),
            resources: BTreeSet::from(["https://api.example/".into()]),
            authorization_details: Vec::new(),
            max_delegation_depth: 2,
        };
        let mut ceiling = Ceiling::approved(&permissions).expect("controlled approval");
        let mut kinds = BTreeSet::from(["authorization_code".into()]);
        let mut ttl = 60;
        apply_root_observation(None, &mut task, &mut ceiling, &mut kinds, &mut ttl);
        assert_eq!(task.state, State::AncestorUnavailable);
        assert!(ceiling.scopes.is_empty() && ceiling.resources.is_empty());
        assert!(kinds.is_empty());
        assert_eq!(ttl, 0);
    }
}
