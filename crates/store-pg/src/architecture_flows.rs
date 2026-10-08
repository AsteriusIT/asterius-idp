//! Tenant-bound persistence for architecture drafts.

use asterius_domain::{
    ApplicationRole, ClientRegistration, DomainError, JwksSource, ResourceServer, RoleOwner,
    TenantId,
};
use serde_json::{Value, json};
use sqlx::{FromRow, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::to_domain_error;

#[derive(Debug, Clone)]
pub struct PgArchitectureFlows {
    pool: PgPool,
}

#[derive(Debug)]
pub struct FlowLinkIntent<'a> {
    pub node: &'a str,
    pub kind: &'a str,
    pub resource: &'a str,
    pub relation: &'a str,
}

#[derive(Debug)]
pub struct FlowApplyStep<'a> {
    pub flow: Uuid,
    pub token: Uuid,
    pub revision: i64,
    pub node: &'a str,
    pub now: OffsetDateTime,
}

#[derive(FromRow)]
struct FlowRow {
    flow_id: Uuid,
    name: String,
    graph: Value,
    revision: i64,
    applied_revision: Option<i64>,
    applied_digest: Option<String>,
    applied_graph: Option<Value>,
    last_apply_error: Option<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct FlowLinkRow {
    node_id: String,
    resource_kind: String,
    resource_id: String,
    relation: String,
    state: String,
    created_in_revision: i64,
    last_applied_revision: Option<i64>,
    resource_revision: Option<String>,
}

impl FlowRow {
    fn document(self) -> Value {
        json!({
            "id": self.flow_id,
            "name": self.name,
            "graph": self.graph,
            "revision": self.revision,
            "applied_revision": self.applied_revision,
            "applied_digest": self.applied_digest,
            "applied_graph": self.applied_graph,
            "last_apply_error": self.last_apply_error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }
}

impl PgArchitectureFlows {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list(&self, tenant: &TenantId) -> Result<Vec<Value>, DomainError> {
        let rows: Vec<FlowRow> = sqlx::query_as(
            "select flow_id, name, graph, revision, applied_revision, applied_digest, applied_graph, last_apply_error, created_at, updated_at from architecture_flows
             where tenant_id = $1 order by updated_at desc, flow_id limit 100",
        )
        .bind(tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(rows.into_iter().map(FlowRow::document).collect())
    }

    pub async fn read(&self, tenant: &TenantId, id: Uuid) -> Result<Value, DomainError> {
        let row: FlowRow = sqlx::query_as(
            "select flow_id, name, graph, revision, applied_revision, applied_digest, applied_graph, last_apply_error, created_at, updated_at from architecture_flows
             where tenant_id = $1 and flow_id = $2",
        )
        .bind(tenant.as_str())
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(row.document())
    }

    pub async fn create(
        &self,
        tenant: &TenantId,
        id: Uuid,
        name: &str,
        graph: Value,
        now: OffsetDateTime,
    ) -> Result<Value, DomainError> {
        let row: FlowRow = sqlx::query_as(
            "insert into architecture_flows (tenant_id, flow_id, name, graph, created_at, updated_at)
             values ($1, $2, $3, $4, $5, $5)
             returning flow_id, name, graph, revision, applied_revision, applied_digest, applied_graph, last_apply_error, created_at, updated_at"
        ).bind(tenant.as_str()).bind(id).bind(name).bind(graph).bind(now)
            .fetch_one(&self.pool).await.map_err(to_domain_error)?;
        Ok(row.document())
    }

    pub async fn update(
        &self,
        tenant: &TenantId,
        id: Uuid,
        revision: i64,
        name: &str,
        graph: Value,
        now: OffsetDateTime,
    ) -> Result<Value, DomainError> {
        let row: Option<FlowRow> = sqlx::query_as(
            "update architecture_flows set name = $4, graph = $5, revision = revision + 1, updated_at = $6
             where tenant_id = $1 and flow_id = $2 and revision = $3
               and (apply_token is null or apply_deadline < $6)
             returning flow_id, name, graph, revision, applied_revision, applied_digest, applied_graph, last_apply_error, created_at, updated_at"
        ).bind(tenant.as_str()).bind(id).bind(revision).bind(name).bind(graph).bind(now)
            .fetch_optional(&self.pool).await.map_err(to_domain_error)?;
        match row {
            Some(row) => Ok(row.document()),
            None => match self.read(tenant, id).await {
                Ok(_) => Err(DomainError::Conflict(
                    "flow revision changed; reload before saving".into(),
                )),
                Err(error) => Err(error),
            },
        }
    }

    pub async fn links(&self, tenant: &TenantId, id: Uuid) -> Result<Vec<Value>, DomainError> {
        let rows: Vec<FlowLinkRow> = sqlx::query_as(
            "select node_id, resource_kind, resource_id, relation, state, created_in_revision, last_applied_revision, resource_revision
             from flow_resource_links where tenant_id = $1 and flow_id = $2 order by node_id"
        ).bind(tenant.as_str()).bind(id).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        Ok(rows.into_iter().map(|row| json!({
            "node_id": row.node_id, "resource_kind": row.resource_kind, "resource_id": row.resource_id,
            "relation": row.relation, "state": row.state, "created_in_revision": row.created_in_revision,
            "last_applied_revision": row.last_applied_revision,
            "resource_revision": row.resource_revision,
        })).collect())
    }

    /// Returns every flow that names this tenant's resource. A managed link is
    /// its creation origin; references never claim ownership.
    pub async fn origins(
        &self,
        tenant: &TenantId,
        kind: &str,
        resource: &str,
    ) -> Result<Vec<Value>, DomainError> {
        let rows: Vec<(Uuid, String, String, String, String)> = sqlx::query_as(
            "select links.flow_id, flows.name, links.node_id, links.relation, links.state
             from flow_resource_links links
             join architecture_flows flows on flows.tenant_id = links.tenant_id and flows.flow_id = links.flow_id
             where links.tenant_id = $1 and links.resource_kind = $2 and links.resource_id = $3
             order by links.relation, flows.name, links.node_id",
        )
        .bind(tenant.as_str()).bind(kind).bind(resource)
        .fetch_all(&self.pool).await.map_err(to_domain_error)?;
        Ok(rows
            .into_iter()
            .map(|(flow, name, node, relation, state)| {
                json!({
                    "flow_id": flow, "flow_name": name, "node_id": node,
                    "relation": relation, "state": state,
                })
            })
            .collect())
    }

    pub async fn begin_apply(
        &self,
        tenant: &TenantId,
        id: Uuid,
        revision: i64,
        now: OffsetDateTime,
    ) -> Result<Uuid, DomainError> {
        let token = Uuid::new_v4();
        let claimed = sqlx::query(
            "update architecture_flows set apply_token = $4, apply_deadline = $5, last_apply_error = null
             where tenant_id = $1 and flow_id = $2 and revision = $3
               and (apply_token is null or apply_deadline < $6)"
        ).bind(tenant.as_str()).bind(id).bind(revision).bind(token)
            .bind(now + time::Duration::minutes(5)).bind(now)
            .execute(&self.pool).await.map_err(to_domain_error)?.rows_affected();
        if claimed == 1 {
            Ok(token)
        } else {
            match self.read(tenant, id).await {
                Ok(_) => Err(DomainError::Conflict(
                    "flow changed or another apply is running".into(),
                )),
                Err(error) => Err(error),
            }
        }
    }

    pub async fn reserve(
        &self,
        tenant: &TenantId,
        flow: Uuid,
        token: Uuid,
        revision: i64,
        link: &FlowLinkIntent<'_>,
        now: OffsetDateTime,
    ) -> Result<Value, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let active: bool = sqlx::query_scalar(
            "select exists(select 1 from architecture_flows where tenant_id = $1 and flow_id = $2 and revision = $3 and apply_token = $4 and apply_deadline > $5)"
        ).bind(tenant.as_str()).bind(flow).bind(revision).bind(token).bind(now)
            .fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        if !active {
            return Err(DomainError::Conflict(
                "apply lease expired; preview again".into(),
            ));
        }
        let row: (String, String, String, String) = sqlx::query_as(
            "insert into flow_resource_links (tenant_id, flow_id, node_id, resource_kind, resource_id, relation, state, created_in_revision, created_at, updated_at)
             values ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $8)
             on conflict (tenant_id, flow_id, node_id) do update set updated_at = flow_resource_links.updated_at
             returning resource_kind, resource_id, relation, state"
        ).bind(tenant.as_str()).bind(flow).bind(link.node).bind(link.kind).bind(link.resource).bind(link.relation).bind(revision).bind(now)
            .fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        if row.0 != link.kind || row.1 != link.resource || row.2 != link.relation {
            return Err(DomainError::Conflict(
                "flow node already belongs to another resource".into(),
            ));
        }
        sqlx::query("update architecture_flows set apply_deadline = $4 where tenant_id = $1 and flow_id = $2 and apply_token = $3")
            .bind(tenant.as_str()).bind(flow).bind(token).bind(now + time::Duration::minutes(5))
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(
            json!({"node_id": link.node, "resource_kind": link.kind, "resource_id": link.resource, "relation": link.relation, "state": row.3}),
        )
    }

    /// Pin the exact flow-owned established stream under its retained row lock.
    pub async fn complete_stream(&self, tenant: &TenantId, step: &FlowApplyStep<'_>, peer: &str) -> Result<(), DomainError> {
        let mut tx=self.pool.begin().await.map_err(to_domain_error)?;
        let stream: Option<String> = sqlx::query_scalar("select stream_id from ssf_receiver_upstream_streams where tenant_id=$1 and peer_client_id=$2 and origin_flow=$3 and origin_node=$4 and deletion_started_at is null for share")
            .bind(tenant.as_str()).bind(peer).bind(step.flow).bind(step.node).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        let stream=stream.ok_or_else(||DomainError::Conflict("exact flow-owned established stream required".into()))?;
        let changed=sqlx::query("update flow_resource_links set state='applied',last_applied_revision=$4,resource_revision=$5,updated_at=clock_timestamp() where tenant_id=$1 and flow_id=$2 and node_id=$3 and resource_kind='stream' and resource_id=$6 and relation='managed' and exists(select 1 from architecture_flows where tenant_id=$1 and flow_id=$2 and revision=$4 and apply_token=$7 and apply_deadline>clock_timestamp())")
            .bind(tenant.as_str()).bind(step.flow).bind(step.node).bind(step.revision).bind(stream).bind(peer).bind(step.token)
            .execute(&mut *tx).await.map_err(to_domain_error)?.rows_affected();
        if changed!=1 {return Err(DomainError::Conflict("stream apply lease or origin changed".into()));}
        tx.commit().await.map_err(to_domain_error)
    }

    pub async fn complete(
        &self,
        tenant: &TenantId,
        flow: Uuid,
        token: Uuid,
        revision: i64,
        node: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let changed = sqlx::query(
            "update flow_resource_links set state = 'applied', last_applied_revision = $4, updated_at = $5
             where tenant_id = $1 and flow_id = $2 and node_id = $3
               and exists (select 1 from architecture_flows where tenant_id = $1 and flow_id = $2 and apply_token = $6)"
        ).bind(tenant.as_str()).bind(flow).bind(node).bind(revision).bind(now).bind(token)
            .execute(&self.pool).await.map_err(to_domain_error)?.rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(DomainError::Conflict("apply lease was lost".into()))
        }
    }

    pub async fn finish_apply(
        &self,
        tenant: &TenantId,
        flow: Uuid,
        token: Uuid,
        revision: i64,
        digest: &str,
        error: Option<&str>,
    ) -> Result<(), DomainError> {
        let changed = sqlx::query(
            "update architecture_flows set apply_token = null, apply_deadline = null,
             applied_revision = case when $6::text is null then $4 else applied_revision end,
             applied_digest = case when $6::text is null then $5 else applied_digest end,
             applied_graph = case when $6::text is null then graph else applied_graph end,
             last_apply_error = $6
             where tenant_id = $1 and flow_id = $2 and apply_token = $3 and revision = $4",
        )
        .bind(tenant.as_str())
        .bind(flow)
        .bind(token)
        .bind(revision)
        .bind(digest)
        .bind(error)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(DomainError::Conflict("apply lease was lost".into()))
        }
    }

    /// Inserts a pre-reserved group ID, so an interrupted apply can retry
    /// without claiming a same-name group that somebody else created.
    pub async fn create_group(
        &self,
        tenant: &TenantId,
        id: Uuid,
        name: &str,
        display_name: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let changed = sqlx::query(
            "insert into managed_groups (tenant_id, group_id, name, display_name, created_at, updated_at)
             values ($1, $2, $3, $4, $5, $5) on conflict (tenant_id, group_id) do nothing"
        ).bind(tenant.as_str()).bind(id).bind(name).bind(display_name).bind(now)
            .execute(&self.pool).await.map_err(to_domain_error)?.rows_affected();
        if changed == 1 {
            return Ok(());
        }
        let existing: (String, String) = sqlx::query_as(
            "select name, display_name from managed_groups where tenant_id = $1 and group_id = $2",
        )
        .bind(tenant.as_str())
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)?;
        if existing.0 == name && existing.1 == display_name {
            Ok(())
        } else {
            Err(DomainError::Conflict(
                "reserved group ID has different metadata".into(),
            ))
        }
    }

    /// Defines a client role and marks its flow link in one transaction. A
    /// process crash cannot leave a role that the next apply might mistake for
    /// somebody else's same-name definition.
    pub async fn create_role_and_complete(
        &self,
        flow: Uuid,
        token: Uuid,
        revision: i64,
        node: &str,
        role: &ApplicationRole,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let RoleOwner::Client(client) = &role.owner else {
            return Err(DomainError::invalid(
                "role.owner",
                "flow roles need an application",
            ));
        };
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let active: bool = sqlx::query_scalar(
            "select exists(select 1 from architecture_flows where tenant_id = $1 and flow_id = $2 and revision = $3 and apply_token = $4 and apply_deadline > $5)"
        ).bind(role.tenant.as_str()).bind(flow).bind(revision).bind(token).bind(now)
            .fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        if !active {
            return Err(DomainError::Conflict("apply lease expired".into()));
        }
        let created = sqlx::query(
            "insert into client_roles (tenant_id, client_id, name, description, created_at)
             values ($1, $2, $3, $4, $5) on conflict (tenant_id, client_id, name) do nothing",
        )
        .bind(role.tenant.as_str())
        .bind(client.as_str())
        .bind(role.name.as_str())
        .bind(role.description.as_deref())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        if created != 1 {
            return Err(DomainError::Conflict(
                "role was created after preview".into(),
            ));
        }
        let changed = sqlx::query(
            "update flow_resource_links set state = 'applied', last_applied_revision = $4, updated_at = $5
             where tenant_id = $1 and flow_id = $2 and node_id = $3 and state = 'pending'
               and resource_kind = 'role' and relation = 'managed' and resource_id = $6"
        ).bind(role.tenant.as_str()).bind(flow).bind(node).bind(revision).bind(now)
            .bind(json!([client.as_str(), role.name.as_str()]).to_string())
            .execute(&mut *tx).await.map_err(to_domain_error)?.rows_affected();
        if changed != 1 {
            return Err(DomainError::Conflict("role link was not reserved".into()));
        }
        tx.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    /// Changes only a role still carrying its previous applied description.
    pub async fn update_role_description(
        &self,
        tenant: &TenantId,
        client: &str,
        name: &str,
        expected: Option<&str>,
        description: Option<&str>,
    ) -> Result<(), DomainError> {
        let changed = sqlx::query(
            "update client_roles set description = $5
             where tenant_id = $1 and client_id = $2 and name = $3
               and description is not distinct from $4",
        )
        .bind(tenant.as_str())
        .bind(client)
        .bind(name)
        .bind(expected)
        .bind(description)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(DomainError::Conflict("role changed since preview".into()))
        }
    }

    /// Creates a new API without replacing another operator's registration.
    pub async fn create_api(
        &self,
        tenant: &TenantId,
        server: &ResourceServer,
    ) -> Result<(), DomainError> {
        let scopes = server
            .scopes
            .as_ref()
            .map(|set| set.iter().cloned().collect::<Vec<_>>());
        let lifetime = server
            .default_token_lifetime
            .and_then(|duration| i32::try_from(duration.whole_seconds()).ok());
        let introspectors = server
            .introspection_clients
            .iter()
            .map(|client| client.as_str().to_owned())
            .collect::<Vec<_>>();
        let created = sqlx::query(
            "insert into resource_servers (tenant_id, identifier, scopes, token_lifetime_seconds, introspection_clients)
             values ($1, $2, $3, $4, $5) on conflict (tenant_id, identifier) do nothing"
        ).bind(tenant.as_str()).bind(server.identifier.as_str()).bind(scopes).bind(lifetime).bind(introspectors)
            .execute(&self.pool).await.map_err(to_domain_error)?.rows_affected();
        if created == 1 {
            Ok(())
        } else {
            Err(DomainError::Conflict(
                "API identifier was registered after preview".into(),
            ))
        }
    }

    /// Inserts the API and marks its origin together. An interrupted apply
    /// cannot adopt another operator's same-URI API on retry.
    pub async fn create_api_and_complete(
        &self,
        tenant: &TenantId,
        step: &FlowApplyStep<'_>,
        server: &ResourceServer,
    ) -> Result<(), DomainError> {
        let scopes = server
            .scopes
            .as_ref()
            .map(|set| set.iter().cloned().collect::<Vec<_>>());
        let lifetime = server
            .default_token_lifetime
            .and_then(|duration| i32::try_from(duration.whole_seconds()).ok());
        let introspectors = server
            .introspection_clients
            .iter()
            .map(|client| client.as_str().to_owned())
            .collect::<Vec<_>>();
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let active: bool = sqlx::query_scalar(
            "select exists(select 1 from architecture_flows where tenant_id = $1 and flow_id = $2 and revision = $3 and apply_token = $4 and apply_deadline > $5)"
        ).bind(tenant.as_str()).bind(step.flow).bind(step.revision).bind(step.token).bind(step.now)
            .fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        if !active {
            return Err(DomainError::Conflict("apply lease expired".into()));
        }
        let created = sqlx::query(
            "insert into resource_servers (tenant_id, identifier, scopes, token_lifetime_seconds, introspection_clients)
             values ($1, $2, $3, $4, $5) on conflict (tenant_id, identifier) do nothing"
        ).bind(tenant.as_str()).bind(server.identifier.as_str()).bind(scopes).bind(lifetime).bind(introspectors)
            .execute(&mut *tx).await.map_err(to_domain_error)?.rows_affected();
        if created != 1 {
            return Err(DomainError::Conflict(
                "API was registered after preview".into(),
            ));
        }
        let linked = sqlx::query(
            "update flow_resource_links set state = 'applied', last_applied_revision = $4, updated_at = $5
             where tenant_id = $1 and flow_id = $2 and node_id = $3 and state = 'pending'
               and resource_kind = 'api' and relation = 'managed' and resource_id = $6"
        ).bind(tenant.as_str()).bind(step.flow).bind(step.node).bind(step.revision).bind(step.now)
            .bind(server.identifier.as_str()).execute(&mut *tx).await.map_err(to_domain_error)?.rows_affected();
        if linked != 1 {
            return Err(DomainError::Conflict("API link was not reserved".into()));
        }
        tx.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    /// Replaces a resource server only while its live policy still equals the
    /// last applied specification. Manual edits cannot be overwritten by a
    /// concurrent flow apply.
    pub async fn update_api(
        &self,
        tenant: &TenantId,
        old: &ResourceServer,
        new: &ResourceServer,
    ) -> Result<(), DomainError> {
        let columns = |server: &ResourceServer| {
            (
                server
                    .scopes
                    .as_ref()
                    .map(|set| set.iter().cloned().collect::<Vec<_>>()),
                server
                    .default_token_lifetime
                    .and_then(|value| i32::try_from(value.whole_seconds()).ok()),
                server
                    .introspection_clients
                    .iter()
                    .map(|client| client.as_str().to_owned())
                    .collect::<Vec<_>>(),
            )
        };
        let (old_scopes, old_lifetime, old_clients) = columns(old);
        let (scopes, lifetime, clients) = columns(new);
        let changed = sqlx::query(
            "update resource_servers set scopes = $3, token_lifetime_seconds = $4, introspection_clients = $5, updated_at = now()
             where tenant_id = $1 and identifier = $2 and scopes is not distinct from $6
               and token_lifetime_seconds is not distinct from $7 and introspection_clients = $8",
        ).bind(tenant.as_str()).bind(new.identifier.as_str()).bind(scopes).bind(lifetime).bind(clients)
            .bind(old_scopes).bind(old_lifetime).bind(old_clients)
            .execute(&self.pool).await.map_err(to_domain_error)?.rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(DomainError::Conflict("API changed since preview".into()))
        }
    }

    /// Updates only fields owned by the architecture node. Other client
    /// security metadata and audience policy remain untouched.
    pub async fn update_client(
        &self,
        tenant: &TenantId,
        id: &str,
        expected_updated_at: OffsetDateTime,
        registration: &ClientRegistration,
    ) -> Result<(), DomainError> {
        let (jwks, jwks_uri) = match &registration.jwks {
            JwksSource::Uri(uri) => (None, Some(uri.as_str())),
            JwksSource::Inline(keys) => (Some(keys.clone()), None),
            JwksSource::None => {
                return Err(DomainError::invalid("jwks", "public keys are required"));
            }
        };
        let redirects = registration
            .redirect_uris
            .iter()
            .map(|uri| uri.as_str().to_owned())
            .collect::<Vec<_>>();
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        crate::PgClientRepository::lifecycle_fence_on(&mut transaction, tenant).await?;
        let changed = sqlx::query(
            "update clients set client_name = $4, redirect_uris = $5, jwks_uri = $6, jwks = $7
             where tenant_id = $1 and client_id = $2 and updated_at = $3
               and token_endpoint_auth_method = 'private_key_jwt'",
        )
        .bind(tenant.as_str())
        .bind(id)
        .bind(expected_updated_at)
        .bind(&registration.client_name)
        .bind(redirects)
        .bind(jwks_uri)
        .bind(jwks)
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        if changed == 1 {
            transaction.commit().await.map_err(to_domain_error)?;
            Ok(())
        } else {
            Err(DomainError::Conflict(
                "application changed since preview".into(),
            ))
        }
    }

    /// Adds one already registered API audience without replacing concurrent
    /// additions made through the ordinary client editor.
    pub async fn add_client_resource(
        &self,
        tenant: &TenantId,
        client: &str,
        resource: &str,
    ) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        crate::PgClientRepository::lifecycle_fence_on(&mut transaction, tenant).await?;
        let changed = sqlx::query(
            "update clients set resources = (select array_agg(distinct value order by value)
               from unnest(resources || array[$3]::text[]) as items(value))
             where tenant_id = $1 and client_id = $2
               and exists (select 1 from resource_servers where tenant_id = $1 and identifier = $3)"
        ).bind(tenant.as_str()).bind(client).bind(resource).execute(&mut *transaction).await
            .map_err(to_domain_error)?.rows_affected();
        if changed == 1 {
            transaction.commit().await.map_err(to_domain_error)?;
            Ok(())
        } else {
            Err(DomainError::Conflict(
                "client or API is no longer available".into(),
            ))
        }
    }
}
