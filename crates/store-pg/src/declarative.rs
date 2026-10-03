//! Atomic management writes over live runtime tables, never a shadow configuration.
use asterius_domain::declarative::{Document, Error, Identity, Kind, Management, Mutation};
use asterius_domain::{Capabilities, GroupMetadata, TenantId};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{PgConnection, PgPool};

#[derive(Debug, Clone)]
pub struct PgDeclarative {
    pool: PgPool,
    capabilities: Capabilities,
    kek: std::sync::Arc<dyn asterius_jose::Kek>,
}

fn storage(error: sqlx::Error) -> Error {
    if let sqlx::Error::Database(ref db) = error {
        match db.message() {
            "declarative_delete_protected" => return Error::Protected,
            "declarative_owner_conflict" => return Error::Owner,
            _ if db.is_unique_violation() => return Error::LogicalKey,
            _ if db.is_foreign_key_violation() => return Error::Dependency,
            _ => {}
        }
    }
    Error::Storage(crate::to_domain_error(error))
}

impl PgDeclarative {
    #[must_use]
    pub const fn new(
        pool: PgPool,
        capabilities: Capabilities,
        kek: std::sync::Arc<dyn asterius_jose::Kek>,
    ) -> Self {
        Self {
            pool,
            capabilities,
            kek,
        }
    }
}

async fn lock(
    connection: &mut PgConnection,
    id: &Identity,
    require_parent: bool,
) -> Result<(), Error> {
    id.validate()?;
    if matches!(id.kind, Kind::Membership | Kind::Group) {
        sqlx::query("select declarative_lock($1,'group',$2)")
            .bind(id.tenant.as_str())
            .bind(json!([id.keys[0]]))
            .execute(&mut *connection)
            .await
            .map_err(storage)?;
        let group = sqlx::query(
            "select group_id from managed_groups where tenant_id=$1 and group_id=$2 for update",
        )
        .bind(id.tenant.as_str())
        .bind(uuid_key(&id.keys[0])?)
        .fetch_optional(&mut *connection)
        .await
        .map_err(storage)?;
        // A membership requires its live parent. Group creation uses a fresh
        // UUID, so the advisory lock is sufficient until its row is inserted.
        // Other operations check live rows after locking. In particular,
        // deletion receipts remain usable after the parent group is removed.
        if require_parent && id.kind == Kind::Membership && group.is_none() {
            return Err(Error::NotFound);
        }
    }
    sqlx::query("select declarative_lock($1,$2,$3)")
        .bind(id.tenant.as_str())
        .bind(id.kind.as_str())
        .bind(json!(id.keys))
        .execute(connection)
        .await
        .map_err(storage)?;
    Ok(())
}

async fn origins(connection: &mut PgConnection, id: &Identity) -> Result<Vec<Value>, Error> {
    let builder_kind = match id.kind {
        Kind::Application => "application",
        Kind::Resource => "api",
        _ => id.kind.as_str(),
    };
    sqlx::query_scalar("select jsonb_build_object('flow_id',flow_id,'node_id',node_id,'relation',relation,'state',state) from flow_resource_links where tenant_id=$1 and resource_kind=$2 and resource_id=$3 order by flow_id,node_id")
        .bind(id.tenant.as_str()).bind(builder_kind).bind(&id.keys[0])
        .fetch_all(connection).await.map_err(storage)
}

async fn metadata(
    connection: &mut PgConnection,
    id: &Identity,
) -> Result<(Option<String>, bool), Error> {
    let value: Option<(Option<String>, bool)> = sqlx::query_as("select owner,deletion_protection from declarative_owners where tenant_id=$1 and kind=$2 and keys=$3")
        .bind(id.tenant.as_str()).bind(id.kind.as_str()).bind(json!(id.keys)).fetch_optional(connection).await.map_err(storage)?;
    Ok(value.unwrap_or((None, true)))
}

async fn read_live(
    connection: &mut PgConnection,
    id: &Identity,
    capabilities: Capabilities,
) -> Result<Value, Error> {
    match id.kind {
        Kind::Resource => sqlx::query_scalar("select jsonb_build_object('identifier',identifier,'scopes',scopes,'default_token_lifetime_seconds',token_lifetime_seconds,'introspection_clients',introspection_clients) from resource_servers where tenant_id=$1 and identifier=$2")
            .bind(id.tenant.as_str()).bind(&id.keys[0]).fetch_optional(connection).await.map_err(storage)?.ok_or(Error::NotFound),
        Kind::Group => sqlx::query_scalar("select jsonb_build_object('name',name,'display_name',display_name) from managed_groups where tenant_id=$1 and group_id=$2")
            .bind(id.tenant.as_str()).bind(uuid_key(&id.keys[0])?).fetch_optional(connection).await.map_err(storage)?.ok_or(Error::NotFound),
        Kind::Membership => sqlx::query_scalar("select jsonb_build_object('group_id',group_id,'user_id',user_id) from group_memberships where tenant_id=$1 and group_id=$2 and user_id=$3")
            .bind(id.tenant.as_str()).bind(uuid_key(&id.keys[0])?).bind(uuid_key(&id.keys[1])?).fetch_optional(connection).await.map_err(storage)?.ok_or(Error::NotFound),
        Kind::Policy => sqlx::query_scalar("select document from tenant_policies where tenant_id=$1")
            .bind(id.tenant.as_str()).fetch_optional(connection).await.map_err(storage)?.ok_or(Error::NotFound),
        Kind::Application => crate::declarative_clients::read(connection, id, capabilities).await,
        Kind::Tenant => crate::declarative_tenants::read(connection, id).await,
    }
}

async fn read_document(
    connection: &mut PgConnection,
    id: &Identity,
    capabilities: Capabilities,
) -> Result<Document, Error> {
    let spec = read_live(connection, id, capabilities).await?;
    let (owner, protection) = metadata(connection, id).await?;
    let origin = origins(connection, id).await?;
    let parent_revision: Option<Value> = if matches!(id.kind, Kind::Membership | Kind::Group) {
        sqlx::query_scalar("select jsonb_build_array(g.revision,o.revision) from managed_groups g left join declarative_owners o on o.tenant_id=g.tenant_id and o.kind='group' and o.keys=jsonb_build_array(g.group_id::text) where g.tenant_id=$1 and g.group_id=$2")
            .bind(id.tenant.as_str()).bind(uuid_key(&id.keys[0])?).fetch_optional(&mut *connection).await.map_err(storage)?
    } else {
        None
    };
    let generation: Option<i64> = sqlx::query_scalar(
        "select revision from declarative_owners where tenant_id=$1 and kind=$2 and keys=$3",
    )
    .bind(id.tenant.as_str())
    .bind(id.kind.as_str())
    .bind(json!(id.keys))
    .fetch_optional(&mut *connection)
    .await
    .map_err(storage)?;
    let revision_value = json!([spec, owner, protection, origin, parent_revision, generation]);
    let encoded = serde_json::to_vec(&revision_value).map_err(|_| Error::Invalid)?;
    let revision = format!("{:x}", Sha256::digest(encoded));
    Ok(Document {
        contract_version: 1,
        id: id.encode()?,
        kind: id.kind,
        spec,
        revision,
        owner,
        origin,
        deletion_protection: protection,
    })
}

fn uuid_key(key: &str) -> Result<uuid::Uuid, Error> {
    uuid::Uuid::parse_str(key).map_err(|_| Error::Invalid)
}

async fn set_owner(
    connection: &mut PgConnection,
    id: &Identity,
    owner: Option<&str>,
    protection: bool,
) -> Result<(), Error> {
    sqlx::query("insert into declarative_owners(tenant_id,kind,keys,owner,deletion_protection) values($1,$2,$3,$4,$5) on conflict(tenant_id,kind,keys) do update set owner=excluded.owner,deletion_protection=excluded.deletion_protection,revision=declarative_owners.revision+1")
        .bind(id.tenant.as_str()).bind(id.kind.as_str()).bind(json!(id.keys)).bind(owner).bind(protection).execute(connection).await.map_err(storage)?;
    Ok(())
}

async fn may_adopt(connection: &mut PgConnection, id: &Identity) -> Result<(), Error> {
    if origins(connection, id)
        .await?
        .iter()
        .any(|origin| origin["relation"] == "managed")
    {
        return Err(Error::Owner);
    }
    if id.kind == Kind::Group || id.kind == Kind::Membership {
        let scim_owned:bool=sqlx::query_scalar("select exists(select 1 from scim_group_owners where tenant_id=$1 and group_id=$2 union all select 1 from ldap_group_owners where tenant_id=$1 and group_id=$2)")
            .bind(id.tenant.as_str()).bind(uuid_key(&id.keys[0])?).fetch_one(connection).await.map_err(storage)?;
        if scim_owned {
            return Err(Error::Owner);
        }
    }
    Ok(())
}

fn identity_for(tenant: &TenantId, kind: Kind, spec: &Value) -> Result<Identity, Error> {
    let keys = match kind {
        Kind::Group => vec![uuid::Uuid::new_v4().to_string()],
        Kind::Resource => vec![
            spec["identifier"]
                .as_str()
                .ok_or(Error::Invalid)?
                .to_owned(),
        ],
        Kind::Membership => vec![
            spec["group_id"].as_str().ok_or(Error::Invalid)?.to_owned(),
            spec["user_id"].as_str().ok_or(Error::Invalid)?.to_owned(),
        ],
        Kind::Policy => vec!["policy".to_owned()],
        Kind::Tenant => vec![tenant.as_str().to_owned()],
        Kind::Application => return Err(Error::Unsupported),
    };
    let id = Identity {
        tenant: tenant.clone(),
        kind,
        keys,
    };
    id.validate()?;
    Ok(id)
}

async fn write_live(
    connection: &mut PgConnection,
    id: &Identity,
    spec: &Value,
    creating: bool,
    capabilities: Capabilities,
) -> Result<(), Error> {
    match id.kind {
        Kind::Resource => {
            let identifier = asterius_domain::ResourceIdentifier::parse(&id.keys[0])
                .map_err(|_| Error::Invalid)?;
            if spec["identifier"].as_str() != Some(identifier.as_str()) {
                return Err(Error::Invalid);
            }
            let scopes: Option<Vec<String>> =
                serde_json::from_value(spec["scopes"].clone()).map_err(|_| Error::Invalid)?;
            let lifetime: Option<i32> =
                serde_json::from_value(spec["default_token_lifetime_seconds"].clone())
                    .map_err(|_| Error::Invalid)?;
            let callers: Vec<String> =
                serde_json::from_value(spec["introspection_clients"].clone())
                    .map_err(|_| Error::Invalid)?;
            if creating {
                sqlx::query("insert into resource_servers(tenant_id,identifier,scopes,token_lifetime_seconds,introspection_clients) values($1,$2,$3,$4,$5)")
                    .bind(id.tenant.as_str()).bind(identifier.as_str()).bind(scopes).bind(lifetime).bind(callers).execute(connection).await.map_err(storage)?;
            } else {
                sqlx::query("update resource_servers set scopes=$3,token_lifetime_seconds=$4,introspection_clients=$5 where tenant_id=$1 and identifier=$2")
                    .bind(id.tenant.as_str()).bind(identifier.as_str()).bind(scopes).bind(lifetime).bind(callers).execute(connection).await.map_err(storage)?;
            }
        }
        Kind::Group => {
            let name = spec["name"].as_str().ok_or(Error::Invalid)?;
            let display = spec["display_name"].as_str().ok_or(Error::Invalid)?;
            GroupMetadata::parse(name, display).map_err(|_| Error::Invalid)?;
            if creating {
                sqlx::query("insert into managed_groups(tenant_id,group_id,name,display_name,created_at,updated_at) values($1,$2,$3,$4,now(),now())")
                    .bind(id.tenant.as_str()).bind(uuid_key(&id.keys[0])?).bind(name).bind(display).execute(connection).await.map_err(storage)?;
            } else {
                sqlx::query("update managed_groups set name=$3,display_name=$4,revision=revision+1,updated_at=now() where tenant_id=$1 and group_id=$2")
                    .bind(id.tenant.as_str()).bind(uuid_key(&id.keys[0])?).bind(name).bind(display).execute(connection).await.map_err(storage)?;
            }
        }
        Kind::Membership => {
            if spec != &json!({"group_id":id.keys[0],"user_id":id.keys[1]}) {
                return Err(Error::Invalid);
            }
            sqlx::query("insert into group_memberships(tenant_id,group_id,user_id,created_at) values($1,$2,$3,now()) on conflict do nothing")
                .bind(id.tenant.as_str()).bind(uuid_key(&id.keys[0])?).bind(uuid_key(&id.keys[1])?).execute(&mut *connection).await.map_err(storage)?;
            sqlx::query("update managed_groups set revision=revision+1,updated_at=now() where tenant_id=$1 and group_id=$2")
                .bind(id.tenant.as_str()).bind(uuid_key(&id.keys[0])?).execute(connection).await.map_err(storage)?;
        }
        Kind::Policy => {
            let rules =
                asterius_domain::policy::RuleSet::from_json(spec).map_err(|_| Error::Invalid)?;
            sqlx::query("insert into tenant_policies(tenant_id,document,created_at,updated_at) values($1,$2,now(),now()) on conflict(tenant_id) do update set document=excluded.document,updated_at=now()")
                .bind(id.tenant.as_str()).bind(rules.to_json()).execute(connection).await.map_err(storage)?;
        }
        Kind::Application => {
            crate::declarative_clients::replace(connection, id, spec, capabilities).await?;
        }
        Kind::Tenant => {
            if creating {
                return Err(Error::Unsupported);
            }
            crate::declarative_tenants::replace(connection, id, spec).await?;
        }
    }
    Ok(())
}

async fn delete_live(connection: &mut PgConnection, id: &Identity) -> Result<(), Error> {
    match id.kind {
        Kind::Resource => {
            sqlx::query("delete from resource_servers where tenant_id=$1 and identifier=$2")
                .bind(id.tenant.as_str())
                .bind(&id.keys[0])
                .execute(connection)
                .await
                .map_err(storage)?;
        }
        Kind::Group => {
            let members:bool=sqlx::query_scalar("select exists(select 1 from group_memberships where tenant_id=$1 and group_id=$2 union all select 1 from group_tenant_roles where tenant_id=$1 and group_id=$2 union all select 1 from group_client_roles where tenant_id=$1 and group_id=$2)")
                .bind(id.tenant.as_str()).bind(uuid_key(&id.keys[0])?).fetch_one(&mut *connection).await.map_err(storage)?;
            if members {
                return Err(Error::Dependency);
            }
            sqlx::query("delete from managed_groups where tenant_id=$1 and group_id=$2")
                .bind(id.tenant.as_str())
                .bind(uuid_key(&id.keys[0])?)
                .execute(connection)
                .await
                .map_err(storage)?;
        }
        Kind::Membership => {
            sqlx::query(
                "delete from group_memberships where tenant_id=$1 and group_id=$2 and user_id=$3",
            )
            .bind(id.tenant.as_str())
            .bind(uuid_key(&id.keys[0])?)
            .bind(uuid_key(&id.keys[1])?)
            .execute(&mut *connection)
            .await
            .map_err(storage)?;
            sqlx::query("update managed_groups set revision=revision+1,updated_at=now() where tenant_id=$1 and group_id=$2")
                .bind(id.tenant.as_str()).bind(uuid_key(&id.keys[0])?).execute(connection).await.map_err(storage)?;
        }
        Kind::Policy => {
            sqlx::query("delete from tenant_policies where tenant_id=$1")
                .bind(id.tenant.as_str())
                .execute(connection)
                .await
                .map_err(storage)?;
        }
        Kind::Application => {
            crate::declarative_clients::delete(connection, id).await?;
        }
        Kind::Tenant => {
            crate::declarative_tenants::delete(connection, id)?;
        }
    }
    Ok(())
}

async fn normalise_spec(
    connection: &mut PgConnection,
    tenant: &TenantId,
    kind: Kind,
    spec: &Value,
    capabilities: Capabilities,
) -> Result<Value, Error> {
    match kind {
        Kind::Application => {
            crate::declarative_clients::normalise(connection, tenant, spec, capabilities).await
        }
        Kind::Tenant => crate::declarative_tenants::normalise(connection, tenant, spec),
        _ => Ok(spec.clone()),
    }
}

#[async_trait::async_trait]
impl Management for PgDeclarative {
    async fn normalise(&self, tenant: &TenantId, kind: Kind, spec: &Value) -> Result<Value, Error> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let spec = normalise_spec(&mut tx, tenant, kind, spec, self.capabilities).await?;
        tx.commit().await.map_err(storage)?;
        Ok(spec)
    }

    async fn read(&self, id: &Identity) -> Result<Document, Error> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        lock(&mut tx, id, false).await?;
        let document = read_document(&mut tx, id, self.capabilities).await?;
        tx.commit().await.map_err(storage)?;
        Ok(document)
    }
    async fn resolve(
        &self,
        tenant: &TenantId,
        owner: &str,
        kind: Kind,
        external_key: &str,
    ) -> Result<Document, Error> {
        let keys:Option<Value>=sqlx::query_scalar("select keys from declarative_creation_keys where tenant_id=$1 and kind=$2 and owner=$3 and external_key=$4")
            .bind(tenant.as_str()).bind(kind.as_str()).bind(owner).bind(external_key).fetch_optional(&self.pool).await.map_err(storage)?;
        let keys =
            serde_json::from_value(keys.ok_or(Error::NotFound)?).map_err(|_| Error::Invalid)?;
        self.read(&Identity {
            tenant: tenant.clone(),
            kind,
            keys,
        })
        .await
    }
    // Keep claim, CAS, live write and logical identity inside one visibly shared transaction.
    #[allow(clippy::too_many_lines)]
    async fn mutate(
        &self,
        tenant: &TenantId,
        owner: &str,
        mutation: Mutation,
    ) -> Result<Option<Document>, Error> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        sqlx::query("select set_config('asterius.declarative_owner',$1,true)")
            .bind(owner)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        let mutation = match mutation {
            Mutation::Create {
                kind,
                external_key,
                spec,
                deletion_protection,
            } => Mutation::Create {
                kind,
                external_key,
                spec: normalise_spec(&mut tx, tenant, kind, &spec, self.capabilities).await?,
                deletion_protection,
            },
            Mutation::Replace {
                identity,
                expected,
                spec,
                deletion_protection,
            } => {
                let canonical =
                    normalise_spec(&mut tx, tenant, identity.kind, &spec, self.capabilities)
                        .await?;
                Mutation::Replace {
                    identity,
                    expected,
                    spec: canonical,
                    deletion_protection,
                }
            }
            other => other,
        };
        let id = match &mutation {
            Mutation::Create {
                kind,
                external_key,
                spec,
                deletion_protection,
            } => {
                if external_key.is_empty()
                    || external_key.len() > 512
                    || external_key.chars().any(char::is_control)
                {
                    return Err(Error::Invalid);
                }
                sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,1))")
                    .bind(format!(
                        "{}:{}:{}:{}",
                        tenant.as_str(),
                        kind.as_str(),
                        owner,
                        external_key
                    ))
                    .execute(&mut *tx)
                    .await
                    .map_err(storage)?;
                let existing:Option<(Value,Value,bool,uuid::Uuid)>=sqlx::query_as("select keys,initial_spec,initial_protection,incarnation from declarative_creation_keys where tenant_id=$1 and kind=$2 and owner=$3 and external_key=$4")
                    .bind(tenant.as_str()).bind(kind.as_str()).bind(owner).bind(external_key).fetch_optional(&mut *tx).await.map_err(storage)?;
                if let Some((keys, initial_spec, initial_protection, incarnation)) = existing {
                    if initial_protection != *deletion_protection || initial_spec != *spec {
                        return Err(Error::LogicalKey);
                    }
                    let id = Identity {
                        tenant: tenant.clone(),
                        kind: *kind,
                        keys: serde_json::from_value(keys).map_err(|_| Error::Invalid)?,
                    };
                    lock(&mut tx, &id, false).await?;
                    let current:Option<(bool,uuid::Uuid)>=sqlx::query_as("select deleted,incarnation from declarative_owners where tenant_id=$1 and kind=$2 and keys=$3")
                        .bind(tenant.as_str()).bind(kind.as_str()).bind(json!(id.keys)).fetch_optional(&mut *tx).await.map_err(storage)?;
                    if current != Some((false, incarnation)) {
                        return Err(Error::LogicalKey);
                    }
                    let document = read_document(&mut tx, &id, self.capabilities)
                        .await
                        .map_err(|e| {
                            if matches!(e, Error::NotFound) {
                                Error::LogicalKey
                            } else {
                                e
                            }
                        })?;
                    if document.owner.as_deref() != Some(owner) {
                        return Err(Error::Owner);
                    }
                    tx.commit().await.map_err(storage)?;
                    return Ok(Some(document));
                }
                let id = match kind {
                    Kind::Application => {
                        crate::declarative_clients::create(&mut tx, tenant, spec, self.capabilities)
                            .await?
                    }
                    Kind::Tenant => {
                        crate::declarative_tenants::create_with_kek(
                            &mut tx,
                            tenant,
                            spec,
                            self.kek.as_ref(),
                        )
                        .await?
                    }
                    _ => identity_for(tenant, *kind, spec)?,
                };
                lock(&mut tx, &id, true).await?;
                if !matches!(kind, Kind::Application | Kind::Tenant) {
                    match read_live(&mut tx, &id, self.capabilities).await {
                        Ok(_) => return Err(Error::LogicalKey),
                        Err(Error::NotFound) => {}
                        Err(error) => return Err(error),
                    }
                }
                may_adopt(&mut tx, &id).await?;
                if !matches!(kind, Kind::Application | Kind::Tenant) {
                    write_live(&mut tx, &id, spec, true, self.capabilities).await?;
                }
                set_owner(&mut tx, &id, Some(owner), *deletion_protection).await?;
                sqlx::query("insert into declarative_creation_keys(tenant_id,kind,owner,external_key,keys,initial_spec,initial_protection,incarnation) select $1,$2,$3,$4,$5,$6,$7,incarnation from declarative_owners where tenant_id=$1 and kind=$2 and keys=$5")
                    .bind(tenant.as_str()).bind(kind.as_str()).bind(owner).bind(external_key).bind(json!(id.keys)).bind(spec).bind(deletion_protection).execute(&mut *tx).await.map_err(storage)?;
                id
            }
            Mutation::Replace { identity, .. }
            | Mutation::Adopt { identity, .. }
            | Mutation::Release { identity, .. }
            | Mutation::Delete { identity, .. } => {
                if identity.tenant != *tenant {
                    return Err(Error::NotFound);
                }
                lock(&mut tx, identity, false).await?;
                let (held_owner, protected) = metadata(&mut tx, identity).await?;
                if let Mutation::Delete { expected, .. } = &mutation {
                    let receipt:bool=sqlx::query_scalar("select exists(select 1 from declarative_deletion_receipts where tenant_id=$1 and kind=$2 and keys=$3 and owner=$4 and expected_revision=$5)")
                        .bind(tenant.as_str()).bind(identity.kind.as_str()).bind(json!(identity.keys)).bind(owner).bind(expected).fetch_one(&mut *tx).await.map_err(storage)?;
                    if receipt {
                        tx.commit().await.map_err(storage)?;
                        return Ok(None);
                    }
                }
                let (Mutation::Replace { expected, .. }
                | Mutation::Adopt { expected, .. }
                | Mutation::Release { expected, .. }
                | Mutation::Delete { expected, .. }) = &mutation
                else {
                    return Err(Error::Invalid);
                };
                match read_document(&mut tx, identity, self.capabilities).await {
                    Ok(held) => {
                        if &held.revision != expected {
                            return Err(Error::Revision);
                        }
                    }
                    Err(Error::NotFound)
                        if matches!(mutation, Mutation::Release { .. })
                            && held_owner.as_deref() == Some(owner) =>
                    {
                        set_owner(&mut tx, identity, None, protected).await?;
                        tx.commit().await.map_err(storage)?;
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                }
                if matches!(mutation, Mutation::Adopt { .. }) {
                    if held_owner.as_deref().is_some_and(|held| held != owner) {
                        return Err(Error::Owner);
                    }
                    may_adopt(&mut tx, identity).await?;
                    set_owner(&mut tx, identity, Some(owner), true).await?;
                } else {
                    if held_owner.as_deref() != Some(owner) {
                        return Err(Error::Owner);
                    }
                    match &mutation {
                        Mutation::Replace {
                            spec,
                            deletion_protection,
                            ..
                        } => {
                            may_adopt(&mut tx, identity).await?;
                            write_live(&mut tx, identity, spec, false, self.capabilities).await?;
                            set_owner(&mut tx, identity, Some(owner), *deletion_protection).await?;
                        }
                        Mutation::Release { .. } => {
                            set_owner(&mut tx, identity, None, protected).await?;
                        }
                        Mutation::Delete { .. } => {
                            if protected {
                                return Err(Error::Protected);
                            }
                            delete_live(&mut tx, identity).await?;
                            sqlx::query("insert into declarative_deletion_receipts(tenant_id,kind,keys,owner,expected_revision) values($1,$2,$3,$4,$5)")
                                .bind(tenant.as_str()).bind(identity.kind.as_str()).bind(json!(identity.keys)).bind(owner).bind(expected).execute(&mut *tx).await.map_err(storage)?;
                            tx.commit().await.map_err(storage)?;
                            return Ok(None);
                        }
                        _ => return Err(Error::Invalid),
                    }
                }
                identity.clone()
            }
        };
        let result = read_document(&mut tx, &id, self.capabilities).await?;
        tx.commit().await.map_err(storage)?;
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    #[ignore = "slow live PostgreSQL management integration; CI only"]
    // One persisted six-kind stack verifies cross-resource retry/import relationships.
    #[allow(clippy::too_many_lines)]
    async fn six_kinds_commit_live_state_and_refuse_stale_or_conflicting_retries() {
        let url = std::env::var("DATABASE_URL").expect("CI database URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("database");
        let tenant = TenantId::parse(&format!("decl-{}", uuid::Uuid::new_v4().simple()))
            .expect("tenant identity");
        let kek = Arc::new(asterius_jose::LocalKek::from_bytes(&[0x52; 32]).expect("test KEK"));
        let management = PgDeclarative::new(pool.clone(), Capabilities::default(), kek);
        let owner = "[\"deployment\",\"controller-a\"]";
        let tenant_spec = json!({"tenant_id":tenant.as_str(),"issuer":format!("https://id.example/t/{}",tenant.as_str()),"display_name":"Managed","default_resource":"https://default.example/","options":{}});
        let tenant_document = management
            .mutate(
                &tenant,
                owner,
                Mutation::Create {
                    kind: Kind::Tenant,
                    external_key: "tenant-config".to_owned(),
                    spec: tenant_spec.clone(),
                    deletion_protection: true,
                },
            )
            .await
            .expect("atomic tenant/key/salt creation")
            .expect("tenant document");
        let tenant_retry = management
            .mutate(
                &tenant,
                owner,
                Mutation::Create {
                    kind: Kind::Tenant,
                    external_key: "tenant-config".to_owned(),
                    spec: tenant_spec,
                    deletion_protection: true,
                },
            )
            .await
            .expect("lost response retry")
            .expect("tenant");
        assert_eq!(tenant_retry.id, tenant_document.id);
        let tenant_id = Identity::parse(&tenant_document.id).expect("import identity");
        assert!(matches!(
            management
                .mutate(
                    &tenant,
                    owner,
                    Mutation::Delete {
                        identity: tenant_id,
                        expected: tenant_document.revision.clone()
                    }
                )
                .await,
            Err(Error::Protected)
        ));
        let resource=management.mutate(&tenant,owner,Mutation::Create{kind:Kind::Resource,external_key:"audience-config".to_owned(),spec:json!({"identifier":"https://managed.example/","scopes":["read"],"default_token_lifetime_seconds":300,"introspection_clients":[]}),deletion_protection:true}).await.expect("resource").expect("resource document");
        let resource_id = Identity::parse(&resource.id).expect("identity");
        assert!(matches!(
            management
                .mutate(
                    &tenant,
                    "[\"deployment\",\"controller-b\"]",
                    Mutation::Adopt {
                        identity: resource_id.clone(),
                        expected: resource.revision.clone()
                    }
                )
                .await,
            Err(Error::Owner)
        ));
        let mut updated = resource.spec.clone();
        updated["scopes"] = json!(["read", "write"]);
        let changed = management
            .mutate(
                &tenant,
                owner,
                Mutation::Replace {
                    identity: resource_id.clone(),
                    expected: resource.revision.clone(),
                    spec: updated,
                    deletion_protection: false,
                },
            )
            .await
            .expect("conditional replace")
            .expect("resource");
        assert!(matches!(
            management
                .mutate(
                    &tenant,
                    owner,
                    Mutation::Replace {
                        identity: resource_id.clone(),
                        expected: resource.revision,
                        spec: changed.spec.clone(),
                        deletion_protection: false
                    }
                )
                .await,
            Err(Error::Revision)
        ));
        let deletion = Mutation::Delete {
            identity: resource_id,
            expected: changed.revision,
        };
        assert!(
            management
                .mutate(&tenant, owner, deletion.clone())
                .await
                .expect("delete")
                .is_none()
        );
        assert!(
            management
                .mutate(&tenant, owner, deletion)
                .await
                .expect("delete retry")
                .is_none()
        );
        let group = management
            .mutate(
                &tenant,
                owner,
                Mutation::Create {
                    kind: Kind::Group,
                    external_key: "group-config".to_owned(),
                    spec: json!({"name":"managed","display_name":"Managed"}),
                    deletion_protection: true,
                },
            )
            .await
            .expect("group")
            .expect("document");
        let group_id = Identity::parse(&group.id).expect("group identity");
        let user = uuid::Uuid::new_v4();
        sqlx::query("insert into users(tenant_id,user_id,username) values($1,$2,$3)")
            .bind(tenant.as_str())
            .bind(user)
            .bind(format!("{user}@example.test"))
            .execute(&pool)
            .await
            .expect("existing tenant user");
        let membership = management
            .mutate(
                &tenant,
                owner,
                Mutation::Create {
                    kind: Kind::Membership,
                    external_key: "membership-config".to_owned(),
                    spec: json!({"group_id":group_id.keys[0],"user_id":user.to_string()}),
                    deletion_protection: true,
                },
            )
            .await
            .expect("membership")
            .expect("document");
        assert_ne!(
            management
                .read(&group_id)
                .await
                .expect("group refresh")
                .revision,
            group.revision
        );
        let policy = management
            .mutate(
                &tenant,
                owner,
                Mutation::Create {
                    kind: Kind::Policy,
                    external_key: "policy-config".to_owned(),
                    spec: json!({"version":1,"rules":[]}),
                    deletion_protection: true,
                },
            )
            .await
            .expect("policy")
            .expect("document");
        let public_key =
            asterius_jose::SigningKey::generate(asterius_domain::SigningAlgorithm::Es256)
                .expect("client signing key")
                .public_jwk()
                .expect("public JWK");
        let application=management.mutate(&tenant,owner,Mutation::Create{kind:Kind::Application,external_key:"application-config".to_owned(),spec:json!({"client_name":"Managed","redirect_uris":["https://rp.example/cb"],"jwks":{"keys":[public_key]},"resources":["https://default.example/"]}),deletion_protection:true}).await.expect("FAPI application").expect("document");
        for document in [&tenant_document, &group, &membership, &policy, &application] {
            let imported = Identity::parse(&document.id).expect("import");
            let read = management
                .read(&imported)
                .await
                .expect("canonical live read");
            let canonical = management
                .normalise(&tenant, imported.kind, &read.spec)
                .await
                .expect("canonical plan");
            assert_eq!(canonical, read.spec, "second plan must be empty");
            let encoded = serde_json::to_string(&read).expect("wire document");
            for secret in [
                "private_key_ciphertext",
                "client_secret",
                "registration_access_token",
            ] {
                assert!(!encoded.contains(secret));
            }
        }
        let member_id = Identity::parse(&membership.id).expect("membership identity");
        let receipt = remove_managed(&management, &tenant, owner, &member_id).await;
        remove_managed(&management, &tenant, owner, &group_id).await;
        assert!(
            management
                .mutate(&tenant, owner, receipt)
                .await
                .expect("completed member deletion survives parent removal")
                .is_none()
        );
        assert!(matches!(
            management
                .mutate(
                    &tenant,
                    owner,
                    Mutation::Create {
                        kind: Kind::Membership,
                        external_key: "absent-parent".to_owned(),
                        spec: membership.spec,
                        deletion_protection: true,
                    },
                )
                .await,
            Err(Error::NotFound)
        ));
        pool.close().await;
    }

    async fn remove_managed(
        management: &PgDeclarative,
        tenant: &TenantId,
        owner: &str,
        identity: &Identity,
    ) -> Mutation {
        let current = management.read(identity).await.expect("live document");
        let unprotected = management
            .mutate(
                tenant,
                owner,
                Mutation::Replace {
                    identity: identity.clone(),
                    expected: current.revision,
                    spec: current.spec,
                    deletion_protection: false,
                },
            )
            .await
            .expect("disable deletion protection")
            .expect("live document");
        let deletion = Mutation::Delete {
            identity: identity.clone(),
            expected: unprotected.revision,
        };
        assert!(
            management
                .mutate(tenant, owner, deletion.clone())
                .await
                .expect("delete")
                .is_none()
        );
        deletion
    }
}
