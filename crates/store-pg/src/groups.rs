//! Atomic managed-group persistence. All SQL binds tenant identity explicitly.

use std::collections::BTreeSet;

use asterius_domain::{
    Actor, AuditEvent, ClientId, Detail, DomainError, EventType, Group, GroupDirectory, GroupId,
    GroupMetadata, Outcome, ScimGroupReplacement, ScimGroupState, TenantId, UserId,
};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::to_domain_error;

/// Deployment-wide adapter; every operation requires an explicit tenant.
#[derive(Debug, Clone)]
pub struct PgGroups {
    pool: PgPool,
}

impl PgGroups {
    /// Binds a database pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn membership(
        &self,
        tenant: &TenantId,
        id: GroupId,
        user: UserId,
        now: OffsetDateTime,
        add: bool,
    ) -> Result<bool, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        lock_revision(&mut tx, tenant, id, None).await?;
        let changed = if add {
            sqlx::query(
                "insert into group_memberships (tenant_id, group_id, user_id, created_at)
                values ($1, $2, $3, $4) on conflict (tenant_id, group_id, user_id) do nothing",
            )
            .bind(tenant.as_str())
            .bind(id.as_uuid())
            .bind(user.as_uuid())
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?
            .rows_affected()
                == 1
        } else {
            sqlx::query("delete from group_memberships where tenant_id = $1 and group_id = $2 and user_id = $3")
                .bind(tenant.as_str()).bind(id.as_uuid()).bind(user.as_uuid())
                .execute(&mut *tx).await.map_err(to_domain_error)?.rows_affected() == 1
        };
        if changed {
            sqlx::query(
                "update managed_groups set revision = revision + 1, updated_at = $3
                where tenant_id = $1 and group_id = $2",
            )
            .bind(tenant.as_str())
            .bind(id.as_uuid())
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        }
        tx.commit().await.map_err(to_domain_error)?;
        Ok(changed)
    }
}

#[derive(sqlx::FromRow)]
struct GroupRow {
    tenant_id: String,
    group_id: Uuid,
    name: String,
    display_name: String,
    revision: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct ScimGroupRow {
    tenant_id: String,
    group_id: Uuid,
    name: String,
    display_name: String,
    revision: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    external_id: Option<String>,
}

impl ScimGroupRow {
    fn into_state(self, members: Vec<UserId>) -> Result<ScimGroupState, DomainError> {
        let external_id = self.external_id;
        let group = GroupRow {
            tenant_id: self.tenant_id,
            group_id: self.group_id,
            name: self.name,
            display_name: self.display_name,
            revision: self.revision,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
        .try_into()?;
        Ok(ScimGroupState {
            group,
            external_id,
            members,
        })
    }
}

const SCIM_MAX_MEMBERS: usize = 1_000;

async fn validate_scim_members(
    connection: &mut PgConnection,
    tenant: &TenantId,
    client: &ClientId,
    members: &[UserId],
) -> Result<Vec<Uuid>, DomainError> {
    if members.len() > SCIM_MAX_MEMBERS {
        return Err(DomainError::invalid(
            "members",
            "too many SCIM group members",
        ));
    }
    let ids = members
        .iter()
        .map(|user| *user.as_uuid())
        .collect::<Vec<_>>();
    let unique = ids.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != ids.len() {
        return Err(DomainError::invalid(
            "members",
            "duplicate SCIM group member",
        ));
    }
    let visible: i64 = sqlx::query_scalar(
        "select count(*) from users u left join scim_user_external_ids e
           on e.tenant_id = u.tenant_id and e.user_id = u.user_id and e.client_id = $2
         where u.tenant_id = $1 and u.user_id = any($3::uuid[])
           and e.deleted_at is null",
    )
    .bind(tenant.as_str())
    .bind(client.as_str())
    .bind(&ids)
    .fetch_one(connection)
    .await
    .map_err(to_domain_error)?;
    if usize::try_from(visible).unwrap_or(usize::MAX) != ids.len() {
        return Err(DomainError::invalid(
            "members",
            "member is outside this client's tenant view",
        ));
    }
    Ok(ids)
}

async fn scim_role_free(
    connection: &mut PgConnection,
    tenant: &TenantId,
    id: GroupId,
) -> Result<(), DomainError> {
    let has_roles: bool = sqlx::query_scalar(
        "select exists(select 1 from group_tenant_roles
                        where tenant_id = $1 and group_id = $2)
             or exists(select 1 from group_client_roles
                       where tenant_id = $1 and group_id = $2)",
    )
    .bind(tenant.as_str())
    .bind(id.as_uuid())
    .fetch_one(connection)
    .await
    .map_err(to_domain_error)?;
    if has_roles {
        return Err(DomainError::Conflict(
            "SCIM group carries application roles".to_owned(),
        ));
    }
    Ok(())
}

async fn scim_owned_locked(
    connection: &mut PgConnection,
    tenant: &TenantId,
    client: &ClientId,
    id: GroupId,
    expected_revision: i64,
) -> Result<String, DomainError> {
    if expected_revision < 1 {
        return Err(DomainError::invalid("revision", "must be positive"));
    }
    let row: Option<(String, i64)> = sqlx::query_as(
        "select g.name, g.revision from managed_groups g
         join scim_group_owners o on o.tenant_id = g.tenant_id and o.group_id = g.group_id
         where g.tenant_id = $1 and g.group_id = $2 and o.client_id = $3
         for update of g",
    )
    .bind(tenant.as_str())
    .bind(id.as_uuid())
    .bind(client.as_str())
    .fetch_optional(&mut *connection)
    .await
    .map_err(to_domain_error)?;
    let (name, revision) = row.ok_or(DomainError::NotFound)?;
    if revision != expected_revision {
        return Err(DomainError::Conflict("group revision changed".to_owned()));
    }
    scim_role_free(connection, tenant, id).await?;
    Ok(name)
}

async fn scim_members(
    pool: &PgPool,
    tenant: &TenantId,
    id: GroupId,
) -> Result<Vec<UserId>, DomainError> {
    let rows: Vec<Uuid> = sqlx::query_scalar(
        "select user_id from group_memberships
         where tenant_id = $1 and group_id = $2
         order by user_id limit $3",
    )
    .bind(tenant.as_str())
    .bind(id.as_uuid())
    .bind(i64::try_from(SCIM_MAX_MEMBERS + 1).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(to_domain_error)?;
    if rows.len() > SCIM_MAX_MEMBERS {
        return Err(DomainError::invalid(
            "members",
            "SCIM group exceeds member limit",
        ));
    }
    Ok(rows.into_iter().map(UserId::new).collect())
}

impl TryFrom<GroupRow> for Group {
    type Error = DomainError;

    fn try_from(row: GroupRow) -> Result<Self, Self::Error> {
        Ok(Self {
            tenant: TenantId::new(row.tenant_id),
            id: GroupId::from_uuid(row.group_id),
            metadata: GroupMetadata::parse(&row.name, &row.display_name)
                .map_err(|error| DomainError::invalid("group.metadata", error.to_string()))?,
            revision: row.revision,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

fn page_limit(limit: u16) -> Result<i64, DomainError> {
    if !(1..=200).contains(&limit) {
        return Err(DomainError::invalid("limit", "must be between 1 and 200"));
    }
    Ok(i64::from(limit))
}

/// The same lock serializes metadata, membership and deletion. Check the
/// expected revision after acquiring it so concurrent edits cannot both win.
async fn lock_revision(
    connection: &mut PgConnection,
    tenant: &TenantId,
    id: GroupId,
    expected: Option<i64>,
) -> Result<(), DomainError> {
    if expected.is_some_and(|revision| revision < 1) {
        return Err(DomainError::invalid("revision", "must be positive"));
    }
    let revision: i64 = sqlx::query_scalar(
        "select revision from managed_groups
        where tenant_id = $1 and group_id = $2 for update",
    )
    .bind(tenant.as_str())
    .bind(id.as_uuid())
    .fetch_one(connection)
    .await
    .map_err(to_domain_error)?;
    if expected.is_some_and(|expected| expected != revision) {
        return Err(DomainError::Conflict("group revision changed".to_owned()));
    }
    Ok(())
}

#[async_trait::async_trait]
impl GroupDirectory for PgGroups {
    async fn scim_create(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        display_name: &str,
        external_id: Option<&str>,
        members: &[UserId],
        now: OffsetDateTime,
    ) -> Result<ScimGroupState, DomainError> {
        let id = GroupId::mint();
        let name = format!("scim:{}", id.as_uuid());
        let metadata = GroupMetadata::parse(&name, display_name)
            .map_err(|error| DomainError::invalid("displayName", error.to_string()))?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let member_ids = validate_scim_members(&mut tx, tenant, client, members).await?;
        let row: GroupRow = sqlx::query_as(
            "insert into managed_groups
             (tenant_id, group_id, name, display_name, created_at, updated_at)
             values ($1, $2, $3, $4, $5, $5)
             returning tenant_id, group_id, name, display_name, revision, created_at, updated_at",
        )
        .bind(tenant.as_str())
        .bind(id.as_uuid())
        .bind(metadata.name().as_str())
        .bind(metadata.display_name())
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "insert into scim_group_owners (tenant_id, client_id, group_id, external_id)
             values ($1, $2, $3, $4)",
        )
        .bind(tenant.as_str())
        .bind(client.as_str())
        .bind(id.as_uuid())
        .bind(external_id)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "insert into group_memberships (tenant_id, group_id, user_id, created_at)
             select $1, $2, member, $4 from unnest($3::uuid[]) as member",
        )
        .bind(tenant.as_str())
        .bind(id.as_uuid())
        .bind(&member_ids)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        crate::audit::append(
            &mut tx,
            AuditEvent::new(
                tenant.clone(),
                EventType::ADMIN_CHANGED,
                Outcome::Success,
                Actor::Client(client.clone()),
                now,
            )
            .subject(id.as_uuid().to_string())
            .detail(
                Detail::new()
                    .label("operation", "scim.groups.create")
                    .number(
                        "member_count",
                        i64::try_from(members.len()).unwrap_or(i64::MAX),
                    ),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(ScimGroupState {
            group: row.try_into()?,
            external_id: external_id.map(str::to_owned),
            members: members.to_vec(),
        })
    }

    async fn scim_get(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        id: GroupId,
    ) -> Result<Option<ScimGroupState>, DomainError> {
        let row: Option<ScimGroupRow> = sqlx::query_as(
            "select g.tenant_id, g.group_id, g.name, g.display_name, g.revision,
                    g.created_at, g.updated_at, o.external_id
             from managed_groups g join scim_group_owners o
               on o.tenant_id = g.tenant_id and o.group_id = g.group_id
             where g.tenant_id = $1 and o.client_id = $2 and g.group_id = $3",
        )
        .bind(tenant.as_str())
        .bind(client.as_str())
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let Some(row) = row else { return Ok(None) };
        let mut connection = self.pool.acquire().await.map_err(to_domain_error)?;
        scim_role_free(&mut connection, tenant, id).await?;
        let members = scim_members(&self.pool, tenant, id).await?;
        Ok(Some(row.into_state(members)?))
    }

    async fn scim_page(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        display_name: Option<&str>,
        offset: u32,
        limit: u16,
    ) -> Result<(u64, Vec<ScimGroupState>), DomainError> {
        if offset > 10_000 || !(1..=200).contains(&limit) {
            return Err(DomainError::invalid("page", "outside SCIM page bounds"));
        }
        let total: i64 = sqlx::query_scalar(
            "select count(*) from managed_groups g join scim_group_owners o
               on o.tenant_id = g.tenant_id and o.group_id = g.group_id
             where g.tenant_id = $1 and o.client_id = $2
               and ($3::text is null or g.display_name = $3)",
        )
        .bind(tenant.as_str())
        .bind(client.as_str())
        .bind(display_name)
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let rows: Vec<ScimGroupRow> = sqlx::query_as(
            "select g.tenant_id, g.group_id, g.name, g.display_name, g.revision,
                    g.created_at, g.updated_at, o.external_id
             from managed_groups g join scim_group_owners o
               on o.tenant_id = g.tenant_id and o.group_id = g.group_id
             where g.tenant_id = $1 and o.client_id = $2
               and ($3::text is null or g.display_name = $3)
             order by g.group_id offset $4 limit $5",
        )
        .bind(tenant.as_str())
        .bind(client.as_str())
        .bind(display_name)
        .bind(i64::from(offset))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let mut states = Vec::with_capacity(rows.len());
        for row in rows {
            let id = GroupId::from_uuid(row.group_id);
            let mut connection = self.pool.acquire().await.map_err(to_domain_error)?;
            scim_role_free(&mut connection, tenant, id).await?;
            states.push(row.into_state(scim_members(&self.pool, tenant, id).await?)?);
        }
        Ok((u64::try_from(total).unwrap_or(0), states))
    }

    async fn scim_replace(
        &self,
        replacement: ScimGroupReplacement,
    ) -> Result<ScimGroupState, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let name = scim_owned_locked(
            &mut tx,
            &replacement.tenant,
            &replacement.client,
            replacement.group,
            replacement.expected_revision,
        )
        .await?;
        let metadata = GroupMetadata::parse(&name, &replacement.display_name)
            .map_err(|error| DomainError::invalid("displayName", error.to_string()))?;
        let member_ids = validate_scim_members(
            &mut tx,
            &replacement.tenant,
            &replacement.client,
            &replacement.members,
        )
        .await?;
        let row: GroupRow = sqlx::query_as(
            "update managed_groups set display_name = $3,
                    revision = revision + 1, updated_at = $4
             where tenant_id = $1 and group_id = $2
             returning tenant_id, group_id, name, display_name, revision, created_at, updated_at",
        )
        .bind(replacement.tenant.as_str())
        .bind(replacement.group.as_uuid())
        .bind(metadata.display_name())
        .bind(replacement.now)
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "update scim_group_owners set external_id = $4
             where tenant_id = $1 and client_id = $2 and group_id = $3",
        )
        .bind(replacement.tenant.as_str())
        .bind(replacement.client.as_str())
        .bind(replacement.group.as_uuid())
        .bind(&replacement.external_id)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "delete from group_memberships where tenant_id = $1 and group_id = $2
               and not (user_id = any($3::uuid[]))",
        )
        .bind(replacement.tenant.as_str())
        .bind(replacement.group.as_uuid())
        .bind(&member_ids)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "insert into group_memberships (tenant_id, group_id, user_id, created_at)
             select $1, $2, member, $4 from unnest($3::uuid[]) as member
             on conflict (tenant_id, group_id, user_id) do nothing",
        )
        .bind(replacement.tenant.as_str())
        .bind(replacement.group.as_uuid())
        .bind(&member_ids)
        .bind(replacement.now)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        crate::audit::append(
            &mut tx,
            AuditEvent::new(
                replacement.tenant.clone(),
                EventType::ADMIN_CHANGED,
                Outcome::Success,
                Actor::Client(replacement.client.clone()),
                replacement.now,
            )
            .subject(replacement.group.as_uuid().to_string())
            .detail(
                Detail::new()
                    .label("operation", replacement.operation)
                    .number(
                        "member_count",
                        i64::try_from(member_ids.len()).unwrap_or(i64::MAX),
                    ),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(ScimGroupState {
            group: row.try_into()?,
            external_id: replacement.external_id,
            members: replacement.members,
        })
    }

    async fn scim_delete(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        id: GroupId,
        expected_revision: i64,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        scim_owned_locked(&mut tx, tenant, client, id, expected_revision).await?;
        sqlx::query("delete from managed_groups where tenant_id = $1 and group_id = $2")
            .bind(tenant.as_str())
            .bind(id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        crate::audit::append(
            &mut tx,
            AuditEvent::new(
                tenant.clone(),
                EventType::ADMIN_CHANGED,
                Outcome::Success,
                Actor::Client(client.clone()),
                now,
            )
            .subject(id.as_uuid().to_string())
            .detail(Detail::new().label("operation", "scim.groups.delete")),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    async fn create(
        &self,
        tenant: &TenantId,
        metadata: &GroupMetadata,
        now: OffsetDateTime,
    ) -> Result<Group, DomainError> {
        let row = sqlx::query_as::<_, GroupRow>(
            "insert into managed_groups
            (tenant_id, group_id, name, display_name, created_at, updated_at)
            values ($1, $2, $3, $4, $5, $5)
            returning tenant_id, group_id, name, display_name, revision, created_at, updated_at",
        )
        .bind(tenant.as_str())
        .bind(GroupId::mint().as_uuid())
        .bind(metadata.name().as_str())
        .bind(metadata.display_name())
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.try_into()
    }

    async fn get(&self, tenant: &TenantId, id: GroupId) -> Result<Option<Group>, DomainError> {
        sqlx::query_as::<_, GroupRow>(
            "select tenant_id, group_id, name, display_name, revision, created_at, updated_at
            from managed_groups where tenant_id = $1 and group_id = $2",
        )
        .bind(tenant.as_str())
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        .map(TryInto::try_into)
        .transpose()
    }

    async fn list(
        &self,
        tenant: &TenantId,
        after: Option<GroupId>,
        limit: u16,
    ) -> Result<Vec<Group>, DomainError> {
        sqlx::query_as::<_, GroupRow>(
            "select tenant_id, group_id, name, display_name, revision, created_at, updated_at
            from managed_groups where tenant_id = $1 and ($2::uuid is null or group_id > $2)
            order by group_id limit $3",
        )
        .bind(tenant.as_str())
        .bind(after.map(GroupId::as_uuid))
        .bind(page_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
    }

    async fn search(
        &self,
        tenant: &TenantId,
        term: &str,
        after: Option<GroupId>,
        limit: u16,
    ) -> Result<Vec<Group>, DomainError> {
        if term.len() > GroupMetadata::MAX_DISPLAY_BYTES {
            return Err(DomainError::invalid("q", "must be at most 200 bytes"));
        }
        let literal = term
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        sqlx::query_as::<_, GroupRow>(
            "select tenant_id, group_id, name, display_name, revision, created_at, updated_at
            from managed_groups
            where tenant_id = $1 and ($2::uuid is null or group_id > $2)
              and (name ilike '%' || $3 || '%' escape '\\'
                   or display_name ilike '%' || $3 || '%' escape '\\')
            order by group_id limit $4",
        )
        .bind(tenant.as_str())
        .bind(after.map(GroupId::as_uuid))
        .bind(literal)
        .bind(page_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
    }

    async fn update(
        &self,
        tenant: &TenantId,
        id: GroupId,
        expected_revision: i64,
        metadata: &GroupMetadata,
        now: OffsetDateTime,
    ) -> Result<Group, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        lock_revision(&mut tx, tenant, id, Some(expected_revision)).await?;
        let previous_name: String = sqlx::query_scalar(
            "select name from managed_groups where tenant_id = $1 and group_id = $2",
        )
        .bind(tenant.as_str())
        .bind(id.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let row = sqlx::query_as::<_, GroupRow>(
            "update managed_groups
            set name = $3, display_name = $4, revision = revision + 1, updated_at = $5
            where tenant_id = $1 and group_id = $2
            returning tenant_id, group_id, name, display_name, revision, created_at, updated_at",
        )
        .bind(tenant.as_str())
        .bind(id.as_uuid())
        .bind(metadata.name().as_str())
        .bind(metadata.display_name())
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if previous_name != metadata.name().as_str() {
            sqlx::query(
                "insert into managed_group_aliases (tenant_id, group_id, name, created_at)
                 values ($1, $2, $3, $4) on conflict do nothing",
            )
            .bind(tenant.as_str())
            .bind(id.as_uuid())
            .bind(previous_name)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        }
        let group = row.try_into()?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(group)
    }

    async fn delete(
        &self,
        tenant: &TenantId,
        id: GroupId,
        expected_revision: i64,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        lock_revision(&mut tx, tenant, id, Some(expected_revision)).await?;
        sqlx::query("delete from managed_groups where tenant_id = $1 and group_id = $2")
            .bind(tenant.as_str())
            .bind(id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    async fn add_member(
        &self,
        tenant: &TenantId,
        id: GroupId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        self.membership(tenant, id, user, now, true).await
    }

    async fn remove_member(
        &self,
        tenant: &TenantId,
        id: GroupId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        self.membership(tenant, id, user, now, false).await
    }

    async fn members(
        &self,
        tenant: &TenantId,
        id: GroupId,
        after: Option<UserId>,
        limit: u16,
    ) -> Result<Vec<UserId>, DomainError> {
        // A single statement gives a coherent snapshot. A missing group has an
        // empty member list; get() is the separate existence query.
        sqlx::query_scalar::<_, Uuid>(
            "select user_id from group_memberships
            where tenant_id = $1 and group_id = $2 and ($3::uuid is null or user_id > $3)
            order by user_id limit $4",
        )
        .bind(tenant.as_str())
        .bind(id.as_uuid())
        .bind(after.map(|user| *user.as_uuid()))
        .bind(page_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?
        .into_iter()
        .map(|id| Ok(UserId::new(id)))
        .collect()
    }

    async fn groups_for_user(
        &self,
        tenant: &TenantId,
        user: UserId,
        after: Option<GroupId>,
        limit: u16,
    ) -> Result<Vec<Group>, DomainError> {
        sqlx::query_as::<_, GroupRow>("select g.tenant_id, g.group_id, g.name, g.display_name, g.revision, g.created_at, g.updated_at
            from managed_groups g join group_memberships m on m.tenant_id = g.tenant_id and m.group_id = g.group_id
            where g.tenant_id = $1 and m.user_id = $2 and ($3::uuid is null or g.group_id > $3)
            order by g.group_id limit $4")
            .bind(tenant.as_str()).bind(user.as_uuid()).bind(after.map(GroupId::as_uuid)).bind(page_limit(limit)?)
            .fetch_all(&self.pool).await.map_err(to_domain_error)?.into_iter().map(TryInto::try_into).collect()
    }

    async fn authorization_references_for_user(
        &self,
        tenant: &TenantId,
        user: UserId,
    ) -> Result<BTreeSet<String>, DomainError> {
        const MAX_AUTHORITY_GROUPS: usize = 200;
        let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
            "select g.group_id, g.name, a.name
             from group_memberships m
             join managed_groups g
               on g.tenant_id = m.tenant_id and g.group_id = m.group_id
             left join managed_group_aliases a
               on a.tenant_id = g.tenant_id and a.group_id = g.group_id
             where m.tenant_id = $1 and m.user_id = $2
             order by g.group_id, a.name
             limit $3",
        )
        .bind(tenant.as_str())
        .bind(user.as_uuid())
        .bind(i64::try_from(MAX_AUTHORITY_GROUPS * 16).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let mut references = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for (id, name, alias) in rows {
            identities.insert(id);
            if identities.len() > MAX_AUTHORITY_GROUPS {
                return Err(DomainError::invalid(
                    "groups",
                    "a subject may have at most 200 authorization groups",
                ));
            }
            references.insert(GroupId::from_uuid(id).to_string());
            references.insert(name);
            if let Some(alias) = alias {
                references.insert(alias);
            }
        }
        Ok(references)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_pagination_rejects_unbounded_queries() {
        assert!(page_limit(0).is_err());
        assert!(page_limit(201).is_err());
        assert_eq!(page_limit(200).unwrap(), 200);
    }

    #[test]
    fn groups_stored_metadata_is_validated_on_read() {
        let row = GroupRow {
            tenant_id: "demo".to_owned(),
            group_id: Uuid::new_v4(),
            name: "Admins".to_owned(),
            display_name: "Admins".to_owned(),
            revision: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(matches!(
            Group::try_from(row),
            Err(DomainError::Invalid { .. })
        ));
    }
}
