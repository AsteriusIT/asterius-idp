//! Atomic managed-group persistence. All SQL binds tenant identity explicitly.

use std::collections::BTreeSet;

use asterius_domain::{
    DomainError, Group, GroupDirectory, GroupId, GroupMetadata, TenantId, UserId,
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
