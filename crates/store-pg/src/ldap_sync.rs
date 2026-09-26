//! One-shot LDAP snapshot application. No account or group is adopted by name:
//! the ownership tables are the only authority for subsequent updates.

use std::collections::{BTreeMap, BTreeSet};

use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::{DomainError, GroupMetadata, TenantId};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::to_domain_error;

const MAX_USERS: usize = 500;
const MAX_GROUPS: usize = 500;
const MAX_MEMBERS: usize = 1_000;

#[derive(Debug, Clone)]
pub struct LdapUser {
    pub dn: String,
    pub external_id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Clone)]
pub struct LdapGroup {
    pub dn: String,
    pub display_name: String,
    pub member_dns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LdapSnapshot {
    pub users: Vec<LdapUser>,
    pub groups: Vec<LdapGroup>,
}

#[derive(Debug, Clone, Copy)]
pub struct LdapSyncOutcome {
    pub users_created: usize,
    pub users_updated: usize,
    pub groups_created: usize,
    pub groups_updated: usize,
    pub memberships_changed: usize,
}

#[derive(Debug, Clone)]
pub struct PgLdapSync {
    pool: PgPool,
}

impl PgLdapSync {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Apply a fully read, validated snapshot in one tenant transaction.
    /// Existing local/SCIM users and groups remain outside this source's
    /// authority. An incomplete remote read must never reach this method.
    pub async fn apply(
        &self,
        tenant: &TenantId,
        source_key: &str,
        snapshot: &LdapSnapshot,
    ) -> Result<LdapSyncOutcome, DomainError> {
        if source_key.len() != 64 || !source_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DomainError::invalid(
                "source_key",
                "must be a SHA-256 hex digest",
            ));
        }
        validate(snapshot)?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        // A per-tenant run lock also serializes concurrent command invocations.
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), 198541)")
            .bind(tenant.as_str())
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let mut outcome = LdapSyncOutcome {
            users_created: 0,
            users_updated: 0,
            groups_created: 0,
            groups_updated: 0,
            memberships_changed: 0,
        };
        let mut by_dn = BTreeMap::new();
        for user in &snapshot.users {
            let owned: Option<Uuid> = sqlx::query_scalar(
                "select user_id from ldap_user_owners
                 where tenant_id = $1 and source_key = $2 and external_id = $3",
            )
            .bind(tenant.as_str())
            .bind(source_key)
            .bind(&user.external_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(to_domain_error)?;
            let user_id = if let Some(id) = owned {
                let changed = sqlx::query(
                    "update users set username = $3, email = $4,
                        email_verified = case when email is distinct from $4 then false else email_verified end,
                        claims = jsonb_set(claims, '{name}', to_jsonb($5::text), true)
                     where tenant_id = $1 and user_id = $2
                       and (username is distinct from $3 or email is distinct from $4
                            or claims->>'name' is distinct from $5)",
                )
                .bind(tenant.as_str())
                .bind(id)
                .bind(&user.username)
                .bind(&user.email)
                .bind(&user.display_name)
                .execute(&mut *tx)
                .await
                .map_err(to_domain_error)?
                .rows_affected();
                outcome.users_updated += usize::from(changed != 0);
                id
            } else {
                let id = Uuid::new_v4();
                sqlx::query(
                    "insert into users (tenant_id, user_id, username, email, email_verified, status, claims)
                     values ($1, $2, $3, $4, false, 'active', jsonb_build_object('name', $5::text))",
                )
                .bind(tenant.as_str())
                .bind(id)
                .bind(&user.username)
                .bind(&user.email)
                .bind(&user.display_name)
                .execute(&mut *tx)
                .await
                .map_err(to_domain_error)?;
                sqlx::query(
                    "insert into ldap_user_owners (tenant_id, source_key, user_id, external_id)
                     values ($1, $2, $3, $4)",
                )
                .bind(tenant.as_str())
                .bind(source_key)
                .bind(id)
                .bind(&user.external_id)
                .execute(&mut *tx)
                .await
                .map_err(to_domain_error)?;
                outcome.users_created += 1;
                id
            };
            by_dn.insert(user.dn.to_ascii_lowercase(), user_id);
        }

        let seen_users = by_dn.values().copied().collect::<BTreeSet<_>>();
        for group in &snapshot.groups {
            let memberships_before = outcome.memberships_changed;
            let owned: Option<Uuid> = sqlx::query_scalar(
                "select group_id from ldap_group_owners
                 where tenant_id = $1 and source_key = $2 and external_id = $3",
            )
            .bind(tenant.as_str())
            .bind(source_key)
            .bind(&group.dn)
            .fetch_optional(&mut *tx)
            .await
            .map_err(to_domain_error)?;
            let group_id = if let Some(id) = owned {
                let changed = sqlx::query(
                    "update managed_groups set display_name = $3, revision = revision + 1, updated_at = now()
                     where tenant_id = $1 and group_id = $2 and display_name is distinct from $3",
                )
                .bind(tenant.as_str())
                .bind(id)
                .bind(&group.display_name)
                .execute(&mut *tx)
                .await
                .map_err(to_domain_error)?
                .rows_affected();
                outcome.groups_updated += usize::from(changed != 0);
                id
            } else {
                let id = Uuid::new_v4();
                let name = format!("ldap:{id}");
                GroupMetadata::parse(&name, &group.display_name)
                    .map_err(|e| DomainError::invalid("group", e.to_string()))?;
                sqlx::query(
                    "insert into managed_groups
                     (tenant_id, group_id, name, display_name, created_at, updated_at)
                     values ($1, $2, $3, $4, now(), now())",
                )
                .bind(tenant.as_str())
                .bind(id)
                .bind(&name)
                .bind(&group.display_name)
                .execute(&mut *tx)
                .await
                .map_err(to_domain_error)?;
                sqlx::query(
                    "insert into ldap_group_owners (tenant_id, source_key, group_id, external_id)
                     values ($1, $2, $3, $4)",
                )
                .bind(tenant.as_str())
                .bind(source_key)
                .bind(id)
                .bind(&group.dn)
                .execute(&mut *tx)
                .await
                .map_err(to_domain_error)?;
                outcome.groups_created += 1;
                id
            };
            let desired = group
                .member_dns
                .iter()
                .filter_map(|dn| by_dn.get(&dn.to_ascii_lowercase()).copied())
                .collect::<BTreeSet<_>>();
            let current: Vec<Uuid> = sqlx::query(
                "select user_id from group_memberships where tenant_id = $1 and group_id = $2",
            )
            .bind(tenant.as_str())
            .bind(group_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(to_domain_error)?
            .into_iter()
            .map(|row| row.get("user_id"))
            .collect();
            // Unknown or locally managed members are preserved. Only users
            // present in this complete snapshot may be withdrawn here.
            for id in current {
                if desired.contains(&id) || !seen_users.contains(&id) {
                    continue;
                }
                let changed = sqlx::query(
                    "delete from group_memberships m where m.tenant_id = $1 and m.group_id = $2
                     and m.user_id = $3 and exists
                     (select 1 from ldap_user_owners o
                      where o.tenant_id = m.tenant_id and o.user_id = m.user_id and o.source_key = $4)",
                )
                .bind(tenant.as_str())
                .bind(group_id)
                .bind(id)
                .bind(source_key)
                .execute(&mut *tx)
                .await
                .map_err(to_domain_error)?
                .rows_affected();
                outcome.memberships_changed += usize::from(changed != 0);
            }
            for id in desired {
                let changed = sqlx::query(
                    "insert into group_memberships (tenant_id, group_id, user_id, created_at)
                     values ($1, $2, $3, now()) on conflict do nothing",
                )
                .bind(tenant.as_str())
                .bind(group_id)
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(to_domain_error)?
                .rows_affected();
                outcome.memberships_changed += usize::from(changed != 0);
            }
            if outcome.memberships_changed != memberships_before {
                sqlx::query(
                    "update managed_groups set revision = revision + 1, updated_at = now()
                     where tenant_id = $1 and group_id = $2",
                )
                .bind(tenant.as_str())
                .bind(group_id)
                .execute(&mut *tx)
                .await
                .map_err(to_domain_error)?;
            }
        }
        crate::audit::append(
            &mut tx,
            AuditEvent::new(
                tenant.clone(),
                EventType::ADMIN_CHANGED,
                Outcome::Success,
                Actor::System,
                OffsetDateTime::now_utc(),
            )
            .detail(
                Detail::new()
                    .label("operation", "ldap.sync")
                    .text("source_key_prefix", &source_key[..12])
                    .number("users_created", outcome.users_created as i64)
                    .number("users_updated", outcome.users_updated as i64)
                    .number("groups_created", outcome.groups_created as i64)
                    .number("groups_updated", outcome.groups_updated as i64)
                    .number("memberships_changed", outcome.memberships_changed as i64),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(outcome)
    }
}

fn validate(snapshot: &LdapSnapshot) -> Result<(), DomainError> {
    if snapshot.users.len() > MAX_USERS || snapshot.groups.len() > MAX_GROUPS {
        return Err(DomainError::invalid(
            "ldap",
            "snapshot exceeds configured bounds",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut dns = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut emails = BTreeSet::new();
    for user in &snapshot.users {
        if user.external_id.is_empty()
            || user.external_id.len() > 256
            || user.dn.is_empty()
            || user.dn.len() > 1024
            || user.dn.chars().any(char::is_control)
            || user.external_id.chars().any(char::is_control)
            || user.username.is_empty()
            || user.username.len() > 256
            || user.username.trim() != user.username
            || user.email.is_empty()
            || user.email.len() > 320
            || user.email.trim() != user.email
            || !user.email.contains('@')
            || user.email.chars().any(char::is_whitespace)
            || user.display_name.is_empty()
            || user.display_name.len() > 200
            || [
                user.username.as_str(),
                user.email.as_str(),
                user.display_name.as_str(),
            ]
            .iter()
            .any(|value| value.chars().any(char::is_control))
            || !ids.insert(user.external_id.clone())
            || !dns.insert(user.dn.to_ascii_lowercase())
            || !names.insert(user.username.to_ascii_lowercase())
            || !emails.insert(user.email.to_ascii_lowercase())
        {
            return Err(DomainError::invalid(
                "ldap.users",
                "invalid or duplicate mapped user",
            ));
        }
    }
    let mut group_dns = BTreeSet::new();
    for group in &snapshot.groups {
        let mut member_dns = BTreeSet::new();
        if group.dn.is_empty()
            || group.dn.len() > 1024
            || group.dn.chars().any(char::is_control)
            || group.member_dns.len() > MAX_MEMBERS
            || !group_dns.insert(group.dn.to_ascii_lowercase())
            || GroupMetadata::parse("ldap:placeholder", &group.display_name).is_err()
            || group.member_dns.iter().any(|dn| {
                dn.is_empty()
                    || dn.len() > 1024
                    || dn.chars().any(char::is_control)
                    || !member_dns.insert(dn.to_ascii_lowercase())
            })
        {
            return Err(DomainError::invalid(
                "ldap.groups",
                "invalid or duplicate mapped group",
            ));
        }
    }
    Ok(())
}
