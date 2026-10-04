//! One-shot LDAP snapshot application. No account or group is adopted by name:
//! the ownership tables are the only authority for subsequent updates.

use std::collections::{BTreeMap, BTreeSet};

use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::{DomainError, GroupMetadata, SessionRevocation, TenantId};
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

/// The default records absence without changing access. An operator must
/// select the bounded action policy on every run that may change access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapAbsencePolicy {
    MarkOnly,
    DeactivateAndPrune {
        grace_days: u16,
        max_users: u16,
        max_groups: u16,
    },
}

impl LdapAbsencePolicy {
    fn validate(self) -> Result<(), DomainError> {
        if let Self::DeactivateAndPrune {
            grace_days,
            max_users,
            max_groups,
        } = self
            && (!(7..=365).contains(&grace_days)
                || max_users > 10
                || max_groups > 10
                || max_users == 0 && max_groups == 0)
        {
            return Err(DomainError::invalid(
                "ldap.absence_policy",
                "grace must be 7–365 days; each cap at most 10; one cap must be nonzero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LdapSyncOutcome {
    pub users_created: usize,
    pub users_updated: usize,
    pub groups_created: usize,
    pub groups_updated: usize,
    pub memberships_changed: usize,
    pub users_marked_missing: usize,
    pub groups_marked_missing: usize,
    pub users_disabled: usize,
    pub groups_deleted: usize,
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
    // All ownership, membership, absence, and audit changes share one transaction.
    #[allow(clippy::too_many_lines)]
    pub async fn apply(
        &self,
        tenant: &TenantId,
        source_key: &str,
        snapshot: &LdapSnapshot,
        absence_policy: LdapAbsencePolicy,
    ) -> Result<LdapSyncOutcome, DomainError> {
        absence_policy.validate()?;
        if source_key.len() != 64 || !source_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DomainError::invalid(
                "source_key",
                "must be a SHA-256 hex digest",
            ));
        }
        validate(snapshot)?;
        if let LdapAbsencePolicy::DeactivateAndPrune {
            max_users,
            max_groups,
            ..
        } = absence_policy
        {
            if max_users > 0 && snapshot.users.is_empty() {
                return Err(DomainError::invalid(
                    "ldap.absence_policy",
                    "cannot disable users from an empty directory user snapshot",
                ));
            }
            if max_groups > 0 && snapshot.groups.is_empty() {
                return Err(DomainError::invalid(
                    "ldap.absence_policy",
                    "cannot prune groups from an empty directory group snapshot",
                ));
            }
        }
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        // Lifecycle and group changes take the issuance fence before source/user locks.
        crate::users::PgUserRepository::lifecycle_fence_on(&mut tx, tenant).await?;
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
            users_marked_missing: 0,
            groups_marked_missing: 0,
            users_disabled: 0,
            groups_deleted: 0,
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
            sqlx::query(
                "update ldap_user_owners set missing_since = null
                 where tenant_id = $1 and source_key = $2 and user_id = $3
                   and missing_since is not null",
            )
            .bind(tenant.as_str())
            .bind(source_key)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
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
            sqlx::query(
                "update ldap_group_owners set missing_since = null
                 where tenant_id = $1 and source_key = $2 and group_id = $3
                   and missing_since is not null",
            )
            .bind(tenant.as_str())
            .bind(source_key)
            .bind(group_id)
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
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
        // Every search finished successfully before this transaction began.
        // Present owners were cleared above; only this source's remaining
        // owners may become tombstones. A retry leaves the original clock.
        let present_users = snapshot
            .users
            .iter()
            .map(|user| user.external_id.as_str())
            .collect::<Vec<_>>();
        outcome.users_marked_missing = sqlx::query(
            "update ldap_user_owners set missing_since = now()
             where tenant_id = $1 and source_key = $2 and missing_since is null
               and not (external_id = any($3::text[]))",
        )
        .bind(tenant.as_str())
        .bind(source_key)
        .bind(&present_users)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?
        .rows_affected()
        .try_into()
        .map_err(|_| DomainError::Conflict("LDAP user count exceeds platform limits".to_owned()))?;
        let present_groups = snapshot
            .groups
            .iter()
            .map(|group| group.dn.as_str())
            .collect::<Vec<_>>();
        outcome.groups_marked_missing = sqlx::query(
            "update ldap_group_owners set missing_since = now()
             where tenant_id = $1 and source_key = $2 and missing_since is null
               and not (external_id = any($3::text[]))",
        )
        .bind(tenant.as_str())
        .bind(source_key)
        .bind(&present_groups)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?
        .rows_affected()
        .try_into()
        .map_err(|_| {
            DomainError::Conflict("LDAP group count exceeds platform limits".to_owned())
        })?;

        if let LdapAbsencePolicy::DeactivateAndPrune {
            grace_days,
            max_users,
            max_groups,
        } = absence_policy
        {
            let grace_days = i32::from(grace_days);
            if max_users != 0 {
                // Never disable a tenant or deployment administrator. Rows
                // are locked before the role guard and status write.
                let candidates: Vec<Uuid> = sqlx::query_scalar(
                    "select u.user_id from users u
                     join ldap_user_owners o on o.tenant_id = u.tenant_id and o.user_id = u.user_id
                     where o.tenant_id = $1 and o.source_key = $2
                       and o.missing_since <= now() - ($3::int * interval '1 day')
                       and u.status = 'active'
                       and not exists (select 1 from user_roles r
                                       where r.tenant_id = u.tenant_id and r.user_id = u.user_id)
                     order by u.user_id limit $4 for update of u",
                )
                .bind(tenant.as_str())
                .bind(source_key)
                .bind(grace_days)
                .bind(i64::from(max_users) + 1)
                .fetch_all(&mut *tx)
                .await
                .map_err(to_domain_error)?;
                if candidates.len() > usize::from(max_users) {
                    return Err(DomainError::Conflict(
                        "LDAP absent-user cap exceeded; no changes committed".to_owned(),
                    ));
                }
                for id in candidates {
                    let changed = sqlx::query(
                        "update users set status = 'disabled'
                         where tenant_id = $1 and user_id = $2 and status = 'active'
                           and not exists (select 1 from user_roles r
                                           where r.tenant_id = $1 and r.user_id = $2)",
                    )
                    .bind(tenant.as_str())
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(to_domain_error)?
                    .rows_affected();
                    if changed == 0 {
                        continue;
                    }
                    sqlx::query(
                        "update ldap_user_owners set disabled_by_ldap_at = now()
                         where tenant_id = $1 and source_key = $2 and user_id = $3",
                    )
                    .bind(tenant.as_str())
                    .bind(source_key)
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(to_domain_error)?;
                    sqlx::query(
                        "update sessions set revoked_at = coalesce(revoked_at, now()),
                             revocation_reason = coalesce(revocation_reason, $3)
                         where tenant_id = $1 and user_id = $2 and revoked_at is null",
                    )
                    .bind(tenant.as_str())
                    .bind(id)
                    .bind(SessionRevocation::Administrative.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(to_domain_error)?;
                    outcome.users_disabled += 1;
                    crate::audit::append(
                        &mut tx,
                        AuditEvent::new(
                            tenant.clone(),
                            EventType::ADMIN_CHANGED,
                            Outcome::Success,
                            Actor::System,
                            OffsetDateTime::now_utc(),
                        )
                        .subject(id.to_string())
                        .detail(
                            Detail::new()
                                .label("operation", "ldap.user.absence.disable")
                                .text("source_key_prefix", &source_key[..12]),
                        ),
                    )
                    .await?;
                }
            }
            if max_groups != 0 {
                // Group rows lock before checking membership. Existing local
                // or SCIM-owned members, or any role grant, block deletion.
                let candidates: Vec<Uuid> = sqlx::query_scalar(
                    "select g.group_id from managed_groups g
                     join ldap_group_owners o on o.tenant_id = g.tenant_id and o.group_id = g.group_id
                     where o.tenant_id = $1 and o.source_key = $2
                       and o.missing_since <= now() - ($3::int * interval '1 day')
                       and not exists (select 1 from group_tenant_roles r
                                       where r.tenant_id = g.tenant_id and r.group_id = g.group_id)
                       and not exists (select 1 from group_client_roles r
                                       where r.tenant_id = g.tenant_id and r.group_id = g.group_id)
                       and not exists (
                           select 1 from group_memberships m
                           left join ldap_user_owners u
                             on u.tenant_id = m.tenant_id and u.user_id = m.user_id
                                and u.source_key = $2
                           where m.tenant_id = g.tenant_id and m.group_id = g.group_id
                             and u.user_id is null)
                     order by g.group_id limit $4 for update of g",
                )
                .bind(tenant.as_str())
                .bind(source_key)
                .bind(grace_days)
                .bind(i64::from(max_groups) + 1)
                .fetch_all(&mut *tx)
                .await
                .map_err(to_domain_error)?;
                if candidates.len() > usize::from(max_groups) {
                    return Err(DomainError::Conflict(
                        "LDAP absent-group cap exceeded; no changes committed".to_owned(),
                    ));
                }
                for id in candidates {
                    let changed = sqlx::query(
                        "delete from managed_groups g where g.tenant_id = $1 and g.group_id = $2
                         and exists (select 1 from ldap_group_owners o
                                     where o.tenant_id = g.tenant_id and o.group_id = g.group_id
                                       and o.source_key = $3)
                         and not exists (select 1 from group_tenant_roles r
                                         where r.tenant_id = g.tenant_id and r.group_id = g.group_id)
                         and not exists (select 1 from group_client_roles r
                                         where r.tenant_id = g.tenant_id and r.group_id = g.group_id)
                         and not exists (
                             select 1 from group_memberships m
                             left join ldap_user_owners u
                               on u.tenant_id = m.tenant_id and u.user_id = m.user_id
                                  and u.source_key = $3
                             where m.tenant_id = g.tenant_id and m.group_id = g.group_id
                               and u.user_id is null)",
                    )
                    .bind(tenant.as_str())
                    .bind(id)
                    .bind(source_key)
                    .execute(&mut *tx)
                    .await
                    .map_err(to_domain_error)?
                    .rows_affected();
                    outcome.groups_deleted += usize::from(changed != 0);
                    if changed != 0 {
                        crate::audit::append(
                            &mut tx,
                            AuditEvent::new(
                                tenant.clone(),
                                EventType::ADMIN_CHANGED,
                                Outcome::Success,
                                Actor::System,
                                OffsetDateTime::now_utc(),
                            )
                            .subject(id.to_string())
                            .detail(
                                Detail::new()
                                    .label("operation", "ldap.group.absence.delete")
                                    .text("source_key_prefix", &source_key[..12]),
                            ),
                        )
                        .await?;
                    }
                }
            }
        }
        let policy_name = match absence_policy {
            LdapAbsencePolicy::MarkOnly => "mark_only",
            LdapAbsencePolicy::DeactivateAndPrune { .. } => "deactivate_and_prune",
        };
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
                    .text("absence_policy", policy_name)
                    .text("source_key_prefix", &source_key[..12])
                    .number("users_created", audit_count(outcome.users_created))
                    .number("users_updated", audit_count(outcome.users_updated))
                    .number("groups_created", audit_count(outcome.groups_created))
                    .number("groups_updated", audit_count(outcome.groups_updated))
                    .number(
                        "memberships_changed",
                        audit_count(outcome.memberships_changed),
                    )
                    .number(
                        "users_marked_missing",
                        audit_count(outcome.users_marked_missing),
                    )
                    .number(
                        "groups_marked_missing",
                        audit_count(outcome.groups_marked_missing),
                    )
                    .number("users_disabled", audit_count(outcome.users_disabled))
                    .number("groups_deleted", audit_count(outcome.groups_deleted)),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(outcome)
    }
}

fn audit_count(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
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
