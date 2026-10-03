//! Read-only, bounded governance findings. No lifecycle mutation port is held.
use asterius_domain::governance_reports::{
    Cursor, Finding, GovernanceReports, INACTIVITY_DAYS, MEMBERSHIP_REVIEW_DAYS,
    PRIVILEGE_REVIEW_DAYS, Page, Proposal, Query, Reason, SCAN_BOUND, Section, Thresholds,
};
use asterius_domain::{DomainError, TenantId, UserId};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime};

use crate::error::to_domain_error;

#[derive(Debug, Clone)]
pub struct PgGovernanceReports {
    pool: PgPool,
    /// Exact configured one-shot LDAP source identity, not a health assertion.
    ldap_sources: BTreeMap<String, String>,
}
impl PgGovernanceReports {
    #[must_use]
    pub const fn new(pool: PgPool, ldap_sources: BTreeMap<String, String>) -> Self {
        Self { pool, ldap_sources }
    }
}

const ACCOUNTS: &str = "select u.user_id::text report_key,jsonb_build_object(
    'user_id',u.user_id,'status',u.status,'created_at',extract(epoch from u.created_at)::bigint,
    'last_retained_session_activity',(select extract(epoch from max(s.last_seen_at))::bigint from sessions s where s.tenant_id=$1 and s.user_id=u.user_id and s.revoked_at is null),
    'administrator',exists(select 1 from user_roles r where r.tenant_id=$1 and r.user_id=u.user_id),
    'sources',coalesce((select jsonb_agg(source) from (
        select jsonb_build_object('kind','scim','client_id',e.client_id,'client_status',c.status,
          'deleted_at',extract(epoch from e.deleted_at)::bigint,'last_mapping_update',extract(epoch from e.updated_at)::bigint) source
          from scim_user_external_ids e left join clients c on c.tenant_id=e.tenant_id and c.client_id=e.client_id
          where e.tenant_id=$1 and e.user_id=u.user_id
        union all select jsonb_build_object('kind','ldap','source_key',l.source_key,
          'missing_since',extract(epoch from l.missing_since)::bigint,'disabled_by_ldap_at',extract(epoch from l.disabled_by_ldap_at)::bigint)
          from ldap_user_owners l where l.tenant_id=$1 and l.user_id=u.user_id
        limit 33) bounded), '[]'::jsonb)) evidence
    from users u where u.tenant_id=$1 and ($2::text is null or u.user_id::text collate \"C\">$2 collate \"C\")
    order by u.user_id::text collate \"C\" limit $3";

const OWNERSHIP: &str = "select o.ownership_id::text report_key,jsonb_build_object(
    'ownership_id',o.ownership_id,'target_kind',o.target_kind,'target_keys',o.target_keys,
    'owner',o.owner_user_id,'owner_status',u.status,'enabled',o.enabled,'revision',o.revision,
    'owner_authority_current',exists(select 1 from user_roles r where r.tenant_id=$1 and r.user_id=o.owner_user_id and r.role='tenant_admin'),
    'source_present',case o.target_kind
      when 'membership' then exists(select 1 from group_memberships a where a.tenant_id=$1 and a.group_id::text=o.target_keys->>0 and a.user_id::text=o.target_keys->>1)
      when 'user_tenant_role' then exists(select 1 from user_tenant_roles a where a.tenant_id=$1 and a.user_id::text=o.target_keys->>0 and a.name=o.target_keys->>1)
      when 'user_client_role' then exists(select 1 from user_client_roles a where a.tenant_id=$1 and a.user_id::text=o.target_keys->>0 and a.client_id=o.target_keys->>1 and a.name=o.target_keys->>2)
      when 'group_tenant_role' then exists(select 1 from group_tenant_roles a where a.tenant_id=$1 and a.group_id::text=o.target_keys->>0 and a.name=o.target_keys->>1)
      when 'group_client_role' then exists(select 1 from group_client_roles a where a.tenant_id=$1 and a.group_id::text=o.target_keys->>0 and a.client_id=o.target_keys->>1 and a.name=o.target_keys->>2)
      else false end,
    'reviewer_count',cardinality(o.reviewers),
    'active_reviewer_count',(select count(*) from users r join user_roles a using(tenant_id,user_id) where r.tenant_id=$1 and r.user_id=any(o.reviewers) and r.status='active' and a.role='tenant_admin')) evidence
    from governance_ownerships o left join users u on u.tenant_id=o.tenant_id and u.user_id=o.owner_user_id
    where o.tenant_id=$1 and ($2::text is null or o.ownership_id::text collate \"C\">$2 collate \"C\")
    order by o.ownership_id::text collate \"C\" limit $3";

const ASSIGNMENTS: &str = "with assignments as (
    select 'membership'::text kind,jsonb_build_array(group_id::text,user_id::text) keys,governance_generation generation,created_at,
      jsonb_build_object('kind','membership','group_id',group_id,'user_id',user_id) target
      from group_memberships where tenant_id=$1
    union all select 'user_tenant_role',jsonb_build_array(user_id::text,name),governance_generation,granted_at,
      jsonb_build_object('kind','user_tenant_role','user_id',user_id,'name',name) from user_tenant_roles where tenant_id=$1
    union all select 'user_client_role',jsonb_build_array(user_id::text,client_id,name),governance_generation,granted_at,
      jsonb_build_object('kind','user_client_role','user_id',user_id,'client_id',client_id,'name',name) from user_client_roles where tenant_id=$1
    union all select 'group_tenant_role',jsonb_build_array(group_id::text,name),governance_generation,granted_at,
      jsonb_build_object('kind','group_tenant_role','group_id',group_id,'name',name) from group_tenant_roles where tenant_id=$1
    union all select 'group_client_role',jsonb_build_array(group_id::text,client_id,name),governance_generation,granted_at,
      jsonb_build_object('kind','group_client_role','group_id',group_id,'client_id',client_id,'name',name) from group_client_roles where tenant_id=$1
    ), keyed as (select *,kind||':'||keys::text report_key from assignments)
    select a.report_key,jsonb_build_object('target',a.target,'assignment_generation',a.generation,
      'created_at',extract(epoch from a.created_at)::bigint,'ownership_id',o.ownership_id,
      'owner',o.owner_user_id,'owner_status',u.status,'ownership_enabled',o.enabled,
      'owner_authority_current',exists(select 1 from user_roles a where a.tenant_id=$1 and a.user_id=o.owner_user_id and a.role='tenant_admin'),
      'last_applied_retain_at',extract(epoch from retained.applied_at)::bigint,
      'review_context',retained.snapshot->'context',
      'overdue_review',exists(select 1 from governance_review_items i join governance_reviews r using(tenant_id,review_id)
        where i.tenant_id=$1 and i.ownership_id=o.ownership_id and i.assignment_generation=a.generation
          and i.ownership_revision=o.revision and r.cancelled_at is null and r.completed_at is null and r.due_at<=$4),
      'unapplied_decision',exists(select 1 from governance_review_items i join governance_reviews r using(tenant_id,review_id)
        where i.tenant_id=$1 and i.ownership_id=o.ownership_id and i.assignment_generation=a.generation
          and i.ownership_revision=o.revision and r.cancelled_at is null and i.decision is not null and i.apply_status='pending')) evidence
    from keyed a left join governance_ownerships o on o.tenant_id=$1 and o.target_kind=a.kind and o.target_keys=a.keys
      left join users u on u.tenant_id=$1 and u.user_id=o.owner_user_id
      left join lateral (select i.applied_at,i.snapshot from governance_review_items i join governance_reviews r using(tenant_id,review_id)
        where i.tenant_id=$1 and i.ownership_id=o.ownership_id and i.assignment_generation=a.generation and i.ownership_revision=o.revision
          and i.decision='retain' and i.apply_status='retained' and r.cancelled_at is null order by i.applied_at desc limit 1) retained on true
    where ($2::text is null or a.report_key collate \"C\">$2 collate \"C\") order by a.report_key collate \"C\" limit $3";

const TEMPORARY: &str = "select e.entitlement_id::text report_key,jsonb_build_object(
    'entitlement_id',e.entitlement_id,'revision',e.revision,'client_id',e.client_id,'resource',e.resource,'role_name',e.role_name,
    'owner',e.owner_user_id,'owner_status',u.status,'owner_reference',e.owner_reference,
    'client_reference',e.client_reference,'role_reference',e.role_reference,'resource_reference',e.resource_reference,
    'enabled',e.enabled,'created_at',extract(epoch from e.created_at)::bigint,
    'current_lifecycle_only',true,'standing_review_coverage',false) evidence
    from temporary_entitlements e left join users u on u.tenant_id=e.tenant_id and u.user_id=e.owner_reference
    where e.tenant_id=$1 and ($2::text is null or e.entitlement_id::text collate \"C\">$2 collate \"C\")
    order by e.entitlement_id::text collate \"C\" limit $3";

const ADMINISTRATIVE_ROLES: &str = "select r.user_id::text||':'||r.role report_key,
    jsonb_build_object('user_id',r.user_id,'role',r.role,'account_status',u.status,
      'created_at',extract(epoch from r.granted_at)::bigint,'standing_review_coverage',false,
      'local_recovery_candidate',not exists(select 1 from scim_user_external_ids s where s.tenant_id=$1 and s.user_id=r.user_id)
        and not exists(select 1 from ldap_user_owners l where l.tenant_id=$1 and l.user_id=r.user_id)) evidence
    from user_roles r join users u using(tenant_id,user_id) where r.tenant_id=$1
      and ($2::text is null or (r.user_id::text||':'||r.role) collate \"C\">$2 collate \"C\")
    order by (r.user_id::text||':'||r.role) collate \"C\" limit $3";

#[async_trait::async_trait]
impl GovernanceReports for PgGovernanceReports {
    async fn findings(
        &self,
        tenant: &TenantId,
        actor: UserId,
        query: &Query,
    ) -> Result<Page, DomainError> {
        if !(1..=asterius_domain::governance_reports::MAX_PAGE).contains(&query.limit) {
            return Err(DomainError::invalid("limit", "bounded page required"));
        }
        let after = query
            .after
            .as_ref()
            .map(|cursor| cursor.key_for(tenant, query.section))
            .transpose()?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query("set transaction isolation level repeatable read read only")
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let active: bool = sqlx::query_scalar("select exists(select 1 from users u join user_roles r using(tenant_id,user_id) join tenants t using(tenant_id) where u.tenant_id=$1 and u.user_id=$2 and u.status='active' and t.status='active' and r.role in ('tenant_admin','deployment_admin','security_auditor'))")
            .bind(tenant.as_str()).bind(actor.as_uuid()).fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        if !active {
            return Err(DomainError::NotFound);
        }
        let now: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let sql = match query.section {
            Section::Accounts => ACCOUNTS,
            Section::Ownership => OWNERSHIP,
            Section::Assignments => ASSIGNMENTS,
            Section::TemporaryEntitlements => TEMPORARY,
            Section::AdministrativeRoles => ADMINISTRATIVE_ROLES,
        };
        let mut selected = sqlx::query(sql).bind(tenant.as_str()).bind(after).bind(
            i64::try_from(SCAN_BOUND + 1)
                .map_err(|_| DomainError::invalid("limit", "scan bound"))?,
        );
        if query.section == Section::Assignments {
            selected = selected.bind(now);
        }
        let rows = selected
            .fetch_all(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let has_more = rows.len() > SCAN_BOUND;
        let mut items = Vec::new();
        let mut scanned = 0;
        let mut last = None;
        let total = rows.len().min(SCAN_BOUND);
        for row in rows.iter().take(SCAN_BOUND) {
            let key: String = row.try_get("report_key").map_err(to_domain_error)?;
            let mut evidence: Value = row.try_get("evidence").map_err(to_domain_error)?;
            if query.section == Section::Assignments {
                assignment_context(
                    &mut tx,
                    tenant,
                    &mut evidence,
                    self.ldap_sources.get(tenant.as_str()).map(String::as_str),
                )
                .await?;
            }
            let finding = classify(
                query.section,
                key.clone(),
                evidence,
                now,
                self.ldap_sources.get(tenant.as_str()).map(String::as_str),
            );
            scanned += 1;
            last = Some(key);
            if let Some(finding) = finding {
                items.push(finding);
            }
            if items.len() == usize::from(query.limit) {
                break;
            }
        }
        let next = if has_more || scanned < total {
            last.map(|key| Cursor::new(tenant, query.section, key)?.encode())
                .transpose()?
        } else {
            None
        };
        tx.commit().await.map_err(to_domain_error)?;
        let page = Page {
            section: query.section,
            observed_at: now,
            thresholds: Thresholds::default(),
            items,
            next,
            scanned,
            read_only: true,
        };
        if serde_json::to_vec(&page)
            .map_err(|error| DomainError::Storage(Box::new(error)))?
            .len()
            > 4 * 1024 * 1024
        {
            return Err(DomainError::Conflict(
                "report exceeds the bounded four-MiB response".into(),
            ));
        }
        Ok(page)
    }
}

async fn assignment_context(
    connection: &mut sqlx::PgConnection,
    tenant: &TenantId,
    evidence: &mut Value,
    configured_ldap: Option<&str>,
) -> Result<(), DomainError> {
    let target: asterius_domain::access_reviews::Target =
        serde_json::from_value(evidence["target"].clone())
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
    if let Some(group) = evidence["target"]["group_id"].as_str() {
        evidence["managed_provenance"] = managed_provenance(
            connection,
            tenant,
            group,
            &evidence["target"],
            configured_ldap,
        )
        .await?;
    }
    match crate::PgAccessReviews::context_for_report_on(connection, tenant, &target).await {
        Ok(current) => {
            evidence["review_context_current"] = json!(evidence["review_context"] == current);
            evidence["review_context_complete"] = json!(true);
        }
        Err(DomainError::Conflict(_)) => {
            // An oversized group is an unknown complete context;
            // a partial fingerprint cannot certify current coverage.
            evidence["review_context_current"] = json!(false);
            evidence["review_context_complete"] = json!(false);
        }
        Err(error) => return Err(error),
    }

    Ok(())
}

async fn managed_provenance(
    connection: &mut sqlx::PgConnection,
    tenant: &TenantId,
    group: &str,
    target: &Value,
    configured_ldap: Option<&str>,
) -> Result<Value, DomainError> {
    sqlx::query_scalar("select jsonb_build_object(
      'scim',exists(select 1 from scim_group_owners where tenant_id=$1 and group_id::text=$2),
      'ldap',exists(select 1 from ldap_group_owners where tenant_id=$1 and group_id::text=$2),
      'builder',exists(select 1 from flow_resource_links where tenant_id=$1 and resource_kind='group' and resource_id=$2 and relation='managed'),
      'controller',exists(select 1 from declarative_owners where tenant_id=$1 and kind='group' and keys=jsonb_build_array($2::text) and owner is not null)
        or exists(select 1 from declarative_owners where tenant_id=$1 and kind='membership' and keys=jsonb_build_array($2::text,$3::text) and owner is not null),
      'disconnected_source',exists(select 1 from scim_group_owners o left join clients c using(tenant_id,client_id) where o.tenant_id=$1 and o.group_id::text=$2 and c.status is distinct from 'active')
        or exists(select 1 from ldap_group_owners where tenant_id=$1 and group_id::text=$2 and source_key is distinct from $4::text),
      'upstream_absent',exists(select 1 from ldap_group_owners where tenant_id=$1 and group_id::text=$2 and missing_since is not null),
      'reachability_verified',false)")
        .bind(tenant.as_str()).bind(group).bind(target["user_id"].as_str())
        .bind(configured_ldap).fetch_one(connection).await.map_err(to_domain_error)
}

fn age_exceeds(evidence: &Value, field: &str, now: OffsetDateTime, days: i64) -> bool {
    evidence
        .get(field)
        .and_then(Value::as_i64)
        .is_some_and(|at| at <= (now - Duration::days(days)).unix_timestamp())
}
fn classify(
    section: Section,
    key: String,
    mut evidence: Value,
    now: OffsetDateTime,
    configured_ldap: Option<&str>,
) -> Option<Finding> {
    let mut reasons = Vec::new();
    let mut proposals = Vec::new();
    match section {
        Section::Accounts => classify_accounts(
            &mut evidence,
            now,
            &mut reasons,
            &mut proposals,
            configured_ldap,
        ),
        Section::Ownership => {
            if evidence["owner"].is_null() || evidence["owner_status"].is_null() {
                reasons.push(Reason::MissingOwner);
            } else if evidence["owner_status"] != "active" {
                reasons.push(Reason::InactiveOwner);
            } else if evidence["owner_authority_current"] == false {
                reasons.push(Reason::OwnerAuthorityUnavailable);
            }
            if evidence["enabled"] == false {
                reasons.push(Reason::StaleReview);
            }
            if evidence["active_reviewer_count"].as_i64() == Some(0) {
                reasons.push(Reason::ReviewerUnavailable);
            }
            if evidence["source_present"] == false {
                reasons.push(Reason::DisconnectedSource);
            }
            proposals.push(Proposal::AssignCurrentOwner);
        }
        Section::Assignments => {
            classify_assignments(&mut evidence, now, &mut reasons, &mut proposals);
        }
        Section::TemporaryEntitlements => {
            if evidence["owner_reference"].is_null() || evidence["owner_status"].is_null() {
                reasons.push(Reason::MissingOwner);
            } else if evidence["owner_status"] != "active" {
                reasons.push(Reason::InactiveOwner);
            }
            if ["client_reference", "role_reference", "resource_reference"]
                .iter()
                .any(|key| evidence[key].is_null())
            {
                reasons.push(Reason::DisconnectedSource);
            }
            proposals.push(Proposal::ReviewAccountLifecycle);
        }
        Section::AdministrativeRoles => {
            if evidence["account_status"] != "active" {
                reasons.push(Reason::InactiveAccount);
            }
            if age_exceeds(&evidence, "created_at", now, PRIVILEGE_REVIEW_DAYS) {
                reasons.push(Reason::UnreviewedPrivilege);
            }
            if !reasons.is_empty() && evidence["local_recovery_candidate"] == true {
                reasons.push(Reason::ProtectedRecoveryAccount);
                proposals.push(Proposal::PreserveRecoveryAccess);
            }
            proposals.push(Proposal::ReviewAccountLifecycle);
        }
    }
    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        None
    } else {
        Some(Finding {
            key,
            reasons,
            evidence,
            proposals,
        })
    }
}

fn classify_accounts(
    evidence: &mut Value,
    now: OffsetDateTime,
    reasons: &mut Vec<Reason>,
    proposals: &mut Vec<Proposal>,
    configured_ldap: Option<&str>,
) {
    if evidence["status"] != "active" {
        reasons.push(Reason::InactiveAccount);
    }
    if age_exceeds(
        evidence,
        "last_retained_session_activity",
        now,
        INACTIVITY_DAYS,
    ) {
        reasons.push(Reason::NoRecentObservedActivity);
    } else if evidence["last_retained_session_activity"].is_null()
        && age_exceeds(evidence, "created_at", now, INACTIVITY_DAYS)
    {
        reasons.push(Reason::UnknownActivity);
    }
    let sources = evidence["sources"].as_array().cloned().unwrap_or_default();
    let local = sources.is_empty();
    if sources.len() > 32 {
        reasons.push(Reason::SourceHealthUnknown);
    }
    evidence["source_records_complete"] = json!(sources.len() <= 32);
    evidence["sources"] = json!(sources.iter().take(32).collect::<Vec<_>>());
    for source in sources.iter().take(32) {
        if source["kind"] == "scim" {
            if source["client_status"] != "active" {
                reasons.push(Reason::DisconnectedSource);
            }
            if !source["deleted_at"].is_null() {
                reasons.push(Reason::UpstreamDeleted);
            }
        } else if source["kind"] == "ldap" {
            if source["source_key"].as_str() != configured_ldap {
                reasons.push(Reason::DisconnectedSource);
            }
            if !source["missing_since"].is_null() {
                reasons.push(Reason::UpstreamAbsent);
            }
        }
    }
    evidence["origin"] = json!(if local {
        "no_recorded_provisioning_source"
    } else {
        "recorded_provisioning_source"
    });
    evidence["source_reachability_verified"] = json!(false);
    evidence["activity_history_complete"] = json!(false);
    if !reasons.is_empty() {
        proposals.extend([
            Proposal::ReviewAccountLifecycle,
            Proposal::InspectProvisioningSource,
        ]);
        if local && evidence["administrator"] == true {
            reasons.push(Reason::ProtectedRecoveryAccount);
            proposals.push(Proposal::PreserveRecoveryAccess);
        }
    }
}

fn classify_assignments(
    evidence: &mut Value,
    now: OffsetDateTime,
    reasons: &mut Vec<Reason>,
    proposals: &mut Vec<Proposal>,
) {
    if evidence["ownership_id"].is_null() {
        reasons.push(Reason::MissingOwnership);
    } else if evidence["owner"].is_null() || evidence["owner_status"].is_null() {
        reasons.push(Reason::MissingOwner);
    } else if evidence["owner_status"] != "active" {
        reasons.push(Reason::InactiveOwner);
    } else if evidence["owner_authority_current"] == false {
        reasons.push(Reason::OwnerAuthorityUnavailable);
    }
    if evidence["managed_provenance"]["disconnected_source"] == true {
        reasons.push(Reason::DisconnectedSource);
    }
    if evidence["managed_provenance"]["upstream_absent"] == true {
        reasons.push(Reason::UpstreamAbsent);
    }
    let current = evidence["review_context_current"] == true;
    let reviewed = current
        && evidence["ownership_enabled"] == true
        && evidence["owner_authority_current"] != false
        && !evidence["last_applied_retain_at"].is_null();
    if !current && !evidence["last_applied_retain_at"].is_null() {
        reasons.push(Reason::StaleReview);
    }
    if evidence["review_context_complete"] == false {
        reasons.push(Reason::SourceHealthUnknown);
    }
    if evidence["target"]["kind"] == "membership" {
        if age_exceeds(evidence, "created_at", now, MEMBERSHIP_REVIEW_DAYS)
            && (!reviewed
                || age_exceeds(
                    evidence,
                    "last_applied_retain_at",
                    now,
                    MEMBERSHIP_REVIEW_DAYS,
                ))
        {
            reasons.push(Reason::StaleMembership);
        }
        proposals.push(Proposal::ReviewMembershipSource);
    } else if age_exceeds(evidence, "created_at", now, PRIVILEGE_REVIEW_DAYS)
        && (!reviewed
            || age_exceeds(
                evidence,
                "last_applied_retain_at",
                now,
                PRIVILEGE_REVIEW_DAYS,
            ))
    {
        reasons.push(Reason::UnreviewedPrivilege);
    }
    if evidence["overdue_review"] == true {
        reasons.push(Reason::OverdueReview);
    }
    if evidence["unapplied_decision"] == true {
        reasons.push(Reason::UnappliedDecision);
    }
    proposals.extend([
        Proposal::AssignCurrentOwner,
        Proposal::StartIndependentReview,
        Proposal::InspectReviewApplication,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
    }
    fn account() -> Value {
        json!({"status":"active","created_at":(now()-Duration::days(400)).unix_timestamp(),
            "last_retained_session_activity":now().unix_timestamp(),"administrator":false,"sources":[]})
    }
    #[test]
    fn governance_local_recovery_missing_history_is_unknown_not_deleted_or_disconnected() {
        let mut evidence = account();
        evidence["administrator"] = json!(true);
        evidence["last_retained_session_activity"] = Value::Null;
        let finding =
            classify(Section::Accounts, "user".into(), evidence, now(), None).expect("candidate");
        assert!(finding.reasons.contains(&Reason::UnknownActivity));
        assert!(finding.reasons.contains(&Reason::ProtectedRecoveryAccount));
        assert!(
            finding
                .proposals
                .contains(&Proposal::PreserveRecoveryAccess)
        );
        assert!(!finding.reasons.contains(&Reason::DisconnectedSource));
        assert!(!finding.reasons.contains(&Reason::UpstreamDeleted));
        assert!(!finding.reasons.contains(&Reason::NoRecentObservedActivity));
    }
    #[test]
    fn governance_disconnected_source_does_not_infer_account_inactivity_or_upstream_deletion() {
        let mut evidence = account();
        evidence["sources"] = json!([{"kind":"scim","client_id":"removed-client","client_status":null,"deleted_at":null}]);
        let finding = classify(Section::Accounts, "user".into(), evidence, now(), None)
            .expect("source candidate");
        assert_eq!(finding.reasons, [Reason::DisconnectedSource]);
        assert_eq!(finding.evidence["source_reachability_verified"], false);
    }
    #[test]
    fn governance_explicit_scim_deletion_and_complete_ldap_absence_remain_distinct() {
        let mut evidence = account();
        evidence["sources"] = json!([{"kind":"scim","client_id":"active-source","client_status":"active","deleted_at":1},
            {"kind":"ldap","source_key":"configured","missing_since":1}]);
        let finding = classify(
            Section::Accounts,
            "user".into(),
            evidence,
            now(),
            Some("configured"),
        )
        .expect("upstream evidence");
        assert!(finding.reasons.contains(&Reason::UpstreamDeleted));
        assert!(finding.reasons.contains(&Reason::UpstreamAbsent));
        assert!(!finding.reasons.contains(&Reason::DisconnectedSource));
    }
    fn assignment(kind: &str) -> Value {
        json!({"target":{"kind":kind},"created_at":(now()-Duration::days(400)).unix_timestamp(),
            "ownership_id":"configured","owner":"owner","owner_status":"active","ownership_enabled":true,
            "last_applied_retain_at":now().unix_timestamp(),"review_context_current":true,"review_context_complete":true,
            "overdue_review":false,"unapplied_decision":false})
    }
    #[test]
    fn governance_historical_retain_never_covers_changed_context_or_generation() {
        let mut evidence = assignment("user_client_role");
        assert!(
            classify(
                Section::Assignments,
                "source".into(),
                evidence.clone(),
                now(),
                None
            )
            .is_none()
        );
        evidence["review_context_current"] = json!(false);
        let finding = classify(Section::Assignments, "source".into(), evidence, now(), None)
            .expect("stale context");
        assert!(finding.reasons.contains(&Reason::StaleReview));
        assert!(finding.reasons.contains(&Reason::UnreviewedPrivilege));
    }
    #[test]
    fn governance_membership_age_is_a_review_candidate_and_current_review_clears_it() {
        let mut evidence = assignment("membership");
        assert!(
            classify(
                Section::Assignments,
                "source".into(),
                evidence.clone(),
                now(),
                None
            )
            .is_none()
        );
        evidence["last_applied_retain_at"] = Value::Null;
        let finding = classify(Section::Assignments, "source".into(), evidence, now(), None)
            .expect("old membership");
        assert!(finding.reasons.contains(&Reason::StaleMembership));
        assert!(!finding.reasons.contains(&Reason::UpstreamDeleted));
        assert!(
            finding
                .proposals
                .contains(&Proposal::ReviewMembershipSource)
        );
    }
}
