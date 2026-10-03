//! Governance commands bind tenant, lock live authority, and append audit atomically.

mod rows;
mod sources;

use asterius_domain::access_reviews::{
    AccessReviews, ApplyStatus, ConfigureOwnership, Decision, Item, Ownership, Review, Reviewer,
    StartReview, Target,
};
use asterius_domain::{
    Actor, AuditEvent, Detail, DomainError, EventType, Outcome, TenantId, UserId,
};
use serde_json::json;
use sqlx::{PgConnection, PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::to_domain_error;
use rows::{ItemRow, OwnershipRow, ReviewRow};

/// Deployment-wide adapter; tenant and trusted actor are required on every command.
#[derive(Debug, Clone)]
pub struct PgAccessReviews {
    pool: PgPool,
}
impl PgAccessReviews {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Return the bounded review context in the caller's read-only snapshot.
    /// This evidence does not grant authority or lock source assignments for mutation.
    pub async fn context_for_report_on(
        connection: &mut PgConnection,
        tenant: &TenantId,
        target: &Target,
    ) -> Result<serde_json::Value, DomainError> {
        target.validate()?;
        sources::context_for_report_on(connection, tenant, target).await
    }
}

fn page(limit: u16) -> Result<i64, DomainError> {
    if limit == 0 || limit > 100 {
        return Err(DomainError::invalid(
            "limit",
            "must be between one and one hundred",
        ));
    }
    Ok(i64::from(limit))
}
async fn clock(connection: &mut PgConnection) -> Result<OffsetDateTime, DomainError> {
    sqlx::query_scalar("select clock_timestamp()")
        .fetch_one(connection)
        .await
        .map_err(to_domain_error)
}
async fn evidence(
    connection: &mut PgConnection,
    tenant: &TenantId,
    actor: UserId,
    now: OffsetDateTime,
    operation: &'static str,
    id: Uuid,
    result: &'static str,
) -> Result<(), DomainError> {
    crate::audit::append(
        connection,
        AuditEvent::new(
            tenant.clone(),
            EventType::ADMIN_CHANGED,
            Outcome::Success,
            Actor::Admin(actor.to_string()),
            now,
        )
        .subject(id.to_string())
        .detail(
            Detail::new()
                .label("operation", operation)
                .label("result", result),
        ),
    )
    .await
}
async fn ownership_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
) -> Result<Ownership, DomainError> {
    sqlx::query_as::<_, OwnershipRow>(
        "select * from governance_ownerships where tenant_id=$1 and ownership_id=$2 for update",
    )
    .bind(tenant.as_str())
    .bind(id)
    .fetch_one(connection)
    .await
    .map_err(to_domain_error)?
    .try_into()
}
async fn eligible(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ownership: &Ownership,
    actor: UserId,
) -> Result<(), DomainError> {
    if !ownership.enabled || !ownership.reviewers.contains(actor.as_uuid()) {
        return Err(DomainError::Conflict(
            "reviewer is no longer assigned to this ownership".into(),
        ));
    }
    let owner = ownership
        .owner
        .ok_or_else(|| DomainError::Conflict("ownership has no current owner".into()))?;
    sources::active_admin(&mut *connection, tenant, UserId::new(owner)).await?;
    sources::active_admin(connection, tenant, actor).await
}
async fn review_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
) -> Result<Review, DomainError> {
    let row = sqlx::query_as::<_, ReviewRow>(
        "select * from governance_reviews where tenant_id=$1 and review_id=$2 for update",
    )
    .bind(tenant.as_str())
    .bind(id)
    .fetch_one(connection)
    .await
    .map_err(to_domain_error)?;
    Ok(row.into())
}
async fn item_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    review: Uuid,
    id: Uuid,
) -> Result<Item, DomainError> {
    sqlx::query_as::<_,ItemRow>("select * from governance_review_items where tenant_id=$1 and review_id=$2 and item_id=$3 for update")
        .bind(tenant.as_str()).bind(review).bind(id).fetch_one(connection).await.map_err(to_domain_error)?.try_into()
}
fn live(review: &Review, now: OffsetDateTime) -> Result<(), DomainError> {
    if review.cancelled_at.is_some() || review.completed_at.is_some() || now >= review.due_at {
        return Err(DomainError::Conflict(
            "review is cancelled, completed, or past its deadline".into(),
        ));
    }
    Ok(())
}

async fn snapshot(
    connection: &mut PgConnection,
    tenant: &TenantId,
    target: &Target,
    now: OffsetDateTime,
    context: serde_json::Value,
) -> Result<serde_json::Value, DomainError> {
    let users = match target {
        Target::Membership { user_id, .. }
        | Target::UserTenantRole { user_id, .. }
        | Target::UserClientRole { user_id, .. } => vec![*user_id],
        Target::GroupTenantRole { group_id, .. } | Target::GroupClientRole { group_id, .. } => {
            let users: Vec<Uuid> = sqlx::query_scalar("select user_id from group_memberships where tenant_id=$1 and group_id=$2 order by user_id limit 101")
                .bind(tenant.as_str()).bind(group_id).fetch_all(&mut *connection).await.map_err(to_domain_error)?;
            if users.len() > 100 {
                return Err(DomainError::Conflict(
                    "group exceeds the bounded hundred-user review snapshot".into(),
                ));
            }
            users
        }
    };
    let mut affected = Vec::with_capacity(users.len());
    for user in users {
        let standing = sources::standing_for_user(&mut *connection, tenant, user).await?;
        // This read-only lifecycle provenance never enters HeldRoles or causes
        // an unrelated temporary activation to be revoked by this review.
        let temporary = crate::PgTemporaryEntitlements::provenance_for_user_at_on(
            &mut *connection,
            tenant,
            &UserId::new(user),
            now,
        )
        .await?;
        let identity: (String, String) = sqlx::query_as(
            "select username,status from users where tenant_id=$1 and user_id=$2 for share",
        )
        .bind(tenant.as_str())
        .bind(user)
        .fetch_one(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        affected.push(json!({"user_id":user,"username":identity.0,"account_status":identity.1,"standing_sources":standing,"temporary_sources":temporary}));
    }
    Ok(
        json!({"observed_at":now.format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| DomainError::invalid("observed_at","database instant cannot be encoded"))?,
        "target":target,"context":context,
        "protected":sources::protected(connection,tenant,target).await?,"affected_users":affected}),
    )
}

#[async_trait::async_trait]
impl AccessReviews for PgAccessReviews {
    async fn reviewers(
        &self,
        tenant: &TenantId,
        after: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<Reviewer>, DomainError> {
        let rows=sqlx::query("select u.user_id,u.username from users u join user_roles r using(tenant_id,user_id) where u.tenant_id=$1 and u.status='active' and r.role='tenant_admin' and ($2::uuid is null or u.user_id>$2) order by u.user_id limit $3")
            .bind(tenant.as_str()).bind(after).bind(page(limit)?).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        rows.into_iter()
            .map(|row| {
                Ok(Reviewer {
                    user_id: row.try_get("user_id").map_err(to_domain_error)?,
                    username: row.try_get("username").map_err(to_domain_error)?,
                })
            })
            .collect()
    }

    async fn ownerships(
        &self,
        tenant: &TenantId,
        after: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<Ownership>, DomainError> {
        sqlx::query_as::<_,OwnershipRow>("select * from governance_ownerships where tenant_id=$1 and ($2::uuid is null or ownership_id>$2) order by ownership_id limit $3")
            .bind(tenant.as_str()).bind(after).bind(page(limit)?).fetch_all(&self.pool).await.map_err(to_domain_error)?
            .into_iter().map(TryInto::try_into).collect()
    }
    async fn configure(
        &self,
        tenant: &TenantId,
        actor: UserId,
        request: ConfigureOwnership,
    ) -> Result<Ownership, DomainError> {
        request.validate()?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let existing: Option<OwnershipRow> = sqlx::query_as("select * from governance_ownerships where tenant_id=$1 and target_kind=$2 and target_keys=$3 for update")
            .bind(tenant.as_str()).bind(request.target.kind()).bind(json!(request.target.keys()))
            .fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if existing.as_ref().map(|row| row.revision) != request.expected_revision {
            return Err(DomainError::Conflict("ownership revision changed".into()));
        }
        let mut principals = request.reviewers.clone();
        principals.extend([request.owner_user_id, *actor.as_uuid()]);
        principals.sort_unstable();
        principals.dedup();
        for principal in principals {
            sources::active_admin(&mut tx, tenant, UserId::new(principal)).await?;
        }
        if sources::lock(&mut tx, tenant, &request.target)
            .await?
            .is_none()
        {
            return Err(DomainError::NotFound);
        }
        let id = existing.map_or_else(Uuid::new_v4, |row| row.ownership_id);
        let row = sqlx::query_as::<_,OwnershipRow>("insert into governance_ownerships(tenant_id,ownership_id,target_kind,target_keys,owner_user_id,reviewers,enabled)
            values($1,$2,$3,$4,$5,$6,$7) on conflict(tenant_id,target_kind,target_keys) do update set owner_user_id=excluded.owner_user_id,
            reviewers=excluded.reviewers,enabled=excluded.enabled where governance_ownerships.revision=$8 returning *")
            .bind(tenant.as_str()).bind(id).bind(request.target.kind()).bind(json!(request.target.keys()))
            .bind(request.owner_user_id).bind(request.reviewers).bind(request.enabled).bind(request.expected_revision)
            .fetch_optional(&mut *tx).await.map_err(to_domain_error)?
            .ok_or_else(||DomainError::Conflict("ownership changed concurrently".into()))?;
        let now = clock(&mut tx).await?;
        evidence(
            &mut tx,
            tenant,
            actor,
            now,
            "governance.ownership.configure",
            id,
            "configured",
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        row.try_into()
    }
    async fn start(
        &self,
        tenant: &TenantId,
        actor: UserId,
        mut request: StartReview,
    ) -> Result<Review, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        // Independent provenance reads use one MVCC snapshot; selected sources
        // and authority rows are additionally locked until the evidence commits.
        sqlx::query("set transaction isolation level repeatable read")
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        sqlx::query("select tenant_id from tenants where tenant_id=$1 for share")
            .bind(tenant.as_str())
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        sources::active_admin(&mut tx, tenant, actor).await?;
        // Validate cardinality before locks; validate deadline again after them.
        request.validate(clock(&mut tx).await?)?;
        request.ownership_ids.sort_unstable();
        let mut selected = Vec::with_capacity(request.ownership_ids.len());
        for id in request.ownership_ids {
            let owner = ownership_on(&mut tx, tenant, id).await?;
            eligible(&mut tx, tenant, &owner, UserId::new(request.reviewer_id)).await?;
            selected.push(owner);
        }
        selected.sort_by_key(|owner| (owner.target.kind(), owner.target.keys()));
        let mut generations = Vec::with_capacity(selected.len());
        for owner in &selected {
            let generation = sources::lock(&mut tx, tenant, &owner.target)
                .await?
                .ok_or(DomainError::NotFound)?;
            let context = sources::context_fingerprint(&mut tx, tenant, &owner.target).await?;
            generations.push((generation, context));
        }
        let now = clock(&mut tx).await?;
        if request.due_at <= now {
            return Err(DomainError::Conflict(
                "deadline elapsed while selecting the snapshot".into(),
            ));
        }
        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_,ReviewRow>("insert into governance_reviews(tenant_id,review_id,created_by,created_at,due_at) values($1,$2,$3,$4,$5) returning *")
            .bind(tenant.as_str()).bind(id).bind(actor.as_uuid()).bind(now).bind(request.due_at)
            .fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        let mut snapshot_bytes = 0_usize;
        for (owner, (generation, context)) in selected.into_iter().zip(generations) {
            let value = snapshot(&mut tx, tenant, &owner.target, now, context).await?;
            let size = serde_json::to_vec(&value)
                .map_err(|_| DomainError::invalid("snapshot", "evidence cannot be encoded"))?
                .len();
            snapshot_bytes = snapshot_bytes.checked_add(size).ok_or_else(|| {
                DomainError::Conflict("review evidence exceeds the complete snapshot bound".into())
            })?;
            if size > 524_288 || snapshot_bytes > 4_194_304 {
                return Err(DomainError::Conflict(
                    "review evidence exceeds the complete snapshot bound".into(),
                ));
            }
            sqlx::query("insert into governance_review_items(tenant_id,review_id,item_id,ownership_id,ownership_revision,target_kind,target_keys,assignment_generation,assigned_reviewer,snapshot)
                values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                .bind(tenant.as_str()).bind(id).bind(Uuid::new_v4()).bind(owner.id).bind(owner.revision)
                .bind(owner.target.kind()).bind(json!(owner.target.keys())).bind(generation).bind(request.reviewer_id).bind(value)
                .execute(&mut *tx).await.map_err(to_domain_error)?;
        }
        evidence(
            &mut tx,
            tenant,
            actor,
            now,
            "governance.review.start",
            id,
            "snapshot",
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(row.into())
    }
    async fn review(
        &self,
        tenant: &TenantId,
        actor: UserId,
        administrative: bool,
        id: Uuid,
    ) -> Result<Review, DomainError> {
        let row=sqlx::query_as::<_,ReviewRow>("select r.* from governance_reviews r where r.tenant_id=$1 and r.review_id=$2 and ($3 or exists(select 1 from governance_review_items i where i.tenant_id=r.tenant_id and i.review_id=r.review_id and i.assigned_reviewer=$4))")
            .bind(tenant.as_str()).bind(id).bind(administrative).bind(actor.as_uuid()).fetch_one(&self.pool).await.map_err(to_domain_error)?;
        Ok(row.into())
    }
    async fn reviews(
        &self,
        tenant: &TenantId,
        actor: UserId,
        administrative: bool,
        after: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<Review>, DomainError> {
        let rows=sqlx::query_as::<_,ReviewRow>("select r.* from governance_reviews r where r.tenant_id=$1 and ($2::uuid is null or r.review_id>$2)
            and ($3 or exists(select 1 from governance_review_items i where i.tenant_id=r.tenant_id and i.review_id=r.review_id and i.assigned_reviewer=$4)) order by r.review_id limit $5")
            .bind(tenant.as_str()).bind(after).bind(administrative).bind(actor.as_uuid()).bind(page(limit)?)
            .fetch_all(&self.pool).await.map_err(to_domain_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
    async fn items(
        &self,
        tenant: &TenantId,
        actor: UserId,
        administrative: bool,
        review: Uuid,
        after: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<Item>, DomainError> {
        sqlx::query_as::<_,ItemRow>("select * from governance_review_items where tenant_id=$1 and review_id=$2 and ($3::uuid is null or item_id>$3)
            and ($4 or assigned_reviewer=$5) order by item_id limit $6")
            .bind(tenant.as_str()).bind(review).bind(after).bind(administrative).bind(actor.as_uuid()).bind(page(limit)?)
            .fetch_all(&self.pool).await.map_err(to_domain_error)?.into_iter().map(TryInto::try_into).collect()
    }
    async fn decide(
        &self,
        tenant: &TenantId,
        actor: UserId,
        review: Uuid,
        id: Uuid,
        decision: Decision,
        reason: String,
    ) -> Result<Item, DomainError> {
        asterius_domain::access_reviews::validate_reason(&reason)?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let review_row = review_on(&mut tx, tenant, review).await?;
        let item = item_on(&mut tx, tenant, review, id).await?;
        if item.assigned_reviewer != *actor.as_uuid() {
            return Err(DomainError::NotFound);
        }
        let owner = ownership_on(&mut tx, tenant, item.ownership_id).await?;
        eligible(&mut tx, tenant, &owner, actor).await?;
        if owner.revision != item.ownership_revision {
            return Err(DomainError::Conflict(
                "ownership changed since snapshot".into(),
            ));
        }
        let now = clock(&mut tx).await?;
        if item.decision.is_some() {
            if item.decision == Some(decision) && item.reason.as_ref() == Some(&reason) {
                return Ok(item);
            }
            return Err(DomainError::Conflict("decision is already recorded".into()));
        }
        live(&review_row, now)?;
        let decision_name = match decision {
            Decision::Retain => "retain",
            Decision::Remove => "remove",
        };
        sqlx::query("update governance_review_items set decision=$4,decided_by=$5,decided_at=$6,reason=$7 where tenant_id=$1 and review_id=$2 and item_id=$3")
            .bind(tenant.as_str()).bind(review).bind(id).bind(decision_name).bind(actor.as_uuid()).bind(now).bind(reason)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        evidence(
            &mut tx,
            tenant,
            actor,
            now,
            "governance.review.decide",
            id,
            decision_name,
        )
        .await?;
        let result = item_on(&mut tx, tenant, review, id).await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    async fn apply(
        &self,
        tenant: &TenantId,
        actor: UserId,
        review: Uuid,
        id: Uuid,
    ) -> Result<Item, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let review_row = review_on(&mut tx, tenant, review).await?;
        let item = item_on(&mut tx, tenant, review, id).await?;
        if item.assigned_reviewer != *actor.as_uuid() {
            return Err(DomainError::NotFound);
        }
        let owner = ownership_on(&mut tx, tenant, item.ownership_id).await?;
        eligible(&mut tx, tenant, &owner, actor).await?;
        if item.apply_status != ApplyStatus::Pending {
            return Ok(item);
        }
        let generation = sources::lock(&mut tx, tenant, &item.target).await?;
        // Capture the deadline only after any account/catalogue locks needed
        // for a removal have completed; lock waits must not extend eligibility.
        let removal_candidate = owner.revision == item.ownership_revision
            && item.decision == Some(Decision::Remove)
            && generation == Some(item.assignment_generation);
        let context = if removal_candidate {
            Some(sources::context_fingerprint(&mut tx, tenant, &item.target).await?)
        } else {
            None
        };
        let protected =
            removal_candidate && sources::protected(&mut tx, tenant, &item.target).await?;
        let now = clock(&mut tx).await?;
        live(&review_row, now)?;
        let result = if owner.revision != item.ownership_revision {
            "conflict"
        } else if item.decision == Some(Decision::Retain) {
            "retained"
        } else if item.decision.is_none() {
            return Err(DomainError::Conflict(
                "a decision is required before application".into(),
            ));
        } else if generation.is_none() {
            "absent"
        } else if generation != Some(item.assignment_generation)
            || item.snapshot.get("context") != context.as_ref()
        {
            "conflict"
        } else if protected {
            "protected"
        } else if sources::withdraw(&mut tx, tenant, &item.target, now).await? {
            "removed"
        } else {
            "absent"
        };
        sqlx::query("update governance_review_items set apply_status=$4,applied_by=$5,applied_at=$6 where tenant_id=$1 and review_id=$2 and item_id=$3")
            .bind(tenant.as_str()).bind(review).bind(id).bind(result).bind(actor.as_uuid()).bind(now)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        sqlx::query("update governance_reviews r set completed_at=$3 where tenant_id=$1 and review_id=$2 and not exists(select 1 from governance_review_items i where i.tenant_id=r.tenant_id and i.review_id=r.review_id and i.apply_status='pending')")
            .bind(tenant.as_str()).bind(review).bind(now).execute(&mut *tx).await.map_err(to_domain_error)?;
        evidence(
            &mut tx,
            tenant,
            actor,
            now,
            "governance.review.apply",
            id,
            result,
        )
        .await?;
        let result = item_on(&mut tx, tenant, review, id).await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    async fn cancel(
        &self,
        tenant: &TenantId,
        actor: UserId,
        review: Uuid,
    ) -> Result<Review, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sources::active_admin(&mut tx, tenant, actor).await?;
        let current = review_on(&mut tx, tenant, review).await?;
        if current.created_by != *actor.as_uuid() {
            return Err(DomainError::NotFound);
        }
        if current.cancelled_at.is_some() {
            return Ok(current);
        }
        if current.completed_at.is_some() {
            return Err(DomainError::Conflict(
                "completed review cannot be cancelled".into(),
            ));
        }
        let now = clock(&mut tx).await?;
        sqlx::query(
            "update governance_reviews set cancelled_at=$3 where tenant_id=$1 and review_id=$2",
        )
        .bind(tenant.as_str())
        .bind(review)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        evidence(
            &mut tx,
            tenant,
            actor,
            now,
            "governance.review.cancel",
            review,
            "cancelled",
        )
        .await?;
        let result = review_on(&mut tx, tenant, review).await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
}
