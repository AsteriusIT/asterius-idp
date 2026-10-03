use super::records::{
    ACTIVATION, ELIGIBILITY, ENTITLEMENT, REQUEST, activation, entitlement, owner, request,
};
use super::*;

async fn eligible(
    tx: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
    user: Uuid,
    now: OffsetDateTime,
) -> Result<(Uuid, Uuid, OffsetDateTime, Uuid), DomainError> {
    let row:Option<(Uuid,Uuid,OffsetDateTime,Uuid)>=sqlx::query_as("select el.eligibility_id,el.revision,el.expires_at,el.editor_user_id from temporary_entitlement_eligibility el join temporary_entitlements e on e.tenant_id=el.tenant_id and e.entitlement_id=el.entitlement_id join users u on u.tenant_id=el.tenant_id and u.user_id=el.user_id join users o on o.tenant_id=e.tenant_id and o.user_id=e.owner_reference join clients c on c.tenant_id=e.tenant_id and c.client_id=e.client_reference join resource_servers rs on rs.tenant_id=e.tenant_id and rs.identifier=e.resource_reference where el.tenant_id=$1 and el.entitlement_id=$2 and el.user_id=$3 and el.revoked_at is null and el.not_before<=$4 and el.expires_at>$4 and el.expires_at-el.not_before<=make_interval(secs=>e.max_eligibility_seconds) and el.expires_at<=$4+make_interval(secs=>e.max_eligibility_seconds) and e.enabled and e.role_reference is not null and o.status='active' and u.status='active' and c.status='active' and not c.is_agent and (rs.scopes is null or e.permissions<@rs.scopes)")
        .bind(tenant.as_str()).bind(id).bind(user).bind(now).fetch_optional(tx).await.map_err(to_domain_error)?;
    row.ok_or(DomainError::NotFound)
}
impl PgTemporaryEntitlements {
    pub(super) async fn submit(
        &self,
        tenant: &TenantId,
        actor: &SessionActor,
        c: RequestActivation,
    ) -> Result<EntitlementRequest, DomainError> {
        validate_reason(&c.reason)?;
        let payload = encode(&c)?;
        let (mut tx, now) = self.begin(tenant).await?;
        session(&mut tx, tenant, actor, None, now).await?;
        if let Some(result) = replay(
            &mut tx,
            tenant,
            &actor.user,
            "request",
            c.idempotency_key,
            &payload,
        )
        .await?
        {
            return decode(result);
        }
        let e = entitlement(&mut tx, tenant, c.entitlement_id).await?;
        session(
            &mut tx,
            tenant,
            actor,
            Some(&e.configuration.requester_acr),
            now,
        )
        .await?;
        let (eligibility_id, eligibility_revision, _, eligibility_editor) = eligible(
            &mut tx,
            tenant,
            c.entitlement_id,
            *actor.user.as_uuid(),
            now,
        )
        .await?;
        let independent:Option<(Uuid,)>=sqlx::query_as("select ap.user_id from temporary_entitlement_approvers ap join users u on u.tenant_id=ap.tenant_id and u.user_id=ap.user_id where ap.tenant_id=$1 and ap.entitlement_id=$2 and ap.user_id<>all($3) and u.status='active' limit 1")
            .bind(tenant.as_str()).bind(e.entitlement_id).bind(vec![*actor.user.as_uuid(),e.editor_user_id,eligibility_editor]).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if independent.is_none() {
            return Err(DomainError::NotFound);
        }
        if !(1..=e.configuration.max_duration_seconds).contains(&c.duration_seconds) {
            return Err(DomainError::invalid(
                "duration_seconds",
                "outside configured maximum",
            ));
        }
        let id = Uuid::new_v4();
        sqlx::query("insert into temporary_entitlement_requests(tenant_id,request_id,entitlement_id,eligibility_id,eligibility_revision,policy_revision,requester_user_id,client_id,resource,role_name,permissions,duration_seconds,reason,created_at,deadline,requester_acr,approver_acr) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14+interval '5 minutes',$15,$16)")
            .bind(tenant.as_str()).bind(id).bind(c.entitlement_id).bind(eligibility_id).bind(eligibility_revision).bind(e.revision).bind(actor.user.as_uuid()).bind(&e.configuration.client_id).bind(&e.configuration.resource).bind(&e.configuration.role_name).bind(&e.configuration.permissions).bind(c.duration_seconds).bind(&c.reason).bind(now).bind(&e.configuration.requester_acr).bind(&e.configuration.approver_acr).execute(&mut *tx).await.map_err(to_domain_error)?;
        audit(&mut tx, tenant, Some(&actor.user), "requested", id, now).await?;
        let result = request(&mut tx, tenant, id).await?;
        remember(
            &mut tx,
            tenant,
            &actor.user,
            "request",
            c.idempotency_key,
            &payload,
            &encode(&result)?,
            now,
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    pub(super) async fn decision(
        &self,
        tenant: &TenantId,
        actor: &SessionActor,
        c: DecideRequest,
    ) -> Result<EntitlementRequest, DomainError> {
        let payload = encode(&c)?;
        let (mut tx, now) = self.begin(tenant).await?;
        session(&mut tx, tenant, actor, None, now).await?;
        let r = request(&mut tx, tenant, c.request_id).await?;
        let e = entitlement(&mut tx, tenant, r.entitlement_id).await?;
        let selected:Option<(Uuid,)>=sqlx::query_as("select user_id from temporary_entitlement_approvers where tenant_id=$1 and entitlement_id=$2 and user_id=$3").bind(tenant.as_str()).bind(r.entitlement_id).bind(actor.user.as_uuid()).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if selected.is_none()
            || r.requester_user_id == *actor.user.as_uuid()
            || e.editor_user_id == *actor.user.as_uuid()
        {
            return Err(DomainError::NotFound);
        }
        if let Some(result) = replay(
            &mut tx,
            tenant,
            &actor.user,
            "decide",
            c.idempotency_key,
            &payload,
        )
        .await?
        {
            return decode(result);
        }
        let (eligibility_id, eligibility_revision, end, editor) =
            eligible(&mut tx, tenant, r.entitlement_id, r.requester_user_id, now).await?;
        if editor == *actor.user.as_uuid() {
            return Err(DomainError::NotFound);
        }
        session(
            &mut tx,
            tenant,
            actor,
            Some(&e.configuration.approver_acr),
            now,
        )
        .await?;
        if r.status != RequestStatus::Pending
            || now.unix_timestamp() >= r.deadline
            || eligibility_id != r.eligibility_id
            || eligibility_revision != r.eligibility_revision
            || e.revision != r.policy_revision
            || r.duration_seconds > e.configuration.max_duration_seconds
        {
            return Err(DomainError::Conflict(
                "approval snapshot is no longer current".into(),
            ));
        }
        if c.decision == Decision::Approve {
            let existing:Option<(Uuid,)> = sqlx::query_as("select a.activation_id from temporary_entitlement_activations a join temporary_entitlement_requests r on r.tenant_id=a.tenant_id and r.request_id=a.request_id join temporary_entitlement_eligibility el on el.tenant_id=r.tenant_id and el.eligibility_id=r.eligibility_id where a.tenant_id=$1 and a.entitlement_id=$2 and a.user_id=$3 and a.revoked_at is null and a.expires_at>$4 and el.revoked_at is null and el.revision=r.eligibility_revision and r.policy_revision=$5").bind(tenant.as_str()).bind(r.entitlement_id).bind(r.requester_user_id).bind(now).bind(e.revision).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
            if existing.is_some() {
                return Err(DomainError::Conflict(
                    "an activation is already active".into(),
                ));
            }
            let activation_id = Uuid::new_v4();
            let expires_at =
                (now + time::Duration::seconds(i64::from(r.duration_seconds))).min(end);
            sqlx::query("insert into temporary_entitlement_activations(tenant_id,activation_id,request_id,entitlement_id,user_id,activated_at,expires_at) values($1,$2,$3,$4,$5,$6,$7)")
                .bind(tenant.as_str()).bind(activation_id).bind(r.request_id).bind(r.entitlement_id).bind(r.requester_user_id).bind(now).bind(expires_at).execute(&mut *tx).await.map_err(to_domain_error)?;
            audit(
                &mut tx,
                tenant,
                Some(&actor.user),
                "activated",
                activation_id,
                now,
            )
            .await?;
        }
        let status = if c.decision == Decision::Approve {
            "approved"
        } else {
            "denied"
        };
        let changed=sqlx::query("update temporary_entitlement_requests set status=$3,decided_at=$4,decided_by=$5,decision_key=$6 where tenant_id=$1 and request_id=$2 and status='pending'")
            .bind(tenant.as_str()).bind(r.request_id).bind(status).bind(now).bind(actor.user.as_uuid()).bind(c.idempotency_key).execute(&mut *tx).await.map_err(to_domain_error)?.rows_affected();
        if changed != 1 {
            return Err(DomainError::Conflict("request is terminal".into()));
        }
        audit(
            &mut tx,
            tenant,
            Some(&actor.user),
            status,
            r.request_id,
            now,
        )
        .await?;
        let result = request(&mut tx, tenant, r.request_id).await?;
        remember(
            &mut tx,
            tenant,
            &actor.user,
            "decide",
            c.idempotency_key,
            &payload,
            &encode(&result)?,
            now,
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    pub(super) async fn cancellation(
        &self,
        tenant: &TenantId,
        actor: &SessionActor,
        c: CancelRequest,
    ) -> Result<EntitlementRequest, DomainError> {
        let payload = encode(&c)?;
        let (mut tx, now) = self.begin(tenant).await?;
        session(&mut tx, tenant, actor, None, now).await?;
        let r = request(&mut tx, tenant, c.request_id).await?;
        if r.requester_user_id != *actor.user.as_uuid() {
            return Err(DomainError::NotFound);
        }
        if let Some(result) = replay(
            &mut tx,
            tenant,
            &actor.user,
            "cancel",
            c.idempotency_key,
            &payload,
        )
        .await?
        {
            return decode(result);
        }
        let changed=sqlx::query("update temporary_entitlement_requests set status='cancelled',decided_at=$3,decided_by=$4,decision_key=$5 where tenant_id=$1 and request_id=$2 and status='pending'").bind(tenant.as_str()).bind(r.request_id).bind(now).bind(actor.user.as_uuid()).bind(c.idempotency_key).execute(&mut *tx).await.map_err(to_domain_error)?.rows_affected();
        if changed != 1 {
            return Err(DomainError::Conflict("request is terminal".into()));
        }
        audit(
            &mut tx,
            tenant,
            Some(&actor.user),
            "cancelled",
            r.request_id,
            now,
        )
        .await?;
        let result = request(&mut tx, tenant, r.request_id).await?;
        remember(
            &mut tx,
            tenant,
            &actor.user,
            "cancel",
            c.idempotency_key,
            &payload,
            &encode(&result)?,
            now,
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    pub(super) async fn revocation(
        &self,
        tenant: &TenantId,
        actor: &UserId,
        session_actor: Option<&SessionActor>,
        entitlement_id: Option<Uuid>,
        c: RevokeActivation,
    ) -> Result<Activation, DomainError> {
        validate_reason(&c.reason)?;
        let payload = encode(&c)?;
        let operation = if session_actor.is_some() {
            "revoke"
        } else {
            "owner_revoke"
        };
        let (mut tx, now) = self.begin(tenant).await?;
        if let Some(actor) = session_actor {
            session(&mut tx, tenant, actor, None, now).await?;
        }
        let a = activation(&mut tx, tenant, c.activation_id).await?;
        if let Some(id) = entitlement_id {
            if id != a.entitlement_id {
                return Err(DomainError::NotFound);
            }
            owner(&mut tx, tenant, actor, id).await?;
        } else if a.user_id != *actor.as_uuid() {
            return Err(DomainError::NotFound);
        }
        if let Some(result) = replay(
            &mut tx,
            tenant,
            actor,
            operation,
            c.idempotency_key,
            &payload,
        )
        .await?
        {
            return decode(result);
        }
        if a.revoked_at.is_none() {
            sqlx::query("update temporary_entitlement_activations set revoked_at=$3,revocation_reason=$4 where tenant_id=$1 and activation_id=$2 and revoked_at is null").bind(tenant.as_str()).bind(a.activation_id).bind(now).bind(&c.reason).execute(&mut *tx).await.map_err(to_domain_error)?;
            audit(
                &mut tx,
                tenant,
                Some(actor),
                "revoked",
                a.activation_id,
                now,
            )
            .await?;
        }
        let result = activation(&mut tx, tenant, a.activation_id).await?;
        remember(
            &mut tx,
            tenant,
            actor,
            operation,
            c.idempotency_key,
            &payload,
            &encode(&result)?,
            now,
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    pub(super) async fn account_records(
        &self,
        tenant: &TenantId,
        actor: &SessionActor,
    ) -> Result<AccountEntitlements, DomainError> {
        let (mut tx, now) = self.begin(tenant).await?;
        session(&mut tx, tenant, actor, None, now).await?;
        let visible = "e.tenant_id=$1 and (exists(select 1 from temporary_entitlement_eligibility el where el.tenant_id=e.tenant_id and el.entitlement_id=e.entitlement_id and el.user_id=$2) or exists(select 1 from temporary_entitlement_approvers ap where ap.tenant_id=e.tenant_id and ap.entitlement_id=e.entitlement_id and ap.user_id=$2))";
        let sql = format!("{ENTITLEMENT} where {visible} order by e.created_at desc limit 100");
        let entitlements = read_many(&mut tx, &sql, tenant, &actor.user).await?;
        let sql = format!(
            "{ELIGIBILITY} where e.tenant_id=$1 and e.user_id=$2 order by e.expires_at desc limit 100"
        );
        let eligibilities = read_many(&mut tx, &sql, tenant, &actor.user).await?;
        let sql = format!(
            "{REQUEST} where e.tenant_id=$1 and (e.requester_user_id=$2 or (e.requester_user_id<>$2 and exists(select 1 from temporary_entitlement_approvers ap join temporary_entitlements config on config.tenant_id=ap.tenant_id and config.entitlement_id=ap.entitlement_id join temporary_entitlement_eligibility el on el.tenant_id=e.tenant_id and el.eligibility_id=e.eligibility_id where ap.tenant_id=e.tenant_id and ap.entitlement_id=e.entitlement_id and ap.user_id=$2 and config.editor_user_id<>$2 and el.editor_user_id<>$2))) order by e.created_at desc limit 100"
        );
        let requests = read_many(&mut tx, &sql, tenant, &actor.user).await?;
        let sql = format!(
            "{ACTIVATION} where e.tenant_id=$1 and e.user_id=$2 order by e.activated_at desc limit 100"
        );
        let activations = read_many(&mut tx, &sql, tenant, &actor.user).await?;
        Ok(AccountEntitlements {
            observed_at: now.unix_timestamp(),
            entitlements,
            eligibilities,
            requests,
            activations,
        })
    }
    pub(super) async fn owner_records<T: serde::de::DeserializeOwned>(
        &self,
        tenant: &TenantId,
        actor: &UserId,
        id: Uuid,
        select: &str,
    ) -> Result<Vec<T>, DomainError> {
        let (mut tx, _) = self.begin(tenant).await?;
        owner(&mut tx, tenant, actor, id).await?;
        let sql =
            format!("{select} where e.tenant_id=$1 and e.entitlement_id=$2 order by 1 limit 100");
        let rows: Vec<(serde_json::Value,)> = sqlx::query_as(&sql)
            .bind(tenant.as_str())
            .bind(id)
            .fetch_all(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        rows.into_iter().map(|r| decode(r.0)).collect()
    }
    pub(super) async fn expiry(&self, tenant: &TenantId, limit: u16) -> Result<u64, DomainError> {
        if !(1..=100).contains(&limit) {
            return Err(DomainError::invalid("limit", "requires 1..100"));
        }
        let (mut tx, now) = self.begin(tenant).await?;
        let rows:Vec<(Uuid,)>=sqlx::query_as("update temporary_entitlement_activations set expiry_recorded_at=$2 where tenant_id=$1 and activation_id in (select activation_id from temporary_entitlement_activations where tenant_id=$1 and expires_at<=$2 and expiry_recorded_at is null order by expires_at,activation_id limit $3) returning activation_id")
            .bind(tenant.as_str()).bind(now).bind(i64::from(limit)).fetch_all(&mut *tx).await.map_err(to_domain_error)?;
        for (id,) in &rows {
            audit(&mut tx, tenant, None, "expired", *id, now).await?;
        }
        let count = u64::try_from(rows.len()).map_err(|e| DomainError::Storage(Box::new(e)))?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(count)
    }
}
async fn read_many<T: serde::de::DeserializeOwned>(
    tx: &mut PgConnection,
    sql: &str,
    tenant: &TenantId,
    user: &UserId,
) -> Result<Vec<T>, DomainError> {
    let rows: Vec<(serde_json::Value,)> = sqlx::query_as(sql)
        .bind(tenant.as_str())
        .bind(user.as_uuid())
        .fetch_all(tx)
        .await
        .map_err(to_domain_error)?;
    rows.into_iter().map(|r| decode(r.0)).collect()
}
