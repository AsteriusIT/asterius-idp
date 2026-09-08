//! The grant repository, and the revocation cascade.
//!
//! Two things here are worth more than the CRUD around them.
//!
//! ## The cascade is one transaction, or it is nothing
//!
//! Revoking a grant has to reach three tables: the grant itself, the refresh
//! tokens minted from it, and the denylist that catches the access tokens
//! already in the wild. A revocation that revoked the refresh token and left an
//! access token live is precisely the failure a revocation exists to prevent —
//! the caller is told the authorization is gone, the user is told the
//! application no longer has access, and for the next five minutes it still
//! does.
//!
//! So [`PgGrantRepository::revoke`] is a single transaction, it takes the
//! grant's row with `select … for update` before it writes anything, and it
//! writes the grant's own `revoked_at` last. If any statement fails, PostgreSQL
//! rolls the whole thing back and the grant is left exactly as it was —
//! standing, revocable, and reported as an error rather than as a success.
//! `a_revocation_that_fails_part_way_revokes_nothing` in the database tests
//! injects a failure at the denylist insert and reads all three tables back.
//!
//! ## The claim is a stamp; the status is still computed
//!
//! Grant Management ID1 §5.6 makes a grant `active` "when associated tokens
//! have been successfully claimed by the client". This adapter used to derive
//! that from the credentials that reference the grant — a refresh token, a
//! consumed authorization code, or one of the two grant shapes minted at the
//! token endpoint. The appeal was that a derivation cannot disagree with
//! reality the way a flag can.
//!
//! It could disagree with reality in one direction, though, and it was the
//! direction that loses tokens. **A bare access token leaves nothing behind to
//! derive from.** It is a stateless JWT (RFC 9068) and nothing records that it
//! was issued; the authorization code it was exchanged for is gone inside 60
//! seconds (FAPI 2.0 SP §5.3.2.1 item 11); and a code flow need not issue a
//! token at all. So a grant in exactly that state — the ordinary one for a
//! client that asked for no `offline_access` — had nothing pointing at it, read
//! as never claimed, and was deleted by [`PgGrantRepository::purge_unclaimed`]
//! while its access token was still live, taking with it the only row that
//! could have revoked that token.
//!
//! `grants.claimed_at` closes that: [`PgGrantRepository::claim`] stamps it, and
//! [`PgGrantRepository::claim`] is the only way to obtain the [`ClaimedGrant`]
//! every issuance path demands. A credential cannot be minted without the stamp
//! being written first, so there is no issuance path — including the device and
//! CIBA flows that have no table of their own yet — that can leave a claimed
//! grant looking abandoned.
//!
//! What stays derived is `expired`, and deliberately: a stored status would say
//! `active` about a grant that is not, from the instant `expires_at` passes
//! until a sweep got round to it. [`Grant::status`] compares against `now`
//! instead, so it cannot be stale.

use crate::error::to_domain_error;
use asterius_domain::ports::TenantScoped;
use asterius_domain::{
    ClaimedGrant, ClientId, DomainError, Grant, GrantId, GrantRecord, LiveAccessToken,
    RevocationReason, SessionId, SubjectId, TenantId, UserId,
};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// What a revocation reached.
///
/// Returned rather than discarded because the counts are what an audit record
/// and an operator's alert are made of: "revoked a grant" is not evidence,
/// "revoked a grant, one refresh token and denylisted three access tokens" is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Revocation {
    /// When the withdrawal took effect. One instant for every row the cascade
    /// touched, so the trail cannot show a refresh token revoked before the
    /// grant it belonged to.
    pub revoked_at: OffsetDateTime,
    /// How many refresh tokens were still live and are not any more.
    pub refresh_tokens_revoked: u64,
    /// How many access tokens were put on the denylist. Tokens already past
    /// their `exp` are skipped: the denylist's own comment says a row stops
    /// earning its keep once the token fails on `exp` anyway.
    pub access_tokens_denylisted: u64,
}

/// The grant repository for one tenant.
///
/// Constructed from a [`TenantScope`], so the tenant is a precondition of
/// holding the handle rather than an argument a query might forget.
///
/// [`TenantScope`]: crate::TenantScope
#[derive(Debug, Clone)]
pub struct PgGrantRepository {
    pool: PgPool,
    tenant: TenantId,
}

impl TenantScoped for PgGrantRepository {
    fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}

impl PgGrantRepository {
    /// Binds a pool to one tenant.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Stores a new grant.
    ///
    /// An insert and not an upsert. A grant id is minted by [`Grant::new`] and
    /// never chosen, so a conflict is a collision or a bug — and an upsert here
    /// would let a caller holding somebody else's grant id overwrite the
    /// permissions it records. Grant Management ID1 §5.2's `merge` and
    /// `replace` are changes to an existing grant and belong to their own story
    /// (`ast-uwv.4`), which will state what may change and what may not.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when the grant belongs to another tenant or its
    /// id is not a UUID, [`DomainError::Conflict`] when the client does not
    /// exist or the id is taken, or a storage error.
    pub async fn create(&self, grant: &Grant) -> Result<(), DomainError> {
        if grant.tenant != self.tenant {
            // The scope is the tenant. An entity from another one arriving here
            // is a bug in the caller, and writing it would file one customer's
            // authorization under another's.
            return Err(DomainError::invalid(
                "tenant_id",
                "does not match the tenant this repository is scoped to",
            ));
        }
        let id = uuid(&grant.id)?;
        let parent = grant.parent.as_ref().map(uuid).transpose()?;
        let scopes: Vec<String> = grant.scopes.iter().cloned().collect();
        let resources: Vec<String> = grant.resources.iter().cloned().collect();
        let authorization_details = serde_json::Value::Array(grant.authorization_details.clone());
        let actor_chain = serde_json::Value::Array(grant.actor_chain.clone());

        // `claimed_at` is written here as well as by `claim`, because the two
        // shapes minted at the token endpoint — `client_credentials` and an RFC
        // 8693 exchange — are created already claimed. A caller that leaves it
        // `None`, which is what `Grant::new` produces, is storing a grant no
        // credential has been taken from yet, and the sweep may collect it.
        sqlx::query!(
            "insert into grants (tenant_id, grant_id, client_id, user_id, subject, scopes,
                                 claims, authorization_details, resources, actor_chain,
                                 parent_grant_id, session_id, created_at, updated_at, expires_at,
                                 claimed_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13, $14, $15)",
            self.tenant.as_str(),
            id,
            grant.client.as_str(),
            grant.user.map(|user| *user.as_uuid()),
            grant.subject.as_ref().map(SubjectId::as_str),
            &scopes,
            grant.claims,
            authorization_details,
            &resources,
            actor_chain,
            parent,
            grant.session.as_ref().map(SessionId::as_str),
            grant.created_at,
            grant.expires_at,
            grant.claimed_at,
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(to_domain_error)
    }

    /// Finds one grant by id.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when the id is not a UUID or the stored row is
    /// not one this model accepts, or a storage error.
    pub async fn find(&self, id: &GrantId) -> Result<Option<Grant>, DomainError> {
        let row = sqlx::query_as!(
            Row,
            "select grant_id, client_id, user_id, subject, scopes, claims,
                    authorization_details, resources, actor_chain, parent_grant_id,
                    session_id, created_at, updated_at, expires_at, claimed_at, revoked_at,
                    revocation_reason
               from grants
               where tenant_id = $1 and grant_id = $2",
            self.tenant.as_str(),
            uuid(id)?
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(|row| row.into_entity(&self.tenant)).transpose()
    }

    /// Every grant a person has given, newest first.
    ///
    /// What the grants dashboard (`ast-uwv.6`) and Grant Management's query
    /// endpoint are built on. Revoked grants are included: a person asking
    /// "what does this application have" is also asking "what did it have", and
    /// hiding the withdrawn ones makes the answer look like it was always so.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when a stored row is not one this model
    /// accepts, or a storage error.
    pub async fn list_for_subject(&self, subject: &SubjectId) -> Result<Vec<Grant>, DomainError> {
        sqlx::query_as!(
            Row,
            "select grant_id, client_id, user_id, subject, scopes, claims,
                    authorization_details, resources, actor_chain, parent_grant_id,
                    session_id, created_at, updated_at, expires_at, claimed_at, revoked_at,
                    revocation_reason
               from grants
               where tenant_id = $1 and subject = $2
               order by created_at desc, grant_id",
            self.tenant.as_str(),
            subject.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?
        .into_iter()
        .map(|row| row.into_entity(&self.tenant))
        .collect()
    }

    /// Takes the authority to mint one credential from a grant, and records
    /// that it was taken.
    ///
    /// The guard every issuance path passes through. It refuses a grant that is
    /// revoked or expired, which is where the illegal transition `revoked ->
    /// active` is actually stopped: nothing else can produce a
    /// [`ClaimedGrant`], and nothing can be issued without one.
    ///
    /// **The guard and the stamp are one statement.** The predicate that
    /// decides — not revoked, not past `expires_at` — is the `where` clause of
    /// the `update` that writes `claimed_at`, so PostgreSQL takes the row lock
    /// before evaluating it and [`Self::revoke`]'s `select … for update`
    /// serialises against it. A read followed by a separate write would leave a
    /// gap, and a revocation committing in that gap would be a token minted
    /// from a grant that was already gone — the exact failure the type is meant
    /// to make unrepresentable.
    ///
    /// **The stamp is written before the credential exists**, which is the safe
    /// direction of the only ordering available. Stamp first and a mint that
    /// then fails leaves a grant reading `active` with nothing issued under it:
    /// the sweep spares a row it did not have to. Stamp afterwards and there is
    /// a window in which a live credential's grant reads abandoned, and the
    /// sweep deletes the row that revokes it. One costs a row, the other costs
    /// a revocation.
    ///
    /// `coalesce` because "when the first credential was taken" is the fact
    /// Grant Management ID1 §5.6 turns on; a second claim must not rewrite it.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] when this tenant has no such grant, and
    /// [`DomainError::Invalid`] when the grant is revoked or expired.
    pub async fn claim(
        &self,
        id: &GrantId,
        now: OffsetDateTime,
    ) -> Result<ClaimedGrant, DomainError> {
        let row = sqlx::query_as!(
            Row,
            "update grants set claimed_at = coalesce(claimed_at, $3)
             where tenant_id = $1 and grant_id = $2
               and revoked_at is null
               and (expires_at is null or expires_at > $3)
             returning grant_id, client_id, user_id, subject, scopes, claims,
                       authorization_details, resources, actor_chain, parent_grant_id,
                       session_id, created_at, updated_at, expires_at, claimed_at, revoked_at,
                       revocation_reason",
            self.tenant.as_str(),
            uuid(id)?,
            now
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = row else {
            // Nothing matched, so the grant is missing, revoked or expired.
            // Which one is a second query, taken only on the failure path: the
            // answer is an error message, and charging every successful
            // issuance for it would be paying in the wrong place. The verdict
            // comes from `Grant::claim` rather than a hand-written mapping, so
            // the two ways this repository can refuse a claim cannot drift.
            let grant = self.find(id).await?.ok_or(DomainError::NotFound)?;
            return Err(grant.claim(now).map_or_else(
                |error| DomainError::invalid("grant_id", error.to_string()),
                // Claimable now, but not a moment ago when the update ran. Only
                // a concurrent writer undoing a revocation or an expiry could
                // do that, and nothing in this server does either — so the
                // answer that cannot mint a token by accident is the right one.
                |_| DomainError::invalid("grant_id", "changed while it was being claimed"),
            ));
        };

        // The update's `where` clause has already established that this grant
        // is claimable, so this cannot fail — but it is the one constructor of
        // `ClaimedGrant`, and going through it is what keeps that true.
        row.into_entity(&self.tenant)?
            .claim(now)
            .map_err(|error| DomainError::invalid("grant_id", error.to_string()))
    }

    /// Withdraws a grant and everything issued under it.
    ///
    /// The cascade, in order, inside one transaction:
    ///
    /// 1. take the grant's row with `select … for update`, so two concurrent
    ///    revocations serialise instead of both cascading;
    /// 2. mark every live refresh token of the grant revoked;
    /// 3. put every still-live access token of the grant on the denylist until
    ///    its own `exp`;
    /// 4. stamp the grant.
    ///
    /// The grant is stamped last on purpose. It is the row every other reader
    /// consults, so it becomes revoked only once the credentials it covers
    /// already are — and if step 3 fails, nothing at all is written.
    ///
    /// `live` is the access tokens the caller knows are still within their
    /// `exp`. It is a parameter and not something this repository can look up,
    /// because the baseline schema has no record of issued access tokens: they
    /// are stateless JWTs (RFC 9068), and FAPI 2.0 SP §6.8 item 3 is exactly
    /// the trade-off that buys. What catches the ones the caller does not know
    /// about is the grant's own `revoked_at`, which introspection resolves
    /// through the token's `grant_id` claim.
    ///
    /// A second revocation of the same grant is [`DomainError::NotFound`],
    /// which is also what an unknown grant returns. That is deliberate and
    /// matches Grant Management ID1 §6.6: telling a caller apart from "already
    /// gone" and "never existed" is an oracle for whether a grant id was ever
    /// real.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] when this tenant has no such live grant, or a
    /// storage error — in which case nothing was revoked.
    pub async fn revoke(
        &self,
        id: &GrantId,
        reason: RevocationReason,
        live: &[LiveAccessToken],
        now: OffsetDateTime,
    ) -> Result<Revocation, DomainError> {
        let id = uuid(id)?;
        let jtis: Vec<String> = live.iter().map(|token| token.jti().to_owned()).collect();
        let expiries: Vec<OffsetDateTime> = live.iter().map(LiveAccessToken::expires_at).collect();

        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        // Step 1. The lock is what makes the rest a decision rather than a
        // race: a concurrent revocation waits here, and finds the grant already
        // stamped when it gets in.
        let live_grant = sqlx::query_scalar!(
            "select grant_id from grants
             where tenant_id = $1 and grant_id = $2 and revoked_at is null
             for update",
            self.tenant.as_str(),
            id
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if live_grant.is_none() {
            return Err(DomainError::NotFound);
        }

        // Step 2.
        let refresh_tokens_revoked = sqlx::query!(
            "update refresh_tokens set revoked_at = $3
             where tenant_id = $1 and grant_id = $2 and revoked_at is null",
            self.tenant.as_str(),
            id,
            now
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .rows_affected();

        // Step 3. One statement for the whole set: a loop would be one round
        // trip per token inside a transaction holding a lock. `on conflict do
        // nothing` because a `jti` already on the denylist is already revoked,
        // and a duplicate must not abort a revocation that is otherwise fine.
        let access_tokens_denylisted = sqlx::query!(
            "insert into access_token_denylist (tenant_id, jti, grant_id, revoked_at, expires_at)
             select $1, token.jti, $2, $3, token.expires_at
             from unnest($4::text[], $5::timestamptz[]) as token(jti, expires_at)
             where token.expires_at > $3
             on conflict (tenant_id, jti) do nothing",
            self.tenant.as_str(),
            id,
            now,
            &jtis,
            &expiries
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .rows_affected();

        // Step 4.
        sqlx::query!(
            "update grants set revoked_at = $3, revocation_reason = $4
             where tenant_id = $1 and grant_id = $2 and revoked_at is null",
            self.tenant.as_str(),
            id,
            now,
            reason.as_str()
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        transaction.commit().await.map_err(to_domain_error)?;

        Ok(Revocation {
            revoked_at: now,
            refresh_tokens_revoked,
            access_tokens_denylisted,
        })
    }

    /// Deletes this tenant's grants that nobody ever took a credential from.
    ///
    /// Grant Management ID1 §5.6: "If the tokens haven't been claimed the grant
    /// should be deleted by the AS after a reasonable timeout. Timeline of the
    /// deletion is left up to AS implementations." `older_than` is that
    /// timeout, resolved to an instant by the caller, because a tenant sets it.
    ///
    /// Per tenant, though one unqualified `delete` would be cheaper. The
    /// `sql_audit` invariant is that *every* statement over a tenant-scoped
    /// table names `tenant_id`, and an invariant with one maintenance-shaped
    /// exception is one an ordinary query can later be written to look like.
    ///
    /// ## What this deliberately will not delete
    ///
    /// `claimed_at is null` is the whole predicate now, and it is safe in the
    /// one direction that matters because [`Self::claim`] writes the stamp
    /// *before* the credential exists. There is no instant at which a live
    /// credential's grant reads unclaimed, so there is no window in which this
    /// statement can delete the only row that could revoke a token — including
    /// for the shape the previous derivation could not see: a code-flow grant
    /// whose only live credential is a bare access token, with no refresh token
    /// issued and its ≤60 s authorization code (FAPI 2.0 SP §5.3.2.1 item 11)
    /// already
    /// purged. That grant has nothing pointing at it and is kept anyway,
    /// because the stamp is on the grant itself.
    ///
    /// A revoked grant is kept as well, and not because it might still be
    /// claimed: the record of a withdrawal is the evidence that the withdrawal
    /// happened, and an investigation asking "when did this stop" needs a row
    /// to answer from.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub async fn purge_unclaimed(&self, older_than: OffsetDateTime) -> Result<u64, DomainError> {
        let result = sqlx::query!(
            "delete from grants
             where tenant_id = $1
               and created_at < $2
               and claimed_at is null
               and revoked_at is null",
            self.tenant.as_str(),
            older_than
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }
}

/// The `grant_id` column is `uuid`, and [`Grant::new`] is the only thing that
/// mints one — so this only ever fails on an identifier that came from
/// somewhere else, which is worth an error rather than a panic.
pub(crate) fn uuid(id: &GrantId) -> Result<Uuid, DomainError> {
    Uuid::parse_str(id.as_str())
        .map_err(|_| DomainError::invalid("grant_id", "is not a UUID and cannot name a grant"))
}

/// One row of `grants`, before it becomes an entity.
struct Row {
    grant_id: Uuid,
    client_id: String,
    user_id: Option<Uuid>,
    subject: Option<String>,
    scopes: Vec<String>,
    claims: serde_json::Value,
    authorization_details: serde_json::Value,
    resources: Vec<String>,
    actor_chain: serde_json::Value,
    parent_grant_id: Option<Uuid>,
    session_id: Option<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    expires_at: Option<OffsetDateTime>,
    claimed_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    revocation_reason: Option<String>,
}

impl Row {
    /// Puts the row through the same validation the values passed on the way
    /// in.
    ///
    /// The columns the database enforces nothing about are the point: three
    /// `jsonb` bags, two `text[]`s and a free-text revocation reason. A row
    /// edited during an incident must fail to load rather than reach a token —
    /// see [`GrantRecord`] for what each rule is defending.
    fn into_entity(self, tenant: &TenantId) -> Result<Grant, DomainError> {
        GrantRecord {
            id: GrantId::new(self.grant_id.to_string()),
            client: ClientId::new(self.client_id),
            user: self.user_id.map(UserId::new),
            subject: self.subject,
            scopes: self.scopes,
            claims: self.claims,
            authorization_details: self.authorization_details,
            resources: self.resources,
            actor_chain: self.actor_chain,
            parent: self
                .parent_grant_id
                .map(|parent| GrantId::new(parent.to_string())),
            session: self.session_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            expires_at: self.expires_at,
            claimed_at: self.claimed_at,
            revoked_at: self.revoked_at,
            revocation_reason: self.revocation_reason,
        }
        .validate(tenant)
        .map_err(|error| {
            DomainError::invalid(
                "grants",
                format!("stored row is not a valid grant: {error}"),
            )
        })
    }
}

/// The one operation the authorization endpoint needs. Reading, claiming and
/// revoking stay on the concrete type, where the endpoints that do those things
/// reach them — see [`asterius_domain::GrantRepository`].
#[async_trait::async_trait]
impl asterius_domain::GrantRepository for PgGrantRepository {
    async fn create(&self, grant: &Grant) -> Result<(), DomainError> {
        Self::create(self, grant).await
    }
}
