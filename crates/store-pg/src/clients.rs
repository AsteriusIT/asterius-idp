//! The client repository.
//!
//! One rule shapes this file: **a row is validated by the same code on the way
//! out as on the way in.** A row is turned back into a [`ClientMetadata`]
//! document and put through [`ClientMetadata::validate`], so there is no second
//! definition of an acceptable client living in the adapter and drifting away
//! from the first. Rows get edited by hand during incidents, and a client whose
//! `token_endpoint_auth_method` became `client_secret_basic` in a `psql`
//! session must fail to load rather than quietly authenticate.
//!
//! ## Every validated field has a column
//!
//! `ast-m9c.1` was implemented against a baseline schema that had no column for
//! `application_type`, `subject_type`, `sector_identifier_uri`, the two signing
//! algorithms, the token-binding pair, `authorization_details_types` or
//! `use_mtls_endpoint_aliases`. Rather than drop those values on the floor —
//! which would silently move a certificate-bound client onto DPoP, or a
//! pairwise client onto public subjects — `upsert` refused a client it could
//! not represent.
//!
//! The columns exist now, so the refusal is gone and a client this parser
//! accepts is a client this repository can store. Two of the rules moved into
//! the schema on the way: a row bound to neither DPoP nor a certificate cannot
//! exist, and a `sector_identifier_uri` without a pairwise `subject_type`
//! cannot exist. Both were already enforced by the validator; having them in
//! both places is the point, because the validator protects the API and the
//! constraint protects the table.

use crate::cutoffs;
use crate::error::to_domain_error;
use asterius_domain::SigningAlgorithm;
use asterius_domain::ports::TenantScoped;
use asterius_domain::{
    Capabilities, Client, ClientId, ClientMetadata, ClientRegistration, ClientStatus, DomainError,
    JwksSource, ManagedClient, PreviousRegistrationAccessToken, TenantId, TokenDeliveryMode,
};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// The client repository for one tenant.
///
/// Constructed from a [`TenantScope`], so the tenant is a precondition of
/// holding the handle rather than an argument a query might forget.
///
/// [`TenantScope`]: crate::TenantScope
#[derive(Debug, Clone)]
pub struct PgClientRepository {
    pool: PgPool,
    tenant: TenantId,
    capabilities: Capabilities,
}

#[async_trait::async_trait]
impl asterius_domain::ClientRepository for PgClientRepository {
    async fn find(&self, client_id: &ClientId) -> Result<Option<Client>, DomainError> {
        Self::find(self, client_id).await
    }
}

#[async_trait::async_trait]
impl asterius_domain::ClientRegistry for PgClientRepository {
    async fn register(
        &self,
        client: &Client,
        registration_access_token: &[u8; 32],
    ) -> Result<Client, DomainError> {
        Self::register(self, client, registration_access_token).await
    }
}

#[async_trait::async_trait]
impl asterius_domain::ClientConfiguration for PgClientRepository {
    async fn managed(&self, client_id: &ClientId) -> Result<Option<ManagedClient>, DomainError> {
        Self::managed(self, client_id).await
    }

    async fn replace(&self, client: &Client) -> Result<Client, DomainError> {
        Self::replace(self, client).await
    }

    async fn deprovision(
        &self,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Self::delete(self, client_id, now).await
    }

    async fn revoke_registration_access_token(&self, digest: &[u8; 32]) -> Result<(), DomainError> {
        Self::revoke_registration_access_token(self, digest).await
    }

    async fn rotate_registration_access_token(
        &self,
        client_id: &ClientId,
        digest: &[u8; 32],
        grace_expires_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Self::rotate_registration_access_token(self, client_id, digest, grace_expires_at).await
    }

    async fn retire_previous_registration_access_token(
        &self,
        client_id: &ClientId,
    ) -> Result<(), DomainError> {
        Self::retire_previous_registration_access_token(self, client_id).await
    }
}

impl TenantScoped for PgClientRepository {
    fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}

impl PgClientRepository {
    /// Binds a pool to one tenant.
    ///
    /// `capabilities` is what a stored row is re-validated against: a client
    /// registered for `tls_client_auth` on a deployment that has since turned
    /// mTLS off is a client that can no longer authenticate, and saying so at
    /// load time is more useful than an `invalid_client` at the token endpoint.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId, capabilities: Capabilities) -> Self {
        Self {
            pool,
            tenant,
            capabilities,
        }
    }

    /// Finds one client by `client_id`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] if the stored row no longer describes a
    /// client this profile accepts, or a storage error.
    pub async fn find(&self, client_id: &ClientId) -> Result<Option<Client>, DomainError> {
        let row = sqlx::query_as!(
            Row,
            "select client_id, client_name, token_endpoint_auth_method, redirect_uris,
                    post_logout_redirect_uris, grant_types, response_types, scopes, resources, jwks, jwks_uri,
                    id_token_signed_response_alg, application_type, subject_type, sector_identifier_uri,
                    request_object_signing_alg, backchannel_authentication_request_signing_alg,
                    dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens,
                    authorization_details_types, use_mtls_endpoint_aliases,
                    tls_client_auth_field, tls_client_auth_value,
                    userinfo_signed_response_alg,
                    backchannel_token_delivery_mode, backchannel_client_notification_endpoint,
                    backchannel_user_code_parameter,
                    is_agent, agent_owner_user_id, agent_policy,
                    backchannel_logout_uri, backchannel_logout_session_required,
                    roles_in_id_token,
                    status, created_at, updated_at
             from clients
             where tenant_id = $1 and client_id = $2",
            self.tenant.as_str(),
            client_id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(|row| row.into_entity(&self.tenant, self.capabilities))
            .transpose()
    }

    /// Every client in this tenant, ordered by `client_id`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] if any stored row no longer describes a
    /// client this profile accepts, or a storage error.
    pub async fn list(&self) -> Result<Vec<Client>, DomainError> {
        sqlx::query_as!(
            Row,
            "select client_id, client_name, token_endpoint_auth_method, redirect_uris,
                    post_logout_redirect_uris, grant_types, response_types, scopes, resources, jwks, jwks_uri,
                    id_token_signed_response_alg, application_type, subject_type, sector_identifier_uri,
                    request_object_signing_alg, backchannel_authentication_request_signing_alg,
                    dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens,
                    authorization_details_types, use_mtls_endpoint_aliases,
                    tls_client_auth_field, tls_client_auth_value,
                    userinfo_signed_response_alg,
                    backchannel_token_delivery_mode, backchannel_client_notification_endpoint,
                    backchannel_user_code_parameter,
                    is_agent, agent_owner_user_id, agent_policy,
                    backchannel_logout_uri, backchannel_logout_session_required,
                    roles_in_id_token,
                    status, created_at, updated_at
             from clients
             where tenant_id = $1
             order by client_id",
            self.tenant.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?
        .into_iter()
        .map(|row| row.into_entity(&self.tenant, self.capabilities))
        .collect()
    }

    /// Creates or replaces a client.
    ///
    /// The `on conflict` clause updates only the columns this story owns. The
    /// agent profile (`ast-lh3.1`), the registration access token and the
    /// software statement (`ast-m9c.4`, `ast-m9c.6`) live in the same row and
    /// are written by their own code paths; an update here must not erase them.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] when the client carries a value the
    /// baseline schema cannot hold (see the module documentation), a
    /// [`DomainError::Conflict`] when the tenant does not exist, or a storage
    /// error.
    #[expect(
        clippy::too_many_lines,
        reason = "one INSERT ... ON CONFLICT statement and the binds it needs, in the order \
                  the column list gives them; splitting it would put half a column list in \
                  another function, which is exactly how a bind drifts away from its column"
    )]
    pub async fn upsert(&self, client: &Client) -> Result<(), DomainError> {
        if client.tenant != self.tenant {
            // The scope is the tenant. An entity from another one arriving here
            // is a bug in the caller, and writing it would put a row under the
            // wrong owner.
            return Err(DomainError::invalid(
                "tenant_id",
                "does not match the tenant this repository is scoped to",
            ));
        }
        let registration = &client.registration;
        let lists = ListColumns::of(registration);
        let (jwks, jwks_uri) = key_columns(registration);
        let (tls_field, tls_value) = subject_columns(registration);
        let (backchannel_uri, backchannel_session_required) =
            backchannel_logout_columns(registration);
        let (agent, agent_policy) = agent_columns(registration);

        sqlx::query!(
            "insert into clients (tenant_id, client_id, client_name,
                                  token_endpoint_auth_method, redirect_uris, grant_types,
                                  response_types, scopes, resources, jwks, jwks_uri,
                                  id_token_signed_response_alg, application_type, subject_type,
                                  sector_identifier_uri, request_object_signing_alg,
                                  backchannel_authentication_request_signing_alg,
                                  dpop_bound_access_tokens,
                                  tls_client_certificate_bound_access_tokens,
                                  authorization_details_types, use_mtls_endpoint_aliases, status,
                                  post_logout_redirect_uris,
                                  tls_client_auth_field, tls_client_auth_value,
                                  userinfo_signed_response_alg,
                                  backchannel_token_delivery_mode,
                                  backchannel_client_notification_endpoint,
                                  backchannel_user_code_parameter,
                                  is_agent, agent_owner_user_id, agent_policy,
                                  backchannel_logout_uri, backchannel_logout_session_required,
                                  roles_in_id_token)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                     $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31,
                     $32, $33, $34, $35)
             on conflict (tenant_id, client_id) do update
             set client_name = excluded.client_name,
                 token_endpoint_auth_method = excluded.token_endpoint_auth_method,
                 redirect_uris = excluded.redirect_uris,
                 grant_types = excluded.grant_types,
                 response_types = excluded.response_types,
                 scopes = excluded.scopes,
                 resources = excluded.resources,
                 jwks = excluded.jwks,
                 jwks_uri = excluded.jwks_uri,
                 id_token_signed_response_alg = excluded.id_token_signed_response_alg,
                 application_type = excluded.application_type,
                 subject_type = excluded.subject_type,
                 sector_identifier_uri = excluded.sector_identifier_uri,
                 request_object_signing_alg = excluded.request_object_signing_alg,
                 backchannel_authentication_request_signing_alg =
                     excluded.backchannel_authentication_request_signing_alg,
                 dpop_bound_access_tokens = excluded.dpop_bound_access_tokens,
                 tls_client_certificate_bound_access_tokens =
                     excluded.tls_client_certificate_bound_access_tokens,
                 authorization_details_types = excluded.authorization_details_types,
                 use_mtls_endpoint_aliases = excluded.use_mtls_endpoint_aliases,
                 status = excluded.status,
                 post_logout_redirect_uris = excluded.post_logout_redirect_uris,
                 tls_client_auth_field = excluded.tls_client_auth_field,
                 tls_client_auth_value = excluded.tls_client_auth_value,
                 userinfo_signed_response_alg = excluded.userinfo_signed_response_alg,
                 backchannel_token_delivery_mode = excluded.backchannel_token_delivery_mode,
                 backchannel_client_notification_endpoint =
                     excluded.backchannel_client_notification_endpoint,
                 backchannel_user_code_parameter = excluded.backchannel_user_code_parameter,
                 is_agent = excluded.is_agent,
                 agent_owner_user_id = excluded.agent_owner_user_id,
                 agent_policy = excluded.agent_policy,
                 backchannel_logout_uri = excluded.backchannel_logout_uri,
                 backchannel_logout_session_required =
                     excluded.backchannel_logout_session_required,
                 roles_in_id_token = excluded.roles_in_id_token",
            self.tenant.as_str(),
            client.id.as_str(),
            registration.client_name,
            registration.token_endpoint_auth_method.as_str(),
            &lists.redirect_uris,
            &lists.grant_types,
            &lists.response_types,
            &lists.scopes,
            &lists.resources,
            jwks,
            jwks_uri.as_deref(),
            registration.id_token_signed_response_alg.as_str(),
            registration.application_type.as_str(),
            registration.subject_type.as_str(),
            registration.sector_identifier_uri.as_deref(),
            algorithm_column(registration.request_object_signing_alg),
            algorithm_column(registration.backchannel_authentication_request_signing_alg),
            registration.token_binding.is_dpop_bound(),
            registration.token_binding.is_certificate_bound(),
            &lists.authorization_details_types,
            registration.use_mtls_endpoint_aliases,
            client.status.as_str(),
            &lists.post_logout_redirect_uris,
            tls_field,
            tls_value,
            algorithm_column(registration.userinfo_signed_response_alg),
            registration
                .backchannel_token_delivery_mode
                .map(TokenDeliveryMode::as_str),
            registration
                .backchannel_client_notification_endpoint
                .as_deref(),
            registration.backchannel_user_code_parameter,
            agent.is_some(),
            agent.map(|profile| *profile.owner().user_id().as_uuid()),
            agent_policy,
            backchannel_uri,
            backchannel_session_required,
            registration.roles_in_id_token.is_issued(),
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(to_domain_error)
    }

    /// Creates a client that did not exist, with the digest of its RFC 7592
    /// registration access token.
    ///
    /// Not [`Self::upsert`] with an extra column, for two reasons.
    ///
    /// **`insert` and not `on conflict do update`.** Registration mints its own
    /// `client_id`, so a row already sitting under that id is a collision in a
    /// 256-bit space, not an update anybody asked for. Upserting would let the
    /// improbable case silently replace a live client's keys, redirect URIs and
    /// registration access token — which is the shape of a takeover, arriving
    /// through the one endpoint that is reachable without a client credential.
    /// A conflict is therefore an error, and the caller retries with a fresh
    /// draw or gives up; neither outcome touches an existing row.
    ///
    /// **`returning` and not a second `select`.** RFC 7591 §3.2.1 requires the
    /// response to carry the metadata the server actually registered, and the
    /// only honest source for that is the row. Reading it back in the same
    /// statement means what the client is told is what was committed, with no
    /// window in between and no second round trip that could fail after the row
    /// exists — a failure there would leave a registered client whose owner was
    /// handed an error and never learned its `client_id`.
    ///
    /// The row is put back through [`ClientMetadata::validate`] on the way out
    /// like every other read, so a registration that the schema silently
    /// altered — a default, a trigger — fails here rather than at the token
    /// endpoint weeks later.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the `client_id` is taken or the tenant does
    /// not exist, [`DomainError::Invalid`] if the entity belongs to another
    /// tenant or the stored row does not validate, or a storage error.
    pub async fn register(
        &self,
        client: &Client,
        registration_access_token: &[u8; 32],
    ) -> Result<Client, DomainError> {
        if client.tenant != self.tenant {
            return Err(DomainError::invalid(
                "tenant_id",
                "does not match the tenant this repository is scoped to",
            ));
        }
        let registration = &client.registration;
        let lists = ListColumns::of(registration);
        let (jwks, jwks_uri) = key_columns(registration);
        let (tls_field, tls_value) = subject_columns(registration);
        let (backchannel_uri, backchannel_session_required) =
            backchannel_logout_columns(registration);
        let (agent, agent_policy) = agent_columns(registration);

        let row = sqlx::query_as!(
            Row,
            "insert into clients (tenant_id, client_id, client_name,
                                  token_endpoint_auth_method, redirect_uris, grant_types,
                                  response_types, scopes, resources, jwks, jwks_uri,
                                  id_token_signed_response_alg, application_type, subject_type,
                                  sector_identifier_uri, request_object_signing_alg,
                                  backchannel_authentication_request_signing_alg,
                                  dpop_bound_access_tokens,
                                  tls_client_certificate_bound_access_tokens,
                                  authorization_details_types, use_mtls_endpoint_aliases, status,
                                  registration_access_token_hash, post_logout_redirect_uris,
                                  tls_client_auth_field, tls_client_auth_value,
                                  userinfo_signed_response_alg,
                                  backchannel_token_delivery_mode,
                                  backchannel_client_notification_endpoint,
                                  backchannel_user_code_parameter,
                                  is_agent, agent_owner_user_id, agent_policy,
                                  backchannel_logout_uri, backchannel_logout_session_required,
                                  roles_in_id_token)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                     $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31,
                     $32, $33, $34, $35, $36)
             returning client_id, client_name, token_endpoint_auth_method, redirect_uris,
                       post_logout_redirect_uris, grant_types, response_types, scopes, resources, jwks, jwks_uri,
                       id_token_signed_response_alg, application_type, subject_type,
                       sector_identifier_uri, request_object_signing_alg,
                       backchannel_authentication_request_signing_alg,
                       dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens,
                       authorization_details_types, use_mtls_endpoint_aliases,
                       tls_client_auth_field, tls_client_auth_value,
                       userinfo_signed_response_alg,
                       backchannel_token_delivery_mode, backchannel_client_notification_endpoint,
                       backchannel_user_code_parameter,
                       is_agent, agent_owner_user_id, agent_policy,
                       backchannel_logout_uri, backchannel_logout_session_required,
                       roles_in_id_token,
                       status, created_at, updated_at",
            self.tenant.as_str(),
            client.id.as_str(),
            registration.client_name,
            registration.token_endpoint_auth_method.as_str(),
            &lists.redirect_uris,
            &lists.grant_types,
            &lists.response_types,
            &lists.scopes,
            &lists.resources,
            jwks,
            jwks_uri.as_deref(),
            registration.id_token_signed_response_alg.as_str(),
            registration.application_type.as_str(),
            registration.subject_type.as_str(),
            registration.sector_identifier_uri.as_deref(),
            algorithm_column(registration.request_object_signing_alg),
            algorithm_column(registration.backchannel_authentication_request_signing_alg),
            registration.token_binding.is_dpop_bound(),
            registration.token_binding.is_certificate_bound(),
            &lists.authorization_details_types,
            registration.use_mtls_endpoint_aliases,
            client.status.as_str(),
            &registration_access_token[..],
            &lists.post_logout_redirect_uris,
            tls_field,
            tls_value,
            algorithm_column(registration.userinfo_signed_response_alg),
            registration
                .backchannel_token_delivery_mode
                .map(TokenDeliveryMode::as_str),
            registration.backchannel_client_notification_endpoint.as_deref(),
            registration.backchannel_user_code_parameter,
            agent.is_some(),
            agent.map(|profile| *profile.owner().user_id().as_uuid()),
            agent_policy,
            backchannel_uri,
            backchannel_session_required,
            registration.roles_in_id_token.is_issued(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)?;

        row.into_entity(&self.tenant, self.capabilities)
    }

    /// The two columns a management request is authorised against.
    ///
    /// Deliberately not [`Self::find`] with an extra field. `find` rebuilds the
    /// registration document and puts it back through
    /// [`ClientMetadata::validate`], which is right for every caller that is
    /// about to *use* the client and wrong for the one caller that is about to
    /// authenticate a request to change or delete it: a row that no longer
    /// validates — because an operator turned mTLS off, or because somebody
    /// edited a column by hand — would fail to load, and RFC 7592's endpoint is
    /// the only way its owner could have fixed or removed it. So this reads two
    /// scalar columns and validates nothing.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] if the stored `status` is not one this
    /// server knows, or a storage error. Never `Ok(None)` for a client that
    /// exists: the caller distinguishes "no such client" from "cannot tell",
    /// and answering a management request as though the client were absent when
    /// the database was merely unreachable would refuse a client that is
    /// perfectly valid.
    pub async fn managed(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<ManagedClient>, DomainError> {
        let row = sqlx::query!(
            "select status, registration_access_token_hash,
                    previous_registration_access_token_hash,
                    previous_registration_access_token_expires_at,
                    is_agent, agent_owner_user_id, agent_policy
             from clients
             where tenant_id = $1 and client_id = $2",
            self.tenant.as_str(),
            client_id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        row.map(|row| {
            let status = ClientStatus::parse(&row.status).ok_or_else(|| {
                DomainError::invalid("status", format!("unknown: {}", row.status))
            })?;
            // A column of the wrong width is not a token that happens to be
            // short: it is a row nothing should authenticate against, so it
            // becomes "this client has no registration access token" rather
            // than a comparison against a truncated digest.
            let registration_access_token = row
                .registration_access_token_hash
                .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok());
            // Both columns or neither, which the schema's own check constraint
            // already guarantees; read as a pair anyway, because a predecessor
            // with no expiry read as "no expiry" would be the one shape of this
            // row that must never authenticate anybody — a second permanent
            // credential. A half-row becomes no predecessor at all.
            let previous_registration_access_token = row
                .previous_registration_access_token_hash
                .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                .zip(row.previous_registration_access_token_expires_at)
                .map(
                    |(digest, grace_expires_at)| PreviousRegistrationAccessToken {
                        digest,
                        grace_expires_at,
                    },
                );
            // `ast-lh3.1`. A row flagged `is_agent` whose profile does not
            // parse, or whose owner column is empty, yields `None` rather than
            // an error: this read exists to authenticate a management request,
            // and RFC 7592 §2.1/§2.3 make that endpoint the only way such a
            // client could be repaired or deleted. What `None` costs is the
            // agent check on an update, and `PgClientRepository::replace`
            // makes that up before it writes.
            let agent = row
                .agent_owner_user_id
                .zip(asterius_domain::AgentLimits::from_json(&row.agent_policy).ok())
                .filter(|_| row.is_agent)
                .map(|(owner, limits)| {
                    asterius_domain::AgentProfile::new(
                        asterius_domain::AgentOwner::User(asterius_domain::UserId::new(owner)),
                        limits,
                    )
                });
            Ok(ManagedClient {
                registration_access_token,
                previous_registration_access_token,
                status,
                agent,
            })
        })
        .transpose()
    }

    /// Replaces a client's registration metadata (RFC 7592 §2.2).
    ///
    /// An `update`, not an upsert: the row must already exist, because the
    /// caller has just authenticated against it. A `client_id` that vanished in
    /// between is [`DomainError::NotFound`], never a fresh row — a client
    /// cannot bring itself back from the dead by updating itself.
    ///
    /// **The `set` list is the whole security argument.** It names exactly the
    /// columns [`ClientRegistration`] can express, and therefore exactly the
    /// fields RFC 7592 §2.2 lets a client replace. Everything else in the row is
    /// untouched *by construction* rather than by a check somebody could forget
    /// to write: `registration_access_token_hash` (the credential that
    /// authorised this call), `resources` (the per-client audience allow-list,
    /// which is policy — `ast-m9c.6`), `is_agent` / `agent_owner_user_id` /
    /// `agent_policy` (`ast-lh3.1`), `software_statement`, `status` (a
    /// suspension is an operator's decision and not a client's), `client_type`
    /// and `created_at`. `updated_at` moves, because the row's trigger moves it.
    ///
    /// Note what is here that [`Self::upsert`] has and this does not:
    /// `resources`. The admin API may set the allow-list; a client updating
    /// itself may not, and the difference is a missing column in a statement
    /// rather than a rule in prose.
    ///
    /// `returning` for the same reason [`Self::register`] uses it: RFC 7592 §3
    /// makes the response "all registered metadata about this client", and the
    /// only honest source for that is the committed row.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if there is no such client in this tenant,
    /// [`DomainError::Invalid`] if the entity belongs to another tenant or the
    /// stored row does not validate, or a storage error.
    pub async fn replace(&self, client: &Client) -> Result<Client, DomainError> {
        if client.tenant != self.tenant {
            return Err(DomainError::invalid(
                "tenant_id",
                "does not match the tenant this repository is scoped to",
            ));
        }
        let registration = &client.registration;
        let lists = ListColumns::of(registration);
        let (jwks, jwks_uri) = key_columns(registration);
        let (tls_field, tls_value) = subject_columns(registration);
        let (backchannel_uri, backchannel_session_required) =
            backchannel_logout_columns(registration);
        // `ast-lh3.1`. This statement does not write the agent columns — an
        // agent profile is policy the tenant attached, exactly like
        // `resources`, and RFC 7592 §2.2 is the *client* rewriting its own
        // metadata — so the replacement has to be something the stored profile
        // still permits. Checked before the write and not after: the read-back
        // below applies the same rule, and by then the change would already be
        // committed.
        self.check_agent_limits(&client.id, registration).await?;

        let row = sqlx::query_as!(
            Row,
            "update clients
             set client_name = $3,
                 token_endpoint_auth_method = $4,
                 redirect_uris = $5,
                 grant_types = $6,
                 response_types = $7,
                 scopes = $8,
                 jwks = $9,
                 jwks_uri = $10,
                 id_token_signed_response_alg = $11,
                 application_type = $12,
                 subject_type = $13,
                 sector_identifier_uri = $14,
                 request_object_signing_alg = $15,
                 backchannel_authentication_request_signing_alg = $16,
                 dpop_bound_access_tokens = $17,
                 tls_client_certificate_bound_access_tokens = $18,
                 authorization_details_types = $19,
                 use_mtls_endpoint_aliases = $20,
                 post_logout_redirect_uris = $21,
                 tls_client_auth_field = $22,
                 tls_client_auth_value = $23,
                 userinfo_signed_response_alg = $24,
                 backchannel_token_delivery_mode = $25,
                 backchannel_client_notification_endpoint = $26,
                 backchannel_user_code_parameter = $27,
                 backchannel_logout_uri = $28,
                 backchannel_logout_session_required = $29,
                 roles_in_id_token = $30
             where tenant_id = $1 and client_id = $2
             returning client_id, client_name, token_endpoint_auth_method, redirect_uris,
                       post_logout_redirect_uris, grant_types, response_types, scopes, resources, jwks, jwks_uri,
                       id_token_signed_response_alg, application_type, subject_type,
                       sector_identifier_uri, request_object_signing_alg,
                       backchannel_authentication_request_signing_alg,
                       dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens,
                       authorization_details_types, use_mtls_endpoint_aliases,
                       tls_client_auth_field, tls_client_auth_value,
                       userinfo_signed_response_alg,
                       backchannel_token_delivery_mode, backchannel_client_notification_endpoint,
                       backchannel_user_code_parameter,
                       is_agent, agent_owner_user_id, agent_policy,
                       backchannel_logout_uri, backchannel_logout_session_required,
                       roles_in_id_token,
                       status, created_at, updated_at",
            self.tenant.as_str(),
            client.id.as_str(),
            registration.client_name,
            registration.token_endpoint_auth_method.as_str(),
            &lists.redirect_uris,
            &lists.grant_types,
            &lists.response_types,
            &lists.scopes,
            jwks,
            jwks_uri.as_deref(),
            registration.id_token_signed_response_alg.as_str(),
            registration.application_type.as_str(),
            registration.subject_type.as_str(),
            registration.sector_identifier_uri.as_deref(),
            algorithm_column(registration.request_object_signing_alg),
            algorithm_column(registration.backchannel_authentication_request_signing_alg),
            registration.token_binding.is_dpop_bound(),
            registration.token_binding.is_certificate_bound(),
            &lists.authorization_details_types,
            registration.use_mtls_endpoint_aliases,
            &lists.post_logout_redirect_uris,
            tls_field,
            tls_value,
            algorithm_column(registration.userinfo_signed_response_alg),
            registration
                .backchannel_token_delivery_mode
                .map(TokenDeliveryMode::as_str),
            registration.backchannel_client_notification_endpoint.as_deref(),
            registration.backchannel_user_code_parameter,
            backchannel_uri,
            backchannel_session_required,
            registration.roles_in_id_token.is_issued(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        .ok_or(DomainError::NotFound)?;

        row.into_entity(&self.tenant, self.capabilities)
    }

    /// Whether `registration` is admissible under the agent profile the stored
    /// row already carries (`ast-lh3.1`).
    ///
    /// `Ok(())` for every client that is not an agent, which is nearly all of
    /// them, at the cost of one indexed read of two columns.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when the row is an agent and the replacement
    /// leaves its limits, or when the stored profile does not parse.
    async fn check_agent_limits(
        &self,
        client_id: &ClientId,
        registration: &ClientRegistration,
    ) -> Result<(), DomainError> {
        let row = sqlx::query!(
            "select is_agent, agent_policy from clients
             where tenant_id = $1 and client_id = $2",
            self.tenant.as_str(),
            client_id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let Some(row) = row.filter(|row| row.is_agent) else {
            return Ok(());
        };
        asterius_domain::AgentLimits::from_json(&row.agent_policy)
            .map_err(|error| DomainError::invalid("clients.agent_policy", error.to_string()))?
            .check(registration)
            .map_err(|error| DomainError::invalid("clients", error.to_string()))
    }

    /// Deletes a client and, by cascade, its keys, pushed requests, grants and
    /// every token hanging off them.
    ///
    /// The cascade is the schema's, and it is what makes RFC 7592 §2.3's
    /// "SHOULD immediately invalidate all existing authorization grants and
    /// currently active access tokens, all refresh tokens, and all other tokens
    /// associated with this client" true without a second statement to forget:
    /// `client_keys` and `auth_requests` reference `(tenant_id, client_id)` on
    /// delete cascade, `grants` does too, and `authorization_codes` and
    /// `refresh_tokens` cascade from `grants`.
    ///
    /// `audit_events` does not, deliberately: it has no foreign key to
    /// `clients`, so deprovisioning a client does not erase the record of what
    /// it did. That is the property an append-only trail exists for.
    ///
    /// ## The one thing no cascade can reach
    ///
    /// An access token already issued. It is a signed JWT this server does not
    /// hold (RFC 9068), so there is no row to delete and no `jti` to put on
    /// `access_token_denylist` — the schema has never inventoried the ones it
    /// signed. What is written instead, in the same transaction as the delete,
    /// is a mark: the private `cutoffs::withdraw` records that nothing issued to
    /// this `client_id` before `now` is good any more, and the resource path
    /// compares it against the token's own `iat` (`ast-m9c.13`).
    ///
    /// The mark is deliberately not a column on `clients`: this is a real
    /// delete, so a mark living on the row would be erased by the very act it
    /// records.
    ///
    /// `now` is the caller's clock reading, the same one the audit event
    /// carries, so the trail and the cutoff cannot disagree about when the
    /// client was deprovisioned.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::NotFound`] if no such client exists in this
    /// tenant, or a storage error — in which case neither the delete nor the
    /// mark was written.
    pub async fn delete(
        &self,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        let result = sqlx::query!(
            "delete from clients where tenant_id = $1 and client_id = $2",
            self.tenant.as_str(),
            client_id.as_str()
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }

        // After the delete and inside its transaction: a client that was not
        // there is not a client whose tokens were withdrawn, and a mark
        // committed without the delete would refuse the tokens of a client
        // that still works.
        cutoffs::withdraw(
            &mut *transaction,
            &self.tenant,
            cutoffs::Principal::Client(client_id.as_str()),
            now,
        )
        .await?;

        transaction.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    /// Nulls a registration access token digest wherever this tenant holds it.
    ///
    /// One statement, resolved by `clients_by_registration_access_token` — the
    /// partial index the baseline carries for this caller and no other. That is
    /// the whole reason the method can exist: it runs on a request that has not
    /// authenticated, so a sequential scan over `clients` would turn RFC 7592's
    /// housekeeping SHOULD into a denial-of-service primitive. The database test
    /// reads the plan back rather than trusting the index to be chosen.
    ///
    /// `where ... is not null` is not redundant with the digest equality: it is
    /// what makes the predicate match the partial index's own, so the planner
    /// may use it.
    ///
    /// A digest no client holds updates no rows and writes nothing — no row
    /// version, no `updated_at`, no WAL beyond an empty transaction — which is
    /// what keeps a caller sweeping `client_id`s from leaving a trail.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Never
    /// `NotFound`: "no client held this" is the ordinary case here, not a
    /// failure, and the caller has already decided to refuse.
    pub async fn revoke_registration_access_token(
        &self,
        digest: &[u8; 32],
    ) -> Result<(), DomainError> {
        let result = sqlx::query!(
            "update clients set registration_access_token_hash = null
             where tenant_id = $1
               and registration_access_token_hash = $2
               and registration_access_token_hash is not null",
            self.tenant.as_str(),
            digest.as_slice()
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        // At `warn`, and only when something was actually burned. This is the
        // one record of an event whose victim is usually its owner: a client
        // that mistyped its configuration URL has just lost its only credential
        // and will arrive asking why, and the answer has to exist somewhere.
        // The digest is not logged — it is the credential's identity, and a log
        // line is not where it belongs. The requester learns none of this.
        if result.rows_affected() > 0 {
            tracing::warn!(
                tenant = %self.tenant.as_str(),
                clients = result.rows_affected(),
                "revoked a registration access token presented at a client it does not manage \
                 (RFC 7592 2.1); that client now has no credential and must be re-registered"
            );
        }
        Ok(())
    }

    /// Issues a new registration access token and demotes the current one
    /// (RFC 7592 §5, `ast-m9c.12`).
    ///
    /// One statement, and that is the whole correctness argument. The digest
    /// the client will authenticate with next and the digest it may still
    /// authenticate with meanwhile are two columns of the same row, so a
    /// two-statement version would have an instant in which a crash leaves a
    /// client with no credential and no way to ask for one. Written as a single
    /// `update`, there is no such instant: either the row rotated or it did not.
    ///
    /// The demotion reads `registration_access_token_hash` in the same
    /// statement that overwrites it, which Postgres evaluates against the row
    /// as it was — so `previous` becomes the token the caller just
    /// authenticated with, never the one being issued.
    ///
    /// Any predecessor already sitting in the row is overwritten rather than
    /// kept. A client that updates itself twice inside one grace window ends
    /// with two live tokens, not three: the generation before last dies early,
    /// which is the direction to fail in.
    ///
    /// A client with no registration access token — one the admin API created —
    /// cannot reach this: the endpoint refuses it before any write. If it ever
    /// did, the `where` clause would leave the row alone rather than mint a
    /// credential for a client that was deliberately given none.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if no row was rotated, so that a caller never
    /// tells a client its token changed when nothing was written.
    /// [`DomainError::Storage`] otherwise.
    pub async fn rotate_registration_access_token(
        &self,
        client_id: &ClientId,
        digest: &[u8; 32],
        grace_expires_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let result = sqlx::query!(
            "update clients
                set previous_registration_access_token_hash = registration_access_token_hash,
                    previous_registration_access_token_expires_at = $4,
                    registration_access_token_hash = $3
             where tenant_id = $1
               and client_id = $2
               and registration_access_token_hash is not null",
            self.tenant.as_str(),
            client_id.as_str(),
            digest.as_slice(),
            grace_expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }

    /// Clears a client's rotated-out registration access token.
    ///
    /// Runs on every authenticated management request that presented the
    /// *current* token, which is why it is written to be cheap and silent: the
    /// `where` clause carries `is not null`, so the ordinary case — a client
    /// that has never rotated — matches no row and writes nothing at all. No
    /// row version, no `updated_at`, no WAL beyond an empty transaction.
    ///
    /// It is what keeps the grace window a cover for a lost response rather
    /// than a period of coexistence: the moment the client proves it received
    /// the new token, the old one stops working, whatever the window still had
    /// left.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Never
    /// `NotFound`: nothing to retire is the common case, not a failure.
    pub async fn retire_previous_registration_access_token(
        &self,
        client_id: &ClientId,
    ) -> Result<(), DomainError> {
        sqlx::query!(
            "update clients
                set previous_registration_access_token_hash = null,
                    previous_registration_access_token_expires_at = null
             where tenant_id = $1
               and client_id = $2
               and previous_registration_access_token_hash is not null",
            self.tenant.as_str(),
            client_id.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }
}

/// The array columns, gathered once.
///
/// `sqlx` binds slices by reference, so every list needs an owned `Vec` that
/// outlives the query. Collecting them here rather than inline is what keeps
/// `upsert` down to the statement it is really made of.
struct ListColumns {
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    scopes: Vec<String>,
    resources: Vec<String>,
    authorization_details_types: Vec<String>,
}

impl ListColumns {
    fn of(registration: &ClientRegistration) -> Self {
        Self {
            redirect_uris: registration
                .redirect_uris
                .iter()
                .map(|uri| uri.as_str().to_owned())
                .collect(),
            post_logout_redirect_uris: registration.registered_post_logout_redirect_uris(),
            grant_types: registration
                .grant_types
                .iter()
                .map(|grant| grant.as_str().to_owned())
                .collect(),
            // Kept consistent with `grant_types` rather than defaulted by the
            // column: RFC 7591 §2.1 ties the two together, and a row where they
            // disagree is a row that fails to load. The derivation lives on the
            // registration so that the registration endpoint echoes back
            // exactly what this writes (`ast-m9c.4`).
            response_types: registration
                .response_types()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            scopes: registration.scopes.iter().cloned().collect(),
            resources: registration.resources.iter().cloned().collect(),
            authorization_details_types: registration
                .authorization_details_types
                .iter()
                .cloned()
                .collect(),
        }
    }
}

/// One row of `clients`, before it becomes an entity.
/// RFC 8705 §2.1.2's registered subject, as the two columns that hold it.
///
/// `(None, None)` for every client that is not `tls_client_auth`, which is the
/// pair the schema's `clients_tls_client_auth_subject_matches_method`
/// constraint requires of them. Written from the registration rather than from
/// the document that produced it, so a client whose method changed on an
/// update loses the subject in the same statement.
/// The `text` column an optional signing algorithm is stored in.
///
/// A helper so that each of the three algorithm members is one line at each
/// writing site: three lines each, at three sites, is what pushed these
/// statements past what a reader holds at once.
const fn algorithm_column(algorithm: Option<SigningAlgorithm>) -> Option<&'static str> {
    match algorithm {
        Some(algorithm) => Some(algorithm.as_str()),
        None => None,
    }
}

/// The two back-channel logout columns (OIDC Back-Channel Logout 1.0 §2.2).
///
/// A helper rather than an expression at each of the three writing sites: they
/// are one pair of columns, and a site that wrote the URL without the flag
/// would store a client that is notified but not the way it registered for.
fn backchannel_logout_columns(registration: &ClientRegistration) -> (Option<&str>, bool) {
    (
        registration
            .backchannel_logout_uri
            .as_ref()
            .map(asterius_domain::RedirectUri::as_str),
        registration.backchannel_logout_session_required,
    )
}

fn subject_columns(registration: &ClientRegistration) -> (Option<&str>, Option<&str>) {
    registration
        .tls_client_auth_subject
        .as_ref()
        .map_or((None, None), |subject| {
            (Some(subject.field()), Some(subject.value()))
        })
}

/// The agent columns of a row, lifted out before the rest of it is consumed.
///
/// A struct rather than three locals because it travels from the top of
/// [`Row::into_entity`] to its end, past the point where `self` is partially
/// moved into the metadata document it rebuilds.
struct StoredAgent {
    is_agent: bool,
    owner: Option<uuid::Uuid>,
    policy: serde_json::Value,
}

/// The two key columns, of which the schema holds exactly one.
///
/// `clients_exactly_one_key_source` is a check constraint, and the domain's
/// [`JwksSource`] is the same rule as a type, so this is a translation and not
/// a decision: writing it once means the three statements that store a client
/// cannot disagree about which column a key source lands in.
fn key_columns(registration: &ClientRegistration) -> (Option<serde_json::Value>, Option<String>) {
    match &registration.jwks {
        JwksSource::Inline(value) => (Some(value.clone()), None),
        JwksSource::Uri(uri) => (None, Some(uri.clone())),
    }
}

/// The three columns an agent profile (`ast-lh3.1`) occupies.
///
/// The owner is written to its own column and *not* left only in the document:
/// the foreign key and the disable-on-delete trigger of migration `0021` act on
/// a column, and an owner that lived only in the JSON would be a reference the
/// database cannot enforce. The document therefore stores the limits alone,
/// which is what [`asterius_domain::AgentLimits::from_json`] reads back — a
/// second copy of the owner is a second thing to disagree.
fn agent_columns(
    registration: &ClientRegistration,
) -> (Option<&asterius_domain::AgentProfile>, serde_json::Value) {
    match &registration.agent {
        Some(profile) => (Some(profile), profile.limits().to_json()),
        None => (None, serde_json::json!({})),
    }
}

/// One `clients` row, column for column.
///
/// The booleans are columns and not a state: `dpop_bound_access_tokens` and
/// `tls_client_certificate_bound_access_tokens` are RFC 9449 §5.2 and
/// RFC 8705 §3.4, `use_mtls_endpoint_aliases` is FAPI 2.0 SP §5.2.2.1.1, and
/// `backchannel_user_code_parameter` is CIBA Core 1.0 §4 and `is_agent` is
/// `ast-lh3.1`. They are independent
/// of each other, so the enum clippy suggests cannot express them, and the
/// combinations that are *not* independent are refused by the schema's check
/// constraints rather than by this type.
#[expect(
    clippy::struct_excessive_bools,
    reason = "a row mirrors its table, and five of these columns are booleans in it"
)]
struct Row {
    client_id: String,
    client_name: String,
    token_endpoint_auth_method: String,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    scopes: Vec<String>,
    resources: Vec<String>,
    jwks: Option<serde_json::Value>,
    jwks_uri: Option<String>,
    id_token_signed_response_alg: String,
    application_type: String,
    subject_type: String,
    sector_identifier_uri: Option<String>,
    request_object_signing_alg: Option<String>,
    backchannel_authentication_request_signing_alg: Option<String>,
    dpop_bound_access_tokens: bool,
    tls_client_certificate_bound_access_tokens: bool,
    authorization_details_types: Vec<String>,
    use_mtls_endpoint_aliases: bool,
    tls_client_auth_field: Option<String>,
    tls_client_auth_value: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    backchannel_token_delivery_mode: Option<String>,
    backchannel_client_notification_endpoint: Option<String>,
    backchannel_user_code_parameter: bool,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
    roles_in_id_token: bool,
    is_agent: bool,
    agent_owner_user_id: Option<uuid::Uuid>,
    agent_policy: serde_json::Value,
    status: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Row {
    /// Rebuilds the registration document the row came from and validates it
    /// again.
    ///
    /// Going back through [`ClientMetadata::validate`] rather than mapping
    /// columns to fields directly is what stops the adapter growing a second,
    /// laxer definition of an acceptable client. It costs one document
    /// construction per row and buys the guarantee that anything this
    /// repository hands out would be accepted at registration today.
    fn into_entity(
        self,
        tenant: &TenantId,
        capabilities: Capabilities,
    ) -> Result<Client, DomainError> {
        let status = ClientStatus::parse(&self.status)
            .ok_or_else(|| DomainError::invalid("status", format!("unknown: {}", self.status)))?;
        let stored_agent = StoredAgent {
            is_agent: self.is_agent,
            owner: self.agent_owner_user_id,
            policy: self.agent_policy,
        };

        let mut metadata = ClientMetadata {
            client_name: Some(self.client_name),
            token_endpoint_auth_method: Some(self.token_endpoint_auth_method),
            redirect_uris: Some(self.redirect_uris),
            post_logout_redirect_uris: Some(self.post_logout_redirect_uris),
            grant_types: Some(self.grant_types),
            response_types: Some(self.response_types),
            scope: Some(self.scopes.join(" ")),
            jwks: self.jwks,
            jwks_uri: self.jwks_uri,
            id_token_signed_response_alg: Some(self.id_token_signed_response_alg),
            application_type: Some(self.application_type),
            subject_type: Some(self.subject_type),
            sector_identifier_uri: self.sector_identifier_uri,
            request_object_signing_alg: self.request_object_signing_alg,
            backchannel_authentication_request_signing_alg: self
                .backchannel_authentication_request_signing_alg,
            dpop_bound_access_tokens: Some(self.dpop_bound_access_tokens),
            tls_client_certificate_bound_access_tokens: Some(
                self.tls_client_certificate_bound_access_tokens,
            ),
            authorization_details_types: Some(self.authorization_details_types),
            use_mtls_endpoint_aliases: Some(self.use_mtls_endpoint_aliases),
            userinfo_signed_response_alg: self.userinfo_signed_response_alg,
            backchannel_token_delivery_mode: self.backchannel_token_delivery_mode,
            backchannel_client_notification_endpoint: self.backchannel_client_notification_endpoint,
            // CIBA Core 1.0 §4's default is false, and the column is not null,
            // so a `false` here would be a member the document did not carry.
            // It is written back only when it is true, which is what makes the
            // round trip through `validate` exact for a client that is not a
            // CIBA client — that member is refused on one.
            backchannel_user_code_parameter: self.backchannel_user_code_parameter.then_some(true),
            backchannel_logout_uri: self.backchannel_logout_uri,
            backchannel_logout_session_required: Some(self.backchannel_logout_session_required),
            roles_in_id_token: Some(self.roles_in_id_token),
            ..ClientMetadata::default()
        };
        // RFC 8705 §2.1.2's subject, put back under the one member of the five
        // the row names. A field name the schema's check constraint permits but
        // this build does not know is dropped here, and the document then fails
        // "a tls_client_auth client registers exactly one" — which is the same
        // refusal an edited row gets everywhere else in this file, rather than
        // a client whose certificate is compared against nothing.
        if let (Some(field), Some(value)) =
            (&self.tls_client_auth_field, &self.tls_client_auth_value)
            && let Some(subject) = asterius_domain::TlsClientAuthSubject::from_field(field, value)
        {
            metadata.set_tls_client_auth_subject(&subject);
        }
        let mut registration = metadata.validate(capabilities).map_err(|error| {
            DomainError::invalid(
                "clients",
                format!("stored row is not a valid registration: {error}"),
            )
        })?;
        // Not part of the registration document: the per-client resource
        // allow-list is policy (`ast-m9c.6`), so it is restored from the column
        // rather than validated out of a document that never carried it.
        registration.resources = self.resources.iter().cloned().collect();
        // `ast-lh3.1`, restored the same way and for the same reason: an agent
        // profile is policy the tenant attached, not metadata the client sent.
        // After `resources`, because the profile's audience allow-list is
        // checked against them.
        //
        // The owner is taken from `agent_owner_user_id` and *not* from the
        // stored document, even though a document could carry one: the column
        // is what the foreign key and the disable-on-delete trigger act on, so
        // trusting the document instead would let a row whose owner had been
        // deleted keep naming them.
        registration.agent = Self::agent(&stored_agent, &registration)?;

        Ok(Client {
            tenant: tenant.clone(),
            id: ClientId::new(self.client_id),
            registration,
            status,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// The stored agent profile (`ast-lh3.1`), or `None` for a client that is
    /// not an agent.
    ///
    /// A row flagged `is_agent` with no owner is refused rather than loaded as
    /// an ordinary client: the schema makes that row disabled and unusable, and
    /// silently demoting it to a non-agent would hand back a client with an
    /// agent's grants and none of an agent's limits.
    fn agent(
        stored: &StoredAgent,
        registration: &ClientRegistration,
    ) -> Result<Option<asterius_domain::AgentProfile>, DomainError> {
        if !stored.is_agent {
            return Ok(None);
        }
        let owner = stored.owner.ok_or_else(|| {
            DomainError::invalid(
                "clients.agent_owner_user_id",
                "an agent whose owner has been deleted cannot be loaded",
            )
        })?;
        let limits = asterius_domain::AgentLimits::from_json(&stored.policy)
            .map_err(|error| DomainError::invalid("clients.agent_policy", error.to_string()))?;
        let profile = asterius_domain::AgentProfile::new(
            asterius_domain::AgentOwner::User(asterius_domain::UserId::new(owner)),
            limits,
        );
        // The registration the row rebuilt has to be one these limits permit.
        // A tenant that narrowed its agent profile after a client was
        // registered leaves rows the policy would refuse today, and the honest
        // answer for those is to refuse them now rather than at issuance.
        profile
            .limits()
            .check(registration)
            .map_err(|error| DomainError::invalid("clients", error.to_string()))?;
        Ok(Some(profile))
    }
}
