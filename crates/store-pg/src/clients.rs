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

use crate::error::to_domain_error;
use asterius_domain::SigningAlgorithm;
use asterius_domain::ports::TenantScoped;
use asterius_domain::{
    Capabilities, Client, ClientId, ClientMetadata, ClientRegistration, ClientStatus, DomainError,
    JwksSource, ManagedClient, TenantId,
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

    async fn deprovision(&self, client_id: &ClientId) -> Result<(), DomainError> {
        Self::delete(self, client_id).await
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
                    grant_types, response_types, scopes, resources, jwks, jwks_uri,
                    id_token_signed_response_alg, application_type, subject_type, sector_identifier_uri,
                    request_object_signing_alg, backchannel_authentication_request_signing_alg,
                    dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens,
                    authorization_details_types, use_mtls_endpoint_aliases,
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
                    grant_types, response_types, scopes, resources, jwks, jwks_uri,
                    id_token_signed_response_alg, application_type, subject_type, sector_identifier_uri,
                    request_object_signing_alg, backchannel_authentication_request_signing_alg,
                    dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens,
                    authorization_details_types, use_mtls_endpoint_aliases,
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
        let (jwks, jwks_uri) = match &registration.jwks {
            JwksSource::Inline(value) => (Some(value.clone()), None),
            JwksSource::Uri(uri) => (None, Some(uri.clone())),
        };

        sqlx::query!(
            "insert into clients (tenant_id, client_id, client_name,
                                  token_endpoint_auth_method, redirect_uris, grant_types,
                                  response_types, scopes, resources, jwks, jwks_uri,
                                  id_token_signed_response_alg, application_type, subject_type,
                                  sector_identifier_uri, request_object_signing_alg,
                                  backchannel_authentication_request_signing_alg,
                                  dpop_bound_access_tokens,
                                  tls_client_certificate_bound_access_tokens,
                                  authorization_details_types, use_mtls_endpoint_aliases, status)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                     $18, $19, $20, $21, $22)
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
                 status = excluded.status",
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
            registration
                .request_object_signing_alg
                .map(SigningAlgorithm::as_str),
            registration
                .backchannel_authentication_request_signing_alg
                .map(SigningAlgorithm::as_str),
            registration.token_binding.is_dpop_bound(),
            registration.token_binding.is_certificate_bound(),
            &lists.authorization_details_types,
            registration.use_mtls_endpoint_aliases,
            client.status.as_str(),
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
        let (jwks, jwks_uri) = match &registration.jwks {
            JwksSource::Inline(value) => (Some(value.clone()), None),
            JwksSource::Uri(uri) => (None, Some(uri.clone())),
        };

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
                                  registration_access_token_hash)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                     $18, $19, $20, $21, $22, $23)
             returning client_id, client_name, token_endpoint_auth_method, redirect_uris,
                       grant_types, response_types, scopes, resources, jwks, jwks_uri,
                       id_token_signed_response_alg, application_type, subject_type,
                       sector_identifier_uri, request_object_signing_alg,
                       backchannel_authentication_request_signing_alg,
                       dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens,
                       authorization_details_types, use_mtls_endpoint_aliases,
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
            registration
                .request_object_signing_alg
                .map(SigningAlgorithm::as_str),
            registration
                .backchannel_authentication_request_signing_alg
                .map(SigningAlgorithm::as_str),
            registration.token_binding.is_dpop_bound(),
            registration.token_binding.is_certificate_bound(),
            &lists.authorization_details_types,
            registration.use_mtls_endpoint_aliases,
            client.status.as_str(),
            &registration_access_token[..],
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
            "select status, registration_access_token_hash
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
            Ok(ManagedClient {
                registration_access_token,
                status,
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
    /// which is policy — `ast-m9c.6`), `is_agent` / `agent_owner_sub` /
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
        let (jwks, jwks_uri) = match &registration.jwks {
            JwksSource::Inline(value) => (Some(value.clone()), None),
            JwksSource::Uri(uri) => (None, Some(uri.clone())),
        };

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
                 use_mtls_endpoint_aliases = $20
             where tenant_id = $1 and client_id = $2
             returning client_id, client_name, token_endpoint_auth_method, redirect_uris,
                       grant_types, response_types, scopes, resources, jwks, jwks_uri,
                       id_token_signed_response_alg, application_type, subject_type,
                       sector_identifier_uri, request_object_signing_alg,
                       backchannel_authentication_request_signing_alg,
                       dpop_bound_access_tokens, tls_client_certificate_bound_access_tokens,
                       authorization_details_types, use_mtls_endpoint_aliases,
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
            registration
                .request_object_signing_alg
                .map(SigningAlgorithm::as_str),
            registration
                .backchannel_authentication_request_signing_alg
                .map(SigningAlgorithm::as_str),
            registration.token_binding.is_dpop_bound(),
            registration.token_binding.is_certificate_bound(),
            &lists.authorization_details_types,
            registration.use_mtls_endpoint_aliases,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        .ok_or(DomainError::NotFound)?;

        row.into_entity(&self.tenant, self.capabilities)
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
    /// # Errors
    ///
    /// Returns [`DomainError::NotFound`] if no such client exists in this
    /// tenant, or a storage error.
    pub async fn delete(&self, client_id: &ClientId) -> Result<(), DomainError> {
        let result = sqlx::query!(
            "delete from clients where tenant_id = $1 and client_id = $2",
            self.tenant.as_str(),
            client_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }
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
struct Row {
    client_id: String,
    client_name: String,
    token_endpoint_auth_method: String,
    redirect_uris: Vec<String>,
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

        let metadata = ClientMetadata {
            client_name: Some(self.client_name),
            token_endpoint_auth_method: Some(self.token_endpoint_auth_method),
            redirect_uris: Some(self.redirect_uris),
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
            ..ClientMetadata::default()
        };
        let mut registration = metadata.validate(capabilities).map_err(|error| {
            DomainError::invalid(
                "clients",
                format!("stored row is not a valid registration: {error}"),
            )
        })?;
        // Not part of the registration document: the per-client resource
        // allow-list is policy (`ast-m9c.6`), so it is restored from the column
        // rather than validated out of a document that never carried it.
        registration.resources = self.resources.into_iter().collect();

        Ok(Client {
            tenant: tenant.clone(),
            id: ClientId::new(self.client_id),
            registration,
            status,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}
