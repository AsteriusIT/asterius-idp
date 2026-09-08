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
    JwksSource, TenantId,
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

    /// Deletes a client and, by cascade, its grants, tokens and pushed
    /// requests.
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
            // disagree is a row that fails to load.
            response_types: if registration
                .grant_types
                .iter()
                .any(|grant| grant.uses_the_authorization_endpoint())
            {
                ClientRegistration::RESPONSE_TYPES
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect()
            } else {
                Vec::new()
            },
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
