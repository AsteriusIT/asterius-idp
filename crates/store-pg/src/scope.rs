//! The tenant scope: the handle every tenant-scoped repository hangs off.

use crate::auth_requests::PgAuthRequestRepository;
use crate::authorization_details_types::PgAuthorizationDetailsTypes;
use crate::clients::PgClientRepository;
use crate::codes::PgCodeRepository;
use crate::grants::PgGrantRepository;
use crate::passkeys::PgPasskeyRepository;
use crate::refresh::PgRefreshTokenRepository;
use crate::resource_servers::PgResourceServers;
use crate::sessions::PgSessionRepository;
use crate::users::PgUserRepository;
use asterius_domain::ports::TenantScoped;
use asterius_domain::{Capabilities, TenantId};
use asterius_jose::Kek;
use sqlx::postgres::PgPool;
use std::sync::Arc;

/// Database access confined to one tenant.
///
/// Repositories for clients, users, sessions, grants and tokens are implemented
/// as methods on this type (each by its own story), and every one of them binds
/// [`TenantScope::tenant`] into its `WHERE` clause. The tenant is therefore not
/// an argument a caller can omit — it is a precondition of having the handle.
#[derive(Debug, Clone)]
pub struct TenantScope<'a> {
    pool: &'a PgPool,
    tenant: TenantId,
}

impl<'a> TenantScope<'a> {
    pub(crate) const fn new(pool: &'a PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// The client repository for this tenant.
    ///
    /// `capabilities` is what a stored client is re-validated against on the
    /// way out; see [`PgClientRepository::new`].
    #[must_use]
    pub fn clients(&self, capabilities: Capabilities) -> PgClientRepository {
        PgClientRepository::new(self.pool.clone(), self.tenant.clone(), capabilities)
    }

    /// The user repository for this tenant.
    ///
    /// `kek` is what opens the tenant's pairwise salt; see
    /// [`PgUserRepository::new`]. A user repository that could not reach the
    /// salt would be a user repository that cannot mint a `sub`, and minting
    /// one is not an optional part of having a user.
    #[must_use]
    pub fn users(&self, kek: Arc<dyn Kek>) -> PgUserRepository {
        PgUserRepository::new(self.pool.clone(), self.tenant.clone(), kek)
    }

    /// The authorization-code repository for this tenant.
    #[must_use]
    pub fn codes(&self) -> PgCodeRepository {
        PgCodeRepository::new(self.pool.clone(), self.tenant.clone())
    }

    /// The device-authorization repository for this tenant (RFC 8628).
    #[must_use]
    pub fn device_codes(&self) -> crate::PgDeviceCodeRepository {
        crate::PgDeviceCodeRepository::new(self.pool.clone(), self.tenant.clone())
    }

    /// The backchannel-authentication repository for this tenant (CIBA Core
    /// 1.0).
    #[must_use]
    pub fn ciba_requests(&self) -> crate::PgCibaRequestRepository {
        crate::PgCibaRequestRepository::new(self.pool.clone(), self.tenant.clone())
    }

    /// The refresh-token repository for this tenant.
    #[must_use]
    pub fn refresh_tokens(&self) -> PgRefreshTokenRepository {
        PgRefreshTokenRepository::new(self.pool.clone(), self.tenant.clone())
    }

    /// The session repository for this tenant.
    #[must_use]
    pub fn sessions(&self) -> PgSessionRepository {
        PgSessionRepository::new(self.pool.clone(), self.tenant.clone())
    }

    /// The pushed-authorization-request repository for this tenant.
    #[must_use]
    pub fn auth_requests(&self) -> PgAuthRequestRepository {
        PgAuthRequestRepository::new(self.pool.clone(), self.tenant.clone())
    }

    /// The resource-server registry for this tenant (RFC 8707, `ast-gxh.7`).
    ///
    /// Tenant-scoped like everything else here, and that is what makes a
    /// resource identifier meaningful *inside* a tenant: two tenants may front
    /// the same API, and neither may name the other's audiences.
    #[must_use]
    pub fn resource_servers(&self) -> PgResourceServers {
        PgResourceServers::new(self.pool.clone(), self.tenant.clone())
    }

    /// The application-role catalogues and assignments (`ast-095`).
    ///
    /// The port is deployment-wide and takes the tenant on every call, so this
    /// hands back the repository rather than a scoped one; the tenant this
    /// scope was built for is the one a caller passes. It is here so that the
    /// token endpoint reaches roles through the same seam as everything else
    /// it reads, over the same pool.
    #[must_use]
    pub fn application_roles(&self) -> crate::PgApplicationRoles {
        crate::PgApplicationRoles::new(self.pool.clone())
    }

    /// The authorization details type registry for this tenant (RFC 9396
    /// §2.1, `ast-gxh.6`).
    ///
    /// Tenant-scoped for the same reason the resource-server registry is: a
    /// `type` name means what the tenant that registered it says it means, and
    /// two tenants may register the same name for different things.
    #[must_use]
    pub fn authorization_details_types(&self) -> PgAuthorizationDetailsTypes {
        PgAuthorizationDetailsTypes::new(self.pool.clone(), self.tenant.clone())
    }

    /// The grant repository for this tenant.
    #[must_use]
    pub fn grants(&self) -> PgGrantRepository {
        PgGrantRepository::new(self.pool.clone(), self.tenant.clone())
    }

    /// The passkey repository for this tenant.
    ///
    /// Tenant-scoped like everything else here, and that is what makes
    /// credential-id uniqueness a tenant property rather than a global one:
    /// the unique index is over `(tenant_id, passkey_credential_id)`, and no
    /// query can reach a row outside the scope that found it.
    #[must_use]
    pub fn passkeys(&self) -> PgPasskeyRepository {
        PgPasskeyRepository::new(self.pool.clone(), self.tenant.clone())
    }

    /// The account-recovery tokens for this tenant (`ast-2vk.10`).
    #[must_use]
    pub fn recovery_tokens(&self) -> crate::PgRecoveryTokens {
        crate::PgRecoveryTokens::new(self.pool.clone(), self.tenant.clone())
    }

    /// This tenant's SSF streams (SSF 1.0 §8.1.1, `ast-0ju.3`).
    ///
    /// Tenant-scoped like everything else here, and the receiver is the *other*
    /// half of every statement it makes: see [`crate::PgSsfStreams`].
    #[must_use]
    pub fn ssf_streams(&self) -> crate::PgSsfStreams {
        crate::PgSsfStreams::new(self.pool.clone(), self.tenant.clone())
    }

    /// The journal mail sender for this tenant.
    ///
    /// Scoped like everything else, so an outbox row can never be written
    /// under a tenant other than the one the request resolved to.
    #[must_use]
    pub fn mail(&self) -> crate::PgOutboxMailSender {
        crate::PgOutboxMailSender::new(self.pool.clone(), self.tenant.clone())
    }
}

impl TenantScoped for TenantScope<'_> {
    fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}
