//! The tenant entity.

use crate::{Issuer, TenantId};
use time::OffsetDateTime;

/// A tenant. One tenant is one issuer, and one issuer is one tenant.
///
/// Deliberately not `#[non_exhaustive]`: adapters build entities from rows, so
/// sealing the struct would only push every adapter through a constructor that
/// takes the same fields in the same order, with less type checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    /// The tenant's identifier, as it appears in a path-based issuer.
    pub id: TenantId,
    /// The canonical issuer identifier.
    pub issuer: Issuer,
    /// The resource identifier an access token is audienced at when the grant
    /// names none of its own.
    ///
    /// RFC 9068 §3 requires one: an access token must carry an `aud`, and a
    /// grant that went through no `resource` parameter (RFC 8707 §2) has
    /// nothing to put there. Leaving it to the issuance code would mean
    /// inventing an audience at the moment a token is signed, which is how a
    /// deployment ends up with tokens every resource server accepts.
    ///
    /// Per tenant rather than per deployment, because `aud` is what a resource
    /// server compares to decide a token was meant for it, and two tenants
    /// sharing one identifier would give it nothing to tell them apart by
    /// except `iss`.
    pub default_resource: String,
    /// A vanity host that resolves to this tenant without a path prefix.
    pub custom_host: Option<String>,
    /// Human-readable name, shown on login and consent pages.
    pub display_name: String,
    /// Whether the tenant answers requests.
    pub status: TenantStatus,
    /// When the tenant was created.
    pub created_at: OffsetDateTime,
    /// When the tenant was last modified.
    pub updated_at: OffsetDateTime,
}

impl Tenant {
    /// Whether this tenant should answer protocol requests.
    ///
    /// A disabled tenant's endpoints behave as if the tenant does not exist,
    /// rather than returning a distinguishable error: an unauthenticated caller
    /// should not be able to enumerate which tenants have been suspended.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == TenantStatus::Active
    }
}

/// Whether a tenant answers requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    /// Serving.
    Active,
    /// Suspended; endpoints behave as if the tenant is not there.
    Disabled,
}

impl TenantStatus {
    /// The value as stored in the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}
