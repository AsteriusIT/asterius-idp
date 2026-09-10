//! Entities: the things Asterius stores and reasons about.

pub mod acr_policy;
pub mod admin_access;
pub mod auth_request;
pub mod authorization_details;
pub mod client;
pub mod grant;
pub mod passkey;
pub mod password;
pub mod resource_server;
pub mod role;
pub mod session;
pub mod tenant;
pub mod tenant_settings;
pub mod user;

pub use acr_policy::{AcrLevel, AcrPolicy, AcrPolicyError};
pub use admin_access::{AdminAdmission, PasskeyEnrolment};
pub use authorization_details::{
    AuthorizationDetail, AuthorizationDetails, AuthorizationDetailsRegistry,
    AuthorizationDetailsType, InvalidAuthorizationDetails, Schema as JsonSchema,
    SchemaError as JsonSchemaError,
};
pub use client::{
    ApplicationType, Client, ClientMetadata, ClientMetadataError, ClientRegistration, ClientStatus,
    GrantType, JwksSource, RedirectUri, RedirectUriError, SubjectType, TokenBinding,
    TokenEndpointAuthMethod,
};
pub use grant::{
    ClaimedGrant, Grant, GrantAuthentication, GrantError, GrantRecord, GrantStatus,
    LiveAccessToken, RevocationReason,
};
pub use resource_server::{InvalidTarget, ResourceIdentifier, ResourceRegistry, ResourceServer};
pub use role::{Role, RoleScope, UserRole};
pub use tenant::{RefreshPolicy, RefreshPolicyError, Rotation, Tenant, TenantStatus};
pub use tenant_settings::{TenantSettings, TenantSettingsError, TokenLifetimes};
pub use user::{
    Claim, ClaimError, ClaimName, ClaimSet, ClaimSource, PairwiseSalt, SectorIdentifier,
    SubjectError, User, UserId, UserStatus,
};
