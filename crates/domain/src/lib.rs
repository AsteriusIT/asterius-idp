//! Core entities and ports for Asterius.
//!
//! This crate is the centre of the hexagon: it owns the vocabulary of the
//! identity provider (tenants, clients, subjects, grants) and the *ports* —
//! traits — through which protocol code reaches the outside world. It must
//! never depend on a database driver, an HTTP framework or an async runtime.
#![forbid(unsafe_code)]

pub mod audit;
pub mod capabilities;
pub mod credentials;
pub mod entities;
pub mod error;
pub mod ids;
pub mod issuer;
pub mod json_sentinel;
pub mod keys;
pub mod ports;
pub mod rate_limit;
pub mod secret;
mod secret_audit;

pub use audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
pub use capabilities::{Capabilities, Feature};
pub use credentials::{OpaqueToken, sha256, sha256_hex};
/// The authentication contexts a tenant can produce (`ast-2vk.7`).
pub use entities::acr_policy as acr;
pub use entities::auth_request::{
    ClientRequest, CodeBinding, Consumed, Continuation, FirstPartyDestination, InteractionRecord,
    PushedRequest,
};
pub use entities::passkey::{
    ASSERTION_TTL, ENROLMENT_TTL, Enrolment, NewPasskey, RegisteredPasskey,
};
pub use entities::password::{AcceptedPassword, Argon2Parameters, ParameterError, PasswordError};
pub use entities::session::{
    AuthenticationMethod, Lifetimes, Participant, Session, SessionRevocation, SessionStatus,
};
pub use entities::{
    AcrLevel, AcrPolicy, AcrPolicyError, ApplicationType, AuthorizationDetail,
    AuthorizationDetails, AuthorizationDetailsRegistry, AuthorizationDetailsType, Claim,
    ClaimError, ClaimName, ClaimSet, ClaimSource, ClaimedGrant, Client, ClientMetadata,
    ClientMetadataError, ClientRegistration, ClientStatus, Grant, GrantAuthentication, GrantError,
    GrantRecord, GrantStatus, GrantType, InvalidAuthorizationDetails, InvalidTarget, JsonSchema,
    JsonSchemaError, JwksSource, LiveAccessToken, PairwiseSalt, RedirectUri, RedirectUriError,
    RefreshPolicy, RefreshPolicyError, ResourceIdentifier, ResourceRegistry, ResourceServer,
    RevocationReason, Role, RoleScope, Rotation, SectorIdentifier, SubjectError, SubjectType,
    Tenant, TenantSettings, TenantSettingsError, TenantStatus, TokenBinding,
    TokenEndpointAuthMethod, TokenLifetimes, User, UserId, UserRole, UserStatus,
};
pub use error::DomainError;
pub use ids::{ClientId, GrantId, SessionId, SubjectId, TenantId, TenantIdError};
pub use issuer::{Issuer, IssuerError};
pub use json_sentinel::{
    SERDE_JSON_SENTINELS, is_serde_json_sentinel, names_a_serde_json_sentinel, serde_json_sentinel,
};
pub use keys::{
    Activation, CompactJws, KeyAdministration, KeyRotation, KeyState, KeyStore, Kid,
    PublicKeyRecord, RotationSchedule, Signer, SigningAlgorithm,
};
pub use ports::{
    AuthRequestRepository, AuthorizationDetailsTypeRepository, ClientAdministration,
    ClientConfiguration, ClientRegistry, ClientRepository, CodeIssuer, CredentialVerifier,
    GrantRepository, InteractionRepository, ManagedClient, PasskeyRepository, ReplayCheck,
    ReplayGuard, ReplayPurpose, ResourceServerRepository, SessionRepository, SubjectResolver,
    TenantSettingsRepository, UserDirectory,
};
pub use rate_limit::{
    Bucket, Decision as RateLimitDecision, EndpointLimit, EndpointLimits, LimitedEndpoint,
    LoginLimits, RateLimit, RateLimitStore, Scope as RateLimitScope, account_bucket,
    admin_api_bucket, audited_once_bucket, endpoint_address_bucket, endpoint_client_bucket,
    ip_bucket,
};
pub use secret::{Secret, ct_eq};
