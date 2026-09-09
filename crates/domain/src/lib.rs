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
pub use entities::auth_request::{CodeBinding, Consumed, InteractionRecord, PushedRequest};
pub use entities::passkey::{
    ASSERTION_TTL, ENROLMENT_TTL, Enrolment, NewPasskey, RegisteredPasskey,
};
pub use entities::password::{AcceptedPassword, Argon2Parameters, ParameterError, PasswordError};
pub use entities::session::{
    AuthenticationMethod, Lifetimes, Participant, Session, SessionRevocation, SessionStatus,
};
pub use entities::{
    ApplicationType, Claim, ClaimError, ClaimName, ClaimSet, ClaimSource, ClaimedGrant, Client,
    ClientMetadata, ClientMetadataError, ClientRegistration, ClientStatus, Grant, GrantError,
    GrantRecord, GrantStatus, GrantType, JwksSource, LiveAccessToken, PairwiseSalt, RedirectUri,
    RedirectUriError, RefreshPolicy, RefreshPolicyError, RevocationReason, Role, RoleScope,
    Rotation, SectorIdentifier, SubjectError, SubjectType, Tenant, TenantStatus, TokenBinding,
    TokenEndpointAuthMethod, User, UserId, UserRole, UserStatus,
};
pub use error::DomainError;
pub use ids::{ClientId, GrantId, SessionId, SubjectId, TenantId, TenantIdError};
pub use issuer::{Issuer, IssuerError};
pub use json_sentinel::{
    SERDE_JSON_SENTINELS, is_serde_json_sentinel, names_a_serde_json_sentinel, serde_json_sentinel,
};
pub use keys::{CompactJws, KeyState, KeyStore, Kid, PublicKeyRecord, Signer, SigningAlgorithm};
pub use ports::{
    AuthRequestRepository, ClientConfiguration, ClientRegistry, ClientRepository, CodeIssuer,
    CredentialVerifier, GrantRepository, InteractionRepository, ManagedClient, PasskeyRepository,
    ReplayCheck, ReplayGuard, ReplayPurpose, SessionRepository, SubjectResolver, UserDirectory,
};
pub use rate_limit::{
    Bucket, Decision as RateLimitDecision, EndpointLimit, EndpointLimits, LimitedEndpoint,
    LoginLimits, RateLimit, RateLimitStore, Scope as RateLimitScope, account_bucket,
    audited_once_bucket, endpoint_address_bucket, endpoint_client_bucket, ip_bucket,
};
pub use secret::{Secret, ct_eq};
