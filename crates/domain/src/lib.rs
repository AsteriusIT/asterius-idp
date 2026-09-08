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
pub mod keys;
pub mod ports;
pub mod secret;
mod secret_audit;

pub use audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
pub use capabilities::{Capabilities, Feature};
pub use credentials::{OpaqueToken, sha256, sha256_hex};
pub use entities::auth_request::{Consumed, PushedRequest};
pub use entities::{
    ApplicationType, Claim, ClaimError, ClaimName, ClaimSet, ClaimSource, ClaimedGrant, Client,
    ClientMetadata, ClientMetadataError, ClientRegistration, ClientStatus, Grant, GrantError,
    GrantRecord, GrantStatus, GrantType, JwksSource, LiveAccessToken, PairwiseSalt, RedirectUri,
    RedirectUriError, RevocationReason, SectorIdentifier, SubjectError, SubjectType, Tenant,
    TenantStatus, TokenBinding, TokenEndpointAuthMethod, User, UserId, UserStatus,
};
pub use error::DomainError;
pub use ids::{ClientId, GrantId, SessionId, SubjectId, TenantId, TenantIdError};
pub use issuer::{Issuer, IssuerError};
pub use keys::{CompactJws, KeyState, KeyStore, Kid, PublicKeyRecord, Signer, SigningAlgorithm};
pub use ports::{AuthRequestRepository, ClientRepository, ReplayCheck, ReplayGuard, ReplayPurpose};
pub use secret::{Secret, ct_eq};
