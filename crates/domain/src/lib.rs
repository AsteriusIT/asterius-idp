//! Core entities and ports for Asterius.
//!
//! This crate is the centre of the hexagon: it owns the vocabulary of the
//! identity provider (tenants, clients, subjects, grants) and the *ports* —
//! traits — through which protocol code reaches the outside world. It must
//! never depend on a database driver, an HTTP framework or an async runtime.
#![forbid(unsafe_code)]

pub mod administration;
pub mod audit;
pub mod capabilities;
pub mod credentials;
pub mod entities;
pub mod error;
pub mod ids;
pub mod issuer;
pub mod json_sentinel;
pub mod keys;
pub mod limits;
pub mod locale;
pub mod messages;
pub mod notification;
pub mod outbox;
pub mod ports;
pub mod rate_limit;
pub mod secret;
mod secret_audit;

pub use administration::{
    CredentialSummary, NewAccount, PasskeySummary, PasswordReset, SessionSummary, Terminated,
    UserAdministration,
};
pub use audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
pub use capabilities::{Capabilities, Feature};
pub use credentials::{OpaqueToken, sha256, sha256_hex};
/// The authentication contexts a tenant can produce (`ast-2vk.7`).
pub use entities::acr_policy as acr;
/// Whether an administrative session proved enough to act (`ast-895`).
pub use entities::admin_access as admin_access_policy;
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
    AGENT_GRANT_TYPES, AcceptedRegistration, AcrLevel, AcrPolicy, AcrPolicyError, AdminAdmission,
    AgentLimits, AgentOwner, AgentProfile, AgentProfileError, ApplicationRole,
    ApplicationRoleError, ApplicationType, AuthorizationDetail, AuthorizationDetails,
    AuthorizationDetailsRegistry, AuthorizationDetailsType, Claim, ClaimError, ClaimName, ClaimSet,
    ClaimSource, ClaimedGrant, Client, ClientMetadata, ClientMetadataError, ClientRegistration,
    ClientStatus, DEFAULT_MAX_DELEGATION_DEPTH, EMAIL_VERIFICATION_LIFETIME,
    EMAIL_VERIFICATION_TOKEN_BITS, EmailVerificationToken, EmailVerificationTokenError, Grant,
    GrantAuthentication, GrantError, GrantRecord, GrantStatus, GrantType, HeldRoles,
    InitialAccessToken, InitialAccessTokenReservation, InvalidAuthorizationDetails, InvalidTarget,
    IssuedEmailVerification, IssuedRecovery, JsonSchema, JsonSchemaError, JwksRequirement,
    JwksSource, LiveAccessToken, MAX_DELEGATION_DEPTH, MAX_DISPLAY_NAME_LENGTH,
    MAX_INITIAL_ACCESS_TOKEN_LABEL_LEN, MAX_REGISTRATION_EMAIL_LENGTH,
    MAX_REGISTRATION_USERNAME_LENGTH, MAX_ROLE_DESCRIPTION_LEN, NewInitialAccessToken,
    PairwiseSalt, PasskeyEnrolment, PolicyViolation, RECOVERY_LIFETIME, RECOVERY_TOKEN_BITS,
    RecoveryToken, RecoveryTokenError, RedirectUri, RedirectUriError, RefreshPolicy,
    RefreshPolicyError, RegistrationError, RegistrationMode, RegistrationPolicy,
    RegistrationPolicyError, ResourceIdentifier, ResourceRegistry, ResourceServer,
    RevocationReason, Role, RoleAssignment, RoleClaim, RoleName, RoleNameError, RoleOwner,
    RoleScope, RolesInIdToken, Rotation, RuleId, SectorIdentifier, SoftwareStatementIssuer,
    SoftwareStatementRule, SubjectError, SubjectType, Tenant, TenantIcon, TenantSettings,
    TenantSettingsError, TenantStatus, Theme, ThemeError, TlsClientAuthSubject, TokenBinding,
    TokenDeliveryMode, TokenEndpointAuthMethod, TokenLifetimes, User, UserId, UserRole, UserStatus,
    VerifiedAddress,
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
pub use limits::MAX_JWT_BYTES;
pub use locale::{Locale, UiLocales, negotiate};
pub use messages::{MessageOverrideError, MessageOverrides};
pub use notification::{MailSender, Notification, NotificationKind};
pub use outbox::{DeadLetter, DeadLetterOperations, DeadLetterQuery, OutboxEvent};
pub use ports::{
    ApplicationRoleDirectory, AuthRequestRepository, AuthorizationDetailsTypeRepository,
    ClientAdministration, ClientConfiguration, ClientRegistry, ClientRepository,
    ClientUsageRecorder, CodeIssuer, CredentialVerifier, EmailVerificationStore, GrantAmendments,
    GrantRepository, InitialAccessTokenStore, InteractionRepository, ManagedClient,
    PasskeyRepository, PreviousRegistrationAccessToken, RecoveryTokenStore, ReplayCheck,
    ReplayGuard, ReplayPurpose, ResourceServerRepository, SessionRepository, SubjectResolver,
    TenantSettingsRepository, UserDirectory,
};
pub use rate_limit::{
    Bucket, Decision as RateLimitDecision, EndpointLimit, EndpointLimits, LimitedEndpoint,
    LoginLimits, RateLimit, RateLimitStore, Scope as RateLimitScope, account_bucket,
    admin_api_bucket, approval_decision_bucket, audited_once_bucket, endpoint_address_bucket,
    endpoint_client_bucket, endpoint_subject_bucket, ip_bucket,
};
pub use secret::{Secret, ct_eq};
