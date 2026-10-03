//! PostgreSQL adapters.
//!
//! Implements the domain repository ports with `sqlx`. The organising idea is
//! that a query cannot be written without first choosing a tenant: everything
//! except [`PgTenantRepository`] hangs off [`TenantScope`], which carries the
//! tenant id and binds it into every statement. See
//! [ADR-0001](../../../docs/adr/0001-modular-monolith.md).
#![forbid(unsafe_code)]

mod access_reviews;
mod admin_seed;
mod agent_task_lifecycle;
mod agent_task_views;
pub mod agent_tasks;
pub use agent_task_views::PgAgentTaskViews;
mod aggregated_claims;
mod application_roles;
mod architecture_flows;
mod audit;
mod auth_requests;
mod authorization_details_types;
mod ciba_requests;
mod claims_provider_oauth;
mod client_key_fetches;
mod client_usage;
mod clients;
mod codes;
mod conditional;
mod cutoffs;
mod device_codes;
mod email_change;
mod email_verification;
mod error;
mod federation_keys;
mod grants;
mod groups;
mod id_jag_redemption;
mod initial_access_tokens;
mod invitations;
mod key_store;
mod keys;
mod ldap_sync;
mod native_sso;
mod notifications;
mod oid4vci_nonces;
mod oid4vp_transactions;
mod oidc_bindings;
mod oidc_providers;
mod oidc_upstream_pending;
mod outbox;
mod overview;
mod passkeys;
mod passwords;
mod policies;
mod provisioning;
mod rate_limits;
mod recovery;
mod refresh;
mod replay;
mod resource_servers;
mod retention;
mod rewrap;
mod roles;
mod salts;
mod saml_idp_keys;
mod saml_pending;
mod saml_trust;
mod scope;
mod sessions;
mod sql_audit;
mod ssf_poll;
mod ssf_receiver;
mod ssf_streams;
mod ssf_subjects;
mod ssf_upstream_streams;
mod store;
mod temporary_entitlements;
mod tenant_settings;
mod tenants;
mod themes;
mod totp;
pub use temporary_entitlements::PgTemporaryEntitlements;
mod users;
mod verified_claims;

pub use access_reviews::PgAccessReviews;
pub use admin_seed::{DeploymentAdmin, PgAdminSeed, Seeded};
pub use aggregated_claims::{PgAggregatedClaims, StoredClaimSource};
pub use application_roles::PgApplicationRoles;
pub use architecture_flows::{FlowApplyStep, FlowLinkIntent, PgArchitectureFlows};
pub use audit::{PgAuditSink, VerifiedChain};
pub use auth_requests::PgAuthRequestRepository;
pub use authorization_details_types::PgAuthorizationDetailsTypes;
pub use ciba_requests::{
    CibaPoll, CibaPolled, NewCibaRequest, PING_OUTBOX_KIND, PendingApproval,
    PgCibaRequestRepository, PingCredentials, PingTarget, RedeemedCiba,
};
pub use claims_provider_oauth::{CpConnection, CpConnectionSummary, CpPending, PgCpOAuth};
pub use client_key_fetches::PgClientKeyFetches;
pub use client_usage::PgClientUsage;
pub use clients::PgClientRepository;
pub use codes::{PgCodeRepository, Redemption};
pub use device_codes::{
    NewDeviceAuthorization, PendingDevice, PgDeviceCodeRepository, Poll, Polled, RedeemedDevice,
};
pub use email_change::{ConfirmedEmailChange, PgEmailChangeRequests};
pub use email_verification::PgEmailVerificationTokens;
pub use error::to_domain_error;
pub use federation_keys::{
    FederationKeyRecord, FederationKeySnapshot, PgFederationKeys, ROTATION_PERIOD,
};
pub use grants::{PgGrantRepository, Revocation};
pub use id_jag_redemption::{IdJagConsent, MAX_CONSENT_LIFETIME, PgIdJagRedemption};
pub use initial_access_tokens::PgInitialAccessTokens;
pub use invitations::{
    ActivatedInvitation, Invitation, InvitationPreview, MAX_INVITATION_LIFETIME, NewInvitation,
    PgInvitations,
};
pub use key_store::TenantKeyStore;
pub use keys::{PgKeyRepository, Rotation, RotationSchedule};
pub use ldap_sync::{
    LdapAbsencePolicy, LdapGroup, LdapSnapshot, LdapSyncOutcome, LdapUser, PgLdapSync,
};
pub use native_sso::{NativeSsoBinding, PgNativeSso};
pub use notifications::{PgOutboxMailSender, QueuedNotification};
pub use oid4vci_nonces::{NONCE_LIFETIME as OID4VCI_NONCE_LIFETIME, PgOid4vciNonces};
pub use oid4vp_transactions::{
    ConsumedOid4vpTransaction, NewOid4vpTransaction, Oid4vpTransactionResult, PgOid4vpTransactions,
    TRANSACTION_LIFETIME as OID4VP_TRANSACTION_LIFETIME,
};
pub use oidc_bindings::{OidcBinding, OidcRefusal, OidcResolution, PgOidcBindings};
pub use oidc_providers::{OidcProvider, OidcProviderCredential, PgOidcProviders};
pub use oidc_upstream_pending::{ConsumedOidcPending, NewOidcPending, PgOidcUpstreamPending};
pub use outbox::{
    Backoff, DEFAULT_LEASE, DEFAULT_MAX_ATTEMPTS, NewOutboxEntry, Outcome, PgOutbox, PgTransaction,
    Verdict, enqueue,
};
pub use overview::{Metric as OverviewMetric, PgOverview};
pub use passkeys::{PgPasskeyRepository, RemovedPasskey, RenamedPasskey};
pub use passwords::PgPasswordVerifier;
pub use policies::{PgPolicies, PolicyPublicationFence};
pub use provisioning::ProvisionedTenants;
pub use rate_limits::PgRateLimitStore;
pub use recovery::PgRecoveryTokens;
pub use refresh::{
    NewRefreshToken, PgRefreshTokenRepository, Presentation, RefreshBinding, RefreshTokenRecord,
};
pub use replay::PgReplayGuard;
pub use resource_servers::PgResourceServers;
pub use retention::{POLICY, PgRetention, Retention, Rule, Sweep, SweepOutcome};
pub use rewrap::{PgKekRewrap, Rewrap, RewrapOutcome};
pub use roles::PgRoleRepository;
pub use saml_idp_keys::{PgSamlIdpKeys, SamlIdpKeyMaterial, SamlIdpKeySummary};
pub use saml_pending::{ConsumedPendingSamlLogin, NewPendingSamlLogin, PgSamlPending};
pub use saml_trust::{PgSamlTrust, SamlSp};
pub use scope::TenantScope;
pub use sessions::PgSessionRepository;
pub use ssf_poll::{Discarded, Enqueued, PgSsfPoll, PollBatch, QueuedSet};
pub use ssf_receiver::{
    PgSsfReceiver, ReceiverAction, ReceiverNotificationPreparer, ReceiverNotifications,
    ReceiverOutcome, ReceiverPollSet, ReceiverSession, ReceiverSubjectReservation,
};
pub use ssf_streams::{
    DeliveryMethod, PgSsfStreams, PushTarget, SET_OUTBOX_KIND, StreamOverview, StreamStats,
    Subscription, VerificationClaim,
};
pub use ssf_subjects::{Added, MAX_SUBJECTS, PgSsfSubjects};
pub use ssf_upstream_streams::{PgSsfUpstreamStreams, UpstreamSetupIntent, UpstreamStream};
pub use store::{MIGRATOR, Store};
pub use tenant_settings::PgTenantSettings;
pub use tenants::PgTenantRepository;
pub use themes::PgThemes;
pub use totp::{PgTotpCredentials, TotpStatus};
pub use users::PgUserRepository;
pub use verified_claims::{PgVerifiedClaims, StoredVerifiedClaims};

pub use groups::PgGroups;

mod declarative;
mod declarative_clients;
mod declarative_tenants;
pub use declarative::PgDeclarative;
pub mod workload;
pub use workload::PgWorkloadTrusts;

pub use conditional::PgConditionalSettings;
