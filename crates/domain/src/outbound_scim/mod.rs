//! Candidate outbound SCIM contract; connector activation defaults to disabled.

mod administration;
mod lifecycle;
mod model;
mod peer;
mod ports;
mod protocol;
mod validation;

pub use model::{
    Assignment, Connector, CredentialBinding, DeliveryFence, FailureCode, GroupProjection,
    MappingReceipt, PreparedDelivery, Projection, ResourceKind, ReviewedDelete, UserProjection,
};
pub use ports::{OutboundScimCredentials, OutboundScimJobs};

pub use validation::{canonical_issuer, canonical_uuid, resource_identity};

pub use protocol::{
    GROUP_SCHEMA, MAX_RESPONSE_BYTES, RemoteDocument, USER_SCHEMA, parse_document, target_etag,
};

pub use administration::{
    AssignmentPreview, AssignmentView, ConfigureConnector, ConnectorPreview, ConnectorView,
    CredentialDescriptor, OutboundScimAdministration, OutboundScimCredentialCatalogue,
    OutboundScimInspection, PreviewSelection, SelectSources, parse_configure, parse_selection,
};

pub use peer::{
    INCARNATION_PROTECTION_SCHEMA, PeerToken, parse_peer_capabilities, parse_peer_token,
};

pub use lifecycle::{
    LifecycleCommand, LifecycleKind, LifecyclePreparation, LifecycleReceipt, LifecycleRequest,
    LifecycleView, OutboundScimLifecycle, PreparedLifecycle, parse_lifecycle,
};
