//! Candidate outbound SCIM contract; connector activation defaults to disabled.

mod model;
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
