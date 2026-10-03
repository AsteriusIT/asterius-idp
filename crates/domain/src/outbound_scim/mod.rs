//! Inert source preparation for the proposed outbound SCIM contract.
//! The crate root intentionally does not export this module before review/checks.

mod model;
mod ports;

pub use model::{
    Assignment, Connector, CredentialBinding, DeliveryFence, FailureCode, GroupProjection,
    MappingReceipt, ResourceKind, ReviewedDelete, UserProjection,
};
pub use ports::{OutboundScimCredentials, OutboundScimJobs};
