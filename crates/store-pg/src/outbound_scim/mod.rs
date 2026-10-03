//! Candidate scoped catalogue and delivery adapters. No network inside a transaction.

mod jobs;

pub use jobs::PgOutboundScimJobs;
