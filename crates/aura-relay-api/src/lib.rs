//! Stable HTTP/gRPC ingress façade for AURA Relay.
//!
//! The public wire/API surface is re-exported from this module while service
//! orchestration, authentication, persistence adapters, and typed errors remain
//! private implementation details.

mod service;

pub use service::*;
