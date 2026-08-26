//! HTTP-boundary contracts and response helpers. Router, handlers, and this
//! module are the Axum boundary; domain modules do not know Axum.

pub(crate) mod contract;
pub(crate) mod error;
