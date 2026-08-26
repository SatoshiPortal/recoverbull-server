//! Recovery-domain orchestration between HTTP commands and storage operations.
//!
//! This layer owns validation, admission, leases, and outcome accounting; it
//! does not depend on Axum or Diesel.

pub(crate) mod identifiers;
pub(crate) mod service;
