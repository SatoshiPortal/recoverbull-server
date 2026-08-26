//! Attempt-domain values shared by lookup admission and telemetry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AttemptStatus {
    /// The initial telemetry contract distinguishes candidate counters from
    /// request-counting semantics.
    pub(crate) version: u8,
    /// Total distinct candidates in the current window.
    pub(crate) total_attempts: u8,
    pub(crate) failed_attempts: u8,
    pub(crate) remaining_attempts: u8,
    pub(crate) total_requests: u64,
    pub(crate) window_started_at: DateTime<Utc>,
    /// Distinct candidate immediately preceding this request, if any.
    pub(crate) previous_attempt_at: Option<DateTime<Utc>>,
    pub(crate) resets_at: DateTime<Utc>,
}

pub(crate) mod ledger;
pub(crate) mod snapshot;
