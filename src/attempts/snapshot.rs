//! Serialized attempt snapshot values and their public timestamp precision.

use chrono::DurationRound;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct AttemptEntry {
    /// SHA-256 of the raw identifier bytes, so clients can recognize their
    /// own identifier without exposing it (pre-image resistance).
    pub(crate) id_hash: String,
    /// Total distinct candidates in the current cooldown window.
    pub(crate) total_attempts: u8,
    pub(crate) failed_attempts: u8,
    pub(crate) total_requests: u64,
    /// Hour-truncated: exact timestamps would ease correlation.
    pub(crate) window_started_at: chrono::DateTime<chrono::Utc>,
    /// Compatibility field name; this is the hour-truncated last distinct
    /// candidate timestamp, never the timestamp of a replay request.
    pub(crate) last_attempt_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AttemptsSnapshot {
    pub(crate) version: u8,
    /// Hour-truncated start of the in-memory collection. A changed value
    /// tells clients to reset their baseline after startup or global wipe.
    pub(crate) collection_started_at: chrono::DateTime<chrono::Utc>,
    pub(crate) entries: Vec<AttemptEntry>,
}

pub(crate) fn truncate_to_hour(
    timestamp: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    timestamp
        .duration_trunc(chrono::Duration::hours(1))
        .expect("hour truncation of a valid timestamp")
}
