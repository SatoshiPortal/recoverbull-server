//! Serde DTOs crossing the HTTP boundary.
//!
//! These shapes are compatibility contracts: request fields come from HTTP,
//! response fields are emitted to clients, and persisted `created_at` remains
//! a String rather than being reinterpreted as a server-side date type.

use crate::attempts::AttemptStatus;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
/// `/info` response contract, including retained legacy names.
pub(crate) struct Info {
    /// Maximum accepted encrypted payload length.
    pub(crate) secret_max_length: usize,
    /// Current warrant-canary value or the deliberate empty value.
    pub(crate) canary: String,
    /// Cooldown in minutes for the per-identifier `secret_id` budget.
    pub(crate) rate_limit_cooldown: u64,
    /// Maximum distinct secret_ids per identifier.
    pub(crate) rate_limit_max_attempts: u8,
    /// Legacy alias for `rate_limit_max_attempts`; retained for compatibility.
    pub(crate) rate_limit_max_failed_attempts: u8,
    /// Hour-truncated start of the current in-memory attempt collection. It is
    /// reset at startup and after the global wipe, letting clients detect that
    /// boundary without downloading the `/attempts` snapshot.
    pub(crate) attempts_collection_started_at: chrono::DateTime<chrono::Utc>,
    /// Configured capacity of the attempt map, so clients can compute the
    /// snapshot fullness ratio. Never a live count.
    pub(crate) max_attempt_identifiers: usize,
}

#[derive(Serialize, Deserialize)]
/// `/store` request DTO; all fields are supplied by the HTTP client.
pub(crate) struct StoreSecret {
    /// Client identifier encoded as 64 hexadecimal characters.
    pub(crate) identifier: String,
    /// Raw client authentication-key hash.
    pub(crate) authentication_key: String,
    /// Base64 encrypted secret payload.
    pub(crate) encrypted_secret: String,
}

#[derive(Serialize, Deserialize)]
/// Shared `/fetch` and `/trash` request DTO.
pub(crate) struct FetchSecret {
    /// Client identifier encoded as 64 hexadecimal characters.
    pub(crate) identifier: String,
    /// Raw client authentication-key hash.
    pub(crate) authentication_key: String,
}

#[derive(Serialize)]
/// Successful lookup response; `created_at` preserves storage's String format.
pub(crate) struct LookupSuccessResponse {
    /// Derived opaque secret identifier.
    pub(crate) id: String,
    /// Persisted creation timestamp kept as a compatibility String.
    pub(crate) created_at: String,
    /// Base64 encrypted secret payload.
    pub(crate) encrypted_secret: String,
    pub(crate) attempt_status: AttemptStatus,
}

#[derive(Serialize, Deserialize)]
/// Failed lookup response carrying retry and attempt telemetry.
pub(crate) struct ResponseFailedAttempt {
    pub(crate) error: String,
    pub(crate) requested_at: chrono::DateTime<chrono::Utc>,
    pub(crate) rate_limit_cooldown: i64,
    pub(crate) attempts: u8,
    pub(crate) total_requests: u64,
}
