use crate::attempts::AttemptStatus;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct Info {
    pub(crate) secret_max_length: usize,
    pub(crate) canary: String,
    pub(crate) rate_limit_cooldown: u64,
    pub(crate) rate_limit_max_attempts: u8,
    /// Legacy alias for `rate_limit_max_attempts`; retained for compatibility.
    pub(crate) rate_limit_max_failed_attempts: u8,
    /// Hour-truncated start of the in-memory attempt collection (last server
    /// boot). Lets clients detect a telemetry wipe during their connection
    /// check without downloading the `/attempts` snapshot.
    pub(crate) attempts_collection_started_at: chrono::DateTime<chrono::Utc>,
    /// Configured capacity of the attempt map, so clients can compute the
    /// snapshot fullness ratio. Never a live count.
    pub(crate) max_attempt_identifiers: usize,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StoreSecret {
    pub(crate) identifier: String,
    pub(crate) authentication_key: String,
    pub(crate) encrypted_secret: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct FetchSecret {
    pub(crate) identifier: String,
    pub(crate) authentication_key: String,
}

#[derive(Serialize)]
pub(crate) struct LookupSuccessResponse {
    pub(crate) id: String,
    pub(crate) created_at: String,
    pub(crate) encrypted_secret: String,
    pub(crate) attempt_status: AttemptStatus,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ResponseFailedAttempt {
    pub(crate) error: String,
    pub(crate) requested_at: chrono::DateTime<chrono::Utc>,
    pub(crate) rate_limit_cooldown: i64,
    pub(crate) attempts: u8,
    pub(crate) total_requests: u64,
}
