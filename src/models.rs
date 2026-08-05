use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Info {
    pub secret_max_length: usize,
    pub canary: String,
    pub rate_limit_cooldown: u64,
    pub rate_limit_max_failed_attempts: u8,
}

#[derive(Serialize, Deserialize)]
pub struct StoreSecret {
    pub identifier: String,
    pub authentication_key: String,
    pub encrypted_secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct FetchSecret {
    pub identifier: String,
    pub authentication_key: String,
}

#[derive(Insertable, Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::secret)]
pub struct Secret {
    pub id: String,
    pub created_at: String,
    pub encrypted_secret: String,
}

#[derive(Clone)]
pub struct RateLimitInfo {
    /// First admitted attempt of the current window.
    pub window_started_at: chrono::DateTime<chrono::Utc>,
    pub last_request: chrono::DateTime<chrono::Utc>,
    /// All secret lookups count, including matches: an unauthenticated
    /// caller can create its own matching row through `/store`.
    pub attempts: u8,
    pub failed_attempts: u8,
}

/// Attempt counters reported to the caller of a successful `/fetch` or
/// `/trash`. This is a security signal, not an audit ledger: concurrent
/// requests may shift the counters by one.
#[derive(Serialize, Deserialize)]
pub struct AttemptStatus {
    /// Total lookups in the current window, including this request.
    pub total_attempts: u8,
    pub failed_attempts: u8,
    pub remaining_attempts: u8,
    pub window_started_at: chrono::DateTime<chrono::Utc>,
    /// Admitted attempt immediately preceding this request, if any.
    pub previous_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resets_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct ResponseFailedAttempt {
    pub error: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub rate_limit_cooldown: i64,
    pub attempts: u8,
}

#[derive(Serialize, Deserialize)]
pub struct AttemptEntry {
    /// SHA-256 of the raw identifier bytes, so clients can recognize their
    /// own identifier without exposing it (pre-image resistance).
    pub id_hash: String,
    /// Total `/fetch` and `/trash` lookups in the current cooldown window.
    pub total_attempts: u8,
    pub failed_attempts: u8,
    /// Hour-truncated: exact timestamps would ease correlation.
    pub window_started_at: chrono::DateTime<chrono::Utc>,
    pub last_attempt_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct AttemptsSnapshot {
    pub version: u8,
    /// Hour-truncated start of the in-memory collection (last server boot).
    /// A changed value tells clients to reset their baseline.
    pub collection_started_at: chrono::DateTime<chrono::Utc>,
    pub entries: Vec<AttemptEntry>,
}
