use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Builds a consistent error body. Clients classify errors by HTTP status;
/// this text is intended for humans and may change without notice.
pub fn error_body(error: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "error": error.into() })
}

/// Builds a rate-limit/backoff error response with a `Retry-After` header
/// (seconds), so a client can respect a concrete backoff instead of guessing.
pub fn retry_after_response(
    status: StatusCode,
    retry_after_secs: u64,
    error: impl Into<String>,
) -> Response {
    let mut response = (status, Json(error_body(error))).into_response();
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after_secs.to_string())
            .expect("a stringified non-negative integer is a valid header value"),
    );
    response
}

#[derive(Serialize, Deserialize)]
pub struct Info {
    pub secret_max_length: usize,
    pub canary: String,
    pub rate_limit_cooldown: u64,
    pub rate_limit_max_attempts: u8,
    /// Legacy alias for `rate_limit_max_attempts`; retained for compatibility.
    pub rate_limit_max_failed_attempts: u8,
    /// Hour-truncated start of the in-memory attempt collection (last server
    /// boot). Lets clients detect a telemetry wipe during their connection
    /// check without downloading the `/attempts` snapshot.
    pub attempts_collection_started_at: chrono::DateTime<chrono::Utc>,
    /// Configured capacity of the attempt map, so clients can compute the
    /// snapshot fullness ratio. Never a live count.
    pub max_attempt_identifiers: usize,
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CandidateState {
    Pending,
    Committed,
}

/// The already-derived `secret_id`/`key_id`; raw authentication material is
/// never retained in rate-limit state.
pub type CandidateTag = String;

#[derive(Clone)]
pub struct RateLimitInfo {
    pub window_started_at: chrono::DateTime<chrono::Utc>,
    pub last_candidate_at: chrono::DateTime<chrono::Utc>,
    pub last_request_at: chrono::DateTime<chrono::Utc>,
    pub candidates: HashMap<CandidateTag, CandidateState>,
    pub failed_candidates: u8,
    pub total_requests: u64,
}

impl RateLimitInfo {
    pub fn new(now: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            window_started_at: now,
            last_candidate_at: now,
            last_request_at: now,
            candidates: HashMap::new(),
            failed_candidates: 0,
            total_requests: 0,
        }
    }

    pub fn candidate_count(&self) -> u8 {
        self.candidates
            .len()
            .try_into()
            .expect("candidate map cannot exceed the configured u8 bound")
    }
}

/// Attempt counters reported to the caller of a successful `/fetch` or
/// `/trash`. This is a security signal, not an audit ledger: concurrent
/// requests may shift the counters by one.
#[derive(Clone, Serialize, Deserialize)]
pub struct AttemptStatus {
    /// The initial telemetry contract distinguishes candidate counters from
    /// request-counting semantics.
    pub version: u8,
    /// Total distinct candidates in the current window.
    pub total_attempts: u8,
    pub failed_attempts: u8,
    pub remaining_attempts: u8,
    pub total_requests: u64,
    pub window_started_at: chrono::DateTime<chrono::Utc>,
    /// Distinct candidate immediately preceding this request, if any.
    pub previous_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resets_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct ResponseFailedAttempt {
    pub error: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub rate_limit_cooldown: i64,
    pub attempts: u8,
    pub total_requests: u64,
}

#[derive(Serialize, Deserialize)]
pub struct AttemptEntry {
    /// SHA-256 of the raw identifier bytes, so clients can recognize their
    /// own identifier without exposing it (pre-image resistance).
    pub id_hash: String,
    /// Total distinct candidates in the current cooldown window.
    pub total_attempts: u8,
    pub failed_attempts: u8,
    pub total_requests: u64,
    /// Hour-truncated: exact timestamps would ease correlation.
    pub window_started_at: chrono::DateTime<chrono::Utc>,
    /// Compatibility field name; this is the hour-truncated last distinct
    /// candidate timestamp, never the timestamp of a replay request.
    pub last_attempt_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct AttemptsSnapshot {
    pub version: u8,
    /// Hour-truncated start of the in-memory collection. A changed value
    /// tells clients to reset their baseline after startup or global wipe.
    pub collection_started_at: chrono::DateTime<chrono::Utc>,
    pub entries: Vec<AttemptEntry>,
}
