use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

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
    pub last_request: chrono::DateTime<chrono::Utc>,
    /// All secret lookups count, including matches: an unauthenticated
    /// caller can create its own matching row through `/store`.
    pub attempts: u8,
    pub failed_attempts: u8,
}

#[derive(Serialize, Deserialize)]
pub struct ResponseFailedAttempt {
    pub error: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub rate_limit_cooldown: i64,
    pub attempts: u8,
}
