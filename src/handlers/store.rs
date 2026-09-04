//! `/store` request extraction and response mapping.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use serde_json::Value;

use crate::app::AppState;
use crate::http::{contract::StoreSecret, error::retry_after_response};
use crate::recovery::service::{StoreCommand, StoreResult};

/// Advisory backoff for pressure that has no deadline to derive (a busy
/// database): "try again shortly". Bucket refusals carry their own estimate.
const DATABASE_BUSY_RETRY_AFTER_SECS: u64 = 1;

/// Accepts and stores an encrypted secret through the recovery service.
pub async fn store_secret(
    State(state): State<AppState>,
    Json(request): Json<StoreSecret>,
) -> Response {
    match state
        .recovery_service()
        .store(StoreCommand {
            identifier: request.identifier,
            authentication_key: request.authentication_key,
            encrypted_secret: request.encrypted_secret,
        })
        .await
    {
        StoreResult::Stored => (StatusCode::CREATED, Json(Value::Null)).into_response(),
        StoreResult::Invalid(error) => (
            StatusCode::BAD_REQUEST,
            Json(crate::http::error::error_body(error)),
        )
            .into_response(),
        StoreResult::GlobalOverload { retry_after_secs } => retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            retry_after_secs,
            "Too many store requests, retry later",
        ),
        StoreResult::DatabaseBusy => retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            DATABASE_BUSY_RETRY_AFTER_SECS,
            "Database busy, retry later",
        ),
        StoreResult::DatabaseError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(crate::http::error::error_body("Internal server error")),
        )
            .into_response(),
    }
}
