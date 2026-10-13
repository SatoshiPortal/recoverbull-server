//! `/store` request extraction and response mapping.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use serde_json::Value;

use crate::app::AppState;
use crate::http::{contract::StoreSecret, error::retry_after_response};
use crate::recovery::service::{StoreCommand, StoreResult};

/// Storage pressure clears only when an operator intervenes, so a client
/// gains nothing by retrying every second.
const STORAGE_PRESSURE_RETRY_AFTER_SECS: u64 = 60;

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
            crate::rate_limit::ADVISORY_RETRY_AFTER_SECS,
            "Database busy, retry later",
        ),
        StoreResult::StoragePressure => retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            STORAGE_PRESSURE_RETRY_AFTER_SECS,
            "Storage unavailable, retry later",
        ),
        StoreResult::DatabaseError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(crate::http::error::error_body("Internal server error")),
        )
            .into_response(),
    }
}
