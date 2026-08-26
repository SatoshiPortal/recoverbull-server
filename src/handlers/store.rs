use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use serde_json::Value;

use crate::app::AppState;
use crate::http::{contract::StoreSecret, error::retry_after_response};
use crate::recovery::service::{StoreCommand, StoreResult};

const GLOBAL_OVERLOAD_RETRY_AFTER_SECS: u64 = 1;

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
        StoreResult::GlobalOverload => retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
            "Too many store requests, retry later",
        ),
        StoreResult::DatabaseBusy => retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
            "Database busy, retry later",
        ),
        StoreResult::DatabaseError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(crate::http::error::error_body("Internal server error")),
        )
            .into_response(),
    }
}
