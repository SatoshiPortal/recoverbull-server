use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use serde_json::json;

use crate::http::contract::{FetchSecret, LookupSuccessResponse, ResponseFailedAttempt};
use crate::http::error::retry_after_response;
use crate::recovery::service::{LookupCommand, LookupKind, LookupResult};
use crate::AppState;

const GLOBAL_OVERLOAD_RETRY_AFTER_SECS: u64 = 1;

pub async fn fetch_secret(
    State(state): State<AppState>,
    Json(request): Json<FetchSecret>,
) -> Response {
    map_lookup(
        state
            .recovery_service
            .lookup(
                LookupCommand {
                    identifier: request.identifier,
                    authentication_key: request.authentication_key,
                },
                LookupKind::Fetch,
            )
            .await,
        LookupKind::Fetch,
    )
}

pub async fn trash_secret(
    State(state): State<AppState>,
    Json(request): Json<FetchSecret>,
) -> Response {
    map_lookup(
        state
            .recovery_service
            .lookup(
                LookupCommand {
                    identifier: request.identifier,
                    authentication_key: request.authentication_key,
                },
                LookupKind::Trash,
            )
            .await,
        LookupKind::Trash,
    )
}

fn map_lookup(result: LookupResult, kind: LookupKind) -> Response {
    match result {
        LookupResult::Invalid => (
            StatusCode::BAD_REQUEST,
            Json(crate::http::error::error_body(
                "identifier or authentication_key are not 256 bits HEX hashes",
            )),
        )
            .into_response(),
        LookupResult::GlobalOverload => retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
            "Too many lookup requests, retry later",
        ),
        LookupResult::Capacity => retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
            "Rate-limit capacity exhausted, retry later",
        ),
        LookupResult::Pending => retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
            "Candidate lookup pending, retry later",
        ),
        LookupResult::DatabaseBusy => retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
            "Database busy, retry later",
        ),
        LookupResult::RateLimited {
            count,
            requested_at,
            retry_after_secs,
            cooldown_minutes,
        } => {
            let body = json!({
                "error": "Too many attempts",
                "requested_at": requested_at,
                "rate_limit_cooldown": cooldown_minutes,
                "attempts": count,
            });
            let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                retry_after_secs
                    .to_string()
                    .parse()
                    .expect("valid retry header"),
            );
            response
        }
        LookupResult::DatabaseError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(crate::http::error::error_body("Internal server error")),
        )
            .into_response(),
        LookupResult::Completed {
            secret,
            attempt_status,
            requested_at,
            cooldown_minutes,
        } => match secret {
            Some(secret) => {
                let status = if matches!(kind, LookupKind::Trash) {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::OK
                };
                (
                    status,
                    Json(LookupSuccessResponse {
                        id: secret.id,
                        created_at: secret.created_at,
                        encrypted_secret: secret.encrypted_secret,
                        attempt_status,
                    }),
                )
                    .into_response()
            }
            None => (
                StatusCode::UNAUTHORIZED,
                Json(ResponseFailedAttempt {
                    error: "Invalid identifier/authentication_key".to_owned(),
                    requested_at,
                    rate_limit_cooldown: cooldown_minutes,
                    attempts: attempt_status.total_attempts,
                    total_requests: attempt_status.total_requests,
                }),
            )
                .into_response(),
        },
    }
}
