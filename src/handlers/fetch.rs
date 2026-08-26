use crate::attempts::ledger::{Admission, LookupOutcome};
use crate::http::contract::LookupSuccessResponse;
use crate::http::{
    contract::{FetchSecret, ResponseFailedAttempt},
    error::{error_body, retry_after_response},
};
use crate::recovery::identifiers::{generate_secret_id, identifier_hash, is_256bits_hex_hash};
use crate::storage::sqlite::{
    establish_connection, read_and_trash_secret_by_id, read_secret_by_id,
};
use crate::AppState;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use serde_json::json;

const DATABASE_PERMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const GLOBAL_OVERLOAD_RETRY_AFTER_SECS: u64 = 1;

fn rate_limited(
    count: u8,
    last_candidate_at: chrono::DateTime<chrono::Utc>,
    requested_at: chrono::DateTime<chrono::Utc>,
    state: &AppState,
) -> Response {
    state.security_counters.lookup_target_lockout();
    let retry_after_secs = (last_candidate_at + state.rate_limit_cooldown - requested_at)
        .num_seconds()
        .max(1) as u64;
    let response = json!({
        "error": "Too many attempts",
        "requested_at": last_candidate_at,
        "rate_limit_cooldown": state.rate_limit_cooldown.num_minutes(),
        "attempts": count,
    });
    let mut http_response = (StatusCode::TOO_MANY_REQUESTS, Json(response)).into_response();
    http_response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        retry_after_secs
            .to_string()
            .parse()
            .expect("valid retry header"),
    );
    http_response
}

enum FinalizerError {
    Connection,
    Database,
    Join(tokio::task::JoinError),
}

pub async fn fetch_secret(
    State(state): State<AppState>,
    Json(request): Json<FetchSecret>,
    is_trashing_secret: bool,
) -> Response {
    let identifier = request.identifier.to_lowercase();
    let authentication_key = request.authentication_key.to_lowercase();
    if !is_256bits_hex_hash(&identifier) || !is_256bits_hex_hash(&authentication_key) {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_body(
                "identifier or authentication_key are not 256 bits HEX hashes",
            )),
        )
            .into_response();
    }
    let id_hash = identifier_hash(&identifier).expect("validated hex identifier");
    {
        let mut bucket = state.lookup_token_bucket.lock().await;
        if !bucket.try_consume() {
            state.security_counters.lookup_rate_limited();
            return retry_after_response(
                StatusCode::SERVICE_UNAVAILABLE,
                GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
                "Too many lookup requests, retry later",
            );
        }
    }
    let candidate = generate_secret_id(&identifier, &authentication_key);
    let requested_at = chrono::Utc::now();
    let admission = state
        .identifier_rate_limit
        .admit(
            id_hash.clone(),
            candidate.clone(),
            requested_at,
            state.rate_limit_max_attempts,
            state.rate_limit_max_identifiers,
            state.rate_limit_cooldown,
        )
        .await;
    if matches!(admission, Admission::Saturated { .. }) {
        state.security_counters.lookup_map_capacity();
        return retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
            "Rate-limit capacity exhausted, retry later",
        );
    }
    if let Admission::RateLimited {
        count,
        last_candidate_at,
    } = admission
    {
        return rate_limited(count, last_candidate_at, requested_at, &state);
    }
    if matches!(admission, Admission::Pending) {
        state.security_counters.lookup_rate_limited();
        return retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
            "Candidate lookup pending, retry later",
        );
    }
    let (attempt_status, generation, mut pending_guard) = match admission {
        Admission::New {
            status,
            generation,
            reservation,
        } => (status, generation, Some(reservation)),
        Admission::Replay { status, generation } => (status, generation, None),
        Admission::Pending => unreachable!("pending admission returned above"),
        Admission::Saturated { .. } => unreachable!("saturated admission returned above"),
        Admission::RateLimited { .. } => unreachable!("rate-limited admission returned above"),
    };
    let is_new = pending_guard.is_some();

    let permit = match tokio::time::timeout(
        DATABASE_PERMIT_TIMEOUT,
        state.database_semaphore.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) | Err(_) => {
            if let Some(guard) = pending_guard.as_mut() {
                // Disarm only after the async removal has completed. If this
                // handler is cancelled while waiting for the map lock, Drop
                // remains armed and performs the same idempotent cleanup.
                guard.refund().await;
            }
            state.security_counters.database_busy();
            return retry_after_response(
                StatusCode::SERVICE_UNAVAILABLE,
                GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
                "Database busy, retry later",
            );
        }
    };

    let database_url = state.database_url.clone();
    #[cfg(test)]
    let test_database_guard = state._test_database_guard.clone();
    let key_id = candidate.clone();
    let task_id_hash = id_hash.clone();
    let task_candidate = candidate.clone();
    let task_state = state.clone();
    let task = tokio::spawn(async move {
        let database_result = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            let _test_database_guard = test_database_guard;
            let _database_permit = permit;
            let mut connection =
                establish_connection(database_url).map_err(|_| FinalizerError::Connection)?;
            if is_trashing_secret {
                read_and_trash_secret_by_id(&mut connection, &key_id)
                    .map_err(|_| FinalizerError::Database)
            } else {
                read_secret_by_id(&mut connection, &key_id).map_err(|_| FinalizerError::Database)
            }
        })
        .await;
        let final_result = match database_result {
            Ok(result) => result,
            Err(error) => Err(FinalizerError::Join(error)),
        };
        if is_new {
            let outcome = match &final_result {
                Ok(Some(_)) => LookupOutcome::Hit,
                Ok(None) => LookupOutcome::Miss,
                Err(_) => LookupOutcome::Error,
            };
            task_state
                .identifier_rate_limit
                .finalize(&task_id_hash, &task_candidate, generation, outcome)
                .await;
        }
        // An accepted lookup is one whose database operation returned Ok,
        // regardless of whether it found a row. This accounting lives here so
        // it survives cancellation after the blocking work was transferred.
        match &final_result {
            Ok(Some(_)) => {
                task_state.security_counters.lookup_accepted();
                if is_trashing_secret {
                    task_state.security_counters.trash_hit();
                } else {
                    task_state.security_counters.fetch_hit();
                }
            }
            Ok(None) => {
                task_state.security_counters.lookup_accepted();
                if is_trashing_secret {
                    task_state.security_counters.trash_miss();
                } else {
                    task_state.security_counters.fetch_miss();
                }
            }
            Err(_) => task_state.security_counters.database_error(),
        }
        final_result
    });
    // The detached task now owns finalization and continues if this handler is
    // cancelled after the database work has been transferred to it.
    if let Some(guard) = pending_guard.as_mut() {
        guard.disarm();
    }

    let result = match task.await {
        Ok(result) => result,
        Err(_error) => {
            if is_new {
                state
                    .identifier_rate_limit
                    .refund(&id_hash, &candidate, generation)
                    .await;
            }
            state.security_counters.database_error();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("Internal server error")),
            )
                .into_response();
        }
    };
    let result = match result {
        Ok(result) => result,
        Err(FinalizerError::Connection) | Err(FinalizerError::Database) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("Internal server error")),
            )
                .into_response();
        }
        Err(FinalizerError::Join(_error)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("Internal server error")),
            )
                .into_response();
        }
    };

    match result {
        Some(key) => {
            let code = if is_trashing_secret {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            };
            let body = LookupSuccessResponse {
                id: key.id,
                created_at: key.created_at,
                encrypted_secret: key.encrypted_secret,
                attempt_status,
            };
            (code, Json(body)).into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(ResponseFailedAttempt {
                error: "Invalid identifier/authentication_key".to_owned(),
                requested_at,
                rate_limit_cooldown: state.rate_limit_cooldown.num_minutes(),
                attempts: attempt_status.total_attempts,
                total_requests: attempt_status.total_requests,
            }),
        )
            .into_response(),
    }
}
