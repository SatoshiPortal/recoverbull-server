use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use serde_json::json;
use std::collections::HashMap;

use crate::database::{establish_connection, read_and_trash_secret_by_id, read_secret_by_id};
use crate::models::{
    error_body, retry_after_response, AttemptStatus, CandidateState, FetchSecret, RateLimitInfo,
    ResponseFailedAttempt,
};
use crate::utils::{generate_secret_id, identifier_hash, is_256bits_hex_hash};
use crate::AppState;

const DATABASE_PERMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const GLOBAL_OVERLOAD_RETRY_AFTER_SECS: u64 = 1;

fn remove_pending(
    map: &mut HashMap<String, RateLimitInfo>,
    id_hash: &str,
    candidate: &str,
    generation: chrono::DateTime<chrono::Utc>,
) {
    let remove_identifier = map.get_mut(id_hash).is_some_and(|info| {
        if info.window_started_at == generation
            && info.candidates.get(candidate) == Some(&CandidateState::Pending)
        {
            info.candidates.remove(candidate);
        }
        info.window_started_at == generation && info.candidates.is_empty()
    });
    if remove_identifier {
        map.remove(id_hash);
    }
}

async fn remove_pending_async(
    state: &AppState,
    id_hash: &str,
    candidate: &str,
    generation: chrono::DateTime<chrono::Utc>,
) {
    let mut map = state.identifier_rate_limit.lock().await;
    remove_pending(&mut map, id_hash, candidate, generation);
}

/// The generation check makes a delayed cancellation safe even if it outlives
/// the cooldown and a replacement window has already been created.
struct PendingGuard {
    state: AppState,
    id_hash: String,
    candidate: String,
    generation: chrono::DateTime<chrono::Utc>,
    armed: bool,
}

impl PendingGuard {
    fn new(
        state: AppState,
        id_hash: String,
        candidate: String,
        generation: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            state,
            id_hash,
            candidate,
            generation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let state = self.state.clone();
        let id_hash = std::mem::take(&mut self.id_hash);
        let candidate = std::mem::take(&mut self.candidate);
        let generation = self.generation;
        let removed_now = match state.identifier_rate_limit.try_lock() {
            Ok(mut map) => {
                remove_pending(&mut map, &id_hash, &candidate, generation);
                true
            }
            Err(_) => false,
        };
        if !removed_now {
            tokio::spawn(async move {
                remove_pending_async(&state, &id_hash, &candidate, generation).await;
            });
        }
    }
}

fn attempt_status(
    info: &RateLimitInfo,
    max: u8,
    previous: Option<chrono::DateTime<chrono::Utc>>,
    cooldown: chrono::TimeDelta,
) -> AttemptStatus {
    let count = info.candidate_count();
    AttemptStatus {
        version: 1,
        total_attempts: count,
        failed_attempts: info.failed_candidates,
        remaining_attempts: max.saturating_sub(count),
        total_requests: info.total_requests,
        window_started_at: info.window_started_at,
        previous_attempt_at: previous,
        resets_at: info.last_candidate_at + cooldown,
    }
}

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

enum Admission {
    New(AttemptStatus, chrono::DateTime<chrono::Utc>),
    Replay(AttemptStatus, chrono::DateTime<chrono::Utc>),
    Pending,
}

enum FinalizerError {
    Database(diesel::result::Error),
    Join(tokio::task::JoinError),
}

async fn finalize(
    state: &AppState,
    id_hash: &str,
    candidate: &str,
    generation: chrono::DateTime<chrono::Utc>,
    result: &Result<Option<crate::models::Secret>, FinalizerError>,
) {
    let mut map = state.identifier_rate_limit.lock().await;
    let remove_identifier = {
        let Some(info) = map.get_mut(id_hash) else {
            return;
        };
        if info.window_started_at != generation
            || info.candidates.get(candidate) != Some(&CandidateState::Pending)
        {
            return;
        }
        match result {
            Ok(Some(_)) => {
                info.candidates
                    .insert(candidate.to_owned(), CandidateState::Committed);
                false
            }
            Ok(None) => {
                info.candidates
                    .insert(candidate.to_owned(), CandidateState::Committed);
                info.failed_candidates = info.failed_candidates.saturating_add(1);
                false
            }
            Err(_) => {
                info.candidates.remove(candidate);
                info.candidates.is_empty()
            }
        }
    };
    // Candidate removal and empty-entry removal are one atomic map update.
    // Releasing this lock between the two would let an older finalizer delete
    // a fresh reservation created in the same window.
    if remove_identifier {
        map.remove(id_hash);
    }
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
    let admission = {
        let mut map = state.identifier_rate_limit.lock().await;
        if map.get(&id_hash).is_some_and(|info| {
            requested_at.signed_duration_since(info.last_candidate_at) > state.rate_limit_cooldown
        }) {
            map.remove(&id_hash);
        }
        if !map.contains_key(&id_hash) && map.len() >= state.rate_limit_max_identifiers {
            map.retain(|_, info| {
                requested_at.signed_duration_since(info.last_candidate_at)
                    <= state.rate_limit_cooldown
            });
            if map.len() >= state.rate_limit_max_identifiers {
                state.security_counters.lookup_map_capacity();
                return retry_after_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
                    "Rate-limit capacity exhausted, retry later",
                );
            }
        }
        let info = map
            .entry(id_hash.clone())
            .or_insert_with(|| RateLimitInfo::new(requested_at));
        info.total_requests = info.total_requests.saturating_add(1);
        info.last_request_at = requested_at;
        // This check intentionally precedes membership, including for known
        // candidates, so saturation cannot become an authentication oracle.
        if info.candidate_count() >= state.rate_limit_max_attempts {
            return rate_limited(
                info.candidate_count(),
                info.last_candidate_at,
                requested_at,
                &state,
            );
        }
        match info.candidates.get(&candidate).copied() {
            Some(CandidateState::Pending) => Admission::Pending,
            Some(CandidateState::Committed) => Admission::Replay(
                attempt_status(
                    info,
                    state.rate_limit_max_attempts,
                    None,
                    state.rate_limit_cooldown,
                ),
                info.window_started_at,
            ),
            None => {
                let previous = (info.candidate_count() > 0).then_some(info.last_candidate_at);
                info.candidates
                    .insert(candidate.clone(), CandidateState::Pending);
                info.last_candidate_at = requested_at;
                Admission::New(
                    attempt_status(
                        info,
                        state.rate_limit_max_attempts,
                        previous,
                        state.rate_limit_cooldown,
                    ),
                    info.window_started_at,
                )
            }
        }
    };
    if matches!(admission, Admission::Pending) {
        state.security_counters.lookup_rate_limited();
        return retry_after_response(
            StatusCode::SERVICE_UNAVAILABLE,
            GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
            "Candidate lookup pending, retry later",
        );
    }
    let (attempt_status, generation, is_new) = match admission {
        Admission::New(status, generation) => (status, generation, true),
        Admission::Replay(status, generation) => (status, generation, false),
        Admission::Pending => unreachable!("pending admission returned above"),
    };
    let mut pending_guard = is_new.then(|| {
        PendingGuard::new(
            state.clone(),
            id_hash.clone(),
            candidate.clone(),
            generation,
        )
    });

    let permit = match tokio::time::timeout(
        DATABASE_PERMIT_TIMEOUT,
        state.database_semaphore.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) | Err(_) => {
            if let Some(guard) = pending_guard.as_mut() {
                remove_pending_async(&state, &id_hash, &candidate, generation).await;
                // Disarm only after the async removal has completed. If this
                // handler is cancelled while waiting for the map lock, Drop
                // remains armed and performs the same idempotent cleanup.
                guard.disarm();
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
            let mut connection = establish_connection(database_url);
            if is_trashing_secret {
                read_and_trash_secret_by_id(&mut connection, &key_id)
            } else {
                read_secret_by_id(&mut connection, &key_id)
            }
        })
        .await;
        let final_result = match database_result {
            Ok(result) => result.map_err(FinalizerError::Database),
            Err(error) => Err(FinalizerError::Join(error)),
        };
        if is_new {
            finalize(
                &task_state,
                &task_id_hash,
                &task_candidate,
                generation,
                &final_result,
            )
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
                remove_pending_async(&state, &id_hash, &candidate, generation).await;
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
        Err(FinalizerError::Database(_error)) => {
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
            let mut body = serde_json::to_value(key).expect("secret is serializable");
            body["attempt_status"] = json!(attempt_status);
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
