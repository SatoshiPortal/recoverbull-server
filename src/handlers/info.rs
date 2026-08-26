use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::attempts::snapshot::truncate_to_hour;
use crate::http::contract::Info;
use crate::AppState;

pub async fn get_info(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    // The dotenv file is synchronously parsed on a blocking worker for every
    // request. Removal serves an empty canary (the compromise signal), while
    // an unavailable file falls back to startup. Process-env CANARY remains
    // authoritative and never reads the file.
    let canary = if state.canary_from_env {
        state.canary.clone()
    } else {
        let permit = match state.canary_read_semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return fallback_info(state).await,
        };
        let path = state.canary_path.clone();
        let file_state = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            crate::env::canary_file_state(&path)
        })
        .await
        .unwrap_or(crate::env::CanaryFileState::Unavailable);
        match file_state {
            crate::env::CanaryFileState::Value(value) => value,
            crate::env::CanaryFileState::Removed => String::new(),
            crate::env::CanaryFileState::Unavailable => {
                state.security_counters.canary_unavailable();
                state.canary.clone()
            }
        }
    };

    let info = &Info {
        canary,
        secret_max_length: state.secret_max_length,
        rate_limit_cooldown: state.rate_limit_cooldown.num_minutes() as u64,
        rate_limit_max_attempts: state.rate_limit_max_attempts,
        rate_limit_max_failed_attempts: state.rate_limit_max_attempts,
        attempts_collection_started_at: truncate_to_hour(
            state.attempts_snapshot.collection_started_at().await,
        ),
        max_attempt_identifiers: state.rate_limit_max_identifiers,
    };

    (StatusCode::OK, Json(json!(info)))
}

async fn fallback_info(state: AppState) -> (StatusCode, Json<Value>) {
    let info = Info {
        canary: state.canary,
        secret_max_length: state.secret_max_length,
        rate_limit_cooldown: state.rate_limit_cooldown.num_minutes() as u64,
        rate_limit_max_attempts: state.rate_limit_max_attempts,
        rate_limit_max_failed_attempts: state.rate_limit_max_attempts,
        attempts_collection_started_at: truncate_to_hour(
            state.attempts_snapshot.collection_started_at().await,
        ),
        max_attempt_identifiers: state.rate_limit_max_identifiers,
    };
    (StatusCode::OK, Json(json!(info)))
}
