use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::models::Info;
use crate::utils::truncate_to_hour;
use crate::AppState;

pub async fn get_info(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    // The warrant canary is re-read from the dotenv file on each request so
    // an operator can update or remove it without restarting the server
    // (env::var alone would never see the edit: dotenvy loads the file only
    // at startup). A deliberate removal must serve an empty canary — that IS
    // the compromise signal clients watch for — while an unreadable file is
    // an ops error and falls back to the startup value to avoid a false
    // alarm. An environment-provided canary is authoritative: signaling then
    // requires a restart with a changed value.
    let canary = if state.canary_from_env {
        state.canary.clone()
    } else {
        match crate::env::canary_file_state(&state.canary_path) {
            crate::env::CanaryFileState::Value(value) => value,
            crate::env::CanaryFileState::Removed => String::new(),
            crate::env::CanaryFileState::Unavailable => state.canary.clone(),
        }
    };

    let info = &Info {
        canary,
        secret_max_length: state.secret_max_length,
        rate_limit_cooldown: state.rate_limit_cooldown.num_minutes() as u64,
        rate_limit_max_failed_attempts: state.rate_limit_max_failed_attempts,
        attempts_collection_started_at: truncate_to_hour(state.attempts_collection_started_at),
        max_attempt_identifiers: state.rate_limit_max_identifiers,
    };

    (StatusCode::OK, Json(json!(info)))
}
