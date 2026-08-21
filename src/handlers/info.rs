use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::models::Info;
use crate::utils::truncate_to_hour;
use crate::AppState;

pub async fn get_info(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    // The warrant canary is re-read from the dotenv file so an operator can
    // update or remove it without restarting the server (env::var alone
    // would never see the edit: dotenvy loads the file only at startup).
    // `/info` is deliberately not rate-limited, so the parse is cached and
    // only redone when the file's metadata (modification time and length)
    // changes, instead of on every request. A deliberate removal must serve
    // an empty canary — that IS the compromise signal clients watch for —
    // while an unreadable file is an ops error and falls back to the
    // startup value to avoid a false alarm. An environment-provided canary
    // is authoritative: signaling then requires a restart with a changed
    // value, and the file is never read.
    let canary = if state.canary_from_env {
        state.canary.clone()
    } else {
        let mut cache = state.canary_cache.lock().await;
        match crate::env::canary_file_state_cached(&state.canary_path, &mut cache) {
            crate::env::CanaryFileState::Value(value) => value,
            crate::env::CanaryFileState::Removed => String::new(),
            crate::env::CanaryFileState::Unavailable => state.canary.clone(),
        }
    };

    let info = &Info {
        canary,
        secret_max_length: state.secret_max_length,
        rate_limit_cooldown: state.rate_limit_cooldown.num_minutes() as u64,
        rate_limit_max_attempts: state.rate_limit_max_attempts,
        rate_limit_max_failed_attempts: state.rate_limit_max_attempts,
        attempts_collection_started_at: truncate_to_hour(
            *state.attempts_collection_started_at.lock().await,
        ),
        max_attempt_identifiers: state.rate_limit_max_identifiers,
    };

    (StatusCode::OK, Json(json!(info)))
}
