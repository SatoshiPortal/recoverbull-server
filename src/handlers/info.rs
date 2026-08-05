use std::env;

use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::models::Info;
use crate::utils::truncate_to_hour;
use crate::AppState;

pub async fn get_info(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let canary = env::var("CANARY").expect("CANARY must be set");

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
