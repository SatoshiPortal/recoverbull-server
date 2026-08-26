use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::app::AppState;
use crate::attempts::snapshot::truncate_to_hour;
use crate::http::contract::Info;

pub async fn get_info(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let info_state = state.info_state();
    let canary = info_state.current_canary().await;

    let info = &Info {
        canary,
        secret_max_length: info_state.secret_max_length(),
        rate_limit_cooldown: info_state.policy().cooldown().num_minutes() as u64,
        rate_limit_max_attempts: info_state.policy().max_attempts(),
        rate_limit_max_failed_attempts: info_state.policy().max_attempts(),
        attempts_collection_started_at: truncate_to_hour(
            state.attempts_collection_started_at().await,
        ),
        max_attempt_identifiers: info_state.policy().max_identifiers(),
    };

    (StatusCode::OK, Json(json!(info)))
}
