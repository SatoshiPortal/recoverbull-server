use std::env;

use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::models::Info;
use crate::AppState;

pub async fn get_info(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let canary = env::var("CANARY").expect("CANARY must be set");

    let info = &Info {
        canary,
        secret_max_length: state.secret_max_length,
        rate_limit_cooldown: state.rate_limit_cooldown.num_minutes() as u64,
        rate_limit_max_failed_attempts: state.rate_limit_max_failed_attempts,
    };

    (StatusCode::OK, Json(json!(info)))
}
