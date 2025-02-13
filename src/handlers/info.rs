use std::env;

use axum::extract::State;
use axum::{http::StatusCode, Json};
use chrono::Utc;
use serde_json::{json, Value};

use crate::models::InfoResponse;
use crate::AppState;

pub async fn get_info(State(state): State<AppState>) -> (StatusCode, Json<Option<Value>>) {
    let canary = env::var("CANARY").expect("CANARY must be set");

    (
        StatusCode::OK,
        Json(Some(json!(InfoResponse {
            timestamp: Utc::now().timestamp(),
            cooldown: state.cooldown.num_minutes(),
            secret_max_length: state.secret_max_length,
            canary,
        }))),
    )
}
