use std::env;

use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::models::Info;
use crate::AppState;

pub async fn get_info(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let canary = env::var("CANARY").expect("CANARY must be set");

    let info = &Info {
        cooldown: state.cooldown.num_minutes(),
        secret_max_length: state.secret_max_length,
        canary,
    };

    (StatusCode::OK, Json(json!(info)))
}
