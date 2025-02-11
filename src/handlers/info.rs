use std::env;

use axum::extract::State;
use axum::{http::StatusCode, Json};
use chrono::Utc;
use serde_json::{json, Value};


use crate::AppState;


pub async fn get_info(State(state): State<AppState>) -> (StatusCode, Json<Option<Value>>) {
    let info_message = env::var("INFO_MESSAGE").expect("INFO_MESSAGE must be set");
    
    return (StatusCode::OK, Json(Some(json!({
        "timestamp": Utc::now().timestamp(),
        "cooldown": state.cooldown.num_minutes(),
        "secret_max_length": state.secret_max_length,
        "message": info_message,
    }))));
}
