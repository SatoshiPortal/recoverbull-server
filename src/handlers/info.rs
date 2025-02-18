use std::env;

use axum::extract::State;
use axum::{http::StatusCode, Json};
use chrono::Utc;
use serde_json::{json, Value};

use crate::env::get_secret_key_from_dotenv;
use crate::models::{Info, Payload, SignedResponse};
use crate::{schnorr, AppState};

pub async fn get_info(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let canary = env::var("CANARY").expect("CANARY must be set");

    let server_secret_key = get_secret_key_from_dotenv();

    let info = serde_json::to_string(&Info{
        cooldown: state.cooldown.num_minutes(),
        secret_max_length: state.secret_max_length,
        canary,
    }).unwrap();

    let payload= serde_json::to_string(&Payload{
        timestamp: Utc::now().timestamp(),
        data: info
    }).unwrap();

    let signature = schnorr::sha256_and_sign(&server_secret_key, &payload.as_bytes()).unwrap();

    (
        StatusCode::OK,
        Json(json!(SignedResponse {
            response: payload,
            signature: hex::encode(signature)
        })),
    )
}
