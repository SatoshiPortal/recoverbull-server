use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::database::establish_connection;
use crate::models::{Secret, StoreSecret};
use crate::utils::{generate_secret_id, is_256bits_hex_hash, is_base64};
use crate::AppState;

pub async fn store_secret(
    State(state): State<AppState>,
    Json(request): Json<StoreSecret>,
) -> (StatusCode, Json<Option<Value>>) {
    let authentication_key = &request.authentication_key;
    let encrypted_secret = &request.encrypted_secret;
    let identifier = &request.identifier;

    if !is_256bits_hex_hash(identifier) || !is_256bits_hex_hash(authentication_key) {
        return (
            StatusCode::BAD_REQUEST,
            Json(Some(json!({
                "error": "identifier or authentication_key are not 256 bits HEX hashes",
            }))),
        );
    }

    if encrypted_secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(Some(json!({
                "error": "encrypted_secret is empty",
            }))),
        );
    }

    if !is_base64(encrypted_secret) {
        return (
            StatusCode::BAD_REQUEST,
            Json(Some(json!({
                "error": "encrypted_secret should be base64 encoded",
            }))),
        );
    }

    if encrypted_secret.len() > state.secret_max_length {
        return (
            StatusCode::BAD_REQUEST,
            Json(Some(json!({
                "error": format!("encrypted_secret length exceeds the limit {}", state.secret_max_length),
            }))),
        );
    }

    let key = Secret {
        id: generate_secret_id(identifier, authentication_key),
        created_at: chrono::Utc::now().to_rfc3339(),
        encrypted_secret: encrypted_secret.clone(),
    };

    let mut connection = establish_connection(state.database_url);
    let is_stored = crate::database::write(&mut connection, &key);

    match is_stored {
        Some(true) => (StatusCode::CREATED, Json(None)),
        Some(false) => (StatusCode::BAD_REQUEST, Json(None)),
        None => (StatusCode::FORBIDDEN, Json(None)), // duplicate
    }
}
