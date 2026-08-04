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
    // canonicalize hex inputs: "AB…" and "ab…" are the same logical value
    // and must map to the same record and the same rate-limit entry
    let authentication_key = &request.authentication_key.to_lowercase();
    let encrypted_secret = &request.encrypted_secret;
    let identifier = &request.identifier.to_lowercase();

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

    // diesel is synchronous: run the write on a blocking thread so it
    // cannot stall the async workers
    let database_url = state.database_url.clone();
    let is_stored = tokio::task::spawn_blocking(move || {
        let mut connection = establish_connection(database_url);
        crate::database::write(&mut connection, &key)
    })
    .await
    .expect("database task panicked");

    match is_stored {
        true => {
            tracing::info!("secret stored");
            (StatusCode::CREATED, Json(None))
        }
        false => {
            tracing::error!("database error on store");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(None))
        }
    }
}
