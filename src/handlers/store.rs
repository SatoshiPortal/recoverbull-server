use axum::extract::State;
use axum::{http::StatusCode, Json};

use crate::database::establish_connection;
use crate::models::{Secret, StoreSecret};
use crate::utils::{generate_secret_id, is_sha256_hash};
use crate::AppState;

pub async fn store_secret(State(state): State<AppState>, Json(payload): Json<StoreSecret>) -> StatusCode {
    let authentication_key = &payload.authentication_key;
    let encrypted_secret = &payload.encrypted_secret;
    let identifier = &payload.identifier;

    if !is_sha256_hash(authentication_key) || !is_sha256_hash(&identifier) {
        return StatusCode::BAD_REQUEST;
    }

    let key = Secret {
        id: generate_secret_id(identifier, authentication_key),
        created_at: chrono::Utc::now().to_rfc3339(),
        encrypted_secret: encrypted_secret.clone(),
    };

    let mut connection = establish_connection(state.database_url);
    let is_stored = crate::database::write(&mut connection, &key);

    match is_stored {
        Some(true) => return StatusCode::CREATED,
        Some(false) => return StatusCode::BAD_REQUEST,
        None => return StatusCode::FORBIDDEN,
    }
}
