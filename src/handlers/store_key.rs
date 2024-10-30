use axum::extract::State;
use axum::{http::StatusCode, Json};

use crate::database::establish_connection;
use crate::models::{Key, StoreKey};
use crate::utils::{generate_key_id, is_sha256_hash};
use crate::AppState;

pub async fn store_key(State(state): State<AppState>, Json(payload): Json<StoreKey>) -> StatusCode {
    let secret_hash = &payload.secret_hash;
    let backup_key = &payload.backup_key;
    let backup_id = &payload.backup_id;

    if !is_sha256_hash(secret_hash) || !is_sha256_hash(&backup_id) {
        return StatusCode::BAD_REQUEST;
    }

    let key = Key {
        id: generate_key_id(backup_id, secret_hash),
        created_at: chrono::Utc::now().to_rfc3339(),
        backup_key: backup_key.clone(),
    };

    let mut connection = establish_connection(state.database_url);
    let is_stored = crate::database::write_key(&mut connection, &key);

    match is_stored {
        Some(true) => return StatusCode::CREATED,
        Some(false) => return StatusCode::BAD_REQUEST,
        None => return StatusCode::FORBIDDEN,
    }
}
