use axum::extract::State;
use axum::{http::StatusCode, Json};
use sha2::{Digest, Sha256};

use crate::database::establish_connection;
use crate::models::{Key, StoreKey};
use crate::utils::is_sha256_hash;
use crate::AppState;

pub async fn store_key(State(state): State<AppState>, Json(payload): Json<StoreKey>) -> StatusCode {
    let secret_hash = &payload.secret_hash;
    let backup_key_bytes = hex::decode(payload.backup_key).unwrap();

    if !is_sha256_hash(secret_hash) {
        return StatusCode::BAD_REQUEST;
    }

    let mut hasher = Sha256::new();
    hasher.update(backup_key_bytes.clone());
    let backup_key_hash = hasher.finalize_reset();
    let backup_key_hash_hex = format!("{:x}", backup_key_hash);

    let mut backup_and_secret = Vec::new();
    backup_and_secret.extend_from_slice(&backup_key_hash_hex.as_bytes());
    backup_and_secret.extend_from_slice(&secret_hash.as_bytes());
    hasher.update(&backup_and_secret);
    let key_id = hasher.finalize();
    let key_id_hex = format!("{:x}", key_id);

    let key = Key {
        id: key_id_hex.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
        backup_key: hex::encode(backup_key_bytes),
    };

    let mut connection = establish_connection(state.database_url);
    let is_stored = crate::database::write_key(&mut connection, &key);

    match is_stored {
        Some(true) => return StatusCode::CREATED,
        Some(false) => return StatusCode::BAD_REQUEST,
        None => return StatusCode::FORBIDDEN,
    }
}
