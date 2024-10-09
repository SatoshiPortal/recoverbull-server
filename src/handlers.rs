use axum::{http::StatusCode, Json};

use crate::database::{establish_connection, read_key_by_id_and_secret};
use crate::models::{FetchKey, Key, StoreKey};
use crate::utils::is_sha256_hash;

use sha2::{Digest, Sha256};

pub async fn store_key(Json(payload): Json<StoreKey>) -> StatusCode {
    let mut hasher = Sha256::new();
    hasher.update(&payload.backup_key);
    let backup_key_hash = hasher.finalize();

    if !is_sha256_hash(payload.secret_hash.as_str()) {
        return StatusCode::BAD_REQUEST;
    }

    let key = Key {
        id: format!("{:x}", backup_key_hash),
        created_at: chrono::Local::now().naive_utc().to_string(),
        secret: payload.secret_hash,
        private: payload.backup_key,
    };

    let mut connection = establish_connection();
    let is_stored = crate::database::write_key(&mut connection, &key);

    match is_stored {
        Some(true) => return StatusCode::CREATED,
        Some(false) => return StatusCode::BAD_REQUEST,
        None => return StatusCode::FORBIDDEN,
    }
}

pub async fn fetch_key(Json(payload): Json<FetchKey>) -> (StatusCode, Json<Option<Key>>) {
    let id = &payload.id;
    let secret_hash = &payload.secret_hash;

    if !is_sha256_hash(id) || !is_sha256_hash(secret_hash) {
        return (StatusCode::BAD_REQUEST, Json(None));
    }

    let mut connection: diesel::SqliteConnection = establish_connection();
    let result = read_key_by_id_and_secret(&mut connection, &id, &secret_hash);

    match result {
        Some(key) => (StatusCode::FOUND, Json(Some(key))),
        None => (StatusCode::NOT_FOUND, Json(None)),
    }
}
