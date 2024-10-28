use axum::{http::StatusCode, Json};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::database::establish_connection;
use crate::models::{Key, StoreKey};
use crate::utils::is_sha256_hash;

pub async fn store_key(Json(payload): Json<StoreKey>) -> StatusCode {
    let decoded_backup_key = BASE64_STANDARD.decode(payload.backup_key.clone()).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&decoded_backup_key);
    let backup_key_hash = hasher.finalize();

    if !is_sha256_hash(payload.secret.as_str()) {
        return StatusCode::BAD_REQUEST;
    }

    let key = Key {
        id: format!("{:x}", backup_key_hash),
        created_at: chrono::Utc::now().to_rfc3339(),
        secret: payload.secret,
        backup_key: payload.backup_key,
        requested_at: None,
    };

    let mut connection = establish_connection();
    let is_stored = crate::database::write_key(&mut connection, &key);

    match is_stored {
        Some(true) => return StatusCode::CREATED,
        Some(false) => return StatusCode::BAD_REQUEST,
        None => return StatusCode::FORBIDDEN,
    }
}
