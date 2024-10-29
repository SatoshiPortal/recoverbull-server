use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::database::{establish_connection, read_key_by_id};
use crate::models::FetchKey;
use crate::utils::is_sha256_hash;
use crate::AppState;

pub async fn recover_key(
    State(state): State<AppState>,
    Json(payload): Json<FetchKey>,
) -> (StatusCode, Json<Option<Value>>) {
    let backup_key_hash = &payload.backup_key_hash;
    let secret_hash = &payload.secret_hash;

    if !is_sha256_hash(backup_key_hash) || !is_sha256_hash(secret_hash) {
        return (StatusCode::BAD_REQUEST, Json(None));
    }

    let last_request_time = {
        let key_access_time = state.key_access_time.lock().await;
        key_access_time.get(backup_key_hash).cloned()
    };

    let current_time: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
    let last_request = match last_request_time {
        Some(ref requested_at) => Some(requested_at),
        None => None,
    };

    let has_cooled_down = match last_request {
        Some(x) => current_time.signed_duration_since(x) > state.cooldown,
        None => true,
    };

    if has_cooled_down || last_request.is_none() {
        // set cooldown
        {
            let mut request_times = state.key_access_time.lock().await;
            request_times.insert(backup_key_hash.to_string(), current_time);
        }

        // re-generate the key_id_hex
        let mut hasher = Sha256::new();
        let mut backup_and_secret = Vec::new();
        backup_and_secret.extend_from_slice(&backup_key_hash.as_bytes());
        backup_and_secret.extend_from_slice(&secret_hash.as_bytes());
        hasher.update(&backup_and_secret);
        let key_id = hasher.finalize();
        let key_id_hex = format!("{:x}", key_id);

        // look in db for this key_id_hex
        let mut connection: diesel::SqliteConnection = establish_connection(state.database_url);
        let result = read_key_by_id(&mut connection, &key_id_hex);
        match result {
            Some(key) => {
                return (
                    StatusCode::OK,
                    Json(Some(serde_json::to_value(&key).unwrap())),
                );
            }
            None => {
                let response = json!({
                    "error": "Invalid key/secret_hash",
                    "requested_at": current_time.to_rfc3339(),
                    "cooldown": state.cooldown.num_minutes(),
                });
                return (StatusCode::UNAUTHORIZED, Json(Some(response)));
            }
        }
    } else {
        let response = json!({
            "error": "Too many attempts",
            "requested_at": last_request_time.unwrap(),
            "cooldown": state.cooldown.num_minutes(),
        });
        return (StatusCode::TOO_MANY_REQUESTS, Json(Some(response)));
    }
}
