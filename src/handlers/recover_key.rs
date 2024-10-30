use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::database::{establish_connection, read_key_by_id};
use crate::models::FetchKey;
use crate::utils::{generate_key_id, is_sha256_hash};
use crate::AppState;

pub async fn recover_key(
    State(state): State<AppState>,
    Json(payload): Json<FetchKey>,
) -> (StatusCode, Json<Option<Value>>) {
    let backup_id = &payload.backup_id;
    let secret_hash = &payload.secret_hash;

    if !is_sha256_hash(backup_id) || !is_sha256_hash(secret_hash) {
        return (StatusCode::BAD_REQUEST, Json(None));
    }

    let last_request_time = {
        let key_access_time = state.key_access_time.lock().await;
        key_access_time.get(backup_id).cloned()
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
            request_times.insert(backup_id.to_string(), current_time);
        }

        // re-generate the key_id
        let key_id = generate_key_id(backup_id, secret_hash);

        // look in db for this key_id
        let mut connection: diesel::SqliteConnection = establish_connection(state.database_url);
        let result = read_key_by_id(&mut connection, &key_id);
        match result {
            Some(key) => {
                return (
                    StatusCode::OK,
                    Json(Some(serde_json::to_value(&key).unwrap())),
                );
            }
            None => {
                let response = json!({
                    "error": "Invalid key_id/secret_hash",
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
