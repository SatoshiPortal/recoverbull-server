use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::database::{establish_connection, read_secret_by_id, trash};
use crate::models::FetchSecret;
use crate::utils::{generate_secret_id, is_256bits_hex_hash};

use crate::AppState;

pub async fn fetch_secret(
    State(state): State<AppState>,
    Json(request): Json<FetchSecret>,
    is_trashing_secret: bool,
) -> (StatusCode, Json<Value>) {
    let identifier = &request.identifier;
    let authentication_key = &request.authentication_key;

    if !is_256bits_hex_hash(identifier) || !is_256bits_hex_hash(authentication_key) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "identifier or authentication_key are not 256 bits HEX hashes",
            })),
        );
    }

    let last_request_time = {
        let key_access_time = state.identifier_access_time.lock().await;
        key_access_time.get(identifier).cloned()
    };

    let current_time: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
    let last_request = last_request_time.as_ref();

    let has_cooled_down = match last_request {
        Some(x) => current_time.signed_duration_since(x) > state.cooldown,
        None => true,
    };

    if has_cooled_down || last_request.is_none() {
        // re-generate the key_id
        let key_id = generate_secret_id(identifier, authentication_key);

        // look in db for this key_id
        let mut connection: diesel::SqliteConnection = establish_connection(state.database_url);
        let result = read_secret_by_id(&mut connection, &key_id);
        match result {
            Some(key) => {
                if is_trashing_secret {
                    trash(&mut connection, &key_id);
                }

                let code = if is_trashing_secret {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::OK
                };

                (code, Json(json!(&key)))
            }

            None => {
                // target brute-force mitigation
                // set cooldown only if the entry is not found (because it doesn't exist or the user input is invalid)
                let mut request_times = state.identifier_access_time.lock().await;
                request_times.insert(identifier.to_string(), current_time);

                let response = json!({
                    "error": "Invalid identifier/authentication_key",
                    "requested_at": current_time.to_rfc3339(),
                    "cooldown": state.cooldown.num_minutes(),
                });

                (StatusCode::UNAUTHORIZED, Json(response))
            }
        }
    } else {
        let response = json!({
            "error": "Too many attempts",
            "requested_at": last_request_time.unwrap(),
            "cooldown": state.cooldown.num_minutes(),
        });
        (StatusCode::TOO_MANY_REQUESTS, Json(response))
    }
}
