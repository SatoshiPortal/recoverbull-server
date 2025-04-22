use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::database::{establish_connection, read_secret_by_id, trash};
use crate::models::{ResponseFailedAttempt, FetchSecret, RateLimitInfo};
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

    let current_time: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
    
    let rate_limit_info = {
        let identifier_rate_limit = state.identifier_rate_limit.lock().await;
        identifier_rate_limit.get(identifier).cloned()
    };

    let mut can_attempt = match rate_limit_info.clone() {
        Some(x) => x.attempts < state.max_failed_attempts,
        None => true,
    };

    // If has too many attempts we verify if the rate-limit cooldown is elapsed
    if can_attempt == false {
        let is_cooldown_over = match rate_limit_info.clone() {
            Some(x) => current_time.signed_duration_since(x.last_request) > state.cooldown,
            None => true,
        };
        // If the cooldown is over we reset the rate-limit and the user can attempt
        if is_cooldown_over {
            let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
            identifier_rate_limit.remove(identifier);
            can_attempt = true;
        }
    } 

    if can_attempt {
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
                // If the entry is not found:
                // - The key has been deleted by the user
                // - The key_id doesn't exists for the provided identifier + authentication_key
                // We set the rate-limit last_request and attempts for this identifier
                let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
                let rate_limit_info = identifier_rate_limit
                .entry(identifier.to_string())
                .and_modify(|info| {
                    info.last_request = current_time;
                    info.attempts += 1;
                })
                .or_insert(RateLimitInfo {
                    last_request: current_time,
                    attempts: 1,
                });

                let response = json!(ResponseFailedAttempt{
                    error: "Invalid identifier/authentication_key".to_owned(),
                    requested_at: rate_limit_info.last_request,
                    cooldown: state.cooldown.num_minutes(),
                    attempts: rate_limit_info.attempts,
                });

                (StatusCode::UNAUTHORIZED, Json(response))
            }
        }
    } else {
        let rate_limit_info = rate_limit_info.unwrap();
        let response = json!({
            "error": "Too many attempts",
            "requested_at": rate_limit_info.last_request,
            "cooldown": state.cooldown.num_minutes(),
            "attempts": rate_limit_info.attempts,
        });
        (StatusCode::TOO_MANY_REQUESTS, Json(response))
    }
}
