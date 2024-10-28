use std::env;

use axum::{http::StatusCode, Json};
use chrono::Duration;
use serde_json::{json, Value};

use crate::database::{establish_connection, read_key_by_id, update_requested_at};
use crate::models::FetchKey;
use crate::utils::is_sha256_hash;

pub async fn recover_key(Json(payload): Json<FetchKey>) -> (StatusCode, Json<Option<Value>>) {
    let id = &payload.id;
    let secret = &payload.secret;

    if !is_sha256_hash(id) || !is_sha256_hash(secret) {
        return (StatusCode::BAD_REQUEST, Json(None));
    }

    let mut connection: diesel::SqliteConnection = establish_connection();
    let result = read_key_by_id(&mut connection, &id);

    match result {
        Some(key) => {
            let current_time: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
            let request_cooldown =
                env::var("REQUEST_COOLDOWN").expect("REQUEST_COOLDOWN must be set");

            let cooldown = match request_cooldown.parse::<i64>() {
                Ok(number) => Duration::minutes(number),
                Err(e) => {
                    println!("Error: REQUEST_COOLDOWN must be a integer: {}", e);
                    std::process::exit(1);
                }
            };

            let has_cooled_down = match key.requested_at {
                Some(ref requested_at_str) => {
                    match chrono::DateTime::parse_from_rfc3339(requested_at_str) {
                        Ok(requested_at) => {
                            current_time.signed_duration_since(requested_at) > cooldown
                        }
                        Err(_) => false,
                    }
                }
                None => true,
            };

            if has_cooled_down {
                update_requested_at(&mut connection, &key.id);
                if key.secret == secret.clone() {
                    return (
                        StatusCode::OK,
                        Json(Some(serde_json::to_value(&key).unwrap())),
                    );
                } else {
                    let response = json!({
                        "error": "Invalid secret",
                        "requested_at": key.requested_at.unwrap_or("".to_string()),
                        "cooldown": cooldown.num_minutes(),
                    });
                    return (StatusCode::UNAUTHORIZED, Json(Some(response)));
                }
            } else {
                let response = json!({
                    "error": "Too many attempts",
                    "requested_at": key.requested_at.unwrap_or("".to_string()),
                    "cooldown": cooldown.num_minutes(),
                });
                return (StatusCode::TOO_MANY_REQUESTS, Json(Some(response)));
            }
        }
        None => (StatusCode::NOT_FOUND, Json(None)),
    }
}
