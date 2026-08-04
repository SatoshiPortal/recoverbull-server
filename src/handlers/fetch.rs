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
    // canonicalize hex inputs: "AB…" and "ab…" are the same logical value
    // and must map to the same record and the same rate-limit entry
    let identifier = &request.identifier.to_lowercase();
    let authentication_key = &request.authentication_key.to_lowercase();

    if !is_256bits_hex_hash(identifier) || !is_256bits_hex_hash(authentication_key) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "identifier or authentication_key are not 256 bits HEX hashes",
            })),
        );
    }

    let current_time: chrono::DateTime<chrono::Utc> = chrono::Utc::now();

    // The rate-limit check and the attempt reservation are atomic: the entry
    // is checked and incremented under the same lock, so concurrent requests
    // cannot all pass the check before anyone increments.
    let (can_attempt, attempt_number, last_request) = {
        let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;

        // entries expire once the cooldown has elapsed
        if identifier_rate_limit.get(identifier).is_some_and(|info| {
            current_time.signed_duration_since(info.last_request) > state.rate_limit_cooldown
        }) {
            identifier_rate_limit.remove(identifier);
        }

        let info = identifier_rate_limit
            .entry(identifier.to_string())
            .or_insert(RateLimitInfo {
                last_request: current_time,
                attempts: 0,
            });

        if info.attempts >= state.rate_limit_max_failed_attempts {
            (false, info.attempts, info.last_request)
        } else {
            info.attempts += 1;
            info.last_request = current_time;
            (true, info.attempts, info.last_request)
        }
    };

    if !can_attempt {
        let response = json!({
            "error": "Too many attempts",
            "requested_at": last_request,
            "rate_limit_cooldown": state.rate_limit_cooldown.num_minutes(),
            "attempts": attempt_number,
        });
        return (StatusCode::TOO_MANY_REQUESTS, Json(response));
    }

    // re-generate the key_id
    let key_id = generate_secret_id(identifier, authentication_key);

    // look in db for this key_id, outside the rate-limit lock and on a
    // blocking thread: diesel is synchronous and must not stall the async
    // workers. The trash happens in the same blocking task on success.
    let database_url = state.database_url.clone();
    let key_id_for_db = key_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut connection = establish_connection(database_url);
        let result = read_secret_by_id(&mut connection, &key_id_for_db);
        if let Ok(Some(_)) = &result {
            if is_trashing_secret {
                trash(&mut connection, &key_id_for_db);
            }
        }
        result
    })
    .await
    .expect("database task panicked");

    match result {
        Err(_) => {
            // A database error is not a wrong credential: respond 500 and
            // refund the attempt reserved above so transient database
            // trouble cannot burn a user's rate-limit attempts.
            let should_remove = {
                let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
                match identifier_rate_limit.get_mut(identifier) {
                    Some(info) => {
                        info.attempts = info.attempts.saturating_sub(1);
                        info.attempts == 0
                    }
                    None => false,
                }
            };
            if should_remove {
                let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
                identifier_rate_limit.remove(identifier);
            }

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            )
        }

        Ok(Some(key)) => {
            // Report the failed attempts recorded for this identifier so the
            // client can warn the user about a possible brute-force or lockout
            // attempt, then reset them: a successful authentication proves
            // ownership of the secret. The attempt reserved above for this
            // successful request is discounted.
            let failed_attempts = {
                let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
                identifier_rate_limit
                    .remove(identifier)
                    .map(|info| info.attempts.saturating_sub(1))
                    .unwrap_or(0)
            };

            let code = if is_trashing_secret {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            };

            let mut response = json!(&key);
            response["failed_attempts"] = json!(failed_attempts);

            (code, Json(response))
        }

        Ok(None) => {
            // target brute-force mitigation
            // If the entry is not found:
            // - The key has been deleted by the user
            // - The key_id doesn't exists for the provided identifier + authentication_key
            let response = json!(ResponseFailedAttempt {
                error: "Invalid identifier/authentication_key".to_owned(),
                requested_at: last_request,
                rate_limit_cooldown: state.rate_limit_cooldown.num_minutes(),
                attempts: attempt_number,
            });

            (StatusCode::UNAUTHORIZED, Json(response))
        }
    }
}
