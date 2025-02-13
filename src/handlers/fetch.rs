use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::database::{establish_connection, read_secret_by_id};
use crate::models::{EncryptedResponse, FetchSecret, EncryptedRequest};
use crate::utils::{decrypt_body, encrypt_body, generate_secret_id, get_secret_key_from_dotenv, is_256bits_hex_hash};
use crate::AppState;

pub async fn fetch_secret(
    State(state): State<AppState>,
    Json(encryptedrequest): Json<EncryptedRequest>,
) -> (StatusCode, Json<Value>) {
    let client_public_key = encryptedrequest.public_key.clone();
    let encrypted_body = encryptedrequest.encrypted_body.clone();
    let server_secret_key = get_secret_key_from_dotenv();

    let body: String = match decrypt_body(&server_secret_key, &client_public_key, encrypted_body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "server not able to decrypt the encrypted_body"})),
            );
        }
    };

    let request: FetchSecret = match serde_json::from_str(&body){
        Ok(value) => value,
        Err(_)=> {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "the decrypted body is invalid"})),
            );
        }
    };

    let identifier = &request.identifier;
    let authentication_key = &request.authentication_key;

    if !is_256bits_hex_hash(identifier) || !is_256bits_hex_hash(authentication_key) {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error": "identifier or authentication_key are not 256 bits HEX hashes",
        })));
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
                let response = serde_json::to_string(&key).unwrap();
                let encrypted_response = encrypt_body(&server_secret_key, &client_public_key,response).unwrap();
                (
                    StatusCode::OK,
                    Json(json!(&EncryptedResponse{encrypted_response})),
                )
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
