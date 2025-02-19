use axum::extract::State;
use axum::{http::StatusCode, Json};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Utc;
use serde_json::{json, Value};

use crate::database::{establish_connection, read_secret_by_id, trash};
use crate::models::{Payload, EncryptedRequest, FetchSecret, SignedResponse};
use crate::nip44::{decrypt_body, encrypt_body};
use crate::utils::{generate_secret_id, is_256bits_hex_hash};
use crate::env::get_secret_key_from_dotenv;
use crate::{schnorr, AppState};

pub async fn fetch_secret(
    State(state): State<AppState>,
    Json(encryptedrequest): Json<EncryptedRequest>,
    is_trashing_secret: bool,
) -> (StatusCode, Json<Value>) {
    let client_public_key = match hex::decode(encryptedrequest.public_key.clone()){
        Ok(value)=> value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "public_key should be hex encoded"})),
            );
        }
    };
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

    let request: FetchSecret = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "the decrypted body is invalid"})),
            );
        }
    };

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
                let code = if is_trashing_secret {StatusCode::ACCEPTED} else {StatusCode::OK};


                let payload = serde_json::to_string(&Payload{
                    timestamp: Utc::now().timestamp(),
                    data: serde_json::to_string(&key).unwrap(),
                }).unwrap();

                let encrypted_response =
                    encrypt_body(&server_secret_key, &client_public_key, payload).unwrap();
                let encrypted_data_bytes = BASE64_STANDARD.decode(encrypted_response.clone()).unwrap();

                let signature = schnorr::sha256_and_sign(&server_secret_key, &encrypted_data_bytes).unwrap();
                (
                    code,
                    Json(json!(&SignedResponse {
                        response: encrypted_response,
                        signature: hex::encode(signature),
                    })),
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
