use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use serde_json::Value;

use crate::database::establish_connection;
use crate::models::{error_body, retry_after_response, Secret, StoreSecret};
use crate::utils::{generate_secret_id, is_256bits_hex_hash, is_base64};
use crate::AppState;

const DATABASE_PERMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Small fixed advisory backoff for the global store bucket and the
/// database-busy path: unlike the per-identifier lockout, there is no real
/// cooldown deadline to derive here, only "try again shortly".
const GLOBAL_OVERLOAD_RETRY_AFTER_SECS: u64 = 1;

pub async fn store_secret(
    State(state): State<AppState>,
    Json(request): Json<StoreSecret>,
) -> Response {
    // canonicalize hex inputs: "AB…" and "ab…" are the same logical value
    // and must map to the same record and the same rate-limit entry
    let authentication_key = &request.authentication_key.to_lowercase();
    let encrypted_secret = &request.encrypted_secret;
    let identifier = &request.identifier.to_lowercase();

    if !is_256bits_hex_hash(identifier) || !is_256bits_hex_hash(authentication_key) {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_body(
                "identifier or authentication_key are not 256 bits HEX hashes",
            )),
        )
            .into_response();
    }

    if encrypted_secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_body("encrypted_secret is empty")),
        )
            .into_response();
    }

    // Length before base64: the cheap check rejects oversized input without
    // paying for a full decode of a body that will be rejected anyway.
    if encrypted_secret.len() > state.secret_max_length {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_body(format!(
                "encrypted_secret length exceeds the limit {}",
                state.secret_max_length
            ))),
        )
            .into_response();
    }

    if !is_base64(encrypted_secret) {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_body("encrypted_secret should be base64 encoded")),
        )
            .into_response();
    }

    // Global write damper: unauthenticated writes are token-bucketed so a
    // flood cannot fill the database at full speed.
    {
        let mut bucket = state.store_token_bucket.lock().await;
        if !bucket.try_consume() {
            tracing::warn!("store rate-limit exceeded");
            return retry_after_response(
                StatusCode::SERVICE_UNAVAILABLE,
                GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
                "Too many store requests, retry later",
            );
        }
    }

    let key = Secret {
        id: generate_secret_id(identifier, authentication_key),
        created_at: chrono::Utc::now().to_rfc3339(),
        encrypted_secret: encrypted_secret.clone(),
    };

    let database_permit = match tokio::time::timeout(
        DATABASE_PERMIT_TIMEOUT,
        state.database_semaphore.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) | Err(_) => {
            tracing::warn!("database concurrency limit exceeded");
            return retry_after_response(
                StatusCode::SERVICE_UNAVAILABLE,
                GLOBAL_OVERLOAD_RETRY_AFTER_SECS,
                "Database busy, retry later",
            );
        }
    };

    // diesel is synchronous: run the write on a blocking thread so it
    // cannot stall the async workers
    let database_url = state.database_url.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _database_permit = database_permit;
        let mut connection = establish_connection(database_url);
        crate::database::write(&mut connection, &key)
    })
    .await;

    let is_stored = match task {
        Ok(is_stored) => is_stored,
        Err(error) => {
            tracing::error!(error = %error, "database task panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("Internal server error")),
            )
                .into_response();
        }
    };

    match is_stored {
        true => {
            tracing::info!("secret stored");
            // No useful body on success: the client only needs the status.
            (StatusCode::CREATED, Json(Value::Null)).into_response()
        }
        false => {
            tracing::error!("database error on store");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("Internal server error")),
            )
                .into_response()
        }
    }
}
