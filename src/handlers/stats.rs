use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::models::StatEntry;
use crate::utils::sha256_hex;
use crate::AppState;

/// Public brute-force telemetry.
///
/// Publishes the identifiers currently rate-limited for failed fetch/trash
/// attempts, hashed with SHA-256 over the raw identifier bytes so that:
/// - a client can recognize its own identifier (it knows the raw value),
/// - nobody else can recover a raw identifier from the list (pre-image
///   resistance), which keeps the list useless for griefing or lockout.
///
/// Entries live in the same in-memory map as the rate-limiter, so they
/// expire with it (cooldown reset or server reboot): no persistence.
pub async fn get_stats(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let identifier_rate_limit = state.identifier_rate_limit.lock().await;

    let stats: Vec<StatEntry> = identifier_rate_limit
        .iter()
        .filter_map(|(identifier, info)| {
            hex::decode(identifier).ok().map(|raw_identifier| StatEntry {
                id_hash: sha256_hex(&raw_identifier),
                attempts: info.attempts,
                last_failed_at: info.last_request,
            })
        })
        .collect();

    (StatusCode::OK, Json(json!(stats)))
}
