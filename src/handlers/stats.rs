use axum::extract::State;
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

use crate::models::StatEntry;
use crate::AppState;

/// Public brute-force telemetry.
///
/// Publishes the identifiers currently rate-limited for fetch/trash lookups,
/// hashed with SHA-256 over the raw identifier bytes so that:
/// - a client can recognize its own identifier (it knows the raw value),
/// - nobody else can recover a raw identifier from the list (pre-image
///   resistance), which keeps the list useless for griefing or lockout.
///
/// Entries live in the same in-memory map as the rate-limiter, so they
/// expire with it (cooldown reset or server reboot): no persistence.
pub async fn get_stats(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let stats: Vec<StatEntry> = {
        let now = chrono::Utc::now();
        let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
        identifier_rate_limit.retain(|_, info| {
            now.signed_duration_since(info.last_request) <= state.rate_limit_cooldown
        });
        identifier_rate_limit
            .iter()
            .map(|(id_hash, info)| StatEntry {
                id_hash: id_hash.clone(),
                attempts: info.attempts,
                failed_attempts: info.failed_attempts,
                last_attempt_at: info.last_request,
            })
            .collect()
    };

    (StatusCode::OK, Json(json!(stats)))
}
