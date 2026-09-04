//! `/info` operational metadata response construction.

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use serde_json::json;

use crate::app::AppState;
use crate::attempts::snapshot::truncate_to_hour;
use crate::http::contract::Info;

/// Returns public operational limits and the canary state.
///
/// `Cache-Control` carries what remains of the canary's freshness, so a
/// client or proxy cache cannot make the signal older than one re-read
/// interval. `/info` is deliberately never rate-limited: a client must
/// always be able to tell "the telemetry subsystem is broken" from "the
/// server is unreachable".
pub async fn get_info(State(state): State<AppState>) -> Response {
    let info_state = state.info_state();
    let canary = info_state.current_canary();
    let max_age = info_state.canary_max_age();

    let info = &Info {
        canary,
        secret_max_length: info_state.secret_max_length(),
        rate_limit_cooldown: info_state.policy().cooldown().num_minutes() as u64,
        rate_limit_max_attempts: info_state.policy().max_attempts(),
        rate_limit_max_failed_attempts: info_state.policy().max_attempts(),
        attempts_collection_started_at: truncate_to_hour(
            state.attempts_collection_started_at().await,
        ),
        max_attempt_identifiers: info_state.policy().max_identifiers(),
    };

    let mut response = (StatusCode::OK, Json(json!(info))).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        format!("public, max-age={max_age}")
            .parse()
            .expect("a formatted max-age is a valid header value"),
    );
    response
}
