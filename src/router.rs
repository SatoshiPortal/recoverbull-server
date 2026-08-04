use axum::{
    extract::{DefaultBodyLimit, State},
    routing::{get, post},
    Json, Router,
};

use crate::{
    handlers::{fetch, info, stats, store},
    models::FetchSecret,
    AppState,
};

// No CORS layers: clients are native apps reaching the server over Tor,
// not browsers. Allowing any origin would let any web page conscript its
// visitors' browsers into calling this API.
pub fn new(app_state: AppState) -> Router {
    // Bound the total request duration, including body reads: a client
    // dribbling its request byte by byte (slow-loris) sees it expire.
    // Header reads happen before the service and remain a proxy concern.
    let timeout = tower_http::timeout::TimeoutLayer::new(std::time::Duration::from_secs(30));

    Router::new()
        .route("/store", post(store::store_secret))
        .with_state(app_state.clone())
        .route(
            "/fetch",
            post(|state: State<AppState>, json: Json<FetchSecret>| {
                fetch::fetch_secret(state, json, false)
            }),
        )
        .with_state(app_state.clone())
        .route(
            "/trash",
            post(|state: State<AppState>, json: Json<FetchSecret>| {
                fetch::fetch_secret(state, json, true)
            }),
        )
        .with_state(app_state.clone())
        .route("/info", get(info::get_info))
        .with_state(app_state.clone())
        .route("/stats", get(stats::get_stats))
        .with_state(app_state)
        // Legitimate JSON requests are below 320 bytes. Keep modest headroom
        // while rejecting oversized bodies before deserialization.
        .layer(DefaultBodyLimit::max(1024))
        .layer(timeout)
}
