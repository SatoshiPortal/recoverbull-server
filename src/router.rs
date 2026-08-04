use axum::{
    extract::State,
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
}
