use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

use crate::{
    handlers::{fetch, info, store},
    models::FetchSecret,
    AppState,
};

pub fn new(app_state: AppState) -> Router {
    Router::new()
        .route("/store", post(store::store_secret))
        .with_state(app_state.clone())
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .route(
            "/fetch",
            post(|state: State<AppState>, json: Json<FetchSecret>| {
                fetch::fetch_secret(state, json, false)
            }),
        )
        .with_state(app_state.clone())
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .route(
            "/trash",
            post(|state: State<AppState>, json: Json<FetchSecret>| {
                fetch::fetch_secret(state, json, true)
            }),
        )
        .with_state(app_state.clone())
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .route("/info", get(info::get_info))
        .with_state(app_state)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
}
