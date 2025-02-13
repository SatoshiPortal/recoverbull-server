use axum::{routing::{get, post}, Router};

use crate::{
    handlers::{info, fetch, store},
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
        .route("/fetch", post(fetch::fetch_secret))
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
