use axum::{routing::{get, post}, Router};

use crate::{
    handlers::{info, recover, store},
    AppState,
};

pub fn new(app_state: AppState) -> Router {
    return Router::new()
        .route("/store", post(store::store_secret))
        .with_state(app_state.clone())
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .route("/recover", post(recover::recover_secret))
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
        );

}
