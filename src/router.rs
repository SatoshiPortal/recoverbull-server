use axum::{routing::post, Router};

use crate::{handlers, AppState};

pub fn new(app_state: AppState) -> Router {
    return Router::new()
        .route("/store_key", post(handlers::store_key::store_key))
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any) // TODO: Change this to a specific origin
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .route("/recover_key", post(handlers::recover_key::recover_key))
        .with_state(app_state)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any) // TODO: Change this to a specific origin
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        );
}
