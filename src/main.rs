mod database;
mod handlers;
mod models;
mod schema;
mod utils;

use axum::{routing::post, Router};

#[tokio::main]
async fn main() {
    crate::database::init_db();

    let app = Router::new()
        .route("/key", post(crate::handlers::store_key))
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any) // TODO: Change this to a specific origin
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .route("/recover", post(crate::handlers::fetch_key))
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any) // TODO: Change this to a specific origin
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
