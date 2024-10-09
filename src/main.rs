mod database;
mod handlers;
mod models;
mod schema;
mod utils;

use axum::{routing::post, Router};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/key", post(crate::handlers::store_key))
        .route("/recover", post(crate::handlers::fetch_key));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
