mod database;
mod env;
mod handlers;
mod models;
mod router;
mod schema;

#[cfg(test)]
mod tests;
mod utils;

use std::{collections::HashMap, sync::Arc};

use chrono::TimeDelta;
use tokio::sync::Mutex;

#[derive(Clone)]
struct AppState {
    server_address: String,
    database_url: String,
    rate_limit_cooldown: TimeDelta,
    identifier_rate_limit: Arc<Mutex<HashMap<String, models::RateLimitInfo>>>,
    secret_max_length: usize,
    rate_limit_max_failed_attempts: u8,
}

#[tokio::main]
async fn main() {
    let app_state = crate::env::init();

    crate::database::init_db(app_state.clone());

    let app = router::new(app_state.clone());

    let listener = tokio::net::TcpListener::bind(&app_state.server_address)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
