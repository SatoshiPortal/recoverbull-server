mod database;
mod handlers;
mod models;
mod router;
mod schema;
#[cfg(test)]
mod tests;
mod utils;

use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, TimeDelta, Utc};
use tokio::sync::Mutex;

#[derive(Clone)]
struct AppState {
    server_address: String,
    database_url: String,
    cooldown: TimeDelta,
    identifier_access_time: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
    secret_max_length: usize,
}

#[tokio::main]
async fn main() {
    let app_state = crate::utils::init();

    crate::database::init_db(app_state.clone());

    let app = router::new(app_state.clone());

    let listener = tokio::net::TcpListener::bind(&app_state.server_address)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
