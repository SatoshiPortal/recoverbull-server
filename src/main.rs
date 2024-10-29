mod database;
mod handlers;
mod models;
mod router;
mod schema;
#[cfg(test)]
mod tests;
mod utils;

use std::{collections::HashMap, env, sync::Arc};

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

#[derive(Clone)]
struct AppState {
    key_access_time: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
}

#[tokio::main]
async fn main() {
    let app_state = AppState {
        key_access_time: Arc::new(Mutex::new(HashMap::new())),
    };

    crate::utils::init();

    crate::database::init_db();

    let app = router::new(app_state);

    let keychain_address: String =
        env::var("KEYCHAIN_ADDRESS").expect("KEYCHAIN_ADDRESS must be set");

    let listener = tokio::net::TcpListener::bind(keychain_address)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
