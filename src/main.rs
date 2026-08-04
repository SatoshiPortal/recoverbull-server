mod database;
mod env;
mod handlers;
mod models;
mod rate_limit;
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let app_state = crate::env::init();

    if !app_state.server_address.starts_with("127.0.0.1")
        && !app_state.server_address.starts_with("localhost")
        && !app_state.server_address.starts_with("[::1]")
    {
        eprintln!(
            "WARNING: SERVER_ADDRESS ({}) is not loopback. This server is designed to run behind a Tor onion service or a TLS-terminating proxy; never expose it directly on a public interface.",
            app_state.server_address
        );
    }

    crate::database::init_db(app_state.clone());

    crate::rate_limit::spawn_sweeper(app_state.clone());

    let app = router::new(app_state.clone());

    let listener = tokio::net::TcpListener::bind(&app_state.server_address)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
