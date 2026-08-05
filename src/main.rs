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

use std::{collections::HashMap, sync::Arc, time::Instant};

use axum::body::Bytes;
use chrono::TimeDelta;
use tokio::sync::{Mutex, Semaphore};

/// Immutable `/attempts` representation: serialized and compressed at most
/// once per TTL window, then shared by every response without copying.
struct AttemptsSnapshotCache {
    gzip_body: Arc<Bytes>,
    etag: String,
    created_at: Instant,
}

#[derive(Clone)]
struct AppState {
    server_address: String,
    database_url: String,
    /// Warrant canary captured at startup. Serves as the fallback when the
    /// dotenv file is unreadable, and as the authoritative value when it
    /// came from the process environment.
    canary: String,
    /// True when CANARY was provided by the process environment (dotenvy
    /// never overrides it): the file is then ignored at request time.
    canary_from_env: bool,
    /// Dotenv file the canary is re-read from, so an operator can update or
    /// remove it without restarting the server.
    canary_path: std::path::PathBuf,
    rate_limit_cooldown: TimeDelta,
    identifier_rate_limit: Arc<Mutex<HashMap<String, models::RateLimitInfo>>>,
    secret_max_length: usize,
    rate_limit_max_failed_attempts: u8,
    store_token_bucket: Arc<Mutex<rate_limit::TokenBucket>>,
    lookup_token_bucket: Arc<Mutex<rate_limit::TokenBucket>>,
    attempts_token_bucket: Arc<Mutex<rate_limit::TokenBucket>>,
    rate_limit_max_identifiers: usize,
    database_semaphore: Arc<Semaphore>,
    attempts_collection_started_at: chrono::DateTime<chrono::Utc>,
    attempts_snapshot: Arc<Mutex<Option<AttemptsSnapshotCache>>>,
    attempts_snapshot_ttl: std::time::Duration,
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
