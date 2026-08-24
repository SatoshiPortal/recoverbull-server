mod database;
mod diagnostic;
mod env;
mod handlers;
mod models;
mod rate_limit;
mod router;
mod schema;
mod security_counters;

#[cfg(test)]
mod tests;
mod utils;

use std::{collections::HashMap, future::IntoFuture, sync::Arc, time::Instant};

use axum::body::Bytes;
use chrono::TimeDelta;
use tokio::sync::{Mutex, Semaphore};

const APP_GRACE_PERIOD: std::time::Duration = std::time::Duration::from_secs(35);

enum ShutdownResult<E> {
    Completed(Result<(), E>),
    TimedOut,
}

async fn run_with_graceful_shutdown<F, S, E>(
    server: F,
    signal: S,
    shutdown_trigger: tokio::sync::oneshot::Sender<()>,
    grace_period: std::time::Duration,
) -> ShutdownResult<E>
where
    F: std::future::Future<Output = Result<(), E>>,
    S: std::future::Future<Output = &'static str>,
{
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => ShutdownResult::Completed(result),
        signal = signal => {
            tracing::info!(signal, "shutdown signal received; starting graceful shutdown");
            let _ = shutdown_trigger.send(());
            tokio::select! {
                result = &mut server => ShutdownResult::Completed(result),
                _ = tokio::time::sleep(grace_period) => ShutdownResult::TimedOut,
            }
        }
    }
}

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
    #[cfg(test)]
    _test_database_guard: Arc<env::TestDatabaseGuard>,
    /// Warrant canary captured at startup for unavailable-file fallback, or
    /// as the authoritative value when it came from process environment.
    canary: String,
    /// True when CANARY was provided by the process environment (dotenvy
    /// never overrides it): the file is then ignored at request time.
    canary_from_env: bool,
    /// Dotenv file re-read for every `/info` request.
    canary_path: std::path::PathBuf,
    /// Serializes dotenv reads so `/info` cannot exhaust Tokio's blocking pool.
    canary_read_semaphore: Arc<Semaphore>,
    rate_limit_cooldown: TimeDelta,
    identifier_rate_limit: Arc<Mutex<HashMap<String, models::RateLimitInfo>>>,
    secret_max_length: usize,
    rate_limit_max_attempts: u8,
    store_token_bucket: Arc<Mutex<rate_limit::TokenBucket>>,
    lookup_token_bucket: Arc<Mutex<rate_limit::TokenBucket>>,
    attempts_token_bucket: Arc<Mutex<rate_limit::TokenBucket>>,
    rate_limit_max_identifiers: usize,
    database_semaphore: Arc<Semaphore>,
    attempts_collection_started_at: Arc<Mutex<chrono::DateTime<chrono::Utc>>>,
    attempts_snapshot: Arc<Mutex<Option<AttemptsSnapshotCache>>>,
    attempts_snapshot_ttl: std::time::Duration,
    security_counters: Arc<security_counters::SecurityCounters>,
    diagnostic_logs: Arc<diagnostic::LogQuota>,
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

    if let Err(error) = crate::database::try_init_db(app_state.clone()) {
        eprintln!("Failed to initialize database: {error:?}");
        std::process::exit(1);
    }
    tracing::info!(target: "security", secure_delete = true, counter_window_seconds = 300, "security controls enabled");
    crate::security_counters::spawn_reporter(
        app_state.clone(),
        std::time::Duration::from_secs(300),
    );

    crate::rate_limit::spawn_sweeper(app_state.clone());
    let mut wiper = crate::rate_limit::spawn_production_wiper(app_state.clone());

    let app = router::new(app_state.clone());

    let listener = tokio::net::TcpListener::bind(&app_state.server_address)
        .await
        .unwrap();
    let (shutdown_trigger, shutdown_request) = tokio::sync::oneshot::channel();
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_request.await;
        })
        .into_future();
    tokio::select! {
        result = &mut wiper => {
            match result {
                Ok(()) => tracing::error!("production rate-limit wiper exited unexpectedly"),
                Err(_error) => tracing::error!("production rate-limit wiper failed"),
            }
            std::process::exit(1);
        }
        result = run_with_graceful_shutdown(server, shutdown_signal(), shutdown_trigger, APP_GRACE_PERIOD) => {
            wiper.abort();
            let _ = wiper.await;
            match result {
                ShutdownResult::Completed(Ok(())) => {}
                ShutdownResult::Completed(Err(error)) => panic!("server failed: {error:?}"),
                ShutdownResult::TimedOut => {
                    tracing::error!(grace_period_seconds = APP_GRACE_PERIOD.as_secs(), "graceful shutdown timed out; forcing process exit");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Waits for SIGINT or SIGTERM. Graceful shutdown lets in-flight requests
/// finish instead of being killed mid-handler: `/trash` commits its database
/// transaction before sending the response, so an abrupt process kill
/// between the commit and the response would make the caller retry (or give
/// up on) a backup that was, in fact, already removed from the active table.
async fn shutdown_signal() -> &'static str {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => "SIGINT",
        _ = terminate => "SIGTERM",
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::{run_with_graceful_shutdown, ShutdownResult};
    use std::time::Duration;

    #[tokio::test]
    async fn ready_server_completes_without_waiting_for_grace_period() {
        let (trigger, _request) = tokio::sync::oneshot::channel();
        let result = run_with_graceful_shutdown(
            async { Ok::<(), ()>(()) },
            std::future::pending::<&'static str>(),
            trigger,
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(result, ShutdownResult::Completed(Ok(()))));
    }

    #[tokio::test]
    async fn shutdown_times_out_after_signal_with_bounded_grace_period() {
        let (trigger, request) = tokio::sync::oneshot::channel();
        let result = run_with_graceful_shutdown(
            std::future::pending::<Result<(), ()>>(),
            async { "SIGTERM" },
            trigger,
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(result, ShutdownResult::TimedOut));
        assert!(request.await.is_ok());
    }
}
