//! Recoverbull server entry point and bounded process lifecycle.
//!
//! Startup assembles shared owners, initializes SQLite, starts maintenance and
//! reporting tasks, and shuts down with a finite grace period.

mod app;
mod attempts;
mod config;
mod digest;
mod handlers;
mod http;
mod observability;
mod rate_limit;
mod recovery;
mod router;
mod schema;
mod storage;

pub(crate) use app::AppState;

#[cfg(test)]
mod tests;

use std::{future::IntoFuture, time::Duration};

/// The whole budget for stopping, from the moment shutdown begins to the
/// moment the process is gone. It covers both halves: Axum draining its
/// in-flight requests, and the detached SQLite work those requests handed to
/// blocking threads.
const APP_GRACE_PERIOD: Duration = Duration::from_secs(35);

enum ShutdownResult<E> {
    Completed(Result<(), E>),
    TimedOut,
}

/// Runs the server until it stops, and reports what is left of the grace
/// period so the caller can bound the wait for detached blocking work.
async fn run_with_graceful_shutdown<F, S, E>(
    server: F,
    signal: S,
    shutdown_trigger: tokio::sync::oneshot::Sender<()>,
    grace_period: Duration,
) -> (ShutdownResult<E>, Duration)
where
    F: std::future::Future<Output = Result<(), E>>,
    S: std::future::Future<Output = &'static str>,
{
    tokio::pin!(server);
    let (result, shutdown_started) = tokio::select! {
        result = &mut server => (ShutdownResult::Completed(result), std::time::Instant::now()),
        signal = signal => {
            tracing::info!(signal, "shutdown signal received; starting graceful shutdown");
            let shutdown_started = std::time::Instant::now();
            let _ = shutdown_trigger.send(());
            let result = tokio::select! {
                result = &mut server => ShutdownResult::Completed(result),
                _ = tokio::time::sleep(grace_period) => ShutdownResult::TimedOut,
            };
            (result, shutdown_started)
        }
    };
    let remaining = match result {
        ShutdownResult::TimedOut => Duration::ZERO,
        ShutdownResult::Completed(_) => grace_period.saturating_sub(shutdown_started.elapsed()),
    };
    (result, remaining)
}

/// Starts the runtime, serves, then bounds the wait for detached work.
///
/// The runtime is built explicitly rather than by `#[tokio::main]` because
/// dropping a runtime waits, without any limit, for every `spawn_blocking`
/// task that has already started — and those tasks are deliberate: a
/// transferred SQLite operation must finish rather than be abandoned
/// mid-transaction. So Axum could drain its requests well inside the grace
/// period while one stuck blocking thread kept the process alive
/// indefinitely. `shutdown_timeout` gives that work the rest of the grace
/// period and then stops waiting, which makes the documented 35 seconds a
/// property of this process instead of a promise kept only by systemd's
/// `TimeoutStopSec=40s`. The bound is on the *waiting*, not on the work:
/// blocking tasks are not cancellable, so a thread may still be running when
/// the process exits.
fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build the Tokio runtime");
    let remaining = runtime.block_on(serve());
    runtime.shutdown_timeout(remaining);
}

/// Starts the server after configuration and SQLite capability checks, and
/// returns what is left of the grace period once it has stopped.
async fn serve() -> Duration {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let app_state = crate::app::build(crate::config::init());

    if let Err(error) = app_state.initialize_storage() {
        eprintln!("Failed to initialize database: {error:?}");
        std::process::exit(1);
    }
    tracing::info!(target: "security", secure_delete = true, counter_window_seconds = 300, "security controls enabled");
    app_state.spawn_security_reporter(std::time::Duration::from_secs(300));

    let mut wiper = app_state.spawn_production_wiper();

    let app = router::new(app_state.clone());

    let listener = tokio::net::TcpListener::bind(app_state.server_address())
        .await
        .unwrap();
    warn_unless_loopback(listener.local_addr());
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
        (result, remaining) = run_with_graceful_shutdown(server, shutdown_signal(), shutdown_trigger, APP_GRACE_PERIOD) => {
            wiper.abort();
            let _ = wiper.await;
            match result {
                ShutdownResult::Completed(Ok(())) => remaining,
                // Exit rather than unwind: a panic here would drop the
                // runtime while unwinding, which is the unbounded wait this
                // lifecycle exists to avoid.
                ShutdownResult::Completed(Err(error)) => {
                    tracing::error!("server failed: {error:?}");
                    std::process::exit(1);
                }
                ShutdownResult::TimedOut => {
                    tracing::error!(grace_period_seconds = APP_GRACE_PERIOD.as_secs(), "graceful shutdown timed out; forcing process exit");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Whether a bound socket address is loopback.
///
/// Decided on the address the kernel actually bound, never on the configured
/// string: a textual prefix check accepted `localhost.attacker.example` or
/// `127.0.0.1.example`, which resolve wherever their owner wants, and flagged
/// `127.0.0.2`, which is loopback.
pub(crate) fn is_loopback_bind(address: std::net::SocketAddr) -> bool {
    address.ip().is_loopback()
}

/// Prints the deployment warning when the listener is not on loopback. This
/// is a warning, not an enforcement: the runbook requires the proxy and Tor
/// in front of this process, and the binary cannot verify that itself.
fn warn_unless_loopback(bound: std::io::Result<std::net::SocketAddr>) {
    match bound {
        Ok(address) if is_loopback_bind(address) => {}
        Ok(address) => eprintln!(
            "WARNING: the listener is bound to {address}, which is not loopback. This server is designed to run behind a Tor onion service or a TLS-terminating proxy; never expose it directly on a public interface."
        ),
        Err(error) => eprintln!(
            "WARNING: could not read the bound listener address ({error}); verify that SERVER_ADDRESS is loopback."
        ),
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
mod bind_tests {
    use super::is_loopback_bind;

    /// The decision is on the address, so every loopback address passes and
    /// no textual lookalike can: there is no string to match a prefix on.
    #[test]
    fn loopback_is_decided_on_the_bound_address() {
        for loopback in [
            "127.0.0.1:3000",
            "127.0.0.2:3000",
            "127.255.255.254:1",
            "[::1]:3000",
        ] {
            assert!(
                is_loopback_bind(loopback.parse().unwrap()),
                "{loopback} is loopback"
            );
        }
        for public in [
            "0.0.0.0:3000",
            "192.168.1.10:3000",
            "10.0.0.1:80",
            "[::]:3000",
            "[2001:db8::1]:3000",
        ] {
            assert!(
                !is_loopback_bind(public.parse().unwrap()),
                "{public} is not loopback"
            );
        }
    }

    /// The check runs on the socket the process bound, so a configured name
    /// is only ever judged by what it resolved to.
    #[tokio::test]
    async fn bound_localhost_is_judged_by_its_resolved_address() {
        let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
        assert!(is_loopback_bind(listener.local_addr().unwrap()));
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::{run_with_graceful_shutdown, ShutdownResult};
    use std::time::Duration;

    #[tokio::test]
    async fn ready_server_completes_without_waiting_for_grace_period() {
        let (trigger, _request) = tokio::sync::oneshot::channel();
        let (result, remaining) = run_with_graceful_shutdown(
            async { Ok::<(), ()>(()) },
            std::future::pending::<&'static str>(),
            trigger,
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(result, ShutdownResult::Completed(Ok(()))));
        assert!(
            remaining > Duration::ZERO,
            "a server that stopped on its own leaves the grace period for detached work"
        );
    }

    #[tokio::test]
    async fn shutdown_times_out_after_signal_with_bounded_grace_period() {
        let (trigger, request) = tokio::sync::oneshot::channel();
        let (result, remaining) = run_with_graceful_shutdown(
            std::future::pending::<Result<(), ()>>(),
            async { "SIGTERM" },
            trigger,
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(result, ShutdownResult::TimedOut));
        assert_eq!(
            remaining,
            Duration::ZERO,
            "a shutdown that already used its whole budget leaves nothing"
        );
        assert!(request.await.is_ok());
    }

    /// The grace period is one budget for both halves of stopping: whatever a
    /// graceful drain spends is no longer available to detached blocking work.
    #[tokio::test]
    async fn the_grace_period_is_shared_between_draining_and_detached_work() {
        let (trigger, _request) = tokio::sync::oneshot::channel();
        let grace_period = Duration::from_millis(500);
        let (result, remaining) = run_with_graceful_shutdown(
            async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok::<(), ()>(())
            },
            async { "SIGTERM" },
            trigger,
            grace_period,
        )
        .await;
        assert!(matches!(result, ShutdownResult::Completed(Ok(()))));
        assert!(
            remaining < grace_period && remaining > Duration::ZERO,
            "the drain must consume part of the budget, {remaining:?} left of {grace_period:?}"
        );
    }

    /// The reason the runtime is built by hand: dropping a runtime waits
    /// without limit for a `spawn_blocking` task that has already started,
    /// and this server deliberately hands SQLite work to such tasks. Without
    /// `shutdown_timeout` this test would take as long as the stuck task.
    #[test]
    fn shutdown_timeout_bounds_a_stuck_blocking_task() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn_blocking(|| std::thread::sleep(Duration::from_secs(30)));
        // let the blocking task start, so it is no longer cancellable
        runtime.block_on(async { tokio::time::sleep(Duration::from_millis(50)).await });

        let started = std::time::Instant::now();
        runtime.shutdown_timeout(Duration::from_millis(100));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait for detached blocking work must be bounded, took {:?}",
            started.elapsed()
        );
    }
}
