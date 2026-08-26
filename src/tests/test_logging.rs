use std::{
    future::Future,
    io::{self, Write},
    sync::{Arc, Mutex},
};

use axum::http::StatusCode;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::SubscriberExt;

use crate::{
    models::{FetchSecret, StoreSecret},
    tests::{BASE64_ENCRYPTED_SECRET, SHA256_111111, SHA256_222222, SHA256_CONCAT_111111_222222},
};

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

struct BufferWriter(LogBuffer);

impl Write for BufferWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 .0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = BufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BufferWriter(self.clone())
    }
}

impl LogBuffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

async fn capture<F: Future>(future: F) -> (F::Output, String) {
    let buffer = LogBuffer::default();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::TRACE)
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(buffer.clone()),
        );
    // Attach the owned dispatch to this future; it is installed for every poll
    // and does not replace the process-wide default subscriber.
    let dispatch = tracing::Dispatch::new(subscriber);
    let output = future.with_subscriber(dispatch).await;
    (output, buffer.text())
}

fn assert_no_sensitive_values(logs: &str, canary: &str) {
    let id_hash = crate::utils::identifier_hash(SHA256_111111).unwrap();
    let known_candidate = crate::utils::generate_secret_id(SHA256_111111, SHA256_222222);
    let miss_candidate =
        crate::utils::generate_secret_id(SHA256_111111, &crate::tests::distinct_candidate(0));
    for sensitive in [
        SHA256_111111,
        SHA256_222222,
        BASE64_ENCRYPTED_SECRET,
        SHA256_CONCAT_111111_222222,
        id_hash.as_str(),
        known_candidate.as_str(),
        miss_candidate.as_str(),
        canary,
    ] {
        assert!(
            !logs.contains(sensitive),
            "log leaked sensitive value {sensitive:?}: {logs}"
        );
    }
}

#[test]
fn test_request_ids_are_fixed_width_and_non_repeating() {
    let ids: std::collections::HashSet<_> = (0..1_000)
        .map(|_| crate::diagnostic::request_id())
        .collect();
    assert_eq!(ids.len(), 1_000);
    assert!(ids
        .iter()
        .all(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())));
}

#[test]
fn test_duration_bucket_boundaries_are_deterministic() {
    use std::time::Duration;
    assert_eq!(
        crate::diagnostic::duration_bucket(Duration::from_millis(499)),
        "lt500ms"
    );
    assert_eq!(
        crate::diagnostic::duration_bucket(Duration::from_millis(500)),
        "500ms_1s"
    );
    assert_eq!(
        crate::diagnostic::duration_bucket(Duration::from_secs(1)),
        "1s_5s"
    );
    assert_eq!(
        crate::diagnostic::duration_bucket(Duration::from_secs(5)),
        "gte5s"
    );
}

#[test]
fn test_status_categories_are_deterministic() {
    assert_eq!(crate::diagnostic::status_category(503), "overload");
    assert_eq!(crate::diagnostic::status_category(500), "server_error");
    assert_eq!(crate::diagnostic::status_category(429), "overload");
    assert_eq!(crate::diagnostic::status_category(400), "client_error");
}

#[tokio::test]
async fn test_request_id_header_ignores_client_value() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let response = server
        .get("/info")
        .add_header("x-request-id", "client-value")
        .await;
    let request_id = response.header("x-request-id");
    let id = request_id.to_str().unwrap();
    assert_eq!(id.len(), 64);
    assert_ne!(id, "client-value");
}

#[tokio::test]
async fn test_request_id_header_covers_public_sensitive_and_other_routes() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    for response in [
        server.get("/info").await,
        server.get("/attempts").await,
        server.post("/store").json(&serde_json::json!({})).await,
        server.get("/user-controlled/path?secret=fixture").await,
    ] {
        let request_id = response.header("x-request-id");
        let id = request_id.to_str().unwrap();
        assert_eq!(id.len(), 64);
    }
}

#[tokio::test]
async fn test_other_route_logs_do_not_contain_user_path_or_header() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let (_, logs) = capture(async {
        server
            .get("/user-controlled/path?secret=fixture-secret")
            .add_header("x-request-id", "client-controlled-id")
            .await
    })
    .await;
    assert!(
        logs.contains("route=\"other\""),
        "missing static other route: {logs}"
    );
    assert!(!logs.contains("user-controlled"));
    assert!(!logs.contains("fixture-secret"));
    assert!(!logs.contains("client-controlled-id"));
    assert!(state.security_counters.flush().diagnostic_logs_emitted > 0);
}

#[tokio::test]
async fn test_debug_request_logging_is_quota_bounded() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let (_, logs) = capture(async {
        for _ in 0..1_000 {
            let _ = server.get("/unknown").await;
        }
    })
    .await;
    let detailed = logs
        .lines()
        .filter(|line| line.contains("request completed"))
        .count();
    assert!(
        detailed <= 10,
        "request diagnostics escaped quota: {detailed}"
    );
    let counters = state.security_counters.flush();
    assert_eq!(
        counters.diagnostic_logs_emitted + counters.diagnostic_logs_suppressed,
        1_000
    );
    assert!(counters.diagnostic_logs_suppressed >= 990);
}

#[tokio::test]
async fn test_sensitive_operations_do_not_log_secret_material() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let store = StoreSecret {
        identifier: SHA256_111111.to_owned(),
        authentication_key: SHA256_222222.to_owned(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_owned(),
    };
    let fetch = FetchSecret {
        identifier: SHA256_111111.to_owned(),
        authentication_key: SHA256_222222.to_owned(),
    };

    let (responses, logs) = capture(async {
        let stored = server.post("/store").json(&store).await;
        let released = server.post("/fetch").json(&fetch).await;
        let miss = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_owned(),
                authentication_key: crate::tests::distinct_candidate(0),
            })
            .await;
        let trashed = server.post("/trash").json(&fetch).await;
        // Replaying the known-miss candidate exercises the rejected path after
        // the successful store/fetch/trash flow without introducing a fixture.
        let rejected_replay = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_owned(),
                authentication_key: crate::tests::distinct_candidate(0),
            })
            .await;
        (
            stored.status_code(),
            released.status_code(),
            miss.status_code(),
            trashed.status_code(),
            rejected_replay.status_code(),
        )
    })
    .await;

    assert_eq!(responses.0, StatusCode::CREATED);
    assert_eq!(responses.1, StatusCode::OK);
    assert_eq!(responses.2, StatusCode::UNAUTHORIZED);
    assert_eq!(responses.3, StatusCode::ACCEPTED);
    assert_eq!(responses.4, StatusCode::UNAUTHORIZED);
    assert_no_sensitive_values(&logs, &state.canary);
}

#[tokio::test]
async fn test_canary_updates_and_wipe_do_not_log_canary_value() {
    let mut state = crate::env::init();
    state.canary_from_env = false;
    let canary_path = std::env::temp_dir().join(format!(
        "recoverbull-test-logging-canary-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    state.canary_path = canary_path.clone();
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();
    let first = "logging-canary-first";
    let second = "logging-canary-second";

    std::fs::write(&canary_path, format!("CANARY={first}\n")).unwrap();
    let (_, first_logs) = capture(async { server.get("/info").await }).await;
    std::fs::write(&canary_path, format!("CANARY={second}\n")).unwrap();
    let (_, second_logs) = capture(async {
        crate::rate_limit::wipe_identifier_rate_limit(&state).await;
        server.get("/info").await
    })
    .await;
    std::fs::write(&canary_path, "OTHER=value\n").unwrap();
    let (_, removed_logs) = capture(async { server.get("/info").await }).await;
    std::fs::remove_file(canary_path).unwrap();

    for logs in [first_logs, second_logs, removed_logs] {
        assert!(!logs.contains(first), "log leaked the first canary: {logs}");
        assert!(
            !logs.contains(second),
            "log leaked the second canary: {logs}"
        );
    }
}

#[tokio::test]
async fn test_database_error_logs_are_diagnostic_without_sensitive_details() {
    use diesel::RunQueryDsl;

    let (server, state) = crate::tests::test_server::new_test_server().await;
    let mut connection =
        crate::storage::sqlite::establish_connection(state.database_url.clone()).unwrap();
    diesel::sql_query("DROP TABLE secret")
        .execute(&mut connection)
        .unwrap();
    let request = FetchSecret {
        identifier: SHA256_111111.to_owned(),
        authentication_key: SHA256_222222.to_owned(),
    };

    let (response, logs) = capture(async { server.post("/fetch").json(&request).await }).await;
    assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_no_sensitive_values(&logs, &state.canary);
    assert!(
        !logs.contains(&state.database_url),
        "log leaked the database path: {logs}"
    );
    assert!(!logs.contains("SELECT"));
    assert!(!logs.contains(SHA256_CONCAT_111111_222222));
}

/// The external PoC sends 10,000 requests; 1,000 is sufficient here to prove
/// the event-volume contract while keeping this Rust test fast. Counter
/// saturation overflow is intentionally deferred until an aggregate counter
/// implementation exists.
#[tokio::test]
async fn test_global_lookup_rejection_logging_is_bounded() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    *state.lookup_token_bucket.lock().await = crate::rate_limit::TokenBucket::new(1.0, 0.0);
    let request = FetchSecret {
        identifier: SHA256_111111.to_owned(),
        authentication_key: SHA256_222222.to_owned(),
    };

    let (statuses, logs) = capture(async {
        let mut statuses = Vec::with_capacity(1_000);
        for _ in 0..1_000 {
            statuses.push(server.post("/fetch").json(&request).await.status_code());
        }
        statuses
    })
    .await;

    assert_eq!(statuses[0], StatusCode::UNAUTHORIZED);
    assert!(statuses[1..]
        .iter()
        .all(|status| *status == StatusCode::SERVICE_UNAVAILABLE));
    let warning_lines = logs
        .lines()
        .filter(|line| line.contains("global lookup rate-limit exceeded"))
        .count();
    assert!(
        warning_lines <= 2,
        "expected O(1) rejection warnings, observed {warning_lines}: {logs}"
    );
    assert_eq!(state.security_counters.flush().lookup_rate_limited, 999);
}

#[test]
fn test_security_counter_saturates_and_flush_resets() {
    let counters = crate::security_counters::SecurityCounters::default();
    counters.set_database_error_for_test(u64::MAX - 1);
    counters.database_error();
    counters.database_error();
    assert_eq!(counters.flush().database_error, u64::MAX);
    assert_eq!(counters.flush().database_error, 0);
}

#[test]
fn test_diagnostic_counters_saturate_and_flush() {
    let counters = crate::security_counters::SecurityCounters::default();
    counters.set_diagnostic_logs_for_test(u64::MAX - 1, u64::MAX - 1);
    counters.diagnostic_logs_emitted();
    counters.diagnostic_logs_emitted();
    counters.diagnostic_logs_suppressed();
    counters.diagnostic_logs_suppressed();
    let snapshot = counters.flush();
    assert_eq!(snapshot.diagnostic_logs_emitted, u64::MAX);
    assert_eq!(snapshot.diagnostic_logs_suppressed, u64::MAX);
    assert_eq!(counters.flush().diagnostic_logs_emitted, 0);
    assert_eq!(counters.flush().diagnostic_logs_suppressed, 0);
}

#[tokio::test]
async fn test_counter_report_is_one_line_and_resets_window() {
    let (_, state) = crate::tests::test_server::new_test_server().await;
    state.security_counters.store_rejected();
    let (_, logs) = capture(async {
        crate::security_counters::report_once(&state);
    })
    .await;
    assert_eq!(logs.lines().count(), 1, "unexpected counter report: {logs}");
    assert_eq!(state.security_counters.flush().store_rejected, 0);
}
