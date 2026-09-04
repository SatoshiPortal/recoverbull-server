use std::{
    future::Future,
    io::{self, Write},
    sync::{Arc, Mutex},
};

use axum::http::StatusCode;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::SubscriberExt;

use crate::{
    http::contract::{FetchSecret, StoreSecret},
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

pub(crate) async fn capture<F: Future>(future: F) -> (F::Output, String) {
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
    let id_hash = crate::recovery::identifiers::identifier_hash(SHA256_111111).unwrap();
    let known_candidate =
        crate::recovery::identifiers::generate_secret_id(SHA256_111111, SHA256_222222);
    let miss_candidate = crate::recovery::identifiers::generate_secret_id(
        SHA256_111111,
        &crate::tests::distinct_candidate(0),
    );
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

/// Request IDs are fixed width, unique, and — the part that matters — not
/// the request counter. A bare counter would let any client subtract two IDs
/// and read how many requests the server handled in between, an activity
/// oracle no endpoint publishes.
#[test]
fn test_request_ids_are_opaque_fixed_width_and_non_repeating() {
    let ids: Vec<_> = (0..1_000)
        .map(|_| crate::observability::diagnostic::request_id())
        .collect();
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), 1_000);
    assert!(ids
        .iter()
        .all(|id| id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit())));

    let values: Vec<u64> = ids
        .iter()
        .map(|id| u64::from_str_radix(id, 16).unwrap())
        .collect();
    let consecutive = values
        .windows(2)
        .filter(|pair| pair[1] == pair[0] + 1)
        .count();
    assert!(
        consecutive < 10,
        "request IDs must not expose the request counter, {consecutive} consecutive pairs"
    );
}

/// Paths are never logged as text: an unknown target collapses to the static
/// `other` enum, so a client cannot place its own bytes in a log line.
#[test]
fn test_unknown_routes_collapse_to_a_static_enum() {
    use crate::observability::diagnostic::route_kind;
    assert_eq!(route_kind("/user-controlled/path"), "other");
    assert_eq!(route_kind("/fetch"), "fetch");
    assert_eq!(route_kind("/attempts"), "attempts");
}

/// **A server error leaves one line; a `503` leaves none because it is
/// pressure.** Those two sentences are the whole logging policy, and this
/// test is their oracle: every status this service can return to a client,
/// `503` included, is driven through the router and must produce no line.
///
/// It replaces a two-class quota system whose status-to-category table
/// misfiled `304` into the WARN class, so ordinary conditional polling raised
/// false server-error alarms and starved the budget a genuine `500` needed.
/// With one rule there is no table to misfile and no budget to starve.
#[tokio::test]
async fn test_only_a_genuine_server_error_is_logged() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let request = FetchSecret {
        identifier: SHA256_111111.to_owned(),
        authentication_key: SHA256_222222.to_owned(),
    };

    let (statuses, logs) = capture(async {
        let mut statuses = Vec::new();
        // 200 and a conditional 304 on the documented polling path
        statuses.push(server.get("/info").await.status_code());
        let primed = server.get("/attempts").await;
        let etag = primed.header("etag").to_str().unwrap().to_string();
        statuses.push(primed.status_code());
        statuses.push(
            server
                .get("/attempts")
                .add_header("If-None-Match", etag)
                .await
                .status_code(),
        );
        // 400 invalid body, 401 wrong credentials, 404 unknown route,
        // 405 wrong method, 413 oversized body
        statuses.push(
            server
                .post("/fetch")
                .json(&serde_json::json!({ "identifier": "short" }))
                .await
                .status_code(),
        );
        statuses.push(server.post("/fetch").json(&request).await.status_code());
        statuses.push(server.get("/unknown").await.status_code());
        statuses.push(server.get("/fetch").await.status_code());
        statuses.push(
            server
                .post("/fetch")
                .json(&serde_json::json!({
                    "identifier": SHA256_111111,
                    "authentication_key": SHA256_222222,
                    "pad": "x".repeat(2048),
                }))
                .await
                .status_code(),
        );
        // 503 from an exhausted global bucket: the one 5xx a client can
        // trigger at will, and the reason the rule has an exception
        state
            .recovery
            .set_lookup_bucket_for_test(crate::rate_limit::TokenBucket::new(1.0, 0.0))
            .await;
        server.post("/fetch").json(&request).await;
        statuses.push(server.post("/fetch").json(&request).await.status_code());
        statuses
    })
    .await;

    assert!(
        statuses
            .iter()
            .all(|status| status.as_u16() < 500 || status.as_u16() == 503),
        "fixture must only produce responses below 500 plus the 503: {statuses:?}"
    );
    // The capture subscriber enables every level, so axum's own extractor
    // rejections appear here at TRACE (invisible under the default `info`
    // filter). What must never appear is a line from this server's
    // diagnostics, which is the only thing WARN-visible by default.
    assert!(
        !logs.contains("request failed") && !logs.contains("WARN"),
        "only a genuine server error may be logged: {logs}"
    );
    assert_no_sensitive_values(&logs, state.info.canary_for_test());
}

/// The `304` of a conditional `GET /attempts` is the caching path the README
/// tells clients to use, and a client may poll it continuously. Pinned on its
/// own because misfiling exactly this status is what broke the previous
/// design.
#[tokio::test]
async fn test_conditional_polling_is_never_logged() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    state
        .attempts
        .maintenance
        .set_bucket_for_test(crate::rate_limit::TokenBucket::new(10_000.0, 10_000.0))
        .await;
    let etag = server
        .get("/attempts")
        .expect_success()
        .await
        .header("etag")
        .to_str()
        .unwrap()
        .to_string();

    let (statuses, logs) = capture(async {
        let mut statuses = Vec::new();
        for _ in 0..40 {
            statuses.push(
                server
                    .get("/attempts")
                    .add_header("If-None-Match", etag.clone())
                    .await
                    .status_code(),
            );
        }
        statuses
    })
    .await;

    assert!(
        statuses
            .iter()
            .all(|status| *status == StatusCode::NOT_MODIFIED),
        "every conditional poll must be a 304, got {statuses:?}"
    );
    assert!(
        logs.is_empty(),
        "conditional polling must produce no log line at all: {logs}"
    );
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
    assert_eq!(id.len(), 16);
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
        assert_eq!(id.len(), 16);
    }
}

/// A request to an attacker-chosen path with an attacker-chosen request ID
/// leaves nothing behind: it is a `404`, so it produces no line, and the
/// client's `x-request-id` is dropped before routing rather than echoed.
#[tokio::test]
async fn test_user_controlled_path_and_header_never_reach_the_logs() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let (response, logs) = capture(async {
        server
            .get("/user-controlled/path?secret=fixture-secret")
            .add_header("x-request-id", "client-controlled-id")
            .await
    })
    .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    assert!(logs.is_empty(), "a 404 must produce no log line: {logs}");
    assert_ne!(
        response.header("x-request-id").to_str().unwrap(),
        "client-controlled-id",
        "the client value must never be reused"
    );
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
    assert_no_sensitive_values(&logs, state.info.canary_for_test());
}

#[tokio::test]
async fn test_canary_updates_and_wipe_do_not_log_canary_value() {
    let mut state = crate::app::init();
    state.info.set_canary_from_env_for_test(false);
    let canary_path = std::env::temp_dir().join(format!(
        "recoverbull-test-logging-canary-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    state.info.set_canary_path_for_test(canary_path.clone());
    state.storage.initialize().unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();
    let first = "logging-canary-first";
    let second = "logging-canary-second";

    std::fs::write(&canary_path, format!("CANARY={first}\n")).unwrap();
    let (_, first_logs) = capture(async { server.get("/info").await }).await;
    std::fs::write(&canary_path, format!("CANARY={second}\n")).unwrap();
    let (_, second_logs) = capture(async {
        crate::attempts::maintenance::wipe_identifier_rate_limit(
            &state.attempts.ledger,
            &state.attempts.snapshot,
        )
        .await;
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
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    diesel::sql_query("DROP TABLE secret")
        .execute(&mut connection)
        .unwrap();
    let request = FetchSecret {
        identifier: SHA256_111111.to_owned(),
        authentication_key: SHA256_222222.to_owned(),
    };

    let (response, logs) = capture(async { server.post("/fetch").json(&request).await }).await;
    assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    // exactly one line, at WARN so the default `info` filter lets it through,
    // carrying only the request ID, the static route and the status
    assert_eq!(
        logs.lines().count(),
        1,
        "one server error, one line: {logs}"
    );
    assert!(
        logs.contains("WARN"),
        "a 500 must be visible by default: {logs}"
    );
    assert!(
        logs.contains("route=\"fetch\"") && logs.contains("status=500"),
        "{logs}"
    );
    assert!(
        logs.contains(response.header("x-request-id").to_str().unwrap()),
        "the line must be correlatable with the response: {logs}"
    );
    assert_no_sensitive_values(&logs, state.info.canary_for_test());
    assert!(
        !logs.contains(&state.storage.database_url_for_test()),
        "log leaked the database path: {logs}"
    );
    assert!(!logs.contains("SELECT"));
    assert!(!logs.contains(SHA256_CONCAT_111111_222222));
}

/// Overload is counted, not logged. A thousand rejections produce no line at
/// all, so an attacker cannot use them to fill the disk or to push a genuine
/// server error out of a bounded log; the volume is visible in the
/// unconditional five-minute counter window instead.
#[tokio::test]
async fn test_global_lookup_rejections_are_counted_not_logged() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    state
        .recovery
        .set_lookup_bucket_for_test(crate::rate_limit::TokenBucket::new(1.0, 0.0))
        .await;
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
    assert!(
        logs.is_empty(),
        "1,000 overload rejections must produce no log line: {logs}"
    );
    assert_eq!(state.counters.flush().lookup_rate_limited, 999);
}

#[test]
fn test_security_counter_saturates_and_flush_resets() {
    let counters = crate::observability::counters::SecurityCounters::default();
    counters.set_database_error_for_test(u64::MAX - 1);
    counters.database_error();
    counters.database_error();
    assert_eq!(counters.flush().database_error, u64::MAX);
    assert_eq!(counters.flush().database_error, 0);
}

#[tokio::test]
async fn test_counter_report_is_one_line_and_resets_window() {
    let (_, state) = crate::tests::test_server::new_test_server().await;
    state.counters.store_rejected();
    let (_, logs) = capture(async {
        crate::observability::counters::report_once(&state.counters);
    })
    .await;
    assert_eq!(logs.lines().count(), 1, "unexpected counter report: {logs}");
    assert_eq!(state.counters.flush().store_rejected, 0);
}
