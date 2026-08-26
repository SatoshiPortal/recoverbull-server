use crate::{
    models::{AttemptsSnapshot, FetchSecret, RateLimitInfo, StoreSecret},
    tests::{BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
    utils::sha256_hex,
};
use axum::http::StatusCode;
use chrono::Timelike;
use std::io::Read;
use std::sync::atomic::Ordering;

fn decode_gzip(body: &[u8]) -> (String, AttemptsSnapshot) {
    let mut decoder = flate2::read::GzDecoder::new(body);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).unwrap();
    let text = String::from_utf8(decoded).unwrap();
    let snapshot = serde_json::from_str(&text).unwrap();
    (text, snapshot)
}

fn assert_hour_truncated(timestamp: chrono::DateTime<chrono::Utc>) {
    assert_eq!(timestamp.minute(), 0, "timestamp must be hour-truncated");
    assert_eq!(timestamp.second(), 0);
    assert_eq!(timestamp.nanosecond(), 0);
}

#[tokio::test]
async fn test_attempts_publish_hashed_identifier_with_counters() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    // two failed attempts
    for index in 0..2 {
        let response = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: crate::tests::distinct_candidate(index),
            })
            .expect_failure()
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    let response = server.get("/attempts").expect_success().await;
    assert_eq!(response.header("content-encoding"), "gzip");
    assert!(response.maybe_header("vary").is_none());

    let (body, snapshot) = decode_gzip(response.as_bytes());

    // the raw identifier must never leak, compressed or not
    assert!(!body.contains(SHA256_111111));

    assert_eq!(snapshot.version, 1);
    assert_hour_truncated(snapshot.collection_started_at);
    assert_eq!(snapshot.entries.len(), 1);

    let entry = &snapshot.entries[0];
    let expected_id_hash = sha256_hex(&hex::decode(SHA256_111111).unwrap());
    assert_eq!(entry.id_hash, expected_id_hash);
    assert_eq!(entry.total_attempts, 2);
    assert_eq!(entry.failed_attempts, 2);
    assert_eq!(entry.total_requests, 2);
    assert_hour_truncated(entry.window_started_at);
    assert_hour_truncated(entry.last_attempt_at);
}

/// The id_hash algorithm is pinned by a shared test vector with the client:
/// sha256(hex_decode(identifier)) — raw bytes, not the hex string. The client
/// pins the same value; a drift on either side breaks the match loudly.
#[test]
fn test_attempts_id_hash_matches_shared_client_vector() {
    let expected = "f5bb872a08ef929e6744d117a69d4073ee7b5df4f5d7a4ecdd606f30a58f76db";
    assert_eq!(
        crate::utils::identifier_hash(SHA256_111111).unwrap(),
        expected
    );
}

#[tokio::test]
async fn test_attempts_count_hits_and_planted_rows() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    server.post("/store").json(&store).expect_success().await;

    // two misses, then a hit: the hit consumes the budget without counting
    // as a failure
    for index in 0..2 {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: crate::tests::distinct_candidate(index),
            })
            .expect_failure()
            .await;
    }
    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;

    let response = server.get("/attempts").expect_success().await;
    let (_, snapshot) = decode_gzip(response.as_bytes());
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].total_attempts, 3);
    assert_eq!(snapshot.entries[0].failed_attempts, 2);
    assert_eq!(snapshot.entries[0].total_requests, 3);
}

#[tokio::test]
async fn test_fetch_success_reports_status_without_resetting_attempt_budget() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    server.post("/store").json(&store).expect_success().await;

    // two failed attempts
    for index in 0..2 {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: crate::tests::distinct_candidate(index),
            })
            .expect_failure()
            .await;
    }

    // successful fetch reports the full attempt status
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;
    let body = response.json::<serde_json::Value>();
    let attempt_status = &body["attempt_status"];
    assert_eq!(attempt_status["total_attempts"], 3);
    assert_eq!(attempt_status["failed_attempts"], 2);
    assert_eq!(attempt_status["remaining_attempts"], 0);
    assert!(attempt_status["previous_attempt_at"].is_string());
    assert!(attempt_status["window_started_at"].is_string());
    assert!(attempt_status["resets_at"].is_string());
    assert!(body.get("failed_attempts").is_none());

    // The successful lookup is the third consultation and must remain in the
    // security budget. The two actual misses remain visible separately.
    let response = server.get("/attempts").expect_success().await;
    let (_, snapshot) = decode_gzip(response.as_bytes());
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].total_attempts, 3);
    assert_eq!(snapshot.entries[0].failed_attempts, 2);

    // A subsequent request is denied even with the correct key: database hits
    // cannot reset the budget because callers can plant their own rows.
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.header("retry-after").to_str().is_ok());
}

#[tokio::test]
async fn test_attempts_snapshot_etag_and_conditional_requests() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let response = server.get("/attempts").expect_success().await;
    let etag = response.header("etag").to_str().unwrap().to_owned();
    let cache_control = response
        .header("cache-control")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cache_control.starts_with("public, max-age="));
    let max_age: u64 = cache_control
        .strip_prefix("public, max-age=")
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&max_age));

    // a matching conditional request reuses the snapshot without a body
    let not_modified = server
        .get("/attempts")
        .add_header("If-None-Match", etag.as_str())
        .await;
    assert_eq!(not_modified.status_code(), StatusCode::NOT_MODIFIED);
    assert!(not_modified.as_bytes().is_empty());
    assert_eq!(not_modified.header("etag"), etag.as_str());

    // a wildcard conditional request matches any current representation
    let wildcard = server
        .get("/attempts")
        .add_header("If-None-Match", "*")
        .await;
    assert_eq!(wildcard.status_code(), StatusCode::NOT_MODIFIED);

    // RFC 9110: If-None-Match uses weak comparison — a weak validator
    // matches our strong ETag
    let weak = server
        .get("/attempts")
        .add_header("If-None-Match", format!("W/{etag}"))
        .await;
    assert_eq!(weak.status_code(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn test_attempts_snapshot_rebuild_is_deterministic() {
    let mut state = crate::env::init();
    // force a rebuild on every request
    state.attempts_snapshot_ttl = std::time::Duration::ZERO;
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state)).unwrap();

    // unchanged activity: the ETag survives rebuilds
    let first = server.get("/attempts").expect_success().await;
    let second = server.get("/attempts").expect_success().await;
    assert_eq!(first.header("etag"), second.header("etag"));

    // new activity: the ETag changes
    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    let third = server.get("/attempts").expect_success().await;
    assert_ne!(first.header("etag"), third.header("etag"));
}

/// A cancelled initiator must not cancel the single snapshot rebuild. The
/// explicit worker gate makes the cancellation happen after build start and
/// makes a second build observable on the unfixed implementation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cancelled_attempts_request_keeps_single_rebuild_in_flight() {
    let (_server, mut state) = crate::tests::test_server::new_test_server().await;
    state.attempts_snapshot_ttl = std::time::Duration::ZERO;
    state
        .attempts_build_probe
        .hold
        .store(true, Ordering::SeqCst);
    let first_state = state.clone();
    let first = tokio::spawn(async move {
        crate::handlers::attempts::get_attempts(
            axum::extract::State(first_state),
            axum::http::HeaderMap::new(),
        )
        .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        state.attempts_build_probe.started_notify.notified(),
    )
    .await
    .expect("snapshot worker did not start within 5 seconds");
    first.abort();

    let second_state = state.clone();
    let second = tokio::spawn(async move {
        crate::handlers::attempts::get_attempts(
            axum::extract::State(second_state),
            axum::http::HeaderMap::new(),
        )
        .await
    });
    state
        .attempts_build_probe
        .released
        .store(true, Ordering::SeqCst);
    state.attempts_build_probe.release.notify_one();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), second)
        .await
        .expect("joined snapshot request did not complete within 5 seconds")
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let builds_started = state.attempts_build_probe.started.load(Ordering::SeqCst);
    assert_eq!(
        builds_started, 1,
        "the second request must join the rebuild started by the cancelled request"
    );
}

#[tokio::test]
async fn test_attempts_entries_are_sorted_by_id_hash() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    for identifier in [SHA256_222222, SHA256_111111] {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: identifier.to_string(),
                authentication_key: NOT_PASSWORD_HASH.to_string(),
            })
            .expect_failure()
            .await;
    }

    let response = server.get("/attempts").expect_success().await;
    let (_, snapshot) = decode_gzip(response.as_bytes());
    assert_eq!(snapshot.entries.len(), 2);
    let hashes: Vec<&str> = snapshot
        .entries
        .iter()
        .map(|entry| entry.id_hash.as_str())
        .collect();
    let mut sorted = hashes.clone();
    sorted.sort_unstable();
    assert_eq!(
        hashes, sorted,
        "entries must be sorted for a deterministic representation"
    );
}

#[tokio::test]
async fn test_attempts_omit_entries_after_cooldown_without_waiting_for_sweeper() {
    let state = crate::env::init();
    {
        let mut entries = state.identifier_rate_limit.lock().await;
        let window_started_at =
            chrono::Utc::now() - state.rate_limit_cooldown - chrono::Duration::seconds(1);
        entries.insert(
            crate::utils::identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                window_started_at,
                last_candidate_at: window_started_at,
                last_request_at: window_started_at,
                candidates: std::collections::HashMap::new(),
                failed_candidates: 1,
                total_requests: 1,
            },
        );
    }
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state)).unwrap();

    let response = server.get("/attempts").expect_success().await;
    let (_, snapshot) = decode_gzip(response.as_bytes());
    assert!(snapshot.entries.is_empty());
}

#[tokio::test]
async fn test_attempts_last_attempt_at_is_last_distinct_candidate() {
    let mut state = crate::env::init();
    state.rate_limit_cooldown = chrono::TimeDelta::hours(24);
    let now = chrono::Utc::now();
    let window_started_at = now - chrono::TimeDelta::hours(4);
    let last_candidate_at = now - chrono::TimeDelta::hours(2);
    let last_request_at = now - chrono::TimeDelta::hours(1);
    {
        let mut entries = state.identifier_rate_limit.lock().await;
        entries.insert(
            crate::utils::identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                window_started_at,
                last_candidate_at,
                last_request_at,
                candidates: std::collections::HashMap::new(),
                failed_candidates: 1,
                total_requests: 4,
            },
        );
    }
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state)).unwrap();

    let response = server.get("/attempts").expect_success().await;
    let (_, snapshot) = decode_gzip(response.as_bytes());
    assert_eq!(
        snapshot.entries[0].last_attempt_at,
        crate::utils::truncate_to_hour(last_candidate_at)
    );
    assert_eq!(snapshot.entries[0].total_requests, 4);
}

#[tokio::test]
async fn test_attempts_rate_limit_bucket() {
    let mut state = crate::env::init();
    state.attempts_token_bucket = std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::rate_limit::TokenBucket::new(1.0, 0.0),
    ));
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state)).unwrap();

    server.get("/attempts").expect_success().await;
    let response = server.get("/attempts").await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.header("retry-after").to_str().is_ok());
}

#[tokio::test]
async fn test_stats_route_is_not_exposed() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    assert_eq!(
        server.get("/stats").await.status_code(),
        StatusCode::NOT_FOUND
    );
}

/// Fill the rate-limit map to its configured capacity (100,000) and request
/// /attempts: the build must complete in bounded time with bounded output,
/// and the second request must be served from the cache with the same ETag.
/// This is the worst case the deployment guardrails are sized for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_attempts_snapshot_at_full_map_scale() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    let now = chrono::Utc::now();
    {
        let mut map = state.identifier_rate_limit.lock().await;
        for i in 0..100_000u32 {
            map.insert(
                format!("{:064x}", i),
                crate::models::RateLimitInfo {
                    window_started_at: now,
                    last_candidate_at: now,
                    last_request_at: now,
                    candidates: std::collections::HashMap::new(),
                    failed_candidates: 0,
                    total_requests: 1,
                },
            );
        }
    }

    let started = std::time::Instant::now();
    let response = server.get("/attempts").await;
    let first_build = started.elapsed();

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: &[u8] = response.as_bytes();
    let (raw, snapshot) = decode_gzip(body);
    assert_eq!(snapshot.entries.len(), 100_000);

    println!(
        "full-map snapshot: build={first_build:?} gzip={}B json={}B",
        body.len(),
        raw.len()
    );
    assert!(
        first_build < std::time::Duration::from_secs(10),
        "snapshot build at full scale exceeded 10s: {first_build:?}"
    );

    // Second request within the TTL: cached, same ETag, fast.
    let started = std::time::Instant::now();
    let second = server.get("/attempts").await;
    let cached_serve = started.elapsed();
    assert_eq!(second.header("etag"), response.header("etag"));
    assert!(cached_serve < std::time::Duration::from_secs(1));
}
