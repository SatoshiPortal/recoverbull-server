//! Adversarial contract tests: they pin the structural wire contract the
//! clients depend on, so a drift on the server side breaks loudly here rather
//! than silently in a client. These tests deliberately avoid treating
//! human-readable error text as a protocol discriminator.

use crate::{
    attempts::snapshot::truncate_to_hour,
    http::contract::{FetchSecret, StoreSecret},
    recovery::identifiers::identifier_hash,
    tests::{
        BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222,
        SHA256_CONCAT_111111_222222,
    },
};
use axum::http::StatusCode;
use chrono::Timelike;
use std::collections::BTreeSet;
use std::io::Read;

fn assert_lookup_success_contract(
    response: &axum_test::TestResponse,
    expected_status: StatusCode,
) -> serde_json::Value {
    assert_eq!(response.status_code(), expected_status);
    assert_eq!(response.header("content-type"), "application/json");

    let body = response.json::<serde_json::Value>();
    let object = body
        .as_object()
        .expect("lookup success body must be an object");
    assert_eq!(
        object.keys().cloned().collect::<BTreeSet<_>>(),
        ["attempt_status", "created_at", "encrypted_secret", "id",]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    );

    let attempt_status = body["attempt_status"]
        .as_object()
        .expect("attempt_status must be an object");
    assert_eq!(
        attempt_status.keys().cloned().collect::<BTreeSet<_>>(),
        [
            "failed_attempts",
            "previous_attempt_at",
            "remaining_attempts",
            "resets_at",
            "total_attempts",
            "total_requests",
            "version",
            "window_started_at",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
    );

    body
}

#[tokio::test]
async fn test_fetch_success_response_contract() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_owned(),
            authentication_key: SHA256_222222.to_owned(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_owned(),
        })
        .expect_success()
        .await;

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_owned(),
            authentication_key: SHA256_222222.to_owned(),
        })
        .expect_success()
        .await;
    let body = assert_lookup_success_contract(&response, StatusCode::OK);

    assert_eq!(body["id"], SHA256_CONCAT_111111_222222);
    assert!(
        body["created_at"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<chrono::Utc>>()
            .is_ok(),
        "created_at must be an RFC3339 timestamp"
    );
    assert_eq!(body["encrypted_secret"], BASE64_ENCRYPTED_SECRET);
    assert_eq!(body["attempt_status"]["version"], 1);
    assert_eq!(body["attempt_status"]["total_attempts"], 1);
    assert_eq!(body["attempt_status"]["failed_attempts"], 0);
    assert_eq!(body["attempt_status"]["remaining_attempts"], 2);
    assert_eq!(body["attempt_status"]["total_requests"], 1);
    assert!(body["attempt_status"]["previous_attempt_at"].is_null());
    assert!(body["attempt_status"]["window_started_at"]
        .as_str()
        .is_some());
    assert!(body["attempt_status"]["resets_at"].as_str().is_some());
}

#[tokio::test]
async fn test_trash_success_response_contract() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_owned(),
            authentication_key: SHA256_222222.to_owned(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_owned(),
        })
        .expect_success()
        .await;

    let response = server
        .post("/trash")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_owned(),
            authentication_key: SHA256_222222.to_owned(),
        })
        .expect_success()
        .await;
    let body = assert_lookup_success_contract(&response, StatusCode::ACCEPTED);

    assert_eq!(body["id"], SHA256_CONCAT_111111_222222);
    assert!(
        body["created_at"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<chrono::Utc>>()
            .is_ok(),
        "created_at must be an RFC3339 timestamp"
    );
    assert_eq!(body["encrypted_secret"], BASE64_ENCRYPTED_SECRET);
    assert_eq!(body["attempt_status"]["version"], 1);
    assert_eq!(body["attempt_status"]["total_attempts"], 1);
    assert_eq!(body["attempt_status"]["failed_attempts"], 0);
    assert_eq!(body["attempt_status"]["remaining_attempts"], 2);
    assert_eq!(body["attempt_status"]["total_requests"], 1);
    assert!(body["attempt_status"]["previous_attempt_at"].is_null());
    assert!(body["attempt_status"]["window_started_at"]
        .as_str()
        .is_some());
    assert!(body["attempt_status"]["resets_at"].as_str().is_some());
}

/// The `/attempts` body is always gzip: decode before parsing.
fn decode_snapshot(body: &[u8]) -> serde_json::Value {
    let mut decoder = flate2::read::GzDecoder::new(body);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).unwrap();
    serde_json::from_slice(&decoded).unwrap()
}

/// The contract behind bull-3 finding #2: `attempt_status` (direct response)
/// carries EXACT timestamps, while the public `/attempts` snapshot is
/// HOUR-TRUNCATED. A client comparing the two windows for equality must
/// truncate first — pin the asymmetry so it is never "fixed" into a match
/// by accident (which would break the privacy rationale of the snapshot).
#[tokio::test]
async fn test_attempt_status_is_exact_while_snapshot_is_hour_truncated() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;

    // the direct response's window is exact (second precision)
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    let exact_window = response.json::<serde_json::Value>()["requested_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();

    // the public snapshot's window for the same identifier is hour-truncated
    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    let entry = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id_hash"] == identifier_hash(SHA256_111111).unwrap())
        .expect("the identifier must appear in the snapshot");
    let snapshot_window = entry["window_started_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();

    assert_eq!(
        snapshot_window,
        truncate_to_hour(exact_window),
        "the snapshot window must be the hour-truncated direct window"
    );
    assert_eq!(
        snapshot_window.second(),
        0,
        "the snapshot window must be truncated (no sub-hour precision)"
    );
    assert_eq!(snapshot_window.minute(), 0);
}

/// The contract behind bull-3 finding #3: `/store` is NOT counted in the
/// rate-limit map and never appears in `/attempts`. A client counting its own
/// store as an attempt would inflate its baseline and mask a real probe.
#[tokio::test]
async fn test_store_is_not_counted_in_attempts() {
    // a zero snapshot TTL forces a rebuild on every poll, so the test sees
    // fresh state at each step instead of the first cached snapshot
    let mut state = crate::env::init();
    state
        .attempts_snapshot
        .set_ttl_for_test(std::time::Duration::ZERO);
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };

    // a store alone creates no rate-limit entry
    server.post("/store").json(&store).expect_success().await;
    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    assert!(
        !body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["id_hash"] == identifier_hash(SHA256_111111).unwrap()),
        "a store alone must not appear in /attempts"
    );

    // after a fetch, a subsequent store does not increment the counter
    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;
    server.post("/store").json(&store).expect_success().await;

    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    let entry = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id_hash"] == identifier_hash(SHA256_111111).unwrap())
        .expect("the fetch must appear in the snapshot");
    assert_eq!(
        entry["total_attempts"], 1,
        "the store must not increment the attempt counter"
    );
}

/// A targeted lockout is the only 429 response and carries targeted metadata.
#[tokio::test]
async fn test_targeted_429_has_targeted_metadata() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    // exhaust the per-identifier budget
    for index in 0..3 {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: crate::tests::distinct_candidate(index),
            })
            .expect_failure()
            .await;
    }

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
    let body = response.json::<serde_json::Value>();
    for field in ["attempts", "requested_at", "rate_limit_cooldown"] {
        assert!(
            body.get(field).is_some(),
            "targeted 429 must include {field}"
        );
    }
    let retry_after = response
        .header("retry-after")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .expect("Retry-After must be a positive integer number of seconds");
    assert!(retry_after > 0, "Retry-After must be a positive backoff");
}

/// Global buckets all use 503 and carry no targeted-attempt metadata.
#[tokio::test]
async fn test_global_buckets_use_503_without_targeted_metadata() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // exhaust the global lookup bucket
    *state.lookup_token_bucket.lock().await = crate::rate_limit::TokenBucket::new(0.0, 0.0);
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.json::<serde_json::Value>();
    for field in ["attempts", "requested_at", "rate_limit_cooldown"] {
        assert!(
            body.get(field).is_none(),
            "global lookup 503 must not include {field}"
        );
    }
    assert!(response
        .header("retry-after")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .is_ok());

    // exhaust the global store bucket
    *state.store_token_bucket.lock().await = crate::rate_limit::TokenBucket::new(0.0, 0.0);
    let response = server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.json::<serde_json::Value>();
    for field in ["attempts", "requested_at", "rate_limit_cooldown"] {
        assert!(
            body.get(field).is_none(),
            "global store 503 must not include {field}"
        );
    }
    assert!(response
        .header("retry-after")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .is_ok());

    // exhaust the global attempts bucket
    state
        .attempts_maintenance
        .set_bucket_for_test(crate::rate_limit::TokenBucket::new(0.0, 0.0))
        .await;
    let response = server.get("/attempts").expect_failure().await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.json::<serde_json::Value>();
    for field in ["attempts", "requested_at", "rate_limit_cooldown"] {
        assert!(
            body.get(field).is_none(),
            "global attempts 503 must not include {field}"
        );
    }
    assert!(response
        .header("retry-after")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .is_ok());
}

/// Capacity and database pressure both use 503 and carry `Retry-After`.
#[tokio::test]
async fn test_503_responses_have_no_machine_code() {
    // identifier-map capacity exhausted: force a full map so a brand new
    // identifier cannot get a slot.
    let mut state = crate::env::init();
    state.rate_limit_max_identifiers = 1;
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .await;
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_222222.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.json::<serde_json::Value>();
    assert!(body.get("error").is_some());
    assert!(response
        .header("retry-after")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .is_ok());

    // database busy: block the concurrency semaphore.
    let mut state = crate::env::init();
    state.database_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.json::<serde_json::Value>();
    assert!(body.get("error").is_some());
    assert!(response
        .header("retry-after")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .is_ok());
}
