//! Adversarial contract tests: they pin the structural wire contract the
//! clients depend on, so a drift on the server side breaks loudly here rather
//! than silently in a client. These tests deliberately avoid treating
//! human-readable error text as a protocol discriminator.

use crate::{
    models::{FetchSecret, StoreSecret},
    tests::{BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
    utils::{identifier_hash, truncate_to_hour},
};
use axum::http::StatusCode;
use chrono::Timelike;
use std::io::Read;

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
    state.attempts_snapshot_ttl = std::time::Duration::ZERO;
    crate::database::init_db(state.clone());
    let server = axum_test::TestServer::new(crate::router::new(state.clone())).unwrap();

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
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // exhaust the per-identifier budget
    for _ in 0..state.rate_limit_max_attempts {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: NOT_PASSWORD_HASH.to_string(),
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
    *state.attempts_token_bucket.lock().await = crate::rate_limit::TokenBucket::new(0.0, 0.0);
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
    crate::database::init_db(state.clone());
    let server = axum_test::TestServer::new(crate::router::new(state.clone())).unwrap();

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
    crate::database::init_db(state.clone());
    let server = axum_test::TestServer::new(crate::router::new(state.clone())).unwrap();

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
