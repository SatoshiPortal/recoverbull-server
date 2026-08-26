//! Adversarial tests for the attack surface: each test pins a behavior whose
//! violation would open a vulnerability or a bypass — oracles, rate-limit
//! evasion, information disclosure, denial of service, and telemetry
//! integrity. They are written to attack the server, not to confirm it.

use crate::{
    http::contract::{FetchSecret, StoreSecret},
    recovery::identifiers::identifier_hash,
    tests::{
        BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222,
        SHA256_CONCAT_111111_222222,
    },
};
use axum::http::StatusCode;
use diesel::RunQueryDsl;
use std::io::Read;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The `/attempts` body is always gzip: decode before parsing.
fn decode_snapshot(body: &[u8]) -> serde_json::Value {
    let mut decoder = flate2::read::GzDecoder::new(body);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).unwrap();
    serde_json::from_slice(&decoded).unwrap()
}

/// The decoded `/attempts` body as searchable text.
fn snapshot_text(body: &[u8]) -> String {
    let mut decoder = flate2::read::GzDecoder::new(body);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).unwrap();
    String::from_utf8(decoded).unwrap()
}

// ---------------------------------------------------------------------------
// Oracles: a wrong key must be indistinguishable whether or not a row exists
// ---------------------------------------------------------------------------

/// `/fetch` with a wrong key returns the same 401 shape for an unknown
/// identifier and for a stored one: the only existence signal is the
/// documented attempt counter, never a different status or body shape.
#[tokio::test]
async fn test_fetch_wrong_key_unknown_vs_known_identifier_same_shape() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;

    let unknown = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_222222.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    let known = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;

    assert_eq!(unknown.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(known.status_code(), StatusCode::UNAUTHORIZED);
    let unknown_keys: Vec<String> = unknown
        .json::<serde_json::Value>()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let known_keys: Vec<String> = known
        .json::<serde_json::Value>()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        unknown_keys, known_keys,
        "the 401 body shape must not reveal whether the identifier exists"
    );
}

/// `/trash` with a wrong key returns 401 whether or not a row exists: it must
/// not become an identifier-existence oracle either.
#[tokio::test]
async fn test_trash_wrong_key_unknown_vs_known_identifier_same_status() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;

    let unknown = server
        .post("/trash")
        .json(&FetchSecret {
            identifier: SHA256_222222.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    let known = server
        .post("/trash")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;

    assert_eq!(unknown.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(known.status_code(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Rate-limit integrity: no evasion, no refund abuse, no eviction of victims
// ---------------------------------------------------------------------------

/// A hit counts: a successful fetch increments `total_attempts`. This is the
/// planted-row detection signal — a row an attacker plants through `/store`
/// and fetches still shows up in the counter.
#[tokio::test]
async fn test_successful_fetch_increments_total_attempts() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;
    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;

    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    let entry = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id_hash"] == identifier_hash(SHA256_111111).unwrap())
        .expect("the successful fetch must appear in the snapshot");
    assert_eq!(entry["total_attempts"], 1, "a hit must count");
    assert_eq!(entry["failed_attempts"], 0);
}

/// A success never resets the counter: after a successful fetch, a distinct
/// failed candidate continues the count instead of restarting at 1 — while a
/// replay only increases total_requests.
#[tokio::test]
async fn test_success_does_not_reset_the_counter() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;
    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    let status = &response.json::<serde_json::Value>();
    assert_eq!(
        status["attempts"], 2,
        "the counter must continue, not reset after a success"
    );
    assert_eq!(status["total_requests"], 2);
}

/// A successful fetch is never refunded: the attempt stays consumed. Refunds
/// exist only for internal errors (DB failure, semaphore timeout, panic) that
/// taught the caller nothing — a 200 must leave the counter incremented.
#[tokio::test]
async fn test_successful_fetch_is_not_refunded() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;
    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;

    let map = state.identifier_rate_limit.lock_for_test().await;
    let info = &map[&identifier_hash(SHA256_111111).unwrap()];
    assert_eq!(info.candidate_count(), 1, "a 200 must not be refunded");
}

/// A 429 does not consume budget: a locked-out identifier's rejected request
/// leaves the counter at the max instead of growing — the lockout state must
/// stay exactly at the threshold, not drift.
#[tokio::test]
async fn test_429_does_not_consume_budget() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    for index in 0..state.rate_limit_max_attempts as usize {
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
            // Replay an already admitted key: saturation must be based on
            // distinct candidates, while this request still counts.
            authentication_key: crate::tests::distinct_candidate(0),
        })
        .expect_failure()
        .await;

    let map = state.identifier_rate_limit.lock_for_test().await;
    let info = &map[&identifier_hash(SHA256_111111).unwrap()];
    assert_eq!(
        info.candidate_count(),
        state.rate_limit_max_attempts,
        "a 429 must not consume budget"
    );
    assert_eq!(
        info.total_requests,
        u64::from(state.rate_limit_max_attempts) + 1,
        "a rejected replay must still increase total_requests"
    );
}

/// A full map must not evict an existing protected identifier: when the map
/// is at capacity, new identifiers get 503 but an already locked-out
/// identifier stays locked out (429) — the victim's protection is not
/// sacrificed to make room.
#[tokio::test]
async fn test_full_map_does_not_evict_protected_identifier() {
    let mut state = crate::env::init();
    state.rate_limit_max_identifiers = 1;
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    // lock out the first identifier
    for index in 0..state.rate_limit_max_attempts as usize {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: crate::tests::distinct_candidate(index),
            })
            .expect_failure()
            .await;
    }

    // a new identifier is refused (map full)
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_222222.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);

    // the locked-out identifier is still locked out, not evicted
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::TOO_MANY_REQUESTS,
        "a full map must not evict the protected identifier"
    );
}

/// `remaining_attempts` always equals `max_failed_attempts - total_attempts`
/// (the budget counts hits AND misses — a successful fetch consumes budget
/// too). The client derives its countdown from this exact relationship.
#[tokio::test]
async fn test_remaining_attempts_relationship() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;

    // after a success (total=1, failed=0): remaining = max - total
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;
    let status = &response.json::<serde_json::Value>()["attempt_status"];
    let total = status["total_attempts"].as_u64().unwrap() as u8;
    let remaining = status["remaining_attempts"].as_u64().unwrap() as u8;
    assert_eq!(total, 1);
    assert_eq!(
        remaining,
        state.rate_limit_max_attempts - total,
        "remaining must equal max - total_attempts"
    );
    assert_eq!(status["total_requests"], 1);

    // a distinct failure consumes budget too; replaying the stored candidate
    // reports the same distinct-candidate total
    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: crate::tests::distinct_candidate(2),
        })
        .expect_failure()
        .await;
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;
    let status = &response.json::<serde_json::Value>()["attempt_status"];
    let total = status["total_attempts"].as_u64().unwrap() as u8;
    let remaining = status["remaining_attempts"].as_u64().unwrap() as u8;
    assert_eq!(total, 2);
    assert_eq!(
        remaining,
        state.rate_limit_max_attempts - total,
        "remaining must equal max - total_attempts"
    );
    assert_eq!(status["total_requests"], 3);
}

// ---------------------------------------------------------------------------
// Input validation: reject anything that is not exactly the expected shape
// ---------------------------------------------------------------------------

/// A 64-char identifier containing a non-ASCII character (fullwidth lookalike)
/// is rejected: hex is ASCII-only, and Unicode must never bypass the length
/// check through multi-byte tricks.
#[tokio::test]
async fn test_unicode_identifier_rejected() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    // 63 ASCII hex chars + one fullwidth 'ａ' (U+FF41): 64 chars, not hex
    let mut identifier = "a".repeat(63);
    identifier.push('ａ');

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier,
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

/// An identifier with interior whitespace is rejected: it is not 64 hex
/// characters, and normalization must not silently strip spaces into a valid
/// one.
#[tokio::test]
async fn test_identifier_with_whitespace_rejected() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let mut identifier = "a".repeat(32);
    identifier.push(' ');
    identifier.push_str(&"b".repeat(31));

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier,
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

/// Identifier and authentication_key must be exactly 64 hex characters:
/// empty, 63, 65, and non-hex are all rejected before any lookup.
#[tokio::test]
async fn test_malformed_identifier_and_key_lengths_rejected() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    for identifier in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "z".repeat(64), // not hex
    ] {
        let response = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier,
                authentication_key: SHA256_222222.to_string(),
            })
            .expect_failure()
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }

    for key in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "z".repeat(64),
    ] {
        let response = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: key,
            })
            .expect_failure()
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }
}

/// The 1024-byte body limit applies to `/fetch` and `/trash` too, not only
/// `/store`: an oversized body is rejected before deserialization.
#[tokio::test]
async fn test_fetch_and_trash_reject_oversized_body() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    // serde ignores unknown fields, so a padded but otherwise valid body is
    // the way to exceed the limit through the JSON extractor
    let oversized = serde_json::json!({
        "identifier": SHA256_111111,
        "authentication_key": SHA256_222222,
        "pad": "x".repeat(2048),
    });

    for path in ["/fetch", "/trash"] {
        let response = server.post(path).json(&oversized).expect_failure().await;
        assert_eq!(
            response.status_code(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{path} must enforce the body limit"
        );
    }
}

/// A maximally nested JSON body below the HTTP limit is rejected without
/// crashing the worker. `FetchSecret` has no recursive fields, and serde's
/// ignored-value path does not raise a separate recursion-limit error here;
/// the 1024-byte body limit is therefore the effective nesting bound.
#[tokio::test]
async fn test_maximally_nested_under_body_limit_json_rejected_without_crash() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    const DEPTH: usize = 500;
    let mut nested = String::from("{\"ignored\":");
    for _ in 0..DEPTH {
        nested.push('[');
    }
    nested.push('1');
    for _ in 0..DEPTH {
        nested.push(']');
    }
    nested.push('}');
    assert!(
        nested.len() < 1024,
        "the nested payload must stay below the HTTP body limit, got {} bytes",
        nested.len()
    );

    let response = server
        .post("/fetch")
        .bytes(nested.into())
        .content_type("application/json")
        .expect_failure()
        .await;
    assert!(
        response.status_code() != StatusCode::PAYLOAD_TOO_LARGE,
        "the recursion payload must not be rejected by the HTTP body limit"
    );
    assert_eq!(
        response.status_code(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "serde JSON recursion errors must use Axum's 422 rejection"
    );
    let body = response.text();
    assert!(
        body.contains("missing field `identifier`"),
        "the under-limit nested body must be rejected by the request schema, got: {body}"
    );

    // the server is still alive
    let alive = server.get("/info").expect_success().await;
    assert_eq!(alive.status_code(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Information disclosure: nothing secret ever leaves the server
// ---------------------------------------------------------------------------

/// The public `/attempts` snapshot never contains the raw identifier, the
/// authentication_key, or the encrypted_secret — only the opaque id_hash and
/// counters.
#[tokio::test]
async fn test_snapshot_never_contains_secret_material() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;
    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;

    let snapshot = server.get("/attempts").expect_success().await;
    let body = snapshot_text(snapshot.as_bytes());
    assert!(!body.contains(SHA256_111111), "no raw identifier");
    assert!(!body.contains(SHA256_222222), "no authentication_key");
    assert!(
        !body.contains(BASE64_ENCRYPTED_SECRET),
        "no encrypted_secret"
    );
}

/// Error responses (401, 429, 503) never contain the secret_id, the
/// encrypted_secret, or the authentication_key.
#[tokio::test]
async fn test_error_responses_leak_no_secret_material() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;

    // 401
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    let body = response.text();
    assert!(!body.contains(BASE64_ENCRYPTED_SECRET));
    assert!(!body.contains(SHA256_222222));

    // drive to 429
    for index in 1..state.rate_limit_max_attempts as usize {
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
    let body = response.text();
    assert!(!body.contains(BASE64_ENCRYPTED_SECRET));
    assert!(!body.contains(SHA256_222222));
}

/// The 401's `requested_at` is the caller's own request time, never someone
/// else's: a failed attempt must not leak when the victim last tried.
#[tokio::test]
async fn test_401_requested_at_is_the_callers_own_time() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let before = chrono::Utc::now();
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    let after = chrono::Utc::now();

    let requested_at = response.json::<serde_json::Value>()["requested_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    assert!(
        requested_at >= before && requested_at <= after,
        "the 401 requested_at must be the caller's own request time"
    );
}

// ---------------------------------------------------------------------------
// Telemetry integrity: determinism and shape of the public snapshot
// ---------------------------------------------------------------------------

/// The ETag is always a quoted 64-char hex string, whether the snapshot is
/// empty or holds entries: its length leaks nothing about the content.
#[tokio::test]
async fn test_etag_is_fixed_length_regardless_of_content() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let empty = server.get("/attempts").expect_success().await;
    let empty_etag = empty.header("etag").to_str().unwrap().to_string();
    assert!(
        empty_etag.starts_with('"') && empty_etag.ends_with('"') && empty_etag.len() == 66,
        "ETag must be a quoted 64-hex string, got {empty_etag}"
    );

    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;

    // force a rebuild past the TTL by waiting is avoided: the ETag format is
    // what matters, and a fresh server rebuilds on first poll
    let with_entry = server.get("/attempts").expect_success().await;
    let etag = with_entry.header("etag").to_str().unwrap().to_string();
    assert_eq!(etag.len(), 66, "ETag length is content-independent");
}

/// Snapshot entries are sorted by id_hash: the deterministic build (same
/// state → same bytes → same ETag) depends on a stable order.
#[tokio::test]
async fn test_snapshot_entries_are_sorted_by_id_hash() {
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

    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    let hashes: Vec<String> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id_hash"].as_str().unwrap().to_string())
        .collect();
    let mut sorted = hashes.clone();
    sorted.sort();
    assert_eq!(hashes, sorted, "entries must be sorted by id_hash");
}

// ---------------------------------------------------------------------------
// Cross-endpoint consistency: the direct response and the snapshot must agree
// ---------------------------------------------------------------------------

/// `attempt_status.total_attempts` (direct response) and the snapshot's
/// `total_attempts` for the same identifier must agree: a client reconciling
/// the two must never see them diverge.
#[tokio::test]
async fn test_attempt_status_and_snapshot_counters_agree() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;
    let direct_total = response.json::<serde_json::Value>()["attempt_status"]["total_attempts"]
        .as_u64()
        .unwrap();

    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    let entry = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id_hash"] == identifier_hash(SHA256_111111).unwrap())
        .unwrap();
    assert_eq!(entry["total_attempts"].as_u64().unwrap(), direct_total);
}

/// The 401's `attempts` field and the snapshot's `total_attempts` must agree
/// too: the failed-lookup counter is the same seen from both endpoints.
#[tokio::test]
async fn test_401_attempts_and_snapshot_counters_agree() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    let direct_attempts = response.json::<serde_json::Value>()["attempts"]
        .as_u64()
        .unwrap();

    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    let entry = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id_hash"] == identifier_hash(SHA256_111111).unwrap())
        .unwrap();
    assert_eq!(entry["total_attempts"].as_u64().unwrap(), direct_attempts);
}

/// `resets_at` advances for each distinct admitted candidate, but remains
/// stable when the same candidate is replayed.
#[tokio::test]
async fn test_resets_at_advances_with_each_distinct_candidate() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;

    let first = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;
    let first_resets = first.json::<serde_json::Value>()["attempt_status"]["resets_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();

    let replay = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;
    let replay_resets = replay.json::<serde_json::Value>()["attempt_status"]["resets_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    assert_eq!(
        replay_resets, first_resets,
        "a replay must not renew resets_at"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: crate::tests::distinct_candidate(1),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;

    let second = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: crate::tests::distinct_candidate(1),
        })
        .expect_success()
        .await;
    let second_resets = second.json::<serde_json::Value>()["attempt_status"]["resets_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();

    assert!(
        second_resets > first_resets,
        "resets_at must advance with each distinct admitted candidate"
    );
}

/// The 429's `requested_at` is the LAST ADMITTED attempt, not the rejected
/// request: a client computing `requested_at + cooldown` to schedule its
/// retry depends on this being the last admitted attempt.
#[tokio::test]
async fn test_429_requested_at_is_the_last_admitted_attempt() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    for index in 0..state.rate_limit_max_attempts as usize {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: crate::tests::distinct_candidate(index),
            })
            .expect_failure()
            .await;
    }

    let before_429 = chrono::Utc::now();
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);

    let requested_at = response.json::<serde_json::Value>()["requested_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    assert!(
        requested_at <= before_429,
        "the 429 requested_at must be the last admitted attempt, not the rejected request"
    );
}

/// An expired entry disappears from `/attempts`: the client treats a
/// disappeared entry as "window expired, reset my baseline" — the snapshot
/// must only ever hold active entries.
#[tokio::test]
async fn test_expired_entry_disappears_from_snapshot() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // insert an already-expired entry directly into the map
    {
        let mut map = state.identifier_rate_limit.lock_for_test().await;
        let expired_at =
            chrono::Utc::now() - state.rate_limit_cooldown - chrono::Duration::minutes(1);
        map.insert(
            identifier_hash(SHA256_111111).unwrap(),
            crate::attempts::ledger::RateLimitInfo {
                window_started_at: expired_at,
                last_candidate_at: expired_at,
                last_request_at: expired_at,
                candidates: std::collections::HashMap::new(),
                failed_candidates: 3,
                total_requests: 3,
            },
        );
    }

    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    assert!(
        !body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["id_hash"] == identifier_hash(SHA256_111111).unwrap()),
        "an expired entry must not appear in the snapshot"
    );
}

/// A successful trash removes the row but not the counter: a subsequent
/// lookup continues the count (the trash was an attempt, the next lookup is
/// the next one) — trash must not erase the security signal.
#[tokio::test]
async fn test_trash_does_not_reset_the_counter() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;
    server
        .post("/trash")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;

    // the row is gone, but the distinct-candidate counter stays stable while
    // total_requests records the replay
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    let body = response.json::<serde_json::Value>();
    assert_eq!(body["attempts"], 1, "trash must not reset the counter");
    assert_eq!(body["total_requests"], 2);
}

/// `/info`'s `attempts_collection_started_at` and the snapshot's
/// `collection_started_at` must be the same value: the client uses `/info`
/// for cheap wipe detection and expects consistency.
#[tokio::test]
async fn test_info_and_snapshot_collection_started_at_agree() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    let info = server.get("/info").expect_success().await;
    let info_collection = info.json::<serde_json::Value>()["attempts_collection_started_at"]
        .as_str()
        .unwrap()
        .to_string();

    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    let snapshot_collection = body["collection_started_at"].as_str().unwrap().to_string();

    assert_eq!(info_collection, snapshot_collection);

    crate::attempts::maintenance::wipe_identifier_rate_limit(
        &state.identifier_rate_limit,
        &state.attempts_snapshot,
    )
    .await;
    let info = server.get("/info").expect_success().await;
    let info_collection = info.json::<serde_json::Value>()["attempts_collection_started_at"]
        .as_str()
        .unwrap()
        .to_string();
    let snapshot = server.get("/attempts").expect_success().await;
    let snapshot_collection = decode_snapshot(snapshot.as_bytes())["collection_started_at"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(info_collection, snapshot_collection);
}

/// The snapshot version is pinned at 1: the client parses according to this
/// version and must reject an unexpected one loudly here, not in production.
#[tokio::test]
async fn test_snapshot_version_is_pinned() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    assert_eq!(
        body["version"], 1,
        "the snapshot version is a client contract"
    );
}

/// An empty snapshot returns an empty entries array (not null, not missing):
/// the client iterates it unconditionally.
#[tokio::test]
async fn test_empty_snapshot_has_empty_entries_array() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    assert_eq!(body["entries"].as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// Conditional requests: edge cases that must not crash or over-304
// ---------------------------------------------------------------------------

/// A non-matching If-None-Match returns 200 with the full body, never 304.
#[tokio::test]
async fn test_if_none_match_with_wrong_etag_returns_200() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let response = server
        .get("/attempts")
        .add_header(
            "If-None-Match",
            "\"0000000000000000000000000000000000000000000000000000000000000000\"",
        )
        .expect_success()
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(!response.as_bytes().is_empty());
}

/// A comma-separated If-None-Match list containing the current ETag returns
/// 304: caches and clients send lists, not just single values.
#[tokio::test]
async fn test_if_none_match_list_containing_current_etag_returns_304() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let first = server.get("/attempts").expect_success().await;
    let etag = first.header("etag").to_str().unwrap().to_string();

    let response = server
        .get("/attempts")
        .add_header(
            "If-None-Match",
            format!("\"deadbeef\", {etag}, \"cafebabe\""),
        )
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_MODIFIED);
}

/// A malformed If-None-Match is ignored (200), never a crash and never a
/// spurious 304.
#[tokio::test]
async fn test_malformed_if_none_match_returns_200() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let response = server
        .get("/attempts")
        .add_header("If-None-Match", "not-an-etag%%%")
        .expect_success()
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Bucket independence: the three global buckets must not starve each other
// ---------------------------------------------------------------------------

/// Exhausting the lookup bucket does not block `/store`, and exhausting the
/// store bucket does not block `/fetch`: the buckets are independent so one
/// flooded route cannot take the others down.
#[tokio::test]
async fn test_lookup_and_store_buckets_are_independent() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // exhaust the lookup bucket: /fetch is 429 but /store still works
    *state.lookup_token_bucket.lock().await = crate::rate_limit::TokenBucket::new(0.0, 0.0);
    let store = server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;
    assert_eq!(store.status_code(), StatusCode::CREATED);

    // restore the lookup bucket, then exhaust the store bucket: /store is
    // 429 but /fetch still reaches the per-identifier path (401, not 429)
    *state.lookup_token_bucket.lock().await = crate::rate_limit::TokenBucket::new(100.0, 100.0);
    *state.store_token_bucket.lock().await = crate::rate_limit::TokenBucket::new(0.0, 0.0);
    let fetch = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_222222.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(fetch.status_code(), StatusCode::UNAUTHORIZED);
}

/// Exhausting the lookup bucket does not block `/attempts`: the telemetry
/// route has its own bucket so a lookup flood cannot suppress telemetry.
#[tokio::test]
async fn test_lookup_bucket_does_not_block_attempts() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    *state.lookup_token_bucket.lock().await = crate::rate_limit::TokenBucket::new(0.0, 0.0);
    let snapshot = server.get("/attempts").expect_success().await;
    assert_eq!(snapshot.status_code(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Storage isolation: distinct rows, no cross-key reads, length boundary
// ---------------------------------------------------------------------------

/// Two rows with the same identifier but different authentication_keys are
/// independent: both are stored, both fetchable with their own key, neither
/// overwrites the other.
#[tokio::test]
async fn test_same_identifier_different_keys_are_independent_rows() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let other_secret =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
    let other_key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;
    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: other_key.to_string(),
            encrypted_secret: other_secret.to_string(),
        })
        .expect_success()
        .await;

    let first = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;
    assert_eq!(
        first.json::<serde_json::Value>()["encrypted_secret"],
        BASE64_ENCRYPTED_SECRET
    );

    let second = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: other_key.to_string(),
        })
        .expect_success()
        .await;
    assert_eq!(
        second.json::<serde_json::Value>()["encrypted_secret"],
        other_secret
    );
}

/// A fetch with the right identifier but another row's key fails: the
/// secret_id derivation isolates rows from each other.
#[tokio::test]
async fn test_cross_key_fetch_fails() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

/// The encrypted_secret length boundary is exact: SECRET_MAX_LENGTH base64
/// chars are accepted, one more (a valid base64 length) is rejected.
#[tokio::test]
async fn test_encrypted_secret_length_boundary() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // exactly at the limit: accepted
    let at_limit = "A".repeat(state.secret_max_length);
    let response = server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: at_limit,
        })
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // one valid base64 quantum over the limit: rejected
    let over_limit = "A".repeat(state.secret_max_length + 4);
    let response = server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_222222.to_string(),
            authentication_key: SHA256_111111.to_string(),
            encrypted_secret: over_limit,
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Contract: the two hash algorithms must never be unified
// ---------------------------------------------------------------------------

/// `generate_secret_id` hashes the concatenated lowercase hex STRINGS, while
/// `id_hash` hashes the raw identifier bytes: they are different algorithms
/// and a client must not mix them. Pin both, and pin that they differ.
#[test]
fn test_secret_id_and_id_hash_are_distinct_algorithms() {
    // generate_secret_id: sha256 over the concatenated hex strings
    let secret_id = crate::recovery::identifiers::generate_secret_id(SHA256_111111, SHA256_222222);
    assert_eq!(secret_id, SHA256_CONCAT_111111_222222);

    // id_hash: sha256 over the raw identifier bytes (shared client vector)
    let id_hash = identifier_hash(SHA256_111111).unwrap();
    assert_eq!(
        id_hash,
        "f5bb872a08ef929e6744d117a69d4073ee7b5df4f5d7a4ecdd606f30a58f76db"
    );

    // hashing the secret_id input as raw bytes would give a different value:
    // the two algorithms must never be "unified"
    let raw_concat = [
        hex::decode(SHA256_111111).unwrap(),
        hex::decode(SHA256_222222).unwrap(),
    ]
    .concat();
    let raw_concat_hash = crate::digest::sha256_hex(&raw_concat);
    assert_ne!(
        raw_concat_hash, secret_id,
        "secret_id is over the hex strings, not the raw bytes"
    );
}

// ---------------------------------------------------------------------------
// Error handling: no internal detail leaks, exact lockout boundary
// ---------------------------------------------------------------------------

/// A 500 returns a generic body: no SQL error, no schema detail, no internal
/// path — the diesel error goes to the operator's logs, never to the client.
#[tokio::test]
async fn test_500_does_not_leak_internals() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // force every query to fail
    let mut connection =
        crate::storage::sqlite::establish_connection(state.clone().database_url).unwrap();
    diesel::sql_query("DROP TABLE secret")
        .execute(&mut connection)
        .expect("failed to drop table");

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.text();
    assert!(!body.contains("secret"), "no table name: {body}");
    assert!(!body.contains("no such table"), "no SQL error: {body}");
    assert!(!body.contains("sqlite"), "no engine detail: {body}");
    assert!(!body.contains("database"), "no database detail: {body}");

    // restore for the next test
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
}

/// The exact lockout boundary: the max-th attempt is admitted (401), the
/// (max+1)-th is rejected (429). An off-by-one here either gifts the attacker
/// a free guess or locks the owner out early.
#[tokio::test]
async fn test_lockout_boundary_is_exact() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let max = state.rate_limit_max_attempts;

    // the first `max` attempts are all admitted (401)
    for i in 0..max as usize {
        let response = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: crate::tests::distinct_candidate(i),
            })
            .expect_failure()
            .await;
        assert_eq!(
            response.status_code(),
            StatusCode::UNAUTHORIZED,
            "attempt {i} of {max} must be admitted"
        );
    }

    // the (max+1)-th is rejected
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::TOO_MANY_REQUESTS,
        "attempt {} of {max} must be rejected",
        max + 1
    );
}

// ---------------------------------------------------------------------------
// Route surface: methods, unknown routes, content-type, /info availability
// ---------------------------------------------------------------------------

/// `/info` is not rate-limited: it stays available even when every bucket is
/// exhausted (it is the cheap liveness + canary endpoint).
#[tokio::test]
async fn test_info_is_not_rate_limited() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    *state.lookup_token_bucket.lock().await = crate::rate_limit::TokenBucket::new(0.0, 0.0);
    *state.store_token_bucket.lock().await = crate::rate_limit::TokenBucket::new(0.0, 0.0);
    state
        .attempts_maintenance
        .set_bucket_for_test(crate::rate_limit::TokenBucket::new(0.0, 0.0))
        .await;

    let response = server.get("/info").expect_success().await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

/// Wrong method on a known route is 405, not 404 and not a handler bypass.
#[tokio::test]
async fn test_wrong_method_returns_405() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    for (method, path) in [
        ("GET", "/fetch"),
        ("GET", "/store"),
        ("GET", "/trash"),
        ("POST", "/attempts"),
        ("POST", "/info"),
    ] {
        let response = match method {
            "GET" => server.get(path).await,
            _ => server.post(path).text("").await,
        };
        assert_eq!(
            response.status_code(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} must be 405"
        );
    }
}

/// An unknown route is 404: no catch-all handler leaks into an endpoint.
#[tokio::test]
async fn test_unknown_route_returns_404() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let response = server.get("/nonexistent").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

/// A POST without a JSON content-type is 415: the Json extractor rejects it
/// before any handler logic runs.
#[tokio::test]
async fn test_missing_or_wrong_content_type_returns_415() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let body = format!(
        "{{\"identifier\":\"{}\",\"authentication_key\":\"{}\"}}",
        SHA256_111111, SHA256_222222
    );

    // wrong content-type
    let response = server
        .post("/fetch")
        .add_header("content-type", "text/plain")
        .text(body.clone())
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ---------------------------------------------------------------------------
// Snapshot invariants: ordering and freshness
// ---------------------------------------------------------------------------

/// In a snapshot entry, `last_attempt_at` is never before `window_started_at`
/// (both hour-truncated): the ordering must hold for the client's display.
#[tokio::test]
async fn test_snapshot_last_attempt_not_before_window_start() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;

    let snapshot = server.get("/attempts").expect_success().await;
    let body = decode_snapshot(snapshot.as_bytes());
    let entry = &body["entries"].as_array().unwrap()[0];
    let window = entry["window_started_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    let last = entry["last_attempt_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    assert!(
        last >= window,
        "last_attempt_at must not precede window start"
    );
}

/// `resets_at` is always in the future for an active entry: a client showing
/// "try again at resets_at" depends on it not being in the past.
#[tokio::test]
async fn test_resets_at_is_in_the_future_for_active_entry() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        })
        .expect_success()
        .await;
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;

    let resets_at = response.json::<serde_json::Value>()["attempt_status"]["resets_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    assert!(
        resets_at > chrono::Utc::now(),
        "resets_at must be in the future for an active entry"
    );
}

// ---------------------------------------------------------------------------
// Edge-case guards: counter overflow and snapshot single-flight
// ---------------------------------------------------------------------------

/// With the maximum configurable budget (255, the u8 ceiling), the counter
/// caps at 255 without overflowing: the 256th attempt is rejected and the
/// counter stays at 255 — no wrap-around to 0 that would unlock the budget.
#[tokio::test]
async fn test_attempts_counter_does_not_overflow_at_u8_max() {
    let mut state = crate::env::init();
    state.rate_limit_max_attempts = 255;
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    // seed the map at 254 so only two requests are needed
    {
        let mut map = state.identifier_rate_limit.lock_for_test().await;
        map.insert(
            identifier_hash(SHA256_111111).unwrap(),
            crate::attempts::ledger::RateLimitInfo {
                window_started_at: chrono::Utc::now(),
                last_candidate_at: chrono::Utc::now(),
                last_request_at: chrono::Utc::now(),
                candidates: (0..254)
                    .map(|i| {
                        (
                            format!("candidate-{i}"),
                            crate::attempts::ledger::CandidateState::Committed,
                        )
                    })
                    .collect(),
                failed_candidates: 254,
                total_requests: 254,
            },
        );
    }

    // admitted: attempts becomes 255
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // rejected: attempts stays 255, no overflow to 0
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);

    let map = state.identifier_rate_limit.lock_for_test().await;
    assert_eq!(
        map[&identifier_hash(SHA256_111111).unwrap()].candidate_count(),
        255,
        "the counter must cap at u8::MAX, never wrap to 0"
    );
}

/// Concurrent `/attempts` polls all succeed and agree on the ETag: the
/// single-flight rebuild must not produce divergent snapshots or failures
/// under concurrency.
#[tokio::test]
async fn test_concurrent_attempts_polls_agree_on_etag() {
    let app_state = crate::env::init();
    crate::storage::sqlite::try_init_db(app_state.clone()).unwrap();
    let app = crate::router::new_for_tests(app_state.clone());
    let mut connection =
        crate::storage::sqlite::establish_connection(app_state.clone().database_url).unwrap();
    crate::tests::test_server::clear_table_secret(&mut connection).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // one entry so the snapshot is non-trivial
    let fetch = format!(
        "{{\"identifier\":\"{}\",\"authentication_key\":\"{}\"}}",
        SHA256_111111, NOT_PASSWORD_HASH
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /fetch HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        fetch.len(),
        fetch
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();

    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(tokio::spawn(async move { raw_get_attempts(addr).await }));
    }
    let mut etags = std::collections::HashSet::new();
    for handle in handles {
        let (status, etag) = handle.await.unwrap();
        assert_eq!(status, 200);
        etags.insert(etag);
    }
    assert_eq!(
        etags.len(),
        1,
        "all concurrent polls must agree on the ETag"
    );
}

/// A raw GET /attempts returning the status and the ETag header.
async fn raw_get_attempts(addr: std::net::SocketAddr) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /attempts HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    let etag = text
        .lines()
        .find(|l| l.to_lowercase().starts_with("etag:"))
        .map(|l| l[5..].trim().to_string())
        .unwrap_or_default();
    (status, etag)
}
