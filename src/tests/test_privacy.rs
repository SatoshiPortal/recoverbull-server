//! Privacy-oracle tests for response shape and secret-material disclosure.
//!
//! These tests pin the externally observable privacy boundary: callers must
//! not learn identifier existence or receive secrets and internal diagnostics
//! through response bodies or timestamps.

use crate::{
    http::contract::{FetchSecret, StoreSecret},
    tests::{BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
};
use axum::http::StatusCode;
use diesel::RunQueryDsl;
use std::io::Read;

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
    for index in 1..state.attempts.policy.max_attempts() as usize {
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
// Error handling: no internal detail leaks
// ---------------------------------------------------------------------------

/// A 500 returns a generic body: no SQL error, no schema detail, no internal
/// path — the diesel error goes to the operator's logs, never to the client.
#[tokio::test]
async fn test_500_does_not_leak_internals() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // force every query to fail
    let mut connection =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
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

    // No restore: every test owns its database, and `initialize()` now fails
    // closed on the missing table (see `test_migrations`), which is the
    // right startup behaviour rather than a way to recreate it.
}
