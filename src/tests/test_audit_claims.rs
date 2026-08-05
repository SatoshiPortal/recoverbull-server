//! Characterization tests reproducing the claims of the external audit
//! (SECURITY-AUDIT-2026-08-04, multi-model review of commit 38b274f)
//! against the current code of this branch.
//!
//! These tests document the CURRENT behavior. Each one passes today
//! *because the vulnerability exists*. When a claim is remediated, the
//! corresponding test breaks and must be updated to assert the secure
//! behavior — that breakage is the signal that the fix landed.

use crate::{
    models::{FetchSecret, StoreSecret},
    tests::{BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
};
use axum::http::StatusCode;

/// F1 (CRITICAL): /store was an unthrottled authentication_key oracle —
/// FIXED. /store is now idempotent: a fresh secret_id and an existing one
/// both return 201, and a duplicate never overwrites. The regression test
/// lives in test_store.rs (test_duplicate_store_is_indistinguishable_and_does_not_overwrite).
/// This test keeps guarding that wrong guesses are not throttled either
/// (no new oracle may be introduced).
#[tokio::test]
async fn test_audit_f1_store_gives_no_existence_signal() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    let first = server.post("/store").json(store).await;

    // distinct wrong-key guesses: accepted, never throttled
    for i in 0..10u32 {
        let guess = &StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: format!("{:064x}", i + 1),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        };
        let response = server.post("/store").json(guess).await;
        assert_eq!(response.status_code(), StatusCode::CREATED);
    }

    // the correct key submitted as a "store": indistinguishable from a
    // fresh store — the oracle is closed
    let second = server.post("/store").json(store).await;
    assert_eq!(second.status_code(), first.status_code());
}

/// F1 follow-up: a caller must not bypass the fetch budget by planting a row
/// for each guessed key. A planted row makes the lookup return 200, but every
/// lookup still consumes the identifier's shared attempt budget.
#[tokio::test]
async fn test_audit_f1_planted_rows_cannot_reset_fetch_rate_limit() {
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

    for i in 0..state.rate_limit_max_failed_attempts {
        let guessed_key = format!("{:064x}", i + 1);
        let marker = "dGVzdA==";

        server
            .post("/store")
            .json(&StoreSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: guessed_key.clone(),
                encrypted_secret: marker.to_string(),
            })
            .expect_success()
            .await;

        let response = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: guessed_key,
            })
            .expect_success()
            .await;
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["encrypted_secret"], marker);
        // a hit on a planted row still consumes the budget and is reported:
        // total_attempts grows while failed_attempts stays at zero
        assert_eq!(body["attempt_status"]["total_attempts"], i + 1);
        assert_eq!(body["attempt_status"]["failed_attempts"], 0);
    }

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

/// F2 (HIGH): the attempts counter is keyed on the identifier alone and
/// checked before credentials are verified, so an attacker who knows the
/// victim's identifier can lock the legitimate owner out of recovery.
#[tokio::test]
async fn test_audit_f2_attacker_failures_deny_legitimate_owner() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    server.post("/store").json(store).expect_success().await;

    // the attacker exhausts the attempts with a wrong key
    for _ in 0..state.rate_limit_max_failed_attempts {
        let response = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: NOT_PASSWORD_HASH.to_string(),
            })
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    // the legitimate owner, presenting the CORRECT authentication_key,
    // is denied by the attacker's failures
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::TOO_MANY_REQUESTS,
        "CURRENT VULNERABLE BEHAVIOR: the owner is locked out by the attacker"
    );
}

// F3 (MED): database errors were reported as "Invalid
// identifier/authentication_key" (401) and consumed rate-limit attempts —
// FIXED. Database errors now return 500 and refund the attempt. The
// regression test lives in test_db_errors.rs
// (test_database_error_returns_500_without_consuming_attempts).

/// F9 (LOW): /store accepted unlimited writes — FIXED. Unauthenticated
/// writes are now dampened by a global token bucket (per-IP is useless
/// behind an onion service). This test uses a tiny bucket with no refill
/// for determinism.
#[tokio::test]
async fn test_audit_f9_store_writes_are_token_bucketed() {
    let mut app_state = crate::env::init();
    app_state.store_token_bucket = std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::rate_limit::TokenBucket::new(3.0, 0.0),
    ));
    crate::database::init_db(app_state.clone());
    let app = crate::router::new(app_state.clone());
    let mut connection = crate::database::establish_connection(app_state.clone().database_url);
    crate::tests::test_server::clear_table_secret(&mut connection).await;
    let server = axum_test::TestServer::new(app).unwrap();

    for i in 0..5u32 {
        let store = &StoreSecret {
            identifier: format!("{:064x}", i + 1),
            authentication_key: format!("{:064x}", i + 1),
            encrypted_secret: "dGVzdA==".to_string(),
        };
        let response = server.post("/store").json(store).await;
        if i < 3 {
            assert_eq!(response.status_code(), StatusCode::CREATED);
        } else {
            assert_eq!(
                response.status_code(),
                StatusCode::TOO_MANY_REQUESTS,
                "writes beyond the bucket capacity must be rejected"
            );
        }
    }
}

#[tokio::test]
async fn test_lookup_flood_is_globally_token_bucketed() {
    let mut state = crate::env::init();
    state.lookup_token_bucket = std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::rate_limit::TokenBucket::new(1.0, 0.0),
    ));
    crate::database::init_db(state.clone());
    let server = axum_test::TestServer::new(crate::router::new(state)).unwrap();

    let first = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .await;
    assert_eq!(first.status_code(), StatusCode::UNAUTHORIZED);

    let second = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_222222.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .await;
    assert_eq!(second.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

/// F11 (LOW): wildcard CORS on every endpoint — FIXED. The CORS layers
/// were removed entirely (clients are native apps over Tor, not browsers).
/// This test guards that no CORS header ever comes back.
#[tokio::test]
async fn test_audit_f11_no_cors_headers() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let response = server
        .method(axum::http::Method::OPTIONS, "/fetch")
        .add_header("Origin", "https://attacker.example")
        .add_header("Access-Control-Request-Method", "POST")
        .await;

    assert!(
        response
            .maybe_header("access-control-allow-origin")
            .is_none(),
        "no CORS header must be present"
    );
}

/// F12 (LOW): hex inputs were accepted case-insensitively but hashed
/// without canonicalization, producing duplicate records — FIXED. Hex
/// inputs are canonicalized to lowercase before validation and hashing.
#[tokio::test]
async fn test_audit_f12_hex_case_is_canonicalized() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    // store with UPPERCASE credentials
    let store = &StoreSecret {
        identifier: SHA256_111111.to_uppercase(),
        authentication_key: SHA256_222222.to_uppercase(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    let response = server.post("/store").json(store).await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // fetch with lowercase: the same logical record must be found
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}
