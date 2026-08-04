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
use diesel::RunQueryDsl;

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

/// F3 (MED): database errors were reported as "Invalid
/// identifier/authentication_key" (401) and consumed rate-limit attempts —
/// FIXED. Database errors now return 500 and refund the attempt. The
/// regression test lives in test_db_errors.rs
/// (test_database_error_returns_500_without_consuming_attempts).

/// F9 (LOW): /store accepts unlimited writes — no rate limit, no quota.
#[tokio::test]
async fn test_audit_f9_store_accepts_unlimited_writes() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    for i in 0..20u32 {
        let store = &StoreSecret {
            identifier: format!("{:064x}", i + 1),
            authentication_key: format!("{:064x}", i + 1),
            encrypted_secret: "dGVzdA==".to_string(),
        };
        let response = server.post("/store").json(store).await;
        assert_eq!(response.status_code(), StatusCode::CREATED);
    }
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
