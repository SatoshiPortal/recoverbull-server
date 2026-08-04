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

/// F1 (CRITICAL): /store is an unthrottled authentication_key oracle.
/// A fresh secret_id returns 201 while an existing one returns 403, which
/// reveals whether SHA256(identifier || authentication_key) is in the
/// database — with no rate limit, and without ever engaging the fetch
/// rate-limiter.
#[tokio::test]
async fn test_audit_f1_store_duplicate_reveals_authentication_key() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    // the victim stores a record
    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    let response = server.post("/store").json(store).await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // an attacker holding the identifier submits distinct wrong-key
    // guesses: all accepted, never throttled
    for i in 0..10u32 {
        let guess = &StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: format!("{:064x}", i + 1),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
        };
        let response = server.post("/store").json(guess).await;
        assert_eq!(
            response.status_code(),
            StatusCode::CREATED,
            "a wrong guess must not be throttled for the oracle to work"
        );
    }

    // the correct authentication_key submitted as a "store": 403 fires
    // the oracle — the attacker now knows the key is correct
    let response = server.post("/store").json(store).await;
    assert_eq!(
        response.status_code(),
        StatusCode::FORBIDDEN,
        "CURRENT VULNERABLE BEHAVIOR: duplicate reveals row existence"
    );

    // and none of this ever touched the fetch rate-limiter: the victim's
    // own fetch still succeeds with zero attempts consumed
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
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

/// F3 (MED): database errors are reported as "Invalid
/// identifier/authentication_key" (401) and consume rate-limit attempts,
/// so transient database trouble burns the user's recovery attempts.
#[tokio::test]
async fn test_audit_f3_database_error_reported_as_invalid_credentials() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // force every subsequent query to fail (init_db recreates the table
    // on the next test via IF NOT EXISTS)
    let mut connection = crate::database::establish_connection(state.clone().database_url);
    diesel::sql_query("DROP TABLE secret")
        .execute(&mut connection)
        .expect("failed to drop table");

    let fetch = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    };

    // each database error is misreported as wrong credentials and
    // consumes an attempt...
    for expected_attempts in 1..=state.rate_limit_max_failed_attempts {
        let response = server.post("/fetch").json(fetch).await;
        assert_eq!(
            response.status_code(),
            StatusCode::UNAUTHORIZED,
            "CURRENT VULNERABLE BEHAVIOR: database error reported as 401"
        );
        let body: serde_json::Value = response.json();
        assert_eq!(body["attempts"], expected_attempts);
        assert_eq!(body["error"], "Invalid identifier/authentication_key");
    }

    // ...until the user is locked out by database failures alone
    let response = server.post("/fetch").json(fetch).await;
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

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

/// F11 (LOW): wildcard CORS on every endpoint — any web page can issue
/// and read responses from a visitor's browser.
#[tokio::test]
async fn test_audit_f11_cors_allows_any_origin() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let response = server
        .method(axum::http::Method::OPTIONS, "/fetch")
        .add_header("Origin", "https://attacker.example")
        .add_header("Access-Control-Request-Method", "POST")
        .await;

    assert_eq!(
        response.header("access-control-allow-origin"),
        "*",
        "CURRENT BEHAVIOR: any origin may call the API from a browser"
    );
}

/// F12 (LOW): hex inputs are accepted case-insensitively but hashed
/// without canonicalization, so the same logical credentials produce two
/// distinct records.
#[tokio::test]
async fn test_audit_f12_hex_case_creates_duplicate_records() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let lowercase = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    let response = server.post("/store").json(lowercase).await;
    assert_eq!(response.status_code(), StatusCode::CREATED);

    // the same logical credentials, uppercased: accepted as a NEW record
    let uppercase = &StoreSecret {
        identifier: SHA256_111111.to_uppercase(),
        authentication_key: SHA256_222222.to_uppercase(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    let response = server.post("/store").json(uppercase).await;
    assert_eq!(
        response.status_code(),
        StatusCode::CREATED,
        "CURRENT BEHAVIOR: case variants are stored as distinct records"
    );

    // and each case variant is independently fetchable
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_uppercase(),
            authentication_key: SHA256_222222.to_uppercase(),
        })
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}
