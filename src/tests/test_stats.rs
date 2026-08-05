use crate::{
    models::{FetchSecret, RateLimitInfo, StatEntry, StoreSecret},
    tests::{BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
    utils::sha256_hex,
};
use axum::http::StatusCode;

#[tokio::test]
async fn test_stats_publish_hashed_identifier_with_bruteforce_info() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let fetch_wrong_authentication_key = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: NOT_PASSWORD_HASH.to_string(),
    };

    // two failed attempts
    for _ in 0..2 {
        let response = server
            .post("/fetch")
            .json(&fetch_wrong_authentication_key)
            .expect_failure()
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    let response = server.get("/stats").expect_success().await;
    let body = response.text();
    let stats = response.json::<Vec<StatEntry>>();

    // the raw identifier must never leak
    assert!(!body.contains(SHA256_111111));

    assert_eq!(stats.len(), 1);
    let expected_id_hash = sha256_hex(&hex::decode(SHA256_111111).unwrap());
    assert_eq!(stats[0].id_hash, expected_id_hash);
    assert_eq!(stats[0].attempts, 2);
    assert_eq!(stats[0].failed_attempts, 2);
}

#[tokio::test]
async fn test_fetch_success_reports_failures_without_resetting_attempt_budget() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    server.post("/store").json(&store).expect_success().await;

    // two failed attempts
    for _ in 0..2 {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: NOT_PASSWORD_HASH.to_string(),
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
    let response = server.get("/stats").expect_success().await;
    let stats = response.json::<Vec<StatEntry>>();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].attempts, 3);
    assert_eq!(stats[0].failed_attempts, 2);

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
}

#[tokio::test]
async fn test_stats_omit_entries_after_cooldown_without_waiting_for_sweeper() {
    let state = crate::env::init();
    {
        let mut entries = state.identifier_rate_limit.lock().await;
        let window_started_at =
            chrono::Utc::now() - state.rate_limit_cooldown - chrono::Duration::seconds(1);
        entries.insert(
            crate::utils::identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                window_started_at,
                last_request: window_started_at,
                attempts: 1,
                failed_attempts: 1,
            },
        );
    }
    let server = axum_test::TestServer::new(crate::router::new(state)).unwrap();

    let stats = server
        .get("/stats")
        .expect_success()
        .await
        .json::<Vec<StatEntry>>();
    assert!(stats.is_empty());
}
