use crate::{
    http::contract::{FetchSecret, StoreSecret},
    recovery::identifiers::identifier_hash,
    tests::{BASE64_ENCRYPTED_SECRET, SHA256_111111, SHA256_222222, SHA256_CONCAT_111111_222222},
};
use axum::http::StatusCode;

#[tokio::test]
async fn test_fetch_success() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };

    server.post("/store").json(&store).expect_success().await;

    let fetch = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    };

    let response = server.post("/fetch").json(&fetch).expect_success().await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body = response.json::<serde_json::Value>();
    assert_eq!(body["id"], SHA256_CONCAT_111111_222222);
    assert_eq!(body["encrypted_secret"], BASE64_ENCRYPTED_SECRET);
}

#[tokio::test]
async fn test_fetch_success_reports_exact_attempt_status() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    server.post("/store").json(&store).expect_success().await;

    let fetch = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    };

    // first lookup ever: no previous attempt, full budget remaining
    let before_first = chrono::Utc::now();
    let response = server.post("/fetch").json(&fetch).expect_success().await;
    let status = &response.json::<serde_json::Value>()["attempt_status"];
    assert_eq!(status["total_attempts"], 1);
    assert_eq!(status["total_requests"], 1);
    assert_eq!(status["failed_attempts"], 0);
    assert_eq!(
        status["remaining_attempts"],
        state.attempts.policy.max_attempts() - 1
    );
    assert!(status["previous_attempt_at"].is_null());

    let window_started_at = status["window_started_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    assert!(window_started_at >= before_first);

    // the window resets one cooldown after the most recent admitted attempt
    let resets_at = status["resets_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    assert_eq!(
        resets_at - window_started_at,
        state.attempts.policy.cooldown(),
        "first window: resets_at is one cooldown after the first attempt"
    );

    // second lookup replays the same candidate: attempts stay stable while
    // requests increase, and no new candidate timestamp is published
    let response = server.post("/fetch").json(&fetch).expect_success().await;
    let status = &response.json::<serde_json::Value>()["attempt_status"];
    assert_eq!(status["total_attempts"], 1);
    assert_eq!(status["total_requests"], 2);
    assert_eq!(status["failed_attempts"], 0);
    assert!(status["previous_attempt_at"].is_null());
    assert_eq!(
        status["window_started_at"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap(),
        window_started_at,
        "the window start never moves within a window"
    );
}

#[tokio::test]
async fn test_fetch_key_failure_invalid_hash_for_format_identifier() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let fetch = &FetchSecret {
        identifier: "not_a_hash".to_string(),
        authentication_key: SHA256_111111.to_string(),
    };

    let response = server.post("/fetch").json(&fetch).expect_failure().await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_fetch_failure_invalid_hash_format_for_authentication_key() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let fetch = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: "not_a_hash".to_string(),
    };

    let response = server.post("/fetch").json(&fetch).expect_failure().await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_fetch_rate_limit_enforced_and_reset_after_cooldown() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };

    server.post("/store").json(&store).expect_success().await;

    // trigger rate limit by attempting many fail attempts
    for i in 0..state.attempts.policy.max_attempts() as usize {
        let fetch_wrong_authentication_key = FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: crate::tests::distinct_candidate(i),
        };
        let response = server
            .post("/fetch")
            .json(&fetch_wrong_authentication_key)
            .expect_failure()
            .await;

        let failed_attempt = response.json::<serde_json::Value>();
        assert_eq!(failed_attempt["attempts"], (i + 1) as u8);
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    // trigger the rate_limit_cooldown
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: crate::tests::distinct_candidate(0),
        })
        .expect_failure()
        .await;

    let failed_attempt = response.json::<serde_json::Value>();
    assert_eq!(
        failed_attempt["attempts"],
        state.attempts.policy.max_attempts()
    );
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);

    // Simulate cooldown expiry by aging the in-memory entry directly instead
    // of sleeping for the real cooldown duration: the suite must stay fast
    // and must not depend on wall-clock time.
    {
        let mut identifier_rate_limit = state.attempts.ledger.lock_for_test().await;
        let info = identifier_rate_limit
            .get_mut(&identifier_hash(SHA256_111111).unwrap())
            .unwrap();
        let expired_at =
            chrono::Utc::now() - state.attempts.policy.cooldown() - chrono::Duration::minutes(1);
        info.window_started_at = expired_at;
        info.last_candidate_at = expired_at;
        info.last_request_at = expired_at;
    }

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;

    let body = response.json::<serde_json::Value>();

    assert_eq!(body["id"], SHA256_CONCAT_111111_222222);
    assert_eq!(body["encrypted_secret"], BASE64_ENCRYPTED_SECRET);

    // A successful lookup consumes the first attempt of the new window and
    // must not clear the security counter.
    let identifier_rate_limit = state.attempts.ledger.lock_for_test().await;
    let info = identifier_rate_limit
        .get(&identifier_hash(SHA256_111111).unwrap())
        .unwrap();
    assert_eq!(info.candidate_count(), 1);
    assert_eq!(info.failed_candidates, 0);
}
