use crate::{
    models::{FetchSecret, RateLimitInfo, ResponseFailedAttempt},
    tests::{NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
    utils::identifier_hash,
};
use axum::http::StatusCode;

#[tokio::test]
async fn test_sweep_removes_only_expired_entries() {
    let (_, state) = crate::tests::test_server::new_test_server().await;

    let now = chrono::Utc::now();
    let expired_at = now - state.rate_limit_cooldown - chrono::Duration::minutes(1);

    {
        let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
        identifier_rate_limit.insert(
            identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                last_request: expired_at,
                attempts: 2,
                failed_attempts: 2,
            },
        );
        identifier_rate_limit.insert(
            identifier_hash(SHA256_222222).unwrap(),
            RateLimitInfo {
                last_request: now,
                attempts: 1,
                failed_attempts: 1,
            },
        );
    }

    crate::rate_limit::sweep_expired_identifiers(&state).await;

    let identifier_rate_limit = state.identifier_rate_limit.lock().await;
    assert!(
        !identifier_rate_limit.contains_key(&identifier_hash(SHA256_111111).unwrap()),
        "expired entry should have been swept"
    );
    assert!(
        identifier_rate_limit.contains_key(&identifier_hash(SHA256_222222).unwrap()),
        "fresh entry should be kept"
    );
}

#[tokio::test]
async fn test_fetch_expires_sub_threshold_entry_after_cooldown() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    // an expired entry below the max attempts threshold
    {
        let mut identifier_rate_limit = state.identifier_rate_limit.lock().await;
        identifier_rate_limit.insert(
            identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                last_request: chrono::Utc::now()
                    - state.rate_limit_cooldown
                    - chrono::Duration::minutes(1),
                attempts: 2,
                failed_attempts: 2,
            },
        );
    }

    // the next failed attempt must restart the count at 1, not continue to 3:
    // the expired entry is discarded before the check
    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    let failed_attempt = response.json::<ResponseFailedAttempt>();
    assert_eq!(failed_attempt.attempts, 1);
}

#[tokio::test]
async fn test_new_identifiers_fail_closed_when_rate_limit_map_is_full() {
    let mut state = crate::env::init();
    state.rate_limit_max_identifiers = 1;
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
    assert_eq!(second.status_code(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_database_concurrency_rejection_refunds_lookup_attempt() {
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

    let identifier_rate_limit = state.identifier_rate_limit.lock().await;
    assert!(!identifier_rate_limit.contains_key(&identifier_hash(SHA256_111111).unwrap()));
}
