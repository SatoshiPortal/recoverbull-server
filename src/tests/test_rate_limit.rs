use crate::{
    models::{FetchSecret, RateLimitInfo, ResponseFailedAttempt},
    tests::{NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
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
            SHA256_111111.to_string(),
            RateLimitInfo {
                last_request: expired_at,
                attempts: 2,
            },
        );
        identifier_rate_limit.insert(
            SHA256_222222.to_string(),
            RateLimitInfo {
                last_request: now,
                attempts: 1,
            },
        );
    }

    crate::rate_limit::sweep_expired_identifiers(&state).await;

    let identifier_rate_limit = state.identifier_rate_limit.lock().await;
    assert!(
        !identifier_rate_limit.contains_key(SHA256_111111),
        "expired entry should have been swept"
    );
    assert!(
        identifier_rate_limit.contains_key(SHA256_222222),
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
            SHA256_111111.to_string(),
            RateLimitInfo {
                last_request: chrono::Utc::now()
                    - state.rate_limit_cooldown
                    - chrono::Duration::minutes(1),
                attempts: 2,
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
