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
                window_started_at: expired_at,
                last_request: expired_at,
                attempts: 2,
                failed_attempts: 2,
            },
        );
        identifier_rate_limit.insert(
            identifier_hash(SHA256_222222).unwrap(),
            RateLimitInfo {
                window_started_at: now,
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
        let window_started_at =
            chrono::Utc::now() - state.rate_limit_cooldown - chrono::Duration::minutes(1);
        identifier_rate_limit.insert(
            identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                window_started_at,
                last_request: window_started_at,
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

// Security regression: the attempt is reserved (`info.attempts += 1`) under
// the rate-limit lock *before* the handler awaits the database semaphore.
// `refund_attempt` only runs on the error branches reached *after* that
// await. If the request future is cancelled while it is suspended on the
// semaphore acquire - a route timeout, a client disconnect - the handler
// never resumes, the error branch is never reached, and the reservation is
// never refunded. A legitimate user then silently loses part of their
// attempt budget to server-side slowness, with no password ever checked.
//
// This test blocks the database semaphore (capacity 0, like the sibling
// concurrency test above) so the handler is guaranteed to suspend on
// `acquire_owned()`, then cancels the handler future well before the
// production 1s `DATABASE_PERMIT_TIMEOUT` elapses - emulating what an axum
// route timeout or a dropped connection does to the in-flight future.
#[tokio::test]
async fn test_cancelled_request_does_not_consume_an_attempt() {
    let mut state = crate::env::init();
    state.database_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    crate::database::init_db(state.clone());

    let request = FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: NOT_PASSWORD_HASH.to_string(),
    };

    // Call the handler directly (bypassing the HTTP server) so cancellation
    // targets exactly the point we want to exercise: the handler is
    // suspended inside `state.database_semaphore.acquire_owned()`, strictly
    // after the attempt reservation and strictly before any refund path.
    // The 100ms budget is well under the semaphore's own 1s timeout, so the
    // outer timeout is guaranteed to win the race and drop the future while
    // still parked on the semaphore.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        crate::handlers::fetch::fetch_secret(
            axum::extract::State(state.clone()),
            axum::Json(request),
            false,
        ),
    )
    .await;

    assert!(
        outcome.is_err(),
        "test setup invalid: the handler should still be suspended on the blocked \
         database semaphore when the 100ms budget expires"
    );

    let identifier_rate_limit = state.identifier_rate_limit.lock().await;
    let identifier_hash = identifier_hash(SHA256_111111).unwrap();
    let leaked_attempts = identifier_rate_limit
        .get(&identifier_hash)
        .map(|info| info.attempts)
        .unwrap_or(0);
    assert_eq!(
        leaked_attempts, 0,
        "cancelling the request while it awaits the database semaphore must not \
         consume an attempt: the reservation made before the await was never \
         refunded because the cancelled future never reached the refund branch"
    );
}
