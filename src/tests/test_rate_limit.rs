use crate::{
    attempts::ledger::{CandidateState, RateLimitInfo},
    http::contract::{FetchSecret, ResponseFailedAttempt, StoreSecret},
    recovery::identifiers::{generate_secret_id, identifier_hash},
    tests::{BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
};
use axum::http::StatusCode;
use diesel::RunQueryDsl;
use std::time::Duration;

#[tokio::test]
async fn test_global_wipe_clears_candidates_resets_timestamp_and_snapshot() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    server.get("/attempts").expect_success().await;
    let before = *state.attempts_collection_started_at.lock().await;
    {
        let mut map = state.identifier_rate_limit.lock_for_test().await;
        let mut info = RateLimitInfo::new(chrono::Utc::now());
        info.candidates
            .insert("candidate-tag".to_owned(), CandidateState::Committed);
        map.insert(SHA256_111111.to_owned(), info);
    }
    crate::rate_limit::wipe_identifier_rate_limit(&state).await;
    assert!(state.identifier_rate_limit.lock_for_test().await.is_empty());
    assert!(state.attempts_snapshot.lock().await.is_none());
    assert!(*state.attempts_collection_started_at.lock().await > before);
}

#[test]
fn test_global_wiper_first_deadline_is_delayed_by_period() {
    let now = tokio::time::Instant::now();
    let period = Duration::from_secs(24 * 60 * 60);
    assert_eq!(
        crate::rate_limit::global_wiper_first_deadline(now, period),
        now + period
    );
}

#[test]
fn test_production_global_wipe_interval_is_24_hours() {
    assert_eq!(
        crate::rate_limit::PRODUCTION_GLOBAL_WIPE_INTERVAL,
        Duration::from_secs(24 * 60 * 60)
    );
}

#[tokio::test]
async fn test_sweep_removes_only_expired_entries() {
    let (_, state) = crate::tests::test_server::new_test_server().await;

    let now = chrono::Utc::now();
    let expired_at = now - state.rate_limit_cooldown - chrono::Duration::minutes(1);

    {
        let mut identifier_rate_limit = state.identifier_rate_limit.lock_for_test().await;
        identifier_rate_limit.insert(
            identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                window_started_at: expired_at,
                last_candidate_at: expired_at,
                last_request_at: expired_at,
                candidates: std::collections::HashMap::new(),
                failed_candidates: 2,
                total_requests: 2,
            },
        );
        identifier_rate_limit.insert(
            identifier_hash(SHA256_222222).unwrap(),
            RateLimitInfo {
                window_started_at: now,
                last_candidate_at: now,
                last_request_at: now,
                candidates: std::collections::HashMap::new(),
                failed_candidates: 1,
                total_requests: 1,
            },
        );
    }

    crate::rate_limit::sweep_expired_identifiers(&state).await;

    let identifier_rate_limit = state.identifier_rate_limit.lock_for_test().await;
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
        let mut identifier_rate_limit = state.identifier_rate_limit.lock_for_test().await;
        let window_started_at =
            chrono::Utc::now() - state.rate_limit_cooldown - chrono::Duration::minutes(1);
        identifier_rate_limit.insert(
            identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                window_started_at,
                last_candidate_at: window_started_at,
                last_request_at: window_started_at,
                candidates: std::collections::HashMap::new(),
                failed_candidates: 2,
                total_requests: 2,
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
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state)).unwrap();

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
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);

    let identifier_rate_limit = state.identifier_rate_limit.lock_for_test().await;
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
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();

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

    let identifier_rate_limit = state.identifier_rate_limit.lock_for_test().await;
    let identifier_hash = identifier_hash(SHA256_111111).unwrap();
    let leaked_attempts = identifier_rate_limit
        .get(&identifier_hash)
        .map(|info| info.candidate_count())
        .unwrap_or(0);
    assert_eq!(
        leaked_attempts, 0,
        "cancelling the request while it awaits the database semaphore must not \
         consume an attempt: the reservation made before the await was never \
         refunded because the cancelled future never reached the refund branch"
    );
}

// Once the SQLite operation has started, the attempt is committed even if the
// HTTP future is cancelled: the detached blocking closure continues and
// `/trash` may delete the secret. HTTP cannot guarantee delivery after commit;
// this test covers the accounting boundary, not response delivery.
#[tokio::test]
async fn test_cancelled_trash_after_sqlite_start_keeps_attempt_reserved() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let store = StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    server.post("/store").json(&store).expect_success().await;
    state.security_counters.flush();

    let mut lock_connection =
        crate::storage::sqlite::establish_connection(state.database_url.clone()).unwrap();
    diesel::sql_query("BEGIN IMMEDIATE")
        .execute(&mut lock_connection)
        .expect("test must acquire the SQLite write lock");

    let request = FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    };
    let outcome = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        crate::handlers::fetch::fetch_secret(
            axum::extract::State(state.clone()),
            axum::Json(request),
            true,
        ),
    )
    .await;
    assert!(
        outcome.is_err(),
        "test setup invalid: trash should still be waiting on SQLite"
    );

    // Always release the test lock before checking either observable. The
    // detached blocking task must then be allowed to finish its transaction.
    diesel::sql_query("COMMIT")
        .execute(&mut lock_connection)
        .expect("test must release the SQLite write lock");

    let secret_id = generate_secret_id(SHA256_111111, SHA256_222222);
    let deletion = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let mut connection =
                crate::storage::sqlite::establish_connection(state.database_url.clone()).unwrap();
            let remaining = crate::storage::sqlite::read_secret_by_id(&mut connection, &secret_id)
                .expect("secret lookup must succeed after releasing the test lock");
            if remaining.is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        deletion.is_ok(),
        "detached trash operation did not finish in time"
    );

    let mut lookup_accepted = 0;
    let mut trash_hit = 0;
    let mut trash_miss = 0;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let counters = state.security_counters.flush();
            lookup_accepted += counters.lookup_accepted;
            trash_hit += counters.trash_hit;
            trash_miss += counters.trash_miss;
            if trash_hit >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("detached trash counters did not finish in time");

    let identifier_rate_limit = state.identifier_rate_limit.lock_for_test().await;
    assert_eq!(
        identifier_rate_limit
            .get(&identifier_hash(SHA256_111111).unwrap())
            .map(|info| info.candidate_count()),
        Some(1),
        "once SQLite has started, cancelling HTTP must not refund the committed attempt"
    );
    assert_eq!(lookup_accepted, 1);
    assert_eq!(trash_hit, 1);
    assert_eq!(trash_miss, 0);
}

#[tokio::test]
async fn test_cancelled_store_after_sqlite_start_counts_once() {
    let state = crate::env::init();
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let mut lock_connection =
        crate::storage::sqlite::establish_connection(state.database_url.clone()).unwrap();
    diesel::sql_query("BEGIN IMMEDIATE")
        .execute(&mut lock_connection)
        .expect("test must acquire the SQLite write lock");

    let request = StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    let outcome = tokio::time::timeout(
        Duration::from_millis(100),
        crate::handlers::store::store_secret(
            axum::extract::State(state.clone()),
            axum::Json(request),
        ),
    )
    .await;
    assert!(outcome.is_err(), "store should still be waiting on SQLite");

    diesel::sql_query("COMMIT")
        .execute(&mut lock_connection)
        .expect("test must release the SQLite write lock");

    let counted = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = state.security_counters.flush();
            if snapshot.store_accepted == 1 {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached store operation did not report in time");
    assert_eq!(counted.store_accepted, 1);
    assert_eq!(state.security_counters.flush().store_accepted, 0);
}

/// 20 concurrent requests on the same identifier, all cancelled while parked
/// on a blocked database semaphore. Only `max_attempts` are admitted and
/// reserved; the rest get an immediate 429. Every admitted reservation must
/// be refunded exactly once (immediate `try_lock` in `Drop` or the detached
/// task), and the identifier must keep its full budget afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrent_cancellation_refunds_every_reservation() {
    let mut state = crate::env::init();
    state.database_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();

    let request = || FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: NOT_PASSWORD_HASH.to_string(),
    };

    let mut handles = Vec::new();
    for _ in 0..20 {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                crate::handlers::fetch::fetch_secret(
                    axum::extract::State(state),
                    axum::Json(request()),
                    false,
                ),
            )
            .await
        }));
    }
    for handle in handles {
        let _ = handle.await.unwrap();
    }

    // Poll until the deferred refunds land (they complete in milliseconds).
    let hash = identifier_hash(SHA256_111111).unwrap();
    let settled = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            {
                let map = state.identifier_rate_limit.lock_for_test().await;
                if map
                    .get(&hash)
                    .map(|info| info.candidate_count())
                    .unwrap_or(0)
                    == 0
                {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "cancelled reservations were not all refunded within 2s"
    );

    // No phantom budget loss: the identifier must be admitted again. Give the
    // semaphore a permit so the request can reach the (empty) database.
    state.database_semaphore.add_permits(1);
    let response = crate::handlers::fetch::fetch_secret(
        axum::extract::State(state.clone()),
        axum::Json(request()),
        false,
    )
    .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNAUTHORIZED,
        "a cancellation storm must not leak the attempt budget (expected 401, no row)"
    );
}

/// The guard's `Drop` falls back to a detached task when the map lock is
/// contended at drop time. This test holds the map lock while the handler
/// future is aborted, which forces the deferred path (the immediate
/// `try_lock` cannot succeed), then releases it: the refund must still land.
/// If the deferred path were broken, the reservation would leak forever.
#[tokio::test]
async fn test_deferred_refund_runs_when_drop_finds_the_lock_contended() {
    let mut state = crate::env::init();
    state.database_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();

    let request = FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: NOT_PASSWORD_HASH.to_string(),
    };
    let handler_state = state.clone();
    let handle = tokio::spawn(async move {
        crate::handlers::fetch::fetch_secret(
            axum::extract::State(handler_state),
            axum::Json(request),
            false,
        )
        .await;
    });

    // Wait for the reservation to land (the handler is then parked on the
    // blocked semaphore).
    let hash = identifier_hash(SHA256_111111).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            {
                let map = state.identifier_rate_limit.lock_for_test().await;
                if map
                    .get(&hash)
                    .map(|info| info.candidate_count())
                    .unwrap_or(0)
                    == 1
                {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("test setup invalid: the reservation never landed");

    // Hold the map lock across the abort: the guard's Drop cannot take the
    // immediate try_lock path and must spawn the deferred refund task.
    let map_guard = state.identifier_rate_limit.lock_for_test().await;
    handle.abort();
    // Let the Drop run and the spawned task reach the contended lock.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(map_guard);

    // Only the deferred task can now refund: if it were broken, the
    // reservation would leak and this poll would time out.
    let settled = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            {
                let map = state.identifier_rate_limit.lock_for_test().await;
                if map
                    .get(&hash)
                    .map(|info| info.candidate_count())
                    .unwrap_or(0)
                    == 0
                {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "the deferred refund task did not run: the reservation leaked"
    );
}
