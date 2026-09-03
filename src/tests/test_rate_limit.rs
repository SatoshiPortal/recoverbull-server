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
    let before = state.attempts.snapshot.collection_started_at().await;
    {
        let mut map = state.attempts.ledger.lock_for_test().await;
        let mut info = RateLimitInfo::new(chrono::Utc::now());
        info.candidates
            .insert("candidate-tag".to_owned(), CandidateState::Committed);
        map.insert(SHA256_111111.to_owned(), info);
    }
    crate::attempts::maintenance::wipe_identifier_rate_limit(
        &state.attempts.ledger,
        &state.attempts.snapshot,
    )
    .await;
    assert!(state.attempts.ledger.lock_for_test().await.is_empty());
    assert!(!state.attempts.snapshot.is_cached_for_test().await);
    assert!(state.attempts.snapshot.collection_started_at().await > before);
}

#[test]
fn test_global_wiper_first_deadline_is_delayed_by_period() {
    let now = tokio::time::Instant::now();
    let period = Duration::from_secs(24 * 60 * 60);
    assert_eq!(
        crate::attempts::maintenance::global_wiper_first_deadline(now, period),
        now + period
    );
}

#[test]
fn test_production_global_wipe_interval_is_24_hours() {
    assert_eq!(
        crate::attempts::maintenance::PRODUCTION_GLOBAL_WIPE_INTERVAL,
        Duration::from_secs(24 * 60 * 60)
    );
}

#[tokio::test]
async fn test_sweep_removes_only_expired_entries() {
    let (_, state) = crate::tests::test_server::new_test_server().await;

    let now = chrono::Utc::now();
    let expired_at = now - state.attempts.policy.cooldown() - chrono::Duration::minutes(1);

    {
        let mut identifier_rate_limit = state.attempts.ledger.lock_for_test().await;
        identifier_rate_limit.insert(
            identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                window_started_at: expired_at,
                last_candidate_at: expired_at,
                last_request_at: expired_at,
                // expiry decides on the monotonic clock: back-date it too
                last_candidate_instant: crate::tests::monotonic_age(
                    (state.attempts.policy.cooldown() + chrono::Duration::minutes(1))
                        .to_std()
                        .unwrap(),
                ),
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
                last_candidate_instant: tokio::time::Instant::now(),
                candidates: std::collections::HashMap::new(),
                failed_candidates: 1,
                total_requests: 1,
            },
        );
    }

    crate::attempts::maintenance::sweep_expired_identifiers(
        &state.attempts.ledger,
        state.attempts.policy.cooldown(),
    )
    .await;

    let identifier_rate_limit = state.attempts.ledger.lock_for_test().await;
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
        let mut identifier_rate_limit = state.attempts.ledger.lock_for_test().await;
        let window_started_at =
            chrono::Utc::now() - state.attempts.policy.cooldown() - chrono::Duration::minutes(1);
        identifier_rate_limit.insert(
            identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                window_started_at,
                last_candidate_at: window_started_at,
                last_request_at: window_started_at,
                // expiry decides on the monotonic clock: back-date it too
                last_candidate_instant: crate::tests::monotonic_age(
                    (state.attempts.policy.cooldown() + chrono::Duration::minutes(1))
                        .to_std()
                        .unwrap(),
                ),
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
    let mut state = crate::app::init();
    state.recovery.set_max_identifiers_for_test(1);
    state.storage.initialize().unwrap();
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
    let mut state = crate::app::init();
    state
        .recovery
        .set_database_semaphore_for_test(std::sync::Arc::new(tokio::sync::Semaphore::new(0)));
    state.storage.initialize().unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);

    let identifier_rate_limit = state.attempts.ledger.lock_for_test().await;
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
    let mut state = crate::app::init();
    state
        .recovery
        .set_database_semaphore_for_test(std::sync::Arc::new(tokio::sync::Semaphore::new(0)));
    state.storage.initialize().unwrap();

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
        ),
    )
    .await;

    assert!(
        outcome.is_err(),
        "test setup invalid: the handler should still be suspended on the blocked \
         database semaphore when the 100ms budget expires"
    );

    let identifier_rate_limit = state.attempts.ledger.lock_for_test().await;
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
    state.observability.counters.flush();

    let mut lock_connection =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    diesel::sql_query("BEGIN IMMEDIATE")
        .execute(&mut lock_connection)
        .expect("test must acquire the SQLite write lock");

    let request = FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    };
    let outcome = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        crate::handlers::fetch::trash_secret(
            axum::extract::State(state.clone()),
            axum::Json(request),
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
                crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
                    .unwrap();
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
            let counters = state.observability.counters.flush();
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

    let identifier_rate_limit = state.attempts.ledger.lock_for_test().await;
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
    let state = crate::app::init();
    state.storage.initialize().unwrap();
    let mut lock_connection =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
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
            let snapshot = state.observability.counters.flush();
            if snapshot.store_accepted == 1 {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached store operation did not report in time");
    assert_eq!(counted.store_accepted, 1);
    assert_eq!(state.observability.counters.flush().store_accepted, 0);
}

/// 20 concurrent requests on the same identifier, all cancelled while parked
/// on a blocked database semaphore. Only `max_attempts` are admitted and
/// reserved; the rest get an immediate 429. Every admitted reservation must
/// be refunded exactly once (immediate `try_lock` in `Drop` or the detached
/// task), and the identifier must keep its full budget afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrent_cancellation_refunds_every_reservation() {
    let mut state = crate::app::init();
    state
        .recovery
        .set_database_semaphore_for_test(std::sync::Arc::new(tokio::sync::Semaphore::new(0)));
    state.storage.initialize().unwrap();

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
                let map = state.attempts.ledger.lock_for_test().await;
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
    state.recovery.database_semaphore_for_test().add_permits(1);
    let response = crate::handlers::fetch::fetch_secret(
        axum::extract::State(state.clone()),
        axum::Json(request()),
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
    let mut state = crate::app::init();
    state
        .recovery
        .set_database_semaphore_for_test(std::sync::Arc::new(tokio::sync::Semaphore::new(0)));
    state.storage.initialize().unwrap();

    let request = FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: NOT_PASSWORD_HASH.to_string(),
    };
    let handler_state = state.clone();
    let handle = tokio::spawn(async move {
        crate::handlers::fetch::fetch_secret(
            axum::extract::State(handler_state),
            axum::Json(request),
        )
        .await;
    });

    // Wait for the reservation to land (the handler is then parked on the
    // blocked semaphore).
    let hash = identifier_hash(SHA256_111111).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            {
                let map = state.attempts.ledger.lock_for_test().await;
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
    let map_guard = state.attempts.ledger.lock_for_test().await;
    handle.abort();
    // Let the Drop run and the spawned task reach the contended lock.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(map_guard);

    // Only the deferred task can now refund: if it were broken, the
    // reservation would leak and this poll would time out.
    let settled = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            {
                let map = state.attempts.ledger.lock_for_test().await;
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

/// A forward `CLOCK_REALTIME` jump must not reset a per-identifier budget.
///
/// Expiry decides on the monotonic clock, so an entry whose *published*
/// wall-clock timestamps are far older than the cooldown — the state the map
/// is in right after the system clock is stepped forward — keeps its
/// saturated budget. Deciding on wall-clock time instead would hand an
/// attacker a full budget reset for every clock step, on a server whose only
/// control against password brute-force is that budget.
#[tokio::test]
async fn test_a_forward_wall_clock_jump_does_not_reset_a_saturated_budget() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let max = state.attempts.policy.max_attempts();

    // saturate the identifier through the ordinary admission path
    for index in 0..max as usize {
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

    // Step the wall clock far forward: only the published timestamps move,
    // the monotonic reading the expiry decision uses does not.
    let jump = state.attempts.policy.cooldown() + chrono::Duration::hours(24);
    {
        let mut map = state.attempts.ledger.lock_for_test().await;
        let info = map
            .get_mut(&identifier_hash(SHA256_111111).unwrap())
            .expect("the saturated entry is present");
        info.window_started_at -= jump;
        info.last_candidate_at -= jump;
        info.last_request_at -= jump;
    }

    let response = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: crate::tests::distinct_candidate(max as usize + 1),
        })
        .expect_failure()
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::TOO_MANY_REQUESTS,
        "a forward wall-clock jump must not grant a fresh candidate budget"
    );

    let map = state.attempts.ledger.lock_for_test().await;
    let info = &map[&identifier_hash(SHA256_111111).unwrap()];
    assert_eq!(
        info.candidate_count(),
        max,
        "the budget must still be fully consumed after the jump"
    );
}

/// The expiry sweeper follows the same monotonic decision: a forward
/// wall-clock jump must not sweep the whole map and reset every budget.
#[tokio::test]
async fn test_a_forward_wall_clock_jump_does_not_sweep_active_entries() {
    let (_, state) = crate::tests::test_server::new_test_server().await;

    let jumped_past =
        chrono::Utc::now() - state.attempts.policy.cooldown() - chrono::Duration::hours(24);
    {
        let mut map = state.attempts.ledger.lock_for_test().await;
        // published timestamps far in the past, monotonic reading fresh
        let mut info = RateLimitInfo::new(jumped_past);
        info.failed_candidates = 2;
        info.total_requests = 2;
        map.insert(identifier_hash(SHA256_111111).unwrap(), info);
    }

    crate::attempts::maintenance::sweep_expired_identifiers(
        &state.attempts.ledger,
        state.attempts.policy.cooldown(),
    )
    .await;

    let map = state.attempts.ledger.lock_for_test().await;
    assert!(
        map.contains_key(&identifier_hash(SHA256_111111).unwrap()),
        "an entry that is only wall-clock-old must survive the sweep"
    );
}

/// `Retry-After` on a global-bucket `503` is the server's own estimate of
/// when the next token exists, derived from the configured refill rate under
/// the same lock as the refusal. A fixed `1` was only right for the default
/// rates: with a refill of one token per ten seconds it told clients to
/// retry ten times too early, turning the backoff into extra load.
#[tokio::test]
async fn test_global_bucket_retry_after_follows_the_configured_refill() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    state
        .recovery
        .set_lookup_bucket_for_test(crate::rate_limit::TokenBucket::new(1.0, 0.1))
        .await;

    let first = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(
        first.status_code(),
        StatusCode::UNAUTHORIZED,
        "the burst token"
    );

    let refused = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    assert_eq!(refused.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    let retry_after: u64 = refused
        .header("retry-after")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        retry_after, 10,
        "an empty bucket refilling at 0.1 token/s needs ten seconds for one token"
    );
}

/// The bucket's refill path on an injected clock: burst, refusal with the
/// computed backoff, fractional credit retained across a refusal, exact
/// refill, and the capacity cap after a long idle period. No sleeping.
#[test]
fn test_token_bucket_refill_is_deterministic_on_an_injected_clock() {
    use crate::rate_limit::{BucketDecision, TokenBucket};
    let start = std::time::Instant::now();
    let at = |seconds: u64| start + Duration::from_secs(seconds);
    let mut bucket = TokenBucket::new_at(2.0, 0.1, start);

    assert_eq!(bucket.try_consume_at(start), BucketDecision::Consumed);
    assert_eq!(bucket.try_consume_at(start), BucketDecision::Consumed);
    assert_eq!(
        bucket.try_consume_at(start),
        BucketDecision::Rejected {
            retry_after_secs: 10
        },
        "an empty bucket at 0.1 token/s needs ten seconds"
    );
    assert_eq!(
        bucket.try_consume_at(at(5)),
        BucketDecision::Rejected {
            retry_after_secs: 5
        },
        "half a token of credit is retained, so half the wait remains"
    );
    assert_eq!(
        bucket.try_consume_at(at(10)),
        BucketDecision::Consumed,
        "exactly one token after the announced wait"
    );
    assert_eq!(
        bucket.try_consume_at(at(10)),
        BucketDecision::Rejected {
            retry_after_secs: 10
        }
    );
    // a long idle period refills to the capacity, not beyond it
    assert_eq!(bucket.try_consume_at(at(1_000)), BucketDecision::Consumed);
    assert_eq!(bucket.try_consume_at(at(1_000)), BucketDecision::Consumed);
    assert_eq!(
        bucket.try_consume_at(at(1_000)),
        BucketDecision::Rejected {
            retry_after_secs: 10
        }
    );
}

/// The advertised backoff is rounded up and never below one second, and a
/// bucket without refill has no deadline to derive: it keeps the advisory
/// one-second value (the zero-refill mode itself is a separate decision).
#[test]
fn test_token_bucket_backoff_rounds_up_and_floors_at_one_second() {
    use crate::rate_limit::{BucketDecision, TokenBucket};
    let start = std::time::Instant::now();

    // 2 tokens/s: half a second rounds up to the one-second floor
    let mut fast = TokenBucket::new_at(1.0, 2.0, start);
    assert_eq!(fast.try_consume_at(start), BucketDecision::Consumed);
    assert_eq!(
        fast.try_consume_at(start),
        BucketDecision::Rejected {
            retry_after_secs: 1
        }
    );

    // 0.3 token/s: 3.33 seconds rounds up to 4
    let mut slow = TokenBucket::new_at(1.0, 0.3, start);
    assert_eq!(slow.try_consume_at(start), BucketDecision::Consumed);
    assert_eq!(
        slow.try_consume_at(start),
        BucketDecision::Rejected {
            retry_after_secs: 4
        }
    );

    // fractional capacity: 1.5 tokens leaves half a token after one consume
    let mut fractional = TokenBucket::new_at(1.5, 1.0, start);
    assert_eq!(fractional.try_consume_at(start), BucketDecision::Consumed);
    assert_eq!(
        fractional.try_consume_at(start),
        BucketDecision::Rejected {
            retry_after_secs: 1
        }
    );
    assert_eq!(
        fractional.try_consume_at(start + Duration::from_millis(500)),
        BucketDecision::Consumed
    );

    // no refill: never refills, and the backoff stays advisory
    let mut quota = TokenBucket::new_at(1.0, 0.0, start);
    assert_eq!(quota.try_consume_at(start), BucketDecision::Consumed);
    assert_eq!(
        quota.try_consume_at(start + Duration::from_secs(1_000_000)),
        BucketDecision::Rejected {
            retry_after_secs: 1
        }
    );
}
