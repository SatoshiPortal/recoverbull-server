use crate::{
    attempts::ledger::RateLimitInfo,
    http::contract::{FetchSecret, ResponseFailedAttempt, StoreSecret},
    recovery::identifiers::identifier_hash,
    tests::{BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
};
use axum::http::StatusCode;
use diesel::RunQueryDsl;

async fn wait_for_attempts(state: &crate::AppState, expected: u8) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if state
                .attempts
                .ledger
                .lock_for_test()
                .await
                .get(&identifier_hash(SHA256_111111).unwrap())
                .is_some_and(|info| info.consumed_slots() == expected)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("test setup invalid: expected rate-limit reservations did not land");
}

async fn trash(state: crate::AppState, authentication_key: &str) -> StatusCode {
    crate::handlers::fetch::trash_secret(
        axum::extract::State(state),
        axum::Json(fetch(SHA256_111111, authentication_key)),
    )
    .await
    .status()
}

fn fetch(identifier: &str, authentication_key: &str) -> FetchSecret {
    FetchSecret {
        identifier: identifier.to_owned(),
        authentication_key: authentication_key.to_owned(),
    }
}

fn store(identifier: &str, authentication_key: &str, encrypted_secret: &str) -> StoreSecret {
    StoreSecret {
        identifier: identifier.to_owned(),
        authentication_key: authentication_key.to_owned(),
        encrypted_secret: encrypted_secret.to_owned(),
    }
}

#[tokio::test]
async fn test_replaying_one_valid_secret_id_does_not_consume_more_slots() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    server
        .post("/store")
        .json(&store(
            SHA256_111111,
            SHA256_222222,
            BASE64_ENCRYPTED_SECRET,
        ))
        .expect_success()
        .await;

    for request_number in 1..=5 {
        let response = server
            .post("/fetch")
            .json(&fetch(SHA256_111111, SHA256_222222))
            .expect_success()
            .await;
        // A replay of the same secret_id must be idempotent, not a new lookup.
        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["attempt_status"]["version"], 1);
        assert_eq!(body["attempt_status"]["total_attempts"], 1);
        assert_eq!(body["attempt_status"]["total_requests"], request_number);
    }
}

#[tokio::test]
async fn test_replaying_one_invalid_secret_id_does_not_consume_more_slots() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    for _ in 0..5 {
        let response = server
            .post("/fetch")
            .json(&fetch(SHA256_111111, NOT_PASSWORD_HASH))
            .expect_failure()
            .await;
        // Replaying one bad secret_id remains an authentication failure, not 429.
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.json::<ResponseFailedAttempt>().attempts, 1);
    }
}

#[tokio::test]
async fn test_fetch_and_trash_share_one_secret_id_slot() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    server
        .post("/store")
        .json(&store(
            SHA256_111111,
            SHA256_222222,
            BASE64_ENCRYPTED_SECRET,
        ))
        .expect_success()
        .await;

    server
        .post("/fetch")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .expect_success()
        .await;
    let response = server
        .post("/trash")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .expect_success()
        .await;

    // Fetch and trash for one secret_id must observe one logical attempt.
    assert_eq!(response.status_code(), StatusCode::ACCEPTED);
    assert_eq!(
        response.json::<serde_json::Value>()["attempt_status"]["total_attempts"],
        1
    );
}

#[tokio::test]
async fn test_replaying_one_secret_id_does_not_slide_resets_at() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    server
        .post("/store")
        .json(&store(
            SHA256_111111,
            SHA256_222222,
            BASE64_ENCRYPTED_SECRET,
        ))
        .expect_success()
        .await;

    let first = server
        .post("/fetch")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .expect_success()
        .await;
    let first_resets_at = first.json::<serde_json::Value>()["attempt_status"]["resets_at"]
        .as_str()
        .expect("successful fetch must report resets_at")
        .to_owned();

    // Keep the delay short: the oracle is timestamp stability, not cooldown expiry.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    let second = server
        .post("/fetch")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .expect_success()
        .await;
    let second_resets_at = second.json::<serde_json::Value>()["attempt_status"]["resets_at"]
        .as_str()
        .expect("successful replay must report resets_at")
        .to_owned();

    // A replay must not renew the secret_id's cooldown window.
    assert_eq!(second_resets_at, first_resets_at);
}

#[tokio::test]
async fn test_known_secret_id_is_rejected_when_the_budget_is_full() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let secret_ids = [
        SHA256_222222,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
    ];

    for authentication_key in secret_ids {
        let response = server
            .post("/fetch")
            .json(&fetch(SHA256_111111, authentication_key))
            .await;
        // Each new secret_id consumes one admission, even when authentication fails.
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    let response = server
        .post("/fetch")
        .json(&fetch(SHA256_111111, secret_ids[0]))
        .await;
    // Full capacity must fail closed; a known secret_id must not bypass it.
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_distinct_planted_secret_ids_consume_capacity() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let secret_ids = [
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000000000000000000000000000000000000000000003",
    ];

    for (index, authentication_key) in secret_ids.into_iter().enumerate() {
        let marker = "dGVzdA==";
        server
            .post("/store")
            .json(&store(SHA256_111111, authentication_key, marker))
            .expect_success()
            .await;
        let response = server
            .post("/fetch")
            .json(&fetch(SHA256_111111, authentication_key))
            .expect_success()
            .await;
        let body = response.json::<serde_json::Value>();
        // A planted hit is still a counted secret_id, preserving the anti-bypass oracle.
        assert_eq!(body["encrypted_secret"], marker);
        assert_eq!(body["attempt_status"]["total_attempts"], index + 1);
    }

    let fourth = server
        .post("/fetch")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .await;
    // Three planted secret_ids exhaust the distinct-secret_id admission budget.
    assert_eq!(fourth.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_pending_duplicate_trash_is_rejected_without_a_second_reservation() {
    let (server, mut state) = crate::tests::test_server::new_test_server().await;
    server
        .post("/store")
        .json(&store(
            SHA256_111111,
            SHA256_222222,
            BASE64_ENCRYPTED_SECRET,
        ))
        .expect_success()
        .await;
    // Keep one free slot so checking Pending before saturation cannot become
    // a membership oracle. Once the budget is full, every secret_id — known
    // or unknown, Pending or Committed — must receive the same 429.
    state.recovery.set_max_attempts_for_test(3);

    let mut lock_connection =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    diesel::sql_query("BEGIN IMMEDIATE")
        .execute(&mut lock_connection)
        .expect("test must acquire the SQLite write lock");

    let first = tokio::spawn(trash(state.clone(), SHA256_222222));
    wait_for_attempts(&state, 1).await;

    let second = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        trash(state.clone(), SHA256_222222),
    )
    .await
    .expect("duplicate pending trash must be rejected promptly");
    assert_eq!(second, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        state
            .attempts
            .ledger
            .lock_for_test()
            .await
            .get(&identifier_hash(SHA256_111111).unwrap())
            .map(|info| info.consumed_slots()),
        Some(1),
        "a pending duplicate must not reserve another attempt"
    );

    diesel::sql_query("COMMIT")
        .execute(&mut lock_connection)
        .expect("test must release the SQLite write lock");
    let first_status = tokio::time::timeout(std::time::Duration::from_secs(1), first)
        .await
        .expect("first trash did not finish after releasing SQLite")
        .expect("first trash task panicked");
    assert_eq!(first_status, StatusCode::ACCEPTED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_pending_distinct_secret_ids_consume_the_budget() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let secret_ids = [
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000000000000000000000000000000000000000000003",
    ];
    for authentication_key in secret_ids {
        server
            .post("/store")
            .json(&store(SHA256_111111, authentication_key, "dGVzdA=="))
            .expect_success()
            .await;
    }

    let mut lock_connection =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    diesel::sql_query("BEGIN IMMEDIATE")
        .execute(&mut lock_connection)
        .expect("test must acquire the SQLite write lock");

    let first = tokio::spawn(trash(state.clone(), secret_ids[0]));
    let second = tokio::spawn(trash(state.clone(), secret_ids[1]));
    let third = tokio::spawn(trash(state.clone(), secret_ids[2]));
    wait_for_attempts(&state, 3).await;

    let fourth = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        trash(state.clone(), SHA256_222222),
    )
    .await
    .expect("budget exhaustion must be decided before the blocked database");
    assert_eq!(fourth, StatusCode::TOO_MANY_REQUESTS);

    diesel::sql_query("COMMIT")
        .execute(&mut lock_connection)
        .expect("test must release the SQLite write lock");
    for task in [first, second, third] {
        let status = tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("pending trash did not finish after releasing SQLite")
            .expect("pending trash task panicked");
        assert_eq!(status, StatusCode::ACCEPTED);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_old_trash_completion_cannot_update_a_replaced_rate_limit_window() {
    let (_server, state) = crate::tests::test_server::new_test_server().await;
    let mut lock_connection =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    diesel::sql_query("BEGIN IMMEDIATE")
        .execute(&mut lock_connection)
        .expect("test must acquire the SQLite write lock");

    let old_trash = tokio::spawn(trash(state.clone(), SHA256_222222));
    wait_for_attempts(&state, 1).await;

    let fresh_at = chrono::Utc::now();
    let id_hash = identifier_hash(SHA256_111111).unwrap();
    state.attempts.ledger.lock_for_test().await.insert(
        id_hash.clone(),
        RateLimitInfo {
            window_started_at: fresh_at,
            last_secret_id_at: fresh_at,
            last_request_at: fresh_at,
            last_secret_id_instant: tokio::time::Instant::now(),
            secret_ids: std::collections::HashMap::new(),
            forgotten_slots: 0,
            failed_secret_ids: 0,
            total_requests: 0,
        },
    );

    diesel::sql_query("COMMIT")
        .execute(&mut lock_connection)
        .expect("test must release the SQLite write lock");
    let status = tokio::time::timeout(std::time::Duration::from_secs(1), old_trash)
        .await
        .expect("missing trash did not finish after releasing SQLite")
        .expect("missing trash task panicked");
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let info = state
        .attempts
        .ledger
        .lock_for_test()
        .await
        .get(&id_hash)
        .cloned()
        .expect("fresh rate-limit window must remain present");
    assert_eq!(info.window_started_at, fresh_at);
    assert_eq!(info.last_request_at, fresh_at);
    assert_eq!(info.consumed_slots(), 0);
    assert_eq!(info.failed_secret_ids, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_trash_hit_does_not_count_the_losing_miss_as_a_guess() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    server
        .post("/store")
        .json(&store(
            SHA256_111111,
            SHA256_222222,
            BASE64_ENCRYPTED_SECRET,
        ))
        .expect_success()
        .await;

    let mut lock_connection =
        crate::storage::sqlite::establish_connection(state.storage.database_url_for_test())
            .unwrap();
    diesel::sql_query("BEGIN IMMEDIATE")
        .execute(&mut lock_connection)
        .expect("test must acquire the SQLite write lock");
    let first = tokio::spawn(trash(state.clone(), SHA256_222222));
    wait_for_attempts(&state, 1).await;
    let second = tokio::spawn(trash(state.clone(), SHA256_222222));
    let second_status = tokio::time::timeout(std::time::Duration::from_millis(100), second)
        .await
        .expect("pending duplicate must be rejected promptly")
        .expect("duplicate trash task panicked");
    assert_eq!(second_status, StatusCode::SERVICE_UNAVAILABLE);
    diesel::sql_query("COMMIT")
        .execute(&mut lock_connection)
        .expect("test must release the SQLite write lock");
    let first_status = first.await.expect("first trash task panicked");
    assert_eq!(first_status, StatusCode::ACCEPTED);

    let info = state
        .attempts
        .ledger
        .lock_for_test()
        .await
        .get(&identifier_hash(SHA256_111111).unwrap())
        .cloned()
        .expect("trash requests must create a rate-limit entry");
    assert_eq!(info.failed_secret_ids, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_committed_trash_race_returns_accepted_and_unauthorized_without_failure() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    server
        .post("/store")
        .json(&store(
            SHA256_111111,
            SHA256_222222,
            BASE64_ENCRYPTED_SECRET,
        ))
        .expect_success()
        .await;
    server
        .post("/fetch")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .expect_success()
        .await;

    let first = tokio::spawn(trash(state.clone(), SHA256_222222));
    let second = tokio::spawn(trash(state.clone(), SHA256_222222));
    let statuses = [
        first.await.expect("first trash task panicked"),
        second.await.expect("second trash task panicked"),
    ];
    assert!(statuses.contains(&StatusCode::ACCEPTED));
    assert!(statuses.contains(&StatusCode::UNAUTHORIZED));
    let info = state
        .attempts
        .ledger
        .lock_for_test()
        .await
        .get(&identifier_hash(SHA256_111111).unwrap())
        .cloned()
        .expect("trash requests must create a rate-limit entry");
    assert_eq!(info.failed_secret_ids, 0);
}

/// After a successful `/trash`, the secret_id that authenticated the deletion
/// must be indistinguishable from any other secret_id: same status, same
/// counters. Keeping its `secret_id` recognizable made its replay free (`attempts`
/// unchanged) while a different PIN consumed a slot (`attempts` + 1), which
/// told a Backup File holder which PIN had been used for the deletion.
#[tokio::test]
async fn test_deleted_secret_id_is_indistinguishable_from_a_new_one_after_trash() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let mut observed = Vec::new();
    for (identifier, probe) in [
        (SHA256_111111, SHA256_222222),     // the PIN used for the deletion
        (SHA256_222222, NOT_PASSWORD_HASH), // a different PIN
    ] {
        server
            .post("/store")
            .json(&store(identifier, SHA256_222222, BASE64_ENCRYPTED_SECRET))
            .expect_success()
            .await;
        let deleted = server
            .post("/trash")
            .json(&fetch(identifier, SHA256_222222))
            .expect_success()
            .await;
        assert_eq!(deleted.status_code(), StatusCode::ACCEPTED);

        let response = server
            .post("/fetch")
            .json(&fetch(identifier, probe))
            .expect_failure()
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        let body = response.json::<ResponseFailedAttempt>();
        let info = state
            .attempts
            .ledger
            .lock_for_test()
            .await
            .get(&identifier_hash(identifier).unwrap())
            .cloned()
            .expect("the entry survives the deletion");
        observed.push((
            body.attempts,
            body.total_requests,
            info.consumed_slots(),
            info.failed_secret_ids,
        ));
    }
    assert_eq!(
        observed[0], observed[1],
        "deleted PIN and new PIN must produce identical counters after a trash"
    );
    assert_eq!(observed[0].0, 2, "the deletion's slot stays consumed");
}

/// The replay path forgets too: a secret_id committed by a `/fetch` hit and
/// then replayed by a `/trash` that deletes the row is no longer recognizable.
/// The trash response itself still reports one attempt, because the budget
/// is unchanged by the deletion.
#[tokio::test]
async fn test_trash_of_a_fetched_secret_id_forgets_it_without_refunding_the_slot() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    server
        .post("/store")
        .json(&store(
            SHA256_111111,
            SHA256_222222,
            BASE64_ENCRYPTED_SECRET,
        ))
        .expect_success()
        .await;
    server
        .post("/fetch")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .expect_success()
        .await;
    let trashed = server
        .post("/trash")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .expect_success()
        .await;
    assert_eq!(
        trashed.json::<serde_json::Value>()["attempt_status"]["total_attempts"],
        1
    );
    // the detached worker forgets the `secret_id` after the response; wait for it
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let forgotten = state
                .attempts
                .ledger
                .lock_for_test()
                .await
                .get(&identifier_hash(SHA256_111111).unwrap())
                .is_some_and(|info| info.secret_ids.is_empty() && info.consumed_slots() == 1);
            if forgotten {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the deleted secret_id must be forgotten");

    let response = server
        .post("/fetch")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.json::<ResponseFailedAttempt>().attempts, 2);
}

/// A forgotten slot is budget: it survives refunds and counts toward
/// saturation, so a deletion never hands back an attempt. Re-storing the
/// secret in the same window does not recover the slot either.
#[tokio::test]
async fn test_forgotten_slots_count_toward_saturation_and_survive_refunds() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let max = state.attempts.policy.max_attempts();
    let id_hash = identifier_hash(SHA256_111111).unwrap();
    server
        .post("/store")
        .json(&store(
            SHA256_111111,
            SHA256_222222,
            BASE64_ENCRYPTED_SECRET,
        ))
        .expect_success()
        .await;
    server
        .post("/trash")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .expect_success()
        .await;

    // a refund of a Pending secret_id must not drop the entry holding the slot
    let generation = state
        .attempts
        .ledger
        .lock_for_test()
        .await
        .get(&id_hash)
        .expect("entry")
        .window_started_at;
    state
        .attempts
        .ledger
        .lock_for_test()
        .await
        .get_mut(&id_hash)
        .expect("entry")
        .secret_ids
        .insert(
            "pending-secret-id".to_owned(),
            crate::attempts::ledger::SecretIdState::Pending,
        );
    state
        .attempts
        .ledger
        .refund(&id_hash, "pending-secret-id", generation)
        .await;
    let info = state
        .attempts
        .ledger
        .lock_for_test()
        .await
        .get(&id_hash)
        .cloned()
        .expect("the entry keeps the consumed slot through a refund");
    assert_eq!(info.consumed_slots(), 1);
    assert!(info.secret_ids.is_empty());

    // the remaining budget is max - 1, then saturation
    for index in 1..usize::from(max) {
        let response = server
            .post("/fetch")
            .json(&fetch(
                SHA256_111111,
                &crate::tests::distinct_authentication_key(index),
            ))
            .expect_failure()
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }
    server
        .post("/store")
        .json(&store(
            SHA256_111111,
            SHA256_222222,
            BASE64_ENCRYPTED_SECRET,
        ))
        .expect_success()
        .await;
    let response = server
        .post("/fetch")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .expect_failure()
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::TOO_MANY_REQUESTS,
        "the deletion's slot counts toward saturation even after a re-store"
    );
}

/// A late replayed `/trash` from an old window must not forget a `secret_id` in the
/// window that replaced it.
#[tokio::test]
async fn test_old_replay_forget_cannot_touch_a_replaced_window() {
    let (_server, state) = crate::tests::test_server::new_test_server().await;
    let id_hash = identifier_hash(SHA256_111111).unwrap();
    let fresh_at = chrono::Utc::now();
    let stale_generation = fresh_at - chrono::Duration::hours(1);
    {
        let mut map = state.attempts.ledger.lock_for_test().await;
        let mut info = RateLimitInfo::new(fresh_at);
        info.secret_ids.insert(
            "committed-secret-id".to_owned(),
            crate::attempts::ledger::SecretIdState::Committed,
        );
        map.insert(id_hash.clone(), info);
    }

    state
        .attempts
        .ledger
        .forget_committed(&id_hash, "committed-secret-id", stale_generation)
        .await;
    let info = state
        .attempts
        .ledger
        .lock_for_test()
        .await
        .get(&id_hash)
        .cloned()
        .expect("entry");
    assert_eq!(
        info.secret_ids.len(),
        1,
        "a stale generation changes nothing"
    );
    assert_eq!(info.forgotten_slots, 0);

    state
        .attempts
        .ledger
        .forget_committed(&id_hash, "committed-secret-id", fresh_at)
        .await;
    let info = state
        .attempts
        .ledger
        .lock_for_test()
        .await
        .get(&id_hash)
        .cloned()
        .expect("entry");
    assert!(info.secret_ids.is_empty(), "the current generation forgets");
    assert_eq!(info.forgotten_slots, 1);
    assert_eq!(info.consumed_slots(), 1);
}
