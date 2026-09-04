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
                .is_some_and(|info| info.candidate_count() == expected)
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
async fn test_replaying_one_valid_candidate_does_not_consume_more_attempts() {
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
        // A replay of the same candidate must be idempotent, not a new lookup.
        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<serde_json::Value>();
        assert_eq!(body["attempt_status"]["version"], 1);
        assert_eq!(body["attempt_status"]["total_attempts"], 1);
        assert_eq!(body["attempt_status"]["total_requests"], request_number);
    }
}

#[tokio::test]
async fn test_replaying_one_invalid_candidate_does_not_consume_more_attempts() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    for _ in 0..5 {
        let response = server
            .post("/fetch")
            .json(&fetch(SHA256_111111, NOT_PASSWORD_HASH))
            .expect_failure()
            .await;
        // Replaying one bad candidate remains an authentication failure, not 429.
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.json::<ResponseFailedAttempt>().attempts, 1);
    }
}

#[tokio::test]
async fn test_fetch_and_trash_share_one_candidate_attempt() {
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

    // Fetch and trash for one candidate must observe one logical attempt.
    assert_eq!(response.status_code(), StatusCode::ACCEPTED);
    assert_eq!(
        response.json::<serde_json::Value>()["attempt_status"]["total_attempts"],
        1
    );
}

#[tokio::test]
async fn test_replaying_one_candidate_does_not_slide_resets_at() {
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

    // A replay must not renew the candidate's cooldown window.
    assert_eq!(second_resets_at, first_resets_at);
}

#[tokio::test]
async fn test_known_candidate_is_rejected_when_distinct_candidate_capacity_is_full() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let candidates = [
        SHA256_222222,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
    ];

    for authentication_key in candidates {
        let response = server
            .post("/fetch")
            .json(&fetch(SHA256_111111, authentication_key))
            .await;
        // Each new candidate consumes one admission, even when authentication fails.
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    let response = server
        .post("/fetch")
        .json(&fetch(SHA256_111111, candidates[0]))
        .await;
    // Full capacity must fail closed; a known candidate must not bypass it.
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_distinct_planted_candidates_consume_capacity() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let candidates = [
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000000000000000000000000000000000000000000003",
    ];

    for (index, authentication_key) in candidates.into_iter().enumerate() {
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
        // A planted hit is still a counted candidate, preserving the anti-bypass oracle.
        assert_eq!(body["encrypted_secret"], marker);
        assert_eq!(body["attempt_status"]["total_attempts"], index + 1);
    }

    let fourth = server
        .post("/fetch")
        .json(&fetch(SHA256_111111, SHA256_222222))
        .await;
    // Three planted candidates exhaust the distinct-candidate admission budget.
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
    // a membership oracle. Once the budget is full, every candidate — known
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
            .map(|info| info.candidate_count()),
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
async fn test_pending_distinct_candidates_consume_the_attempt_budget() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let candidates = [
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000000000000000000000000000000000000000000003",
    ];
    for authentication_key in candidates {
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

    let first = tokio::spawn(trash(state.clone(), candidates[0]));
    let second = tokio::spawn(trash(state.clone(), candidates[1]));
    let third = tokio::spawn(trash(state.clone(), candidates[2]));
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
            last_candidate_at: fresh_at,
            last_request_at: fresh_at,
            last_candidate_instant: tokio::time::Instant::now(),
            candidates: std::collections::HashMap::new(),
            forgotten_slots: 0,
            failed_candidates: 0,
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
    assert_eq!(info.candidate_count(), 0);
    assert_eq!(info.failed_candidates, 0);
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
    assert_eq!(info.failed_candidates, 0);
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
    assert_eq!(info.failed_candidates, 0);
}

/// After a successful `/trash`, the candidate that authenticated the deletion
/// must be indistinguishable from any other candidate: same status, same
/// counters. Keeping its tag recognizable made its replay free (`attempts`
/// unchanged) while a different PIN consumed a slot (`attempts` + 1), which
/// told a Backup File holder which PIN had been used for the deletion.
#[tokio::test]
async fn test_deleted_candidate_is_indistinguishable_from_a_new_candidate_after_trash() {
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
            info.candidate_count(),
            info.failed_candidates,
        ));
    }
    assert_eq!(
        observed[0], observed[1],
        "deleted PIN and new PIN must produce identical counters after a trash"
    );
    assert_eq!(observed[0].0, 2, "the deletion's slot stays consumed");
}

/// The replay path forgets too: a candidate committed by a `/fetch` hit and
/// then replayed by a `/trash` that deletes the row is no longer recognizable.
/// The trash response itself still reports one attempt, because the budget
/// is unchanged by the deletion.
#[tokio::test]
async fn test_trash_of_a_fetched_candidate_forgets_its_tag_without_refunding_the_slot() {
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
    // the detached worker forgets the tag after the response; wait for it
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let forgotten = state
                .attempts
                .ledger
                .lock_for_test()
                .await
                .get(&identifier_hash(SHA256_111111).unwrap())
                .is_some_and(|info| info.candidates.is_empty() && info.candidate_count() == 1);
            if forgotten {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the deleted candidate's tag must be forgotten");

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

    // a refund of a Pending candidate must not drop the entry holding the slot
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
        .candidates
        .insert(
            "pending-tag".to_owned(),
            crate::attempts::ledger::CandidateState::Pending,
        );
    state
        .attempts
        .ledger
        .refund(&id_hash, "pending-tag", generation)
        .await;
    let info = state
        .attempts
        .ledger
        .lock_for_test()
        .await
        .get(&id_hash)
        .cloned()
        .expect("the entry keeps the consumed slot through a refund");
    assert_eq!(info.candidate_count(), 1);
    assert!(info.candidates.is_empty());

    // the remaining budget is max - 1, then saturation
    for index in 1..usize::from(max) {
        let response = server
            .post("/fetch")
            .json(&fetch(
                SHA256_111111,
                &crate::tests::distinct_candidate(index),
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

/// A late replayed `/trash` from an old window must not forget a tag in the
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
        info.candidates.insert(
            "committed-tag".to_owned(),
            crate::attempts::ledger::CandidateState::Committed,
        );
        map.insert(id_hash.clone(), info);
    }

    state
        .attempts
        .ledger
        .forget_committed(&id_hash, "committed-tag", stale_generation)
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
        info.candidates.len(),
        1,
        "a stale generation changes nothing"
    );
    assert_eq!(info.forgotten_slots, 0);

    state
        .attempts
        .ledger
        .forget_committed(&id_hash, "committed-tag", fresh_at)
        .await;
    let info = state
        .attempts
        .ledger
        .lock_for_test()
        .await
        .get(&id_hash)
        .cloned()
        .expect("entry");
    assert!(info.candidates.is_empty(), "the current generation forgets");
    assert_eq!(info.forgotten_slots, 1);
    assert_eq!(info.candidate_count(), 1);
}
