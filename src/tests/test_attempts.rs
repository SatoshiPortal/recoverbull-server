use crate::{
    attempts::{ledger::RateLimitInfo, snapshot::AttemptsSnapshot},
    digest::sha256_hex,
    http::contract::{FetchSecret, StoreSecret},
    tests::{BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222},
};
use axum::http::StatusCode;
use chrono::Timelike;
use std::io::Read;
use std::sync::atomic::Ordering;

fn decode_gzip(body: &[u8]) -> (String, AttemptsSnapshot) {
    let mut decoder = flate2::read::GzDecoder::new(body);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).unwrap();
    let text = String::from_utf8(decoded).unwrap();
    let snapshot = serde_json::from_str(&text).unwrap();
    (text, snapshot)
}

fn assert_hour_truncated(timestamp: chrono::DateTime<chrono::Utc>) {
    assert_eq!(timestamp.minute(), 0, "timestamp must be hour-truncated");
    assert_eq!(timestamp.second(), 0);
    assert_eq!(timestamp.nanosecond(), 0);
}

#[tokio::test]
async fn test_attempts_publish_hashed_identifier_with_counters() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    // two failed attempts
    for index in 0..2 {
        let response = server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: crate::tests::distinct_authentication_key(index),
            })
            .expect_failure()
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    let response = server.get("/attempts").expect_success().await;
    assert_eq!(response.header("content-encoding"), "gzip");
    assert!(response.maybe_header("vary").is_none());

    let (body, snapshot) = decode_gzip(response.as_bytes());

    // the raw identifier must never leak, compressed or not
    assert!(!body.contains(SHA256_111111));

    assert_eq!(snapshot.version, 1);
    assert_hour_truncated(snapshot.collection_started_at);
    assert_eq!(snapshot.entries.len(), 1);

    let entry = &snapshot.entries[0];
    let expected_id_hash = sha256_hex(&hex::decode(SHA256_111111).unwrap());
    assert_eq!(entry.id_hash, expected_id_hash);
    assert_eq!(entry.total_attempts, 2);
    assert_eq!(entry.failed_attempts, 2);
    assert_eq!(entry.total_requests, 2);
    assert_hour_truncated(entry.window_started_at);
    assert_hour_truncated(entry.last_attempt_at);
}

/// The id_hash algorithm is pinned by a shared test vector with the client:
/// sha256(hex_decode(identifier)) — raw bytes, not the hex string. The client
/// pins the same value; a drift on either side breaks the match loudly.
#[test]
fn test_attempts_id_hash_matches_shared_client_vector() {
    let expected = "f5bb872a08ef929e6744d117a69d4073ee7b5df4f5d7a4ecdd606f30a58f76db";
    assert_eq!(
        crate::recovery::identifiers::identifier_hash(SHA256_111111).unwrap(),
        expected
    );
}

#[tokio::test]
async fn test_attempts_count_hits_and_planted_rows() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    server.post("/store").json(&store).expect_success().await;

    // two misses, then a hit: the hit consumes the budget without counting
    // as a failure
    for index in 0..2 {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: crate::tests::distinct_authentication_key(index),
            })
            .expect_failure()
            .await;
    }
    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await;

    let response = server.get("/attempts").expect_success().await;
    let (_, snapshot) = decode_gzip(response.as_bytes());
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].total_attempts, 3);
    assert_eq!(snapshot.entries[0].failed_attempts, 2);
    assert_eq!(snapshot.entries[0].total_requests, 3);
}

#[tokio::test]
async fn test_fetch_success_reports_status_without_resetting_attempt_budget() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    server.post("/store").json(&store).expect_success().await;

    // two failed attempts
    for index in 0..2 {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: SHA256_111111.to_string(),
                authentication_key: crate::tests::distinct_authentication_key(index),
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
    let response = server.get("/attempts").expect_success().await;
    let (_, snapshot) = decode_gzip(response.as_bytes());
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].total_attempts, 3);
    assert_eq!(snapshot.entries[0].failed_attempts, 2);

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
    assert!(response.header("retry-after").to_str().is_ok());
}

#[tokio::test]
async fn test_attempts_snapshot_etag_and_conditional_requests() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let response = server.get("/attempts").expect_success().await;
    let etag = response.header("etag").to_str().unwrap().to_owned();
    let cache_control = response
        .header("cache-control")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cache_control.starts_with("public, max-age="));
    let max_age: u64 = cache_control
        .strip_prefix("public, max-age=")
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&max_age));

    // a matching conditional request reuses the snapshot without a body
    let not_modified = server
        .get("/attempts")
        .add_header("If-None-Match", etag.as_str())
        .await;
    assert_eq!(not_modified.status_code(), StatusCode::NOT_MODIFIED);
    assert!(not_modified.as_bytes().is_empty());
    assert_eq!(not_modified.header("etag"), etag.as_str());

    // a wildcard conditional request matches any current representation
    let wildcard = server
        .get("/attempts")
        .add_header("If-None-Match", "*")
        .await;
    assert_eq!(wildcard.status_code(), StatusCode::NOT_MODIFIED);

    // RFC 9110: If-None-Match uses weak comparison — a weak validator
    // matches our strong ETag
    let weak = server
        .get("/attempts")
        .add_header("If-None-Match", format!("W/{etag}"))
        .await;
    assert_eq!(weak.status_code(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn test_attempts_snapshot_rebuild_is_deterministic() {
    let mut state = crate::app::init();
    // force a rebuild on every request
    state
        .attempts
        .snapshot
        .set_ttl_for_test(std::time::Duration::ZERO);
    state.storage.initialize().unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state)).unwrap();

    // unchanged activity: the ETag survives rebuilds
    let first = server.get("/attempts").expect_success().await;
    let second = server.get("/attempts").expect_success().await;
    assert_eq!(first.header("etag"), second.header("etag"));

    // new activity: the ETag changes
    server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: NOT_PASSWORD_HASH.to_string(),
        })
        .expect_failure()
        .await;
    let third = server.get("/attempts").expect_success().await;
    assert_ne!(first.header("etag"), third.header("etag"));
}

/// A cancelled initiator must neither cancel the build it started nor cause
/// a second one: the build task owns the mutex, so the next request waits
/// for it and then finds its result in the cache. The worker gate makes the
/// cancellation land after the build has started.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cancelled_attempts_request_keeps_single_rebuild_in_flight() {
    let (_server, state) = crate::tests::test_server::new_test_server().await;
    state
        .attempts
        .snapshot
        .probe()
        .hold
        .store(true, Ordering::SeqCst);
    let first_state = state.clone();
    let first = tokio::spawn(async move {
        crate::handlers::attempts::get_attempts(
            axum::extract::State(first_state),
            axum::http::HeaderMap::new(),
        )
        .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        state.attempts.snapshot.probe().started_notify.notified(),
    )
    .await
    .expect("snapshot worker did not start within 5 seconds");
    first.abort();

    let second_state = state.clone();
    let second = tokio::spawn(async move {
        crate::handlers::attempts::get_attempts(
            axum::extract::State(second_state),
            axum::http::HeaderMap::new(),
        )
        .await
    });
    state
        .attempts
        .snapshot
        .probe()
        .released
        .store(true, Ordering::SeqCst);
    state.attempts.snapshot.probe().release.notify_one();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), second)
        .await
        .expect("waiting snapshot request did not complete within 5 seconds")
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let builds_started = state
        .attempts
        .snapshot
        .probe()
        .started
        .load(Ordering::SeqCst);
    assert_eq!(
        builds_started, 1,
        "the second request must reuse the rebuild started by the cancelled request"
    );
}

#[tokio::test]
async fn test_attempts_entries_are_sorted_by_id_hash() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    for identifier in [SHA256_222222, SHA256_111111] {
        server
            .post("/fetch")
            .json(&FetchSecret {
                identifier: identifier.to_string(),
                authentication_key: NOT_PASSWORD_HASH.to_string(),
            })
            .expect_failure()
            .await;
    }

    let response = server.get("/attempts").expect_success().await;
    let (_, snapshot) = decode_gzip(response.as_bytes());
    assert_eq!(snapshot.entries.len(), 2);
    let hashes: Vec<&str> = snapshot
        .entries
        .iter()
        .map(|entry| entry.id_hash.as_str())
        .collect();
    let mut sorted = hashes.clone();
    sorted.sort_unstable();
    assert_eq!(
        hashes, sorted,
        "entries must be sorted for a deterministic representation"
    );
}

#[tokio::test]
async fn test_attempts_omit_expired_entries_at_build_time() {
    let state = crate::app::init();
    {
        let mut entries = state.attempts.ledger.lock_for_test().await;
        let window_started_at =
            chrono::Utc::now() - state.attempts.policy.cooldown() - chrono::Duration::seconds(1);
        entries.insert(
            crate::recovery::identifiers::identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                window_started_at,
                last_secret_id_at: window_started_at,
                last_request_at: window_started_at,
                // expiry decides on the monotonic clock: back-date it too
                last_secret_id_instant: crate::tests::monotonic_age(
                    (state.attempts.policy.cooldown() + chrono::Duration::seconds(1))
                        .to_std()
                        .unwrap(),
                ),
                secret_ids: std::collections::HashMap::new(),
                forgotten_slots: 0,
                failed_secret_ids: 1,
                total_requests: 1,
            },
        );
    }
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state)).unwrap();

    let response = server.get("/attempts").expect_success().await;
    let (_, snapshot) = decode_gzip(response.as_bytes());
    assert!(snapshot.entries.is_empty());
}

#[tokio::test]
async fn test_attempts_last_attempt_at_is_last_distinct_secret_id() {
    let state = crate::app::init();
    state
        .attempts
        .policy
        .set_cooldown_for_test(chrono::TimeDelta::hours(24));
    let now = chrono::Utc::now();
    let window_started_at = now - chrono::TimeDelta::hours(4);
    let last_secret_id_at = now - chrono::TimeDelta::hours(2);
    let last_request_at = now - chrono::TimeDelta::hours(1);
    {
        let mut entries = state.attempts.ledger.lock_for_test().await;
        entries.insert(
            crate::recovery::identifiers::identifier_hash(SHA256_111111).unwrap(),
            RateLimitInfo {
                window_started_at,
                last_secret_id_at,
                last_request_at,
                // The entry is active (24-hour cooldown), so the monotonic
                // clock stays fresh while the *published* last_secret_id_at
                // remains two hours old: that decoupling is the point here.
                last_secret_id_instant: tokio::time::Instant::now(),
                secret_ids: std::collections::HashMap::new(),
                forgotten_slots: 0,
                failed_secret_ids: 1,
                total_requests: 4,
            },
        );
    }
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state)).unwrap();

    let response = server.get("/attempts").expect_success().await;
    let (_, snapshot) = decode_gzip(response.as_bytes());
    assert_eq!(
        snapshot.entries[0].last_attempt_at,
        crate::attempts::snapshot::truncate_to_hour(last_secret_id_at)
    );
    assert_eq!(snapshot.entries[0].total_requests, 4);
}

#[tokio::test]
async fn test_attempts_rate_limit_bucket() {
    let state = crate::app::init();
    state
        .attempts
        .maintenance
        .set_bucket_for_test(crate::rate_limit::TokenBucket::new(1.0, 0.0))
        .await;
    state.storage.initialize().unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state)).unwrap();

    server.get("/attempts").expect_success().await;
    let response = server.get("/attempts").await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.header("retry-after").to_str().is_ok());
}

#[tokio::test]
async fn test_stats_route_is_not_exposed() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    assert_eq!(
        server.get("/stats").await.status_code(),
        StatusCode::NOT_FOUND
    );
}

/// Fill the rate-limit map to its configured capacity (100,000) and request
/// /attempts: the build must complete in bounded time with bounded output,
/// and the second request must be served from the cache with the same ETag.
/// This is the worst case the deployment guardrails are sized for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_attempts_snapshot_at_full_map_scale() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    let now = chrono::Utc::now();
    {
        let mut map = state.attempts.ledger.lock_for_test().await;
        for i in 0..100_000u32 {
            map.insert(
                format!("{:064x}", i),
                crate::attempts::ledger::RateLimitInfo {
                    window_started_at: now,
                    last_secret_id_at: now,
                    last_request_at: now,
                    last_secret_id_instant: tokio::time::Instant::now(),
                    secret_ids: std::collections::HashMap::new(),
                    forgotten_slots: 0,
                    failed_secret_ids: 0,
                    total_requests: 1,
                },
            );
        }
    }

    let started = std::time::Instant::now();
    let response = server.get("/attempts").await;
    let first_build = started.elapsed();

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: &[u8] = response.as_bytes();
    let (raw, snapshot) = decode_gzip(body);
    assert_eq!(snapshot.entries.len(), 100_000);

    println!(
        "full-map snapshot: build={first_build:?} gzip={}B json={}B",
        body.len(),
        raw.len()
    );
    assert!(
        first_build < std::time::Duration::from_secs(10),
        "snapshot build at full scale exceeded 10s: {first_build:?}"
    );

    // Second request within the TTL: cached, same ETag, fast.
    let started = std::time::Instant::now();
    let second = server.get("/attempts").await;
    let cached_serve = started.elapsed();
    assert_eq!(second.header("etag"), response.header("etag"));
    assert!(cached_serve < std::time::Duration::from_secs(1));
}

/// The published snapshot is a function of the counters and timestamps only:
/// changing every retained SecretId, while leaving the counters alone,
/// must not change a single published byte. The snapshot build projects the
/// ledger instead of cloning it, so a SecretId cannot reach the payload
/// and cannot be inferred from its size either.
#[tokio::test]
async fn test_snapshot_is_independent_of_secret_ids() {
    let mut state = crate::app::init();
    // force a rebuild on every request
    state
        .attempts
        .snapshot
        .set_ttl_for_test(std::time::Duration::ZERO);
    state
        .attempts
        .policy
        .set_cooldown_for_test(chrono::TimeDelta::hours(24));
    state.storage.initialize().unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    let id_hash = crate::recovery::identifiers::identifier_hash(SHA256_111111).unwrap();
    let now = chrono::Utc::now();
    let seed = |tag_prefix: &'static str| {
        let mut info = RateLimitInfo::new(now);
        for index in 0..3u8 {
            info.secret_ids.insert(
                sha256_hex(format!("{tag_prefix}-{index}").as_bytes()),
                crate::attempts::ledger::SecretIdState::Committed,
            );
        }
        info.failed_secret_ids = 2;
        info.total_requests = 7;
        info
    };

    {
        let mut map = state.attempts.ledger.lock_for_test().await;
        map.insert(id_hash.clone(), seed("first-secret_id-set"));
    }
    let first = server.get("/attempts").expect_success().await;
    let first_etag = first.header("etag").to_str().unwrap().to_string();
    let first_body = first.as_bytes().to_vec();

    // same counters and timestamps, entirely different `secret_id` values
    {
        let mut map = state.attempts.ledger.lock_for_test().await;
        let replacement = seed("totally-different-secret_id-set");
        let existing = map.get_mut(&id_hash).expect("the seeded entry is present");
        assert_eq!(
            existing.consumed_slots(),
            replacement.consumed_slots(),
            "the two tag sets must present the same counters"
        );
        existing.secret_ids = replacement.secret_ids;
    }
    let second = server.get("/attempts").expect_success().await;
    let second_etag = second.header("etag").to_str().unwrap().to_string();

    assert_eq!(
        first_etag, second_etag,
        "replacing every SecretId must not change the ETag"
    );
    assert_eq!(
        first_body,
        second.as_bytes().to_vec(),
        "replacing every SecretId must not change the published bytes"
    );

    // and no tag from either set appears in the payload
    let (body, snapshot) = decode_gzip(second.as_bytes());
    for tag_prefix in ["first-secret_id-set", "totally-different-secret_id-set"] {
        for index in 0..3u8 {
            let tag = sha256_hex(format!("{tag_prefix}-{index}").as_bytes());
            assert!(
                !body.contains(&tag),
                "a SecretId must never appear in the snapshot"
            );
        }
    }
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].total_attempts, 3);
    assert_eq!(snapshot.entries[0].total_requests, 7);
}

/// A snapshot build that dies without publishing must release the build
/// mutex, so a later request rebuilds. The mutex guard makes this structural
/// (it releases on unwind); the earlier design kept the dead task's channel
/// receiver in a shared slot, which made every later request a permanent
/// `500`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_attempts_recovers_after_a_snapshot_build_dies() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    state
        .attempts
        .snapshot
        .probe()
        .panic_before_send
        .store(true, Ordering::SeqCst);
    let failed = server.get("/attempts").await;
    assert_eq!(
        failed.status_code(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a build that dies before sending must surface as 500"
    );

    // The failure is counted in the unconditional five-minute window: a
    // client reads `/attempts` to confirm that nothing is wrong, so a broken
    // build must not be as quiet as a quiet channel.
    let counters = state.counters.flush();
    assert_eq!(counters.attempts_snapshot_failed, 1);

    state
        .attempts
        .snapshot
        .probe()
        .panic_before_send
        .store(false, Ordering::SeqCst);
    let recovered = server.get("/attempts").await;
    assert_eq!(
        recovered.status_code(),
        StatusCode::OK,
        "the build mutex must have been released, so a later request rebuilds"
    );
    assert_eq!(
        state
            .attempts
            .snapshot
            .probe()
            .started
            .load(Ordering::SeqCst),
        2,
        "the recovery must be a genuinely new build, not a cached result"
    );
    assert_eq!(
        state.counters.flush().attempts_snapshot_failed,
        0,
        "a successful rebuild is not a failure"
    );
}

/// Drives the ATT-002 interleaving: a build copies the ledger, the real
/// daily wipe runs while that copy is in flight, and the build then resumes.
/// Neither the response of the in-flight request nor the cache it fills may
/// contain a pre-wipe entry. `pause_point` selects where the wipe lands
/// relative to the collection-marker read.
async fn wipe_during_in_flight_build_publishes_nothing_pre_wipe(pause_point: u8) {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let id_hash = crate::recovery::identifiers::identifier_hash(SHA256_111111).unwrap();
    {
        let mut map = state.attempts.ledger.lock_for_test().await;
        let mut info = RateLimitInfo::new(chrono::Utc::now());
        info.secret_ids.insert(
            sha256_hex(b"pre-wipe secret_id"),
            crate::attempts::ledger::SecretIdState::Committed,
        );
        info.failed_secret_ids = 1;
        info.total_requests = 1;
        map.insert(id_hash.clone(), info);
    }

    let probe = state.attempts.snapshot.probe();
    probe.pause_point.store(pause_point, Ordering::SeqCst);
    let request_state = state.clone();
    let request = tokio::spawn(async move {
        crate::handlers::attempts::get_attempts(
            axum::extract::State(request_state),
            axum::http::HeaderMap::new(),
        )
        .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        probe.paused_notify.notified(),
    )
    .await
    .expect("the build did not reach its pause point within 5 seconds");

    // The real wipe, while the build holds a pre-wipe copy of the ledger.
    crate::attempts::maintenance::wipe_identifier_rate_limit(
        &state.attempts.ledger,
        &state.attempts.snapshot,
    )
    .await;
    assert!(state.attempts.ledger.lock_for_test().await.is_empty());
    assert!(!state.attempts.snapshot.is_cached_for_test().await);

    probe.pause_point.store(0, Ordering::SeqCst);
    probe.resume.notify_one();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), request)
        .await
        .expect("the in-flight request did not complete within 5 seconds")
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let (_, snapshot) = decode_gzip(&body);
    assert!(
        snapshot.entries.is_empty(),
        "a build that raced the wipe must not publish pre-wipe entries: {} entries",
        snapshot.entries.len()
    );

    // And the cache filled by that build must not resurrect them either.
    let cached = server.get("/attempts").expect_success().await;
    let (_, cached) = decode_gzip(cached.as_bytes());
    assert!(
        cached.entries.is_empty(),
        "the cache must not hold a pre-wipe snapshot after the wipe: {} entries",
        cached.entries.len()
    );
}

/// The 24-hour wipe is a retention boundary: no pre-wipe telemetry may be
/// published after it. A build that copied the ledger before the wipe and
/// finished after it used to republish the purged entries into the cache,
/// even attaching them to the new `collection_started_at`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_wipe_during_in_flight_build_after_ledger_copy_publishes_nothing_pre_wipe() {
    wipe_during_in_flight_build_publishes_nothing_pre_wipe(
        crate::attempts::snapshot::PAUSE_AFTER_LEDGER_COPY,
    )
    .await;
}

/// Same boundary, with the wipe landing after the build has already read the
/// collection marker: the stale entries and the stale marker are both
/// pre-wipe, and neither may be published.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_wipe_during_in_flight_build_after_collection_read_publishes_nothing_pre_wipe() {
    wipe_during_in_flight_build_publishes_nothing_pre_wipe(
        crate::attempts::snapshot::PAUSE_AFTER_COLLECTION_READ,
    )
    .await;
}
