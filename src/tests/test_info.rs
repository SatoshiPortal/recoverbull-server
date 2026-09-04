use crate::http::contract::Info;
use axum::http::StatusCode;
use chrono::Timelike;

#[tokio::test]
async fn test_info_success() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let response = server.get("/info").expect_success().await;
    let info = response.json::<Info>();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        info.rate_limit_cooldown,
        state.attempts.policy.cooldown().num_minutes() as u64
    );
    assert_eq!(info.secret_max_length, state.recovery.max_secret_length());
    assert_eq!(info.canary, "🐦");
    assert_eq!(
        info.rate_limit_max_attempts,
        state.attempts.policy.max_attempts()
    );
    assert_eq!(
        info.rate_limit_max_failed_attempts, info.rate_limit_max_attempts,
        "the legacy info field must mirror the canonical field"
    );
    assert_eq!(
        info.max_attempt_identifiers,
        state.attempts.policy.max_identifiers()
    );

    // hour-truncated, and consistent with the in-memory collection start
    assert_eq!(info.attempts_collection_started_at.minute(), 0);
    assert_eq!(info.attempts_collection_started_at.second(), 0);
    assert_eq!(info.attempts_collection_started_at.nanosecond(), 0);
    assert!(
        info.attempts_collection_started_at
            <= state.attempts.snapshot.collection_started_at().await
    );
}

#[tokio::test]
async fn test_info_exposes_no_live_identifier_count() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let response = server.get("/info").expect_success().await;
    let body = response.text();

    // `/info` carries the configured capacity, not a live occupancy count.
    // This is a response-shape contract, not a protection: `/attempts`
    // publishes every active entry, so the live count is already derivable
    // from it. See the map-filling accepted risk in SECURITY.md.
    assert!(!body.contains("active"));
    assert!(!body.contains("count"));
}

/// The warrant canary workflow: the operator updates the dotenv file and the
/// next `/info` request serves the new value, without a server restart.
/// Removing the key serves an empty canary (the compromise signal), while a
/// missing file falls back to the startup value (ops error, no false alarm).
#[tokio::test]
async fn test_info_rereads_canary_from_file_with_startup_fallback() {
    let mut state = crate::app::init();
    // this test exercises the file-authoritative deployment, and asserts the
    // file semantics rather than the freshness interval, so it re-reads on
    // every request
    state.info.set_canary_from_env_for_test(false);
    state
        .info
        .set_canary_reread_interval_for_test(std::time::Duration::ZERO);
    let canary_path = std::env::temp_dir().join(format!(
        "keychain-test-info-canary-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    state.info.set_canary_path_for_test(canary_path.clone());
    state.storage.initialize().unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    // the file value wins over the startup value
    std::fs::write(&canary_path, "CANARY='🐦‍⬛'\n").unwrap();
    let response = server.get("/info").expect_success().await;
    assert_eq!(response.json::<Info>().canary, "🐦‍⬛");

    // editing the file is picked up without a restart
    std::fs::write(&canary_path, "CANARY='🆕'\n").unwrap();
    let response = server.get("/info").expect_success().await;
    assert_eq!(response.json::<Info>().canary, "🆕");

    // removing the CANARY key serves an empty canary: the compromise signal
    // must not be masked by the fallback
    std::fs::write(&canary_path, "OTHER=value\n").unwrap();
    let response = server.get("/info").expect_success().await;
    assert_eq!(response.json::<Info>().canary, "");

    // a missing or unreadable file falls back to the startup value
    std::fs::remove_file(&canary_path).unwrap();
    let response = server.get("/info").expect_success().await;
    assert_eq!(response.json::<Info>().canary, state.info.canary_for_test());
}

#[tokio::test]
async fn test_info_rereads_same_length_canary_when_file_metadata_is_restored() {
    let mut state = crate::app::init();
    state.info.set_canary_from_env_for_test(false);
    state
        .info
        .set_canary_reread_interval_for_test(std::time::Duration::ZERO);
    let canary_path = std::env::temp_dir().join(format!(
        "keychain-test-info-canary-metadata-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    state.info.set_canary_path_for_test(canary_path.clone());
    state.storage.initialize().unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state)).unwrap();

    std::fs::write(&canary_path, "CANARY=AAAA\n").unwrap();
    let original_metadata = std::fs::metadata(&canary_path).unwrap();
    let response = server.get("/info").expect_success().await;
    assert_eq!(response.json::<Info>().canary, "AAAA");

    std::fs::write(&canary_path, "CANARY=BBBB\n").unwrap();
    std::fs::File::open(&canary_path)
        .unwrap()
        .set_modified(original_metadata.modified().unwrap())
        .unwrap();
    let (first, second) = tokio::join!(server.get("/info"), server.get("/info"));
    assert_eq!(first.status_code(), StatusCode::OK);
    assert_eq!(second.status_code(), StatusCode::OK);
    assert_eq!(first.json::<Info>().canary, "BBBB");
    assert_eq!(second.json::<Info>().canary, "BBBB");

    std::fs::remove_file(canary_path).ok();
}

/// When CANARY comes from the process environment, the file is not
/// consulted: signaling then requires a restart with a changed value.
#[tokio::test]
async fn test_info_env_canary_is_authoritative_over_file() {
    let mut state = crate::app::init();
    state.info.set_canary_from_env_for_test(true);
    // zero would re-read the file on every request if the file were ever
    // consulted, which it must not be here
    state
        .info
        .set_canary_reread_interval_for_test(std::time::Duration::ZERO);
    let canary_path = std::env::temp_dir().join(format!(
        "keychain-test-info-canary-env-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    state.info.set_canary_path_for_test(canary_path.clone());
    state.storage.initialize().unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    std::fs::write(&canary_path, "CANARY='🐦‍⬛'\n").unwrap();
    let response = server.get("/info").expect_success().await;
    assert_eq!(response.json::<Info>().canary, state.info.canary_for_test());
    std::fs::remove_file(&canary_path).ok();
}

/// The canary is re-read at most once per interval, and `/info` advertises
/// exactly what remains of that freshness so a cache cannot stack a second
/// staleness window on top of it. The file semantics themselves are pinned by
/// `test_info_rereads_canary_from_file_with_startup_fallback`.
#[tokio::test]
async fn test_info_serves_a_cached_canary_and_advertises_its_freshness() {
    let mut state = crate::app::init();
    state.info.set_canary_from_env_for_test(false);
    let canary_path = std::env::temp_dir().join(format!(
        "keychain-test-info-canary-freshness-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    state.info.set_canary_path_for_test(canary_path.clone());
    state.storage.initialize().unwrap();
    let interval = std::time::Duration::from_secs(600);
    state.info.set_canary_reread_interval_for_test(interval);
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    std::fs::write(&canary_path, "CANARY=first\n").unwrap();
    let response = server.get("/info").expect_success().await;
    assert_eq!(response.json::<Info>().canary, "first");
    let max_age: u64 = response
        .header("cache-control")
        .to_str()
        .unwrap()
        .trim_start_matches("public, max-age=")
        .parse()
        .expect("max-age must be a number of seconds");
    assert!(
        max_age > 0 && max_age <= interval.as_secs(),
        "the advertised freshness must be what remains of the interval, got {max_age}"
    );

    // inside the interval the file is not consulted again
    std::fs::write(&canary_path, "CANARY=second\n").unwrap();
    let response = server.get("/info").expect_success().await;
    assert_eq!(
        response.json::<Info>().canary,
        "first",
        "the canary must be re-read at most once per interval"
    );

    // and the edit is picked up once the interval has elapsed
    let mut expired = state.clone();
    expired
        .info
        .set_canary_reread_interval_for_test(std::time::Duration::ZERO);
    let expired_server = axum_test::TestServer::new(crate::router::new_for_tests(expired)).unwrap();
    let response = expired_server.get("/info").expect_success().await;
    assert_eq!(response.json::<Info>().canary, "second");

    std::fs::remove_file(canary_path).ok();
}

/// A process-environment canary can only change with a restart, so `/info`
/// advertises no reuse window at all rather than a misleading one.
#[tokio::test]
async fn test_info_advertises_no_freshness_for_an_env_canary() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let response = server.get("/info").expect_success().await;
    assert_eq!(
        response.header("cache-control").to_str().unwrap(),
        "public, max-age=0"
    );
}
