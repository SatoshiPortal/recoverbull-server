use crate::http::contract::Info;
use axum::http::StatusCode;
use chrono::Timelike;

#[tokio::test]
async fn test_info_success() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    assert_eq!(state.canary_read_semaphore.available_permits(), 1);
    let response = server.get("/info").expect_success().await;
    let info = response.json::<Info>();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        info.rate_limit_cooldown,
        state.rate_limit_cooldown.num_minutes() as u64
    );
    assert_eq!(info.secret_max_length, state.secret_max_length);
    assert_eq!(info.canary, "🐦");
    assert_eq!(info.rate_limit_max_attempts, state.rate_limit_max_attempts);
    assert_eq!(
        info.rate_limit_max_failed_attempts, info.rate_limit_max_attempts,
        "the legacy info field must mirror the canonical field"
    );
    assert_eq!(
        info.max_attempt_identifiers,
        state.rate_limit_max_identifiers
    );

    // hour-truncated, and consistent with the in-memory collection start
    assert_eq!(info.attempts_collection_started_at.minute(), 0);
    assert_eq!(info.attempts_collection_started_at.second(), 0);
    assert_eq!(info.attempts_collection_started_at.nanosecond(), 0);
    assert!(
        info.attempts_collection_started_at <= *state.attempts_collection_started_at.lock().await
    );
}

#[tokio::test]
async fn test_info_exposes_no_live_identifier_count() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let response = server.get("/info").expect_success().await;
    let body = response.text();

    // a live count would make map-filling campaigns cheap to monitor
    assert!(!body.contains("active"));
    assert!(!body.contains("count"));
}

/// The warrant canary workflow: the operator updates the dotenv file and the
/// next `/info` request serves the new value, without a server restart.
/// Removing the key serves an empty canary (the compromise signal), while a
/// missing file falls back to the startup value (ops error, no false alarm).
#[tokio::test]
async fn test_info_rereads_canary_from_file_with_startup_fallback() {
    let mut state = crate::env::init();
    // this test exercises the file-authoritative deployment
    state.canary_from_env = false;
    let canary_path = std::env::temp_dir().join(format!(
        "keychain-test-info-canary-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    state.canary_path = canary_path.clone();
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
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
    assert_eq!(response.json::<Info>().canary, state.canary);
}

#[tokio::test]
async fn test_info_rereads_same_length_canary_when_file_metadata_is_restored() {
    let mut state = crate::env::init();
    state.canary_from_env = false;
    let canary_path = std::env::temp_dir().join(format!(
        "keychain-test-info-canary-metadata-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    state.canary_path = canary_path.clone();
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
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
    let mut state = crate::env::init();
    state.canary_from_env = true;
    state.canary_read_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let canary_path = std::env::temp_dir().join(format!(
        "keychain-test-info-canary-env-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    state.canary_path = canary_path.clone();
    crate::storage::sqlite::try_init_db(state.clone()).unwrap();
    let server = axum_test::TestServer::new(crate::router::new_for_tests(state.clone())).unwrap();

    std::fs::write(&canary_path, "CANARY='🐦‍⬛'\n").unwrap();
    let response = server.get("/info").expect_success().await;
    assert_eq!(response.json::<Info>().canary, state.canary);
    std::fs::remove_file(&canary_path).ok();
}
