use crate::models::Info;
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
        state.rate_limit_cooldown.num_minutes() as u64
    );
    assert_eq!(info.secret_max_length, state.secret_max_length);
    assert_eq!(info.canary, "🐦");
    assert_eq!(
        info.max_attempt_identifiers,
        state.rate_limit_max_identifiers
    );

    // hour-truncated, and consistent with the in-memory collection start
    assert_eq!(info.attempts_collection_started_at.minute(), 0);
    assert_eq!(info.attempts_collection_started_at.second(), 0);
    assert_eq!(info.attempts_collection_started_at.nanosecond(), 0);
    assert!(
        info.attempts_collection_started_at <= state.attempts_collection_started_at,
        "truncation rounds down"
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
