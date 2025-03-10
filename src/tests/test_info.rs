use crate::models::Info;
use axum::http::StatusCode;

#[tokio::test]
async fn test_info_success() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let response = server.get("/info").expect_success().await;
    let info = response.json::<Info>();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(info.cooldown, state.cooldown.num_minutes());
    assert_eq!(info.secret_max_length, state.secret_max_length);
    assert_eq!(info.canary, "🐦");
}
