use axum::http::StatusCode;

use crate::models::InfoResponse;

#[tokio::test]
async fn test_info_success() {
    let (server, state) = crate::tests::test_server::new_test_server().await;
    let response = server.get("/info").expect_success().await;
    let info: InfoResponse = serde_json::from_str(&response.text()).unwrap();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(info.cooldown, state.cooldown.num_minutes());
    assert_eq!(info.secret_max_length, state.secret_max_length);
    assert_eq!(info.canary, "🐦");
}
