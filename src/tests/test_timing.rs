use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde_json::json;

use crate::tests::{BASE64_ENCRYPTED_SECRET, SHA256_111111, SHA256_222222};

const TEST_FLOOR: Duration = Duration::from_millis(40);
#[cfg(test)]
const TEST_DELAY_HEADER: &str = "x-recoverbull-test-sensitive-post-delay";

fn store_body() -> serde_json::Value {
    json!({
        "identifier": SHA256_111111,
        "authentication_key": SHA256_222222,
        "encrypted_secret": BASE64_ENCRYPTED_SECRET,
    })
}

fn fetch_body() -> serde_json::Value {
    json!({
        "identifier": SHA256_111111,
        "authentication_key": SHA256_222222,
    })
}

async fn assert_floor(request: axum_test::TestRequest) -> StatusCode {
    let started = Instant::now();
    let response = request.await;
    assert!(
        started.elapsed() >= TEST_FLOOR,
        "response completed before configured floor: {:?}",
        started.elapsed()
    );
    response.status_code()
}

#[tokio::test]
async fn sensitive_post_success_and_failures_have_the_configured_floor() {
    let (server, _) = crate::tests::test_server::new_test_server_with_delay(TEST_FLOOR).await;

    assert_eq!(
        assert_floor(server.post("/store").json(&store_body())).await,
        StatusCode::CREATED
    );
    assert_eq!(
        assert_floor(server.post("/fetch").json(&fetch_body())).await,
        StatusCode::OK
    );
    assert_eq!(
        assert_floor(server.post("/trash").json(&fetch_body())).await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        assert_floor(server.post("/store").json(&json!({"bad": true}))).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn extractor_rejections_are_also_delayed() {
    let (server, _) = crate::tests::test_server::new_test_server_with_delay(TEST_FLOOR).await;
    assert_eq!(
        assert_floor(server.post("/fetch").text("not json")).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
        assert_floor(
            server
                .post("/fetch")
                .text("{")
                .content_type("application/json")
        )
        .await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn sensitive_post_routes_receive_only_test_marker() {
    let (server, _) = crate::tests::test_server::new_test_server().await;
    let response = server.post("/fetch").json(&fetch_body()).await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.header(TEST_DELAY_HEADER), "1");
}

#[tokio::test]
async fn default_body_limit_rejection_is_also_delayed() {
    let (server, _) = crate::tests::test_server::new_test_server_with_delay(TEST_FLOOR).await;
    let started = Instant::now();
    let response = server.post("/store").json(&"x".repeat(2_000)).await;
    assert_eq!(response.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(started.elapsed() >= TEST_FLOOR);
}

#[tokio::test]
async fn production_router_applies_the_500_millisecond_floor() {
    let app_state = crate::app::init();
    app_state.storage.initialize().unwrap();
    let app = crate::router::new(app_state.clone());
    let mut connection =
        crate::storage::sqlite::establish_connection(app_state.storage.database_url_for_test())
            .unwrap();
    crate::tests::test_server::clear_table_secret(&mut connection).await;
    let server = axum_test::TestServer::new(app).unwrap();

    let started = Instant::now();
    let response = server.post("/fetch").json(&fetch_body()).await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    assert!(started.elapsed() >= crate::router::PRODUCTION_MIN_RESPONSE_DELAY);
}

#[tokio::test]
async fn public_routes_and_unmatched_methods_are_not_delayed() {
    let (server, _) =
        crate::tests::test_server::new_test_server_with_delay(Duration::from_secs(2)).await;

    let info = server.get("/info").await;
    assert_eq!(info.status_code(), StatusCode::OK);
    assert!(info.maybe_header(TEST_DELAY_HEADER).is_none());

    let attempts = server.get("/attempts").await;
    assert_eq!(attempts.status_code(), StatusCode::OK);
    assert!(attempts.maybe_header(TEST_DELAY_HEADER).is_none());

    let method_not_allowed = server.get("/store").await;
    assert_eq!(
        method_not_allowed.status_code(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert!(method_not_allowed.maybe_header(TEST_DELAY_HEADER).is_none());
}

#[test]
fn production_floor_is_500_milliseconds() {
    assert_eq!(
        crate::router::PRODUCTION_MIN_RESPONSE_DELAY,
        Duration::from_millis(500)
    );
}
