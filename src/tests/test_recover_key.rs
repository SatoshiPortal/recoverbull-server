use crate::{
    models::{FetchKey, Key, StoreKey},
    tests::{A64TIMES, SHA256_111111, SHA256_123456, SHA256_222222},
};
use axum::http::StatusCode;

#[tokio::test]
async fn test_recover_key_success() {
    let server = crate::tests::test_server::new_test_server();

    let store_key = StoreKey {
        backup_key: "123456".to_string(),
        secret_hash: SHA256_123456.to_string(),
    };
    server.post("/key").json(&store_key).expect_success().await;

    let fetch_key = FetchKey {
        id: SHA256_123456.to_string(),
        secret_hash: SHA256_123456.to_string(),
    };

    let response = server
        .post("/recover")
        .json(&fetch_key)
        .expect_success()
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: Key = response.json::<Key>();
    assert_eq!(body.id, fetch_key.id);
    assert_eq!(body.secret, fetch_key.secret_hash);
    assert_eq!(body.backup_key, "123456");
}

#[tokio::test]
async fn test_recover_key_failure_invalid_hash_format() {
    let server = crate::tests::test_server::new_test_server();

    let fetch_key = FetchKey {
        id: "not_a_hash".to_string(),
        secret_hash: "not_a_hash".to_string(),
    };

    let response = server
        .post("/recover")
        .json(&fetch_key)
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_recover_key_failure_too_many_attempts() {
    let server = crate::tests::test_server::new_test_server();

    let store_key = StoreKey {
        backup_key: "111111".to_string(),
        secret_hash: SHA256_111111.to_string(),
    };
    server.post("/key").json(&store_key).expect_success().await;

    let fetch_key = FetchKey {
        id: SHA256_111111.to_string(),
        secret_hash: SHA256_111111.to_string(),
    };

    // set the cooldown
    server
        .post("/recover")
        .json(&fetch_key)
        .expect_success()
        .await;

    // trigger the cooldown
    let response = server
        .post("/recover")
        .json(&fetch_key)
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_recover_key_failure_key_not_found() {
    let server = crate::tests::test_server::new_test_server();

    let fetch_key = FetchKey {
        id: A64TIMES.to_string(),
        secret_hash: SHA256_123456.to_string(),
    };

    let response = server
        .post("/recover")
        .json(&fetch_key)
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_recover_key_failure_invalid_secret() {
    let server = crate::tests::test_server::new_test_server();

    let store_key = StoreKey {
        backup_key: "222222".to_string(),
        secret_hash: SHA256_222222.to_string(),
    };
    server.post("/key").json(&store_key).expect_success().await;

    let fetch_key = FetchKey {
        id: SHA256_222222.to_string(),
        secret_hash: SHA256_111111.to_string(),
    };
    let response = server
        .post("/recover")
        .json(&fetch_key)
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}
