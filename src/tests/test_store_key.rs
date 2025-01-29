use axum::http::StatusCode;

use crate::{models::StoreSecret, tests::{SHA256_111111, SHA256_222222}};

#[tokio::test]
async fn test_success_created() {
    let (server,_) = crate::tests::test_server::new_test_server().await;

    let response = server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: "something".to_string(),
        })
        .expect_success()
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
}



#[tokio::test]
async fn test_failure_identifier_not_64_letters() {
    let (server,_) = crate::tests::test_server::new_test_server().await;

    let response = server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111[1..].to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: "something".to_string(),
        })
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}
