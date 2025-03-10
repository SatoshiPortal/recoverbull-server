use axum::http::StatusCode;

use crate::{
    models::StoreSecret,
    tests::{BASE64_ENCRYPTED_SECRET, SHA256_111111, SHA256_222222},
};

#[tokio::test]
async fn test_success_created() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };

    let response = server.post("/store").json(store).expect_success().await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_failure_identifier_not_64_letters() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111[1..].to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };

    let response = server.post("/store").json(store).expect_failure().await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_failure_encrypted_empty_secret() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: "".to_string(),
    };

    let response = server.post("/store").json(store).expect_failure().await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_failure_encrypted_secret_invalid_base64() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: "!@#$%^&*()".to_string(), // invalid_base64
    };

    let response = server.post("/store").json(store).expect_failure().await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}
