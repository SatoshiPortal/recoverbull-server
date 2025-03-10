use crate::{
    models::{FetchSecret, StoreSecret},
    tests::{BASE64_ENCRYPTED_SECRET, SHA256_111111, SHA256_222222},
};
use axum::http::StatusCode;

#[tokio::test]
async fn test_trash_success() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };

    server.post("/store").json(store).expect_success().await;

    let fetch = &FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    };

    let response = server.post("/trash").json(fetch).expect_success().await;

    assert_eq!(response.status_code(), StatusCode::ACCEPTED);

    // re-attempt to /fetch this should fail
    server.post("/fetch").json(fetch).expect_failure().await;
}
