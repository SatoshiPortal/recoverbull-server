use crate::{
    models::{FetchSecret, Secret, StoreSecret},
    tests::{BASE64_ENCRYPTED_SECRET, NOT_PASSWORD_HASH, SHA256_111111, SHA256_222222, SHA256_CONCAT_111111_222222},
};
use axum::http::StatusCode;

#[tokio::test]
async fn test_fetch_success() {

    let (server, _) = crate::tests::test_server::new_test_server().await;

    let payload = StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    
    server
        .post("/store")
        .json(&payload)
        .expect_success()
        .await;

    let fetch = FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
    };

    let response = server
        .post("/fetch")
        .json(&fetch)
        .expect_success()
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: Secret = response.json::<Secret>();
    assert_eq!(body.id, SHA256_CONCAT_111111_222222);
    assert_eq!(body.encrypted_secret, BASE64_ENCRYPTED_SECRET);
}

#[tokio::test]
async fn test_fetch_key_failure_invalid_hash_for_format_identifier() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let fetch = FetchSecret {
        identifier: "not_a_hash".to_string(),
        authentication_key: SHA256_111111.to_string(),
    };

    let response = server
        .post("/fetch")
        .json(&fetch)
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_fetch_failure_invalid_hash_format_for_authentication_key() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let fetch = FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: "not_a_hash".to_string(),
    };

    let response = server
        .post("/fetch")
        .json(&fetch)
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}


#[tokio::test]
async fn test_fetch_failure_too_many_attempts() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string()
        })
        .expect_success()
        .await;

    let fetch = FetchSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: NOT_PASSWORD_HASH.to_string(), // this should make the fetchy fail
    };

    // set the cooldown
    server.post("/fetch").json(&fetch).expect_failure().await;

    // trigger the cooldown
    let response = server.post("/fetch").json(&fetch).expect_failure().await;

    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
}
