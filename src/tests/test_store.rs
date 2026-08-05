use axum::http::StatusCode;

use crate::{
    models::{FetchSecret, Secret, StoreSecret},
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
async fn test_duplicate_store_is_indistinguishable_and_does_not_overwrite() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let store = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    };
    let first = server.post("/store").json(store).await;

    let duplicate = &StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: "dGVzdA==".to_string(),
    };
    let second = server.post("/store").json(duplicate).await;

    // A caller must not be able to distinguish an existing secret_id from a
    // fresh one: otherwise /store is an unthrottled authentication_key oracle.
    assert_eq!(first.status_code(), StatusCode::CREATED);
    assert_eq!(second.status_code(), first.status_code());

    // Idempotency must not turn into an overwrite primitive.
    let fetched = server
        .post("/fetch")
        .json(&FetchSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
        })
        .expect_success()
        .await
        .json::<Secret>();
    assert_eq!(fetched.encrypted_secret, BASE64_ENCRYPTED_SECRET);
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

/// The length check runs before the base64 decode: an oversized secret that
/// is also invalid base64 must be rejected as oversized, without paying for
/// a full decode of a body that is rejected anyway.
#[tokio::test]
async fn test_store_checks_length_before_base64() {
    let (server, state) = crate::tests::test_server::new_test_server().await;

    let oversized_invalid = "!".repeat(state.secret_max_length + 4 - (state.secret_max_length % 4));
    let response = server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: oversized_invalid,
        })
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body = response.text();
    assert!(
        body.contains("length exceeds the limit"),
        "expected the length error, got: {body}"
    );
}

#[tokio::test]
async fn test_store_rejects_oversized_json_before_deserialization() {
    let (server, _) = crate::tests::test_server::new_test_server().await;

    let response = server
        .post("/store")
        .json(&StoreSecret {
            identifier: SHA256_111111.to_string(),
            authentication_key: SHA256_222222.to_string(),
            encrypted_secret: "A".repeat(2_000),
        })
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
}
