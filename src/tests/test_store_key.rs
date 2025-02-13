use axum::http::StatusCode;
use nostr::key::Keys;

use crate::{models::{Payload, StoreSecret}, tests::{test_server::get_test_server_public_key, BASE64_ENCRYPTED_SECRET, CLIENT_SECRET_KEY, SHA256_111111, SHA256_222222}, utils::encrypt_body};

#[tokio::test]
async fn test_success_created() {
    let (server,_) = crate::tests::test_server::new_test_server().await;

    let client_keys = Keys::parse(CLIENT_SECRET_KEY).unwrap();
    let client_secret_key = client_keys.secret_key().to_secret_hex();
    let server_public_key = get_test_server_public_key();

    let body = serde_json::to_string(&StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    }).unwrap();

    let encrypted_body: Payload = encrypt_body(&client_secret_key, &server_public_key, body).unwrap();
    
    let response =     server
        .post("/store")
        .json(&encrypted_body)
        .expect_success()
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
}



#[tokio::test]
async fn test_failure_identifier_not_64_letters() {
    let (server,_) = crate::tests::test_server::new_test_server().await;
    let client_keys = Keys::parse(CLIENT_SECRET_KEY).unwrap();
    let client_secret_key = client_keys.secret_key().to_secret_hex();
    let server_public_key = get_test_server_public_key();

    let body = serde_json::to_string(&StoreSecret {
        identifier: SHA256_111111[1..].to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: BASE64_ENCRYPTED_SECRET.to_string(),
    }).unwrap();

    let encrypted_body: Payload = encrypt_body(&client_secret_key, &server_public_key, body).unwrap();
    
    let response =     server
        .post("/store")
        .json(&encrypted_body)
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_failure_encrypted_empty_secret() {
    let (server,_) = crate::tests::test_server::new_test_server().await;
    let client_keys = Keys::parse(CLIENT_SECRET_KEY).unwrap();
    let client_secret_key = client_keys.secret_key().to_secret_hex();
    let server_public_key = get_test_server_public_key();

    let body = serde_json::to_string(&StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: "".to_string(),
    }).unwrap();

    let encrypted_body: Payload = encrypt_body(&client_secret_key, &server_public_key, body).unwrap();
    
    let response =     server
        .post("/store")
        .json(&encrypted_body)
        .expect_failure()
        .await;

    println!("{}", response.status_code());

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_failure_encrypted_secret_invalid_base64() {
    let (server,_) = crate::tests::test_server::new_test_server().await;
    let client_keys = Keys::parse(CLIENT_SECRET_KEY).unwrap();
    let client_secret_key = client_keys.secret_key().to_secret_hex();
    let server_public_key = get_test_server_public_key();

    let body = serde_json::to_string(&StoreSecret {
        identifier: SHA256_111111.to_string(),
        authentication_key: SHA256_222222.to_string(),
        encrypted_secret: "!@#$%^&*()".to_string(), // invalid_base64
    }).unwrap();

    let encrypted_body: Payload = encrypt_body(&client_secret_key, &server_public_key, body).unwrap();
    
    let response =     server
        .post("/store")
        .json(&encrypted_body)
        .expect_failure()
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}